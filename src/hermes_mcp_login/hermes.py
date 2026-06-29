"""Bridge to the Hermes agent's own OAuth machinery.

This is the only module that imports Hermes/MCP-SDK internals. It deliberately
keeps the surface small; what it touches (re-verify on a Hermes upgrade):

* ``tools.mcp_oauth.HermesTokenStorage`` — the agent's token store (we write
  *its* format, atomically, ``0o600``); the running agent's disk-watch reload
  picks up the fresh token on the next tool call. No restart, no IPC.
* ``hermes_cli.mcp_config._get_mcp_servers`` — reads ``mcp_servers`` from the
  agent's ``config.yaml``. Private (leading underscore); there is no public
  accessor, so this is the one fragile import.
* the MCP SDK's ``OAuthClientProvider`` / metadata / client-info types, the
  streamable-HTTP + SSE clients, and ``ClientSession``.

We build the client metadata and pre-register the client **inline** rather than
calling Hermes' private ``_build_client_metadata`` / ``_maybe_preregister_client``
helpers. That keeps us independent of the fork's ``redirect_uri`` patch (#47755):
because *we* own the ``redirect_uri`` value, there is nothing to resolve — the
authorize request and the token exchange both read it back from the metadata we
constructed. It also means one fewer private signature to track on fork sync.

The ``_is_interactive`` non-interactive gate that blocks ``hermes mcp login``
under systemd is never reached: we don't call ``build_oauth_auth`` /
``get_or_build_provider``. We construct the provider ourselves and supply
interactivity through the browser.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lazy imports — keep them inside functions so the module can be imported (and
# unit-tested) without the agent installed, and so an import error surfaces as a
# clear runtime message instead of a load-time crash.
# ---------------------------------------------------------------------------


def _load_token_storage():
    from tools.mcp_oauth import HermesTokenStorage

    return HermesTokenStorage


def _load_sdk():
    from mcp import ClientSession
    from mcp.client.auth import OAuthClientProvider
    from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata
    from pydantic import AnyUrl

    # Prefer the non-deprecated streamable client (mcp >= 1.24); fall back to
    # the legacy wrapper — mirrors tools/mcp_tool.py's own probing.
    try:
        from mcp.client.streamable_http import streamable_http_client

        new_http = True
    except ImportError:  # pragma: no cover - depends on installed SDK
        from mcp.client.streamable_http import streamablehttp_client as streamable_http_client

        new_http = False

    # SSE transport — for servers that implement the SSE protocol (GET stream +
    # POST messages) instead of streamable HTTP. Optional; only needed when a
    # server sets ``transport: sse``.
    try:
        from mcp.client.sse import sse_client
    except ImportError:  # pragma: no cover - depends on installed SDK
        sse_client = None

    return {
        "ClientSession": ClientSession,
        "OAuthClientProvider": OAuthClientProvider,
        "OAuthClientInformationFull": OAuthClientInformationFull,
        "OAuthClientMetadata": OAuthClientMetadata,
        "AnyUrl": AnyUrl,
        "streamable_http_client": streamable_http_client,
        "sse_client": sse_client,
        "new_http": new_http,
    }


# ---------------------------------------------------------------------------
# Config reads — single source of truth is the agent's own config.yaml
# ---------------------------------------------------------------------------


def oauth_servers() -> dict[str, dict]:
    """Return ``{name: server_cfg}`` for every MCP server using ``auth: oauth``."""
    from hermes_cli.mcp_config import _get_mcp_servers

    servers = _get_mcp_servers()
    return {
        name: cfg
        for name, cfg in servers.items()
        if isinstance(cfg, dict) and cfg.get("auth") == "oauth"
    }


def get_server_cfg(name: str) -> dict:
    """Return the config for one OAuth MCP server, or raise ``KeyError``."""
    servers = oauth_servers()
    if name not in servers:
        raise KeyError(name)
    return servers[name]


def token_present(name: str) -> bool:
    """True if a token file exists on disk for *name* (may be expired)."""
    storage_cls = _load_token_storage()
    return storage_cls(name).has_cached_tokens()


class _ForceReauthStorage:
    """Token-storage wrapper that reports *no* cached token, forcing a fresh
    browser flow — without destroying the existing one.

    A valid cached token short-circuits the OAuth flow (the server answers 200,
    so the 401 that starts the browser login never fires). The obvious fix —
    deleting the token first — is unsafe: if the user abandons the re-auth, the
    agent is left with no credentials, and a destructive GET is CSRF-able. This
    wrapper instead makes ``get_tokens`` return ``None`` so the SDK runs the full
    flow, while every write still goes to the real storage. The old token stays
    on disk and is overwritten only when (and if) a new one is obtained.

    ``wrote_tokens`` records whether the flow actually produced a new token, so
    the caller can tell a completed re-auth from an abandoned one (where the old
    token would otherwise still satisfy ``has_cached_tokens``).
    """

    def __init__(self, inner: Any):
        self._inner = inner
        self.wrote_tokens = False

    async def get_tokens(self):
        return None

    async def set_tokens(self, tokens) -> None:
        await self._inner.set_tokens(tokens)
        self.wrote_tokens = True

    def __getattr__(self, item):
        # Delegate everything else (client info, metadata, paths, remove, …) to
        # the wrapped HermesTokenStorage so writes land in the real token store.
        return getattr(self._inner, item)


# ---------------------------------------------------------------------------
# Login session — couples the two OAuth handlers to the two HTTP requests
# ---------------------------------------------------------------------------


@dataclass
class LoginSession:
    """One in-flight browser login, keyed by the OAuth ``state``.

    ``authorize_url`` is filled by ``redirect_handler`` and read by ``/login``;
    ``code_result`` is filled by ``/callback`` and read by ``callback_handler``.
    The connect task spans both HTTP requests as a background task.
    """

    name: str
    redirect_uri: str
    authorize_url: asyncio.Future
    code_result: asyncio.Future
    task: asyncio.Task | None = None
    error: BaseException | None = None
    # OAuth ``state`` this session was registered under in SESSIONS, so the
    # driver can remove its own entry when the flow ends (success or abandon).
    state: str | None = None


# Live sessions keyed by OAuth ``state`` so the stateless ``/callback`` request
# can find the session the ``/login`` request started.
SESSIONS: dict[str, LoginSession] = {}


# ---------------------------------------------------------------------------
# The flow driver
# ---------------------------------------------------------------------------


def _build_metadata(sdk: dict, oauth_cfg: dict, redirect_uri: str):
    """Construct ``OAuthClientMetadata`` — the inline twin of Hermes'
    ``_build_client_metadata``, but with our own ``redirect_uri`` (no resolve)."""
    AnyUrl = sdk["AnyUrl"]
    kwargs: dict[str, Any] = {
        "client_name": oauth_cfg.get("client_name", "Hermes Agent"),
        "redirect_uris": [AnyUrl(redirect_uri)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    if oauth_cfg.get("scope"):
        kwargs["scope"] = oauth_cfg["scope"]
    if oauth_cfg.get("client_secret"):
        kwargs["token_endpoint_auth_method"] = "client_secret_post"
    return sdk["OAuthClientMetadata"].model_validate(kwargs)


async def _preregister_client(sdk: dict, storage, oauth_cfg: dict, metadata, redirect_uri: str):
    """Persist a pre-registered ``client_id`` so the SDK skips dynamic
    registration. Required for IdPs without RFC 7591 DCR (e.g. Keycloak with a
    statically-configured client). No-op when no ``client_id`` is configured.

    Uses the storage protocol's public ``set_client_info`` rather than poking at
    a private path — patch-independent and signature-stable.
    """
    client_id = oauth_cfg.get("client_id")
    if not client_id:
        return
    info: dict[str, Any] = {
        "client_id": client_id,
        "redirect_uris": [redirect_uri],
        "grant_types": metadata.grant_types,
        "response_types": metadata.response_types,
        "token_endpoint_auth_method": metadata.token_endpoint_auth_method,
    }
    if oauth_cfg.get("client_secret"):
        info["client_secret"] = oauth_cfg["client_secret"]
    if oauth_cfg.get("client_name"):
        info["client_name"] = oauth_cfg["client_name"]
    if oauth_cfg.get("scope"):
        info["scope"] = oauth_cfg["scope"]
    client_info = sdk["OAuthClientInformationFull"].model_validate(info)
    await storage.set_client_info(client_info)


def _persist_oauth_metadata(provider, storage) -> None:
    """Write the discovered OAuth server metadata to ``<name>.meta.json``.

    The raw SDK ``OAuthClientProvider`` discovers the authorization-server
    metadata during the flow but keeps it in memory only — only Hermes'
    ``HermesMCPOAuthProvider`` persists it. Without the on-disk metadata, the
    agent's next cold token refresh has no token endpoint and falls back to the
    SDK's guessed ``{server_url}/token`` → 404/405 → a full browser re-auth.
    Mirrors ``HermesMCPOAuthProvider._persist_oauth_metadata_if_changed`` so the
    on-disk state matches exactly what the running agent expects.
    """
    ctx = getattr(provider, "context", None)
    meta = getattr(ctx, "oauth_metadata", None) if ctx is not None else None
    if meta is not None:
        storage.save_oauth_metadata(meta)
        logger.info("Persisted OAuth metadata (token_endpoint=%s)", meta.token_endpoint)


async def drive_login(
    server_cfg: dict,
    sess: LoginSession,
    *,
    force: bool = False,
    provider_timeout: float = 300.0,
) -> None:
    """Open an MCP connection so the provider fires the OAuth flow on the 401.

    Runs as a background task across ``/login`` and ``/callback``. The two
    handlers below bridge the provider's callbacks to ``sess``'s two futures;
    ``session.initialize()`` triggers the 401 → authorize → token-exchange →
    ``storage.set_tokens`` chain, after which the token is on disk.

    With ``force=True`` (re-auth) the provider is given a storage wrapper that
    hides any cached token so the browser flow runs even when a valid token
    already exists — non-destructively (see :class:`_ForceReauthStorage`).
    ``provider_timeout`` bounds how long the provider waits for the browser
    callback. This coroutine never raises: outcomes are reported via
    ``sess.error`` (and ``sess.authorize_url`` for pre-redirect failures).
    """
    import httpx

    sdk = _load_sdk()
    storage_cls = _load_token_storage()

    name = sess.name
    url = server_cfg["url"]
    oauth_cfg = dict(server_cfg.get("oauth") or {})
    redirect_uri = sess.redirect_uri

    real_storage = storage_cls(name)
    # For re-auth, the provider talks to a wrapper that reports no cached token;
    # all writes still land in real_storage. For a first login they're the same.
    storage = _ForceReauthStorage(real_storage) if force else real_storage
    metadata = _build_metadata(sdk, oauth_cfg, redirect_uri)
    await _preregister_client(sdk, storage, oauth_cfg, metadata, redirect_uri)

    async def redirect_handler(authorization_url: str) -> None:
        # Register the session under its OAuth state so /callback can find it,
        # then hand the authorize URL to the waiting /login request.
        state = parse_qs(urlparse(authorization_url).query).get("state", [None])[0]
        if state:
            sess.state = state
            SESSIONS[state] = sess
        if not sess.authorize_url.done():
            sess.authorize_url.set_result(authorization_url)

    async def callback_handler() -> tuple[str, str | None]:
        return await sess.code_result

    provider = sdk["OAuthClientProvider"](
        server_url=url,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
        timeout=provider_timeout,
    )

    # ``ssl_verify`` is a TOP-LEVEL server key (not under ``oauth:``) — it may be
    # a CA-bundle path for an internal CA. Mirror tools/mcp_tool.py's HTTP path.
    verify = server_cfg.get("ssl_verify", True)
    connect_timeout = float(server_cfg.get("connect_timeout", 60))

    ClientSession = sdk["ClientSession"]
    # Match the transport the agent uses for this server, so the OAuth flow is
    # triggered the same way. SSE servers (GET stream + POST messages) return
    # the 401 challenge on the GET; driving them with the streamable-HTTP POST
    # would hit 404/405 instead and never start the flow.
    transport = server_cfg.get("transport")

    # Drive the connect so the 401 fires the OAuth flow. We only care that the
    # flow runs far enough to exchange the code and write the token — the
    # subsequent MCP `initialize()` round-trip is the agent's job, not ours, and
    # can hiccup independently (e.g. streamable-HTTP "Session terminated"/404 on
    # the post-auth retry). So success is defined by the token landing on disk,
    # not by a clean initialize().
    connect_error: BaseException | None = None
    try:
        if transport == "sse":
            sse_client = sdk["sse_client"]
            if sse_client is None:  # pragma: no cover - depends on installed SDK
                raise RuntimeError(
                    f"server '{name}' uses transport: sse but mcp.client.sse "
                    "is not available in this SDK"
                )

            # sse_client takes no verify/cert kwargs — route TLS settings
            # through an httpx_client_factory, mirroring tools/mcp_tool.py.
            def _sse_http_factory(headers=None, timeout=None, auth=None):
                kw: dict = {
                    "follow_redirects": True,
                    "verify": verify,
                    "timeout": timeout or httpx.Timeout(connect_timeout, read=300.0),
                }
                if headers is not None:
                    kw["headers"] = headers
                if auth is not None:
                    kw["auth"] = auth
                return httpx.AsyncClient(**kw)

            async with sse_client(
                url=url,
                timeout=connect_timeout,
                sse_read_timeout=300.0,
                auth=provider,
                httpx_client_factory=_sse_http_factory,
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()  # ← drives the OAuth flow
        elif sdk["new_http"]:
            client_kwargs = {
                "follow_redirects": True,
                "timeout": httpx.Timeout(connect_timeout, read=300.0),
                "verify": verify,
                "auth": provider,
            }
            async with httpx.AsyncClient(**client_kwargs) as http_client:
                async with sdk["streamable_http_client"](url, http_client=http_client) as (
                    read, write, _sid,
                ):
                    async with ClientSession(read, write) as session:
                        await session.initialize()  # ← drives the OAuth flow
        else:  # pragma: no cover - legacy SDK
            async with sdk["streamable_http_client"](
                url, timeout=connect_timeout, verify=verify, auth=provider
            ) as (read, write, _sid):
                async with ClientSession(read, write) as session:
                    await session.initialize()
    except BaseException as exc:  # noqa: BLE001 - evaluated against token presence below
        connect_error = exc
        logger.warning("MCP connect for '%s' raised (token may still be saved): %s", name, exc)

    finally:
        # Always drop our own SESSIONS entry — otherwise abandoned/timed-out
        # logins (where /callback never fires) leak the dict forever.
        if sess.state is not None:
            SESSIONS.pop(sess.state, None)

    # Metadata is discovered during the auth flow and lives on the provider
    # context even if the post-auth initialize failed — persist it defensively
    # so the agent can cold-refresh (needs <name>.meta.json for the token URL).
    try:
        _persist_oauth_metadata(provider, real_storage)
    except Exception:  # noqa: BLE001 - never let metadata persistence fail the login
        logger.exception("Persisting OAuth metadata for '%s' failed", name)

    # Success = a token was obtained. For re-auth we must check that *this* flow
    # wrote a new token (the old one would still satisfy has_cached_tokens); for
    # a first login, a token file on disk is enough.
    succeeded = storage.wrote_tokens if force else real_storage.has_cached_tokens()
    if succeeded:
        if connect_error is not None:
            logger.info(
                "MCP OAuth login for '%s' succeeded (token written) despite a "
                "post-auth session error", name,
            )
        sess.error = None
        return

    # No token obtained → a real failure. Record it (this coroutine never
    # raises, so an abandoned task doesn't emit "exception never retrieved");
    # surface pre-redirect failures to a still-waiting /login.
    err = connect_error or RuntimeError(
        f"MCP OAuth login for '{name}' finished without a cached token"
    )
    sess.error = err
    if not sess.authorize_url.done():
        sess.authorize_url.set_exception(err)
    logger.error("MCP OAuth login for '%s' failed: %s", name, err)
