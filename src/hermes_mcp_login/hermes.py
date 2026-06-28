"""Bridge to the Hermes agent's own OAuth machinery.

This is the only module that imports Hermes/MCP-SDK internals. It deliberately
keeps the surface small and stable:

* ``HermesTokenStorage`` — the agent's documented token store (we write *its*
  format, atomically, ``0o600``); the running agent's disk-watch reload picks up
  the fresh token on the next tool call. No restart, no IPC.
* the MCP SDK's ``OAuthClientProvider`` / metadata / client-info types.
* the streamable-HTTP client + ``ClientSession`` used to open a connection.

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

    return {
        "ClientSession": ClientSession,
        "OAuthClientProvider": OAuthClientProvider,
        "OAuthClientInformationFull": OAuthClientInformationFull,
        "OAuthClientMetadata": OAuthClientMetadata,
        "AnyUrl": AnyUrl,
        "streamable_http_client": streamable_http_client,
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


async def drive_login(server_cfg: dict, sess: LoginSession) -> None:
    """Open an MCP connection so the provider fires the OAuth flow on the 401.

    Runs as a background task across ``/login`` and ``/callback``. The two
    handlers below bridge the provider's callbacks to ``sess``'s two futures;
    ``session.initialize()`` triggers the 401 → authorize → token-exchange →
    ``storage.set_tokens`` chain, after which the token is on disk.
    """
    import httpx

    sdk = _load_sdk()
    storage_cls = _load_token_storage()

    name = sess.name
    url = server_cfg["url"]
    oauth_cfg = dict(server_cfg.get("oauth") or {})
    redirect_uri = sess.redirect_uri

    storage = storage_cls(name)
    metadata = _build_metadata(sdk, oauth_cfg, redirect_uri)
    await _preregister_client(sdk, storage, oauth_cfg, metadata, redirect_uri)

    async def redirect_handler(authorization_url: str) -> None:
        # Register the session under its OAuth state so /callback can find it,
        # then hand the authorize URL to the waiting /login request.
        state = parse_qs(urlparse(authorization_url).query).get("state", [None])[0]
        if state:
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
        timeout=float(oauth_cfg.get("timeout", 300)),
    )

    # ``ssl_verify`` is a TOP-LEVEL server key (not under ``oauth:``) — it may be
    # a CA-bundle path for an internal CA. Mirror tools/mcp_tool.py's HTTP path.
    verify = server_cfg.get("ssl_verify", True)
    connect_timeout = float(server_cfg.get("connect_timeout", 60))

    streamable = sdk["streamable_http_client"]
    ClientSession = sdk["ClientSession"]

    try:
        if sdk["new_http"]:
            client_kwargs = {
                "follow_redirects": True,
                "timeout": httpx.Timeout(connect_timeout, read=300.0),
                "verify": verify,
                "auth": provider,
            }
            async with httpx.AsyncClient(**client_kwargs) as http_client:
                async with streamable(url, http_client=http_client) as (read, write, _sid):
                    async with ClientSession(read, write) as session:
                        await session.initialize()  # ← drives the OAuth flow
        else:  # pragma: no cover - legacy SDK
            async with streamable(url, timeout=connect_timeout, verify=verify, auth=provider) as (
                read,
                write,
                _sid,
            ):
                async with ClientSession(read, write) as session:
                    await session.initialize()
    except BaseException as exc:  # noqa: BLE001 - surfaced to /callback and /login
        sess.error = exc
        if not sess.code_result.done():
            sess.code_result.set_exception(exc)
        if not sess.authorize_url.done():
            sess.authorize_url.set_exception(exc)
        logger.exception("MCP OAuth login for '%s' failed", name)
        raise
