"""FastAPI app: the three OAuth routes plus a small index.

Flow (see README §How it works):

  GET /mcp/<name>/login      → start a connect task, 302 to the IdP authorize URL
  GET /mcp/<name>/callback   → the registered redirect_uri; hands the code to the
                               flow, the SDK does the PKCE token exchange + write,
                               302 back to the index with a status
  GET /mcp/<name>/status     → JSON: is a token on disk?

There is no loopback listener and no port forward: this service's own
``/callback`` route **is** the OAuth redirect target.

Security note: this service can wipe and re-mint a user's agent token, so it
must not be openly reachable. v1 relies on network isolation (reverse proxy +
firewall, per-user subdomain); ``state``/PKCE additionally protect the callback.
Put an OIDC gate in front if you need stronger auth — see README §Security.
"""

from __future__ import annotations

import asyncio
import html
import logging

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import hermes
from .config import Settings

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="hermes-mcp-login", version="0.1.0")

    # GET renders the index; HEAD is what reverse-proxy health checks hit
    # (e.g. HAProxy `option httpchk HEAD /`). Without HEAD the route returns
    # 405 and the proxy marks the backend down → 503. Starlette strips the
    # body for HEAD automatically.
    @app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
    async def index() -> str:
        return _render_index()

    @app.get("/mcp/{name}/login")
    async def login(name: str):
        try:
            cfg = hermes.get_server_cfg(name)
        except KeyError:
            return _problem(f"unknown OAuth MCP server: {name!r}", 404)

        try:
            redirect_uri = settings.redirect_uri(name)
        except RuntimeError as exc:
            return _problem(str(exc), 500)

        loop = asyncio.get_running_loop()
        sess = hermes.LoginSession(
            name=name,
            redirect_uri=redirect_uri,
            authorize_url=loop.create_future(),
            code_result=loop.create_future(),
        )
        # Background task: outlives this request, spans through /callback.
        sess.task = asyncio.create_task(hermes.drive_login(cfg, sess))

        try:
            authorize_url = await asyncio.wait_for(
                asyncio.shield(sess.authorize_url), timeout=settings.authorize_timeout
            )
        except asyncio.TimeoutError:
            sess.task.cancel()
            return _problem("timed out waiting for the authorize URL", 504)
        except Exception as exc:  # noqa: BLE001 - flow failed before authorize
            return _problem(f"login could not be started: {exc}", 502)

        return RedirectResponse(authorize_url, status_code=302)

    @app.get("/mcp/{name}/callback")
    async def callback(name: str, code: str | None = None, state: str | None = None,
                       error: str | None = None):
        if error:
            return _result_redirect(name, ok=False, detail=error)
        if not code or not state:
            return _problem("missing code/state on callback", 400)

        sess = hermes.SESSIONS.pop(state, None)
        if sess is None:
            return _problem("unknown or expired login session", 400)
        if not sess.code_result.done():
            sess.code_result.set_result((code, state))

        # Wait for the connect task to finish the token exchange + disk write.
        if sess.task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(sess.task), timeout=60)
            except asyncio.TimeoutError:
                return _result_redirect(name, ok=False, detail="token exchange timed out")
            except Exception as exc:  # noqa: BLE001 - flow raised
                return _result_redirect(name, ok=False, detail=str(exc))

        ok = hermes.token_present(name)
        return _result_redirect(name, ok=ok)

    @app.get("/mcp/{name}/status")
    async def status(name: str):
        try:
            hermes.get_server_cfg(name)
        except KeyError:
            return _problem(f"unknown OAuth MCP server: {name!r}", 404)
        return JSONResponse({"name": name, "token_present": hermes.token_present(name)})

    return app


# ---------------------------------------------------------------------------
# Small rendering helpers — no template engine; this is a one-page tool.
# ---------------------------------------------------------------------------


def _problem(detail: str, status_code: int) -> JSONResponse:
    return JSONResponse({"error": detail}, status_code=status_code)


def _result_redirect(name: str, *, ok: bool, detail: str | None = None) -> RedirectResponse:
    suffix = f"&detail={html.escape(detail)}" if detail else ""
    return RedirectResponse(f"/?status={'ok' if ok else 'fail'}&server={name}{suffix}", status_code=302)


def _render_index() -> str:
    try:
        servers = hermes.oauth_servers()
    except Exception as exc:  # noqa: BLE001 - config read failed
        return f"<h1>hermes-mcp-login</h1><p>could not read MCP config: {html.escape(str(exc))}</p>"

    rows = []
    for name in sorted(servers):
        present = hermes.token_present(name)
        badge = "✅ token present" if present else "— no token"
        rows.append(
            f"<tr><td><code>{html.escape(name)}</code></td>"
            f"<td>{badge}</td>"
            f'<td><a href="/mcp/{html.escape(name)}/login">'
            f'{"re-auth" if present else "login"}</a></td></tr>'
        )
    body = "\n".join(rows) or '<tr><td colspan="3"><em>no OAuth MCP servers configured</em></td></tr>'
    return (
        "<!doctype html><meta charset=utf-8>"
        "<title>hermes-mcp-login</title>"
        "<h1>hermes-mcp-login</h1>"
        "<p>Browser-triggered OAuth login for this agent's MCP servers.</p>"
        "<table cellpadding=6>"
        "<tr><th align=left>server</th><th align=left>status</th><th></th></tr>"
        f"{body}</table>"
    )
