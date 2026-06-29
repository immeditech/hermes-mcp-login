# hermes-mcp-login

Browser-triggered OAuth login for a [Hermes agent](https://github.com/NousResearch/hermes-agent)'s
OAuth-protected MCP servers — **no SSH, no paste, no CLI**.

A user opens a URL, authenticates at the IdP in their browser, and the agent's
MCP token is written to disk. The running agent picks it up on its next tool
call (disk-watch reload) — no restart, no IPC.

## What it does (and deliberately doesn't)

This service does **no OAuth of its own** and rebuilds **no token format**. It
drives Hermes' *own* OAuth building blocks in-process and writes through Hermes'
own `HermesTokenStorage`. Concretely it:

1. constructs the MCP SDK's `OAuthClientProvider` with **its own** redirect /
   callback handlers,
2. opens an MCP connection so the provider fires the OAuth flow on the `401`,
3. hands the IdP authorize URL to the browser as a `302`,
4. receives the IdP redirect on its **own** `/callback` route, lets the SDK do
   the PKCE token exchange, and the token lands in `~/.hermes/mcp-tokens/`.

There is **no loopback listener, no port forward, no rewrite**: this service's
`/callback` route *is* the OAuth redirect target. Because *we* own the
`redirect_uri` value in the client metadata, the flow needs no fork patches — it
runs against vanilla upstream Hermes + `mcp >= 1.26`.

## How it works

```
Browser                                   agent host (same LXC)
  │  (1) GET /mcp/<name>/login            ┌──────────────────────────────────┐
  ├──────────────────────────────────────►│ build OAuthClientProvider with   │
  │  (2) 302 → IdP authorize URL          │ our handlers; start connect task │
  │◄──────────────────────────────────────┤  → redirect_handler yields URL   │
  ▼                                        │                                  │
 IdP (authenticate, consent)              │                                  │
  │  (3) 302 → <public>/mcp/<name>/callback?code&state                        │
  ├──── via reverse proxy ───────────────►│ (4) GET /callback                │
  │                                        │  → SDK PKCE token exchange       │
  │                                        │  → HermesTokenStorage.set_tokens │
  │  (5) 302 → / (status)                  │     ~/.hermes/mcp-tokens/<name>  │
  │◄──────────────────────────────────────┤                                  │
  └                                        └──────────────────────────────────┘
                                           agent process reloads the token on
                                           its next MCP tool call (disk-watch).
```

The two OAuth handlers are coupled to the two HTTP requests by a pair of
`asyncio.Future`s, isolated per login by the OAuth `state`. See
`src/hermes_mcp_login/hermes.py`.

## Routes

| Route | Purpose |
|-------|---------|
| `GET /` | index: configured OAuth MCP servers + login / re-auth links |
| `GET /mcp/<name>/login` | start a login, `302` to the IdP authorize URL |
| `GET /mcp/<name>/callback?code&state` | the registered `redirect_uri`; token exchange, `302` back to `/` |
| `GET /mcp/<name>/status` | JSON `{ "token_present": bool }` |

## Deployment model

- **Co-location is mandatory.** Run on the **same host/LXC** as the agent, as
  the **agent's user** — it needs the `tools.mcp_oauth` import and write access
  to the shared `~/.hermes/mcp-tokens/`.
- **Run in the agent's venv Python** (e.g.
  `~/.hermes/hermes-agent/venv/bin/python -m hermes_mcp_login`) so `hermes-agent`
  and `mcp` resolve. `hermes-agent` is not on PyPI — it's already installed in
  that venv; this package just imports from it.
- **Behind a reverse proxy.** Let the proxy (e.g. HAProxy) terminate TLS for
  `<public_base>` and forward to the service (default port `9120`). Bind
  `127.0.0.1` only if the proxy runs on the **same host**; if it's a **central
  proxy on another host**, set `HERMES_MCP_LOGIN_HOST=0.0.0.0` (or the host IP)
  and firewall the port so only the proxy can reach it — otherwise the proxy
  gets "connection refused".
- A `systemd` unit template is in [`deploy/hermes-mcp-login.service`](deploy/hermes-mcp-login.service).

### Install

```bash
# into the agent's venv
~/.hermes/hermes-agent/venv/bin/pip install /path/to/hermes-mcp-login
```

### Configure

The service is configured entirely by environment (see [`.env.example`](.env.example));
**per-server** settings stay in the agent's `~/.hermes/config.yaml` so there is
one source of truth:

```yaml
mcp_servers:
  imcontact:
    url: "https://contact.example.com/mcp/sse"
    transport: sse                                      # omit for streamable HTTP
    auth: oauth
    ssl_verify: "/etc/ssl/certs/ca-certificates.crt"   # path or true/false
    oauth:
      client_id: "contact"                              # pre-registered → skips DCR
      scope: "openid profile email offline_access"      # offline_access → refresh token
```

The service drives the OAuth flow over the **same transport the agent uses**: it
honours the server's `transport: sse` (GET stream + POST messages) and falls
back to streamable HTTP otherwise — so the `401` challenge is triggered the same
way the agent would. TLS (`ssl_verify`) is applied to both transports.

The `redirect_uri` is derived as `<HERMES_MCP_LOGIN_PUBLIC_BASE>/mcp/<name>/callback`
and must be registered as a **Valid Redirect URI** at the IdP.

## Security

This service can wipe and re-mint a user's agent token, so it **must not be
openly reachable**:

- **v1: network isolation** — reverse proxy + firewall + per-user subdomain. The
  OAuth `state`/PKCE live in the agent's process, so the callback can't be
  forged or replayed without them.
- **Stronger: an OIDC gate** in front of the service (a small public client with
  PKCE). Add it when network isolation isn't enough.

Token files are written `0o600` under a `0o700` parent by Hermes'
`HermesTokenStorage` — this service never handles the token bytes itself.

## Coupling to Hermes internals

The only Hermes import is `HermesTokenStorage` (the agent's documented token
store) plus MCP SDK types. Client metadata and client pre-registration are built
**inline** here rather than calling Hermes' private helpers, so the service is
independent of the fork's `redirect_uri` patch and resilient to internal
signature drift. On a Hermes upgrade, verify only that `HermesTokenStorage` and
the `mcp` SDK provider/types still match.

## Development

```bash
pip install -e '.[dev]'
ruff check src
pytest
```

## License

MIT — see [LICENSE](LICENSE).
