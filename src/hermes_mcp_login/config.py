"""Web-service settings.

All knobs come from the environment so the service stays config-file-free and
generic. Per-MCP-server settings (url, scope, client_id, …) are **not** here —
those live in the agent's own ``~/.hermes/config.yaml`` and are read through the
:mod:`hermes_mcp_login.hermes` bridge, so there is a single source of truth.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    """Runtime settings, all sourced from ``HERMES_MCP_LOGIN_*`` env vars."""

    # Public base URL the service is reachable at, e.g.
    # ``https://samuel.hermes.immeditech.ch``. The OAuth ``redirect_uri`` is
    # derived from it as ``<public_base>/mcp/<name>/callback`` and must match the
    # IdP's registered Valid Redirect URI. Required to start a login.
    public_base: str = ""

    # Bind address. Default loopback: the service is meant to sit behind a
    # reverse proxy (HAProxy) that terminates TLS — see README §Deploy.
    host: str = "127.0.0.1"
    port: int = 9120

    # How long a human may take in the browser before the flow is abandoned.
    # This is the *only* timeout that bounds the login — the agent's 40 s probe
    # cap does not apply here (we don't go through the probe path).
    callback_timeout: float = 300.0

    # How long ``/login`` waits for the provider to hand us the authorize URL
    # before giving up (the OAuth discovery round-trip should be sub-second).
    authorize_timeout: float = 30.0

    # Optional "restart agent gateway" button. Off by default since it needs a
    # sudoers rule. The command is configurable; the default is a plain, robust
    # ``systemctl restart`` (a full restart — which is what makes the agent
    # re-probe its MCP servers). A deployment may instead point it at
    # ``hermes gateway restart --system`` for Hermes' graceful drain + unit
    # refresh, but that needs HERMES_HOME preserved through sudo.
    gateway_restart_enabled: bool = False
    gateway_restart_command: str = "sudo -n systemctl restart hermes-gateway.service"
    gateway_restart_timeout: float = 30.0

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            public_base=os.environ.get("HERMES_MCP_LOGIN_PUBLIC_BASE", "").rstrip("/"),
            host=os.environ.get("HERMES_MCP_LOGIN_HOST", "127.0.0.1"),
            port=_env_int("HERMES_MCP_LOGIN_PORT", 9120),
            callback_timeout=_env_float("HERMES_MCP_LOGIN_CALLBACK_TIMEOUT", 300.0),
            authorize_timeout=_env_float("HERMES_MCP_LOGIN_AUTHORIZE_TIMEOUT", 30.0),
            gateway_restart_enabled=_env_bool("HERMES_MCP_LOGIN_GATEWAY_RESTART", False),
            gateway_restart_command=os.environ.get(
                "HERMES_MCP_LOGIN_GATEWAY_RESTART_CMD",
                "sudo -n systemctl restart hermes-gateway.service",
            ),
            gateway_restart_timeout=_env_float("HERMES_MCP_LOGIN_GATEWAY_RESTART_TIMEOUT", 30.0),
        )

    def redirect_uri(self, name: str) -> str:
        """Public callback URL for server *name* (the OAuth ``redirect_uri``)."""
        if not self.public_base:
            raise RuntimeError(
                "HERMES_MCP_LOGIN_PUBLIC_BASE is not set — cannot derive a "
                "redirect_uri. Set it to the externally reachable base URL, "
                "e.g. https://samuel.hermes.immeditech.ch"
            )
        return f"{self.public_base}/mcp/{name}/callback"
