"""Agent-gateway control — restart the co-located Hermes gateway.

Separate from the OAuth bridge: this is plain service control via ``systemctl``,
used by the optional "restart gateway" button. It relies on a sudoers rule that
lets the service user run exactly ``systemctl restart <service>`` — the service
itself holds no extra privilege.

Why a restart helps: the agent only re-probes an MCP server it abandoned at
startup (e.g. a first login, where no token existed yet) after a gateway
restart; the disk-watch reload refreshes tokens for *connected* servers but does
not re-establish a connection that failed the initial OAuth gate.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def restart_gateway(service: str, timeout: float) -> tuple[bool, str]:
    """Run ``sudo systemctl restart <service>``. Returns ``(ok, detail)``.

    ``detail`` carries stderr (or a timeout/exec note) on failure so the caller
    can surface a useful message. Never raises.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "-n", "systemctl", "restart", service,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:  # sudo/systemctl missing
        logger.exception("restart_gateway: could not exec sudo/systemctl")
        return False, f"could not run systemctl: {exc}"

    try:
        _out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return False, f"timed out after {timeout:.0f}s"

    if proc.returncode == 0:
        logger.info("Gateway service %s restarted", service)
        return True, ""
    detail = (err or b"").decode(errors="replace").strip() or f"exit {proc.returncode}"
    logger.warning("restart_gateway failed for %s: %s", service, detail)
    return False, detail
