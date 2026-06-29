"""Agent-gateway control — restart the co-located Hermes gateway.

Separate from the OAuth bridge: this is plain service control, used by the
optional "restart gateway" button. The command is configurable (see
``Settings.gateway_restart_command``); the default
``sudo -n systemctl restart hermes-gateway.service`` relies on a sudoers rule
that grants exactly that — the service itself holds no extra privilege.

A *full* restart is what makes the agent re-probe its MCP servers (the
disk-watch reload only refreshes tokens for already-connected servers).
"""

from __future__ import annotations

import asyncio
import logging
import shlex

logger = logging.getLogger(__name__)


async def restart_gateway(command: str, timeout: float) -> tuple[bool, str]:
    """Run *command* (a shell-style string, split with shlex). Returns
    ``(ok, detail)``; ``detail`` carries stderr / a timeout note on failure.
    Never raises.
    """
    argv = shlex.split(command)
    if not argv:
        return False, "empty restart command"
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        logger.exception("restart_gateway: could not exec %r", argv[0])
        return False, f"could not run {argv[0]!r}: {exc}"

    try:
        _out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return False, f"timed out after {timeout:.0f}s"

    if proc.returncode == 0:
        logger.info("Gateway restart command succeeded: %s", command)
        return True, ""
    detail = (err or b"").decode(errors="replace").strip() or f"exit {proc.returncode}"
    logger.warning("Gateway restart command failed (%s): %s", command, detail)
    return False, detail
