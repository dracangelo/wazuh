"""Pull raw endpoint log tails over the target's transport, for evidence when a test fails."""
from __future__ import annotations

import subprocess

from ..adapters.base import Target, build_command

DEFAULT_LOGS = {"linux": ["/var/log/auth.log", "/var/log/syslog"]}


def tail_logs(target: Target, paths: list[str] | None = None, lines: int = 100) -> dict[str, str]:
    out: dict[str, str] = {}
    if target.platform != "linux":
        return out  # TODO: Windows event log export via wevtutil
    for path in paths or DEFAULT_LOGS["linux"]:
        cmd = build_command(target, ["sudo", "-n", "tail", "-n", str(lines), path])
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            out[path] = p.stdout if p.returncode == 0 else f"<unavailable: {p.stderr.strip()}>"
        except Exception as exc:  # evidence is best-effort
            out[path] = f"<error: {exc}>"
    return out
