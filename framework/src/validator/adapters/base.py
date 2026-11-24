from __future__ import annotations

import secrets
import shlex
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..models import ExecutionResult, TestCase

INTERPRETERS = {
    "sh": ["sh", "-s"],
    "bash": ["bash", "-s"],
    "powershell": ["powershell", "-NoProfile", "-NonInteractive", "-Command", "-"],
}


@dataclass
class Target:
    name: str
    platform: str
    transport: str = "local"
    agent_name: str = ""
    host: str | None = None
    port: int = 22
    user: str | None = None
    key_file: str | None = None

    @classmethod
    def from_config(cls, name: str, cfg: dict) -> Target:
        return cls(name=name, platform=cfg["platform"], transport=cfg.get("transport", "local"),
                   agent_name=cfg.get("agent_name", name), host=cfg.get("host"),
                   port=int(cfg.get("port", 22)), user=cfg.get("user"), key_file=cfg.get("key_file"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def new_exec_id() -> str:
    """Short unique id for one simulation execution (filesystem- and username-safe, 18 chars)."""
    return f"dv{_now():%y%m%d%H%M%S}{secrets.token_hex(2)}"


def build_command(target: Target, argv: list[str]) -> list[str]:
    if target.transport == "local":
        return argv
    if target.transport == "ssh":
        if not (target.host and target.user):
            raise ValueError(f"target {target.name}: ssh needs host and user")
        cmd = ["ssh", "-p", str(target.port), "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]
        if target.key_file:
            cmd += ["-i", str(Path(target.key_file).expanduser())]
        # "--" stops option parsing, so a host or user can never be read as an ssh option.
        return [*cmd, "--", f"{target.user}@{target.host}", " ".join(shlex.quote(a) for a in argv)]
    raise ValueError(f"unsupported transport '{target.transport}'")


def _text(value) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def run_script(target: Target, interpreter: str, script: str, args: list[str] | None = None,
               timeout: int = 300, allow_nonzero: bool = False) -> ExecutionResult:
    """Feed `script` to an interpreter's stdin, locally or over SSH (avoids quoting issues).

    Never raises for command/transport problems: the outcome is classified in `status` so a
    simulation failure can be reported as ERROR instead of a detection miss.
    """
    if interpreter not in INTERPRETERS:
        raise ValueError(f"unsupported interpreter '{interpreter}' (use {sorted(INTERPRETERS)})")
    argv = list(INTERPRETERS[interpreter])
    if args and interpreter in ("sh", "bash"):
        argv = [*argv, "--", *args]
    started = _now()
    try:
        cmd = build_command(target, argv)
    except ValueError as exc:
        return ExecutionResult(started, _now(), False, error=str(exc), status="setup_failed")
    try:
        p = subprocess.run(cmd, check=False, input=script, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return ExecutionResult(started, _now(), False, None, _text(exc.stdout), _text(exc.stderr),
                               f"timeout after {timeout}s", status="timeout")
    except (FileNotFoundError, PermissionError) as exc:
        return ExecutionResult(started, _now(), False, error=f"transport unavailable: {exc}",
                               status="connection_failed")
    except OSError as exc:
        return ExecutionResult(started, _now(), False, error=f"transport error: {exc}",
                               status="connection_failed")
    if target.transport == "ssh" and p.returncode == 255:
        # ssh itself failed (refused, unreachable, auth, host key): the simulation never ran, even
        # when the catalog allows non-zero exits from the remote command.
        return ExecutionResult(started, _now(), False, p.returncode, p.stdout, p.stderr,
                               f"ssh connection failed: {p.stderr.strip()[-200:]}", status="connection_failed")
    ok = p.returncode == 0 or allow_nonzero
    return ExecutionResult(started, _now(), ok, p.returncode, p.stdout, p.stderr,
                           None if ok else f"exit code {p.returncode}",
                           status="ok" if ok else "command_failed")


class Adapter(ABC):
    @abstractmethod
    def run(self, test: TestCase, target: Target) -> ExecutionResult:
        """Execute the simulation for `test` against `target`."""
