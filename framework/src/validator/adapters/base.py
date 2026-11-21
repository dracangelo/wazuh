from __future__ import annotations

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
    def from_config(cls, name: str, cfg: dict) -> "Target":
        return cls(name=name, platform=cfg["platform"], transport=cfg.get("transport", "local"),
                   agent_name=cfg.get("agent_name", name), host=cfg.get("host"),
                   port=int(cfg.get("port", 22)), user=cfg.get("user"), key_file=cfg.get("key_file"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_command(target: Target, argv: list[str]) -> list[str]:
    if target.transport == "local":
        return argv
    if target.transport == "ssh":
        if not (target.host and target.user):
            raise ValueError(f"target {target.name}: ssh needs host and user")
        cmd = ["ssh", "-p", str(target.port), "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new"]
        if target.key_file:
            cmd += ["-i", str(Path(target.key_file).expanduser())]
        return cmd + [f"{target.user}@{target.host}", " ".join(shlex.quote(a) for a in argv)]
    raise ValueError(f"unsupported transport '{target.transport}'")


def run_script(target: Target, interpreter: str, script: str, args: list[str] | None = None,
               timeout: int = 300, allow_nonzero: bool = False) -> ExecutionResult:
    """Feed `script` to an interpreter's stdin, locally or over SSH (avoids quoting issues)."""
    if interpreter not in INTERPRETERS:
        raise ValueError(f"unsupported interpreter '{interpreter}' (use {sorted(INTERPRETERS)})")
    argv = list(INTERPRETERS[interpreter])
    if args and interpreter in ("sh", "bash"):
        argv += ["--", *args]
    cmd = build_command(target, argv)
    started = _now()
    try:
        p = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=timeout)
        ok = p.returncode == 0 or allow_nonzero
        return ExecutionResult(started, _now(), ok, p.returncode, p.stdout, p.stderr,
                               None if ok else f"exit code {p.returncode}")
    except subprocess.TimeoutExpired:
        return ExecutionResult(started, _now(), False, None, error=f"timeout after {timeout}s")


class Adapter(ABC):
    @abstractmethod
    def run(self, test: TestCase, target: Target) -> ExecutionResult:
        """Execute the simulation for `test` against `target`."""
