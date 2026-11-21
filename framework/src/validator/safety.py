"""Central lab-target safety gate.

Every simulation execution is checked here before a command is built or run, so the
boundary does not depend on each simulation script re-implementing it. The gate:

* requires an explicit lab acknowledgement (``DV_LAB_ACK=1`` or ``safety.lab_acknowledged``);
* allows local targets only when configured;
* allows SSH targets only when every resolved address falls inside the configured lab
  CIDRs, and hostnames only when they are explicitly allowlisted (no open DNS trust);
* refuses ``risk: high`` tests unless destructive execution was opted into.

There is deliberately no per-target override flag: changing the boundary means editing
the configuration, which is reviewable, rather than passing a command-line argument.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, replace
from functools import lru_cache

from .adapters.base import Target
from .models import TestCase

LOG = logging.getLogger("validator.safety")

DEFAULT_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)

_TRUTHY = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    code: str
    reason: str

    def __str__(self) -> str:
        return f"{'allowed' if self.allowed else 'denied'} ({self.code}): {self.reason}"


def _allow(reason: str) -> SafetyDecision:
    return SafetyDecision(True, "ok", reason)


def _deny(code: str, reason: str) -> SafetyDecision:
    return SafetyDecision(False, code, reason)


@lru_cache(maxsize=16)
def _networks(cidrs: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets = []
    for entry in cidrs:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise ValueError(f"safety.allowed_cidrs: invalid network {entry!r}") from exc
    return tuple(nets)


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addresses = []
    for info in infos:
        addr = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        if addr not in addresses:
            addresses.append(addr)
    return addresses


@dataclass(frozen=True)
class SafetyPolicy:
    lab_acknowledged: bool = False
    allowed_cidrs: tuple[str, ...] = DEFAULT_CIDRS
    allowed_hostnames: tuple[str, ...] = ()
    allow_local_targets: bool = True
    allow_destructive: bool = False

    @classmethod
    def from_settings(cls, settings: dict) -> SafetyPolicy:
        cfg = settings.get("safety") or {}
        env_ack = os.environ.get("DV_LAB_ACK", "").strip().lower() in _TRUTHY
        return cls(
            lab_acknowledged=bool(cfg.get("lab_acknowledged", False)) or env_ack,
            allowed_cidrs=tuple(str(c) for c in cfg.get("allowed_cidrs") or DEFAULT_CIDRS),
            allowed_hostnames=tuple(str(h).strip().lower() for h in cfg.get("allowed_hostnames") or ()),
            allow_local_targets=bool(cfg.get("allow_local_targets", True)),
            allow_destructive=bool(cfg.get("allow_destructive", False)),
        )

    def with_destructive(self, allowed: bool = True) -> SafetyPolicy:
        return replace(self, allow_destructive=allowed)

    def check_target(self, target: Target) -> SafetyDecision:
        if not self.lab_acknowledged:
            decision = _deny(
                "no-lab-ack",
                "lab acknowledgement missing: run on a disposable lab with DV_LAB_ACK=1 "
                "or safety.lab_acknowledged: true",
            )
            return self._log(decision, target=target.name)
        if target.transport == "local":
            if not self.allow_local_targets:
                return self._log(_deny("local-disabled", f"target {target.name}: local targets are disabled"),
                                 target=target.name)
            return self._log(_allow(f"target {target.name}: local runner"), target=target.name)
        if target.transport != "ssh":
            return self._log(
                _deny("unsupported-transport", f"target {target.name}: unsupported transport {target.transport!r}"),
                target=target.name,
            )

        host = (target.host or "").strip()
        if not host:
            return self._log(_deny("malformed-target", f"target {target.name}: ssh requires a host"),
                             target=target.name)
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            return self._log(self._check_addresses(target, [literal]), target=target.name)
        if host.lower() not in self.allowed_hostnames:
            return self._log(
                _deny(
                    "hostname-not-allowed",
                    f"target {target.name}: hostname {host!r} is not in safety.allowed_hostnames",
                ),
                target=target.name,
            )
        try:
            addresses = _resolve(host)
        except OSError as exc:
            return self._log(
                _deny("target-unresolved", f"target {target.name}: cannot resolve {host!r}: {exc}"),
                target=target.name,
            )
        if not addresses:
            return self._log(_deny("target-unresolved", f"target {target.name}: {host!r} resolved to no address"),
                             target=target.name)
        return self._log(self._check_addresses(target, addresses), target=target.name)

    def check_test(self, test: TestCase) -> SafetyDecision:
        risk = (test.risk or "medium").lower()
        if risk == "high" and not self.allow_destructive:
            return self._log(
                _deny(
                    "high-risk-not-approved",
                    f"test {test.id}: risk is high; re-run with --allow-destructive on a disposable lab",
                ),
                test=test.id,
            )
        return self._log(_allow(f"test {test.id}: risk {risk}"), test=test.id)

    def _check_addresses(self, target: Target, addresses) -> SafetyDecision:
        nets = _networks(self.allowed_cidrs)
        outside = [str(a) for a in addresses if not any(a in net for net in nets)]
        if outside:
            return _deny(
                "target-outside-lab",
                f"target {target.name}: {', '.join(outside)} outside allowed lab ranges "
                f"{list(self.allowed_cidrs)}",
            )
        return _allow(f"target {target.name}: {', '.join(str(a) for a in addresses)} inside lab ranges")

    @staticmethod
    def _log(decision: SafetyDecision, **fields) -> SafetyDecision:
        detail = " ".join(f"{k}={v}" for k, v in fields.items())
        LOG.info("safety %s %s", detail, decision)
        return decision


def blocked_reason(test: TestCase, targets: dict[str, Target], policy: SafetyPolicy) -> str | None:
    """First reason this test may not execute, or None when it may."""
    target = targets.get(test.target)
    if target is None:
        return f"unknown target '{test.target}'"
    for decision in (policy.check_test(test), policy.check_target(target)):
        if not decision.allowed:
            return f"safety: {decision.reason}"
    return None
