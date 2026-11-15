"""Hard-boundary syscall, filesystem, and network egress policy monitor for coding agents."""

from __future__ import annotations

import hashlib
import json
import posixpath
from dataclasses import dataclass, field


BLOCKED_SYSCALLS = frozenset(
    {"ptrace", "mount", "umount2", "unshare", "setuid", "setgid", "kexec_load", "init_module", "bpf"}
)

SECRET_PATH_PATTERNS = (
    "/.env",
    "/.ssh/",
    "/.aws/",
    "/etc/shadow",
    "/etc/passwd",
    "id_rsa",
    "credentials.json",
)


@dataclass(frozen=True)
class SyscallEvent:
    syscall: str
    path: str | None = None
    remote_host: str | None = None
    argv: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule: str
    event_digest: str


@dataclass
class SandboxPolicy:
    workspace_root: str = "/workspace"
    allowed_hosts: frozenset[str] = field(default_factory=lambda: frozenset({"registry.npmjs.org", "pypi.org"}))
    allow_network: bool = True


class AIControlMonitor:
    """Enforces unbypassable OS/container boundary policies independent of model intent."""

    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy
        self.audit_log: list[PolicyDecision] = []

    def _digest(self, event: SyscallEvent) -> str:
        raw = json.dumps(
            {
                "syscall": event.syscall,
                "path": event.path,
                "remote_host": event.remote_host,
                "argv": list(event.argv),
            },
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def evaluate(self, event: SyscallEvent) -> PolicyDecision:
        digest = self._digest(event)

        if event.syscall in BLOCKED_SYSCALLS:
            dec = PolicyDecision(False, f"blocked_privileged_syscall:{event.syscall}", digest)
            self.audit_log.append(dec)
            return dec

        if event.path is not None:
            norm = posixpath.normpath(event.path)
            lower = norm.lower()
            if any(pat in lower for pat in SECRET_PATH_PATTERNS):
                dec = PolicyDecision(False, f"blocked_secret_access:{norm}", digest)
                self.audit_log.append(dec)
                return dec
            if event.syscall in {"openat", "unlink", "rename", "chmod"} and not (
                norm == self.policy.workspace_root
                or norm.startswith(self.policy.workspace_root.rstrip("/") + "/")
                or norm.startswith("/tmp/")
                or norm.startswith("/usr/")
            ):
                dec = PolicyDecision(False, f"blocked_path_escape:{norm}", digest)
                self.audit_log.append(dec)
                return dec

        if event.remote_host is not None:
            if not self.policy.allow_network or event.remote_host not in self.policy.allowed_hosts:
                dec = PolicyDecision(False, f"blocked_egress:{event.remote_host}", digest)
                self.audit_log.append(dec)
                return dec

        dec = PolicyDecision(True, "allowed", digest)
        self.audit_log.append(dec)
        return dec
