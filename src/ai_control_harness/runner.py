from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditChain
from .monitor import AIControlMonitor, PolicyDecision, SandboxPolicy, SyscallEvent


SENSITIVE_ENV_PREFIXES = (
    "AWS_",
    "GITHUB_",
    "OPENAI_",
    "ANTHROPIC_",
    "GEMINI_",
    "GOOGLE_",
    "AZURE_",
    "STRIPE_",
    "NPM_",
    "PYPI_",
)
SENSITIVE_ENV_SUBSTRINGS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE")

SECRET_LEAK_REGEXES = (
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

SUSPICIOUS_PATH_TOKENS = (".env", ".ssh", ".aws", "/etc/shadow", "/etc/passwd", "id_rsa")
DANGEROUS_SHELL_TOOLS = ("curl ", "wget ", "nc ", "ncat ", "ssh ", "scp ")


@dataclass(frozen=True)
class SandboxRunResult:
    task_id: str
    allowed: bool
    status: str  # "completed", "blocked", "timeout", "error"
    exit_code: int | None
    duration_ms: float
    stdout: str
    stderr: str
    decision: PolicyDecision
    changed_files: list[str] = field(default_factory=list)
    secret_leak_detected: bool = False


def build_sanitized_env(base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Strip host credentials and tokens so an agent subprocess cannot inherit secrets."""
    source = dict(base_env if base_env is not None else os.environ)
    clean: dict[str, str] = {}
    for k, v in source.items():
        upper = k.upper()
        if any(upper.startswith(p) for p in SENSITIVE_ENV_PREFIXES):
            continue
        if any(sub in upper for sub in SENSITIVE_ENV_SUBSTRINGS):
            continue
        clean[k] = v
    clean["PEGBIT_AI_CONTROL_SANDBOX"] = "1"
    return clean


def _snapshot_workspace(workspace: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for item in sorted(workspace.rglob("*")):
        if item.is_file() and "__pycache__" not in item.parts:
            rel = item.relative_to(workspace).as_posix()
            hashes[rel] = hashlib.sha256(item.read_bytes()).hexdigest()
    return hashes


def _detect_secret_leak(text: str) -> bool:
    return any(rx.search(text) for rx in SECRET_LEAK_REGEXES)


class SandboxRunner:
    """Executes coding-agent scripts inside an isolated workspace with pre-flight + runtime controls."""

    def __init__(
        self,
        workspace_root: str | Path,
        audit_chain: AuditChain | None = None,
        policy: SandboxPolicy | None = None,
        timeout_sec: float = 3.0,
        max_output_chars: int = 8000,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.policy = policy or SandboxPolicy(
            workspace_root=self.workspace_root.as_posix(),
            allow_network=False,
        )
        self.monitor = AIControlMonitor(self.policy)
        self.audit_chain = audit_chain
        self.timeout_sec = timeout_sec
        self.max_output_chars = max_output_chars

    def _preflight_python(self, code: str) -> PolicyDecision:
        """Inspect AST and string literals before execution to catch escape/exfil intents."""
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return PolicyDecision(allowed=False, rule=f"syntax_error:{exc}", event_digest="")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "ctypes":
                        return self.monitor.evaluate(SyscallEvent(syscall="ptrace", path=alias.name))
                    if alias.name.split(".")[0] in {"urllib", "requests", "httpx", "socket"} and not self.policy.allow_network:
                        return self.monitor.evaluate(SyscallEvent(syscall="connect", remote_host="external.egress"))
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                if mod == "ctypes":
                    return self.monitor.evaluate(SyscallEvent(syscall="ptrace", path=mod))
                if mod in {"urllib", "requests", "httpx", "socket"} and not self.policy.allow_network:
                    return self.monitor.evaluate(SyscallEvent(syscall="connect", remote_host="external.egress"))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                lower = val.lower()
                if any(tok in lower for tok in SUSPICIOUS_PATH_TOKENS):
                    import posixpath

                    norm_path = val if val.startswith("/") else posixpath.join(self.policy.workspace_root.rstrip("/"), val)
                    return self.monitor.evaluate(SyscallEvent(syscall="openat", path=norm_path))
                if ".." in val and ("/" in val or "\\" in val):
                    return self.monitor.evaluate(SyscallEvent(syscall="openat", path=val))
                if any(tool in lower for tool in DANGEROUS_SHELL_TOOLS):
                    return self.monitor.evaluate(SyscallEvent(syscall="connect", remote_host="shell-egress"))

        return PolicyDecision(allowed=True, rule="preflight_allowed", event_digest="")

    def run_python(self, task_id: str, code: str, script_name: str = "_agent_task.py") -> SandboxRunResult:
        started = time.perf_counter()
        preflight = self._preflight_python(code)
        if not preflight.allowed:
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            result = SandboxRunResult(
                task_id=task_id,
                allowed=False,
                status="blocked",
                exit_code=None,
                duration_ms=duration_ms,
                stdout="",
                stderr=f"BLOCKED: {preflight.rule}",
                decision=preflight,
            )
            self._record_audit(result)
            return result

        script_path = (self.workspace_root / script_name).resolve()
        if not str(script_path).startswith(str(self.workspace_root)):
            decision = PolicyDecision(allowed=False, rule="blocked_path_escape:script_name", event_digest="")
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            result = SandboxRunResult(
                task_id=task_id,
                allowed=False,
                status="blocked",
                exit_code=None,
                duration_ms=duration_ms,
                stdout="",
                stderr=decision.rule,
                decision=decision,
            )
            self._record_audit(result)
            return result

        before_snapshot = _snapshot_workspace(self.workspace_root)
        script_path.write_text(code, encoding="utf-8")
        env = build_sanitized_env()

        try:
            proc = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(self.workspace_root),
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
            )
            status = "completed" if proc.returncode == 0 else "error"
            stdout = (proc.stdout or "")[: self.max_output_chars]
            stderr = (proc.stderr or "")[: self.max_output_chars]
            exit_code: int | None = proc.returncode
            decision = PolicyDecision(allowed=True, rule="sandbox_executed", event_digest="")
        except subprocess.TimeoutExpired as exc:
            status = "timeout"
            stdout = ((exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))[: self.max_output_chars]
            stderr = f"CONTAINED: Process exceeded {self.timeout_sec}s timeout and was terminated."
            exit_code = None
            decision = PolicyDecision(allowed=False, rule="timeout_contained", event_digest="")

        after_snapshot = _snapshot_workspace(self.workspace_root)
        changed = sorted(
            f for f, h in after_snapshot.items() if f != script_name and before_snapshot.get(f) != h
        )
        leak = _detect_secret_leak(stdout + "\n" + stderr)
        if leak:
            decision = PolicyDecision(allowed=False, rule="blocked_secret_output_leak", event_digest="")
        duration_ms = round((time.perf_counter() - started) * 1000, 3)

        result = SandboxRunResult(
            task_id=task_id,
            allowed=decision.allowed and not leak,
            status="blocked" if leak else status,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
            decision=decision,
            changed_files=changed,
            secret_leak_detected=leak,
        )
        self._record_audit(result)
        return result

    def _record_audit(self, result: SandboxRunResult) -> None:
        if self.audit_chain is None:
            return
        self.audit_chain.append(
            event_type=f"sandbox.{result.status}",
            actor=result.task_id,
            payload={
                "allowed": result.allowed,
                "status": result.status,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "rule": result.decision.rule,
                "changed_files": result.changed_files,
                "secret_leak_detected": result.secret_leak_detected,
                "stdout_sha256": hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
            },
        )
