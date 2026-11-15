import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_control_harness import AIControlMonitor, SandboxPolicy, SyscallEvent


def test_allows_normal_workspace_coding_and_package_install() -> None:
    mon = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    assert mon.evaluate(SyscallEvent("openat", path="/workspace/src/app.py")).allowed
    assert mon.evaluate(SyscallEvent("connect", remote_host="pypi.org")).allowed


def test_blocks_prompt_injected_api_key_read() -> None:
    mon = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    dec = mon.evaluate(SyscallEvent("openat", path="/workspace/.env"))
    assert not dec.allowed
    assert "blocked_secret_access" in dec.rule


def test_blocks_ssh_key_traversal_escape() -> None:
    mon = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    dec = mon.evaluate(SyscallEvent("openat", path="/workspace/../../home/user/.ssh/id_rsa"))
    assert not dec.allowed
    assert "blocked_secret_access" in dec.rule


def test_blocks_unauthorized_network_exfiltration() -> None:
    mon = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    dec = mon.evaluate(SyscallEvent("connect", remote_host="evil-exfil.example.net"))
    assert not dec.allowed
    assert "blocked_egress" in dec.rule


def test_blocks_container_escape_syscalls() -> None:
    mon = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    for sc in ("unshare", "mount", "ptrace", "setuid"):
        dec = mon.evaluate(SyscallEvent(sc))
        assert not dec.allowed
        assert "blocked_privileged_syscall" in dec.rule
