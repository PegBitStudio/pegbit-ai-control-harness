from pathlib import Path

from ai_control_harness import (
    AIControlMonitor,
    AuditChain,
    SandboxContainerSpec,
    SandboxPolicy,
    SandboxRunner,
    SyscallEvent,
    build_sanitized_env,
    verify_audit_log,
)


def test_allows_workspace_read_and_pip_install():
    monitor = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    assert monitor.evaluate(SyscallEvent(syscall="openat", path="/workspace/app.py")).allowed
    assert monitor.evaluate(SyscallEvent(syscall="connect", remote_host="pypi.org")).allowed


def test_blocks_secret_env_file():
    monitor = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    decision = monitor.evaluate(SyscallEvent(syscall="openat", path="/workspace/.env"))
    assert not decision.allowed
    assert "blocked_secret_access" in decision.rule


def test_blocks_ssh_traversal():
    monitor = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    decision = monitor.evaluate(SyscallEvent(syscall="openat", path="/workspace/../.ssh/id_rsa"))
    assert not decision.allowed


def test_blocks_unauthorized_egress():
    monitor = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    decision = monitor.evaluate(SyscallEvent(syscall="connect", remote_host="evil.example"))
    assert not decision.allowed


def test_blocks_ptrace_syscall():
    monitor = AIControlMonitor(SandboxPolicy(workspace_root="/workspace"))
    decision = monitor.evaluate(SyscallEvent(syscall="ptrace"))
    assert not decision.allowed


def test_sanitized_env_strips_secrets():
    env = build_sanitized_env(
        {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-test-secret",
            "GITHUB_TOKEN": "ghp_secret",
            "AWS_SECRET_ACCESS_KEY": "secret",
        }
    )
    assert "PATH" in env
    assert env["PEGBIT_AI_CONTROL_SANDBOX"] == "1"
    assert "OPENAI_API_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_seccomp_and_docker_profile_generation():
    spec = SandboxContainerSpec()
    profile = spec.generate_seccomp_profile()
    assert profile["defaultAction"] == "SCMP_ACT_ALLOW"
    assert "ptrace" in profile["syscalls"][0]["names"]
    args = spec.generate_docker_args("/tmp/work", "/tmp/seccomp.json")
    assert "--cap-drop=ALL" in args
    assert "--read-only" in args
    assert "--network=none" in args
    assert "--security-opt=seccomp=/tmp/seccomp.json" in args


def test_sandbox_runner_executes_benign_and_blocks_adversarial(tmp_path: Path):
    audit_path = tmp_path / "audit.jsonl"
    chain = AuditChain(audit_path)
    runner = SandboxRunner(workspace_root=tmp_path / "ws", audit_chain=chain, timeout_sec=0.5)

    ok_res = runner.run_python("benign", "print('hello_sandbox')")
    assert ok_res.allowed
    assert ok_res.status == "completed"
    assert "hello_sandbox" in ok_res.stdout

    blocked_res = runner.run_python("exfil", "open('../.env').read()")
    assert not blocked_res.allowed
    assert blocked_res.status == "blocked"

    timeout_res = runner.run_python("hang", "while True:\n    pass")
    assert not timeout_res.allowed
    assert timeout_res.status == "timeout"

    valid, count, err = verify_audit_log(audit_path)
    assert valid, err
    assert count == 3

    # Tamper with line 2 and confirm offline verifier catches it
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("blocked", "completed")
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    valid_after, _, err_after = verify_audit_log(audit_path)
    assert not valid_after
    assert err_after is not None
