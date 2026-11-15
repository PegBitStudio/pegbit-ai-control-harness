# PegBit AI Control Harness

Practical sandboxing, container boundary generation, real-time execution monitoring, and tamper-evident audit logging for autonomous coding agents.

## Why AI Control?
Fine-tuning models to refuse unsafe requests breaks under prompt injection and long-horizon confusion. **AI Control** enforces hard, model-agnostic software boundaries around the agent:

1. **Kernel & Container Isolation (`SandboxContainerSpec`)**: Generates hardened seccomp-BPF JSON profiles and least-privilege Docker runtime arguments (`--cap-drop=ALL`, `--read-only`, `--network=none`, `--pids-limit`, non-root UID).
2. **Isolated Subprocess Sandbox (`SandboxRunner`)**: Strips host secrets from child environments, runs AST/static pre-flight boundary checks, executes agent code with strict timeouts inside an isolated workspace, and diffs workspace file hashes.
3. **Real-Time Policy Monitor (`AIControlMonitor`)**: Enforces workspace-scoped file boundaries, secret-path blocks (`.env`, `.ssh`, cloud credentials), egress allowlists, and dangerous syscall blocks (`ptrace`, `mount`, `bpf`, `kexec_load`, etc.).
4. **Witness-Linked Audit Chain (`AuditChain` & `verify_audit_log`)**: Appends every execution and policy decision to a SHA-256 hash-chained JSONL ledger that can be verified offline.

## Quickstart

```bash
python -m pytest -q
python benchmarks/run_control_suite.py
```
