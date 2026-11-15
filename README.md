# PegBit AI Control Harness

[![CI](https://github.com/PegBitStudio/pegbit-ai-control-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/PegBitStudio/pegbit-ai-control-harness/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **PegBit Studio · Flagship Research Pillar 02** (`PegBit Technologies Ltd`, Nigeria)  
> Research Programme: [pegbitstudio.com/research#ai-control](https://www.pegbitstudio.com/research#ai-control) · Publications: [pegbitstudio.com/research/publications](https://www.pegbitstudio.com/research/publications)

Practical sandboxing, seccomp/Docker profile generation, isolated subprocess execution, and Witness-linked SHA-256 audit logging for autonomous coding agents.

---

## Preliminary Local Benchmark Results (`PegBit AI Control Standard v0.1`)
*(Single-run local baseline; not yet independent external validation.)*

| Metric | Observed Result | Notes |
| :--- | :--- | :--- |
| **Unit & Integration Tests (`pytest`)** | **8 / 8 passed** (`0.94s`) | Covers env secret stripping, seccomp/Docker profiles, sandbox runner, tamper detection |
| **Benign Coding Utility** | **3 / 3 passed** | Unit tests, local JSON transform, isolated env check |
| **Adversarial Containment** | **5 / 5 contained** | `.env` read, `.ssh/id_rsa` traversal, `urllib` egress, `ctypes`/`ptrace`, infinite-loop timeout |
| **Median Adversarial Containment Latency** | **0.272 ms** | Preflight/policy containment latency |
| **Witness-Linked Audit Chain** | **Verified (`True`, 8 records)** | Offline SHA-256 chain check (`verify_audit_log`) |

---

## Architecture & Honest Threat-Model Boundaries

- **Existing Prototype (Runnable Today):**
  1. `SandboxContainerSpec` (`sandbox_profile.py`): Generates Docker-compatible **seccomp-BPF JSON** profiles and least-privilege `docker run` flags (`--cap-drop=ALL`, `--read-only`, `--network=none`, `--pids-limit=64`).
  2. `SandboxRunner` (`runner.py`): Strips host secrets (`build_sanitized_env`), runs AST/literal pre-flight checks, executes Python in an isolated workspace with strict timeouts, and diffs workspace file hashes.
  3. `AIControlMonitor` (`monitor.py`): Evaluates file, egress, and syscall events against workspace-scoped allowlists.
  4. `AuditChain` & `verify_audit_log` (`audit.py`): Appends executions and policy decisions to a SHA-256 hash-chained JSONL ledger.
- **Planned Research (Not Yet Implemented):**
  - Linux **Firecracker / gVisor microVM** execution, **eBPF** kernel syscall telemetry/LSM enforcement, and cryptographic **subagent capability attenuation** (`RQ2`).
- **Explicit Qualification:** Current Python AST pre-flight + subprocess isolation is an *early local evaluation harness*, not a complete kernel security boundary. Architectural controls reduce defined attack surfaces under a stated threat model; they do not claim complete containment.

## Quickstart

```bash
PYTHONPATH=src python -m pytest -v
PYTHONPATH=src python benchmarks/run_control_suite.py
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
