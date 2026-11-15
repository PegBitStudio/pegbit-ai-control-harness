# PegBit AI Control Harness: Sandboxing & Syscall Monitoring for Autonomous Coding Agents

[![CI](https://github.com/PegBitStudio/pegbit-ai-control-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/PegBitStudio/pegbit-ai-control-harness/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **PegBit Studio · Applied AI Systems Research** (`PegBit Technologies Ltd`)  
> Research Inquiry: [pegbitstudio.com/research#ai-control](https://www.pegbitstudio.com/research#ai-control)

## Research Problem & Motivation

Autonomous coding agents now write, execute, and iterate on code for hours. Relying on model alignment or RLHF "politeness" fails under prompt injection or goal-misalignment: a compromised agent can read `.env` API keys, download malicious binaries, or attempt container/privilege escapes.

Building on **AI Control**, this project replaces behavioral trust with **hard, unbreakable software boundaries**:
- **Container & Filesystem Isolation:** Explicit workspace allowlists and secret-path deny boundaries.
- **Real-Time Syscall & Egress Monitoring:** Inspecting `execve`, `openat`, `connect`, and privileged syscalls (`ptrace`, `mount`, `unshare`, `setuid`) before execution.
- **Open Testing Harness & Security Standards:** A reproducible adversarial suite simulating prompt-injected coding agents so labs and regulators can verify boundary enforcement before granting production access.

## Quickstart

```bash
python -m pytest -v
python benchmarks/run_control_suite.py
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
