from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .monitor import BLOCKED_SYSCALLS


@dataclass(frozen=True)
class SandboxContainerSpec:
    """Hardened container and kernel-level isolation profile for coding agents."""

    image: str = "python:3.12-slim"
    workspace_mount: str = "/workspace"
    memory_limit: str = "512m"
    cpu_limit: str = "1.0"
    pids_limit: int = 64
    network_mode: str = "none"
    read_only_rootfs: bool = True
    uid_gid: str = "65534:65534"
    blocked_syscalls: tuple[str, ...] = field(default_factory=lambda: tuple(sorted(BLOCKED_SYSCALLS)))

    def generate_seccomp_profile(self) -> dict[str, Any]:
        """Generate a Docker-compatible seccomp-BPF JSON profile blocking dangerous syscalls."""
        return {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
            "syscalls": [
                {
                    "names": list(self.blocked_syscalls),
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                }
            ],
        }

    def generate_seccomp_json(self, indent: int = 2) -> str:
        return json.dumps(self.generate_seccomp_profile(), indent=indent)

    def generate_docker_args(self, host_workspace: str, seccomp_path: str | None = None) -> list[str]:
        """Return least-privilege `docker run` arguments implementing AI Control boundaries."""
        args = [
            "docker",
            "run",
            "--rm",
            "--init",
            f"--user={self.uid_gid}",
            f"--network={self.network_mode}",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
            f"--pids-limit={self.pids_limit}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
            "-v",
            f"{host_workspace}:{self.workspace_mount}:rw",
            "-w",
            self.workspace_mount,
        ]
        if self.read_only_rootfs:
            args.append("--read-only")
        if seccomp_path:
            args.append(f"--security-opt=seccomp={seccomp_path}")
        args.append(self.image)
        return args
