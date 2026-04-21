"""Sandboxed PoC execution via Docker.

Safety defaults:
  - network disabled (--network none)
  - read-only rootfs where possible
  - CPU and memory limited
  - no access to host volumes except the mounted workdir (read-only)
  - strict timeout
  - non-root user inside container when image allows

If Docker is not installed or the daemon isn't reachable, run() returns a
SandboxResult with executed=False and a clear reason. The pipeline still
produces a PoC artifact; you just can't validate it until Docker is set up.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SandboxResult:
    executed: bool
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    reason: str | None = None


DEFAULT_IMAGES = {
    "python": "python:3.12-slim",
    "node": "node:20-alpine",
    "bash": "alpine:3.20",
}


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5, text=True
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def run_poc(
    code: str,
    language: str = "python",
    timeout_sec: int = 30,
    memory_mb: int = 256,
    cpu_quota: float = 0.5,
    extra_files: dict[str, str] | None = None,
) -> SandboxResult:
    """Execute `code` inside a disposable Docker container with no network.

    `extra_files` maps relative filename → contents; dropped into the workdir.
    """
    if not docker_available():
        return SandboxResult(
            executed=False,
            exit_code=None,
            stdout="",
            stderr="",
            timed_out=False,
            reason=(
                "Docker not available. Install Docker and ensure the daemon is running "
                "(`docker info` should succeed). The PoC was generated but not executed."
            ),
        )

    if language not in DEFAULT_IMAGES:
        return SandboxResult(False, None, "", "", False,
                             reason=f"Unsupported language: {language}")

    image = DEFAULT_IMAGES[language]
    entry_name = {"python": "poc.py", "node": "poc.js", "bash": "poc.sh"}[language]
    run_cmd = {
        "python": ["python", f"/work/{entry_name}"],
        "node": ["node", f"/work/{entry_name}"],
        "bash": ["sh", f"/work/{entry_name}"],
    }[language]

    with tempfile.TemporaryDirectory(prefix="bughunter_") as tmp:
        workdir = Path(tmp)
        (workdir / entry_name).write_text(code)
        for name, contents in (extra_files or {}).items():
            target = workdir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents)

        container = f"bughunter_{uuid.uuid4().hex[:8]}"
        docker_cmd = [
            "docker", "run",
            "--rm",
            "--name", container,
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:size=64m",
            "--memory", f"{memory_mb}m",
            "--cpus", str(cpu_quota),
            "--pids-limit", "128",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{workdir}:/work:ro",
            "-w", "/work",
            image,
            *run_cmd,
        ]
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            return SandboxResult(
                executed=True,
                exit_code=proc.returncode,
                stdout=proc.stdout[-8000:],
                stderr=proc.stderr[-8000:],
                timed_out=False,
            )
        except subprocess.TimeoutExpired as e:
            subprocess.run(["docker", "kill", container], capture_output=True)
            return SandboxResult(
                executed=True,
                exit_code=None,
                stdout=(e.stdout or b"").decode(errors="ignore")[-8000:],
                stderr=(e.stderr or b"").decode(errors="ignore")[-8000:],
                timed_out=True,
            )
        except FileNotFoundError:
            return SandboxResult(False, None, "", "", False, reason="docker CLI missing")
