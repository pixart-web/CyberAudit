#!/usr/bin/env python3
"""Produce a sanitized, deterministic inventory of the readiness workstation."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "artifacts" / "readiness" / "environment-check.json"

TOOLS: tuple[tuple[str, bool, tuple[str, ...]], ...] = (
    ("python3", True, ("python3", "--version")),
    ("node", True, ("node", "--version")),
    ("pnpm", True, ("pnpm", "--version")),
    ("psql", True, ("psql", "--version")),
    ("redis-cli", True, ("redis-cli", "--version")),
    ("docker", True, ("docker", "--version")),
    ("docker-compose", True, ("docker-compose", "version")),
    ("kubectl", True, ("kubectl", "version", "--client=true")),
    ("helm", True, ("helm", "version", "--short")),
    ("kind", True, ("kind", "version")),
    ("vault", True, ("vault", "version")),
    ("mc", True, ("mc", "--version")),
    ("syft", True, ("syft", "version")),
    ("cosign", True, ("cosign", "version", "--json")),
    ("trivy", True, ("trivy", "--version")),
    ("k6", True, ("k6", "version")),
    ("openssl", True, ("openssl", "version")),
    ("gh", True, ("gh", "--version")),
    ("git", True, ("git", "--version")),
    ("curl", True, ("curl", "--version")),
    ("jq", True, ("jq", "--version")),
)


def _version(command: tuple[str, ...]) -> str | None:
    executable = shutil.which(command[0])
    if executable is None:
        return None
    try:
        clean_env = os.environ.copy()
        clean_env.update(
            {
                "MC_CONFIG_DIR": "/tmp/cyberaudit-readiness-mc",
                "NO_COLOR": "1",
            }
        )
        result = subprocess.run(
            (executable, *command[1:]),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=clean_env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "installed; version unavailable"
    if result.returncode != 0:
        return None
    if command[0] == "cosign":
        try:
            return str(json.loads(result.stdout)["gitVersion"])
        except (json.JSONDecodeError, KeyError, TypeError):
            return "installed; version unavailable"
    output = (result.stdout or result.stderr).strip().splitlines()
    meaningful = next(
        (line.strip() for line in output if "version" in line.lower()),
        None,
    ) or next(
        (line.strip() for line in output if line.strip() and set(line.strip()) != {"_"}),
        None,
    )
    return meaningful[:240] if meaningful else "installed; version unavailable"


def _memory_bytes() -> int | None:
    sysctl = shutil.which("sysctl") or Path("/usr/sbin/sysctl")
    if sys.platform == "darwin" and Path(sysctl).exists():
        result = subprocess.run(
            (str(sysctl), "-n", "hw.memsize"),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip().isdigit():
            return int(result.stdout.strip())
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    return None


def collect() -> dict[str, Any]:
    tools = []
    for name, required, command in TOOLS:
        version = _version(command)
        installed = version is not None
        tools.append(
            {
                "tool": name,
                "required": required,
                "installed": installed,
                "version": version,
                "status": "ready" if installed else "blocking",
            }
        )
    disk = shutil.disk_usage(ROOT)
    return {
        "schema_version": "1.0",
        "environment": {
            "operating_system": platform.system(),
            "operating_system_release": platform.release(),
            "architecture": platform.machine(),
            "cpu_count": os.cpu_count(),
            "memory_bytes": _memory_bytes(),
            "workspace_disk_total_bytes": disk.total,
            "workspace_disk_free_bytes": disk.free,
        },
        "tools": tools,
        "summary": {
            "ready": sum(item["status"] == "ready" for item in tools),
            "blocking": sum(item["status"] == "blocking" for item in tools),
        },
    }


def main() -> int:
    output = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    report = collect()
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 1 if report["summary"]["blocking"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
