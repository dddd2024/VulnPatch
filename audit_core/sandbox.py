"""PoC execution sandbox abstractions.

The process sandbox is a best-effort local executor with strict timeouts and an
isolated temporary working directory.  ``DockerSandbox`` adds container
isolation when Docker is available.  Callers can use ``SandboxFactory`` to
select the strongest available backend without importing implementation detail.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SandboxStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"
    SUSPICIOUS = "suspicious"


class PoCResultStatus(Enum):
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass
class ResourceUsage:
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    execution_time_ms: float = 0.0


@dataclass
class SandboxResult:
    status: SandboxStatus
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    artifacts: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    resource_usage: ResourceUsage = field(default_factory=ResourceUsage)
    poc_result: Optional[Dict[str, Any]] = None


@dataclass
class PoCVerificationResult:
    status: PoCResultStatus
    vuln_type: str
    confidence: float
    indicators: List[str]
    severity: str
    cwe: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""


class Sandbox:
    """Best-effort process-isolated PoC executor.

    This fallback does *not* claim to be an adversarial security boundary.  It
    exists for offline/local validation when Docker is unavailable.  Network
    policy is represented in metadata; strong network isolation is provided by
    :class:`DockerSandbox`.
    """

    SUPPORTED_LANGUAGES = {
        "python": {"ext": ".py", "cmd": [sys.executable]},
        "javascript": {"ext": ".js", "cmd": ["node"]},
        "java": {"ext": ".java", "cmd": ["javac", "java"]},
        "go": {"ext": ".go", "cmd": ["go", "run"]},
        "c": {"ext": ".c", "cmd": ["gcc"]},
        "cpp": {"ext": ".cpp", "cmd": ["g++"]},
    }

    def __init__(
        self,
        timeout: int = 60,
        max_memory_mb: int = 512,
        max_cpu_percent: int = 50,
        network_enabled: bool = False,
        enable_resource_monitor: bool = True,
    ) -> None:
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self.network_enabled = network_enabled
        self.enable_resource_monitor = enable_resource_monitor
        self.work_dir: Optional[Path] = None
        self._owns_work_dir = False

    async def __aenter__(self):
        self._ensure_work_dir()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def _ensure_work_dir(self) -> Path:
        if self.work_dir is None:
            self.work_dir = Path(tempfile.mkdtemp(prefix="vulnpatch_sandbox_"))
            self._owns_work_dir = True
        return self.work_dir

    def cleanup(self) -> None:
        if self._owns_work_dir and self.work_dir and self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
        self.work_dir = None
        self._owns_work_dir = False

    async def execute_poc(
        self,
        code: str,
        language: str,
        inputs: Optional[Dict[str, Any]] = None,
        target_file: Optional[str] = None,
    ) -> SandboxResult:
        start = time.time()
        work_dir = self._ensure_work_dir()
        logs = ["backend=process", f"network_enabled={self.network_enabled}"]
        language = language.lower()
        if language not in self.SUPPORTED_LANGUAGES:
            return SandboxResult(
                status=SandboxStatus.ERROR,
                stdout="",
                stderr=f"Unsupported language: {language}",
                exit_code=-1,
                execution_time=0.0,
                logs=logs,
            )

        try:
            if target_file and os.path.exists(target_file):
                dest = work_dir / Path(target_file).name
                shutil.copy2(target_file, dest)
                logs.append(f"target_copy={dest.name}")
            (work_dir / "inputs.json").write_text(
                json.dumps(inputs or {}, ensure_ascii=False), encoding="utf-8"
            )

            if language == "python":
                result = await self._execute_python(code)
            elif language == "javascript":
                result = await self._execute_javascript(code)
            elif language == "java":
                result = await self._execute_java(code)
            elif language == "go":
                result = await self._execute_go(code)
            else:
                result = await self._execute_c_cpp(code, language)

            result.execution_time = time.time() - start
            result.resource_usage.execution_time_ms = result.execution_time * 1000
            result.logs = logs + result.logs
            result.poc_result = self._parse_poc_output(result.stdout)
            return result
        except asyncio.TimeoutError:
            return SandboxResult(
                status=SandboxStatus.TIMEOUT,
                stdout="",
                stderr=f"Execution timed out after {self.timeout} seconds",
                exit_code=-1,
                execution_time=time.time() - start,
                logs=logs + ["timeout"],
            )
        except Exception as exc:
            logger.exception("Sandbox execution failed")
            return SandboxResult(
                status=SandboxStatus.ERROR,
                stdout="",
                stderr=str(exc),
                exit_code=-1,
                execution_time=time.time() - start,
                logs=logs + [f"error={type(exc).__name__}"],
            )

    async def _run(self, command: list[str], *, cwd: Path | None = None) -> SandboxResult:
        cwd = cwd or self._ensure_work_dir()
        started = time.time()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "VULNPATCH_SANDBOX": "1"},
            )
        except FileNotFoundError as exc:
            return SandboxResult(
                status=SandboxStatus.ERROR,
                stdout="",
                stderr=f"Runtime/compiler unavailable: {command[0]}",
                exit_code=-1,
                execution_time=time.time() - started,
                logs=[str(exc)],
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise
        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        status = SandboxStatus.SUCCESS if process.returncode == 0 else SandboxStatus.FAILED
        return SandboxResult(
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=int(process.returncode or 0),
            execution_time=time.time() - started,
            logs=["command=" + " ".join(command)],
        )

    async def _execute_python(self, code: str) -> SandboxResult:
        path = self._ensure_work_dir() / "poc.py"
        path.write_text(code, encoding="utf-8")
        return await self._run([sys.executable, path.name])

    async def _execute_javascript(self, code: str) -> SandboxResult:
        path = self._ensure_work_dir() / "poc.js"
        path.write_text(code, encoding="utf-8")
        return await self._run(["node", path.name])

    async def _execute_java(self, code: str) -> SandboxResult:
        work_dir = self._ensure_work_dir()
        match = re.search(r"\bpublic\s+class\s+([A-Za-z_]\w*)|\bclass\s+([A-Za-z_]\w*)", code)
        class_name = next((group for group in (match.groups() if match else ()) if group), "Main")
        source = work_dir / f"{class_name}.java"
        source.write_text(code, encoding="utf-8")
        compile_result = await self._run(["javac", source.name])
        if compile_result.status != SandboxStatus.SUCCESS:
            return compile_result
        run_result = await self._run(["java", class_name])
        run_result.logs = compile_result.logs + run_result.logs
        return run_result

    async def _execute_go(self, code: str) -> SandboxResult:
        path = self._ensure_work_dir() / "poc.go"
        path.write_text(code, encoding="utf-8")
        return await self._run(["go", "run", path.name])

    async def _execute_c_cpp(self, code: str, language: str) -> SandboxResult:
        work_dir = self._ensure_work_dir()
        ext = ".cpp" if language == "cpp" else ".c"
        compiler = "g++" if language == "cpp" else "gcc"
        source = work_dir / f"poc{ext}"
        binary = work_dir / ("poc.exe" if os.name == "nt" else "poc_bin")
        source.write_text(code, encoding="utf-8")
        compile_result = await self._run([compiler, source.name, "-o", binary.name])
        if compile_result.status != SandboxStatus.SUCCESS:
            return compile_result
        command = [str(binary)] if os.name != "nt" else [binary.name]
        run_result = await self._run(command)
        run_result.logs = compile_result.logs + run_result.logs
        return run_result

    @staticmethod
    def _parse_poc_output(stdout: str) -> Optional[Dict[str, Any]]:
        """Parse a JSON object emitted by a PoC template."""
        text = (stdout or "").strip()
        if not text:
            return None
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            pass
        # Templates may emit informational lines before the final JSON object.
        for start in [m.start() for m in re.finditer(r"\{", text)][::-1]:
            candidate = text[start:]
            try:
                data = json.loads(candidate)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                continue
        return None


class DockerSandbox(Sandbox):
    """Docker-backed executor with network and resource isolation."""

    IMAGE_BY_LANGUAGE = {
        "python": "python:3.11-slim",
        "javascript": "node:20-slim",
        "java": "eclipse-temurin:17-jdk",
        "go": "golang:1.22",
        "c": "gcc:14",
        "cpp": "gcc:14",
    }

    @staticmethod
    def is_docker_available() -> bool:
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, timeout=5, check=False
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    async def execute_poc(
        self,
        code: str,
        language: str,
        inputs: Optional[Dict[str, Any]] = None,
        target_file: Optional[str] = None,
    ) -> SandboxResult:
        language = language.lower()
        if language not in self.IMAGE_BY_LANGUAGE:
            return await super().execute_poc(code, language, inputs, target_file)
        if not self.is_docker_available():
            return SandboxResult(
                status=SandboxStatus.ERROR,
                stdout="",
                stderr="Docker is not available",
                exit_code=-1,
                execution_time=0.0,
                logs=["backend=docker"],
            )

        work_dir = self._ensure_work_dir()
        if target_file and os.path.exists(target_file):
            shutil.copy2(target_file, work_dir / Path(target_file).name)
        (work_dir / "inputs.json").write_text(json.dumps(inputs or {}, ensure_ascii=False), encoding="utf-8")

        if language == "python":
            filename, inner = "poc.py", ["python", "poc.py"]
        elif language == "javascript":
            filename, inner = "poc.js", ["node", "poc.js"]
        elif language == "go":
            filename, inner = "poc.go", ["go", "run", "poc.go"]
        elif language == "java":
            match = re.search(r"\bpublic\s+class\s+([A-Za-z_]\w*)|\bclass\s+([A-Za-z_]\w*)", code)
            class_name = next((g for g in (match.groups() if match else ()) if g), "Main")
            filename = f"{class_name}.java"
            inner = ["sh", "-lc", f"javac {filename} && java {class_name}"]
        else:
            ext = "cpp" if language == "cpp" else "c"
            compiler = "g++" if language == "cpp" else "gcc"
            filename = f"poc.{ext}"
            inner = ["sh", "-lc", f"{compiler} {filename} -o poc_bin && ./poc_bin"]
        (work_dir / filename).write_text(code, encoding="utf-8")

        network = "bridge" if self.network_enabled else "none"
        cpus = max(0.1, self.max_cpu_percent / 100.0)
        command = [
            "docker", "run", "--rm",
            "--network", network,
            "--memory", f"{max(64, self.max_memory_mb)}m",
            "--cpus", str(cpus),
            "--pids-limit", "128",
            "--security-opt", "no-new-privileges",
            "-v", f"{work_dir.resolve()}:/workspace:rw",
            "-w", "/workspace",
            self.IMAGE_BY_LANGUAGE[language],
            *inner,
        ]
        started = time.time()
        result = await self._run(command, cwd=work_dir)
        result.execution_time = time.time() - started
        result.logs.insert(0, "backend=docker")
        result.poc_result = self._parse_poc_output(result.stdout)
        return result


class SandboxFactory:
    """Select Docker isolation when available, otherwise process fallback."""

    @staticmethod
    async def create_sandbox_async(prefer_docker: bool = True, **kwargs: Any) -> Sandbox:
        if prefer_docker and DockerSandbox.is_docker_available():
            return DockerSandbox(**kwargs)
        return Sandbox(**kwargs)

    @staticmethod
    def create_sandbox(prefer_docker: bool = True, **kwargs: Any) -> Sandbox:
        if prefer_docker and DockerSandbox.is_docker_available():
            return DockerSandbox(**kwargs)
        return Sandbox(**kwargs)


def parse_poc_result(result: SandboxResult) -> PoCVerificationResult:
    """Convert low-level sandbox output into a structured verification result."""
    raw = result.poc_result or Sandbox._parse_poc_output(result.stdout) or {}
    vuln_type = str(raw.get("vuln_type") or "unknown")
    indicators = [str(item) for item in (raw.get("indicators") or [])]
    try:
        confidence = float(raw.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    severity = str(raw.get("severity") or "unknown")
    cwe = str(raw["cwe"]) if raw.get("cwe") else None

    if result.status in {SandboxStatus.ERROR, SandboxStatus.FAILED}:
        status = PoCResultStatus.ERROR
    elif result.status == SandboxStatus.TIMEOUT:
        status = PoCResultStatus.INCONCLUSIVE
    elif not raw:
        status = PoCResultStatus.INCONCLUSIVE
    elif indicators and confidence >= 0.70:
        status = PoCResultStatus.VERIFIED
    elif indicators:
        status = PoCResultStatus.SUSPICIOUS
    else:
        status = PoCResultStatus.FALSE_POSITIVE

    details = dict(raw)
    details.update({
        "sandbox_status": result.status.value,
        "exit_code": result.exit_code,
        "execution_time": result.execution_time,
    })
    if result.stderr:
        details["stderr"] = result.stderr[-2000:]
    return PoCVerificationResult(
        status=status,
        vuln_type=vuln_type,
        confidence=confidence,
        indicators=indicators,
        severity=severity,
        cwe=cwe,
        details=details,
        raw_output=result.stdout,
    )
