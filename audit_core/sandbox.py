"""
Sandbox - PoC执行沙箱环境
第六轮改进：增强沙箱实现，添加 Docker 容器执行支持、多语言支持、网络隔离、资源监控和 PoC 结果解析
"""

import asyncio
import logging
import tempfile
import shutil
import os
import time
import json
import platform
from typing import Dict, Optional, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import subprocess

logger = logging.getLogger(__name__)


class SandboxStatus(Enum):
    """沙箱执行状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"
    SUSPICIOUS = "suspicious"


class PoCResultStatus(Enum):
    """PoC 验证结果状态"""
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass
class ResourceUsage:
    """资源使用统计"""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    execution_time_ms: float = 0.0


@dataclass
class SandboxResult:
    """沙箱执行结果"""
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
    """PoC 验证结果"""
    status: PoCResultStatus
    vuln_type: str
    confidence: float
    indicators: List[str]
    severity: str
    cwe: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""


class Sandbox:
    """
    安全的PoC执行沙箱（进程隔离模式）

    功能：
    1. 在隔离环境中执行PoC代码
    2. 限制资源使用（CPU、内存、时间）
    3. 捕获输出和日志
    4. 安全清理
    5. 支持多语言执行
    6. 资源监控
    7. PoC 结果解析
    """

    SUPPORTED_LANGUAGES = {
        "python": {"ext": ".py", "cmd": ["python"]},
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
        enable_resource_monitor: bool = True
    ):
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self.network_enabled = network_enabled
        self.enable_resource_monitor = enable_resource_monitor
        self.work_dir: Optional[Path] = None

    async def __aenter__(self):
        """创建临时工作目录"""
        self.work_dir = Path(tempfile.mkdtemp(prefix="vulnpatch_sandbox_"))
        logger.info(f"Sandbox created at {self.work_dir}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """清理工作目录"""
        if self.work_dir and self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
            logger.info(f"Sandbox cleaned up: {self.work_dir}")

    async def execute_poc(
        self,
        code: str,
        language: str,
        inputs: Optional[Dict[str, Any]] = None,
        target_file: Optional[str] = None
    ) -> SandboxResult:
        """
        执行PoC代码

        Args:
            code: PoC代码
            language: 编程语言 (python, java, javascript, go, c, cpp)
            inputs: 输入参数
            target_file: 目标代码文件路径（用于 PoC 分析）

        Returns:
            执行结果
        """
        start_time = time.time()
        logs = []

        try:
            # 准备执行环境
            if language not in self.SUPPORTED_LANGUAGES:
                return SandboxResult(
                    status=SandboxStatus.ERROR,
                    stdout="",
                    stderr=f"Unsupported language: {language}. Supported: {list(self.SUPPORTED_LANGUAGES.keys())}",
                    exit_code=-1,
                    execution_time=0,
                    artifacts={},
                    logs=[f"Error: Unsupported language {language}"]
                )

            # 复制目标文件到沙箱（如果提供）
            if target_file and os.path.exists(target_file):
                dest = self.work_dir / Path(target_file).name
                shutil.copy2(target_file, dest)
                logs.append(f"Copied target file to sandbox: {dest}")

            # 写入输入数据
            input_file = self.work_dir / "inputs.json"
            input_file.write_text(json.dumps(inputs or {}), encoding='utf-8')

            # 执行对应语言
            if language == "python":
                result = await self._execute_python(code, inputs or {})
            elif language == "javascript":
                result = await self._execute_javascript(code, inputs or {})
            elif language == "java":
                result = await self._execute_java(code, inputs or {})
            elif language == "go":
                result = await self._execute_go(code, inputs or {})
            elif language in ("c", "cpp"):
                result = await self._execute_c_cpp(code, inputs or {}, language)
            else:
                return SandboxResult(
                    status=SandboxStatus.ERROR,
                    stdout="",
                    stderr=f"Execution not implemented for: {language}",
                    exit_code=-1,
                    execution_time=0,
                    artifacts={},
                    logs=logs + [f"Error: Execution not implemented for {language}"]
                )

            execution_time = time.time() - start_time
            result.execution_time = execution_time
            result.logs = logs + result.logs

            # 解析 PoC 结果
            result.poc_result = self._parse_poc_output(result.stdout)
            if result.poc_result:
                result.logs.append("PoC output parsed successfully")

            return result

        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            logger.warning(f"Sandbox execution timed out after {self.timeout}s")
            return SandboxResult(
                status=SandboxStatus.TIMEOUT,
                stdout="",
                stderr=f"Execution timed out after {self.timeout} seconds",
                exit_code=-1,
                execution_time=execution_time,
                artifacts={},
                logs=logs + [f"Timeout after {self.timeout}s"]
            )
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Sandbox execution error: {e}")
            return SandboxResult(
                status=SandboxStatus.ERROR,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time=execution_time,
                artifacts={},
                logs=logs + [f"Error: {str(e)}"]
            )

    def _parse_poc_output(self, stdout: str) -> Optional[Dict[str, Any]]:
        """
        解析 PoC 输出，提取结�