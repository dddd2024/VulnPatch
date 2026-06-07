"""
PoC 执行编排器

统一入口，自动选择沙箱类型（Docker 或进程），支持批量 PoC 验证、结果聚合和报告生成。
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from audit_core.sandbox import (
    Sandbox,
    DockerSandbox,
    SandboxFactory,
    SandboxResult,
    SandboxStatus,
    PoCVerificationResult,
    PoCResultStatus,
    parse_poc_result,
)
from agents.poc_templates import (
    PoCTemplateLibrary,
    VulnType,
    Language,
    get_template_library,
)

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """执行模式"""
    AUTO = "auto"
    DOCKER = "docker"
    PROCESS = "process"


@dataclass
class PoCJob:
    """单个 PoC 验证任务"""
    job_id: str
    vuln_type: str
    language: str
    target_file: str
    target_code: Optional[str] = None
    extra_vars: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5  # 1-10, 数字越小优先级越高


@dataclass
class BatchResult:
    """批量验证结果"""
    total: int
    verified: int
    suspicious: int
    false_positive: int
    inconclusive: int
    error: int
    results: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    summary: Dict[str, Any] = field(default_factory=dict)


class PoCExecutor:
    """
    PoC 执行编排器

    功能：
    1. 自动选择沙箱类型（Docker 或进程）
    2. 支持批量 PoC 验证
    3. 结果聚合和报告
    4. 并发控制
    5. 进度回调
    """

    def __init__(
        self,
        execution_mode: ExecutionMode = ExecutionMode.AUTO,
        max_concurrent: int = 4,
        sandbox_config: Optional[Dict[str, Any]] = None,
        template_library: Optional[PoCTemplateLibrary] = None
    ):
        self.execution_mode = execution_mode
        self.max_concurrent = max_concurrent
        self.sandbox_config = sandbox_config or {
            "timeout": 60,
            "max_memory_mb": 512,
            "network_enabled": False,
            "enable_resource_monitor": True,
        }
        self.template_library = template_library or get_template_library()
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def execute_single(
        self,
        vuln_type: str,
        language: str,
        target_file: str,
        target_code: Optional[str] = None,
        extra_vars: Optional[Dict[str, Any]] = None
    ) -> PoCVerificationResult:
        """
        执行单个 PoC 验证

        Args:
            vuln_type: 漏洞类型
            language: 编程语言
            target_file: 目标文件路径
            target_code: 目标代码内容（可选，用于写入临时文件）
            extra_vars: 额外模板变量

        Returns:
            PoC 验证结果
        """
        # 渲染 PoC 代码
        poc_code = self.template_library.render_template(
            vuln_type=vuln_type,
            language=language,
            target_file=target_file,
            extra_vars=extra_vars
        )

        if not poc_code:
            logger.error(f"Failed to render PoC template for {vuln_type}:{language}")
            return PoCVerificationResult(
                status=PoCResultStatus.ERROR,
                vuln_type=vuln_type,
                confidence=0.0,
                indicators=["PoC template rendering failed"],
                severity="unknown",
                raw_output=""
            )

        # 选择沙箱
        sandbox = await self._create_sandbox()

        async with sandbox:
            sandbox_result = await sandbox.execute_poc(
                code=poc_code,
                language=language,
                inputs={"target_file": target_file, "vuln_type": vuln_type},
                target_file=target_file
            )

        # 解析结果
        return parse_poc_result(sandbox_result)

    async def execute_batch(
        self,
        jobs: List[PoCJob],
        progress_callback: Optional[Callable[[int, int, PoCJob, PoCVerificationResult], None]] = None
    ) -> BatchResult:
        """
        批量执行 PoC 验证

        Args:
            jobs: PoC 任务列表
            progress_callback: 进度回调函数 (current, total, job, result)

        Returns:
            批量验证结果
        """
        start_time = time.time()
        total = len(jobs)

        # 按优先级排序
        sorted_jobs = sorted(jobs, key=lambda j: j.priority)

        # 创建任务
        tasks = []
        for job in sorted_jobs:
            task = self._execute_job_with_semaphore(job, progress_callback, total)
            tasks.append(task)

        # 并发执行
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 聚合结果
        batch_result = BatchResult(total=total, verified=0, suspicious=0, false_positive=0, inconclusive=0, error=0)

        for i, result in enumerate(results):
            job = sorted_jobs[i]
            if isinstance(result, Exception):
                logger.error(f"Job {job.job_id} failed: {result}")
                batch_result.error += 1
                batch_result.results.append({
                    "job_id": job.job_id,
                    "vuln_type": job.vuln_type,
                    "status": "error",
                    "error": str(result),
                    "result": None
                })
            else:
                verification_result: PoCVerificationResult = result
                batch_result.results.append({
                    "job_id": job.job_id,
                    "vuln_type": job.vuln_type,
                    "status": verification_result.status.value,
                    "confidence": verification_result.confidence,
                    "severity": verification_result.severity,
                    "cwe": verification_result.cwe,
                    "indicators": verification_result.indicators,
                    "result": verification_result
                })

                # 统计
                if verification_result.status == PoCResultStatus.VERIFIED:
                    batch_result.verified += 1
                elif verification_result.status == PoCResultStatus.SUSPICIOUS:
                    batch_result.suspicious += 1
                elif verification_result.status == PoCResultStatus.FALSE_POSITIVE:
                    batch_result.false_positive += 1
                elif verification_result.status == PoCResultStatus.INCONCLUSIVE:
                    batch_result.inconclusive += 1
                else:
                    batch_result.error += 1

        batch_result.execution_time = time.time() - start_time
        batch_result.summary = self._generate_summary(batch_result)

        logger.info(
            f"Batch execution complete: {batch_result.verified} verified, "
            f"{batch_result.suspicious} suspicious, {batch_result.false_positive} false positive, "
            f"{batch_result.inconclusive} inconclusive, {batch_result.error} errors"
        )

        return batch_result

    async def _execute_job_with_semaphore(
        self,
        job: PoCJob,
        progress_callback: Optional[Callable],
        total: int
    ) -> PoCVerificationResult:
        """使用信号量限制并发执行单个任务"""
        async with self._semaphore:
            result = await self.execute_single(
                vuln_type=job.vuln_type,
                language=job.language,
                target_file=job.target_file,
                target_code=job.target_code,
                extra_vars=job.extra_vars
            )

            if progress_callback:
                try:
                    # 计算当前进度
                    completed = sum(1 for r in [] if r is not None)  # 简化处理
                    progress_callback(completed, total, job, result)
                except Exception as e:
                    logger.debug(f"Progress callback error: {e}")

            return result

    def _generate_summary(self, batch_result: BatchResult) -> Dict[str, Any]:
        """生成执行摘要"""
        if batch_result.total == 0:
            return {"message": "No jobs executed"}

        verification_rate = (batch_result.verified + batch_result.suspicious) / batch_result.total
        accuracy = batch_result.verified / max(1, batch_result.verified + batch_result.false_positive)

        return {
            "total_jobs": batch_result.total,
            "verification_rate": round(verification_rate, 2),
            "accuracy": round(accuracy, 2),
            "avg_time_per_job": round(batch_result.execution_time / batch_result.total, 2),
            "total_execution_time": round(batch_result.execution_time, 2),
            "distribution": {
                "verified": batch_result.verified,
                "suspicious": batch_result.suspicious,
                "false_positive": batch_result.false_positive,
                "inconclusive": batch_result.inconclusive,
                "error": batch_result.error
            }
        }

    async def _create_sandbox(self) -> Sandbox | DockerSandbox:
        """创建沙箱实例"""
        if self.execution_mode == ExecutionMode.DOCKER:
            if DockerSandbox.is_docker_available():
                return DockerSandbox(**self.sandbox_config)
            else:
                logger.warning("Docker requested but not available, falling back to process sandbox")
                return Sandbox(**self.sandbox_config)
        elif self.execution_mode == ExecutionMode.PROCESS:
            return Sandbox(**self.sandbox_config)
        else:  # AUTO
            return await SandboxFactory.create_sandbox_async(
                prefer_docker=True,
                **self.sandbox_config
            )

    def generate_report(self, batch_result: BatchResult, format: str = "dict") -> Any:
        """
        生成验证报告

        Args:
            batch_result: 批量验证结果
            format: 报告格式 (dict, json, markdown)

        Returns:
            格式化的报告
        """
        if format == "dict":
            return {
                "summary": batch_result.summary,
                "results": [
                    {
                        "job_id": r["job_id"],
                        "vuln_type": r["vuln_type"],
                        "status": r["status"],
                        "confidence": r.get("confidence"),
                        "severity": r.get("severity"),
                        "cwe": r.get("cwe"),
                        "indicators": r.get("indicators", [])
                    }
                    for r in batch_result.results
                ]
            }
        elif format == "markdown":
            lines = [
                "# PoC 验证报告",
                "",
                f"**总任务数**: {batch_result.total}",
                f"**执行时间**: {batch_result.execution_time:.2f}s",
                f"**验证率**: {batch_result.summary.get('verification_rate', 0):.0%}",
                "",
                "## 结果分布",
                "",
                f"- 已验证 (VERIFIED): {batch_result.verified}",
                f"- 可疑 (SUSPICIOUS): {batch_result.suspicious}",
                f"- 误报 (FALSE_POSITIVE): {batch_result.false_positive}",
                f"- 不确定 (INCONCLUSIVE): {batch_result.inconclusive}",
                f"- 错误 (ERROR): {batch_result.error}",
                "",
                "## 详细结果",
                "",
            ]

            for r in batch_result.results:
                lines.append(f"### {r['job_id']} - {r['vuln_type']}")
                lines.append(f"- **状态**: {r['status']}")
                lines.append(f"- **置信度**: {r.get('confidence', 'N/A')}")
                lines.append(f"- **严重级别**: {r.get('severity', 'N/A')}")
                lines.append(f"- **CWE**: {r.get('cwe', 'N/A')}")
                if r.get("indicators"):
                    lines.append("- **指标**:")
                    for indicator in r["indicators"]:
                        lines.append(f"  - {indicator}")
                lines.append("")

            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def list_available_templates(self) -> List[Dict[str, str]]:
        """列出所有可用模板"""
        return self.template_library.list_templates()

    def is_vuln_type_supported(self, vuln_type: str) -> bool:
        """检查漏洞类型是否支持"""
        try:
            VulnType(vuln_type)
            return True
        except ValueError:
            return False

    def is_language_supported(self, language: str) -> bool:
        """检查语言是否支持"""
        try:
            Language(language)
            return True
        except ValueError:
            return False


class PoCExecutorBuilder:
    """
    PoCExecutor 构建器

    提供流式 API 构建 PoCExecutor 实例。
    """

    def __init__(self):
        self._execution_mode = ExecutionMode.AUTO
        self._max_concurrent = 4
        self._sandbox_config: Dict[str, Any] = {}
        self._template_library: Optional[PoCTemplateLibrary] = None

    def with_execution_mode(self, mode: ExecutionMode) -> "PoCExecutorBuilder":
        """设置执行模式"""
        self._execution_mode = mode
        return self

    def with_max_concurrent(self, max_concurrent: int) -> "PoCExecutorBuilder":
        """设置最大并发数"""
        self._max_concurrent = max_concurrent
        return self

    def with_timeout(self, timeout: int) -> "PoCExecutorBuilder":
        """设置超时时间"""
        self._sandbox_config["timeout"] = timeout
        return self

    def with_max_memory(self, max_memory_mb: int) -> "PoCExecutorBuilder":
        """设置最大内存"""
        self._sandbox_config["max_memory_mb"] = max_memory_mb
        return self

    def with_network(self, enabled: bool) -> "PoCExecutorBuilder":
        """设置网络开关"""
        self._sandbox_config["network_enabled"] = enabled
        return self

    def with_template_library(self, library: PoCTemplateLibrary) -> "PoCExecutorBuilder":
        """设置模板库"""
        self._template_library = library
        return self

    def build(self) -> PoCExecutor:
        """构建 PoCExecutor 实例"""
        return PoCExecutor(
            execution_mode=self._execution_mode,
            max_concurrent=self._max_concurrent,
            sandbox_config=self._sandbox_config or None,
            template_library=self._template_library
        )
