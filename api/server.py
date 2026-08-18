"""
VulnPatch FastAPI Server - AI 安全审计平台后端服务

提供完整的 REST API 接口，支持代码扫描、漏洞查询、证据链查看和报告生成。
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from env_config import load_project_env
load_project_env()

from api.schemas import ScanRequest, ScanResponse, RepairRequest, RepairResponse
from api.auth import router as auth_router
from api.competition_demo import router as competition_demo_router
from api.state import audit_state
from api.database import init_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用启动/关闭钩子"""
    init_db()
    logger.info("VulnPatch API server started")
    yield
    logger.info("VulnPatch API server shutting down")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VulnPatch - AI 安全审计平台",
    description="自主多模型调度与案例库自进化的漏洞修复辅助系统",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS - 允许前端跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册认证与比赛演示路由
app.include_router(auth_router, prefix="/api")
app.include_router(competition_demo_router, prefix="/api")


# ---------------------------------------------------------------------------
# Helper: 运行扫描流水线
# ---------------------------------------------------------------------------

def _run_scan_pipeline(request: ScanRequest) -> dict[str, Any]:
    """Run the formal AuditOrchestrator pipeline and persist the AuditResult."""
    from audit_core.orchestrator import AuditOrchestrator

    language = request.language
    if request.input_type == "code" and (not language or language == "auto"):
        language = "python"
    orchestrator = AuditOrchestrator(use_pipeline=True)
    result = orchestrator.scan(
        input_type=request.input_type,
        code=request.code,
        repo_path=request.repo_path,
        repo_url=request.repo_url,
        language=language,
    )
    if request.input_type != "code" and result.summary.total_code_units == 0:
        raise HTTPException(status_code=400, detail="未找到可扫描的代码文件")
    scan_id = audit_state.create_session(result)
    return {
        "scan_id": scan_id,
        "summary": result.summary.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "evidence": [e.model_dump(mode="json") for e in result.evidence],
        "agent_logs": [l.model_dump(mode="json") for l in result.agent_logs],
        "cve_candidates": list(result.cve_candidates),
    }


# ===========================================================================
# API 路由
# ===========================================================================

@app.get("/health", include_in_schema=False)
@app.get("/api/health")
def health_check():
    """健康检查"""
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse, response_model_exclude={"cve_candidates"}, include_in_schema=False)
@app.post("/api/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    """
    主扫描端点 - 执行完整安全审计流水线

    支持三种输入方式:
    - code: 直接提交代码片段
    - path: 指定本地仓库路径
    - github: 提供 GitHub 仓库 URL
    """
    # 输入验证
    if request.input_type == "code" and not request.code:
        raise HTTPException(status_code=400, detail="代码内容不能为空")
    if request.input_type == "path" and not request.repo_path:
        raise HTTPException(status_code=400, detail="仓库路径不能为空")
    if request.input_type == "github" and not request.repo_url:
        raise HTTPException(status_code=400, detail="GitHub URL 不能为空")

    try:
        return _run_scan_pipeline(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Scan failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"扫描失败: {str(e)}")


def _repair_context(finding, code_unit, request: RepairRequest):
    from llm.routing_models import RoutingContext
    confidence = {"high": 0.95, "medium": 0.65, "low": 0.35}.get((finding.confidence or "").lower(), 0.5)
    cwe = (finding.cwe or "").upper()
    is_simple_sql = cwe == "CWE-89" and confidence >= 0.85
    required = ["deterministic_fix"] if is_simple_sql else ["patch_generation"]
    verification_requirements = ["sql_parameterization", "anti_bypass"] if cwe == "CWE-89" else ["anti_bypass"]
    return RoutingContext(
        finding_id=finding.id,
        cwe=finding.cwe,
        vulnerability_type=finding.type,
        language=code_unit.language,
        complexity="low" if is_simple_sql else "high",
        confidence=confidence,
        sensitivity=request.sensitivity,
        file_count=1,
        cross_file=False,
        required_capabilities=required,
        metadata={"source": "product_repair", "verification_requirements": verification_requirements},
    )


@app.post("/api/repair", response_model=RepairResponse)
def repair_finding(request: RepairRequest):
    """Repair one finding from a persisted scan through the shared RepairPipeline."""
    from audit_core.repair_pipeline import RepairPipeline

    result = audit_state.get_by_id(request.scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found")
    finding = next((item for item in result.findings if item.id == request.finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {request.finding_id} not found")
    evidence = next((item for item in result.evidence if item.finding.id == finding.id), None)
    code_unit = evidence.code_unit if evidence is not None else None
    if code_unit is None:
        raise HTTPException(
            status_code=409,
            detail="This scan predates repair-ready evidence. Re-run the scan to retain the source CodeUnit.",
        )

    execution = RepairPipeline().run(
        finding=finding,
        code_unit=code_unit,
        context=_repair_context(finding, code_unit, request),
        scan_id=request.scan_id,
        variant=request.repair_variant,
        framework="generic",
        case_metadata={"demo": False, "source": "product_repair", "scan_id": request.scan_id},
    )
    return {
        "run_id": execution["run_id"],
        "finding": finding.model_dump(mode="json"),
        "routing_decision": execution["routing_decision"].model_dump(mode="json"),
        "historical_matches": [m.model_dump(mode="json") for m in execution["historical_matches"]],
        "patch": execution["patch"].model_dump(mode="json"),
        "verification": execution["verification"].model_dump(mode="json"),
        "verification_log": execution["verification_log"].model_dump(mode="json"),
        "evolved_case": execution["evolved_case"].model_dump(mode="json"),
    }


@app.get("/findings", include_in_schema=False)
@app.get("/api/findings")
def get_findings(scan_id: Optional[str] = Query(None)):
    """获取漏洞发现列表"""
    result = _get_result(scan_id)
    if result is None:
        return []
    return [f.model_dump(mode="json") for f in result.findings]


@app.get("/evidence", include_in_schema=False)
@app.get("/api/evidence")
def get_evidence(scan_id: Optional[str] = Query(None)):
    """获取证据包列表"""
    result = _get_result(scan_id)
    if result is None:
        return []
    return [e.model_dump(mode="json") for e in result.evidence]


@app.get("/agents/logs", include_in_schema=False)
@app.get("/api/agents/logs")
def get_agent_logs(scan_id: Optional[str] = Query(None)):
    """获取 Agent 执行日志"""
    result = _get_result(scan_id)
    if result is None:
        return []
    return [l.model_dump(mode="json") for l in result.agent_logs]


@app.get("/report/json", include_in_schema=False)
@app.get("/api/report/json")
def get_report_json(scan_id: Optional[str] = Query(None)):
    """获取 JSON 格式的完整审计报告"""
    result = _get_result(scan_id)
    if result is None:
        return {"summary": {}, "findings": [], "evidence": [], "agent_logs": []}
    return result.model_dump(mode="json")


@app.get("/report/markdown", include_in_schema=False)
@app.get("/api/report/markdown")
def get_report_markdown(scan_id: Optional[str] = Query(None)):
    """获取 Markdown 格式的审计报告"""
    result = _get_result(scan_id)
    if result is None:
        return "# Audit Report\n\nNo scan data available."

    from report.markdown_report import build_markdown_report
    content = build_markdown_report(result)
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=content, media_type="text/markdown; charset=utf-8")


@app.get("/report/html", include_in_schema=False)
@app.get("/api/report/html")
def get_report_html(scan_id: Optional[str] = Query(None)):
    """获取 HTML 格式的审计报告"""
    result = _get_result(scan_id)
    if result is None:
        return "<html><body><h1>No scan data available.</h1></body></html>"

    from report.html_report import build_html_report
    content = build_html_report(result)
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=content)


@app.get("/scans/{scan_id}/findings", include_in_schema=False)
def legacy_scan_findings(scan_id: str):
    return get_findings(scan_id)


@app.get("/scans/{scan_id}/evidence", include_in_schema=False)
def legacy_scan_evidence(scan_id: str):
    return get_evidence(scan_id)


@app.get("/scans/{scan_id}/agents/logs", include_in_schema=False)
def legacy_scan_logs(scan_id: str):
    return get_agent_logs(scan_id)


@app.get("/scans/{scan_id}/report/json", include_in_schema=False)
def legacy_scan_report(scan_id: str):
    return get_report_json(scan_id)


@app.get("/scans/{scan_id}/metadata", include_in_schema=False)
@app.get("/api/scans/{scan_id}/metadata")
def scan_metadata(scan_id: str):
    result = _get_result(scan_id)
    return result.metadata


@app.get("/scans/{scan_id}/analyzer-info", include_in_schema=False)
@app.get("/api/scans/{scan_id}/analyzer-info")
def scan_analyzer_info(scan_id: str):
    result = _get_result(scan_id)
    return result.metadata.get("analyzer_info", {
        "analyzer_runs": [], "analyzer_errors": [], "skipped_languages": []
    })


@app.get("/api/scans")
def list_scans():
    """获取扫描历史列表"""
    from api.database import get_all_scans
    return get_all_scans()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_result(scan_id: Optional[str] = None):
    """获取 AuditResult，如果未指定 scan_id 则返回最新的"""
    if scan_id:
        result = audit_state.get_by_id(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        return result
    if not audit_state.has_result:
        return None
    return audit_state.get_latest()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
