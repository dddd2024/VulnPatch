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

from api.schemas import ScanRequest, ScanResponse
from api.auth import router as auth_router
from api.competition_demo import router as competition_demo_router
from api.state import audit_state
from api.database import init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("VulnPatch API server started")
    yield
    logger.info("VulnPatch API server shutting down")


app = FastAPI(
    title="VulnPatch - AI 安全审计平台",
    description="自主多模型调度与案例库自进化的漏洞修复辅助系统",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(auth_router, prefix="/api")
app.include_router(competition_demo_router, prefix="/api")


def _run_scan_pipeline(request: ScanRequest) -> dict[str, Any]:
    from audit_core.models import CodeUnit, RawFinding, AuditResult, AuditSummary, EvidenceBundle, AgentLog
    from audit_core.scoring import score_finding
    from audit_core.result_merger import merge_findings
    from audit_core.registry import build_default_registry
    from ingest.language_router import detect_language_by_path

    code_units: list[CodeUnit] = []
    languages: set[str] = set()
    scanned_files: list[str] = []

    if request.input_type == "code":
        lang = request.language if request.language and request.language != "auto" else "python"
        code_units.append(CodeUnit(path="<code_input>", language=lang, content=request.code or ""))
        languages.add(lang)
        scanned_files.append("<code_input>")
    elif request.input_type == "path":
        repo_path = request.repo_path or ""
        if not os.path.isdir(repo_path):
            raise HTTPException(status_code=400, detail=f"路径不存在: {repo_path}")
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', '.git', 'venv', '.venv', 'dist', 'build')]
            for fname in files:
                fpath = os.path.join(root, fname)
                lang = detect_language_by_path(fpath)
                if lang == "unknown":
                    continue
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    if content.strip():
                        code_units.append(CodeUnit(path=os.path.relpath(fpath, repo_path), language=lang, content=content))
                        languages.add(lang)
                        scanned_files.append(os.path.relpath(fpath, repo_path))
                except Exception:
                    continue
    elif request.input_type == "github":
        repo_url = request.repo_url or ""
        if not repo_url:
            raise HTTPException(status_code=400, detail="GitHub URL 不能为空")
        try:
            import tempfile, subprocess
            tmp_dir = tempfile.mkdtemp(prefix="vulnpatch_")
            subprocess.run(["git", "clone", "--depth", "1", repo_url, tmp_dir], capture_output=True, timeout=120, check=True)
            for root, dirs, files in os.walk(tmp_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', '.git', 'venv', '.venv')]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    lang = detect_language_by_path(fpath)
                    if lang == "unknown":
                        continue
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        if content.strip():
                            rel_path = os.path.relpath(fpath, tmp_dir)
                            code_units.append(CodeUnit(path=rel_path, language=lang, content=content))
                            languages.add(lang)
                            scanned_files.append(rel_path)
                    except Exception:
                        continue
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="git 命令不可用，请安装 git")
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=400, detail=f"克隆仓库失败: {e.stderr.decode()[:200]}")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=408, detail="克隆仓库超时")

    if not code_units:
        raise HTTPException(status_code=400, detail="未找到可扫描的代码文件")

    all_findings: list[RawFinding] = []
    agent_logs: list[AgentLog] = []
    try:
        registry = build_default_registry()
        for analyzer in registry.get_analyzers():
            try:
                findings = analyzer.analyze(code_units)
                all_findings.extend(findings)
                agent_logs.append(AgentLog(agent_name=analyzer.name, stage="analysis", message=f"{analyzer.name} 完成，发现 {len(findings)} 个问题"))
            except Exception as e:
                logger.warning("Analyzer %s failed: %s", analyzer.name, e)
                agent_logs.append(AgentLog(agent_name=analyzer.name, stage="analysis", message=f"{analyzer.name} 执行失败: {e}"))
    except Exception as e:
        logger.warning("Failed to build analyzer registry: %s", e)

    merged_findings = merge_findings(all_findings)
    evidence_bundles: list[EvidenceBundle] = []
    for finding in merged_findings:
        score_result = score_finding(finding)
        finding.metadata["score_breakdown"] = score_result
        snippet = None
        for unit in code_units:
            if unit.path == finding.file_path:
                lines = unit.content.split('\n')
                start = max(0, finding.start_line - 3)
                end = min(len(lines), (finding.end_line or finding.start_line) + 3)
                snippet = '\n'.join(lines[start:end])
                break
        snippet_dict = {"content": snippet, "language": finding.file_path} if snippet else None
        evidence_bundles.append(EvidenceBundle(finding=finding, snippets=[snippet_dict] if snippet_dict else [], cwe_info={"cwe_id": finding.cwe} if finding.cwe else {}, score_breakdown=score_result))

    risk_scores = [score_finding(f)["risk_score"] for f in merged_findings]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
    summary = AuditSummary(total_code_units=len(code_units), total_findings=len(merged_findings), total_evidence_bundles=len(evidence_bundles), risk_score=round(avg_risk, 1), languages=sorted(languages), scanned_files=scanned_files[:50])
    result = AuditResult(summary=summary, findings=merged_findings, evidence=evidence_bundles, agent_logs=agent_logs)
    scan_id = audit_state.create_session(result)
    return {"scan_id": scan_id, "summary": summary.model_dump(mode="json"), "findings": [f.model_dump(mode="json") for f in merged_findings], "evidence": [e.model_dump(mode="json") for e in evidence_bundles], "agent_logs": [l.model_dump(mode="json") for l in agent_logs], "cve_candidates": []}


@app.get("/api/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
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


@app.get("/api/findings")
def get_findings(scan_id: Optional[str] = Query(None)):
    result = _get_result(scan_id)
    return [] if result is None else [f.model_dump(mode="json") for f in result.findings]


@app.get("/api/evidence")
def get_evidence(scan_id: Optional[str] = Query(None)):
    result = _get_result(scan_id)
    return [] if result is None else [e.model_dump(mode="json") for e in result.evidence]


@app.get("/api/agents/logs")
def get_agent_logs(scan_id: Optional[str] = Query(None)):
    result = _get_result(scan_id)
    return [] if result is None else [l.model_dump(mode="json") for l in result.agent_logs]


@app.get("/api/report/json")
def get_report_json(scan_id: Optional[str] = Query(None)):
    result = _get_result(scan_id)
    if result is None:
        return {"summary": {}, "findings": [], "evidence": [], "agent_logs": []}
    return result.model_dump(mode="json")


@app.get("/api/report/markdown")
def get_report_markdown(scan_id: Optional[str] = Query(None)):
    result = _get_result(scan_id)
    if result is None:
        return "# Audit Report\n\nNo scan data available."
    from report.markdown_report import build_markdown_report
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=build_markdown_report(result), media_type="text/markdown; charset=utf-8")


@app.get("/api/report/html")
def get_report_html(scan_id: Optional[str] = Query(None)):
    result = _get_result(scan_id)
    if result is None:
        return "<html><body><h1>No scan data available.</h1></body></html>"
    from report.html_report import build_html_report
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=build_html_report(result))


@app.get("/api/scans")
def list_scans():
    from api.database import get_all_scans
    return get_all_scans()


def _get_result(scan_id: Optional[str] = None):
    if scan_id:
        result = audit_state.get_by_id(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        return result
    if not audit_state.has_result:
        return None
    return audit_state.get_latest()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
