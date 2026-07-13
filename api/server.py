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

from api.schemas import ScanRequest, ScanResponse
from api.auth import router as auth_router
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

# 注册认证路由
app.include_router(auth_router, prefix="/api")


# ---------------------------------------------------------------------------
# Helper: 运行扫描流水线
# ---------------------------------------------------------------------------

def _run_scan_pipeline(request: ScanRequest) -> dict[str, Any]:
    """
    执行完整的扫描流水线：
    1. 代码加载 → CodeUnit
    2. 静态分析 → RawFinding
    3. 结果合并
    4. 评分
    5. 构建证据
    6. 持久化
    7. 返回结果
    """
    from audit_core.models import (
        CodeUnit, RawFinding, AuditResult, AuditSummary,
        EvidenceBundle, AgentLog,
    )
    from audit_core.scoring import score_finding
    from audit_core.result_merger import merge_findings
    from audit_core.registry import build_default_registry
    from ingest.language_router import detect_language_by_path

    # --- 1. 加载代码单元 ---
    code_units: list[CodeUnit] = []
    languages: set[str] = set()
    scanned_files: list[str] = []

    if request.input_type == "code":
        lang = request.language if request.language and request.language != "auto" else "python"
        code_units.append(CodeUnit(
            path="<code_input>",
            language=lang,
            content=request.code or "",
        ))
        languages.add(lang)
        scanned_files.append("<code_input>")

    elif request.input_type == "path":
        repo_path = request.repo_path or ""
        if not os.path.isdir(repo_path):
            raise HTTPException(status_code=400, detail=f"路径不存在: {repo_path}")

        for root, dirs, files in os.walk(repo_path):
            # 跳过隐藏目录和常见非代码目录
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in (
                'node_modules', '__pycache__', '.git', 'venv', '.venv', 'dist', 'build',
            )]
            for fname in files:
                fpath = os.path.join(root, fname)
                lang = detect_language_by_path(fpath)
                if lang == "unknown":
                    continue
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    if content.strip():
                        code_units.append(CodeUnit(
                            path=os.path.relpath(fpath, repo_path),
                            language=lang,
                            content=content,
                        ))
                        languages.add(lang)
                        scanned_files.append(os.path.relpath(fpath, repo_path))
                except Exception:
                    continue

    elif request.input_type == "github":
        # GitHub 仓库: 尝试克隆
        repo_url = request.repo_url or ""
        if not repo_url:
            raise HTTPException(status_code=400, detail="GitHub URL 不能为空")
        try:
            import tempfile, subprocess
            tmp_dir = tempfile.mkdtemp(prefix="vulnpatch_")
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, tmp_dir],
                capture_output=True, timeout=120, check=True,
            )
            # 扫描克隆的仓库
            for root, dirs, files in os.walk(tmp_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in (
                    'node_modules', '__pycache__', '.git', 'venv', '.venv',
                )]
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
                            code_units.append(CodeUnit(
                                path=rel_path,
                                language=lang,
                                content=content,
                            ))
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

    # --- 2. 运行分析器 ---
    all_findings: list[RawFinding] = []
    agent_logs: list[AgentLog] = []
    try:
        registry = build_default_registry()
        analyzers = registry.get_analyzers()
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(code_units)
                all_findings.extend(findings)
                agent_logs.append(AgentLog(
                    agent_name=analyzer.name,
                    stage="analysis",
                    message=f"{analyzer.name} 完成，发现 {len(findings)} 个问题",
                ))
            except Exception as e:
                logger.warning("Analyzer %s failed: %s", analyzer.name, e)
                agent_logs.append(AgentLog(
                    agent_name=analyzer.name,
                    stage="analysis",
                    message=f"{analyzer.name} 执行失败: {e}",
                ))
    except Exception as e:
        logger.warning("Failed to build analyzer registry: %s", e)

    # --- 3. 合并结果 ---
    merged_findings = merge_findings(all_findings)

    # --- 4. 评分和构建证据 ---
    evidence_bundles: list[EvidenceBundle] = []
    for finding in merged_findings:
        score_result = score_finding(finding)
        finding.metadata["score_breakdown"] = score_result

        # 提取代码片段
        snippet = None
        for unit in code_units:
            if unit.path == finding.file_path:
                lines = unit.content.split('\n')
                start = max(0, finding.start_line - 3)
                end = min(len(lines), (finding.end_line or finding.start_line) + 3)
                snippet = '\n'.join(lines[start:end])
                break

        snippet_dict = {"content": snippet, "language": finding.file_path} if snippet else None
        evidence_bundles.append(EvidenceBundle(
            finding=finding,
            snippets=[snippet_dict] if snippet_dict else [],
            cwe_info={"cwe_id": finding.cwe} if finding.cwe else {},
            score_breakdown=score_result,
        ))

    # --- 5. 构建摘要 ---
    risk_scores = [score_finding(f)["risk_score"] for f in merged_findings]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

    summary = AuditSummary(
        total_code_units=len(code_units),
        total_findings=len(merged_findings),
        total_evidence_bundles=len(evidence_bundles),
        risk_score=round(avg_risk, 1),
        languages=sorted(languages),
        scanned_files=scanned_files[:50],  # 限制数量
    )

    result = AuditResult(
        summary=summary,
        findings=merged_findings,
        evidence=evidence_bundles,
        agent_logs=agent_logs,
    )

    # --- 6. 持久化 ---
    scan_id = audit_state.create_session(result)

    # --- 7. 返回 ---
    return {
        "scan_id": scan_id,
        "summary": summary.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in merged_findings],
        "evidence": [e.model_dump(mode="json") for e in evidence_bundles],
        "agent_logs": [l.model_dump(mode="json") for l in agent_logs],
        "cve_candidates": [],
    }


# ===========================================================================
# API 路由
# ===========================================================================

@app.get("/api/health")
def health_check():
    """健康检查"""
    return {"status": "ok"}


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


@app.get("/api/findings")
def get_findings(scan_id: Optional[str] = Query(None)):
    """获取漏洞发现列表"""
    result = _get_result(scan_id)
    if result is None:
        return []
    return [f.model_dump(mode="json") for f in result.findings]


@app.get("/api/evidence")
def get_evidence(scan_id: Optional[str] = Query(None)):
    """获取证据包列表"""
    result = _get_result(scan_id)
    if result is None:
        return []
    return [e.model_dump(mode="json") for e in result.evidence]


@app.get("/api/agents/logs")
def get_agent_logs(scan_id: Optional[str] = Query(None)):
    """获取 Agent 执行日志"""
    result = _get_result(scan_id)
    if result is None:
        return []
    return [l.model_dump(mode="json") for l in result.agent_logs]


@app.get("/api/report/json")
def get_report_json(scan_id: Optional[str] = Query(None)):
    """获取 JSON 格式的完整审计报告"""
    result = _get_result(scan_id)
    if result is None:
        return {"summary": {}, "findings": [], "evidence": [], "agent_logs": []}
    return result.model_dump(mode="json")


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
