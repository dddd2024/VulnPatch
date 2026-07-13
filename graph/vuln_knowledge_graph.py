from __future__ import annotations

import os
import re
from typing import Any

from graph.neo4j_builder import GraphWriter
from llm.client import LLMClient
from llm.exceptions import LLMError
from llm.prompts import build_graph_insight_prompt

CASE_LIBRARY: dict[str, list[dict[str, str]]] = {
    "SQL Injection": [
        {
            "id": "owasp-query-parameterization",
            "title": "OWASP SQL Injection Prevention Cheat Sheet",
            "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "summary": "使用参数化查询和预编译语句，避免动态拼接 SQL。",
        },
        {
            "id": "portswigger-sqli-lab-patterns",
            "title": "PortSwigger Web Security Academy SQLi Labs",
            "source_url": "https://portswigger.net/web-security/sql-injection",
            "summary": "真实攻击样例显示输入拼接查询会导致数据泄露与认证绕过。",
        },
    ],
    "Path Traversal": [
        {
            "id": "owasp-path-traversal",
            "title": "OWASP Path Traversal",
            "source_url": "https://owasp.org/www-community/attacks/Path_Traversal",
            "summary": "通过 ../ 绕过目录限制读取任意文件，需做规范化与基目录校验。",
        },
        {
            "id": "mitre-cwe22",
            "title": "MITRE CWE-22 Guidance",
            "source_url": "https://cwe.mitre.org/data/definitions/22.html",
            "summary": "建议对路径输入进行 canonicalization 并限制在允许目录内。",
        },
    ],
    "Privilege Escalation": [
        {
            "id": "owasp-broken-access-control",
            "title": "OWASP Broken Access Control",
            "source_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "summary": "关键资源必须进行强制服务端授权检查，不能依赖前端控制。",
        },
        {
            "id": "mitre-cwe269",
            "title": "MITRE CWE-269 Guidance",
            "source_url": "https://cwe.mitre.org/data/definitions/269.html",
            "summary": "高权限操作必须校验主体权限并执行最小权限原则。",
        },
    ],
}

FIX_PATTERNS: dict[str, list[str]] = {
    "SQL Injection": ["参数化查询", "输入白名单校验", "最小数据库权限"],
    "Path Traversal": ["realpath/resolve 规范化", "commonpath 基目录校验", "拒绝绝对路径与上跳路径"],
    "Privilege Escalation": ["服务端 RBAC/ABAC 校验", "高危路由显式鉴权装饰器", "最小权限默认策略"],
}

CWE_BY_TYPE = {
    "SQL Injection": "CWE-89",
    "Path Traversal": "CWE-22",
    "Privilege Escalation": "CWE-269",
}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _rule_note(vuln_type: str, cwe: str, cases: list[dict[str, str]], fixes: list[str]) -> str:
    case_titles = "；".join(case["title"] for case in cases)
    fix_text = "、".join(fixes)
    return (
        f"参考 {case_titles} 的公开实践，{vuln_type}（{cwe}）建议优先采用："
        f"{fix_text}。"
    )


def _ai_note(
    ai_mode: str,
    vuln: dict[str, Any],
    cwe: str,
    cases: list[dict[str, str]],
    fixes: list[str],
    model_name: str | None = None,
    api_key: str | None = None,
) -> tuple[str, str]:
    if ai_mode == "rule":
        return _rule_note(str(vuln.get("type", "Unknown")), cwe, cases, fixes), "rule"

    prompt = build_graph_insight_prompt(vuln, cwe, cases, fixes)
    try:
        client = LLMClient(ai_mode=ai_mode, model_name=model_name, api_key=api_key)
        note, _ = client.generate_text(prompt)
        return note, ai_mode
    except LLMError as exc:
        note = _rule_note(str(vuln.get("type", "Unknown")), cwe, cases, fixes)
        return f"{note}（AI 不可用，回退规则摘要：{exc}）", "rule-fallback"


def build_vulnerability_knowledge_graph(
    vulnerabilities: list[dict[str, Any]],
    ai_mode: str = "rule",
    model_name: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    if not vulnerabilities:
        raise ValueError("vulnerabilities 不能为空。")

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    seen_node_ids: set[str] = set()
    seen_edge_keys: set[tuple[str, str, str]] = set()

    def add_node(node: dict[str, Any]) -> None:
        node_id = str(node["id"])
        if node_id in seen_node_ids:
            return
        seen_node_ids.add(node_id)
        nodes.append(node)

    def add_edge(source: str, target: str, rel_type: str) -> None:
        key = (source, target, rel_type)
        if key in seen_edge_keys:
            return
        seen_edge_keys.add(key)
        edges.append({"source": source, "target": target, "type": rel_type})

    for idx, vuln in enumerate(vulnerabilities, start=1):
        vuln_type = str(vuln.get("type", "Unknown"))
        cwe = str(vuln.get("cwe") or CWE_BY_TYPE.get(vuln_type, "CWE-Other"))
        cases = CASE_LIBRARY.get(vuln_type, [])
        fixes = FIX_PATTERNS.get(vuln_type, ["输入校验", "最小权限", "安全编码规范"])
        note, note_mode = _ai_note(
            ai_mode, vuln, cwe, cases, fixes, model_name=model_name, api_key=api_key
        )

        vuln_id = f"vuln:{idx}:{_slug(vuln_type)}:{_slug(str(vuln.get('file', 'unknown')))}:{int(vuln.get('line', 0))}"
        cwe_id = f"cwe:{cwe.lower()}"
        note_id = f"insight:{idx}:{_slug(vuln_type)}"

        add_node(
            {
                "id": vuln_id,
                "kind": "vulnerability",
                "title": vuln_type,
                "severity": str(vuln.get("severity", "UNKNOWN")),
                "risk_score": int(vuln.get("risk_score", 0)),
                "file": str(vuln.get("file", "")),
                "line": int(vuln.get("line", 0)),
                "cwe": cwe,
            }
        )
        add_node({"id": cwe_id, "kind": "cwe", "title": cwe})
        add_edge(vuln_id, cwe_id, "HAS_CWE")

        add_node(
            {
                "id": note_id,
                "kind": "ai_insight",
                "title": f"{vuln_type} Insight",
                "text": note,
                "mode": note_mode,
            }
        )
        add_edge(vuln_id, note_id, "HAS_INSIGHT")

        for fix in fixes:
            fix_id = f"fix:{_slug(vuln_type)}:{_slug(fix)}"
            add_node({"id": fix_id, "kind": "fix_pattern", "title": fix})
            add_edge(note_id, fix_id, "RECOMMENDS_FIX")

        for case in cases:
            case_id = f"case:{_slug(vuln_type)}:{_slug(case['id'])}"
            add_node(
                {
                    "id": case_id,
                    "kind": "reference_case",
                    "title": case["title"],
                    "source_url": case["source_url"],
                    "summary": case["summary"],
                }
            )
            add_edge(vuln_id, case_id, "REFERENCES_CASE")
            for fix in fixes:
                fix_id = f"fix:{_slug(vuln_type)}:{_slug(fix)}"
                add_edge(case_id, fix_id, "RECOMMENDS_FIX")

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "vulnerability_count": len(vulnerabilities),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "ai_mode": ai_mode,
            "model_name": (model_name or "").strip() or None,
        },
    }


def sync_knowledge_graph_to_neo4j(
    graph_data: dict[str, Any],
    *,
    uri: str | None = None,
    user: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    graph_writer: GraphWriter | None = None
    try:
        graph_writer = GraphWriter(
            uri=uri or os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            user=user or os.getenv("NEO4J_USER", "neo4j"),
            password=password or os.getenv("NEO4J_PASSWORD", "password"),
        )
        graph_writer.write_security_knowledge_graph(
            graph_data.get("nodes", []), graph_data.get("edges", [])
        )
        return {"synced": True, "node_count": len(graph_data.get("nodes", []))}
    except Exception as exc:
        return {"synced": False, "error": str(exc)}
    finally:
        if graph_writer is not None:
            graph_writer.close()
