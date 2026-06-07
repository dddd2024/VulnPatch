"""
漏洞知识库模块。

基于向量存储的漏洞知识库，内置 8 类常见漏洞知识，
提供语义搜索功能，并与现有 RagRetriever 保持兼容的接口。
"""

from __future__ import annotations

from typing import Any

from rag.vector_store import ChromaVectorStore
from rag.embeddings import EmbeddingModel, get_embedding_model


# 内置漏洞知识文档
VULNERABILITY_KNOWLEDGE_DOCS: list[dict[str, Any]] = [
    {
        "id": "vuln-001",
        "title": "SQL Injection",
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "summary": (
            "SQL injection occurs when untrusted user input is concatenated "
            "directly into SQL queries, allowing attackers to execute arbitrary "
            "SQL commands. This can lead to unauthorized data access, data "
            "modification, or complete database compromise."
        ),
        "remediation": (
            "Use parameterized queries or prepared statements. Never concatenate "
            "user input into SQL strings. Employ ORM frameworks that automatically "
            "handle parameterization. Validate and sanitize all inputs."
        ),
        "keywords": ["sql", "injection", "query", "execute", "cursor", "database"],
    },
    {
        "id": "vuln-002",
        "title": "Cross-Site Scripting (XSS)",
        "vulnerability_type": "XSS",
        "cwe_id": "CWE-79",
        "summary": (
            "XSS vulnerabilities allow attackers to inject malicious scripts into "
            "web pages viewed by other users. This can lead to session hijacking, "
            "credential theft, defacement, or redirection to malicious sites."
        ),
        "remediation": (
            "Encode all output for the appropriate HTML context. Use Content "
            "Security Policy (CSP) headers. Validate and sanitize all user input. "
            "Avoid dangerous APIs like innerHTML and document.write."
        ),
        "keywords": ["xss", "cross", "script", "html", "javascript", "innerhtml"],
    },
    {
        "id": "vuln-003",
        "title": "Path Traversal",
        "vulnerability_type": "Path Traversal",
        "cwe_id": "CWE-22",
        "summary": (
            "Path traversal allows attackers to access files outside the intended "
            "directory by using '../' sequences or absolute paths in user input. "
            "This can lead to information disclosure or arbitrary file access."
        ),
        "remediation": (
            "Validate and sanitize file paths. Use allowlists for permitted "
            "directories. Normalize paths before use. Avoid passing user input "
            "directly to file system APIs."
        ),
        "keywords": ["path", "traversal", "file", "directory", "../", "open"],
    },
    {
        "id": "vuln-004",
        "title": "Command Injection",
        "vulnerability_type": "Command Injection",
        "cwe_id": "CWE-78",
        "summary": (
            "Command injection occurs when user input is passed to system shell "
            "commands without proper sanitization, allowing arbitrary command "
            "execution on the server. This can lead to full system compromise."
        ),
        "remediation": (
            "Avoid shell commands with user input. Use parameterized APIs or "
            "subprocess with argument lists. Validate and sanitize input strictly. "
            "Apply principle of least privilege."
        ),
        "keywords": ["command", "injection", "os.system", "subprocess", "shell"],
    },
    {
        "id": "vuln-005",
        "title": "Server-Side Request Forgery (SSRF)",
        "vulnerability_type": "SSRF",
        "cwe_id": "CWE-918",
        "summary": (
            "SSRF allows attackers to make requests from the server to internal "
            "resources or external systems, bypassing access controls. This can "
            "lead to access to internal APIs, cloud metadata, or internal networks."
        ),
        "remediation": (
            "Validate and sanitize URLs. Use allowlists for permitted destinations. "
            "Disable unnecessary URL schemes. Restrict outbound network access. "
            "Avoid passing user input directly to request libraries."
        ),
        "keywords": ["ssrf", "request", "url", "fetch", "http", "internal"],
    },
    {
        "id": "vuln-006",
        "title": "Hardcoded Secret",
        "vulnerability_type": "Hardcoded Secret",
        "cwe_id": "CWE-798",
        "summary": (
            "Hardcoded credentials, API keys, or secrets in source code can be "
            "exposed through version control, decompilation, or code leaks. This "
            "leads to unauthorized access to systems, services, or data."
        ),
        "remediation": (
            "Use environment variables or secure vaults (e.g., HashiCorp Vault, "
            "AWS Secrets Manager). Never hardcode secrets in source code. Rotate "
            "exposed credentials immediately. Use secret scanning tools."
        ),
        "keywords": ["secret", "password", "api_key", "token", "credential"],
    },
    {
        "id": "vuln-007",
        "title": "Weak Cryptography",
        "vulnerability_type": "Weak Cryptography",
        "cwe_id": "CWE-327",
        "summary": (
            "Use of weak or broken cryptographic algorithms (MD5, SHA1, DES, RC4) "
            "can compromise data confidentiality and integrity. Attackers can "
            "exploit known weaknesses to decrypt or forge data."
        ),
        "remediation": (
            "Use strong algorithms (AES-256-GCM, SHA-256, RSA-2048+). Avoid "
            "deprecated algorithms. Keep cryptographic libraries updated. Use "
            "established libraries instead of custom crypto implementations."
        ),
        "keywords": ["crypto", "md5", "sha1", "des", "encryption", "hash"],
    },
    {
        "id": "vuln-008",
        "title": "Insecure Deserialization",
        "vulnerability_type": "Insecure Deserialization",
        "cwe_id": "CWE-502",
        "summary": (
            "Deserialization of untrusted data can lead to remote code execution, "
            "authentication bypass, or data tampering. Attackers can craft malicious "
            "serialized objects to exploit vulnerable deserialization endpoints."
        ),
        "remediation": (
            "Avoid deserializing untrusted data. Use safe formats like JSON. "
            "Implement integrity checks if serialization is required. Use "
            "language-specific safe deserialization practices."
        ),
        "keywords": ["deserialize", "pickle", "yaml.load", "marshal", "readobject"],
    },
]


class VulnerabilityKnowledgeBase:
    """
    漏洞知识库，基于向量存储实现语义搜索。

    内置 8 类常见漏洞知识，支持按漏洞类型过滤和语义相似度搜索，
    同时提供与现有 RagRetriever 兼容的接口。
    """

    def __init__(
        self,
        embedding_model: EmbeddingModel | None = None,
        collection_name: str = "vulnerability_knowledge",
    ) -> None:
        """
        初始化漏洞知识库。

        Args:
            embedding_model: 嵌入模型实例，默认使用本地 all-MiniLM-L6-v2
            collection_name: ChromaDB 集合名称
        """
        self._embedding_model = embedding_model or get_embedding_model("local")
        self._vector_store = ChromaVectorStore(
            embedding_model=self._embedding_model,
            collection_name=collection_name,
        )
        self._build_knowledge_base()

    def _build_knowledge_base(self) -> None:
        """从内置知识文档构建向量存储。"""
        if self._vector_store.count > 0:
            # 已有数据则跳过初始化
            return

        docs: list[str] = []
        metadatas: list[dict[str, Any]] = []
        ids: list[str] = []

        for item in VULNERABILITY_KNOWLEDGE_DOCS:
            # 构建文档文本：标题 + 摘要 + 修复建议 + 关键词
            doc_text = (
                f"{item['title']}\n"
                f"类型: {item['vulnerability_type']}\n"
                f"CWE: {item['cwe_id']}\n"
                f"描述: {item['summary']}\n"
                f"修复建议: {item['remediation']}\n"
                f"关键词: {', '.join(item['keywords'])}"
            )
            docs.append(doc_text)
            metadatas.append({
                "id": item["id"],
                "title": item["title"],
                "vulnerability_type": item["vulnerability_type"],
                "cwe_id": item["cwe_id"],
                "summary": item["summary"],
                "remediation": item["remediation"],
            })
            ids.append(item["id"])

        self._vector_store.add_documents(docs=docs, metadatas=metadatas, ids=ids)

    def search(
        self,
        query: str,
        vuln_type: str | None = None,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """
        语义搜索漏洞知识。

        Args:
            query: 查询文本
            vuln_type: 漏洞类型过滤（可选），如 "SQL Injection"
            top_k: 返回结果数量上限

        Returns:
            搜索结果列表，每项包含:
            - id: 知识条目 ID
            - title: 漏洞标题
            - vulnerability_type: 漏洞类型
            - cwe_id: CWE 标识
            - summary: 漏洞描述
            - remediation: 修复建议
            - score: 相似度分数（0-1）
            - matched_terms: 匹配到的关键词（兼容 RagRetriever 格式）
        """
        if not query or not isinstance(query, str):
            return []
        if top_k <= 0:
            return []

        filter_dict: dict[str, Any] | None = None
        if vuln_type:
            filter_dict = {"vulnerability_type": vuln_type}

        try:
            results = self._vector_store.search(
                query=query, top_k=top_k, filter_dict=filter_dict
            )
        except Exception:
            return []

        output: list[dict[str, Any]] = []
        for result in results:
            meta = result.get("metadata", {})
            output.append({
                "id": meta.get("id", result["id"]),
                "title": meta.get("title", ""),
                "vulnerability_type": meta.get("vulnerability_type", ""),
                "cwe_id": meta.get("cwe_id", ""),
                "summary": meta.get("summary", ""),
                "remediation": meta.get("remediation", ""),
                "score": result.get("score", 0.0),
                "matched_terms": self._extract_matched_terms(query, meta),
            })

        return output

    def _extract_matched_terms(
        self, query: str, metadata: dict[str, Any]
    ) -> list[str]:
        """
        从查询和元数据中提取匹配到的关键词。

        用于兼容 RagRetriever 的输出格式。
        """
        query_lower = query.lower()
        matched: list[str] = []

        # 检查标题匹配
        title = metadata.get("title", "").lower()
        if title and title in query_lower:
            matched.append(metadata["title"])

        # 检查漏洞类型匹配
        vuln_type = metadata.get("vulnerability_type", "").lower()
        if vuln_type and vuln_type in query_lower:
            matched.append(metadata["vulnerability_type"])

        # 检查 CWE ID 匹配
        cwe_id = metadata.get("cwe_id", "").lower()
        if cwe_id and cwe_id in query_lower:
            matched.append(metadata["cwe_id"])

        # 检查关键词匹配
        summary = metadata.get("summary", "").lower()
        remediation = metadata.get("remediation", "").lower()
        common_terms = [
            "sql", "injection", "xss", "script", "path", "traversal",
            "command", "ssrf", "secret", "crypto", "deserialize",
            "password", "token", "hash", "encryption",
        ]
        for term in common_terms:
            if term in query_lower and (term in summary or term in remediation):
                if term not in [m.lower() for m in matched]:
                    matched.append(term)

        return matched

    def get_knowledge_by_cwe(self, cwe_id: str) -> dict[str, Any] | None:
        """
        通过 CWE ID 获取知识条目。

        Args:
            cwe_id: CWE 标识，如 "CWE-89"

        Returns:
            知识条目字典，未找到则返回 None
        """
        cwe_id_upper = cwe_id.upper()
        for item in VULNERABILITY_KNOWLEDGE_DOCS:
            if item["cwe_id"] == cwe_id_upper:
                return {
                    "id": item["id"],
                    "title": item["title"],
                    "vulnerability_type": item["vulnerability_type"],
                    "cwe_id": item["cwe_id"],
                    "summary": item["summary"],
                    "remediation": item["remediation"],
                }
        return None

    def get_all_knowledge(self) -> list[dict[str, Any]]:
        """
        获取所有知识条目（不含分数）。

        Returns:
            知识条目列表
        """
        return [
            {
                "id": item["id"],
                "title": item["title"],
                "vulnerability_type": item["vulnerability_type"],
                "cwe_id": item["cwe_id"],
                "summary": item["summary"],
                "remediation": item["remediation"],
            }
            for item in VULNERABILITY_KNOWLEDGE_DOCS
        ]

    def get_knowledge_by_type(self, vuln_type: str) -> list[dict[str, Any]]:
        """
        通过漏洞类型获取知识条目。

        Args:
            vuln_type: 漏洞类型名称

        Returns:
            匹配的知识条目列表
        """
        vuln_type_lower = vuln_type.lower()
        results = []
        for item in VULNERABILITY_KNOWLEDGE_DOCS:
            if item["vulnerability_type"].lower() == vuln_type_lower:
                results.append({
                    "id": item["id"],
                    "title": item["title"],
                    "vulnerability_type": item["vulnerability_type"],
                    "cwe_id": item["cwe_id"],
                    "summary": item["summary"],
                    "remediation": item["remediation"],
                })
        return results

    def persist(self, path: str) -> None:
        """
        持久化向量存储到磁盘。

        Args:
            path: 持久化目录路径
        """
        self._vector_store.persist(path)

    def load(self, path: str) -> None:
        """
        从磁盘加载向量存储。

        Args:
            path: 持久化目录路径
        """
        self._vector_store.load(path)

    @property
    def count(self) -> int:
        """返回知识库中的文档数量。"""
        return self._vector_store.count

    @property
    def embedding_dimension(self) -> int:
        """返回嵌入向量的维度。"""
        return self._vector_store.embedding_dimension
