"""
基于 ChromaDB 的向量存储模块。

提供文档的向量嵌入、相似度搜索、持久化与加载功能。
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from rag.embeddings import EmbeddingModel, get_embedding_model


class ChromaVectorStore:
    """
    基于 ChromaDB 的向量存储实现。

    支持文本嵌入、向量相似度搜索、持久化到磁盘和从磁盘加载。
    """

    def __init__(
        self,
        embedding_model: EmbeddingModel | None = None,
        collection_name: str = "vuln_knowledge",
    ) -> None:
        """
        初始化向量存储。

        Args:
            embedding_model: 嵌入模型实例，默认使用本地 all-MiniLM-L6-v2
            collection_name: ChromaDB 集合名称

        Raises:
            ImportError: 未安装 chromadb 库
        """
        try:
            import chromadb
            from chromadb.config import Settings
        except ImportError as exc:
            raise ImportError(
                "使用 ChromaVectorStore 需要安装 chromadb，"
                "请执行: pip install chromadb"
            ) from exc

        self._embedding_model = embedding_model or get_embedding_model("local")
        self._collection_name = collection_name
        self._client = chromadb.Client(
            Settings(anonymized_telemetry=False)
        )
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._persist_path: str | None = None

    def add_documents(
        self,
        docs: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
    ) -> None:
        """
        添加文档到向量存储。

        Args:
            docs: 文档文本列表
            metadatas: 文档元数据列表，与 docs 一一对应
            ids: 文档唯一标识列表，若未提供则自动生成 UUID

        Raises:
            ValueError: 输入参数长度不一致或为空
            RuntimeError: 嵌入或存储失败
        """
        if not docs:
            raise ValueError("文档列表不能为空")
        if metadatas is not None and len(metadatas) != len(docs):
            raise ValueError("metadatas 长度必须与 docs 一致")
        if ids is not None and len(ids) != len(docs):
            raise ValueError("ids 长度必须与 docs 一致")

        if ids is None:
            ids = [str(uuid.uuid4()) for _ in range(len(docs))]
        if metadatas is None:
            metadatas = [{} for _ in range(len(docs))]

        try:
            embeddings = self._embedding_model.embed(docs)
        except Exception as exc:
            raise RuntimeError(f"文档嵌入失败: {exc}") from exc

        # ChromaDB 要求元数据值为基本类型
        cleaned_metadatas = []
        for meta in metadatas:
            cleaned = {}
            for key, value in meta.items():
                if isinstance(value, (str, int, float, bool)):
                    cleaned[key] = value
                else:
                    cleaned[key] = json.dumps(value, ensure_ascii=False)
            cleaned_metadatas.append(cleaned)

        try:
            self._collection.add(
                ids=ids,
                documents=docs,
                embeddings=embeddings,
                metadatas=cleaned_metadatas,
            )
        except Exception as exc:
            raise RuntimeError(f"添加文档到向量存储失败: {exc}") from exc

    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_dict: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        向量相似度搜索。

        Args:
            query: 查询文本
            top_k: 返回结果数量上限
            filter_dict: 元数据过滤条件（可选）

        Returns:
            搜索结果列表，每项包含:
            - id: 文档 ID
            - document: 文档文本
            - metadata: 文档元数据
            - distance: 与查询的向量距离（越小越相似）
            - score: 归一化相似度分数（0-1，越大越相似）

        Raises:
            ValueError: 查询为空或 top_k 不合法
            RuntimeError: 搜索失败
        """
        if not query or not isinstance(query, str):
            raise ValueError("查询文本必须为非空字符串")
        if top_k <= 0:
            raise ValueError("top_k 必须大于 0")

        try:
            query_embedding = self._embedding_model.embed_query(query)
        except Exception as exc:
            raise RuntimeError(f"查询嵌入失败: {exc}") from exc

        try:
            results = self._collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where=filter_dict,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:
            raise RuntimeError(f"向量搜索失败: {exc}") from exc

        # 解析结果
        output: list[dict[str, Any]] = []
        if not results["ids"] or not results["ids"][0]:
            return output

        for i, doc_id in enumerate(results["ids"][0]):
            distance = results["distances"][0][i] if results["distances"] else 0.0
            # 将余弦距离转换为相似度分数 (0-1)
            score = 1.0 - min(distance, 1.0)
            metadata = results["metadatas"][0][i] if results["metadatas"] else {}
            document = results["documents"][0][i] if results["documents"] else ""

            # 尝试将 JSON 字符串元数据还原
            parsed_metadata: dict[str, Any] = {}
            if metadata:
                for key, value in metadata.items():
                    if isinstance(value, str):
                        try:
                            parsed_metadata[key] = json.loads(value)
                        except json.JSONDecodeError:
                            parsed_metadata[key] = value
                    else:
                        parsed_metadata[key] = value

            output.append({
                "id": doc_id,
                "document": document,
                "metadata": parsed_metadata,
                "distance": distance,
                "score": round(score, 4),
            })

        return output

    def persist(self, path: str) -> None:
        """
        持久化向量存储到磁盘。

        Args:
            path: 持久化目录路径

        Raises:
            RuntimeError: 持久化失败
        """
        persist_dir = Path(path)
        persist_dir.mkdir(parents=True, exist_ok=True)

        try:
            # 保存集合数据和元数据
            data = {
                "collection_name": self._collection_name,
                "embedding_provider": "external",
                "count": self._collection.count(),
            }
            with open(persist_dir / "store_meta.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            # 导出所有文档和嵌入
            all_data = self._collection.get(include=["documents", "metadatas", "embeddings"])
            export = {
                "ids": all_data["ids"],
                "documents": all_data["documents"],
                "metadatas": all_data["metadatas"],
                "embeddings": all_data["embeddings"],
            }
            with open(persist_dir / "store_data.json", "w", encoding="utf-8") as f:
                json.dump(export, f, ensure_ascii=False, indent=2)

            self._persist_path = str(persist_dir)
        except Exception as exc:
            raise RuntimeError(f"持久化向量存储失败: {exc}") from exc

    def load(self, path: str) -> None:
        """
        从磁盘加载向量存储。

        Args:
            path: 持久化目录路径

        Raises:
            FileNotFoundError: 持久化文件不存在
            RuntimeError: 加载失败
        """
        persist_dir = Path(path)
        meta_path = persist_dir / "store_meta.json"
        data_path = persist_dir / "store_data.json"

        if not meta_path.exists() or not data_path.exists():
            raise FileNotFoundError(
                f"向量存储持久化文件不存在: {meta_path} 或 {data_path}"
            )

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)

            with open(data_path, "r", encoding="utf-8") as f:
                stored = json.load(f)

            # 清空现有集合并重新加载
            existing_ids = self._collection.get()["ids"]
            if existing_ids:
                self._collection.delete(ids=existing_ids)

            self._collection.add(
                ids=stored["ids"],
                documents=stored["documents"],
                metadatas=stored["metadatas"],
                embeddings=stored["embeddings"],
            )

            self._persist_path = str(persist_dir)
        except Exception as exc:
            raise RuntimeError(f"加载向量存储失败: {exc}") from exc

    def delete(self, ids: list[str]) -> None:
        """
        删除指定 ID 的文档。

        Args:
            ids: 要删除的文档 ID 列表
        """
        if not ids:
            return
        self._collection.delete(ids=ids)

    def clear(self) -> None:
        """清空向量存储中的所有文档。"""
        existing_ids = self._collection.get()["ids"]
        if existing_ids:
            self._collection.delete(ids=existing_ids)

    @property
    def count(self) -> int:
        """返回存储的文档数量。"""
        return self._collection.count()

    @property
    def embedding_dimension(self) -> int:
        """返回嵌入向量的维度。"""
        return self._embedding_model.dimension
