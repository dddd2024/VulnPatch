"""
RAG (Retrieval-Augmented Generation) 模块。

提供向量存储、嵌入模型和提示构建功能，支持从关键词匹配升级到向量检索。
"""

from rag.embeddings import (
    EmbeddingModel,
    LocalEmbeddingModel,
    OpenAIEmbeddingModel,
    get_embedding_model,
)
from rag.vector_store import ChromaVectorStore
from rag.prompt_builder import build_prompt

__all__ = [
    # 嵌入模型
    "EmbeddingModel",
    "LocalEmbeddingModel",
    "OpenAIEmbeddingModel",
    "get_embedding_model",
    # 向量存储
    "ChromaVectorStore",
    # 提示构建
    "build_prompt",
]
