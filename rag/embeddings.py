"""
嵌入模型封装模块。

提供统一的嵌入模型接口，支持本地 sentence-transformers 模型和 OpenAI API 嵌入。
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any


class EmbeddingModel(ABC):
    """嵌入模型抽象基类。"""

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        """
        将文本列表转换为嵌入向量列表。

        Args:
            texts: 待嵌入的文本列表

        Returns:
            嵌入向量列表，每个向量是一个浮点数列表
        """
        ...

    @abstractmethod
    def embed_query(self, text: str) -> list[float]:
        """
        将单个查询文本转换为嵌入向量。

        Args:
            text: 查询文本

        Returns:
            嵌入向量（浮点数列表）
        """
        ...

    @property
    @abstractmethod
    def dimension(self) -> int:
        """返回嵌入向量的维度。"""
        ...


class LocalEmbeddingModel(EmbeddingModel):
    """
    本地嵌入模型，使用 sentence-transformers 库。

    默认使用 all-MiniLM-L6-v2 模型，生成 384 维向量。
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        """
        初始化本地嵌入模型。

        Args:
            model_name: sentence-transformers 模型名称

        Raises:
            ImportError: 未安装 sentence-transformers 库
            RuntimeError: 模型加载失败
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "使用本地嵌入模型需要安装 sentence-transformers，"
                "请执行: pip install sentence-transformers"
            ) from exc

        self._model_name = model_name
        try:
            self._model = SentenceTransformer(model_name)
        except Exception as exc:
            raise RuntimeError(f"加载嵌入模型 '{model_name}' 失败: {exc}") from exc

    def embed(self, texts: list[str]) -> list[list[float]]:
        """
        将文本列表转换为嵌入向量列表。

        Args:
            texts: 待嵌入的文本列表

        Returns:
            嵌入向量列表

        Raises:
            ValueError: 输入为空列表
        """
        if not texts:
            raise ValueError("输入文本列表不能为空")
        embeddings = self._model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()

    def embed_query(self, text: str) -> list[float]:
        """
        将单个查询文本转换为嵌入向量。

        Args:
            text: 查询文本

        Returns:
            嵌入向量
        """
        if not text or not isinstance(text, str):
            raise ValueError("查询文本必须为非空字符串")
        embedding = self._model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    @property
    def dimension(self) -> int:
        """返回嵌入向量的维度。"""
        return self._model.get_sentence_embedding_dimension()


class OpenAIEmbeddingModel(EmbeddingModel):
    """
    OpenAI API 嵌入模型。

    使用 OpenAI 的 text-embedding-ada-002 或其他嵌入模型。
    需要设置 OPENAI_API_KEY 环境变量。
    """

    def __init__(
        self,
        model_name: str = "text-embedding-ada-002",
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        """
        初始化 OpenAI 嵌入模型。

        Args:
            model_name: OpenAI 嵌入模型名称
            api_key: OpenAI API 密钥，默认从环境变量 OPENAI_API_KEY 读取
            base_url: 自定义 API 基础 URL（可选）

        Raises:
            ImportError: 未安装 openai 库
            ValueError: 未提供 API 密钥
        """
        try:
            import openai
        except ImportError as exc:
            raise ImportError(
                "使用 OpenAI 嵌入模型需要安装 openai，"
                "请执行: pip install openai"
            ) from exc

        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise ValueError(
                "使用 OpenAI 嵌入模型需要提供 api_key 参数 "
                "或设置 OPENAI_API_KEY 环境变量"
            )

        self._model_name = model_name
        self._client = openai.OpenAI(api_key=self._api_key, base_url=base_url)

    def embed(self, texts: list[str]) -> list[list[float]]:
        """
        将文本列表转换为嵌入向量列表。

        Args:
            texts: 待嵌入的文本列表

        Returns:
            嵌入向量列表

        Raises:
            ValueError: 输入为空列表
            RuntimeError: API 调用失败
        """
        if not texts:
            raise ValueError("输入文本列表不能为空")
        try:
            response = self._client.embeddings.create(
                model=self._model_name, input=texts
            )
            return [item.embedding for item in response.data]
        except Exception as exc:
            raise RuntimeError(f"OpenAI 嵌入 API 调用失败: {exc}") from exc

    def embed_query(self, text: str) -> list[float]:
        """
        将单个查询文本转换为嵌入向量。

        Args:
            text: 查询文本

        Returns:
            嵌入向量

        Raises:
            RuntimeError: API 调用失败
        """
        if not text or not isinstance(text, str):
            raise ValueError("查询文本必须为非空字符串")
        try:
            response = self._client.embeddings.create(
                model=self._model_name, input=[text]
            )
            return response.data[0].embedding
        except Exception as exc:
            raise RuntimeError(f"OpenAI 嵌入 API 调用失败: {exc}") from exc

    @property
    def dimension(self) -> int:
        """返回嵌入向量的维度。"""
        # text-embedding-ada-002 和 text-embedding-3-small 为 1536 维
        # text-embedding-3-large 为 3072 维
        if "large" in self._model_name:
            return 3072
        return 1536


def get_embedding_model(provider: str, **kwargs: Any) -> EmbeddingModel:
    """
    嵌入模型工厂函数。

    Args:
        provider: 模型提供者，可选 "local" 或 "openai"
        **kwargs: 传递给具体模型构造函数的参数

    Returns:
        对应的 EmbeddingModel 实例

    Raises:
        ValueError: 不支持的 provider
    """
    provider_lower = provider.lower().strip()
    if provider_lower == "local":
        return LocalEmbeddingModel(**kwargs)
    if provider_lower == "openai":
        return OpenAIEmbeddingModel(**kwargs)
    raise ValueError(
        f"不支持的嵌入模型提供者: '{provider}'，"
        f"目前仅支持 'local' 和 'openai'"
    )
