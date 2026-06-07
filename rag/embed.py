from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


def _chunks(text: str, size: int = 500, overlap: int = 100) -> list[str]:
    if size <= overlap:
        raise ValueError("chunk size must be larger than overlap")
    out: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        out.append(text[start:end])
        if end == len(text):
            break
        start += size - overlap
    return out


@dataclass
class ChunkDoc:
    text: str
    source: str


class SimpleVectorStore:
    def __init__(self, docs: list[ChunkDoc]) -> None:
        self.docs = docs

    def similarity_search(self, query: str, k: int = 4) -> list[ChunkDoc]:
        query_terms = set(query.lower().split())
        scored: list[tuple[int, ChunkDoc]] = []
        for doc in self.docs:
            score = len(query_terms & set(doc.text.lower().split()))
            scored.append((score, doc))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [doc for score, doc in scored if score > 0][:k]


def build_vector_store(files: Iterable[str]) -> SimpleVectorStore:
    docs: list[ChunkDoc] = []
    for path in files:
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
        for chunk in _chunks(content):
            docs.append(ChunkDoc(text=chunk, source=path))
    return SimpleVectorStore(docs)

