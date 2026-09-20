"""Local embeddings and retrieval (Phase 10.3.3).

No commercial embedding API is required or supported. Semantic ranking uses
a local embedding backend when one is installed and healthy
(:class:`EmbeddingBackend` -> Ollama's ``/api/embeddings``); otherwise
CyberAudit falls back to a deterministic lexical overlap score, so
retrieval never becomes unavailable end-to-end -- only less semantically
precise while offline or before a model is installed.

Everything here ranks rows the caller already scoped to one tenant.
Nothing in this module queries the database itself: callers (see
``cyberaudit.agent_runtime``, ``cyberaudit.enterprise_services``) are
responsible for filtering candidates to one ``organization_id`` first,
exactly like the existing deterministic Knowledge Graph lookups. Ranking
never crosses that boundary, so a tenant's embeddings can never surface
another tenant's rows.
"""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from cyberaudit.ai_runtime import InferenceHealth
from cyberaudit.config import Settings

_WORD_PATTERN = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> set[str]:
    return set(_WORD_PATTERN.findall(text.lower()))


def lexical_overlap_score(query: str, text: str) -> float:
    """Deterministic Jaccard overlap; the offline-safe default ranking."""
    query_tokens = _tokenize(query)
    text_tokens = _tokenize(text)
    if not query_tokens or not text_tokens:
        return 0.0
    intersection = len(query_tokens & text_tokens)
    union = len(query_tokens | text_tokens)
    return intersection / union if union else 0.0


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


@dataclass(frozen=True)
class RankedCandidate:
    source_id: str
    score: float
    method: str


class EmbeddingBackend(ABC):
    backend_name: str

    @abstractmethod
    async def health_check(self) -> InferenceHealth: ...

    @abstractmethod
    async def embed(self, model_id: str, texts: list[str]) -> list[list[float]]: ...


class DisabledEmbeddingBackend(EmbeddingBackend):
    """The sovereign, offline-safe default: no local embedding model configured."""

    backend_name = "disabled"

    async def health_check(self) -> InferenceHealth:
        return InferenceHealth(
            False, self.backend_name, "Local embeddings are disabled", datetime.now(timezone.utc)
        )

    async def embed(self, model_id: str, texts: list[str]) -> list[list[float]]:
        raise EmbeddingUnavailableError("Local embeddings are disabled")


class EmbeddingUnavailableError(RuntimeError):
    """Raised when no local embedding model can currently serve a request."""


class OllamaEmbeddingBackend(EmbeddingBackend):
    """Client for a locally-run Ollama server's embeddings endpoint."""

    backend_name = "ollama"

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self.timeout_seconds, transport=self.transport)

    async def health_check(self) -> InferenceHealth:
        try:
            async with self._client() as client:
                response = await client.get(f"{self.base_url}/api/tags")
            healthy = response.status_code == 200
            message = (
                "Ollama embeddings reachable"
                if healthy
                else f"Unexpected status {response.status_code}"
            )
        except (httpx.HTTPError, OSError):
            healthy = False
            message = "Ollama embeddings endpoint is unreachable"
        return InferenceHealth(healthy, self.backend_name, message, datetime.now(timezone.utc))

    async def embed(self, model_id: str, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        try:
            async with self._client() as client:
                for text in texts:
                    response = await client.post(
                        f"{self.base_url}/api/embeddings",
                        json={"model": model_id, "prompt": text},
                    )
                    response.raise_for_status()
                    payload = response.json()
                    vector = payload.get("embedding")
                    if not isinstance(vector, list) or not vector:
                        raise EmbeddingUnavailableError("Local embedding model returned no vector")
                    vectors.append([float(value) for value in vector])
        except (httpx.HTTPError, OSError) as exc:
            raise EmbeddingUnavailableError("Local embedding request failed") from exc
        return vectors


def build_embedding_backend(settings: Settings) -> EmbeddingBackend:
    if settings.ai_runtime_backend == "ollama" and settings.ai_runtime_embedding_model:
        return OllamaEmbeddingBackend(
            settings.ai_runtime_base_url, settings.ai_runtime_timeout_seconds
        )
    return DisabledEmbeddingBackend()


class LocalRetrievalService:
    """Ranks tenant-scoped candidates by relevance to a query.

    ``candidates`` is a list of ``(source_id, text)`` pairs the caller has
    already restricted to one tenant (and, where applicable, one
    engagement). This service never fetches its own candidates and never
    widens that set.
    """

    def __init__(self, backend: EmbeddingBackend, model_id: str | None = None):
        self.backend = backend
        self.model_id = model_id

    async def rank(
        self, query: str, candidates: list[tuple[str, str]], *, top_k: int = 20
    ) -> list[RankedCandidate]:
        if not candidates:
            return []
        if self.model_id:
            health = await self.backend.health_check()
            if health.healthy:
                try:
                    texts = [query] + [text for _, text in candidates]
                    vectors = await self.backend.embed(self.model_id, texts)
                    query_vector, candidate_vectors = vectors[0], vectors[1:]
                    ranked = [
                        RankedCandidate(
                            source_id, cosine_similarity(query_vector, vector), "embedding"
                        )
                        for (source_id, _), vector in zip(
                            candidates, candidate_vectors, strict=True
                        )
                    ]
                    ranked.sort(key=lambda item: item.score, reverse=True)
                    return ranked[:top_k]
                except EmbeddingUnavailableError:
                    pass  # Fall through to the deterministic lexical fallback below.
        ranked = [
            RankedCandidate(source_id, lexical_overlap_score(query, text), "lexical")
            for source_id, text in candidates
        ]
        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked[:top_k]
