import json

import httpx
import pytest

from cyberaudit.config import Settings
from cyberaudit.local_retrieval import (
    DisabledEmbeddingBackend,
    EmbeddingUnavailableError,
    LocalRetrievalService,
    OllamaEmbeddingBackend,
    build_embedding_backend,
    cosine_similarity,
    lexical_overlap_score,
)


def test_lexical_overlap_score_rewards_shared_words_and_ignores_case():
    assert lexical_overlap_score("Suspicious Login Attempt", "a login attempt was suspicious") > 0
    assert lexical_overlap_score("completely unrelated text", "another topic entirely") == 0.0
    assert lexical_overlap_score("", "anything") == 0.0


def test_cosine_similarity_handles_identical_orthogonal_and_mismatched_vectors():
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)
    assert cosine_similarity([1.0, 0.0], [0.0, 0.0]) == 0.0
    assert cosine_similarity([1.0], [1.0, 2.0]) == 0.0


def test_build_embedding_backend_defaults_to_disabled():
    settings = Settings(ai_runtime_backend="disabled")
    assert isinstance(build_embedding_backend(settings), DisabledEmbeddingBackend)


def test_build_embedding_backend_requires_a_configured_model():
    settings = Settings(ai_runtime_backend="ollama", ai_runtime_embedding_model=None)
    assert isinstance(build_embedding_backend(settings), DisabledEmbeddingBackend)


def test_build_embedding_backend_builds_ollama_client_when_fully_configured():
    settings = Settings(ai_runtime_backend="ollama", ai_runtime_embedding_model="nomic-embed-text")
    backend = build_embedding_backend(settings)
    assert isinstance(backend, OllamaEmbeddingBackend)


@pytest.mark.asyncio
async def test_disabled_backend_is_unhealthy_and_refuses_to_embed():
    backend = DisabledEmbeddingBackend()
    health = await backend.health_check()
    assert health.healthy is False
    with pytest.raises(EmbeddingUnavailableError):
        await backend.embed("any-model", ["text"])


@pytest.mark.asyncio
async def test_retrieval_service_falls_back_to_lexical_ranking_without_a_model():
    service = LocalRetrievalService(DisabledEmbeddingBackend())
    ranked = await service.rank(
        "suspicious login",
        [("a", "a suspicious login was observed"), ("b", "unrelated maintenance window")],
    )
    assert ranked[0].source_id == "a"
    assert ranked[0].method == "lexical"


@pytest.mark.asyncio
async def test_retrieval_service_returns_empty_for_no_candidates():
    service = LocalRetrievalService(DisabledEmbeddingBackend())
    assert await service.rank("anything", []) == []


@pytest.mark.asyncio
async def test_retrieval_service_uses_embeddings_when_the_backend_is_healthy():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": []})
        prompt = json.loads(request.read())["prompt"]
        # A trivial, deterministic 2-D "embedding" whose direction reflects
        # word/character density, so the closest text is ranked first.
        embedding = [float(len(prompt.split())), float(len(prompt))]
        return httpx.Response(200, json={"embedding": embedding})

    backend = OllamaEmbeddingBackend(
        "http://127.0.0.1:11434", 5.0, transport=httpx.MockTransport(handler)
    )
    service = LocalRetrievalService(backend, model_id="nomic-embed-text")
    ranked = await service.rank(
        "one two three",
        [("short", "one two"), ("exact", "one two three"), ("long", "one two three four five")],
    )
    assert ranked[0].source_id == "exact"
    assert ranked[0].method == "embedding"


@pytest.mark.asyncio
async def test_retrieval_service_falls_back_to_lexical_when_embedding_call_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": []})
        raise httpx.ConnectError("refused", request=request)

    backend = OllamaEmbeddingBackend(
        "http://127.0.0.1:11434", 5.0, transport=httpx.MockTransport(handler)
    )
    service = LocalRetrievalService(backend, model_id="nomic-embed-text")
    ranked = await service.rank(
        "suspicious login",
        [("a", "a suspicious login was observed"), ("b", "unrelated maintenance window")],
    )
    assert ranked[0].source_id == "a"
    assert ranked[0].method == "lexical"


@pytest.mark.asyncio
async def test_retrieval_service_uses_lexical_when_backend_is_unhealthy():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    backend = OllamaEmbeddingBackend(
        "http://127.0.0.1:11434", 5.0, transport=httpx.MockTransport(handler)
    )
    service = LocalRetrievalService(backend, model_id="nomic-embed-text")
    ranked = await service.rank("suspicious login", [("a", "a suspicious login was observed")])
    assert ranked[0].method == "lexical"
