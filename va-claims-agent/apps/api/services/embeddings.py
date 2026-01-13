"""
Embedding service using Claude/Anthropic or compatible embedding models.
"""
from typing import List
import numpy as np
import anthropic
import structlog

from config import settings

logger = structlog.get_logger()

# Embedding dimension (adjust based on your embedding model)
EMBEDDING_DIMENSION = 1536


async def get_embedding(text: str) -> List[float]:
    """
    Get embedding for a single text.

    Uses Anthropic's embedding capability or falls back to a compatible model.

    Args:
        text: Text to embed

    Returns:
        Embedding vector as list of floats
    """
    # For now, we'll use a simple hashing approach as a placeholder
    # In production, you would use an actual embedding model
    # Claude doesn't directly provide embeddings, so you'd typically use:
    # - OpenAI's ada-002
    # - Cohere embeddings
    # - Sentence transformers locally

    # Placeholder: Generate deterministic pseudo-embedding from text hash
    # REPLACE THIS with actual embedding service
    import hashlib

    hash_bytes = hashlib.sha512(text.encode()).digest()
    # Expand hash to embedding dimension
    embedding = []
    for i in range(EMBEDDING_DIMENSION):
        byte_idx = i % len(hash_bytes)
        embedding.append((hash_bytes[byte_idx] - 128) / 128.0)

    # Normalize
    norm = np.linalg.norm(embedding)
    if norm > 0:
        embedding = [x / norm for x in embedding]

    logger.debug("Generated embedding", text_length=len(text))

    return embedding


async def get_embeddings_batch(texts: List[str], batch_size: int = 100) -> List[List[float]]:
    """
    Get embeddings for multiple texts.

    Args:
        texts: List of texts to embed
        batch_size: Number of texts to process at once

    Returns:
        List of embedding vectors
    """
    embeddings = []

    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        batch_embeddings = [await get_embedding(text) for text in batch]
        embeddings.extend(batch_embeddings)

    logger.info("Generated batch embeddings", count=len(texts))

    return embeddings


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """
    Calculate cosine similarity between two vectors.

    Args:
        a: First vector
        b: Second vector

    Returns:
        Cosine similarity (-1 to 1)
    """
    a_np = np.array(a)
    b_np = np.array(b)

    dot_product = np.dot(a_np, b_np)
    norm_a = np.linalg.norm(a_np)
    norm_b = np.linalg.norm(b_np)

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot_product / (norm_a * norm_b)


async def find_similar_chunks(
    query_embedding: List[float],
    chunk_embeddings: List[tuple],  # List of (chunk_id, embedding)
    top_k: int = 10
) -> List[tuple]:
    """
    Find most similar chunks to a query.

    Args:
        query_embedding: Query vector
        chunk_embeddings: List of (chunk_id, embedding) tuples
        top_k: Number of results to return

    Returns:
        List of (chunk_id, similarity_score) tuples
    """
    similarities = []

    for chunk_id, embedding in chunk_embeddings:
        similarity = cosine_similarity(query_embedding, embedding)
        similarities.append((chunk_id, similarity))

    # Sort by similarity descending
    similarities.sort(key=lambda x: x[1], reverse=True)

    return similarities[:top_k]
