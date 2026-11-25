import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

from rag import RAGSystem  # noqa: E402
from security import SecurityManager, load_embeddings  # noqa: E402


@pytest.fixture(scope="session")
def embeddings():
    """Load the embedding model once for the whole test run."""
    return load_embeddings()


@pytest.fixture(scope="session")
def security_manager(embeddings):
    return SecurityManager(embeddings)


@pytest.fixture(scope="session")
def rag(embeddings):
    return RAGSystem(embeddings=embeddings)
