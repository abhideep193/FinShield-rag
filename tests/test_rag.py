import pytest

from rag import MIN_SIMILARITY, confidence_label, distance_to_similarity


def test_index_built(rag):
    assert rag.vector_store is not None


@pytest.mark.parametrize("query, source", [
    ("What is the cooling off period?", "rbi_master_circular.txt"),
    ("What is the interest rate?", "loan_terms.txt"),
    ("What is the cash withdrawal limit?", "credit_card_policy.txt"),
    # These three were dropped by the old, stricter distance cutoff
    ("How many reward points per 100 rupees?", "credit_card_policy.txt"),
    ("What happens if I default on my loan?", "loan_terms.txt"),
    ("Who is the nodal officer?", "rbi_master_circular.txt"),
])
def test_on_topic_queries_hit_right_document(rag, query, source):
    scored = rag.retrieve_with_scores(query)
    assert scored, "no chunks retrieved"
    # The answering document must be among the excerpts shown to the user
    sources = [doc.metadata["source"] for doc, _ in scored]
    assert any(s.endswith(source) for s in sources), sources
    assert all(sim >= MIN_SIMILARITY for _, sim in scored)
    # Results are sorted best first
    sims = [s for _, s in scored]
    assert sims == sorted(sims, reverse=True)


@pytest.mark.parametrize("query", [
    "What is the weather today?",
    "Best pizza in Mumbai",
    "Tell me about cricket",
    "Who won the football world cup?",
])
def test_off_topic_queries_return_nothing(rag, query):
    assert rag.retrieve(query) == []


def test_generate_response_cites_sources(rag):
    docs = rag.retrieve("What is the cooling off period?")
    resp = rag.generate_response("What is the cooling off period?", docs)
    assert "Cooling-off" in resp
    assert "RBI MASTER CIRCULAR" in resp


def test_generate_response_fallback(rag):
    resp = rag.generate_response("anything", [])
    assert "could not find" in resp.lower()


def test_distance_to_similarity():
    assert distance_to_similarity(0.0) == 1.0
    assert distance_to_similarity(2.0) == 0.0


@pytest.mark.parametrize("sim, label", [
    (0.58, "High"), (0.50, "High"), (0.44, "Medium"), (0.30, "Low"), (0.10, "None"), (None, "None"),
])
def test_confidence_label(sim, label):
    assert confidence_label(sim) == label


def test_confidence_for_real_queries(rag):
    strong = rag.retrieve_with_scores("What is the cooling off period?")[0][1]
    weak = rag.retrieve_with_scores("Who is the nodal officer?")[0][1]
    assert confidence_label(strong) == "High"
    assert confidence_label(weak) in ("Medium", "Low")
