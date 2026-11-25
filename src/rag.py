import os
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings

# Chunks below this cosine similarity to the query are treated as off-topic.
# Measured on the sample data: relevant questions score ~0.30-0.60,
# off-topic ones (weather, food, sport) score below ~0.13.
MIN_SIMILARITY = 0.25

# Confidence bands on the best chunk's cosine similarity
CONFIDENCE_BANDS = [(0.50, "High"), (0.35, "Medium"), (MIN_SIMILARITY, "Low")]


def distance_to_similarity(distance):
    """Convert FAISS IndexFlatL2 output (squared L2) to cosine similarity.

    For unit-length vectors ||a - b||^2 = 2 - 2*cos(a, b).
    """
    return 1.0 - float(distance) / 2.0


def confidence_label(similarity):
    if similarity is None:
        return "None"
    for threshold, label in CONFIDENCE_BANDS:
        if similarity >= threshold:
            return label
    return "None"


class RAGSystem:
    def __init__(self, data_dir=None, embeddings=None):
        # Resolve data directory relative to this file's location
        if data_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.data_dir = os.path.join(base_dir, "data")
        else:
            self.data_dir = data_dir

        # Accept a shared model so the app loads it once for security + retrieval.
        # Embeddings are normalised so FAISS distances map to cosine similarity.
        self.embeddings = embeddings or HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
            encode_kwargs={"normalize_embeddings": True},
        )
        self.vector_store = None
        self._build_index()

    def _build_index(self):
        documents = []
        if os.path.exists(self.data_dir):
            for filename in sorted(os.listdir(self.data_dir)):
                if filename.endswith(".txt"):
                    loader = TextLoader(os.path.join(self.data_dir, filename), encoding="utf-8")
                    documents.extend(loader.load())
        else:
            print(f"Warning: Data directory {self.data_dir} not found.")
            return

        if not documents:
            print("Warning: No documents found to index.")
            return

        text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
        texts = text_splitter.split_documents(documents)

        self.vector_store = FAISS.from_documents(texts, self.embeddings)

    def retrieve_with_scores(self, query, k=3, min_similarity=MIN_SIMILARITY):
        """Return up to k (doc, cosine_similarity) pairs, best first.

        Chunks below `min_similarity` are dropped so off-topic queries return
        nothing and the caller can fall back gracefully.
        """
        if not self.vector_store:
            return []
        results = self.vector_store.similarity_search_with_score(query, k=k)
        scored = [(doc, distance_to_similarity(dist)) for doc, dist in results]
        return [(doc, sim) for doc, sim in scored if sim >= min_similarity]

    def retrieve(self, query, k=3, min_similarity=MIN_SIMILARITY):
        """Return only the documents from `retrieve_with_scores`."""
        return [doc for doc, _ in self.retrieve_with_scores(query, k, min_similarity)]

    def generate_response(self, query, context_docs):
        """Generate a response grounded in the retrieved document chunks."""
        if not context_docs:
            return (
                "I could not find relevant information in our policy documents "
                "to answer your question. Please contact support for assistance."
            )

        # Build a readable answer from the retrieved chunks
        response_parts = ["Based on our policy documents:\n"]
        seen_sources = set()

        for doc in context_docs:
            chunk = doc.page_content.strip()
            source = doc.metadata.get('source', 'Unknown Document')
            source_name = os.path.basename(source).replace('.txt', '').replace('_', ' ').upper()

            if chunk:
                response_parts.append(f"- {chunk}")
                if source_name not in seen_sources:
                    seen_sources.add(source_name)

        if seen_sources:
            response_parts.append(
                f"\n**Sources:** {', '.join(sorted(seen_sources))}"
            )

        response_parts.append(
            "\n*This answer is based on retrieved policy excerpts. "
            "For complete details, please refer to the full policy document or contact support.*"
        )

        return "\n".join(response_parts)
