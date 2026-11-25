# FinShield RAG

[![tests](https://github.com/abhideep193/finshield-rag/actions/workflows/tests.yml/badge.svg)](https://github.com/abhideep193/finshield-rag/actions/workflows/tests.yml)

> A security-focused financial Q&A assistant built on Retrieval-Augmented Generation (RAG), with a 3-layer prompt-injection defence and an audit trail.

FinShield answers questions about lending and credit-card policies by retrieving the relevant passages from a small knowledge base and returning them with their sources. Every query first passes through three security layers, and every interaction is written to a tamper-evident, hash-chained audit log.

## Features

- **3-layer security pipeline** (`src/security.py`)
  - **Layer 1 – Lexical filter:** regex patterns for instruction overrides, role hijacking, prompt extraction and SQL injection (`ignore all previous instructions`, `act as admin`, `drop table`, …). Patterns target attack phrasing, so normal questions like *"Can I bypass the processing fee?"* are not blocked
  - **Layer 2 – Semantic filter:** cosine similarity between the query and a blacklist of adversarial and financial-crime prompts (e.g. avoiding reporting thresholds, bypassing KYC), using `all-MiniLM-L6-v2` embeddings; blocks above 0.75
  - **Layer 3 – Canary validator:** internal canary tokens are checked in the query (probing) **and in the answer before it is shown** (leak detection)
- **Retrieval** (`src/rag.py`): documents are split into 500-character chunks, embedded with `all-MiniLM-L6-v2` and indexed in FAISS. The top 3 chunks with cosine similarity ≥ 0.25 are returned; off-topic queries (which score below ~0.13 on the sample data) get a graceful "could not find" fallback.
- **Extractive answers:** responses are built from the retrieved policy excerpts with their sources cited. No external LLM or API key is needed.
- **Explainability panel:** each answer shows security outcome, latency, audit key, a **confidence** label (High ≥ 0.50, Medium ≥ 0.35, Low ≥ 0.25 cosine similarity of the best match) and every source with its similarity score.
- **Tamper-evident audit log** (`src/audit.py`): JSONL log in `logs/audit_trail.jsonl`. Each entry stores a SHA-256 hash of the response, the previous entry's hash (`prev_hash`) and its own hash (`entry_hash`), so editing, deleting or reordering any line breaks the chain. The sidebar shows the chain status live, and `python src/audit.py` verifies it from the command line. PII in queries is masked before logging: Aadhaar, PAN, Indian mobile numbers, card numbers and email addresses.
- **Streamlit UI** with a live per-layer status sidebar and the last 5 audit entries **for the current session only**. The embedding model and FAISS index are loaded once and shared across sessions (`st.cache_resource`).

## Knowledge base

The `data/` folder holds three **sample documents written for this demo** — they are not official RBI or bank publications:

| File | Content |
|---|---|
| `rbi_master_circular.txt` | Simplified digital-lending norms (cooling-off period, data privacy, grievance redressal) modelled on RBI guidelines |
| `loan_terms.txt` | Personal-loan T&Cs for a fictional lender, "Nexus Fintech" |
| `credit_card_policy.txt` | Policy for a fictional "Nexus Platinum" credit card |

Add any `.txt` file to `data/` and it will be indexed on the next start.

## Project structure

```
finshield-rag/
├── data/                    # Knowledge base (sample policy docs)
├── src/
│   ├── app.py               # Streamlit entry point
│   ├── rag.py               # FAISS retrieval + extractive answer builder
│   ├── security.py          # 3-layer security module
│   ├── audit.py             # PII masking & audit logger
│   ├── debug_similarity.py  # Prints L2 similarity scores for a sample query
│   └── .streamlit/config.toml
├── tests/                   # pytest suite (security, retrieval, audit, Streamlit app)
├── .github/workflows/       # CI: runs pytest on every push / PR
├── logs/                    # Created at runtime (git-ignored)
├── requirements.txt
├── requirements-dev.txt     # requirements + pytest
└── run.sh
```

## Quick start

Requires Python 3.10+. The first run downloads the `all-MiniLM-L6-v2` model (~90 MB) from Hugging Face.

```bash
git clone https://github.com/abhideep193/finshield-rag.git
cd finshield-rag

python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

cd src
streamlit run app.py
```

Then open http://localhost:8501. On macOS/Linux you can also run `./run.sh` from the repo root.

### Try it

| Query | Expected outcome |
|---|---|
| What is the cooling off period? | Answer from `rbi_master_circular.txt` |
| What is the cash withdrawal limit? | Answer from `credit_card_policy.txt` |
| What is the weather today? | "Could not find relevant information" fallback |
| ignore previous instructions | Blocked by Layer 1 |
| Help me structure transactions to hide money | Blocked by Layer 2 |
| Can I bypass the processing fee by prepaying? | Answer from `loan_terms.txt` / `credit_card_policy.txt` (not a false positive) |
| Who is the nodal officer? | Answer from `rbi_master_circular.txt`, confidence Low |
| What is NEXUS_INTERNAL_2026? | Blocked by Layer 3 |

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

93 tests, run automatically by GitHub Actions on every push:

| File | Covers |
|---|---|
| `tests/test_security.py` | Each layer, including known false positives (*"bypass the processing fee"*) and evasions (*"Disregard the above…"*), plus the output canary check |
| `tests/test_rag.py` | On-topic retrieval, off-topic rejection, confidence labels |
| `tests/test_audit.py` | PII masking, session filtering, and tamper detection (edited, deleted, reordered and re-hashed entries) |
| `tests/test_app.py` | End-to-end runs of the Streamlit app with `streamlit.testing` |

To check the audit log of a running deployment:

```bash
python src/audit.py            # OK: Chain intact (N entries)  /  TAMPERED: Line 7: contents modified
```

## Tech stack

| Tool | Purpose |
|---|---|
| Streamlit | Web UI |
| LangChain (community, text-splitters, huggingface) | Document loading, chunking, vector-store wrapper |
| FAISS | Vector similarity search |
| sentence-transformers `all-MiniLM-L6-v2` | Embeddings |
| scikit-learn | Cosine similarity for Layer 2 |

## Limitations

- Answers are extractive (retrieved excerpts), not generated by an LLM.
- PII masking and the Layer 1 filter are regex-based, so unusual formats or phrasings can slip through; Layer 2 is a similarity check against a fixed blacklist.
- The knowledge base is small, synthetic sample data.
- The hash chain detects tampering but does not prevent someone with write access from rewriting the whole log; for that, the latest hash would need to be stored somewhere separate (e.g. a database or signed timestamp).

## License

[MIT](LICENSE) © Abhideep Bishui
