import os
import time
import uuid

import streamlit as st

from audit import AuditLogger
from rag import RAGSystem, confidence_label
from security import SecurityManager, load_embeddings

# --- Configuration ---
st.set_page_config(
    page_title="FinShield RAG Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

LAYERS = [
    ("L1", "Layer 1: Lexical Filter"),
    ("L2", "Layer 2: Semantic Anomaly"),
    ("L3", "Layer 3: Canary Validator"),
]


# --- Shared components ---
# Loaded once per server process and shared by all sessions, so the embedding
# model is downloaded/loaded a single time and the FAISS index is built once.
@st.cache_resource(show_spinner="Loading embedding model and building index...")
def load_components():
    embeddings = load_embeddings()
    return SecurityManager(embeddings), RAGSystem(embeddings=embeddings), AuditLogger()


security_manager, rag_system, audit_logger = load_components()

if 'session_id' not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

if 'messages' not in st.session_state:
    st.session_state.messages = []

session_id = st.session_state.session_id

# --- Sidebar: Security Status & Audit Log ---
with st.sidebar:
    st.title("🛡️ FinShield Security")
    st.markdown("---")

    st.subheader("Security Layers Status")
    layer_status = {code: st.empty() for code, _ in LAYERS}
    for code, label in LAYERS:
        layer_status[code].info(f"{label} (Ready)")

    st.markdown("---")
    st.subheader("Audit Log (this session, last 5)")
    chain_placeholder = st.empty()
    audit_placeholder = st.empty()


def update_audit_display():
    """Redraw the audit panel with only this session's entries."""
    chain_ok, _, chain_msg = audit_logger.verify_chain()
    if chain_ok:
        chain_placeholder.success(f"🔗 {chain_msg}")
    else:
        chain_placeholder.error(f"⚠️ Audit log tampered: {chain_msg}")

    logs = audit_logger.get_recent_logs(limit=5, session_id=session_id)
    with audit_placeholder.container():
        if not logs:
            st.caption("No queries yet.")
        for log in logs:
            color = "green" if log['security_outcome'] == "PASSED" else "red"
            st.markdown(f":{color}[{log['timestamp'][11:19]}] **{log['security_outcome']}**")
            st.caption(f"Query: {log['original_query'][:30]}...")
            st.divider()


def show_layer_results(outcome, reason):
    """Mark layers before the blocking one as passed, the blocker as blocked, the rest as skipped."""
    blocked_code = outcome.split("_")[0] if outcome != "PASSED" else None
    reached_block = False
    for code, label in LAYERS:
        if code == blocked_code:
            layer_status[code].error(f"{label}: BLOCKED - {reason}")
            reached_block = True
        elif reached_block:
            layer_status[code].warning(f"{label}: Skipped")
        else:
            layer_status[code].success(f"{label}: PASSED")


update_audit_display()

# --- Main Chat Interface ---
st.title("FinShield RAG Agent")
st.markdown("### Secure Financial AI Assistant (RBI Compliant)")

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if "explainability" in message:
            with st.expander("Explainability & Audit Info"):
                st.json(message["explainability"])

# Chat Input
if prompt := st.chat_input("Ask a financial question..."):
    # 1. User Input
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    start_time = time.time()
    scored_docs = []  # (doc, cosine similarity), best first

    # 2. Input security checks (L1 -> L2 -> L3)
    passed, security_outcome, reason = security_manager.validate(prompt)
    show_layer_results(security_outcome, reason)

    if not passed:
        layer = security_outcome.split("_")[0]
        response_text = f"Your query was flagged by our security system ({layer}). Reference ID: {session_id}"
    else:
        # 3. RAG Retrieval & Generation
        scored_docs = rag_system.retrieve_with_scores(prompt)
        response_text = rag_system.generate_response(prompt, [d for d, _ in scored_docs])

        # 4. Output check: make sure no canary token leaks into the answer
        out_ok, out_outcome, out_reason = security_manager.validate_response(response_text)
        if not out_ok:
            security_outcome = out_outcome
            layer_status["L3"].error(f"Layer 3: Canary Validator: OUTPUT BLOCKED - {out_reason}")
            response_text = f"The response was withheld by our security system (L3 output). Reference ID: {session_id}"
            scored_docs = []

    latency = (time.time() - start_time) * 1000

    # 5. Audit Logging
    log_entry = audit_logger.log_query(
        session_id=session_id,
        user_role="customer",
        original_query=prompt,
        security_outcome=security_outcome,
        retrieved_docs=[d.page_content[:50] + "..." for d, _ in scored_docs],
        final_response=response_text,
        latency_ms=latency
    )

    update_audit_display()

    # 6. Response Delivery
    with st.chat_message("assistant"):
        st.markdown(response_text)

        explainability = {
            "security_status": security_outcome,
            "latency_ms": f"{latency:.2f}ms",
            "session_id": session_id,
            "audit_key": log_entry["key"]
        }

        if security_outcome == "PASSED":
            top_similarity = scored_docs[0][1] if scored_docs else None
            explainability["confidence"] = confidence_label(top_similarity)
            explainability["sources"] = [
                {"file": os.path.basename(d.metadata['source']), "similarity": round(sim, 3)}
                for d, sim in scored_docs
            ]

        with st.expander("Explainability & Audit Info"):
            st.json(explainability)

    st.session_state.messages.append({
        "role": "assistant",
        "content": response_text,
        "explainability": explainability
    })
