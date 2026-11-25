import hashlib
import json
import os
import re
from collections import deque
from datetime import datetime, timezone

# Resolve log path relative to this file so it works regardless of launch dir
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_DIR)
AUDIT_LOG_FILE = os.path.join(_PROJECT_ROOT, "logs", "audit_trail.jsonl")

# Order matters: longer number patterns run first so a card number is not
# partly masked as an Aadhaar or phone number.
_PII_PATTERNS = [
    # Email addresses
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[MASKED_EMAIL]"),
    # Card numbers: 13-19 digits, optionally grouped by spaces or dashes
    (re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), "[MASKED_CARD]"),
    # Aadhaar: 12 digits, optionally as 4-4-4 groups
    (re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"), "[MASKED_AADHAAR]"),
    # PAN: 5 letters, 4 digits, 1 letter
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.IGNORECASE), "[MASKED_PAN]"),
    # Indian mobile numbers, with optional +91 / 0 prefix and a space in the middle
    (re.compile(r"(?:\+91[ -]?|\b0)?\b[6-9]\d{4}[ -]?\d{5}\b"), "[MASKED_PHONE]"),
    # Any other 10-digit number (account / ID numbers)
    (re.compile(r"\b\d{10}\b"), "[MASKED_ID]"),
]


def mask_pii(text):
    """Mask common Indian PII (Aadhaar, PAN, phone, card, email) with regexes."""
    if not text:
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class AuditLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)

    def log_query(self, session_id, user_role, original_query, security_outcome, retrieved_docs, final_response, latency_ms):
        timestamp = datetime.now(timezone.utc).isoformat()

        sanitized_query = self._mask_pii(original_query)

        # Hash the response for immutability check
        response_hash = hashlib.sha256(final_response.encode('utf-8')).hexdigest() if final_response else None

        log_entry = {
            "key": f"audit:{session_id}:{timestamp}",
            "timestamp": timestamp,
            "session_id": session_id,
            "user_role": user_role,
            "original_query": sanitized_query,
            "security_outcome": security_outcome,
            "retrieved_documents": retrieved_docs,
            "final_response_hash": response_hash,
            "latency_ms": latency_ms
        }

        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

        return log_entry

    def _mask_pii(self, text):
        return mask_pii(text)

    def get_recent_logs(self, limit=5, session_id=None):
        """Return the newest `limit` entries, optionally only for one session.

        The UI passes its own session_id so users never see each other's queries.
        """
        logs = deque(maxlen=limit)
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if session_id is None or entry.get("session_id") == session_id:
                        logs.append(entry)
        return list(logs)[::-1]
