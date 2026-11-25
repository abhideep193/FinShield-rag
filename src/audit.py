"""Tamper-evident audit logging with PII masking.

Each log line stores `prev_hash` (the previous entry's hash) and `entry_hash`
(SHA-256 of the entry itself). Editing, deleting or reordering any line breaks
the chain, which `verify_chain()` detects. Run `python audit.py` to verify the log.
"""
import hashlib
import json
import os
import re
import sys
import threading
from collections import deque
from datetime import datetime, timezone

# Resolve log path relative to this file so it works regardless of launch dir
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_DIR)
AUDIT_LOG_FILE = os.path.join(_PROJECT_ROOT, "logs", "audit_trail.jsonl")

GENESIS_HASH = "0" * 64

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


def compute_entry_hash(entry):
    """SHA-256 over every field except `entry_hash`, in a canonical JSON form."""
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_last_line(path):
    """Return the last non-empty line of a file without reading all of it."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        buf = b""
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            if buf.strip().count(b"\n") >= 1:
                break
    lines = buf.strip().splitlines()
    return lines[-1].decode("utf-8") if lines else None


class AuditLogger:
    def __init__(self, log_file=None):
        self.log_file = log_file or AUDIT_LOG_FILE
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        # Streamlit shares one logger across sessions; serialise appends so
        # two writers never read the same prev_hash.
        self._lock = threading.Lock()

    def _last_hash(self):
        if not os.path.exists(self.log_file):
            return GENESIS_HASH
        last = _read_last_line(self.log_file)
        if not last:
            return GENESIS_HASH
        return json.loads(last).get("entry_hash", GENESIS_HASH)

    def log_query(self, session_id, user_role, original_query, security_outcome, retrieved_docs, final_response, latency_ms):
        timestamp = datetime.now(timezone.utc).isoformat()

        sanitized_query = self._mask_pii(original_query)

        # Hash the response so the stored answer can be verified later
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
            "latency_ms": latency_ms,
        }

        with self._lock:
            log_entry["prev_hash"] = self._last_hash()
            log_entry["entry_hash"] = compute_entry_hash(log_entry)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

        return log_entry

    def _mask_pii(self, text):
        return mask_pii(text)

    def get_recent_logs(self, limit=5, session_id=None):
        """Return the newest `limit` entries, optionally only for one session.

        The UI passes its own session_id so users never see each other's queries.
        """
        logs = deque(maxlen=limit)
        if os.path.exists(self.log_file):
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if session_id is None or entry.get("session_id") == session_id:
                        logs.append(entry)
        return list(logs)[::-1]

    def verify_chain(self):
        """Check every entry's hash and link. Returns (ok, entries_checked, message)."""
        if not os.path.exists(self.log_file):
            return True, 0, "No audit log yet"

        expected_prev = GENESIS_HASH
        count = 0
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, count, f"Line {line_no}: not valid JSON"
                if "entry_hash" not in entry:
                    return False, count, f"Line {line_no}: entry has no hash (written before chaining)"
                if entry.get("prev_hash") != expected_prev:
                    return False, count, f"Line {line_no}: chain broken (entry missing, inserted or reordered)"
                if compute_entry_hash(entry) != entry["entry_hash"]:
                    return False, count, f"Line {line_no}: contents modified"
                expected_prev = entry["entry_hash"]
                count += 1
        return True, count, f"Chain intact ({count} entries)"


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    ok, n, msg = AuditLogger(path).verify_chain()
    print(("OK: " if ok else "TAMPERED: ") + msg)
    sys.exit(0 if ok else 1)
