import json

import pytest

from audit import GENESIS_HASH, AuditLogger, compute_entry_hash, mask_pii


@pytest.fixture
def logger(tmp_path):
    return AuditLogger(log_file=str(tmp_path / "audit.jsonl"))


def write(logger, session="s1", query="What is the cooling off period?", outcome="PASSED"):
    return logger.log_query(session, "customer", query, outcome, ["doc..."], "Some answer.", 12.5)


def read_lines(logger):
    with open(logger.log_file, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def rewrite(logger, entries):
    with open(logger.log_file, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


# ── PII masking ──────────────────────────────────────────────────────

@pytest.mark.parametrize("text, tag, secret", [
    ("My Aadhaar is 123456789012", "[MASKED_AADHAAR]", "123456789012"),
    ("Aadhaar 1234 5678 9012", "[MASKED_AADHAAR]", "5678"),
    ("PAN ABCDE1234F", "[MASKED_PAN]", "ABCDE1234F"),
    ("pan abcde1234f", "[MASKED_PAN]", "abcde1234f"),
    ("call +91 98765 43210", "[MASKED_PHONE]", "43210"),
    ("call 9876543210", "[MASKED_PHONE]", "9876543210"),
    ("card 4111 1111 1111 1111", "[MASKED_CARD]", "4111"),
    ("card 4111111111111111", "[MASKED_CARD]", "4111"),
    ("account 1234567890", "[MASKED_ID]", "1234567890"),
    ("mail me at test.user@example.com", "[MASKED_EMAIL]", "example.com"),
])
def test_mask_pii(text, tag, secret):
    masked = mask_pii(text)
    assert tag in masked
    assert secret not in masked


def test_mask_pii_leaves_amounts_alone():
    text = "Annual fee is INR 499, waived above INR 50000"
    assert mask_pii(text) == text


def test_query_is_masked_in_log(logger):
    entry = write(logger, query="My PAN is ABCDE1234F")
    assert "ABCDE1234F" not in json.dumps(read_lines(logger))
    assert entry["original_query"] == "My PAN is [MASKED_PAN]"


# ── Entries and session filtering ────────────────────────────────────

def test_entry_fields(logger):
    entry = write(logger)
    assert len(entry["final_response_hash"]) == 64
    assert entry["prev_hash"] == GENESIS_HASH
    assert len(entry["entry_hash"]) == 64


def test_recent_logs_newest_first_and_limited(logger):
    for i in range(7):
        write(logger, query=f"question {i}")
    recent = logger.get_recent_logs(limit=5)
    assert [e["original_query"] for e in recent] == [f"question {i}" for i in (6, 5, 4, 3, 2)]


def test_recent_logs_filtered_by_session(logger):
    write(logger, session="me")
    write(logger, session="someone-else", query="private question")
    own = logger.get_recent_logs(session_id="me")
    assert len(own) == 1 and own[0]["session_id"] == "me"


# ── Hash chain ───────────────────────────────────────────────────────

def test_empty_log_verifies(logger):
    ok, n, _ = logger.verify_chain()
    assert ok and n == 0


def test_chain_links_entries(logger):
    first = write(logger)
    second = write(logger)
    assert second["prev_hash"] == first["entry_hash"]
    ok, n, _ = logger.verify_chain()
    assert ok and n == 2


def test_chain_continues_across_logger_instances(logger):
    write(logger)
    AuditLogger(log_file=logger.log_file).log_query("s2", "customer", "q", "PASSED", [], "a", 1.0)
    ok, n, _ = logger.verify_chain()
    assert ok and n == 2


def test_detects_modified_entry(logger):
    for _ in range(3):
        write(logger)
    entries = read_lines(logger)
    entries[1]["security_outcome"] = "L1_BLOCKED"
    rewrite(logger, entries)
    ok, _, msg = logger.verify_chain()
    assert not ok and "Line 2" in msg and "modified" in msg


def test_detects_deleted_entry(logger):
    for _ in range(3):
        write(logger)
    entries = read_lines(logger)
    del entries[1]
    rewrite(logger, entries)
    ok, _, msg = logger.verify_chain()
    assert not ok and "chain broken" in msg


def test_detects_reordered_entries(logger):
    for _ in range(3):
        write(logger)
    entries = read_lines(logger)
    entries[0], entries[1] = entries[1], entries[0]
    rewrite(logger, entries)
    ok, _, _ = logger.verify_chain()
    assert not ok


def test_detects_rehashed_entry(logger):
    """Recomputing an edited entry's own hash still breaks the next entry's link."""
    for _ in range(3):
        write(logger)
    entries = read_lines(logger)
    entries[1]["original_query"] = "forged"
    entries[1]["entry_hash"] = compute_entry_hash(entries[1])
    rewrite(logger, entries)
    ok, _, msg = logger.verify_chain()
    assert not ok and "Line 3" in msg
