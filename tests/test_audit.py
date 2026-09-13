import sqlite3
import tempfile
from pathlib import Path

import pytest

from app.audit import AuditError, AuditLog

SECRET = "s" * 40


def make_log(tmp, secret=SECRET, name="audit.db"):
    return AuditLog(Path(tmp) / name, secret)


def append_n(log, n, principal="alice"):
    for i in range(n):
        log.append(
            request_id=f"req-{i}",
            principal=principal,
            role="reader",
            tool="get_document",
            decision="allowed",
            decision_code="ok",
            upstream="demo",
            latency_ms=float(i),
            ts=f"2026-09-13T09:0{i}:00.000+00:00",
        )


def test_a_clean_chain_verifies():
    with tempfile.TemporaryDirectory() as tmp:
        log = make_log(tmp)
        append_n(log, 5)
        result = log.verify()
        assert result.ok
        assert result.rows_checked == 5
        assert result.first_bad_seq is None


def test_an_empty_chain_verifies():
    with tempfile.TemporaryDirectory() as tmp:
        result = make_log(tmp).verify()
        assert result.ok
        assert result.rows_checked == 0


def test_each_row_links_to_the_previous_one():
    with tempfile.TemporaryDirectory() as tmp:
        log = make_log(tmp)
        append_n(log, 3)
        rows = log.rows()
        assert rows[1]["prev_hash"] == rows[0]["hash"]
        assert rows[2]["prev_hash"] == rows[1]["hash"]


def test_the_log_refuses_updates_and_deletes():
    with tempfile.TemporaryDirectory() as tmp:
        log = make_log(tmp)
        append_n(log, 2)
        raw = sqlite3.connect(Path(tmp) / "audit.db")
        with pytest.raises(sqlite3.IntegrityError):
            raw.execute("UPDATE audit_log SET tool='x' WHERE seq=1")
        with pytest.raises(sqlite3.IntegrityError):
            raw.execute("DELETE FROM audit_log WHERE seq=1")
        raw.close()


def test_mutating_a_row_is_detected_and_the_row_identified():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.db"
        log = make_log(tmp)
        append_n(log, 5)
        assert log.verify().ok

        # An attacker with write access drops the append-only triggers first.
        raw = sqlite3.connect(path)
        raw.execute("DROP TRIGGER audit_log_no_update")
        raw.execute("UPDATE audit_log SET decision='denied' WHERE seq=3")
        raw.commit()
        raw.close()

        result = AuditLog(path, SECRET).verify()
        assert not result.ok
        assert result.first_bad_seq == 3
        assert result.rows_checked == 2
        assert "hash" in (result.reason or "")


def test_removing_a_row_is_detected():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.db"
        log = make_log(tmp)
        append_n(log, 4)

        raw = sqlite3.connect(path)
        raw.execute("DROP TRIGGER audit_log_no_delete")
        raw.execute("DELETE FROM audit_log WHERE seq=2")
        raw.commit()
        raw.close()

        result = AuditLog(path, SECRET).verify()
        assert not result.ok
        assert result.first_bad_seq == 3


def test_a_different_signing_secret_does_not_verify():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.db"
        log = AuditLog(path, SECRET)
        append_n(log, 2)
        log.close()

        result = AuditLog(path, "d" * 40).verify()
        assert not result.ok
        assert result.first_bad_seq == 1


def test_a_signing_secret_is_required():
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(AuditError):
            AuditLog(Path(tmp) / "audit.db", "")


def test_arguments_and_results_are_not_stored():
    with tempfile.TemporaryDirectory() as tmp:
        log = make_log(tmp)
        log.append(
            request_id="req-1",
            principal="alice",
            role="reader",
            tool="get_document",
            decision="allowed",
            decision_code="ok",
            findings=[
                {
                    "detector": "aws_access_key_id",
                    "category": "secret",
                    "severity": "high",
                    "count": 1,
                }
            ],
        )
        columns = set(log.rows()[0].keys())
        assert "arguments" not in columns
        assert "result" not in columns
        blob = " ".join(str(value) for value in tuple(log.rows()[0]))
        assert "AKIA" not in blob


def test_findings_are_recorded_with_the_entry():
    with tempfile.TemporaryDirectory() as tmp:
        log = make_log(tmp)
        entry = log.append(
            request_id="req-1",
            principal="alice",
            role="reader",
            tool="fetch_ci_config",
            decision="allowed",
            decision_code="ok",
            findings=[
                {
                    "detector": "aws_access_key_id",
                    "category": "secret",
                    "severity": "high",
                    "count": 1,
                }
            ],
        )
        assert "aws_access_key_id" in entry["findings"]
        assert log.verify().ok


def test_appending_after_verification_keeps_the_chain_valid():
    with tempfile.TemporaryDirectory() as tmp:
        log = make_log(tmp)
        append_n(log, 2)
        assert log.verify().ok
        append_n(log, 2, principal="bob")
        assert log.verify().ok
        assert log.count() == 4
