"""tests/test_reporting.py — Unit tests for build_exec_summary."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sources.helpers.reporting import build_exec_summary


def test_empty_records():
    summary = build_exec_summary({"records": [], "analysis": {}, "scan_meta": {}})
    assert summary["total_records"] == 0
    assert summary["cleartext_passwords"] == 0
    assert summary["nodes_discovered"] == 0


def test_counts_cleartext():
    class R:
        email = "a@b.com"; username = ""; password = "secret"; risk_score = 50.0; is_hvt = False
    summary = build_exec_summary({"records": [R()], "analysis": {}, "scan_meta": {}})
    assert summary["cleartext_passwords"] == 1
    assert summary["total_records"] == 1


def test_hvt_count():
    class R:
        email = "admin@corp.com"; username = ""; password = ""; risk_score = 80.0; is_hvt = True
    summary = build_exec_summary({"records": [R()], "analysis": {}, "scan_meta": {}})
    assert summary["hvt_count"] >= 1


def test_bucket_critical():
    class R:
        email = "x@y.com"; username = ""; password = "pw"; risk_score = 95.0; is_hvt = False
    summary = build_exec_summary({"records": [R()], "analysis": {}, "scan_meta": {}})
    assert summary["buckets"]["Critical"] == 1


def test_elapsed_formatting():
    summary = build_exec_summary({"records": [], "analysis": {}, "scan_meta": {"elapsed_seconds": 12.5}})
    assert summary["elapsed"] == "12.5s"
