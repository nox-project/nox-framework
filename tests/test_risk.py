"""tests/test_risk.py — Unit tests for RiskEngine boundary values."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nox import Record, RiskEngine, Severity


def _make(password="", breach_date="", source="TestSource", email="test@example.com"):
    r = Record(source=source, email=email, password=password, breach_date=breach_date)
    return RiskEngine.score(r)


def test_score_returns_float():
    r = _make(password="hunter2")
    assert isinstance(r.risk_score, float)


def test_score_in_range():
    r = _make(password="hunter2")
    assert 0.0 <= r.risk_score <= 100.0


def test_no_password_lower_score():
    with_pw    = _make(password="secret123")
    without_pw = _make(password="")
    assert with_pw.risk_score >= without_pw.risk_score


def test_cleartext_password_raises_severity():
    r = _make(password="P@ssw0rd!")
    assert r.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)


def test_persistence_does_not_crash():
    records = [_make(password="reused", email="a@b.com"),
               _make(password="reused", email="a@b.com")]
    result = RiskEngine.apply_persistence(records)
    assert len(result) == 2
