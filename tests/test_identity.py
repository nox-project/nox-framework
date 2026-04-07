"""tests/test_identity.py — Unit tests for IdentityResolver Union-Find clustering."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nox import Record, IdentityResolver


def _rec(email="", username="", password="", source="S"):
    return Record(source=source, email=email, username=username, password=password)


def test_single_record_one_cluster():
    records = [_rec(email="a@b.com")]
    profiles = IdentityResolver(records).resolve()
    assert len(profiles) == 1


def test_shared_password_merges_clusters():
    # password must be > 6 chars to be used as a pivot key
    records = [
        _rec(email="a@b.com", password="shared_password_long"),
        _rec(email="c@d.com", password="shared_password_long"),
    ]
    profiles = IdentityResolver(records).resolve()
    assert len(profiles) == 1


def test_distinct_records_separate_clusters():
    records = [
        _rec(email="a@b.com", password="uniquepassword1"),
        _rec(email="c@d.com", password="uniquepassword2"),
    ]
    profiles = IdentityResolver(records).resolve()
    assert len(profiles) == 2


def test_empty_records():
    profiles = IdentityResolver([]).resolve()
    assert profiles == []


def test_hvt_flag_propagates():
    records = [_rec(email="admin@corp.com", password="secretpass")]
    profiles = IdentityResolver(records).resolve()
    assert profiles[0].is_hvt is True
