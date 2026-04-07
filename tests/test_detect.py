"""tests/test_detect.py — Unit tests for input type detection."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nox import Detect


def test_email():
    assert Detect.qtype("user@example.com") == "email"
    assert Detect.qtype("first.last+tag@sub.domain.org") == "email"

def test_domain():
    assert Detect.qtype("example.com") == "domain"
    assert Detect.qtype("sub.example.co.uk") == "domain"

def test_ip():
    assert Detect.qtype("192.168.1.1") == "ip"
    assert Detect.qtype("8.8.8.8") == "ip"

def test_hash_md5():
    assert Detect.qtype("5f4dcc3b5aa765d61d8327deb882cf99") == "hash"

def test_hash_sha256():
    assert Detect.qtype("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8") == "hash"

def test_username():
    assert Detect.qtype("johndoe") == "username"
    assert Detect.qtype("john_doe_99") == "username"
