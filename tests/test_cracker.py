"""tests/test_cracker.py — Unit tests for hash detection."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sources.helpers.cracker import detect_hash


def test_md5():
    assert detect_hash("5f4dcc3b5aa765d61d8327deb882cf99") == "md5"

def test_sha1():
    assert detect_hash("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") == "sha1"

def test_sha256():
    assert detect_hash("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8") == "sha256"

def test_bcrypt():
    assert detect_hash("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW") == "bcrypt"

def test_non_hash():
    assert detect_hash("notahash") is None
    assert detect_hash("") is None
    assert detect_hash("hello@world.com") is None

def test_uppercase_md5():
    assert detect_hash("5F4DCC3B5AA765D61D8327DEB882CF99") == "md5"
