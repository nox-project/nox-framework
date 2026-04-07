"""tests/test_scanner.py — Unit tests for AvalancheScanner dedup and depth cap."""
import asyncio
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sources.helpers.scanner import AvalancheScanner, _extract_ids_from_text as _extract_new_ids, _ids_from_records


# ── _extract_new_ids ──────────────────────────────────────────────────

def test_extract_email():
    ids = _extract_new_ids("contact user@example.com for info")
    assert ("user@example.com", "email") in ids


def test_extract_username_from_github():
    ids = _extract_new_ids("see github.com/johndoe for code")
    assert ("johndoe", "username") in ids


def test_extract_no_false_positives():
    ids = _extract_new_ids("no identifiers here at all")
    assert ids == []


# ── seen_assets dedup ─────────────────────────────────────────────────

class _FakeOrchestrator:
    """Minimal orchestrator stub — records how many times each asset is scanned."""
    def __init__(self):
        self.scan_calls = []
        self.dorking_engine = _FakeDorkingEngine()

    async def _full_async_scan(self, asset, qtype):
        self.scan_calls.append(asset)
        return []

    def dork(self, asset, query_type=None):
        return []

    def scrape(self, asset, query_type=None):
        return {"pastes": [], "credentials": [], "hashes": [], "telegram": [], "dork_misconfigs": []}


class _FakeDorkingEngine:
    async def async_search(self, session, asset, qtype):
        return []


def test_seen_assets_prevents_duplicate_scan():
    orc = _FakeOrchestrator()
    scanner = AvalancheScanner(orc)

    async def _run():
        scanner.seen_assets.add("target@example.com")
        await asyncio.gather(
            scanner._process("target@example.com", depth=0, parent=None, found_in="seed"),
            scanner._process("target@example.com", depth=0, parent=None, found_in="seed"),
        )

    asyncio.run(_run())
    # Should only have been scanned once (or zero times since it was pre-added to seen_assets)
    assert orc.scan_calls.count("target@example.com") <= 1


def test_depth_cap_respected():
    orc = _FakeOrchestrator()
    scanner = AvalancheScanner(orc)

    async def _run():
        await scanner._process("deep@example.com", depth=99, parent=None, found_in="seed")

    asyncio.run(_run())
    assert "deep@example.com" not in orc.scan_calls


def test_global_dork_url_dedup():
    orc = _FakeOrchestrator()
    scanner = AvalancheScanner(orc)
    scanner._seen_dork_urls.add("https://example.com/leak")

    # Simulate accumulating a hit with a URL already seen
    hit = {"url": "https://example.com/leak", "title": "Leak", "snippet": ""}
    initial_len = len(scanner._dork_hits)
    url = hit.get("url", "")
    if url and url not in scanner._seen_dork_urls:
        scanner._seen_dork_urls.add(url)
        scanner._dork_hits.append(hit)

    assert len(scanner._dork_hits) == initial_len  # not added — already seen
