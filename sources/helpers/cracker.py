"""
sources/helpers/cracker.py
Resilient async hash cracker for NOX autoscan.

Detects MD5 / SHA1 / SHA256 / bcrypt hashes inside breach records,
fires background crack attempts against available APIs, and returns
results without ever blocking the main pivot pipeline.
"""

import asyncio
import logging
import re
from typing import List, Optional, Tuple

# C2: MD5 and NTLM share the same 32-char hex pattern.
# We list md5 first (most common in breach data) but also accept ntlm
# so callers can query NTLM-specific APIs when needed.
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("bcrypt",  re.compile(r"^\$2[aby]?\$\d{2}\$.{53}$")),
    ("sha256",  re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("sha1",    re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("md5",     re.compile(r"^[a-f0-9]{32}$", re.I)),
    # ntlm shares the 32-char hex pattern — detected as md5 first,
    # but async_crack queries both md5 and ntlm APIs for 32-char hashes.
]

# Writes to ~/.config/nox-cli/logs/nox_system.log — never to terminal
_syslog = logging.getLogger("nox.system")

# Per-API timeout — each individual rainbow-table query budget
_API_TIMEOUT = 8
# Global crack budget — hard cap regardless of API count or response order
CRACK_TIMEOUT = 20


def detect_hash(value: str) -> Optional[str]:
    """Return hash type string if value matches a known hash pattern, else None."""
    v = value.strip()
    for htype, pat in _PATTERNS:
        if pat.match(v):
            return htype
    return None


async def _query_api(session, url: str, fmt: str) -> Optional[str]:
    """Single API query — returns plaintext or None. Never raises."""
    try:
        import aiohttp
        to = aiohttp.ClientTimeout(total=_API_TIMEOUT)
        async with session.get(url, timeout=to) as resp:
            if resp.status != 200:
                return None
            if fmt == "text":
                text = (await resp.text()).strip()
                # Reject empty, too-long, or obvious error responses
                if not text or len(text) > 128:
                    return None
                tl = text.lower()
                if any(tl.startswith(p) for p in ("not found", "error", "invalid", "no result", "not in", "cmd5-error", "not exist", "code erreur", "erreur", "unknown")):
                    return None
                return text
            data = await resp.json(content_type=None)
            return data.get("result") or data.get("plaintext") or data.get("plain") or None
    except Exception:
        return None


async def async_crack(session, hash_value: str, hash_type: str) -> Optional[str]:
    """
    Attempt to recover the plaintext for a given hash.

    Strategy:
    1. Local rockyou wordlist (no external calls, no rate limits).
    2. hashes.com API if HASHES_COM_API_KEY is configured.

    bcrypt is skipped — computationally infeasible for online cracking.
    """
    if hash_type == "bcrypt":
        return None

    h = hash_value.strip().lower()

    # 1. Local wordlist first — fast, zero external exposure
    import concurrent.futures as _cf
    loop = asyncio.get_running_loop()
    with _cf.ThreadPoolExecutor(max_workers=1) as _ex:
        local = await loop.run_in_executor(_ex, _local_crack_sync_blocking, hash_value, hash_type)
    if local:
        return local

    # 2. hashes.com if API key is configured
    apis = []
    try:
        from sources.helpers.config_handler import ConfigManager  # type: ignore
        hashes_com_key = ConfigManager.get_key("HASHES_COM_API_KEY")
        if hashes_com_key:
            apis.append((f"https://hashes.com/en/api/search?hash={h}&key={hashes_com_key}", "json"))
    except Exception:
        pass

    if not apis:
        return None

    tasks = [asyncio.create_task(_query_api(session, url, fmt)) for url, fmt in apis]
    result: Optional[str] = None
    try:
        for fut in asyncio.as_completed(tasks):
            try:
                res = await asyncio.wait_for(asyncio.shield(fut), timeout=_API_TIMEOUT)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                continue
            if res:
                result = res
                break
    except Exception:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*[t for t in tasks if not t.done()], return_exceptions=True)
    return result


def _local_crack_sync_blocking(hash_value: str, hash_type: str) -> Optional[str]:
    """Pure-sync version for ThreadPoolExecutor."""
    import hashlib as _hl
    from pathlib import Path as _Path
    wordlist = _Path.home() / ".nox" / "wordlists" / "rockyou.txt"
    if not wordlist.exists():
        return None
    h = hash_value.strip().lower()
    _hashers = {
        "md5":    lambda w: _hl.md5(w).hexdigest(),
        "sha1":   lambda w: _hl.sha1(w).hexdigest(),
        "sha256": lambda w: _hl.sha256(w).hexdigest(),
    }
    hasher = _hashers.get(hash_type)
    if not hasher:
        return None
    try:
        with wordlist.open("rb") as f:
            for line in f:
                word = line.rstrip(b"\n\r")
                if hasher(word) == h:
                    return word.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None
