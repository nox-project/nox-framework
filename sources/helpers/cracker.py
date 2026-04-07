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
    Query multiple rainbow-table APIs concurrently.
    Returns first plaintext found, or None. bcrypt is skipped.

    C1: create tasks upfront for cancellation, but await each via asyncio.shield
    inside as_completed — no double wait_for wrapping.
    C2: for 32-char hex (md5/ntlm ambiguity), also query NTLM-specific APIs.

    Per-API timeout: 8s. Global budget: 20s (CRACK_TIMEOUT).
    All tasks are cancelled as soon as the first result is found.
    """
    if hash_type == "bcrypt":
        return None

    h = hash_value.strip().lower()
    apis = [
        (f"https://www.nitrxgen.net/md5db/{h}",                                    "text"),
        (f"https://hashes.com/en/api/hash?hash={h}",                               "json"),
        (f"https://hash.help/api/lookup/{h}",                                       "json"),
        (f"https://hashkiller.io/api/search.php?hash={h}",                         "json"),
        (f"https://md5decrypt.net/Api/api.php?hash={h}&hash_type={hash_type}&email=&code=", "text"),
        (f"https://www.cmd5.org/api.ashx?hash={h}",                                "text"),
    ]
    # C2: for 32-char hashes (md5/ntlm ambiguous), add NTLM-specific endpoint
    if hash_type == "md5" and len(h) == 32:
        apis.append((f"https://hashes.com/en/api/hash?hash={h}&type=ntlm", "json"))

    # C1: create tasks so we can cancel them; shield each before passing to wait_for
    # so cancellation of the shield future does not cancel the underlying task prematurely.
    tasks = [asyncio.create_task(_query_api(session, url, fmt)) for url, fmt in apis]
    result: Optional[str] = None
    try:
        for fut in asyncio.as_completed(tasks):
            try:
                res = await asyncio.wait_for(asyncio.shield(fut), timeout=_API_TIMEOUT)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue
            except Exception:
                continue
            if res:
                result = res
                break
    except Exception:
        pass
    finally:
        # Cancel all remaining tasks and await to suppress pending-task warnings
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*[t for t in tasks if not t.done()], return_exceptions=True)
    return result
