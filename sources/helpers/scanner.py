"""
sources/helpers/scanner.py
Recursive Avalanche Engine for NOX autoscan.

Pipeline per asset (sequential phases):
  Phase 1 — Breach scan
  Phase 2 — Hash crack (non-blocking, on breach results)
  Phase 3 — Dork
  Phase 4 — Scrape
  → Harvest new identifiers from all phases
  → Reinject every new unique identifier (not seen before) recursively
"""

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from nox import Orchestrator

_syslog = logging.getLogger("nox.system")

_EMAIL_RE    = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
_USERNAME_RE = re.compile(r"(?:github\.com|twitter\.com|linkedin\.com/in|reddit\.com/u)/([A-Za-z0-9_.-]{3,39})", re.I)
_PHONE_RE    = re.compile(r"\+\d[\d\s.\-()]{7,14}\d|\b\d{3}[\s.\-]\d{3}[\s.\-]\d{4}\b")
_NAME_RE     = re.compile(r"\b([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,3})\b")

_DORK_LIMIT  = 20
_PIVOT_TYPES = {"email", "username", "phone", "name", "ip", "domain"}


def _cfg_depth(orc=None) -> int:
    if orc is not None:
        cfg = getattr(orc, "config", None)
        if cfg is not None:
            v = getattr(cfg, "pivot_depth", None)
            if v is not None:
                return int(v)
    try:
        from nox import Cfg  # type: ignore
        return Cfg.PIVOT_DEPTH
    except ImportError:
        return 2


def _cfg_concurrency(orc=None) -> int:
    if orc is not None:
        cfg = getattr(orc, "config", None)
        if cfg is not None:
            v = getattr(cfg, "concurrency", None)
            if v is not None:
                return int(v)
    try:
        from nox import Cfg  # type: ignore
        return Cfg.CONCURRENCY
    except ImportError:
        return 15


def _out(level: str, msg: str) -> None:
    try:
        from nox import out as _nox_out  # type: ignore
        _nox_out(level, msg)
    except Exception:
        import sys
        print(f"[{level}] {msg}", file=sys.stderr)


def _extract_ids_from_text(text: str, exclude: str = "") -> List[Tuple[str, str]]:
    """Extract pivotable identifiers from free text, excluding the current asset."""
    found: List[Tuple[str, str]] = []
    excl = exclude.lower()
    for m in _EMAIL_RE.findall(text):
        v = m.lower()
        if v != excl:
            found.append((v, "email"))
    for m in _USERNAME_RE.findall(text):
        v = m.lower()
        if v != excl:
            found.append((v, "username"))
    for m in _PHONE_RE.findall(text):
        clean = re.sub(r"[\s.\-()]", "", m)
        if 8 <= len(clean) <= 15 and clean != excl:
            found.append((clean, "phone"))
    for m in _NAME_RE.findall(text):
        if len(m.split()) >= 2 and m.lower() != excl:
            found.append((m, "name"))
    return found


def _ids_from_records(records: list, exclude: str = "") -> List[Tuple[str, str, str]]:
    """
    Extract pivotable identifiers from breach records.
    Returns (value, qtype, ref) where ref is the source/breach name for logging.
    """
    found: List[Tuple[str, str, str]] = []
    excl = exclude.lower()
    for r in records:
        src = getattr(r, "source", "") or ""
        breach = getattr(r, "breach_name", "") or src
        for val, qtype in [
            (getattr(r, "email",      ""), "email"),
            (getattr(r, "username",   ""), "username"),
            (getattr(r, "phone",      ""), "phone"),
            (getattr(r, "full_name",  ""), "name"),
            (getattr(r, "ip_address", ""), "ip"),
            (getattr(r, "domain",     ""), "domain"),
        ]:
            if val and len(val) > 2 and val.lower() != excl:
                found.append((val.strip(), qtype, breach))
        meta = getattr(r, "metadata", {}) or {}
        for em in meta.get("emails", []):
            if em and em.lower() != excl:
                found.append((em.lower(), "email", breach))
    return found


# ── Pivot log entry schema ─────────────────────────────────────────────────
# {
#   "asset":      str,         # identifier scanned
#   "qtype":      str,         # email/username/phone/name/domain/ip
#   "depth":      int,         # 0=seed, 1=first pivot, …
#   "parent":     str|None,    # asset that discovered this one
#   "found_in":   str,         # phase that found this asset: seed/breach/dork/scrape/hash_crack
#   "records":    int,         # breach records found for this asset
#   "dorks":      int,         # dork hits found for this asset
#   "scrape":     int,         # scrape items found for this asset
#   "children":   List[dict],  # [{asset, qtype, found_in, ref}] — new assets discovered
#   "cracked":    List[str],   # plaintexts cracked from hashes in breach results
# }


class AvalancheScanner:
    def __init__(self, orchestrator: "Orchestrator") -> None:
        self._orc             = orchestrator
        self.seen_assets: Set[str]  = set()
        self._sem: Optional[asyncio.Semaphore] = None
        self._all_records: List     = []
        self._dork_hits:   List[dict] = []
        self._seen_dork_urls: Set[str] = set()
        self._scrape_hits: Dict     = {"pastes": [], "credentials": [], "hashes": [],
                                       "telegram": [], "dork_misconfigs": []}
        self._max_depth: int        = 0
        self._in_flight: Dict[str, asyncio.Future] = {}
        self.pivot_log: List[dict]  = []
        self._seen_discovered: Set[str] = set()
        self.discovered_assets: List[dict] = []

    def _get_sem(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(_cfg_concurrency(self._orc))
        return self._sem

    async def run(self, target: str) -> tuple:
        cfg = getattr(self._orc, "config", None)
        no_pivot = getattr(cfg, "no_pivot", False) if cfg else False
        if no_pivot:
            try:
                from nox import Detect  # type: ignore
                qtype = Detect.qtype(target)
            except ImportError:
                qtype = "email"
            async with self._get_sem():
                try:
                    records = await self._orc._full_async_scan(target, qtype)
                except Exception:
                    records = []
            self._all_records.extend(records)
            self.seen_assets.add(target.lower().strip())
            self.pivot_log.append({
                "asset": target, "qtype": qtype, "depth": 0, "parent": None,
                "found_in": "seed", "records": len(records), "dorks": 0,
                "scrape": 0, "children": [], "cracked": [],
            })
            return self._all_records, self._dork_hits, self._scrape_hits
        await self._process(target, depth=0, parent=None, found_in="seed")
        return self._all_records, self._dork_hits, self._scrape_hits

    def get_discovered_assets(self) -> List[dict]:
        """Return flat list of all discovered assets with full provenance."""
        return self.discovered_assets

    def get_max_depth(self) -> int:
        return self._max_depth

    # ── Dedup gate ────────────────────────────────────────────────────

    async def _process(self, asset: str, depth: int,
                       parent: Optional[str], found_in: str) -> None:
        """Dedup gate: ensures each asset is processed exactly once."""
        if depth > _cfg_depth(self._orc):
            _syslog.debug("avalanche depth cap reached for %s", asset)
            return

        key = asset.lower().strip()
        if not key:
            return

        # Add to seen_assets before any await to prevent concurrent duplicates.
        # If already present, wait on the in-flight future if one exists, then return.
        if key in self.seen_assets:
            if key in self._in_flight:
                try:
                    await self._in_flight[key]
                except Exception:
                    pass
            return

        self.seen_assets.add(key)

        # If already in-flight (shouldn't happen after the seen_assets check above,
        # but guard defensively), wait and return.
        if key in self._in_flight:
            try:
                await self._in_flight[key]
            except Exception:
                pass
            return

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._in_flight[key] = fut

        try:
            await self._do_process(asset, depth, parent, found_in)
        finally:
            if not fut.done():
                fut.set_result(None)

    # ── Core pipeline ─────────────────────────────────────────────────

    async def _do_process(self, asset: str, depth: int,
                          parent: Optional[str], found_in: str) -> None:
        """
        Sequential pipeline:
          Phase 1 — Breach scan
          Phase 2 — Hash crack (concurrent, non-blocking)
          Phase 3 — Dork
          Phase 4 — Scrape
          → Harvest all new identifiers with phase+ref annotation
          → Reinject every unseen identifier
        """
        if depth > self._max_depth:
            self._max_depth = depth

        try:
            from nox import Detect  # type: ignore
            qtype = Detect.qtype(asset)
        except ImportError:
            qtype = "email"

        indent = "  " * depth
        _out("pivot" if depth > 0 else "info",
             f"{indent}[depth={depth}] {'↳' if depth > 0 else '◉'} {asset} ({qtype})"
             + (f"  ← {found_in} via {parent}" if parent else "  [SEED]"))
        _syslog.info("AVALANCHE asset=%s depth=%d parent=%s found_in=%s",
                     asset, depth, parent or "—", found_in)

        # ── Phase 1: Breach scan ──────────────────────────────────────
        async with self._get_sem():
            try:
                records: List = await self._orc._full_async_scan(asset, qtype)
            except Exception as exc:
                _syslog.warning("BREACH_FAIL asset=%s err=%s", asset, exc)
                records = []

        _out("ok" if records else "dim",
             f"{indent}  [breach] {len(records)} records")
        _syslog.info("BREACH_DONE asset=%s records=%d", asset, len(records))
        self._all_records.extend(records)

        # ── Phase 2: Hash crack (non-blocking) ────────────────────────
        cracked_plaintexts: List[str] = []
        try:
            from sources.helpers.cracker import detect_hash  # type: ignore
            import aiohttp as _aio  # type: ignore
            async with _aio.ClientSession(connector=_aio.TCPConnector(limit=5)) as _cs:
                crack_tasks = [
                    _crack_and_inject(_cs, getattr(r, "password_hash", ""), r,
                                      self.seen_assets, self._all_records,
                                      self, depth, asset, cracked_plaintexts)
                    for r in records
                    if getattr(r, "password_hash", "") and not getattr(r, "password", "")
                    and detect_hash(getattr(r, "password_hash", ""))
                ]
                if crack_tasks:
                    await asyncio.gather(*crack_tasks, return_exceptions=True)
        except ImportError:
            pass

        # ── Phase 3: Dork ─────────────────────────────────────────────
        _out("info", f"{indent}  [dork] querying for {asset}…")
        try:
            dork_res = await self._async_dork(asset, qtype)
        except Exception as exc:
            _syslog.warning("DORK_FAIL asset=%s err=%s", asset, exc)
            dork_res = []

        dork_count = 0
        for hit in (dork_res or [])[:_DORK_LIMIT]:
            url = hit.get("url", "") or hit.get("title", "")
            if url and url not in self._seen_dork_urls:
                self._seen_dork_urls.add(url)
                hit["pivot_asset"] = asset
                hit["pivot_depth"] = depth
                self._dork_hits.append(hit)
                dork_count += 1
        _out("ok" if dork_count else "dim",
             f"{indent}  [dork] {dork_count} hits")
        _syslog.info("DORK_DONE asset=%s hits=%d", asset, dork_count)

        # ── Phase 4: Scrape ───────────────────────────────────────────
        _out("info", f"{indent}  [scrape] querying for {asset}…")
        try:
            scrape_res = await self._async_scrape(asset)
        except Exception as exc:
            _syslog.warning("SCRAPE_FAIL asset=%s err=%s", asset, exc)
            scrape_res = {}

        # Collect scrape results locally then merge into the shared dict.
        # The event loop is single-threaded so the merge is safe without a lock.
        scrape_count = 0
        local_scrape: Dict = {k: [] for k in self._scrape_hits}
        for k in self._scrape_hits:
            for item in (scrape_res or {}).get(k, []):
                if isinstance(item, dict):
                    item["pivot_asset"] = asset
                    item["pivot_depth"] = depth
                local_scrape[k].append(item)
                scrape_count += 1
        # Merge into shared dict — safe within the single-threaded event loop.
        for k, items in local_scrape.items():
            self._scrape_hits[k].extend(items)
        _out("ok" if scrape_count else "dim",
             f"{indent}  [scrape] {scrape_count} items")
        _syslog.info("SCRAPE_DONE asset=%s items=%d", asset, scrape_count)

        # ── Harvest new identifiers with phase+ref annotation ─────────
        # Each entry: (value, qtype, found_in_phase, ref)
        new_ids: List[Tuple[str, str, str, str]] = []

        # From breach records
        for val, vqtype, ref in _ids_from_records(records, exclude=asset):
            if vqtype in _PIVOT_TYPES:
                new_ids.append((val, vqtype, "breach", ref))

        # From dork hits
        for hit in (dork_res or [])[:_DORK_LIMIT]:
            url   = hit.get("url", "")
            dork  = hit.get("dork", "")
            ref   = url or dork
            text  = f"{hit.get('title','')} {hit.get('snippet','')} {url} {dork}"
            for val, vqtype in _extract_ids_from_text(text, exclude=asset):
                if vqtype in _PIVOT_TYPES:
                    new_ids.append((val, vqtype, "dork", ref[:120]))

        # From scrape results
        for cred in (scrape_res or {}).get("credentials", []):
            raw = cred.get("raw", "")
            ref = f"paste:{cred.get('paste_id','')}" or cred.get("source", "scrape")
            for val, vqtype in _extract_ids_from_text(raw, exclude=asset):
                if vqtype in _PIVOT_TYPES:
                    new_ids.append((val, vqtype, "scrape", ref))
        for paste in (scrape_res or {}).get("pastes", []):
            ref = f"paste:{paste.get('id', paste.get('site', 'paste'))}"
            for matches in (paste.get("patterns") or {}).values():
                for m in (matches or []):
                    for val, vqtype in _extract_ids_from_text(str(m), exclude=asset):
                        if vqtype in _PIVOT_TYPES:
                            new_ids.append((val, vqtype, "scrape", ref))
        for tg in (scrape_res or {}).get("telegram", []):
            ref = f"t.me/{tg.get('channel','')}"
            for val, vqtype in _extract_ids_from_text(tg.get("text", ""), exclude=asset):
                if vqtype in _PIVOT_TYPES:
                    new_ids.append((val, vqtype, "scrape", ref))
        for mc in (scrape_res or {}).get("dork_misconfigs", []):
            ref = mc.get("url", mc.get("title", "misconfig"))
            for val, vqtype in _extract_ids_from_text(
                    f"{mc.get('title','')} {mc.get('snippet','')}", exclude=asset):
                if vqtype in _PIVOT_TYPES:
                    new_ids.append((val, vqtype, "scrape", ref[:120]))

        # ── Deduplicate and queue children ────────────────────────────
        children: List[dict] = []
        child_tasks = []
        queued: Set[str] = set()

        for val, vqtype, phase, ref in new_ids:
            child_key = val.lower().strip()
            if not child_key or child_key in self.seen_assets or child_key in queued:
                continue
            queued.add(child_key)
            child_entry = {"asset": val, "qtype": vqtype, "found_in": phase, "ref": ref}
            children.append(child_entry)
            if child_key not in self._seen_discovered:
                self._seen_discovered.add(child_key)
                self.discovered_assets.append({
                    "asset":    val,
                    "qtype":    vqtype,
                    "phase":    phase,
                    "ref":      ref,
                    "parent":   asset,
                    "depth":    depth + 1,
                })
            _out("pivot",
                 f"{indent}  ↳ new asset [{phase}]: {val} ({vqtype})  ref: {ref[:60]}")
            _syslog.info("PIVOT_QUEUE asset=%s qtype=%s phase=%s ref=%s parent=%s depth=%d",
                         val, vqtype, phase, ref[:80], asset, depth + 1)
            child_tasks.append(
                self._process(val, depth + 1, parent=asset, found_in=phase)
            )

        # Run child tasks before appending to pivot_log so the log reflects actual outcomes.
        if child_tasks:
            _out("info", f"{indent}  → reinjecting {len(child_tasks)} new asset(s)…")
            await asyncio.gather(*child_tasks, return_exceptions=True)

        # ── Log this node ─────────────────────────────────────────────
        self.pivot_log.append({
            "asset":    asset,
            "qtype":    qtype,
            "depth":    depth,
            "parent":   parent,
            "found_in": found_in,
            "records":  len(records),
            "dorks":    dork_count,
            "scrape":   scrape_count,
            "children": children,
            "cracked":  cracked_plaintexts or [],
        })

    # ── Dork dispatcher ───────────────────────────────────────────────

    async def _async_dork(self, asset: str, qtype: str = "email") -> list:
        try:
            import aiohttp as _aio  # type: ignore
            import ssl as _ssl
            connector = _aio.TCPConnector(limit=10, ssl=_ssl.create_default_context(), family=0)
            async with _aio.ClientSession(connector=connector) as session:
                recs = await self._orc.dorking_engine.async_search(session, asset, qtype)
            return [
                {
                    "url":     r.raw_data.get("url", "") if hasattr(r, "raw_data") else "",
                    "title":   r.raw_data.get("url", r.raw_data.get("dork", "")) if hasattr(r, "raw_data") else "",
                    "snippet": "",
                    "dork":    r.raw_data.get("dork", "") if hasattr(r, "raw_data") else "",
                    "engine":  "DDG",
                }
                for r in recs
            ]
        except ImportError:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, self._orc.dork, asset)
            return result if isinstance(result, list) else []
        except Exception as exc:
            _syslog.debug("DORK_ERR asset=%s err=%s", asset, exc)
            return []

    # ── Scrape dispatcher ─────────────────────────────────────────────

    async def _async_scrape(self, asset: str) -> dict:
        # Instantiate a fresh Session and ScrapeEngine per call — requests.Session
        # and cloudscraper are not safe to share across concurrent coroutines.
        _empty: dict = {"pastes": [], "credentials": [], "hashes": [],
                        "telegram": [], "dork_misconfigs": []}
        try:
            loop = asyncio.get_running_loop()
            try:
                from nox import Session, NoxConfig, ScrapeEngine  # type: ignore
                _cfg = getattr(self._orc, "config", None) or NoxConfig()
                _session = Session(_cfg)
                _engine = ScrapeEngine(_session, self._orc.db)
                qtype = "email"
                try:
                    from nox import Detect  # type: ignore
                    qtype = Detect.qtype(asset)
                except Exception:
                    pass
                result = await loop.run_in_executor(None, _engine.run, asset, qtype)
            except Exception:
                result = await loop.run_in_executor(None, self._orc.scrape, asset)
            return result if isinstance(result, dict) else _empty
        except Exception as exc:
            _syslog.debug("SCRAPE_ERR asset=%s err=%s", asset, exc)
            return _empty


# ── Hash crack helper ──────────────────────────────────────────────────────

async def _crack_and_inject(session, hash_value: str, record_ref,
                             seen_assets: Set[str], all_records: list,
                             scanner: "AvalancheScanner",
                             depth: int, parent_asset: str,
                             cracked_out: List[str]) -> None:
    from sources.helpers.cracker import detect_hash, async_crack, CRACK_TIMEOUT  # type: ignore
    hash_type = detect_hash(hash_value)
    if not hash_type:
        return
    try:
        plaintext = await asyncio.wait_for(
            async_crack(session, hash_value, hash_type), timeout=CRACK_TIMEOUT)
    except (asyncio.TimeoutError, Exception) as exc:
        _syslog.debug("CRACK_FAIL hash=%s reason=%s", hash_value[:16], exc)
        return

    if not plaintext:
        _syslog.debug("CRACK_FAIL hash=%s reason=no_result", hash_value[:16])
        return

    record_ref.password  = plaintext
    record_ref.hash_type = hash_type
    if "Cracked" not in (record_ref.data_types or []):
        record_ref.data_types = list(record_ref.data_types) + ["Cracked"]
    _syslog.info("CRACK_OK hash=%s plain=%s parent=%s", hash_value[:16], plaintext, parent_asset)
    _out("ok", f"  [crack] {hash_value[:16]}… → {plaintext}  (from {parent_asset})")
    cracked_out.append(plaintext)

    # Inject the cracked plaintext as a password-recycling pivot seed.
    key = plaintext.lower()
    if key not in seen_assets and depth + 1 <= _cfg_depth(scanner._orc):
        await scanner._process(plaintext, depth + 1,
                               parent=parent_asset, found_in="hash_crack")
