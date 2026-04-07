#!/usr/bin/env python3
"""
NOX — Cyber Threat Intelligence Framework
Async core | 120+ breach sources | Risk scoring | Identity graphing | HVT detection
"""

import asyncio
import hashlib
import html as html_module
import json
import sys as _sys

# ── Global namespace injection — location-agnostic path anchor ─────────
# Resolves the package root whether NOX is run from /usr/bin, /home, or /tmp.
# Canonical install: /usr/lib/python3/dist-packages/nox/nox.py
# Dev/source run:    <repo>/nox.py
import pathlib as _pl
_SCRIPT_DIR = _pl.Path(__file__).resolve().parent
_INSTALL_PKG = _pl.Path("/usr/lib/python3/dist-packages/nox")
_PKG_ROOT = _INSTALL_PKG if _SCRIPT_DIR == _INSTALL_PKG else _SCRIPT_DIR
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

# ── Credential helper (XDG JSON store) ────────────────────────────────
try:
    from sources.helpers.config_handler import (   # type: ignore
        ConfigManager as _ExtConfigManager,
        UNIVERSAL_PLACEHOLDER,
        SERVICE_REGISTRY,
    )
    _HAS_CONFIG_HANDLER = True
except ImportError:
    _HAS_CONFIG_HANDLER = False
    UNIVERSAL_PLACEHOLDER = "INSERT_API_KEY_HERE"
    SERVICE_REGISTRY = {}
    _ExtConfigManager = None

try:
    from sources.helpers.cracker import detect_hash  # type: ignore
    _HAS_CRACKER = True
except ImportError:
    _HAS_CRACKER = False
    def detect_hash(v):  # type: ignore
        return None

try:
    from sources.helpers.scanner import AvalancheScanner  # type: ignore
    _HAS_AVALANCHE = True
except ImportError:
    _HAS_AVALANCHE = False
    AvalancheScanner = None  # type: ignore

try:
    from sources.helpers.reporting import (  # type: ignore
        to_json as _rep_json,
        to_html as _rep_html,
        to_pdf  as _rep_pdf,
    )
    _HAS_REPORTING = True
except ImportError:
    _HAS_REPORTING = False
import os
import random
import re
import sys
import time
import threading
# Module-level lock for thread-safe proxy env var assignment (Bug 9 fix)
_PROXY_ENV_LOCK = threading.Lock()
import argparse
import csv
import logging
import math
import tempfile
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar
import gzip
import ssl
import base64
from abc import ABC, abstractmethod
from contextlib import contextmanager

aiosqlite = None
try:
    import aiosqlite as _aiosqlite
    aiosqlite = _aiosqlite
except ImportError:
    pass
import sqlite3 as _sqlite3_fallback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple

OPTIONAL: Dict[str, Any] = {}


def _try_import(name: str, pkg: str = None):
    try:
        m = __import__(pkg or name)
        OPTIONAL[name] = m
        return m
    except ImportError:
        return None


aiohttp_mod   = _try_import("aiohttp")
bs4           = _try_import("bs4", "bs4")
BeautifulSoup = getattr(bs4, "BeautifulSoup", None) if bs4 else None
cloudscraper  = _try_import("cloudscraper")
stem          = _try_import("stem")
colorama      = _try_import("colorama")
rich_mod      = _try_import("rich")
phonenumbers  = _try_import("phonenumbers")
requests      = _try_import("requests")
try:
    from weasyprint import HTML as _WP_HTML
    weasyprint = _WP_HTML
except ImportError:
    weasyprint = None

if colorama:
    colorama.init(autoreset=True)

try:
    from importlib.metadata import version as _pkg_version
    VERSION = _pkg_version("nox-cli")
except Exception:
    # Fallback: read directly from pyproject.toml (dev/source run)
    try:
        import tomllib as _toml  # Python 3.11+
    except ImportError:
        try:
            import tomli as _toml  # type: ignore
        except ImportError:
            _toml = None  # type: ignore
    if _toml:
        try:
            with open(_pl.Path(__file__).resolve().parent / "pyproject.toml", "rb") as _f:
                VERSION = _toml.load(_f)["project"]["version"]
        except Exception:
            VERSION = "1.0.0"
    else:
        VERSION = "1.0.0"
BUILD_DATE = "2026-04-02"

# ── Smart Path Layout ──────────────────────────────────────────────────
HOME_NOX    = Path.home() / ".nox"
LOG_DIR     = HOME_NOX / "logs"
REPORT_DIR  = HOME_NOX / "reports"
SOURCE_DIR  = HOME_NOX / "sources"
VAULT_DIR   = HOME_NOX / "vault"
# XDG config dir — canonical location for apikeys, system log
_XDG_CFG    = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "nox-cli"
SYSLOG_DIR  = _XDG_CFG / "logs"


def initialize_environment() -> None:
    """
    Create ~/.nox directory tree, seed sources from the script location or
    /usr/share/nox-cli/sources/ if the user sources dir is empty, and fix
    ownership when the directory was previously created by root (sudo).
    Creates a default config.ini on first run if not present.
    """
    import shutil

    # Create all required directories
    PROVIDER_DIR = HOME_NOX / "providers"
    for d in (HOME_NOX, LOG_DIR, REPORT_DIR, SOURCE_DIR, VAULT_DIR, PROVIDER_DIR):
        d.mkdir(mode=0o755, parents=True, exist_ok=True)

    # Ownership fix: if run as root previously, re-own to the real user
    real_uid = int(os.environ.get("SUDO_UID", os.getuid()))
    real_gid = int(os.environ.get("SUDO_GID", os.getgid()))
    if os.getuid() == 0 and real_uid != 0:
        for d in (HOME_NOX, LOG_DIR, REPORT_DIR, SOURCE_DIR, VAULT_DIR):
            try:
                os.chown(d, real_uid, real_gid)
            except OSError:
                pass

    # Create default config.ini on first run
    _default_cfg = HOME_NOX / "config.ini"
    if not _default_cfg.exists():
        import configparser as _cp
        cfg = _cp.ConfigParser()
        cfg["settings"] = {
            "concurrency": "20",
            "timeout": "30",
            "stealth": "true",
            "rate_limit_lo": "0.5",
            "rate_limit_hi": "2.0",
        }
        cfg["api_keys"] = {}
        with open(_default_cfg, "w") as fh:
            cfg.write(fh)

    # Smart source discovery: seed ~/.nox/sources/ from package sources/
    # B6: only copy if destination is absent — never silently overwrite
    # user-customised sources. Use --reset-sources to force a full resync.
    candidate = _PKG_ROOT / "sources"
    if not candidate.is_dir():
        candidate = Path("/usr/share/nox-cli/sources")
    if candidate.is_dir():
        for jf in candidate.glob("*.json"):
            dst = SOURCE_DIR / jf.name
            try:
                if not dst.exists():
                    shutil.copy2(jf, dst)
            except OSError:
                pass


# ── Static Configuration ───────────────────────────────────────────────
class Cfg:
    TIMEOUT         = 30
    RETRIES         = 3
    RETRY_DELAY     = 2
    CONCURRENCY     = 20
    RATE_LIMIT      = (0.5, 2.0)
    TOR_SOCKS       = 9050
    TOR_CTRL        = 9051
    TOR_PASS        = ""
    STEALTH         = True
    BASE            = HOME_NOX
    DB              = HOME_NOX / "nox_cache.db"
    REPORTS         = REPORT_DIR
    LOGS            = LOG_DIR
    WORDLISTS       = HOME_NOX / "wordlists"
    CACHE_TTL       = 86400
    DORK_MAX        = 50
    DORK_DELAY      = (0.5, 2.0)
    PASTE_MAX       = 100
    PASTE_DELAY     = (1.0, 3.0)
    PIVOT_DEPTH     = 2
    PIVOT_CONFIDENCE = 0.70

    # Browser-grade TLS cipher suite for JA3 fingerprint matching
    TLS_CIPHERS = (
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    )

    @classmethod
    def init(cls) -> None:
        for d in [cls.REPORTS, cls.LOGS, cls.WORDLISTS]:
            d.mkdir(parents=True, exist_ok=True)
        cls.BASE.mkdir(parents=True, exist_ok=True)


Cfg.init()


# ── Runtime Configuration ──────────────────────────────────────────────
class NoxConfig:
    def __init__(self) -> None:
        self.use_tor      = False
        self.proxy        = None
        self.concurrency  = Cfg.CONCURRENCY
        self.timeout      = Cfg.TIMEOUT
        self.stealth      = Cfg.STEALTH
        self.rate_limit   = Cfg.RATE_LIMIT
        self.tor_socks    = Cfg.TOR_SOCKS
        self.tor_ctrl     = Cfg.TOR_CTRL
        self.tor_pass     = Cfg.TOR_PASS
        self.allow_leak   = False
        self.no_online_crack = False
        self.max_threads  = Cfg.CONCURRENCY
        # A9/I3: pivot control — readable by AvalancheScanner
        self.no_pivot     = False
        self.pivot_depth  = Cfg.PIVOT_DEPTH


# ── Logging ────────────────────────────────────────────────────────────
LOG_DIR.mkdir(parents=True, exist_ok=True)
SYSLOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("nox")
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    _fh = logging.FileHandler(str(LOG_DIR / "nox.log"))
    _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    _fh.setLevel(logging.DEBUG)
    logger.addHandler(_fh)
    # Terminal: WARNING and above only — no debug/info noise
    _sh = logging.StreamHandler()
    _sh.setLevel(logging.WARNING)
    _sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(_sh)

# ── System event log: API status, rate-limits, crack attempts ─────────
# Writes to ~/.config/nox-cli/logs/nox_system.log — never to terminal
_syslog = logging.getLogger("nox.system")
if not _syslog.handlers:
    _syslog.setLevel(logging.INFO)
    _sfh = logging.FileHandler(str(SYSLOG_DIR / "nox_system.log"))
    _sfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    _syslog.addHandler(_sfh)
    _syslog.propagate = False


# ── Colors / Console ───────────────────────────────────────────────────
class C:
    R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"; B  = "\033[94m"
    P  = "\033[95m"; CY = "\033[96m"; W  = "\033[97m"; GR = "\033[90m"
    O  = "\033[38;5;208m"; BD = "\033[1m"; DM = "\033[2m"; X  = "\033[0m"

    @staticmethod
    def c(t: str, color: str = "W") -> str:
        m = {
            "red": C.R, "green": C.G, "yellow": C.Y, "blue": C.B,
            "purple": C.P, "cyan": C.CY, "white": C.W, "gray": C.GR,
            "orange": C.O, "bold": C.BD, "dim": C.DM,
        }
        return f"{m.get(color, C.W)}{t}{C.X}"


class Console:
    ICONS = {
        "breach": f"{C.R}[!]{C.X}", "pass": f"{C.Y}[*]{C.X}", "hash": f"{C.P}[#]{C.X}",
        "net": f"{C.B}[~]{C.X}", "stealth": f"{C.GR}[^]{C.X}", "ok": f"{C.G}[+]{C.X}",
        "err": f"{C.R}[-]{C.X}", "warn": f"{C.Y}[!]{C.X}", "info": f"{C.CY}[i]{C.X}",
        "db": f"{C.B}[D]{C.X}", "report": f"{C.G}[R]{C.X}", "dork": f"{C.O}[G]{C.X}",
        "paste": f"{C.P}[P]{C.X}", "scrape": f"{C.B}[S]{C.X}", "combo": f"{C.R}[C]{C.X}",
        "pivot": f"{C.CY}[↻]{C.X}",
    }

    @staticmethod
    def s(msg: str, icon: str = "info") -> None:
        print(f"  {Console.ICONS.get(icon, Console.ICONS['info'])} {msg}")

    @staticmethod
    def ok(msg: str) -> None:
        Console.s(msg, "ok")

    @staticmethod
    def err(msg: str) -> None:
        Console.s(msg, "err")

    @staticmethod
    def warn(msg: str) -> None:
        Console.s(msg, "warn")

    @staticmethod
    def dim(msg: str) -> None:
        pass  # file logging handled by out()

    @staticmethod
    def section(title: str) -> None:
        print(f"\n  {C.c('='*58,'purple')}\n  {C.c(f'  {title}','bold')}\n  {C.c('='*58,'purple')}")

    @staticmethod
    def table(headers: List[str], rows: List[List], title: str = None) -> None:
        if title:
            print(f"\n  {C.c(title,'bold')}")
        if not rows:
            print(f"  {C.c('(empty)','gray')}")
            return
        widths = [
            max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
            for i, h in enumerate(headers)
        ]
        hdr = " | ".join(C.c(str(h).ljust(widths[i]), "cyan") for i, h in enumerate(headers))
        print(f"  {hdr}\n  {'-+-'.join('-'*w for w in widths)}")
        for row in rows:
            print(f"  {' | '.join(str(row[i]).ljust(widths[i]) for i in range(len(headers)))}")

    @staticmethod
    def progress(cur: int, tot: int, prefix: str = "Progress", w: int = 30) -> None:
        if tot == 0:
            return
        p = cur / tot
        f = int(w * p)
        bar = C.c("█" * f, "green") + C.c("░" * (w - f), "gray")
        print(f"\r  {prefix} [{bar}] {C.c(f'{p:.0%}','cyan')} ({cur}/{tot})", end="", flush=True)
        if cur >= tot:
            print()


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def out(level: str, msg: str) -> None:
    fn = getattr(Console, level, None)
    if fn:
        fn(msg)
    else:
        Console.s(msg)
    # Mirror every terminal message to the log file so users can audit the full run.
    clean = _ANSI_RE.sub("", msg)
    if level in ("err",):
        logger.error("[%s] %s", level, clean)
    elif level in ("warn",):
        logger.warning("[%s] %s", level, clean)
    elif level in ("ok", "info", "pivot", "breach", "scrape", "dork", "paste"):
        logger.info("[%s] %s", level, clean)
    else:
        logger.debug("[%s] %s", level, clean)


# ── Data Models ────────────────────────────────────────────────────────
class Severity(Enum):
    CRITICAL = auto()
    HIGH     = auto()
    MEDIUM   = auto()
    LOW      = auto()
    INFO     = auto()


# ── Intelligence constants ─────────────────────────────────────────────
_SRC_CONFIDENCE: Dict[str, float] = {
    "HIBP": 1.0, "HudsonRock": 0.95, "SpyCloud": 0.92, "RecordedFuture": 0.90,
    "Dehashed": 0.88, "WhiteIntel": 0.88, "CyberSixGill": 0.87, "FlareIO": 0.85,
    "DarkTracer": 0.85, "IntelX": 0.83, "SOCRadar": 0.82, "LeakCheck": 0.80,
    "BreachSense": 0.80, "DataViper": 0.78, "Snusbase": 0.75, "WeLeakInfo": 0.75,
    "LeakLookup": 0.72, "LeakLookupV2": 0.72, "BulkLeakLookup": 0.70,
    "Scylla": 0.68, "DeepSearch": 0.65, "BreachDirectory": 0.65, "LeakPeek": 0.65,
    "LeakSearch": 0.63, "CheckLeaked": 0.62, "Antipublic": 0.60, "GhostProject": 0.60,
    "LeakedSite": 0.58, "LeakedPassword": 0.58, "NuclearLeaks": 0.55,
    "ProxyNovaCOMB": 0.55, "CredStuffDB": 0.55, "ComboList": 0.55,
    "PwnDB": 0.52, "LeakOSINT": 0.52, "Pentester": 0.50,
    "HunterIO": 0.70, "FullContact": 0.68, "PeopleDataLabs": 0.68,
    "ZeroBounce": 0.65, "RocketReach": 0.62, "Gravatar": 0.45,
    "EmailRep": 0.55, "Holehe": 0.50, "NameCheck": 0.45,
    "FirefoxMonitor": 0.60, "AvastHackCheck": 0.55, "Inoitsu": 0.50,
    "BreachAlarm": 0.50, "HaveIBeenSold": 0.55, "CyberNews": 0.55,
    "XposedOrNot": 0.60, "AshleyMadison": 0.70,
    "Shodan": 0.80, "Censys": 0.78, "BinaryEdge": 0.75, "SecurityTrails": 0.75,
    "FullHunt": 0.72, "Netlas": 0.70, "ZoomEye": 0.70, "Onyphe": 0.68,
    "VirusTotal": 0.85, "AlienVaultOTX": 0.80, "Pulsedive": 0.72,
    "ThreatCrowd": 0.65, "Maltiverse": 0.65, "PassiveTotal": 0.75,
    "AbuseIPDB": 0.78, "GreyNoise": 0.75, "MXToolbox": 0.65,
    "WhoisXML": 0.60, "URLScan": 0.65, "ExploitDB": 0.70,
    "ThreatBook": 0.68, "Huntress": 0.72,
    "StealerLogSearch": 0.90, "IntelXPhone": 0.80, "IntelFinder": 0.75,
    "BreachForumsIntel": 0.60, "RaidForumsArchive": 0.55, "OGUsers": 0.50,
    "Cracked.to": 0.55, "Nulled.to": 0.55, "DarkWebTor": 0.50,
    "WikiLeaks": 0.75, "RansomWatch": 0.85, "DataBreaches.net": 0.55,
    "PastebinIntel": 0.35, "PasteHunter": 0.35, "ScrapeEngine": 0.30,
    "TelegramOSINT": 0.30, "GoogleDork": 0.30, "SynapsInt": 0.40,
    "WaybackMachine": 0.40, "BuiltWith": 0.40, "CertStream": 0.45,
    "GitLeaks": 0.65, "SPF/DMARC": 0.40, "Picostatus": 0.30,
    "LeakedDomains": 0.60, "Leakix": 0.72,
    "PhoneInfo": 0.55, "Numverify": 0.60, "TrueCaller": 0.65,
    "Hashmob": 0.95, "HashKiller": 0.90, "HashesOrg": 0.90,
    "LeakLookupHash": 0.80,
}

_STEALER_TAGS  = {"stealer", "redline", "raccoon", "vidar", "infostealer", "lumma", "azorult", "stealc"}
_FAST_HASHES   = {"md5", "sha1", "sha256", "ntlm", "lm"}
_CORP_PW_RE    = re.compile(r"(?i)([A-Z][a-z]{2,})(20\d{2}|19\d{2})[!@#$%^&*]?$")
_VIP_EMAIL_RE  = re.compile(r"(?i)(admin|administrator|root|ceo|cto|ciso|cfo|vp|director|manager|sysadmin|devops|security|infosec|noc|soc)")
_VIP_DOM_RE    = re.compile(r"\.(gov|mil|edu|police|gouv|gob)(\.[a-z]{2})?$", re.I)
_HVT_KEYWORDS  = frozenset({
    "admin", "administrator", "root", "ceo", "cto", "ciso", "cfo",
    "vp", "director", "manager", "sysadmin", "devops", "security",
    "infosec", "noc", "soc", "superuser", "sa", "dba", "ops",
})
_HVT_DOMAINS   = re.compile(
    r"\.(gov|mil|int|police|gouv|gob|gc\.ca|gov\.uk|mod\.uk)(\.[a-z]{2})?$",
    re.IGNORECASE,
)

_INTEL_SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    primary_id  TEXT NOT NULL UNIQUE,
    emails      TEXT DEFAULT '[]',
    usernames   TEXT DEFAULT '[]',
    phones      TEXT DEFAULT '[]',
    max_risk    REAL DEFAULT 0.0,
    is_hvt      INTEGER DEFAULT 0,
    pivot_count TEXT DEFAULT '{}',
    ts          REAL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS leaks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id     INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    source          TEXT,
    email           TEXT,
    username        TEXT,
    password        TEXT,
    password_hash   TEXT,
    hash_type       TEXT,
    phone           TEXT,
    breach_name     TEXT,
    breach_date     TEXT,
    risk_score      REAL DEFAULT 0,
    source_conf     REAL DEFAULT 0.5,
    data_types      TEXT DEFAULT '[]',
    is_hvt          INTEGER DEFAULT 0,
    dedup_hash      TEXT UNIQUE,
    ts              REAL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS correlation_links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    pivot_type  TEXT,
    pivot_value TEXT,
    linked_ids  TEXT DEFAULT '[]',
    ts          REAL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS query_cache (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    query   TEXT NOT NULL UNIQUE,
    qtype   TEXT,
    scanned REAL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_leaks_email    ON leaks(email);
CREATE INDEX IF NOT EXISTS idx_leaks_identity ON leaks(identity_id);
CREATE INDEX IF NOT EXISTS idx_leaks_risk     ON leaks(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_leaks_dedup    ON leaks(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_ident_hvt      ON identities(is_hvt);
CREATE INDEX IF NOT EXISTS idx_cache_query    ON query_cache(query);
CREATE TABLE IF NOT EXISTS intel_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT, target TEXT, email TEXT,
    password    TEXT, phone TEXT, address TEXT,
    full_name   TEXT, fingerprint TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS dork_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url    TEXT UNIQUE,
    file_type     TEXT,
    metadata_json TEXT,
    parent_target TEXT,
    ts            REAL DEFAULT (strftime('%s','now'))
);
"""


def _parse_breach_date(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    raw = raw.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    m = re.search(r"(\d{2})/(\d{2})/(\d{4})", raw)
    if m:
        # Try MM/DD/YYYY first, then DD/MM/YYYY (European format)
        for month, day in [(int(m.group(1)), int(m.group(2))), (int(m.group(2)), int(m.group(1)))]:
            try:
                return datetime(int(m.group(3)), month, day, tzinfo=timezone.utc)
            except ValueError:
                pass
    m = re.fullmatch(r"(\d{4})", raw)
    if m:
        return datetime(int(m.group(1)), 1, 1, tzinfo=timezone.utc)
    return None


# ── Shared helpers ─────────────────────────────────────────────────────
def _rec_get(r: Any, k: str) -> Any:
    return r.get(k, "") if isinstance(r, dict) else getattr(r, k, "")


def _is_vip(r: Any) -> bool:
    ident = _rec_get(r, "email") or _rec_get(r, "username")
    return bool(_VIP_EMAIL_RE.search(ident) or _VIP_DOM_RE.search(ident))


def _is_stealer(r: Any) -> bool:
    dt = _rec_get(r, "data_types") or []
    combined = (
        (" ".join(dt) if isinstance(dt, list) else str(dt)).lower()
        + _rec_get(r, "source").lower()
    )
    return any(t in combined for t in _STEALER_TAGS)


# ── Record dataclass ───────────────────────────────────────────────────
@dataclass
class Record:
    source:            str
    email:             str       = ""
    username:          str       = ""
    password:          str       = ""
    password_hash:     str       = ""
    hash_type:         str       = ""
    ip_address:        str       = ""
    phone:             str       = ""
    name:              str       = ""
    domain:            str       = ""
    breach_date:       str       = ""
    breach_name:       str       = ""
    data_types:        List[str] = field(default_factory=list)
    severity:          Severity  = Severity.MEDIUM
    raw_data:          Dict      = field(default_factory=dict)
    verified:          bool      = False
    timestamp:         str       = field(default_factory=lambda: datetime.now().isoformat())
    risk_score:        float     = 0.0
    source_confidence: float     = 0.5
    is_hvt:            bool      = False
    persistence_score: float     = 0.0

    address:           str       = ""
    full_name:         str       = ""
    metadata:          Dict      = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d

    def dedup_key(self) -> str:
        """SHA-256 of normalised email:password for cross-source deduplication."""
        em = (self.email or self.username or "").lower().strip()
        pw = (self.password or self.password_hash or "").strip()
        return hashlib.sha256(f"{em}:{pw}".encode()).hexdigest()

    def get_fingerprint(self) -> str:
        """Genera un hash univoco per evitare duplicati nel database."""
        data_str = f"{self.source}|{self.email}|{self.password}|{self.phone}|{self.address}"
        return hashlib.sha256(data_str.encode()).hexdigest()


# ── Risk Engine ────────────────────────────────────────────────────────
class RiskEngine:
    """
    Predictive risk scoring engine (0–100).

    Temporal Correlation & Exposure Scoring:
    - Persistence Score: multiplier when data appears across multiple distinct
      datasets in different years.
    - Exposure Recency: exponential multiplier for recent breaches.
    """

    _DECAY_BOOST_DAYS   = 365
    _DECAY_MID_DAYS     = 730
    _DECAY_PENALTY_DAYS = 1825

    @staticmethod
    def score(record: "Record") -> "Record":
        conf = _SRC_CONFIDENCE.get(record.source, 0.5)
        record.source_confidence = conf

        dtypes_str = " ".join(record.data_types).lower() if record.data_types else ""
        src_lower  = record.source.lower()

        is_stealer = any(t in dtypes_str or t in src_lower for t in _STEALER_TAGS)
        if is_stealer and record.password:
            record.risk_score = 100.0
            record.severity   = Severity.CRITICAL
            return record

        pts = 0.0
        if record.password:
            pts += 60
            # I5: adjust base points by password complexity
            # Weak passwords (trivially guessable) score lower; strong ones score higher.
            try:
                _pa_score = PassAnalyzer().analyze(record.password).get("score", 50)
                if _pa_score < 30:
                    pts = max(0.0, pts - 15)
                elif _pa_score > 80:
                    pts = min(100.0, pts + 10)
            except Exception:
                pass
        elif record.password_hash:
            ht   = (record.hash_type or "").lower()
            pts += 30 if ht in _FAST_HASHES else 15
        else:
            pts += 5

        dt = _parse_breach_date(record.breach_date)
        if dt:
            age_days = (datetime.now(timezone.utc) - dt).days
            if age_days < RiskEngine._DECAY_BOOST_DAYS:
                # Exponential recency multiplier
                recency_factor = 1.0 + 0.5 * math.exp(-age_days / 180)
                pts = pts * recency_factor + 30
            elif age_days < RiskEngine._DECAY_MID_DAYS:
                pts += 15
            elif age_days > RiskEngine._DECAY_PENALTY_DAYS:
                pts = max(0.0, pts - 20)

        pts *= 0.5 + conf * 0.5

        ident       = record.email or record.username or ""
        local       = ident.split("@")[0].lower() if "@" in ident else ident.lower()
        domain_part = ident.split("@")[1].lower() if "@" in ident else ""
        if (
            any(kw in local for kw in _HVT_KEYWORDS)
            or (_HVT_DOMAINS.search(domain_part) if domain_part else False)
            or _VIP_EMAIL_RE.search(ident)
            or _VIP_DOM_RE.search(ident)
        ):
            pts = min(100.0, pts + 15)

        record.risk_score = round(min(pts, 100.0), 1)
        rs = record.risk_score
        if rs >= 90:   record.severity = Severity.CRITICAL
        elif rs >= 70: record.severity = Severity.HIGH
        elif rs >= 40: record.severity = Severity.MEDIUM
        elif rs >= 10: record.severity = Severity.LOW
        else:          record.severity = Severity.INFO
        return record

    @staticmethod
    def apply_persistence(records: List["Record"]) -> List["Record"]:
        """
        Assign a Persistence Score when the same identity appears across
        multiple distinct breach datasets in different calendar years.
        """
        identity_years: Dict[str, Set[int]] = {}
        identity_sources: Dict[str, Set[str]] = {}

        for r in records:
            ident = (r.email or r.username or "").lower()
            if not ident:
                continue
            identity_sources.setdefault(ident, set()).add(r.source)
            dt = _parse_breach_date(r.breach_date)
            if dt:
                identity_years.setdefault(ident, set()).add(dt.year)

        for r in records:
            ident = (r.email or r.username or "").lower()
            if not ident:
                continue
            years   = identity_years.get(ident, set())
            sources = identity_sources.get(ident, set())
            if len(years) >= 2 and len(sources) >= 2:
                span = max(years) - min(years) if years else 0
                r.persistence_score = round(min(100.0, len(sources) * 10 + span * 5), 1)
                r.risk_score = round(min(100.0, r.risk_score + r.persistence_score * 0.3), 1)
        return records


# ── Identity Graphing & Correlation ───────────────────────────────────
@dataclass
class TargetProfile:
    """Unified identity profile built by IdentityResolver."""

    primary_id:    str
    emails:        List[str]      = field(default_factory=list)
    usernames:     List[str]      = field(default_factory=list)
    phones:        List[str]      = field(default_factory=list)
    records:       list           = field(default_factory=list)
    pivot_count:   Dict[str, int] = field(default_factory=dict)
    max_risk:      float          = 0.0
    is_hvt:        bool           = False
    stuffing_risk: str            = "LOW"

    def _add(self, rec: Any) -> None:
        self.records.append(rec)
        self.max_risk = max(self.max_risk, float(_rec_get(rec, "risk_score") or 0.0))

        pw  = _rec_get(rec, "password")
        usr = _rec_get(rec, "username")
        ph  = _rec_get(rec, "phone")
        for val in filter(None, [
            pw if pw and len(pw) > 6 else None,
            usr or None,
            ph or None,
        ]):
            self.pivot_count[val] = self.pivot_count.get(val, 0) + 1

        em = _rec_get(rec, "email")
        if em  and em  not in self.emails:    self.emails.append(em)
        if usr and usr not in self.usernames: self.usernames.append(usr)
        if ph  and ph  not in self.phones:    self.phones.append(ph)

        ident = em or usr or ""
        if _VIP_EMAIL_RE.search(ident) or _VIP_DOM_RE.search(ident):
            self.is_hvt = True

    def _compute_stuffing_risk(self) -> None:
        max_reuse = max(self.pivot_count.values(), default=0)
        if max_reuse >= 5:   self.stuffing_risk = "CRITICAL"
        elif max_reuse >= 3: self.stuffing_risk = "HIGH"
        elif max_reuse >= 2: self.stuffing_risk = "MEDIUM"
        else:                self.stuffing_risk = "LOW"


class IdentityResolver:
    """Links breach records into unified TargetProfile clusters via Union-Find."""

    def __init__(self, records: list) -> None:
        self._records = records

    def resolve(self) -> List[TargetProfile]:
        parent: Dict[str, str] = {}
        pivot_map: Dict[str, str] = {}

        def _root(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent.get(x, x), x)
                x = parent.get(x, x)
            return x

        def _union(a: str, b: str) -> None:
            ra, rb = _root(a), _root(b)
            if ra != rb:
                parent[rb] = ra

        for rec in self._records:
            node = (
                _rec_get(rec, "email") or _rec_get(rec, "username")
                or _rec_get(rec, "phone") or _rec_get(rec, "source")
            )
            if not node:
                continue
            parent.setdefault(node, node)
            pw = _rec_get(rec, "password")
            for pv in filter(None, [
                _rec_get(rec, "email") or None,
                _rec_get(rec, "username") or None,
                _rec_get(rec, "phone") or None,
                pw if pw and len(pw) > 6 else None,
            ]):
                if pv in pivot_map:
                    _union(node, pivot_map[pv])
                else:
                    pivot_map[pv] = node

        clusters: Dict[str, TargetProfile] = {}
        for rec in self._records:
            node = (
                _rec_get(rec, "email") or _rec_get(rec, "username")
                or _rec_get(rec, "phone") or _rec_get(rec, "source")
            )
            if not node:
                continue
            root = _root(node)
            if root not in clusters:
                clusters[root] = TargetProfile(primary_id=root)
            clusters[root]._add(rec)

        for profile in clusters.values():
            profile._compute_stuffing_risk()

        return sorted(clusters.values(), key=lambda p: -p.max_risk)


# ── HVT Analyzer ──────────────────────────────────────────────────────
class HVTAnalyzer:
    """High-Value Target & VIP detection module."""

    @staticmethod
    def is_hvt(record: Any) -> bool:
        ident       = _rec_get(record, "email") or _rec_get(record, "username") or ""
        local       = ident.split("@")[0].lower() if "@" in ident else ident.lower()
        domain_part = ident.split("@")[1].lower() if "@" in ident else ""
        if any(kw in local for kw in _HVT_KEYWORDS):
            return True
        if domain_part and _HVT_DOMAINS.search(domain_part):
            return True
        if _VIP_EMAIL_RE.search(ident) or _VIP_DOM_RE.search(ident):
            return True
        return False

    @staticmethod
    def filter_hvt(records: list) -> list:
        hvt = [r for r in records if HVTAnalyzer.is_hvt(r)]
        return sorted(hvt, key=lambda r: _rec_get(r, "risk_score") or 0, reverse=True)

    @staticmethod
    def annotate(records: list) -> list:
        for rec in records:
            flag = HVTAnalyzer.is_hvt(rec)
            if isinstance(rec, dict):
                rec["is_hvt"] = flag
            else:
                rec.is_hvt = flag
        return records


# ── Forensic Persistence Layer ─────────────────────────────────────────
class DatabaseManager:
    """
    Async aiosqlite persistence layer for CTI data with 24 h query cache
    and SHA-256 deduplication.  Falls back to synchronous sqlite3 when
    aiosqlite is not installed.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or str(HOME_NOX / "nox_cache.db")
        self._use_async = aiosqlite is not None
        # Initialise schema synchronously so the constructor stays non-async.
        self._init_sync()

    # ── Schema bootstrap ──────────────────────────────────────────────

    def _init_sync(self) -> None:
        con = _sqlite3_fallback.connect(self.path, timeout=15)
        con.execute("PRAGMA journal_mode=WAL")
        # Run column migrations before applying full schema (handles existing DBs)
        _migrations = [
            "ALTER TABLE leaks ADD COLUMN dedup_hash TEXT",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_leaks_dedup_unique ON leaks(dedup_hash) WHERE dedup_hash IS NOT NULL",
        ]
        for stmt in _migrations:
            try:
                con.execute(stmt)
                con.commit()
            except _sqlite3_fallback.OperationalError:
                pass  # column already exists or table doesn't exist yet
        con.executescript(_INTEL_SCHEMA)
        con.commit()
        con.close()

    # ── Public async API ──────────────────────────────────────────────

    async def get_cached(self, query: str) -> Optional[List[dict]]:
        q_lower = query.lower()
        if self._use_async:
            async with aiosqlite.connect(self.path, timeout=15) as db:
                db.row_factory = aiosqlite.Row
                await db.execute("PRAGMA journal_mode=WAL")
                async with db.execute(
                    "SELECT id, scanned FROM query_cache WHERE query=?", (q_lower,)
                ) as cur:
                    row = await cur.fetchone()
                if not row:
                    return None
                if datetime.now(timezone.utc).timestamp() - row["scanned"] > Cfg.CACHE_TTL:
                    return None
                async with db.execute(
                    "SELECT * FROM leaks WHERE email=? OR username=?",
                    (q_lower, q_lower),
                ) as cur:
                    rows = await cur.fetchall()
                return [dict(r) for r in rows]
        else:
            return self._get_cached_sync(q_lower)

    async def cache_records(self, query: str, qtype: str, records: list) -> None:
        if self._use_async:
            await self._cache_records_async(query, qtype, records)
        else:
            self._cache_records_sync(query, qtype, records)

    async def save_correlations(self, query: str, profiles: List[TargetProfile]) -> None:
        if self._use_async:
            await self._save_correlations_async(profiles)
        else:
            self._save_correlations_sync(profiles)

    async def save_record(self, r: "Record") -> None:
        if self._use_async:
            async with aiosqlite.connect(self.path, timeout=15) as db:
                await db.execute(
                    "INSERT OR IGNORE INTO intel_records "
                    "(source, target, email, password, phone, address, full_name, fingerprint) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (r.source, getattr(r, "target", ""), r.email, r.password,
                     r.phone, r.address, r.full_name, r.get_fingerprint()),
                )
                await db.commit()
        else:
            with _sqlite3_fallback.connect(self.path, timeout=15) as db:
                db.execute(
                    "INSERT OR IGNORE INTO intel_records "
                    "(source, target, email, password, phone, address, full_name, fingerprint) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (r.source, getattr(r, "target", ""), r.email, r.password,
                     r.phone, r.address, r.full_name, r.get_fingerprint()),
                )

    async def get_hvt_identities(self) -> List[dict]:
        if self._use_async:
            async with aiosqlite.connect(self.path, timeout=15) as db:
                db.row_factory = aiosqlite.Row
                await db.execute("PRAGMA journal_mode=WAL")
                async with db.execute(
                    "SELECT * FROM identities WHERE is_hvt=1 ORDER BY max_risk DESC"
                ) as cur:
                    rows = await cur.fetchall()
                return [dict(r) for r in rows]
        else:
            return self._get_hvt_sync()

    # ── Async implementations ─────────────────────────────────────────

    async def _cache_records_async(self, query: str, qtype: str, records: list) -> None:
        seen_hashes: Set[str] = set()
        async with aiosqlite.connect(self.path, timeout=15) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL")
            try:
                await db.execute(
                    "INSERT OR REPLACE INTO query_cache (query, qtype) VALUES (?,?)",
                    (query.lower(), qtype),
                )
                for rec in records:
                    dk = rec.dedup_key() if hasattr(rec, "dedup_key") else ""
                    if dk and dk in seen_hashes:
                        continue
                    if dk:
                        seen_hashes.add(dk)
                    ident  = rec.email or rec.username or rec.phone or query
                    is_hvt = int(bool(_VIP_EMAIL_RE.search(ident) or _VIP_DOM_RE.search(ident)))
                    await db.execute(
                        "INSERT OR IGNORE INTO identities (primary_id, is_hvt) VALUES (?,?)",
                        (ident, is_hvt),
                    )
                    async with db.execute(
                        "SELECT id FROM identities WHERE primary_id=?", (ident,)
                    ) as cur:
                        row = await cur.fetchone()
                    if not row:
                        continue
                    iid = row["id"]
                    await db.execute(
                        """INSERT INTO leaks
                           (identity_id, source, email, username, password,
                            password_hash, hash_type, phone, breach_name,
                            breach_date, risk_score, source_conf, data_types, is_hvt, dedup_hash)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            iid, rec.source, rec.email, rec.username,
                            rec.password, rec.password_hash, rec.hash_type,
                            rec.phone, rec.breach_name, rec.breach_date,
                            getattr(rec, "risk_score", 0.0),
                            getattr(rec, "source_confidence", 0.5),
                            json.dumps(rec.data_types),
                            is_hvt, dk,
                        ),
                    )
                await db.commit()
            except Exception as exc:
                logger.warning("DB store error: %s", exc)

    async def _save_correlations_async(self, profiles: List[TargetProfile]) -> None:
        async with aiosqlite.connect(self.path, timeout=15) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL")
            try:
                for profile in profiles:
                    await db.execute(
                        """UPDATE identities
                           SET emails=?, usernames=?, phones=?,
                               max_risk=?, is_hvt=?, pivot_count=?
                           WHERE primary_id=?""",
                        (
                            json.dumps(profile.emails),
                            json.dumps(profile.usernames),
                            json.dumps(profile.phones),
                            profile.max_risk,
                            int(profile.is_hvt),
                            json.dumps(profile.pivot_count),
                            profile.primary_id,
                        ),
                    )
                    async with db.execute(
                        "SELECT id FROM identities WHERE primary_id=?", (profile.primary_id,)
                    ) as cur:
                        row = await cur.fetchone()
                    if not row:
                        continue
                    iid = row["id"]
                    for pivot_val, count in profile.pivot_count.items():
                        if count > 1:
                            # I6: use Detect.qtype instead of length heuristic
                            _ptype = Detect.qtype(pivot_val)
                            if _ptype not in ("email", "username", "phone", "domain", "ip"):
                                _ptype = "username"
                            await db.execute(
                                """INSERT INTO correlation_links
                                   (identity_id, pivot_type, pivot_value, linked_ids)
                                   VALUES (?,?,?,?)""",
                                (
                                    iid,
                                    _ptype,
                                    pivot_val[:64],
                                    json.dumps(profile.emails[:10]),
                                ),
                            )
                await db.commit()
            except Exception as exc:
                logger.warning("DB correlation error: %s", exc)

    # ── Synchronous fallbacks (used when aiosqlite is absent) ─────────

    def _get_cached_sync(self, q_lower: str) -> Optional[List[dict]]:
        con = _sqlite3_fallback.connect(self.path, timeout=15)
        con.row_factory = _sqlite3_fallback.Row
        con.execute("PRAGMA journal_mode=WAL")
        try:
            row = con.execute(
                "SELECT id, scanned FROM query_cache WHERE query=?", (q_lower,)
            ).fetchone()
            if not row:
                return None
            if datetime.now(timezone.utc).timestamp() - row["scanned"] > Cfg.CACHE_TTL:
                return None
            return [
                dict(r) for r in con.execute(
                    "SELECT * FROM leaks WHERE email=? OR username=?",
                    (q_lower, q_lower),
                ).fetchall()
            ]
        finally:
            con.close()

    def _cache_records_sync(self, query: str, qtype: str, records: list) -> None:
        con = _sqlite3_fallback.connect(self.path, timeout=15)
        con.row_factory = _sqlite3_fallback.Row
        con.execute("PRAGMA journal_mode=WAL")
        seen_hashes: Set[str] = set()
        try:
            con.execute(
                "INSERT OR REPLACE INTO query_cache (query, qtype) VALUES (?,?)",
                (query.lower(), qtype),
            )
            for rec in records:
                dk = rec.dedup_key() if hasattr(rec, "dedup_key") else ""
                if dk and dk in seen_hashes:
                    continue
                if dk:
                    seen_hashes.add(dk)
                ident  = rec.email or rec.username or rec.phone or query
                is_hvt = int(bool(_VIP_EMAIL_RE.search(ident) or _VIP_DOM_RE.search(ident)))
                con.execute(
                    "INSERT OR IGNORE INTO identities (primary_id, is_hvt) VALUES (?,?)",
                    (ident, is_hvt),
                )
                row = con.execute(
                    "SELECT id FROM identities WHERE primary_id=?", (ident,)
                ).fetchone()
                if not row:
                    continue
                iid = row["id"]
                con.execute(
                    """INSERT INTO leaks
                       (identity_id, source, email, username, password,
                        password_hash, hash_type, phone, breach_name,
                        breach_date, risk_score, source_conf, data_types, is_hvt, dedup_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        iid, rec.source, rec.email, rec.username,
                        rec.password, rec.password_hash, rec.hash_type,
                        rec.phone, rec.breach_name, rec.breach_date,
                        getattr(rec, "risk_score", 0.0),
                        getattr(rec, "source_confidence", 0.5),
                        json.dumps(rec.data_types),
                        is_hvt, dk,
                    ),
                )
            con.commit()
        except _sqlite3_fallback.OperationalError as exc:
            logger.warning("DB store error: %s", exc)
        finally:
            con.close()

    def _save_correlations_sync(self, profiles: List[TargetProfile]) -> None:
        con = _sqlite3_fallback.connect(self.path, timeout=15)
        con.row_factory = _sqlite3_fallback.Row
        con.execute("PRAGMA journal_mode=WAL")
        try:
            for profile in profiles:
                con.execute(
                    """UPDATE identities
                       SET emails=?, usernames=?, phones=?,
                           max_risk=?, is_hvt=?, pivot_count=?
                       WHERE primary_id=?""",
                    (
                        json.dumps(profile.emails),
                        json.dumps(profile.usernames),
                        json.dumps(profile.phones),
                        profile.max_risk,
                        int(profile.is_hvt),
                        json.dumps(profile.pivot_count),
                        profile.primary_id,
                    ),
                )
                row = con.execute(
                    "SELECT id FROM identities WHERE primary_id=?", (profile.primary_id,)
                ).fetchone()
                if not row:
                    continue
                iid = row["id"]
                for pivot_val, count in profile.pivot_count.items():
                    if count > 1:
                        # I6: use Detect.qtype instead of length heuristic
                        _ptype = Detect.qtype(pivot_val)
                        if _ptype not in ("email", "username", "phone", "domain", "ip"):
                            _ptype = "username"
                        con.execute(
                            """INSERT INTO correlation_links
                               (identity_id, pivot_type, pivot_value, linked_ids)
                               VALUES (?,?,?,?)""",
                            (
                                iid,
                                _ptype,
                                pivot_val[:64],
                                json.dumps(profile.emails[:10]),
                            ),
                        )
            con.commit()
        except _sqlite3_fallback.OperationalError as exc:
            logger.warning("DB correlation error: %s", exc)
        finally:
            con.close()

    def _get_hvt_sync(self) -> List[dict]:
        con = _sqlite3_fallback.connect(self.path, timeout=15)
        con.row_factory = _sqlite3_fallback.Row
        con.execute("PRAGMA journal_mode=WAL")
        try:
            return [
                dict(r) for r in con.execute(
                    "SELECT * FROM identities WHERE is_hvt=1 ORDER BY max_risk DESC"
                ).fetchall()
            ]
        finally:
            con.close()


# ── Legacy DB (backward-compatible) ───────────────────────────────────
class DB:
    """
    Legacy synchronous DB facade.  Internally uses aiosqlite when available,
    running coroutines via a dedicated background event loop so callers
    remain synchronous.  Falls back to sqlite3 when aiosqlite is absent.
    """

    def __init__(self, path=None):
        self.path = str(path or Cfg.DB)
        self._use_async = aiosqlite is not None
        if self._use_async:
            import threading as _threading
            self._loop = asyncio.new_event_loop()
            self._loop_thread = _threading.Thread(
                target=self._loop.run_forever, daemon=True, name="nox-db-loop"
            )
            self._loop_thread.start()
        self._init()

    # ── Internal helpers ──────────────────────────────────────────────

    def _run(self, coro):
        """Submit a coroutine to the background loop and block until done."""
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=60)

    async def _exec(self, sql: str, params: tuple = ()) -> None:
        async with aiosqlite.connect(self.path, timeout=15) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute(sql, params)
            await db.commit()

    async def _fetchone(self, sql: str, params: tuple = ()) -> Optional[dict]:
        async with aiosqlite.connect(self.path, timeout=15) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL")
            async with db.execute(sql, params) as cur:
                row = await cur.fetchone()
            return dict(row) if row else None

    async def _fetchall(self, sql: str, params: tuple = ()) -> List[dict]:
        async with aiosqlite.connect(self.path, timeout=15) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL")
            async with db.execute(sql, params) as cur:
                rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def _init_async(self) -> None:
        async with aiosqlite.connect(self.path, timeout=15) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS breach_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT NOT NULL,
                    source TEXT NOT NULL, data TEXT NOT NULL, ts REAL NOT NULL,
                    ttl INTEGER DEFAULT 86400, UNIQUE(query, source));
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, username TEXT,
                    password TEXT, password_hash TEXT, hash_type TEXT, source TEXT,
                    breach_name TEXT, breach_date TEXT, ts REAL DEFAULT (strftime('%s','now')),
                    UNIQUE(email, password_hash, source));
                CREATE TABLE IF NOT EXISTS hash_cache (
                    hash TEXT PRIMARY KEY, hash_type TEXT, plaintext TEXT,
                    source TEXT, ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS api_keys (
                    service TEXT PRIMARY KEY, key TEXT NOT NULL,
                    ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, qtype TEXT,
                    results INTEGER, sources INTEGER, duration REAL,
                    ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS dork_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, engine TEXT,
                    dork TEXT, results TEXT, ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS paste_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, site TEXT,
                    pid TEXT, content TEXT, ts REAL DEFAULT (strftime('%s','now')),
                    UNIQUE(query, site, pid));
                CREATE TABLE IF NOT EXISTS wordlists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT,
                    data TEXT, ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY, value TEXT);
                CREATE INDEX IF NOT EXISTS idx_cred_email ON credentials(email);
                CREATE INDEX IF NOT EXISTS idx_cred_user  ON credentials(username);
                CREATE INDEX IF NOT EXISTS idx_cred_hash  ON credentials(password_hash);
                CREATE INDEX IF NOT EXISTS idx_cache_q    ON breach_cache(query);
            """)
            await db.commit()

    # ── Sync fallback helpers ─────────────────────────────────────────

    @contextmanager
    def _conn(self):
        c = _sqlite3_fallback.connect(self.path, timeout=15)
        c.row_factory = _sqlite3_fallback.Row
        c.execute("PRAGMA journal_mode=WAL")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def _init_sync(self):
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS breach_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT NOT NULL,
                    source TEXT NOT NULL, data TEXT NOT NULL, ts REAL NOT NULL,
                    ttl INTEGER DEFAULT 86400, UNIQUE(query, source));
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, username TEXT,
                    password TEXT, password_hash TEXT, hash_type TEXT, source TEXT,
                    breach_name TEXT, breach_date TEXT, ts REAL DEFAULT (strftime('%s','now')),
                    UNIQUE(email, password_hash, source));
                CREATE TABLE IF NOT EXISTS hash_cache (
                    hash TEXT PRIMARY KEY, hash_type TEXT, plaintext TEXT,
                    source TEXT, ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS api_keys (
                    service TEXT PRIMARY KEY, key TEXT NOT NULL,
                    ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, qtype TEXT,
                    results INTEGER, sources INTEGER, duration REAL,
                    ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS dork_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, engine TEXT,
                    dork TEXT, results TEXT, ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS paste_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, site TEXT,
                    pid TEXT, content TEXT, ts REAL DEFAULT (strftime('%s','now')),
                    UNIQUE(query, site, pid));
                CREATE TABLE IF NOT EXISTS wordlists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT,
                    data TEXT, ts REAL DEFAULT (strftime('%s','now')));
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY, value TEXT);
                CREATE INDEX IF NOT EXISTS idx_cred_email ON credentials(email);
                CREATE INDEX IF NOT EXISTS idx_cred_user  ON credentials(username);
                CREATE INDEX IF NOT EXISTS idx_cred_hash  ON credentials(password_hash);
                CREATE INDEX IF NOT EXISTS idx_cache_q    ON breach_cache(query);
            """)

    # ── Schema init dispatcher ────────────────────────────────────────

    def _init(self):
        if self._use_async:
            self._run(self._init_async())
        else:
            self._init_sync()

    # ── Public API ────────────────────────────────────────────────────

    def get_cache(self, q, src):
        if self._use_async:
            row = self._run(self._fetchone(
                "SELECT data,ts,ttl FROM breach_cache WHERE query=? AND source=?",
                (q.lower(), src),
            ))
            if row and (time.time() - row["ts"]) < row["ttl"]:
                return json.loads(row["data"])
            return None
        with self._conn() as c:
            r = c.execute(
                "SELECT data,ts,ttl FROM breach_cache WHERE query=? AND source=?",
                (q.lower(), src),
            ).fetchone()
            if r and (time.time() - r["ts"]) < r["ttl"]:
                return json.loads(r["data"])
        return None

    def set_cache(self, q, src, data, ttl=None):
        sql    = "INSERT OR REPLACE INTO breach_cache (query,source,data,ts,ttl) VALUES (?,?,?,?,?)"
        params = (q.lower(), src, json.dumps(data, default=str), time.time(), ttl or Cfg.CACHE_TTL)
        if self._use_async:
            self._run(self._exec(sql, params))
        else:
            with self._conn() as c:
                c.execute(sql, params)

    def store_cred(self, rec):
        # Use (email, password_hash, source) when hash is present;
        # fall back to (email, password, source) for cleartext-only records
        # so distinct cleartext passwords are never silently dropped.
        if rec.password_hash:
            sql    = ("INSERT OR IGNORE INTO credentials "
                      "(email,username,password,password_hash,hash_type,source,breach_name,breach_date) "
                      "VALUES (?,?,?,?,?,?,?,?)")
            params = (rec.email, rec.username, rec.password, rec.password_hash, rec.hash_type, rec.source, rec.breach_name, rec.breach_date)
        else:
            sql    = ("INSERT OR IGNORE INTO credentials "
                      "(email,username,password,password_hash,hash_type,source,breach_name,breach_date) "
                      "SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS "
                      "(SELECT 1 FROM credentials WHERE email=? AND password=? AND source=?)")
            params = (rec.email, rec.username, rec.password, rec.password_hash, rec.hash_type, rec.source, rec.breach_name, rec.breach_date,
                      rec.email, rec.password, rec.source)
        if self._use_async:
            self._run(self._exec(sql, params))
        else:
            with self._conn() as c:
                c.execute(sql, params)

    def get_key(self, svc):
        if self._use_async:
            row = self._run(self._fetchone(
                "SELECT key FROM api_keys WHERE service=?", (svc.lower(),)
            ))
        else:
            with self._conn() as c:
                r = c.execute("SELECT key FROM api_keys WHERE service=?", (svc.lower(),)).fetchone()
                row = dict(r) if r else None
        if row:
            return row["key"]
        svc_up = svc.upper().replace("-", "_")
        return (
            os.environ.get(svc_up)
            or os.environ.get(f"{svc_up}_API_KEY")
            or os.environ.get(f"NOX_{svc_up}_KEY")
            or os.environ.get(f"NOX_{svc_up}_API_KEY")
            or ""
        )

    def set_key(self, svc, key):
        sql    = "INSERT OR REPLACE INTO api_keys (service, key) VALUES (?,?)"
        params = (svc.lower(), key)
        if self._use_async:
            self._run(self._exec(sql, params))
        else:
            with self._conn() as c:
                c.execute(sql, params)

    def store_hash(self, h, ht, pt, src):
        sql    = "INSERT OR REPLACE INTO hash_cache (hash,hash_type,plaintext,source) VALUES (?,?,?,?)"
        params = (h, ht, pt, src)
        if self._use_async:
            self._run(self._exec(sql, params))
        else:
            with self._conn() as c:
                c.execute(sql, params)

    def get_plain(self, h):
        if self._use_async:
            row = self._run(self._fetchone(
                "SELECT plaintext FROM hash_cache WHERE hash=?", (h,)
            ))
            return row["plaintext"] if row else None
        with self._conn() as c:
            r = c.execute("SELECT plaintext FROM hash_cache WHERE hash=?", (h,)).fetchone()
            return r["plaintext"] if r else None

    def log_scan(self, q, qt, n, s, d):
        sql    = "INSERT INTO scans (query,qtype,results,sources,duration) VALUES (?,?,?,?,?)"
        params = (q, qt, n, s, d)
        if self._use_async:
            self._run(self._exec(sql, params))
        else:
            with self._conn() as c:
                c.execute(sql, params)

    def get_creds(self, q):
        sql    = "SELECT * FROM credentials WHERE email=? OR username=? ORDER BY ts DESC"
        params = (q.lower(), q.lower())
        if self._use_async:
            return self._run(self._fetchall(sql, params))
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, params).fetchall()]

    def set_config(self, k, v):
        sql    = "INSERT OR REPLACE INTO config (key, value) VALUES (?,?)"
        params = (k, v)
        if self._use_async:
            self._run(self._exec(sql, params))
        else:
            with self._conn() as c:
                c.execute(sql, params)

    def get_config(self, k, default=""):
        if self._use_async:
            row = self._run(self._fetchone(
                "SELECT value FROM config WHERE key=?", (k,)
            ))
            return row["value"] if row else default
        with self._conn() as c:
            r = c.execute("SELECT value FROM config WHERE key=?", (k,)).fetchone()
            return r["value"] if r else default

    def close(self) -> None:
        """Stop the background event loop thread and release resources."""
        if self._use_async and hasattr(self, "_loop") and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
            if hasattr(self, "_loop_thread"):
                self._loop_thread.join(timeout=5)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


NoxDB = DB


# ── Async TLS Context (JA3 fingerprint matching) ───────────────────────
def _build_ssl_context() -> ssl.SSLContext:
    """
    Build an SSLContext that mirrors a modern Chrome/Firefox TLS handshake
    to prevent bot-detection false positives.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(Cfg.TLS_CIPHERS)
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


_SSL_CTX = _build_ssl_context()


# ── Header randomisation helpers ──────────────────────────────────────
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 15; Mobile; rv:133.0) Gecko/133.0 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
]

_ACCEPT_LANG_POOL = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.8,fr;q=0.5",
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9,en-US;q=0.8",
]

_SEC_FETCH_DEST_POOL = ["document", "empty", "image", "script", "style"]
_SEC_FETCH_MODE_POOL = ["navigate", "cors", "no-cors", "same-origin"]
_SEC_FETCH_SITE_POOL = ["none", "same-origin", "cross-site", "same-site"]


def _random_headers(extra: Optional[Dict] = None) -> Dict[str, str]:
    """Return a randomised, browser-grade header set."""
    h = {
        "User-Agent":        random.choice(_UA_POOL),
        "Accept":            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language":   random.choice(_ACCEPT_LANG_POOL),
        "Accept-Encoding":   "gzip, deflate, br",
        "DNT":               "1",
        "Connection":        "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":    random.choice(_SEC_FETCH_DEST_POOL),
        "Sec-Fetch-Mode":    random.choice(_SEC_FETCH_MODE_POOL),
        "Sec-Fetch-Site":    random.choice(_SEC_FETCH_SITE_POOL),
        "Cache-Control":     "max-age=0",
    }
    if extra:
        h.update(extra)
    return h


async def _jitter(cfg: "NoxConfig") -> None:
    """Asynchronous jittered delay to respect server rate limits."""
    if cfg.stealth:
        lo, hi = cfg.rate_limit
        await asyncio.sleep(random.uniform(lo, hi))


# ── Async Source Base ──────────────────────────────────────────────────
class AsyncSource(ABC):
    """
    Base class for all async breach sources.
    Subclasses implement `async_search` which is called by the Orchestrator
    through a shared asyncio.Semaphore.
    """

    def __init__(self, semaphore, db: "DB", config: "NoxConfig") -> None:
        # Accept either a pre-built Semaphore or an int concurrency limit.
        # When an int is passed the semaphore is created lazily on first use
        # inside a running event loop (required on Python 3.10+).
        if isinstance(semaphore, asyncio.Semaphore):
            self._sem_obj: Optional[asyncio.Semaphore] = semaphore
            self._sem_limit: int = Cfg.CONCURRENCY  # unused when _sem_obj is set
        else:
            self._sem_obj = None
            self._sem_limit = int(semaphore) if semaphore else Cfg.CONCURRENCY
        self._db     = db
        self._config = config
        self.name       = "Unknown"
        self.needs_key  = False
        self.key_name   = ""
        self.ok_email   = True
        self.ok_user    = True
        self.ok_phone   = False
        self.ok_domain  = False
        self.ok_ip      = False
        self.ok_hash    = False
        self.ok_pass    = False
        self.ok_name    = False
        self.ok_url     = False

    @property
    def _sem(self) -> asyncio.Semaphore:
        """Return the semaphore, creating it lazily inside the running loop."""
        if self._sem_obj is None:
            self._sem_obj = asyncio.Semaphore(self._sem_limit)
        return self._sem_obj

    def _key(self) -> str:
        if not self.key_name:
            return ""
        svc = self.key_name[:-8] if self.key_name.endswith("_api_key") else self.key_name
        return self._db.get_key(svc)

    def _ok(self, qt: str) -> bool:
        m = {
            "email": self.ok_email, "username": self.ok_user, "phone": self.ok_phone,
            "domain": self.ok_domain, "ip": self.ok_ip, "hash": self.ok_hash,
            "password": self.ok_pass, "name": self.ok_name, "url": self.ok_url,
        }
        return m.get(qt, False)

    def _rec(self, **kw) -> Record:
        kw.setdefault("source", self.name)
        sev = kw.pop("severity", Severity.MEDIUM)
        r   = Record(**{k: v for k, v in kw.items() if k in Record.__dataclass_fields__})
        r.severity = sev
        return r

    async def _get(self, session: "aiohttp.ClientSession", url: str, headers: Dict = None, timeout: int = None) -> Tuple[int, str, bytes]:
        """Perform a GET with jitter and retry logic."""
        await _jitter(self._config)
        to  = aiohttp_mod.ClientTimeout(total=timeout or self._config.timeout) if aiohttp_mod else None
        hdrs = _random_headers(headers)
        for attempt in range(Cfg.RETRIES):
            try:
                async with self._sem:
                    async with session.get(url, headers=hdrs, timeout=to, ssl=_SSL_CTX) as resp:
                        if resp.status == 429:
                            retry_after = int(resp.headers.get("Retry-After", Cfg.RETRY_DELAY * (attempt + 2)))
                            _syslog.info("RATE_LIMIT source=%s url=%s retry_after=%ds", self.name, url[:80], retry_after)
                            await asyncio.sleep(min(retry_after, 30))
                            continue
                        body = await resp.read()
                        if resp.status >= 400:
                            _syslog.warning("API_ERROR source=%s status=%d url=%s", self.name, resp.status, url[:80])
                        return resp.status, await resp.text(errors="replace"), body
            except Exception as exc:
                if attempt < Cfg.RETRIES - 1:
                    await asyncio.sleep(Cfg.RETRY_DELAY * (attempt + 1))
                    continue
                _syslog.debug("API_FAIL source=%s url=%s error=%s", self.name, url[:80], exc)
        return 0, "", b""

    async def _post(self, session: "aiohttp.ClientSession", url: str, json_data: Dict = None, data: Dict = None, headers: Dict = None, timeout: int = None) -> Tuple[int, str, bytes]:
        """Perform a POST with jitter and retry logic."""
        await _jitter(self._config)
        to   = aiohttp_mod.ClientTimeout(total=timeout or self._config.timeout) if aiohttp_mod else None
        hdrs = _random_headers(headers)
        for attempt in range(Cfg.RETRIES):
            try:
                async with self._sem:
                    if json_data is not None:
                        hdrs["Content-Type"] = "application/json"
                        async with session.post(url, json=json_data, headers=hdrs, timeout=to, ssl=_SSL_CTX) as resp:
                            if resp.status == 429:
                                retry_after = int(resp.headers.get("Retry-After", Cfg.RETRY_DELAY * (attempt + 2)))
                                _syslog.info("RATE_LIMIT source=%s url=%s retry_after=%ds", self.name, url[:80], retry_after)
                                await asyncio.sleep(min(retry_after, Cfg.RETRY_DELAY * (attempt + 2)))
                                continue
                            body = await resp.read()
                            if resp.status >= 400:
                                _syslog.warning("API_ERROR source=%s status=%d url=%s", self.name, resp.status, url[:80])
                            return resp.status, await resp.text(errors="replace"), body
                    else:
                        async with session.post(url, data=data or {}, headers=hdrs, timeout=to, ssl=_SSL_CTX) as resp:
                            if resp.status == 429:
                                retry_after = int(resp.headers.get("Retry-After", Cfg.RETRY_DELAY * (attempt + 2)))
                                _syslog.info("RATE_LIMIT source=%s url=%s retry_after=%ds", self.name, url[:80], retry_after)
                                await asyncio.sleep(min(retry_after, Cfg.RETRY_DELAY * (attempt + 2)))
                                continue
                            body = await resp.read()
                            if resp.status >= 400:
                                _syslog.warning("API_ERROR source=%s status=%d url=%s", self.name, resp.status, url[:80])
                            return resp.status, await resp.text(errors="replace"), body
            except Exception as exc:
                if attempt < Cfg.RETRIES - 1:
                    await asyncio.sleep(Cfg.RETRY_DELAY * (attempt + 1))
                    continue
                _syslog.debug("API_FAIL source=%s url=%s error=%s", self.name, url[:80], exc)
        return 0, "", b""

    @abstractmethod
    async def async_search(self, session: "aiohttp.ClientSession", query: str, qtype: str) -> List[Record]:
        """Coroutine that returns a list of Records for the given query."""

    def search(self, query: str, qtype: str) -> List[Record]:
        """Synchronous shim — runs the coroutine in a new event loop (fallback)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        try:
            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    fut = ex.submit(asyncio.run, self._run_search(query, qtype))
                    return fut.result(timeout=self._config.timeout + 10)
            return asyncio.run(self._run_search(query, qtype))
        except Exception:
            return []

    async def _run_search(self, query: str, qtype: str) -> List[Record]:
        if not aiohttp_mod:
            return []
        connector = aiohttp_mod.TCPConnector(ssl=_SSL_CTX, limit=10, family=0)  # AF_UNSPEC
        async with aiohttp_mod.ClientSession(connector=connector) as session:
            return await self.async_search(session, query, qtype)


# ── Legacy sync shim (keeps all existing Src subclasses working) ───────
class Src(AsyncSource):
    """
    Backward-compatible base that wraps the original synchronous `search`
    pattern while exposing the new AsyncSource interface.
    """

    def __init__(self, semaphore_or_session, db: "DB", config: "NoxConfig" = None) -> None:
        if isinstance(semaphore_or_session, asyncio.Semaphore):
            sem = semaphore_or_session
            self._legacy_session = None
        else:
            # Legacy: passed a Session object — use int limit so semaphore
            # is created lazily inside the event loop (Python 3.13 safe).
            sem = Cfg.CONCURRENCY
            self._legacy_session = semaphore_or_session
        super().__init__(sem, db, config or NoxConfig())
        # Legacy attribute alias
        self.s = self._legacy_session

    async def async_search(self, session: "aiohttp.ClientSession", query: str, qtype: str) -> List[Record]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.search, query, qtype)

    @abstractmethod
    def search(self, query: str, qtype: str) -> List[Record]:
        pass


# ── Input Detection ────────────────────────────────────────────────────
class Detect:
    @staticmethod
    def qtype(q: str) -> str:
        q = q.strip()
        if re.match(r"^[\w.+-]+@[\w-]+\.[\w.]+$", q):                                                    return "email"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", q) and all(0 <= int(o) <= 255 for o in q.split(".")): return "ip"
        if re.match(r"^(\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}$", q):             return "phone"
        if re.match(r"^[a-fA-F0-9]{32,128}$", q):                                                        return "hash"
        if re.match(r"^\$2[aby]?\$", q) or re.match(r"^\$argon2", q) or re.match(r"^\$[156]\$", q):      return "hash"
        if re.match(r"^https?://", q):                                                                    return "url"
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", q) and "." in q:                   return "domain"
        if len(q) <= 30 and re.match(r"^[\w.-]+$", q):                                                   return "username"
        if " " in q and len(q.split()) >= 2 and len(q) <= 60:                                            return "name"
        return "username"


# ── Legacy synchronous Session (kept for Src subclasses) ──────────────
class Session:
    UA = _UA_POOL

    def __init__(self, config: NoxConfig) -> None:
        self.config   = config
        self.use_tor  = config.use_tor
        self.proxy    = config.proxy
        self._lock    = threading.Lock()
        self._n       = 0
        self._s       = None
        self._cs      = None
        if requests:
            self._s = requests.Session()
            self._s.verify = True
            if self.use_tor:
                self._s.proxies = {
                    "http":  f"socks5h://127.0.0.1:{config.tor_socks}",
                    "https": f"socks5h://127.0.0.1:{config.tor_socks}",
                }
        if cloudscraper:
            try:
                self._cs = cloudscraper.create_scraper(
                    browser={"browser": "chrome", "platform": "windows", "mobile": False}
                )
                if self.use_tor:
                    self._cs.proxies = {
                        "http":  f"socks5h://127.0.0.1:{config.tor_socks}",
                        "https": f"socks5h://127.0.0.1:{config.tor_socks}",
                    }
            except Exception:
                pass
        self._jar    = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
            urllib.request.HTTPRedirectHandler(),
        )

    def _hdrs(self, extra: Dict = None) -> Dict:
        return _random_headers(extra)

    def _rl(self) -> None:
        if self.config.stealth:
            time.sleep(random.uniform(*self.config.rate_limit))
        with self._lock:
            self._n += 1

    @staticmethod
    def _make_response(status: int, body: bytes, hdrs: dict, url: str):
        text  = body.decode("utf-8", errors="replace")
        _body = body

        def _json(*_):
            return json.loads(_body.decode("utf-8", errors="replace"))

        ok = 200 <= status < 300
        return type("R", (), {
            "status_code": status, "ok": ok,
            "text": text, "content": _body,
            "json": _json, "headers": hdrs, "url": url,
        })()

    @staticmethod
    def _null_response(url: str = ""):
        def _json(*_): return {}
        return type("R", (), {
            "status_code": 0, "ok": False, "text": "", "content": b"",
            "json": _json, "headers": {}, "url": url,
        })()

    def get(self, url: str, extra_headers: Dict = None, timeout: int = None, use_cloudscraper: bool = False):
        self._rl()
        to   = timeout or self.config.timeout
        hdrs = self._hdrs(extra_headers)
        for attempt in range(Cfg.RETRIES):
            try:
                if use_cloudscraper and self._cs:
                    r = self._cs.get(url, headers=hdrs, timeout=to)
                elif self._s:
                    px = {"http": self.proxy, "https": self.proxy} if self.proxy else None
                    r  = self._s.get(url, headers=hdrs, timeout=to, proxies=px)
                else:
                    req = urllib.request.Request(url, headers=hdrs)
                    raw = self._opener.open(req, timeout=to)
                    data = raw.read()
                    if raw.headers.get("Content-Encoding") == "gzip":
                        data = gzip.decompress(data)
                    return self._make_response(raw.status, data, dict(raw.headers), raw.url)
                if getattr(r, "status_code", 0) == 429:
                    retry_after = int(r.headers.get("Retry-After", Cfg.RETRY_DELAY * (attempt + 2)))
                    time.sleep(min(retry_after, 30))
                    continue
                return r
            except Exception as e:
                if attempt < Cfg.RETRIES - 1:
                    time.sleep(Cfg.RETRY_DELAY * (attempt + 1))
                    continue
                logger.debug("GET fail %s: %s", url, e)
        return self._null_response(url)

    def post(self, url: str, data: Dict = None, json_data: Dict = None, extra_headers: Dict = None, timeout: int = None):
        self._rl()
        to   = timeout or self.config.timeout
        hdrs = self._hdrs(extra_headers)
        for attempt in range(Cfg.RETRIES):
            try:
                if self._s:
                    if json_data:
                        hdrs["Content-Type"] = "application/json"
                        r = self._s.post(url, json=json_data, headers=hdrs, timeout=to)
                    else:
                        r = self._s.post(url, data=data, headers=hdrs, timeout=to)
                    if getattr(r, "status_code", 0) == 429:
                        retry_after = int(r.headers.get("Retry-After", Cfg.RETRY_DELAY * (attempt + 2)))
                        time.sleep(min(retry_after, 30))
                        continue
                    return r
                body = json.dumps(json_data).encode() if json_data else urllib.parse.urlencode(data or {}).encode()
                hdrs["Content-Type"] = "application/json" if json_data else "application/x-www-form-urlencoded"
                req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
                raw = self._opener.open(req, timeout=to)
                rd  = raw.read()
                if raw.headers.get("Content-Encoding") == "gzip":
                    rd = gzip.decompress(rd)
                return self._make_response(raw.status, rd, dict(raw.headers), raw.url)
            except Exception as e:
                if attempt < Cfg.RETRIES - 1:
                    time.sleep(Cfg.RETRY_DELAY * (attempt + 1))
                    continue
                logger.debug("POST fail %s: %s", url, e)
        return self._null_response(url)

    def new_circuit(self) -> bool:
        if not stem:
            return False
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=self.config.tor_ctrl) as ctrl:
                ctrl.authenticate(password=self.config.tor_pass)
                ctrl.signal(Signal.NEWNYM)
            time.sleep(3)
            return True
        except Exception:
            return False


# =======================================================================
# SOURCE REGISTRY
# =======================================================================

class Registry:
    """All intelligence sources are loaded dynamically from sources/*.json by SourceOrchestrator."""

    @classmethod
    def get(cls, session: "Session", db: "DB", qt: str = None) -> list:
        return []

    @classmethod
    def count(cls) -> int:
        return 0


class _LegacySourcePlaceholder(Src):
    async def async_search(self, session, query, qtype): return []
    def search(self, query, qtype): return []




# =======================================================================
# PROXY MANAGER — Guardian System
# =======================================================================

class ProxyManager:
    """
    Dynamic proxy engine ("Guardian System").

    Priority:
      1. proxies.txt in the working directory — loaded and validated.
      2. Auto-fetch from ProxyScrape API if proxies.txt is missing.
      3. Direct connection fallback if auto-fetch fails.

    Proxies are stored in memory and rotated per-request by consumers.

    Fail-Safe: when allow_leak=False (default) and a proxy/Tor was explicitly
    requested but no transport is available, execution is aborted to prevent
    real-IP exposure.
    """

    _VALID_SCHEMES = ("http://", "https://", "socks5://", "socks4://")
    _cache: List[str] = []

    @classmethod
    def reset(cls) -> None:
        """Clear the cached proxy pool so the next call to get_proxies() re-fetches."""
        cls._cache = []

    @classmethod
    def get_proxies(cls) -> List[str]:
        """Return a validated proxy list, fetching if necessary."""
        if cls._cache:
            return list(cls._cache)

        proxy_file = Path("proxies.txt")
        if proxy_file.exists():
            raw = [
                l.strip() for l in proxy_file.read_text().splitlines()
                if l.strip() and any(l.strip().startswith(s) for s in cls._VALID_SCHEMES)
            ]
            if raw:
                cls._cache = raw
                out("info", f"[ProxyManager] Loaded {len(raw)} proxies from proxies.txt")
                return list(cls._cache)
            out("warn", "[ProxyManager] proxies.txt found but contains no valid entries — auto-fetching.")

        # Auto-fetch
        print(
            f"\n  {C.BD}{C.Y}[!] OPSEC WARNING: Using public auto-fetched proxies. "
            f"For professional engagements, use Tor (--tor) or a private proxies.txt.{C.X}\n"
        )
        fetched = cls._fetch_proxies()
        if fetched:
            cls._cache = fetched
            out("ok", f"[ProxyManager] Auto-fetched {len(fetched)} proxies.")
            return list(cls._cache)

        # Failover: direct connection
        print(
            f"\n  {C.BD}{C.R}[!] WARNING: Proxy auto-fetch failed. "
            f"Falling back to DIRECT connection — your real IP may be exposed.{C.X}\n"
        )
        cls._cache = []
        return []

    @classmethod
    def fail_safe_check(cls, config: "NoxConfig", allow_leak: bool = False) -> None:
        """
        Fail-Safe Proxy enforcement.

        If the user explicitly requested a proxy or Tor but the transport is
        unavailable, abort execution immediately to prevent IP leakage.
        Pass allow_leak=True (--allow-leak flag) to bypass this check.
        """
        proxy_requested = bool(config.proxy) or config.use_tor
        if not proxy_requested:
            return  # Guardian Engine handles the no-proxy case separately

        transport_ready = False
        if config.use_tor:
            # Verify Tor SOCKS port is reachable
            import socket
            try:
                s = socket.create_connection(("127.0.0.1", config.tor_socks), timeout=3)
                s.close()
                transport_ready = True
            except OSError:
                transport_ready = False
        elif config.proxy:
            # Treat any non-empty proxy string as "configured" — aiohttp will
            # surface the error at request time; we just confirm it is set.
            transport_ready = True

        if not transport_ready:
            if allow_leak:
                print(
                    f"\n  {C.BD}{C.Y}[WARNING] OPSEC Alert: Proxy/Tor failed. "
                    f"Continuing execution with REAL IP (--allow-leak active).{C.X}\n"
                )
                return
            print(
                f"\n  {C.BD}{C.R}[CRITICAL] OPSEC FAILURE: Requested Proxy/Tor is unavailable. "
                f"Execution aborted to prevent IP leak. Use --allow-leak to override.{C.X}\n"
            )
            sys.exit(1)

    _PROXY_SOURCES = [
        (
            "https://api.proxyscrape.com/v2/"
            "?request=displayproxies&protocol=http&timeout=5000"
            "&country=all&ssl=all&anonymity=all"
        ),
        "https://www.proxy-list.download/api/v1/get?type=http&anon=elite",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    ]

    @classmethod
    def _fetch_proxies(cls) -> List[str]:
        proxies: List[str] = []
        for url in cls._PROXY_SOURCES:
            if proxies:
                break
            try:
                req  = urllib.request.Request(url, headers={"User-Agent": "NOX Framework/ProxyManager"})
                raw  = urllib.request.urlopen(req, timeout=10)
                text = raw.read().decode("utf-8", errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d{2,5}$", line):
                        proxies.append(f"http://{line}")
                    elif any(line.startswith(s) for s in cls._VALID_SCHEMES):
                        proxies.append(line)
                if proxies:
                    logger.debug("ProxyManager: fetched %d proxies from %s", len(proxies), url)
            except Exception as exc:
                logger.debug("ProxyManager._fetch_proxies source=%s: %s", url, exc)
                continue
        return proxies[:200]

    @classmethod
    def validate_proxy(cls, proxy: str, timeout: int = 6) -> Optional[str]:
        """
        Test a proxy by requesting https://api.ipify.org.
        Returns the observed exit IP on success, None on failure.
        F1: SOCKS5 proxies are validated via requests+PySocks, not urllib.
        """
        # F1: urllib.ProxyHandler does not support SOCKS5 — use requests if available
        if proxy.startswith("socks5") or proxy.startswith("socks4"):
            try:
                import requests as _req  # type: ignore
                resp = _req.get("https://api.ipify.org",
                                proxies={"http": proxy, "https": proxy},
                                timeout=timeout)
                ip = resp.text.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    return ip
            except Exception:
                pass
            return None
        try:
            import urllib.request as _ur
            proxy_handler = _ur.ProxyHandler({"http": proxy, "https": proxy})
            opener = _ur.build_opener(proxy_handler)
            resp = opener.open("https://api.ipify.org", timeout=timeout)
            ip = resp.read().decode().strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
        except Exception:
            pass
        return None


# =======================================================================
# DORKING ENGINE — passive document discovery + metadata extraction
# =======================================================================

class _DorkTemplates:
    """Shared dork template lists — defined before DorkingEngine and DorkEngine to avoid forward-reference errors."""
    NAME_DORKS = [
        '"{q}" filetype:pdf', '"{q}" filetype:xlsx', '"{q}" filetype:csv',
        '"{q}" filetype:doc OR filetype:docx', '"{q}" filetype:txt',
        '"{q}" site:linkedin.com', '"{q}" site:facebook.com', '"{q}" site:twitter.com',
        '"{q}" site:instagram.com', '"{q}" site:github.com',
        '"{q}" site:pastebin.com', '"{q}" site:ghostbin.co', '"{q}" site:rentry.co',
        '"{q}" site:pastebin.com "password"', '"{q}" site:pastebin.com "email"',
        '"{q}" intext:"password"', '"{q}" intext:"email"', '"{q}" intext:"phone"',
        '"{q}" intext:"address"', '"{q}" intext:"credentials"',
        '"{q}" "database dump"', '"{q}" "INSERT INTO"',
        '"{q}" site:github.com "password"', '"{q}" site:gist.github.com',
        '"{q}" site:docs.google.com', '"{q}" site:trello.com',
        '"{q}" filetype:pdf site:gov', '"{q}" filetype:pdf site:edu',
    ]
    DOMAIN_DORKS = [
        'site:{q} filetype:sql', 'site:{q} filetype:env', 'site:{q} filetype:log',
        'site:{q} inurl:admin', 'site:{q} inurl:login', 'site:{q} inurl:wp-config',
        'site:{q} inurl:.git', 'site:{q} inurl:backup', 'site:{q} filetype:bak',
        'site:{q} "index of" password', 'site:{q} inurl:config.php',
        'site:{q} ext:conf OR ext:cnf OR ext:cfg', 'site:{q} "phpinfo()"',
        'site:{q} filetype:xml intext:password', 'site:{q} filetype:json api_key OR secret',
        'site:{q} intitle:"index of" .env', 'site:{q} ext:pem OR ext:key',
        'site:{q} "PRIVATE KEY"', 'site:{q} filetype:xlsx', 'site:{q} filetype:csv',
        'site:{q} intitle:"Dashboard" inurl:admin', 'site:{q} inurl:api password',
        'site:{q} filetype:sql "INSERT INTO"', 'site:{q} filetype:log "password"',
        'site:{q} filetype:env "DB_PASSWORD"', 'site:{q} filetype:yaml "password"',
        'site:{q} inurl:phpinfo.php', 'site:{q} inurl:.git/config',
        'site:{q} inurl:wp-config.php', 'site:{q} inurl:.env',
        'site:{q} inurl:database.yml', 'site:{q} inurl:secrets.yml',
        'site:{q} intitle:"index of" "backup"', 'site:{q} intitle:"index of" "dump"',
        'site:{q} intitle:"index of" "sql"', 'site:{q} intitle:"index of" "database"',
        'site:{q} intitle:"index of" ".env"', 'site:{q} intitle:"index of" "sql_dump"',
        'site:{q} ext:sql "sql_dump"', 'site:{q} inurl:sql_dump',
        'site:{q} intitle:"index of" "backup.sql"', 'site:{q} intitle:"index of" "dump.sql"',
    ]


class DorkingEngine(Src):
    """Passive document discovery via Google/DDG dorks + PDF/Office metadata extraction."""

    name = "DorkingEngine"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dead_proxies: set = set()
        self._proxy_index: int = 0
        self.proxies = ProxyManager.get_proxies()

    def _get_next_proxy(self) -> Optional[str]:
        live = [p for p in self.proxies if p not in self._dead_proxies]
        if not live:
            return None
        self._proxy_index = (self._proxy_index + 1) % len(live)
        return live[self._proxy_index]

    _DOC_DORKS = [
        '"{q}" filetype:pdf',
        '"{q}" filetype:xlsx',
        '"{q}" filetype:docx',
        '"{q}" filetype:pptx',
        '"{q}" filetype:log',
        '"{q}" site:pastebin.com',
        '"{q}" site:docs.google.com',
        '"{q}" site:drive.google.com',
        '"{q}" filetype:pdf site:gov',
        '"{q}" filetype:pdf site:edu',
        '"{q}" filetype:xlsx site:gov',
    ]

    _META_RE = {
        "author":       re.compile(rb"/Author\s*\(([^)]{1,120})\)", re.I),
        "creator":      re.compile(rb"/Creator\s*\(([^)]{1,120})\)", re.I),
        "software":     re.compile(rb"/Producer\s*\(([^)]{1,120})\)", re.I),
        "local_paths":  re.compile(rb"(?:[A-Za-z]:\\|/home/|/root/|/var/|/etc/)(?:[^\x00-\x1f\r\n]{1,200})", re.I),
        "emails":       re.compile(rb"[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{2,10}", re.I),
    }

    def generate_queries(self, target: str, qtype: str = "email") -> List[str]:
        if qtype == "name":
            templates = _DorkTemplates.NAME_DORKS
        elif qtype == "domain":
            templates = _DorkTemplates.DOMAIN_DORKS
        else:
            templates = self._DOC_DORKS
        return [d.replace("{q}", target) for d in templates]

    @staticmethod
    async def extract_metadata(url: str, session) -> dict:
        meta = {"author": "", "creator": "", "software": "", "local_paths": [], "emails": []}
        try:
            async with session.get(url, timeout=aiohttp_mod.ClientTimeout(total=15),
                                   headers={"User-Agent": random.choice(_UA_POOL)}) as resp:
                if resp.status != 200:
                    return meta
                chunk = await resp.content.read(131072)  # 128 KB
            for key, pat in DorkingEngine._META_RE.items():
                hits = pat.findall(chunk)
                if not hits:
                    continue
                decoded = [h.decode("latin-1", errors="replace").strip() for h in hits]
                if key in ("local_paths", "emails"):
                    meta[key] = list(dict.fromkeys(decoded))[:10]
                else:
                    meta[key] = decoded[0]
        except Exception:
            pass
        return meta

    async def _ddg_search(self, query: str, _session=None) -> List[dict]:
        """DDG search with proxy rotation and circuit-breaker (max 3 retries)."""
        if not aiohttp_mod:
            return []
        try:
            from aiohttp_socks import ProxyConnector as _ProxyConnector
        except ImportError:
            _ProxyConnector = None
        url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        for attempt in range(3):
            proxy = self._get_next_proxy()
            ua = random.choice(_UA_POOL)
            headers = {"User-Agent": ua}
            try:
                if proxy and _ProxyConnector:
                    connector = _ProxyConnector.from_url(proxy)
                else:
                    connector = aiohttp_mod.TCPConnector(ssl=_SSL_CTX)
                # Create session once per attempt; close it before the next retry.
                async with aiohttp_mod.ClientSession(connector=connector) as sess:
                    async with sess.get(url, headers=headers,
                                        timeout=aiohttp_mod.ClientTimeout(total=12)) as resp:
                        if resp.status in (403, 429):
                            self._dead_proxies.add(proxy)
                            next_p = self._get_next_proxy()
                            logger.warning("[!] Proxy Ban detected. Rotating to %s...", next_p)
                            continue
                        text = await resp.text(errors="replace")
                        hits = []
                        for m in re.finditer(r'class="result__url"[^>]*>([^<]+)<', text):
                            raw = m.group(1).strip()
                            if raw:
                                hits.append({"url": raw if raw.startswith("http") else "https://" + raw,
                                             "title": "", "dork": query})
                        return hits[:5]
            except Exception:
                if proxy:
                    self._dead_proxies.add(proxy)
        return []

    async def async_search(self, session, query: str, qtype: str) -> List[Record]:
        if not aiohttp_mod:
            return []

        dorks = self.generate_queries(query, qtype)
        seen_urls: Set[str] = set()

        async def _process_dork(dork: str) -> List[Tuple]:
            await asyncio.sleep(random.uniform(0.5, 2.0))
            hits = await self._ddg_search(dork)
            rows = []
            for hit in hits:
                url = hit.get("url", "")
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                ext  = url.lower().rsplit(".", 1)[-1].split("?")[0] if "." in url else ""
                meta = await DorkingEngine.extract_metadata(url, session) if ext in ("pdf", "xlsx", "docx", "pptx", "log") else {}
                rows.append((url, ext, meta, dork))
            return rows

        all_rows = []
        for batch in [dorks[i:i+5] for i in range(0, len(dorks), 5)]:
            results = await asyncio.gather(*[_process_dork(d) for d in batch], return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    all_rows.extend(r)

        records = [
            Record(source="DorkingEngine", email=query,
                   raw_data={"url": url, "dork": dork}, metadata=meta)
            for url, ext, meta, dork in all_rows
        ]

        if all_rows and aiosqlite:
            try:
                async with aiosqlite.connect(self._db.path) as db:
                    await db.executemany(
                        "INSERT OR IGNORE INTO dork_results "
                        "(source_url, file_type, metadata_json, parent_target) "
                        "VALUES (?,?,?,?)",
                        [(url, ext, json.dumps(meta), query) for url, ext, meta, _ in all_rows])
                    await db.commit()
            except Exception as exc:
                logger.debug("dork_results persist failed: %s", exc)
        return records

    def search(self, query: str, qtype: str) -> List[Record]:
        # sync fallback — not used when aiohttp is available
        return []


# =======================================================================
# DORK ENGINE
# =======================================================================
class DorkEngine:
    # Delegate to _DorkTemplates to avoid duplication
    NAME_DORKS   = _DorkTemplates.NAME_DORKS
    DOMAIN_DORKS = _DorkTemplates.DOMAIN_DORKS
    EMAIL_DORKS = [
        '"{q}" filetype:sql password', '"{q}" filetype:env', '"{q}" filetype:log password',
        '"{q}" filetype:txt intext:password', '"{q}" filetype:csv email password',
        '"{q}" filetype:xlsx password', '"{q}" filetype:cfg password', '"{q}" filetype:conf password',
        '"{q}" filetype:bak password', '"{q}" filetype:json api_key', '"{q}" filetype:yaml password',
        '"{q}" site:pastebin.com', '"{q}" site:ghostbin.co', '"{q}" site:rentry.co',
        '"{q}" site:justpaste.it', '"{q}" site:dpaste.org', '"{q}" site:paste.ee',
        '"{q}" site:hastebin.com', '"{q}" site:privatebin.net', '"{q}" site:controlc.com',
        '"{q}" site:github.com password', '"{q}" site:gitlab.com password',
        '"{q}" site:docs.google.com', '"{q}" site:trello.com', '"{q}" site:mega.nz',
        '"{q}" intext:"password" intext:"username"', '"{q}" intext:"credentials" filetype:txt',
        '"{q}" filetype:env DB_PASSWORD', '"{q}" filetype:env "API_KEY"',
        '"{q}" ext:sql "INSERT INTO" -git', '"{q}" ext:json "password"',
        '"{q}" ext:yml "password"', '"{q}" ext:yaml "api_key"',
        '"{q}" intitle:"index of" "passwords.txt"', '"{q}" intitle:"index of" "credentials.txt"',
        '"{q}" inurl:passlist.txt', '"{q}" inurl:passwords.txt', '"{q}" inurl:credentials.txt',
        '"{q}" "database dump" filetype:sql', '"{q}" "INSERT INTO" "password"',
        '"{q}" site:pastebin.com "password"', '"{q}" site:pastebin.com "credentials"',
        '"{q}" site:github.com "password"', '"{q}" site:gist.github.com "password"',
    ]

    def __init__(self, session: "Session") -> None:
        self.s = session

    def run(self, q: str, qt: str, engines: List[str] = None) -> List[dict]:
        """
        Parallelised dork runner.
        All (dork, engine) pairs are dispatched concurrently via a thread pool.
        Per-engine jitter is applied inside _search so the sleep is not sequential.
        Total wall-clock time ≈ max(single_request_time) instead of O(n_dorks × sleep).
        """
        if engines is None:
            engines = ["google", "bing", "ddg"]
        dorks = self.EMAIL_DORKS if qt == "email" else self.DOMAIN_DORKS if qt == "domain" else self.NAME_DORKS if qt == "name" else self.EMAIL_DORKS[:20]
        dorks = dorks[:Cfg.DORK_MAX]

        from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

        def _run_one(dork: str, eng: str) -> List[dict]:
            query = dork.replace("{q}", q)
            # Per-engine jitter — applied once per (dork, engine) pair, not per dork
            time.sleep(random.uniform(*Cfg.DORK_DELAY))
            hits = self._search(query, eng)
            for h in hits:
                h["dork"]   = query
                h["engine"] = eng
            return hits

        results = []
        pairs = [(dork, eng) for dork in dorks for eng in engines]
        if not pairs:
            return []
        max_workers = min(len(pairs), 12)  # cap threads to avoid hammering search engines
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_run_one, d, e): (d, e) for d, e in pairs}
            for fut in _as_completed(futures):
                try:
                    results.extend(fut.result())
                except Exception:
                    pass

        seen   = set()
        unique = []
        for r in results:
            key = r.get("url", r.get("title", ""))
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def _search(self, query: str, engine: str) -> List[dict]:
        hits = []
        try:
            urls = {
                "google": f"https://www.google.com/search?q={urllib.parse.quote(query)}&num=10",
                "bing":   f"https://www.bing.com/search?q={urllib.parse.quote(query)}&count=10",
                "ddg":    f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}",
            }
            resp = self.s.get(urls.get(engine, urls["google"]), timeout=15, use_cloudscraper=True)
            if not resp.ok or not BeautifulSoup:
                return hits
            soup      = BeautifulSoup(resp.text, "html.parser")
            selectors = {
                "google": ("div.g", "h3", "a[href]", ".VwiC3b"),
                "bing":   ("li.b_algo", "h2", "a", ".b_caption p"),
                "ddg":    (".result", ".result__title", ".result__url", ".result__snippet"),
            }
            container, title_sel, link_sel, snippet_sel = selectors.get(engine, selectors["google"])
            for item in soup.select(container)[:10]:
                title_el = item.select_one(title_sel)
                link_el  = item.select_one(link_sel)
                snip_el  = item.select_one(snippet_sel)
                if title_el:
                    url = link_el.get("href","") if link_el else ""
                    hits.append({
                        "title":   title_el.get_text().strip(),
                        "url":     url if url.startswith("http") else "",
                        "snippet": snip_el.get_text().strip() if snip_el else "",
                    })
        except Exception:
            pass
        return hits


# =======================================================================
# SCRAPE ENGINE — Telegram indexer + advanced dorks + regex extraction
# =======================================================================
class ScrapeEngine:
    PASTE_SITES = [
        ("Pastebin",    "https://psbdmp.ws/api/v3/search/{q}",                "json"),
        ("IntelX",      "https://2.intelx.io/intelligent/search",             "intelx"),
        ("Paste.ee",    "https://api.paste.ee/v1/search?query={q}",           "json"),
        ("Rentry",      "https://rentry.co/api/search?q={q}",                 "json"),
        ("Ghostbin",    "https://ghostbin.com/api/search?q={q}",              "json"),
        ("JustPaste",   "https://justpaste.it/api/search?q={q}",              "json"),
        ("DPaste",      "https://dpaste.org/api/search?q={q}",                "json"),
        ("Hastebin",    "https://hastebin.com/api/search?q={q}",              "json"),
        ("PrivateBin",  "https://privatebin.net/api/search?q={q}",            "json"),
        ("ControlC",    "https://controlc.com/api/search?q={q}",              "json"),
        ("Paste2",      "https://paste2.org/api/search?q={q}",                "json"),
        ("PastebinPro", "https://pastebin.com/api/api_search.php?q={q}",      "xml"),
    ]

    CRED_RE  = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+\s*[:;|]\s*\S+", re.IGNORECASE)
    EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
    HASH_RE  = re.compile(r"\b[a-f0-9]{32,128}\b", re.IGNORECASE)
    COMBO_RE = re.compile(r"^[^:]+:[^:]+$", re.MULTILINE)

    PATTERNS = [
        (re.compile(r"(?:password|passwd|pass|pwd)\s*[:=]\s*\S+", re.I),                                                    "Password"),
        (re.compile(r"(?:api[_-]?(?:key|secret)|access_token|auth_token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}", re.I),       "API Key/Token"),
        (re.compile(r"AKIA[0-9A-Z]{16}"),                                                                                    "AWS Access Key"),
        (re.compile(r"(?:aws_secret|secret_access_key)\s*[:=]\s*[A-Za-z0-9/+=]{40}", re.I),                                 "AWS Secret Key"),
        (re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH )?PRIVATE KEY-----"),                                                     "Private Key"),
        (re.compile(r"(?:mysql|postgres|mongodb|redis|mssql)://[^\s\"'<>]{8,}", re.I),                                      "DB Connection"),
        (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),                                    "JWT Token"),
        (re.compile(r"xox[baprs]-[0-9A-Za-z-]+"),                                                                           "Slack Token"),
        (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),                             "Slack Webhook"),
        (re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),                                                                          "GitHub Token"),
        (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),                                                                           "GitLab Token"),
        (re.compile(r"ya29\.[A-Za-z0-9_-]+"),                                                                               "Google OAuth"),
        (re.compile(r"AIza[0-9A-Za-z_-]{35}"),                                                                              "Google API Key"),
        (re.compile(r"sk_live_[0-9a-zA-Z]{24}"),                                                                            "Stripe Live Key"),
        (re.compile(r"sk_test_[0-9a-zA-Z]{24}"),                                                                            "Stripe Test Key"),
        (re.compile(r"rk_live_[0-9a-zA-Z]{24}"),                                                                            "Stripe Restricted Key"),
        (re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),                                                           "Discord Token"),
        (re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35,40}"),                                                                     "Telegram Bot Token"),
        (re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),                                                                         "Facebook Token"),
        (re.compile(r"\b[a-f0-9]{32}\b", re.I),                                                                             "MD5 Hash"),
        (re.compile(r"\b[a-f0-9]{40}\b", re.I),                                                                             "SHA1 Hash"),
        (re.compile(r"\b[a-f0-9]{64}\b", re.I),                                                                             "SHA256 Hash"),
        (re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),                                                                 "Bcrypt Hash"),
        (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),                                                  "Email"),
    ]

    TELEGRAM_CTI_CHANNELS = [
        "leakbase", "breachforums", "darkleaks", "combolist", "databreach",
        "leakednews", "cybercrime", "hackersnews", "threatintel", "darkweb",
    ]

    def __init__(self, session: "Session", db: "DB") -> None:
        self.s  = session
        self.db = db

    def run(self, q: str, qt: str) -> dict:
        results = {"pastes": [], "credentials": [], "hashes": [], "telegram": [], "dork_misconfigs": []}

        # Phase 1: Paste sites
        import xml.etree.ElementTree as ET
        for name, url, fmt in self.PASTE_SITES:
            try:
                if fmt == "json":
                    resp = self.s.get(url.replace("{q}", urllib.parse.quote(q)), timeout=12)
                    if resp.ok:
                        data = resp.json() if isinstance(resp.json(), list) else resp.json().get("data",[])
                        for p in (data or [])[:Cfg.PASTE_MAX]:
                            pid = p.get("id","") if isinstance(p,dict) else str(p)
                            results["pastes"].append({"site":name,"id":pid,"data":p})
                elif fmt == "xml":
                    resp = self.s.get(url.replace("{q}", urllib.parse.quote(q)), timeout=12)
                    if resp.ok:
                        root = ET.fromstring(resp.text)
                        for item in root.findall(".//item")[:Cfg.PASTE_MAX]:
                            pid = item.findtext("key") or item.findtext("id") or ""
                            results["pastes"].append({"site":name,"id":pid,"data":item})
                elif fmt == "intelx":
                    key = Vault.get("INTELX_API_KEY") or self.db.get_key("intelx_api_key")
                    if key:
                        resp = self.s.post(url, json_data={"term":q,"maxresults":Cfg.PASTE_MAX,"media":0,"target":0}, extra_headers={"x-key":key}, timeout=15)
                        if resp.ok:
                            sid = resp.json().get("id")
                            if sid:
                                # Exponential backoff poll
                                _delay = 2
                                for _attempt in range(4):
                                    time.sleep(_delay)
                                    res = self.s.get(f"https://2.intelx.io/intelligent/search/result?id={sid}", extra_headers={"x-key":key}, timeout=15)
                                    if res.ok:
                                        records_data = res.json().get("records", [])
                                        if records_data:
                                            for r in records_data[:Cfg.PASTE_MAX]:
                                                results["pastes"].append({"site":"IntelX","id":r.get("systemid",""),"data":r})
                                            break
                                    _delay = min(_delay * 2, 16)  # cap at 16s
            except Exception:
                continue

        # Phase 2: Extract credentials from paste content
        for paste in results["pastes"][:Cfg.PASTE_MAX]:
            try:
                content = self._fetch_content(paste)
                if content:
                    for c in self.CRED_RE.findall(content)[:50]:
                        results["credentials"].append({"raw":c,"source":paste.get("site",""),"paste_id":paste.get("id","")})
                    for h in self.HASH_RE.findall(content)[:20]:
                        results["hashes"].append({"hash":h,"source":paste.get("site",""),"paste_id":paste.get("id","")})
                    for combo in self.COMBO_RE.findall(content)[:50]:
                        if ":" in combo:
                            email, pw = combo.split(":",1)
                            if "@" in email and len(pw) > 0:
                                results["credentials"].append({"raw":combo,"source":paste.get("site",""),"paste_id":paste.get("id","")})
                    found_patterns: Dict[str, List] = {}
                    for pat, label in self.PATTERNS:
                        matches = pat.findall(content)
                        if matches:
                            found_patterns[label] = matches[:10]
                    if found_patterns:
                        paste["patterns"] = found_patterns
            except Exception:
                continue

        # Phase 3: Public Telegram Indexer
        results["telegram"] = self._telegram_index(q, qt)

        # Phase 4: Advanced misconfiguration search
        results["dork_misconfigs"] = self._dork_misconfigs(q, qt)

        # Phase 5: DDG search for leaked data
        _ddg_queries = {
            "name":   [f'"{q}" password leak', f'"{q}" database dump', f'"{q}" site:pastebin.com', f'"{q}" credentials'],
            "email":  [f'"{q}" password leak', f'"{q}" database dump'],
            "domain": [f'site:{q} password', f'"{q}" database dump'],
        }
        for sq in _ddg_queries.get(qt, [f'"{q}" password leak', f'"{q}" database dump']):
            try:
                resp = self.s.get(f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(sq)}", timeout=10, use_cloudscraper=True)
                if resp.ok and BeautifulSoup:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for r in soup.select(".result")[:5]:
                        title_el = r.select_one(".result__title")
                        if title_el:
                            results["pastes"].append({"site":"DDG","title":title_el.get_text().strip(),"query":sq})
            except Exception:
                continue

        return results

    def _telegram_index(self, q: str, qt: str) -> List[dict]:
        """
        Parse public Telegram web-gateway previews to index public CTI
        telemetry and threat actor communications.
        """
        hits = []
        targets = [q] if qt in ("username", "domain", "name") else []
        targets += self.TELEGRAM_CTI_CHANNELS
        for channel in targets:
            try:
                resp = self.s.get(f"https://t.me/s/{urllib.parse.quote(channel)}", timeout=10, use_cloudscraper=True)
                if not resp.ok or not BeautifulSoup:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                msgs = soup.select(".tgme_widget_message_text")
                for msg in msgs[:20]:
                    text = msg.get_text(separator=" ").strip()
                    if not text:
                        continue
                    # Check if query appears in message
                    if q.lower() in text.lower() or qt == "username":
                        found_patterns: Dict[str, List] = {}
                        for pat, label in self.PATTERNS:
                            matches = pat.findall(text)
                            if matches:
                                found_patterns[label] = matches[:5]
                        hits.append({
                            "channel":  channel,
                            "text":     text[:500],
                            "patterns": found_patterns,
                            "contains_target": q.lower() in text.lower(),
                        })
            except Exception:
                continue
        return hits

    def _dork_misconfigs(self, q: str, qt: str) -> List[dict]:
        """
        Automate search queries for exposed public misconfigurations
        (index of, .env, sql_dump files) associated with the target domain.
        """
        hits = []
        if qt not in ("domain", "email", "name"):
            return hits
        if qt == "name":
            dorks = [
                f'"{q}" filetype:pdf', f'"{q}" filetype:xlsx',
                f'"{q}" site:pastebin.com', f'"{q}" intext:"password"',
                f'"{q}" "database dump"', f'"{q}" site:github.com',
            ]
        else:
            target = q if qt == "domain" else q.split("@")[1] if "@" in q else q
            dorks = [
                f'site:{target} intitle:"index of"',
                f'site:{target} intitle:"index of" ".env"',
                f'site:{target} intitle:"index of" "sql_dump"',
                f'site:{target} intitle:"index of" "backup"',
                f'site:{target} ext:env',
                f'site:{target} ext:sql',
                f'"{target}" filetype:env',
                f'"{target}" filetype:sql "sql_dump"',
            ]
        for dork in dorks:
            try:
                resp = self.s.get(f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(dork)}", timeout=10, use_cloudscraper=True)
                if resp.ok and BeautifulSoup:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for r in soup.select(".result")[:5]:
                        title_el = r.select_one(".result__title")
                        url_el   = r.select_one(".result__url")
                        if title_el:
                            hits.append({
                                "dork":  dork,
                                "title": title_el.get_text().strip(),
                                "url":   url_el.get_text().strip() if url_el else "",
                            })
                time.sleep(random.uniform(2.0, 4.0))
            except Exception:
                continue
        return hits

    def _fetch_content(self, paste: dict) -> str:
        try:
            site = paste.get("site","")
            pid  = paste.get("id","")
            data = paste.get("data",{})
            if not pid:
                return ""
            raw_urls = {
                "Pastebin":   f"https://psbdmp.ws/api/v3/dump/{pid}",
                "Rentry":     f"https://rentry.co/api/raw/{pid}",
                "Hastebin":   f"https://hastebin.com/raw/{pid}",
                "DPaste":     f"https://dpaste.org/{pid}/raw/",
                "Ghostbin":   f"https://ghostbin.com/paste/{pid}/raw",
                "JustPaste":  f"https://justpaste.it/{pid}",
                "PrivateBin": f"https://privatebin.net/?{pid}",
                "ControlC":   f"https://controlc.com/{pid}",
                "Paste2":     f"https://paste2.org/raw/{pid}",
                "PastebinPro":f"https://pastebin.com/raw/{pid}",
            }
            if site == "IntelX":
                key = self.db.get_key("intelx")
                if key:
                    resp = self.s.get(f"https://2.intelx.io/file/read?type=1&systemid={pid}&k={key}", timeout=15)
                    if resp.ok:
                        return resp.text[:10000]
            elif site == "Paste.ee":
                resp = self.s.get(f"https://api.paste.ee/v1/pastes/{pid}", timeout=10)
                if resp.ok:
                    sections = resp.json().get("paste",{}).get("sections",[])
                    return "\n".join(s.get("contents","") for s in sections)[:10000]
            elif site in raw_urls:
                resp = self.s.get(raw_urls[site], timeout=10)
                if resp.ok and resp.text:
                    return resp.text[:10000]
            if isinstance(data, dict):
                for k in ("content","text","body","raw","paste"):
                    if data.get(k):
                        return str(data[k])[:10000]
        except Exception:
            pass
        return ""

    @staticmethod
    async def extract_patterns(text: str) -> dict:
        patterns = {
            "phones":    r'\+[1-9]\d{1,14}\b',
            "addresses": r'\d+\s+[A-Za-z0-9\s]+(?:Street|St|Avenue|Ave|Road|Rd|Via|Piazza|Corso|Largo)\W+[A-Za-z\s]+',
            "handles":   r'@[A-Za-z0-9_]+',
        }
        await asyncio.sleep(0)
        return {key: re.findall(pattern, text) for key, pattern in patterns.items()}


# =======================================================================
# HASH ENGINE
# =======================================================================
class HashEngine:
    TYPES = [
        ("MD5",         re.compile(r"^[a-f0-9]{32}$", re.I),       "md5"),
        ("SHA1",        re.compile(r"^[a-f0-9]{40}$", re.I),       "sha1"),
        ("SHA224",      re.compile(r"^[a-f0-9]{56}$", re.I),       "sha224"),
        ("SHA256",      re.compile(r"^[a-f0-9]{64}$", re.I),       "sha256"),
        ("SHA384",      re.compile(r"^[a-f0-9]{96}$", re.I),       "sha384"),
        ("SHA512",      re.compile(r"^[a-f0-9]{128}$", re.I),      "sha512"),
        ("NTLM",        re.compile(r"^[a-f0-9]{32}$", re.I),       "ntlm"),
        ("MySQL",       re.compile(r"^\*[A-F0-9]{40}$"),            "mysql"),
        ("bcrypt",      re.compile(r"^\$2[aby]?\$\d{2}\$"),         "bcrypt"),
        ("Argon2",      re.compile(r"^\$argon2"),                   "argon2"),
        ("SHA512Crypt",  re.compile(r"^\$6\$"),                     "sha512crypt"),
        ("SHA256Crypt",  re.compile(r"^\$5\$"),                     "sha256crypt"),
        ("MD5Crypt",     re.compile(r"^\$1\$"),                     "md5crypt"),
        ("WordPress",    re.compile(r"^\$P\$"),                     "wordpress"),
        ("phpBB",        re.compile(r"^\$H\$"),                     "phpbb"),
        ("Drupal",       re.compile(r"^\$S\$"),                     "drupal"),
        ("Django-SHA256",re.compile(r"^pbkdf2_sha256\$"),           "django"),
        ("LM",           re.compile(r"^[a-f0-9]{32}$", re.I),      "lm"),
        ("CRC32",        re.compile(r"^[a-f0-9]{8}$", re.I),       "crc32"),
    ]

    COMMON_PASS = [
        "password","123456","12345678","qwerty","abc123","monkey","1234567","letmein",
        "trustno1","dragon","baseball","iloveyou","master","sunshine","ashley","bailey",
        "shadow","123123","654321","superman","qazwsx","michael","football","password1",
        "password123","admin","admin123","root","toor","test","guest","welcome","login",
        "pass","pass123","1234","12345","123456789","1234567890","0987654321","111111",
        "666666","888888","000000","P@ssw0rd","P@ss1234","Welcome1","Ch@ngeme","Qwerty123",
        "Summer2024","Winter2025","Spring2024","Fall2024","Password123!","Admin@123",
        "Root@123","Qwerty@123","1qaz2wsx","1qaz@WSX","q1w2e3r4","Password1!",
        "Admin123!","Welcome@2025","Changeme123","P@ssword2025","Secure@123",
    ]

    LEET_MAP = {"a":"@4","e":"3","i":"1!","o":"0","s":"$5","t":"7","l":"1","g":"9","b":"8"}

    def __init__(self, db: "DB", session: "Session" = None) -> None:
        self.db       = db
        self._session = session

    def identify(self, h: str) -> List[Tuple[str, str]]:
        types = [(name, tag) for name, pat, tag in self.TYPES if pat.match(h)]
        # For 32-char hex, MD5/NTLM/LM all match the same pattern.
        # Return only MD5 (most common in breach data) to avoid wasting
        # crack cycles on tags that have no hashlib implementation.
        if len(types) > 1:
            seen_tags: set = set()
            deduped = []
            for name, tag in types:
                if tag not in seen_tags:
                    seen_tags.add(tag)
                    deduped.append((name, tag))
            # If the set contains md5/ntlm/lm ambiguity, keep only md5
            tags = {t for _, t in deduped}
            if "md5" in tags and ("ntlm" in tags or "lm" in tags):
                deduped = [(n, t) for n, t in deduped if t not in ("ntlm", "lm")]
            types = deduped
        return types if types else [("Unknown", "unknown")]

    def crack(self, h: str) -> dict:
        cached = self.db.get_plain(h)
        if cached:
            return {"hash":h,"plaintext":cached,"method":"Cache","types":self.identify(h)}
        types  = self.identify(h)
        result = {"hash":h,"plaintext":None,"method":None,"types":types}
        for fn, method in [(self._dict_attack,"Dictionary+Mutations"),(self._online,"Online Rainbow"),(self._hashmob,"Hashmob Community"),(self._extended,"Extended Mutations")]:
            plain = fn(h) if fn != self._dict_attack else fn(h, types)
            if plain:
                result["plaintext"] = plain
                result["method"]    = method
                self._cache(h, plain, method)
                return result
        return result

    def _dict_attack(self, h: str, types: list) -> Optional[str]:
        h_low = h.lower()
        for pw in self.COMMON_PASS:
            for mutation in self._mutate(pw):
                for _, tag in types:
                    try:
                        if tag == "md5"    and hashlib.md5(mutation.encode()).hexdigest()    == h_low: return mutation
                        if tag == "sha1"   and hashlib.sha1(mutation.encode()).hexdigest()   == h_low: return mutation
                        if tag == "sha256" and hashlib.sha256(mutation.encode()).hexdigest() == h_low: return mutation
                        if tag == "sha512" and hashlib.sha512(mutation.encode()).hexdigest() == h_low: return mutation
                    except Exception: continue
        return None

    def _mutate(self, word: str) -> List[str]:
        mutations = [word, word.upper(), word.lower(), word.capitalize(),
                     word+"!", word+"1", word+"123", word+"@", word+"#",
                     word+"2024", word+"2025", word[::-1], word+word,
                     word.capitalize()+"!", word.capitalize()+"1",
                     word+"!@#", word+"123!", word+"123@", word+"123#"]
        leet = word.lower()
        for c, replacements in self.LEET_MAP.items():
            for r in replacements:
                mutations.append(leet.replace(c, r, 1))
        return list(set(mutations))

    def _online(self, h: str) -> Optional[str]:
        apis = [
            (f"https://www.nitrxgen.net/md5db/{h}", "text"),
            (f"https://hashes.org/api.php?key=&query={h}", "json"),
            (f"https://hash.help/api/lookup/{h}", "json"),
            (f"https://hashkiller.io/api/search.php?hash={h}", "json"),
        ]
        _get = self._session.get if self._session else (lambda url, **kw: Session._null_response(url))
        for url, fmt in apis:
            try:
                resp = _get(url, timeout=8)
                if not resp.ok: continue
                if fmt == "text":
                    text = resp.text.strip()
                    if not text or len(text) >= 100:
                        continue
                    tl = text.lower()
                    if any(tl.startswith(p) for p in ("not found", "error", "invalid", "no result", "not in", "cmd5-error", "not exist", "code erreur", "erreur", "unknown")):
                        continue
                    return text
                elif fmt == "json":
                    data = resp.json()
                    if data.get("result") or data.get("plaintext"):
                        return data.get("result", data.get("plaintext",""))
            except Exception: continue
        return None

    def _hashmob(self, h: str) -> Optional[str]:
        try:
            if not self._session: return None
            resp = self._session.post("https://hashmob.net/api/v2/search", json_data={"hash":h}, timeout=10)
            if resp.ok:
                data = resp.json()
                if data.get("found") and data.get("result"):
                    return data["result"]
        except Exception: pass
        return None

    def _extended(self, h: str) -> Optional[str]:
        extra = ["password!","admin!","root123","test1234","welcome1","changeme","P@ssword1","Passw0rd!","S3cure!","l3tm3in","p4ssw0rd","Summer2024","Winter2025"]
        h_low = h.lower()
        types = self.identify(h)
        for pw in extra:
            for mutation in self._mutate(pw):
                for _, tag in types:
                    try:
                        if tag == "md5"    and hashlib.md5(mutation.encode()).hexdigest()    == h_low: return mutation
                        if tag == "sha1"   and hashlib.sha1(mutation.encode()).hexdigest()   == h_low: return mutation
                        if tag == "sha256" and hashlib.sha256(mutation.encode()).hexdigest() == h_low: return mutation
                    except Exception: continue
        return None

    def _cache(self, h: str, p: str, m: str) -> None:
        try: self.db.store_hash(h, "", p, m)
        except Exception: pass


# =======================================================================
# PASSWORD ANALYZER
# =======================================================================
class PassAnalyzer:
    KEYBOARD_WALKS = ["qwerty","qwertz","azerty","asdf","zxcv","qwer","1234","4321","1qaz","2wsx","3edc","4rfv","5tgb","6yhn","7ujm","qazwsx","zxcvbn","poiuyt","1qaz2wsx","q1w2e3r4","qwertyuiop","asdfghjkl","zxcvbnm"]
    DATE_PATS      = [re.compile(r"\d{4}[-/]\d{2}[-/]\d{2}"), re.compile(r"\d{2}[-/]\d{2}[-/]\d{4}"), re.compile(r"(?:19|20)\d{2}"), re.compile(r"\d{8}")]
    LEET_REV       = {"@":"a","4":"a","3":"e","1":"il","!":"i","0":"o","$":"s","5":"s","7":"t","9":"g","8":"b"}
    _COMMON_FALLBACK = {"password","123456","12345678","qwerty","abc123","monkey","1234567","letmein","trustno1","dragon","baseball","iloveyou","master","sunshine","ashley","bailey","shadow","123123","654321","superman","qazwsx","michael","football","password1","admin","root","welcome","login","test","guest","pass","qwertyuiop","qwerty123","passw0rd","P@ssw0rd","admin123","root123","welcome1","login123","test123","guest123","password123"}

    @classmethod
    def _load_common(cls) -> set:
        """Load wordlist from ~/.nox/wordlists/ if available, else use fallback set."""
        for name in ("10k-most-common.txt", "common-passwords.txt", "rockyou-top1000.txt"):
            p = Cfg.WORDLISTS / name
            if p.exists():
                try:
                    words = {l.strip().lower() for l in p.read_text(errors="ignore").splitlines() if l.strip()}
                    if words:
                        return words
                except Exception:
                    pass
        return cls._COMMON_FALLBACK

    @classmethod
    def _get_common(cls) -> set:
        if not hasattr(cls, "_common_cache"):
            cls._common_cache = cls._load_common()
        return cls._common_cache

    def analyze(self, password: str) -> dict:
        length   = len(password)
        charsets = 0; charset_names = []
        if re.search(r"[a-z]", password): charsets += 26; charset_names.append("lowercase")
        if re.search(r"[A-Z]", password): charsets += 26; charset_names.append("uppercase")
        if re.search(r"[0-9]", password): charsets += 10; charset_names.append("digits")
        if re.search(r"[^a-zA-Z0-9]", password): charsets += 33; charset_names.append("symbols")
        entropy  = length * math.log2(max(charsets, 1)) if charsets else 0
        patterns = []; penalties = 0
        if password.lower() in self._get_common():
            patterns.append("Common password (top 10K)"); penalties += 40
        for walk in self.KEYBOARD_WALKS:
            if walk in password.lower():
                patterns.append(f"Keyboard walk: {walk}"); penalties += 15; break
        for pat in self.DATE_PATS:
            if pat.search(password):
                patterns.append("Date pattern detected"); penalties += 10; break
        if re.search(r"(.)\1{2,}", password):
            patterns.append("Repeated characters"); penalties += 10
        deleet = password
        for leet, orig in self.LEET_REV.items():
            deleet = deleet.replace(leet, orig[0])
        if deleet.lower() != password.lower() and deleet.lower() in self._get_common():
            patterns.append(f"Leet speak of common password: {deleet.lower()}"); penalties += 30
        raw_score   = min(100, int(entropy * 1.5))
        final_score = max(0, raw_score - penalties)
        speeds      = [("Online (10/s)",10),("Throttled (1K/s)",1000),("Offline fast (1B/s)",1_000_000_000),("GPU cluster (100B/s)",100_000_000_000)]
        crack_times = {}
        for label, speed in speeds:
            # Use logarithms to avoid OverflowError on very long passwords
            if charsets <= 1 or length == 0:
                secs = 0.0
            else:
                log_secs = length * math.log10(max(charsets, 1)) - math.log10(speed)
                secs = 0.0 if log_secs < 0 else (float('inf') if log_secs > 300 else 10 ** log_secs)
            if secs == 0.0 or secs < 1:  crack_times[label] = "Instant"
            elif math.isinf(secs):        crack_times[label] = "> 10^300 years"
            elif secs < 60:               crack_times[label] = f"{secs:.0f} seconds"
            elif secs < 3600:             crack_times[label] = f"{secs/60:.0f} minutes"
            elif secs < 86400:            crack_times[label] = f"{secs/3600:.0f} hours"
            elif secs < 86400*365:        crack_times[label] = f"{secs/86400:.0f} days"
            elif secs < 86400*365*1000:   crack_times[label] = f"{secs/(86400*365):.0f} years"
            else:                         crack_times[label] = f"{secs/(86400*365):.2e} years"
        if final_score >= 80:   strength = "VERY STRONG"
        elif final_score >= 60: strength = "STRONG"
        elif final_score >= 40: strength = "MODERATE"
        elif final_score >= 20: strength = "WEAK"
        else:                   strength = "VERY WEAK"
        return {"password":password,"length":length,"entropy":round(entropy,2),"charsets":charset_names,"charset_size":charsets,"patterns":patterns,"penalties":penalties,"score":final_score,"raw_score":raw_score,"strength":strength,"crack_times":crack_times}


# =======================================================================
# CREDENTIAL ANALYZER — Temporal Correlation & Deduplication
# =======================================================================
class CredAnalyzer:
    @staticmethod
    def analyze(records: list) -> dict:
        if not records:
            return {}
        emails: Dict[str,int] = {}; passwords: Dict[str,int] = {}; domains: Dict[str,int] = {}
        timeline = []; stealer_logs = []
        total_crit = total_high = total_med = 0
        dedup_seen: Set[str] = set()
        unique_records = []

        for r in records:
            dk = r.dedup_key() if hasattr(r, "dedup_key") else ""
            if dk and dk in dedup_seen:
                continue
            if dk:
                dedup_seen.add(dk)
            unique_records.append(r)

            em  = _rec_get(r, "email")
            pw  = _rec_get(r, "password")
            dom = _rec_get(r, "domain")
            sev = _rec_get(r, "severity") or Severity.INFO
            if em:  emails[em]   = emails.get(em, 0) + 1
            if pw:  passwords[pw] = passwords.get(pw, 0) + 1
            if dom: domains[dom]  = domains.get(dom, 0) + 1
            bd = _rec_get(r, "breach_date")
            if bd:
                timeline.append({"date":bd,"breach":_rec_get(r,"breach_name"),"severity":sev.name if isinstance(sev,Severity) else str(sev)})
            if any(x in str(_rec_get(r,"data_types") or []).lower() for x in ["stealer","redline","raccoon","vidar","infostealer"]):
                stealer_logs.append(r)
            sev_name = sev.name if isinstance(sev, Severity) else str(sev).upper()
            if sev_name == "CRITICAL": total_crit += 1
            elif sev_name == "HIGH":   total_high += 1
            elif sev_name == "MEDIUM": total_med  += 1

        reused = {pw: cnt for pw, cnt in passwords.items() if cnt > 1}
        score  = min(100, total_crit*25 + total_high*10 + total_med*3 + len(stealer_logs)*20 + len(reused)*15)
        timeline.sort(key=lambda x: x.get("date",""))

        persistence_scores = [getattr(r,"persistence_score",0.0) for r in unique_records if getattr(r,"persistence_score",0.0) > 0]
        avg_persistence    = round(sum(persistence_scores)/len(persistence_scores),1) if persistence_scores else 0.0

        return {
            "total_records":    len(records),
            "unique_records":   len(unique_records),
            "unique_emails":    len(emails),
            "top_emails":       sorted(emails.items(), key=lambda x: -x[1])[:10],
            "unique_passwords": len(passwords),
            "passwords_found":  len(passwords),
            "reused_passwords": reused,
            "unique_domains":   len(domains),
            "top_domains":      sorted(domains.items(), key=lambda x: -x[1])[:10],
            "stealer_logs":     len(stealer_logs),
            "hvt_count":        sum(1 for r in unique_records if getattr(r, "is_hvt", False) or (isinstance(r, dict) and r.get("is_hvt"))),
            "severity":         {"critical":total_crit,"high":total_high,"medium":total_med},
            "risk_score":       score,
            "timeline":         timeline[:20],
            "avg_persistence":  avg_persistence,
        }


# =======================================================================
# PIVOT MANAGER — Recursive Data Enrichment Engine
# =======================================================================
class PivotManager:
    """
    Builds identity graphs by automatically triggering sub-queries on
    high-confidence pivot candidates (usernames, secondary emails, phones)
    up to a configurable depth, with a strict seen-targets set to prevent
    infinite loops.
    """

    def __init__(self, orchestrator: "Orchestrator", max_depth: int = None) -> None:
        self._orc       = orchestrator
        self._max_depth = max_depth or Cfg.PIVOT_DEPTH
        self._seen:  Set[str] = set()

    def enrich(self, seed_records: List[Record], seed_target: str) -> List[Record]:
        """
        Given an initial set of records, extract pivot candidates and
        recursively scan them, returning all discovered records.
        """
        self._seen.add(seed_target.lower())
        all_records = list(seed_records)
        self._pivot(seed_records, depth=1, all_records=all_records)
        return all_records

    def _pivot(self, records: List[Record], depth: int, all_records: List[Record]) -> None:
        if depth > self._max_depth:
            return
        # Only pivot on records with sufficient source confidence
        confident = [r for r in records if getattr(r, "source_confidence", 1.0) >= Cfg.PIVOT_CONFIDENCE]
        candidates = self._extract_candidates(confident or records)
        for candidate, qtype in candidates:
            key = candidate.lower()
            if key in self._seen:
                continue
            self._seen.add(key)
            out("pivot", f"  [Depth {depth}] Pivoting on {qtype}: {candidate}")
            try:
                new_records = self._orc.scan(candidate, qtype)
                if new_records:
                    all_records.extend(new_records)
                    self._pivot(new_records, depth + 1, all_records)
            except Exception as exc:
                logger.debug("Pivot error %s: %s", candidate, exc)

    @staticmethod
    def _extract_candidates(records: List[Record]) -> List[Tuple[str, str]]:
        candidates: List[Tuple[str, str]] = []
        seen_vals: Set[str] = set()
        for r in records:
            for val, qtype in [
                (_rec_get(r, "email"),     "email"),
                (_rec_get(r, "username"),  "username"),
                (_rec_get(r, "phone"),     "phone"),
                (_rec_get(r, "full_name"), "name"),
                (_rec_get(r, "name"),      "name"),
            ]:
                if val and val.lower() not in seen_vals and len(val) > 3:
                    seen_vals.add(val.lower())
                    candidates.append((val, qtype))
        return candidates[:30]


# =======================================================================
# ASYNC ORCHESTRATOR — Full asyncio event loop
# =======================================================================
class Orchestrator:
    def __init__(self, config: NoxConfig = None, db: NoxDB = None) -> None:
        self.config        = config or NoxConfig()
        self.db            = db or NoxDB()
        self.session       = Session(self.config)
        self.hash_engine   = HashEngine(self.db, self.session)
        self.pass_analyzer = PassAnalyzer()
        self.dork_engine   = DorkEngine(self.session)
        self.scrape_engine = ScrapeEngine(self.session, self.db)
        self.intel_db      = DatabaseManager()
        self.dorking_engine = DorkingEngine(self.config.concurrency, self.db, self.config)
        self._json_sources: List["JSONSourceLoader"] = []
        self._source_orchestrator: Optional["SourceOrchestrator"] = None

    def _get_semaphore(self) -> asyncio.Semaphore:
        # Always create a fresh semaphore bound to the current running loop.
        return asyncio.Semaphore(self.config.concurrency)

    # ── Async core scan ───────────────────────────────────────────────

    async def _async_scan(self, target: str, query_type: str) -> List[Record]:
        """
        Run all source queries as non-blocking coroutines managed by a
        global asyncio.Semaphore.
        """
        # ── Fail-Safe Proxy check (transport-level, before any connection) ──
        ProxyManager.fail_safe_check(self.config, allow_leak=self.config.allow_leak)

        # B1: recreate SourceOrchestrator on every call so the new semaphore is
        # propagated to all source instances. Plugin JSON files are cached by
        # SourceOrchestrator._load_nox_sources via the module-level mtime guard (L2).
        if self._source_orchestrator is None:
            self._source_orchestrator = SourceOrchestrator(
                self._get_semaphore(), self.db, self.config
            )
            self._source_orchestrator._ensure_loaded()
        else:
            # Rebind semaphore AND propagate to all loaded source instances
            new_sem = self._get_semaphore()
            self._source_orchestrator._sem = new_sem
            for src in (self._source_orchestrator._nox_sources
                        + self._source_orchestrator._fs_providers
                        + self._source_orchestrator._py_providers):
                src._sem_obj = new_sem
        sources = self._source_orchestrator.get_sources(self.session, query_type)

        out("info", f"Active sources: {len(sources)} / {self._source_orchestrator.plugin_count()} (filtered for input type: {query_type})")

        if not aiohttp_mod:
            # Fallback: synchronous thread pool
            from concurrent.futures import ThreadPoolExecutor, as_completed
            records = []
            with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
                futures = {executor.submit(src.search, target, query_type): src for src in sources}
                for i, future in enumerate(as_completed(futures), 1):
                    src = futures[future]
                    try:
                        recs = future.result(timeout=self.config.timeout + 5)
                        if recs:
                            records.extend(recs)
                            out("ok", f"  [{i}/{len(sources)}] {src.name}: {len(recs)} results")
                        else:
                            out("dim", f"  [{i}/{len(sources)}] {src.name}: 0 results")
                    except Exception as exc:
                        out("dim", f"  [{i}/{len(sources)}] {src.name}: error - {str(exc)[:50]}")
            return records

        connector = aiohttp_mod.TCPConnector(ssl=_SSL_CTX, limit=self.config.concurrency, family=0)  # family=0 → AF_UNSPEC (IPv4+IPv6)
        # B5: SOCKS5 proxies are not supported via trust_env — use ProxyConnector directly.
        _socks5_connector = False
        if self.config.proxy and self.config.proxy.startswith("socks5"):
            try:
                from aiohttp_socks import ProxyConnector as _ProxyConnector  # type: ignore
                connector = _ProxyConnector.from_url(self.config.proxy, ssl=_SSL_CTX, limit=self.config.concurrency)
                _socks5_connector = True
            except ImportError:
                logger.warning("aiohttp_socks not installed — SOCKS5 proxy bypassed. Install: pip install aiohttp-socks")
        # B2: set _proxy_env_set flag immediately after os.environ assignment
        # Use a module-level lock to prevent concurrent scans from racing on env vars.
        _proxy_env_set = False
        if self.config.proxy and not _socks5_connector and not os.environ.get("HTTPS_PROXY"):
            with _PROXY_ENV_LOCK:
                if not os.environ.get("HTTPS_PROXY"):
                    os.environ["HTTPS_PROXY"] = self.config.proxy
                    os.environ["HTTP_PROXY"]  = self.config.proxy
                    _proxy_env_set = True
        session_kwargs: dict = {"trust_env": True} if (self.config.proxy and not _socks5_connector) else {}
        # Per-source semaphores — fresh each call, bound to the current running loop.
        _source_sems: Dict[str, asyncio.Semaphore] = {}
        try:
            async with aiohttp_mod.ClientSession(connector=connector, **session_kwargs) as session:
                _counter = [0]
                # Breach sources only — DorkingEngine is dispatched separately in fullscan/autoscan.
                tasks = [
                    asyncio.create_task(self._run_source(session, src, target, query_type, _counter, len(sources), _source_sems))
                    for src in sources
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            if _proxy_env_set:
                os.environ.pop("HTTPS_PROXY", None)
                os.environ.pop("HTTP_PROXY", None)

        records = []
        for r in results:
            if isinstance(r, list):
                records.extend(r)
        return records

    async def _run_source(self, session, src, target: str, qtype: str, counter: list, total: int, source_sems: dict = None) -> List[Record]:
        # Per-source semaphore: max 3 concurrent requests per source
        if source_sems is None:
            source_sems = {}
        src_name = getattr(src, "name", "unknown")
        if src_name not in source_sems:
            source_sems[src_name] = asyncio.Semaphore(3)
        try:
            async with source_sems[src_name]:
                recs = await src.async_search(session, target, qtype)
            counter[0] += 1
            idx = counter[0]
            if recs:
                out("ok", f"  [{idx}/{total}] {src.name}: {len(recs)} results")
            else:
                out("dim", f"  [{idx}/{total}] {src.name}: 0 results")
            return recs or []
        except Exception as exc:
            counter[0] += 1
            idx = counter[0]
            out("dim", f"  [{idx}/{total}] {src.name}: error - {str(exc)[:50]}")
            return []

    # ── Public scan API ───────────────────────────────────────────────

    def scan(self, target: str, query_type: str = None) -> List[Record]:
        if not query_type:
            query_type = Detect.qtype(target)
        out("info", f"Scanning: {target} (type: {query_type})")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        try:
            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    records = ex.submit(
                        asyncio.run, self._full_async_scan(target, query_type)
                    ).result(timeout=300)
            else:
                records = asyncio.run(self._full_async_scan(target, query_type))
        except Exception:
            records = []
        return records

    async def _full_async_scan(self, target: str, query_type: str) -> List[Record]:
        """Async pipeline: cache-check → network scan → score → persist → dehash → reputation."""
        # Cache check
        try:
            cached = await self.intel_db.get_cached(target)
            if cached:
                out("ok", f"Cache hit: {len(cached)} records (< 24 h old)")
                return self._hydrate_cache(cached)
        except Exception as exc:
            logger.debug("Cache check failed: %s", exc)

        records = await self._async_scan(target, query_type)
        out("ok", f"\nScan complete: {len(records)} records")

        records = [RiskEngine.score(r) for r in records]
        records = RiskEngine.apply_persistence(records)
        HVTAnalyzer.annotate(records)

        # Vault AutoDehash hook — run in executor to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        records = await loop.run_in_executor(None, Vault.autodehash, records, self.db)

        # DeHash & Reputation enrichment — run concurrently (best-effort, non-blocking)
        if aiohttp_mod:
            connector = aiohttp_mod.TCPConnector(ssl=_SSL_CTX, limit=5)
            async with aiohttp_mod.ClientSession(connector=connector) as enrich_session:
                dehash_eng = DeHashEngine(self.db, self.config)
                rep_eng    = ReputationEngine(self.config)
                _dehash_res, rep_result = await asyncio.gather(
                    dehash_eng.dehash_records(enrich_session, records),
                    rep_eng.check(enrich_session, target, query_type),
                    return_exceptions=True,
                )
                if isinstance(_dehash_res, list):
                    records = _dehash_res
                if isinstance(rep_result, dict) and rep_result:
                    out("info", f"VirusTotal: {rep_result['malicious']} malicious, "
                                f"{rep_result['suspicious']} suspicious detections for {target}")

        try:
            await self.intel_db.cache_records(target, query_type, records)
        except Exception as exc:
            logger.debug("DB persist failed: %s", exc)

        return records

    async def fullscan(self, target: str, pivot: bool = True):
        """Full autoscan: Recursive Avalanche Engine — breach + dork + scrape on every discovered asset."""
        out("info", f"[*] Avalanche scan starting: {target}")
        _t0 = time.time()

        if _HAS_AVALANCHE and pivot:
            engine = AvalancheScanner(self)
            all_records, dork_results, scrape_results = await engine.run(target)
            pivot_chain       = [target] + [a for a in engine.seen_assets if a != target.lower()]
            pivot_depth       = engine.get_max_depth()
            pivot_log         = engine.pivot_log
            discovered_assets = engine.get_discovered_assets()
        else:
            all_records = await self._full_async_scan(target, Detect.qtype(target))
            loop = asyncio.get_running_loop()
            dork_results, scrape_results = await asyncio.gather(
                self.async_dork(target),
                loop.run_in_executor(None, self.scrape, target),
                return_exceptions=True,
            )
            if isinstance(dork_results, Exception):   dork_results   = []
            if isinstance(scrape_results, Exception): scrape_results = {}
            pivot_chain       = [target]
            pivot_depth       = 0
            pivot_log         = []
            discovered_assets = []

        # ── Enrich scraped results into records ───────────────────────
        for cred in scrape_results.get("credentials", []):
            raw = cred.get("raw", "")
            if ":" in raw:
                parts = raw.split(":", 1)
                em, pw = parts[0].strip(), parts[1].strip()
                r = Record(source=cred.get("source", "ScrapeEngine"),
                           email=em if "@" in em else "",
                           username=em if "@" not in em else "",
                           password=pw,
                           breach_name=cred.get("paste_id", ""),
                           data_types=["Scraped", "Credentials"])
            else:
                r = Record(source=cred.get("source", "ScrapeEngine"),
                           raw_data=cred,
                           breach_name=cred.get("paste_id", ""),
                           data_types=["Scraped"])
            r = RiskEngine.score(r)
            all_records.append(r)

        for paste in scrape_results.get("pastes", []):
            r = Record(source=paste.get("source", "PasteScraper"),
                       breach_name=paste.get("id", ""),
                       raw_data=paste,
                       data_types=["Paste"])
            r = RiskEngine.score(r)
            all_records.append(r)

        for tg in scrape_results.get("telegram", []):
            r = Record(source=f"Telegram/{tg.get('channel', 'unknown')}",
                       raw_data=tg,
                       data_types=["Telegram"])
            r = RiskEngine.score(r)
            all_records.append(r)

        for mc in scrape_results.get("dork_misconfigs", []):
            r = Record(source="MisconfigScraper",
                       domain=mc.get("url", ""),
                       raw_data=mc,
                       data_types=["Misconfiguration"])
            r = RiskEngine.score(r)
            all_records.append(r)

        analysis    = CredAnalyzer.analyze(all_records)
        HVTAnalyzer.annotate(all_records)   # set is_hvt field on every record
        hvt_records = HVTAnalyzer.filter_hvt(all_records)

        return {
            "target":            target,
            "records":           all_records,
            "analysis":          analysis,
            "hvt_records":       hvt_records,
            "dork_results":      dork_results,
            "scrape_results":    scrape_results,
            "pivot_chain":       pivot_chain,
            "pivot_log":         pivot_log,
            "discovered_assets": discovered_assets,
            "scan_meta": {
                "elapsed_seconds":  round(time.time() - _t0, 1),
                "pivot_depth":      pivot_depth,
                "nodes_discovered": len({
                    v.lower() for r in all_records
                    for v in [
                        _rec_get(r, "email"), _rec_get(r, "username"),
                        _rec_get(r, "ip_address"), _rec_get(r, "phone"), _rec_get(r, "domain"),
                    ] if v
                }),
            },
        }

    def crack(self, hash_value: str) -> dict:
        return self.hash_engine.crack(hash_value)

    def analyze_pass(self, password: str) -> dict:
        return self.pass_analyzer.analyze(password)

    def dork(self, target: str, query_type: str = None) -> List[dict]:
        if not query_type:
            query_type = Detect.qtype(target)
        return self.dork_engine.run(target, query_type)

    async def async_dork(self, target: str, session=None) -> List[dict]:
        """Native async dork dispatch via DorkingEngine."""
        try:
            import aiohttp as _aio  # type: ignore
            if session is None:
                connector = _aio.TCPConnector(limit=10, ssl=_SSL_CTX, family=0)
                async with _aio.ClientSession(connector=connector) as _s:
                    records = await self.dorking_engine.async_search(_s, target, Detect.qtype(target))
            else:
                records = await self.dorking_engine.async_search(session, target, Detect.qtype(target))
            return [
                {
                    "url":     r.raw_data.get("url", "") if hasattr(r, "raw_data") else "",
                    "title":   r.raw_data.get("url", r.raw_data.get("dork", "")) if hasattr(r, "raw_data") else "",
                    "snippet": "",
                    "dork":    r.raw_data.get("dork", "") if hasattr(r, "raw_data") else "",
                    "engine":  "DDG",
                }
                for r in records
            ]
        except Exception as exc:
            logger.debug("async_dork %s: %s", target, exc)
            return []

    def scrape(self, target: str, query_type: str = None) -> dict:
        if not query_type:
            query_type = Detect.qtype(target)
        return self.scrape_engine.run(target, query_type)

    @staticmethod
    def _hydrate_cache(cached: List[dict]) -> List[Record]:
        records = []
        for d in cached:
            try:
                dt = d.get("data_types","[]")
                if isinstance(dt, str):
                    try: dt = json.loads(dt)
                    except Exception: dt = []
                rs = float(d.get("risk_score", 0.0))
                if rs >= 90:   sev = Severity.CRITICAL
                elif rs >= 70: sev = Severity.HIGH
                elif rs >= 40: sev = Severity.MEDIUM
                elif rs >= 10: sev = Severity.LOW
                else:          sev = Severity.INFO
                records.append(Record(
                    source=d.get("source",""), email=d.get("email",""),
                    username=d.get("username",""), password=d.get("password",""),
                    password_hash=d.get("password_hash",""), hash_type=d.get("hash_type",""),
                    phone=d.get("phone",""), breach_name=d.get("breach_name",""),
                    breach_date=d.get("breach_date",""), data_types=dt, severity=sev,
                    risk_score=rs, source_confidence=float(d.get("source_conf",0.5)),
                    is_hvt=bool(d.get("is_hvt",0)),
                ))
            except Exception:
                continue
        return records


# =======================================================================
# ADVANCED REPORTER
# =======================================================================
class AdvancedReporter:
    # Control characters and binary garbage that break PDF/terminal rendering
    _CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

    @staticmethod
    def sanitize_payload(value: Any) -> str:
        """
        Central sanitization for all user-supplied / breach-sourced strings.

        1. Coerce to str.
        2. Strip control characters and binary garbage (safe for PDF/terminal).
        3. HTML-escape the result (safe for HTML embedding — prevents XSS).

        Example: '<script>alert(1)</script>' → '&lt;script&gt;alert(1)&lt;/script&gt;'
        """
        s = str(value) if value is not None else ""
        s = AdvancedReporter._CTRL_RE.sub("", s)
        return html_module.escape(s)

    @staticmethod
    def _raw(value: Any) -> str:
        """Strip control chars only — no HTML escaping (for PDF/CSV/plain-text paths)."""
        s = str(value) if value is not None else ""
        return AdvancedReporter._CTRL_RE.sub("", s)

    @staticmethod
    def _build_summary(records: list) -> dict:
        identities: Set[str] = set(); hvt_list = []; stealers = 0
        buckets = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        pw_patterns: Dict[str,int] = {}; top_threats = []
        for r in records:
            ident = _rec_get(r,"email") or _rec_get(r,"username")
            if ident: identities.add(ident)
            if HVTAnalyzer.is_hvt(r): hvt_list.append(ident)
            if _is_stealer(r): stealers += 1
            rs = float(_rec_get(r,"risk_score") or 0)
            if rs >= 90:   buckets["Critical"] += 1
            elif rs >= 70: buckets["High"]     += 1
            elif rs >= 40: buckets["Medium"]   += 1
            elif rs >= 10: buckets["Low"]      += 1
            else:          buckets["Info"]     += 1
            pw = _rec_get(r,"password")
            if pw:
                if re.search(r"[A-Z]",pw) and re.search(r"\d",pw) and re.search(r"[!@#$%^&*]",pw): pat = "Complex"
                elif _CORP_PW_RE.match(pw): pat = "Corporate (Word+Year+Symbol)"
                elif pw.isdigit(): pat = "Numeric only"
                elif pw.isalpha(): pat = "Alpha only"
                else: pat = "Other"
                pw_patterns[pat] = pw_patterns.get(pat,0) + 1
            if rs >= 70: top_threats.append(r)
        top_threats.sort(key=lambda r: float(_rec_get(r,"risk_score") or 0), reverse=True)
        return {"total_identities":len(identities),"total_records":len(records),"hvt_list":list(dict.fromkeys(hvt_list))[:30],"hvt_count":len(set(hvt_list)),"stealer_count":stealers,"buckets":buckets,"pw_patterns":sorted(pw_patterns.items(),key=lambda x:-x[1])[:8],"top_threats":top_threats[:20]}

    @staticmethod
    def _heatmap_bar(value: float, max_val: int = 100) -> str:
        pct = min(100, int(value / max(max_val,1) * 100))
        colour = "#ff0040" if pct >= 90 else "#ff6600" if pct >= 70 else "#ffcc00" if pct >= 40 else "#00cc44"
        return (f'<div style="background:#1a1a1a;border-radius:3px;height:10px;width:100%">'
                f'<div style="background:{colour};width:{pct}%;height:10px;border-radius:3px"></div></div>'
                f'<span style="font-size:10px;color:{colour}">{value:.1f}</span>')

    @staticmethod
    def to_html(data: dict, path: str) -> None:
        records = data.get("records",[])
        target  = data.get("target","Unknown")
        s       = AdvancedReporter._build_summary(records)
        rec_dicts = [r.to_dict() if hasattr(r,"to_dict") else r for r in records]
        kpi_html = (f'<div class="stat"><div class="num">{s["total_identities"]}</div><div class="label">COMPROMISED IDENTITIES</div></div>'
                    f'<div class="stat crit"><div class="num">{s["stealer_count"]}</div><div class="label">STEALER LOGS</div></div>'
                    f'<div class="stat hvt"><div class="num">{s["hvt_count"]}</div><div class="label">HIGH-VALUE TARGETS</div></div>'
                    f'<div class="stat"><div class="num">{s["total_records"]}</div><div class="label">TOTAL RECORDS</div></div>'
                    f'<div class="stat"><div class="num">{len(data.get("discovered_assets") or [])}</div><div class="label">REINJECTED ASSETS</div></div>')
        total = max(sum(s["buckets"].values()),1)
        heatmap_rows = "".join(f'<tr><td style="width:80px">{lvl}</td><td>{AdvancedReporter._heatmap_bar(cnt,total)}</td><td style="width:40px;text-align:right">{cnt}</td></tr>' for lvl,cnt in s["buckets"].items())
        pw_rows      = "".join(f'<tr><td>{p}</td><td>{c}</td><td>{AdvancedReporter._heatmap_bar(c,max((c2 for _,c2 in s["pw_patterns"]),default=1))}</td></tr>' for p,c in s["pw_patterns"])

        _sp = AdvancedReporter.sanitize_payload  # shorthand

        threat_rows  = "".join(
            f'<tr class="crit">'
            f'<td>{_sp(_rec_get(r,"email") or _rec_get(r,"username"))}</td>'
            f'<td class="pw">{_sp(_rec_get(r,"password") or "")}</td>'
            f'<td style="font-size:10px;color:#aaa">{_sp(_rec_get(r,"password_hash") or "")[:30]}</td>'
            f'<td>{_sp(_rec_get(r,"ip_address") or "")}</td>'
            f'<td>{_sp(_rec_get(r,"phone") or "")}</td>'
            f'<td>{_sp(_rec_get(r,"domain") or "")}</td>'
            f'<td>{_sp(_rec_get(r,"source"))}</td>'
            f'<td>{_sp(_rec_get(r,"breach_date"))}</td>'
            f'<td>{AdvancedReporter._heatmap_bar(float(_rec_get(r,"risk_score") or 0))}</td>'
            f'<td>{"⚑ HVT" if HVTAnalyzer.is_hvt(r) else ""}</td></tr>'
            for r in s["top_threats"]
        )
        hvt_items    = "".join(f'<li>&#9888; {_sp(v)}</li>' for v in s["hvt_list"]) or "<li>None detected</li>"
        cred_rows    = ""
        for r in rec_dicts[:500]:
            rs  = float(r.get("risk_score",0) if isinstance(r,dict) else getattr(r,"risk_score",0))
            cls = "crit" if rs>=90 else "high" if rs>=70 else "med" if rs>=40 else ""
            hvt_badge = "⚑" if HVTAnalyzer.is_hvt(r) else ""
            cred_rows += (
                f"<tr class='{cls}'>"
                f"<td>{_sp(_rec_get(r,'email'))}{hvt_badge}</td>"
                f"<td>{_sp(_rec_get(r,'username') or '')}</td>"
                f"<td class='pw'>{_sp(_rec_get(r,'password') or '')}</td>"
                f"<td style='font-size:10px;color:#aaa'>{_sp((_rec_get(r,'password_hash') or '')[:30])}</td>"
                f"<td>{_sp(_rec_get(r,'ip_address') or '')}</td>"
                f"<td>{_sp(_rec_get(r,'phone') or '')}</td>"
                f"<td>{_sp(_rec_get(r,'domain') or '')}</td>"
                f"<td>{_sp(_rec_get(r,'source'))}</td>"
                f"<td>{_sp(_rec_get(r,'breach_date'))}</td>"
                f"<td>{AdvancedReporter._heatmap_bar(rs)}</td></tr>"
            )
        # ── Discovered documents section ──────────────────────────────
        doc_rows = ""
        for r in records:
            src = _rec_get(r, "source")
            if src != "DorkingEngine":
                continue
            rd   = r if isinstance(r, dict) else r.raw_data if hasattr(r, "raw_data") else {}
            meta = (r.metadata if hasattr(r, "metadata") else {}) or {}
            url  = rd.get("url", "") if isinstance(rd, dict) else ""
            ext  = url.lower().rsplit(".", 1)[-1].split("?")[0] if "." in url else ""
            paths  = "; ".join(meta.get("local_paths", []))
            emails = "; ".join(meta.get("emails", []))
            doc_rows += (
                f"<tr>"
                f"<td><a href='{_sp(url)}' style='color:#00ff41'>{_sp(url[:80])}</a></td>"
                f"<td>{_sp(ext)}</td>"
                f"<td>{_sp(meta.get('author',''))}</td>"
                f"<td>{_sp(meta.get('creator',''))}</td>"
                f"<td style='font-size:10px'>{_sp(paths)}</td>"
                f"<td style='font-size:10px'>{_sp(emails)}</td></tr>"
            )
        doc_section = (f'<div class="section"><h2>&#128269; Discovered Public Documents &amp; Metadata</h2>'
                       f'<table><thead><tr><th>URL</th><th>Type</th><th>Author</th><th>Creator</th><th>Local Paths</th><th>Emails</th></tr></thead>'
                       f'<tbody>{doc_rows if doc_rows else "<tr><td colspan=6 style=text-align:center>No documents found</td></tr>"}</tbody></table></div>'
                       )

        # ── Dork hits section ─────────────────────────────────────────
        dork_results   = data.get("dork_results", []) or []
        dork_hit_rows  = ""
        for h in dork_results:
            url     = h.get("url", "")
            title   = h.get("title", "")
            snippet = h.get("snippet", "")
            dork_q  = h.get("dork", "")
            engine  = h.get("engine", "")
            link    = f'<a href="{_sp(url)}" style="color:#00ff41" target="_blank">{_sp(url[:90])}</a>' if url else _sp(title[:90])
            dork_hit_rows += (
                f"<tr>"
                f"<td>{link}</td>"
                f"<td style='color:#aaa;font-size:11px'>{_sp(snippet[:120])}</td>"
                f"<td style='color:#888;font-size:11px'>{_sp(dork_q[:80])}</td>"
                f"<td style='color:#888'>{_sp(engine)}</td>"
                f"</tr>"
            )
        dork_section = (
            f'<div class="section"><h2>&#128270; Dork Results ({len(dork_results)} hits)</h2>'
            f'<table><thead><tr><th>URL / Title</th><th>Snippet</th><th>Dork Query</th><th>Engine</th></tr></thead>'
            f'<tbody>{dork_hit_rows if dork_hit_rows else "<tr><td colspan=4 style=text-align:center>No dork hits</td></tr>"}</tbody></table></div>'
        )

        # ── Scrape section ────────────────────────────────────────────
        scrape_results = data.get("scrape_results", {}) or {}

        # Pastes
        paste_rows = ""
        for p in scrape_results.get("pastes", []):
            site  = _sp(p.get("site", ""))
            pid   = p.get("id", "")
            title = _sp(p.get("title", pid)[:80])
            query = _sp(p.get("query", "")[:60])
            # Build a best-effort direct link
            paste_links = {
                "Pastebin": f"https://pastebin.com/{pid}",
                "Rentry":   f"https://rentry.co/{pid}",
                "Hastebin": f"https://hastebin.com/{pid}",
                "DPaste":   f"https://dpaste.org/{pid}",
                "Ghostbin": f"https://ghostbin.com/paste/{pid}",
                "JustPaste":f"https://justpaste.it/{pid}",
                "ControlC": f"https://controlc.com/{pid}",
                "Paste2":   f"https://paste2.org/raw/{pid}",
                "PastebinPro": f"https://pastebin.com/{pid}",
            }
            link_url = paste_links.get(p.get("site", ""), "")
            link_html = (f'<a href="{_sp(link_url)}" style="color:#00ff41" target="_blank">{title or pid}</a>'
                         if link_url else (title or _sp(pid)))
            patterns = p.get("patterns", {})
            pat_str  = _sp(", ".join(f"{k}({len(v)})" for k, v in patterns.items()) if patterns else "")
            paste_rows += f"<tr><td>{site}</td><td>{link_html}</td><td style='font-size:11px'>{pat_str}</td><td style='font-size:11px;color:#888'>{query}</td></tr>"

        # Credentials extracted from pastes
        cred_scrape_rows = ""
        for c in scrape_results.get("credentials", []):
            raw   = _sp(c.get("raw", "")[:120])
            src   = _sp(c.get("source", ""))
            pid   = c.get("paste_id", "")
            cred_scrape_rows += f"<tr><td class='pw'>{raw}</td><td>{src}</td><td>{_sp(pid)}</td></tr>"

        # Telegram hits
        tg_rows = ""
        for t in scrape_results.get("telegram", []):
            ch   = _sp(t.get("channel", ""))
            text = _sp(t.get("text", "")[:200])
            pats = _sp(", ".join(f"{k}({len(v)})" for k, v in (t.get("patterns") or {}).items()))
            link = f'<a href="https://t.me/s/{_sp(t.get("channel",""))}" style="color:#00ff41" target="_blank">t.me/s/{ch}</a>'
            tg_rows += f"<tr><td>{link}</td><td style='font-size:11px'>{text}</td><td style='font-size:11px;color:#ff6600'>{pats}</td></tr>"

        # Misconfig dork hits
        mc_rows = ""
        for m in scrape_results.get("dork_misconfigs", []):
            url_m  = m.get("url", "")
            title_m = _sp(m.get("title", "")[:80])
            dork_m  = _sp(m.get("dork", "")[:80])
            link_m  = (f'<a href="{_sp(url_m)}" style="color:#ff0040" target="_blank">{_sp(url_m[:80])}</a>'
                       if url_m else title_m)
            mc_rows += f"<tr><td>{link_m}</td><td style='font-size:11px'>{title_m}</td><td style='font-size:11px;color:#888'>{dork_m}</td></tr>"

        scrape_section = (
            f'<div class="section"><h2>&#128203; Scrape Results</h2>'
            f'<h3>Pastes ({len(scrape_results.get("pastes",[]))})</h3>'
            f'<table><thead><tr><th>Site</th><th>Paste / Link</th><th>Patterns Found</th><th>Query</th></tr></thead>'
            f'<tbody>{paste_rows or "<tr><td colspan=4 style=text-align:center>None</td></tr>"}</tbody></table>'
            f'<h3>Extracted Credentials ({len(scrape_results.get("credentials",[]))})</h3>'
            f'<table><thead><tr><th>Raw Credential</th><th>Source</th><th>Paste ID</th></tr></thead>'
            f'<tbody>{cred_scrape_rows or "<tr><td colspan=3 style=text-align:center>None</td></tr>"}</tbody></table>'
            f'<h3>Telegram CTI ({len(scrape_results.get("telegram",[]))})</h3>'
            f'<table><thead><tr><th>Channel</th><th>Message</th><th>Patterns</th></tr></thead>'
            f'<tbody>{tg_rows or "<tr><td colspan=3 style=text-align:center>None</td></tr>"}</tbody></table>'
            f'<h3>Misconfigurations ({len(scrape_results.get("dork_misconfigs",[]))})</h3>'
            f'<table><thead><tr><th>URL</th><th>Title</th><th>Dork</th></tr></thead>'
            f'<tbody>{mc_rows or "<tr><td colspan=3 style=text-align:center>None</td></tr>"}</tbody></table>'
            f'</div>'
        )

        css = ("*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Courier New',monospace;background:#0a0a0a;color:#e0e0e0;padding:20px}.header{text-align:center;padding:30px;border:1px solid #333;margin-bottom:20px;background:#111}.header h1{color:#00ff41;font-size:28px;letter-spacing:4px}.header p{color:#888;margin-top:6px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:15px 0}.stat{background:#111;border:1px solid #333;padding:18px;text-align:center}.stat .num{font-size:32px;font-weight:bold;color:#00ff41}.stat .label{color:#888;font-size:11px;margin-top:4px}.stat.crit .num{color:#ff0040}.stat.hvt .num{color:#ff6600}.section{margin:20px 0}.section h2{color:#00ff41;border-bottom:1px solid #333;padding-bottom:6px;margin-bottom:12px}.section h3{color:#aaa;margin:12px 0 6px}table{width:100%;border-collapse:collapse}th,td{padding:8px;border:1px solid #222;font-size:12px;word-break:break-all}th{background:#1a1a1a;color:#00ff41;text-transform:uppercase;font-size:11px}td{background:#0d0d0d}tr.crit td{background:#1a0005}tr.high td{background:#1a0a00}tr.med td{background:#1a1500}.pw{color:#ff0040;font-weight:bold}.hvt-box{background:#1a0a00;border:1px solid #ff6600;padding:12px;margin:10px 0}.hvt-box ul{padding-left:20px;color:#ff6600}.pivot-node{margin:4px 0;padding:6px 10px;border-left:2px solid #333;background:#0d0d0d}.pivot-seed{border-left-color:#00ff41}.pivot-pivot{border-left-color:#00ccff}.pivot-crack{border-left-color:#cc00ff}.pivot-asset{color:#00ccff;font-weight:bold}.pivot-stats{color:#888;font-size:11px;margin-top:3px}.pivot-children{margin-left:20px;border-left:1px solid #222;padding-left:8px}")

        # ── Pivot Tree HTML section ───────────────────────────────────
        pivot_log = data.get("pivot_log", []) or []
        if pivot_log:
            log_by_key_html = {e["asset"].lower(): e for e in pivot_log}
            def _build_pivot_html(entries: list) -> str:
                html = ""
                for e in entries:
                    found_in  = e.get("found_in", e.get("source", "?"))
                    src_color = {"seed": "#00ff41", "breach": "#ff0040", "dork": "#ff6600",
                                 "scrape": "#cc00ff", "hash_crack": "#cc00ff",
                                 "pivot": "#00ccff"}.get(found_in, "#888")
                    stats_parts = []
                    if e["records"]: stats_parts.append(f'<span style="color:#ff0040">{e["records"]} breach</span>')
                    if e["dorks"]:   stats_parts.append(f'<span style="color:#ff6600">{e["dorks"]} dork</span>')
                    if e["scrape"]:  stats_parts.append(f'<span style="color:#cc00ff">{e["scrape"]} scrape</span>')
                    if e.get("cracked"): stats_parts.append(f'<span style="color:#cc00ff">cracked→{_sp(", ".join(e["cracked"][:2]))}</span>')
                    # Children with phase+ref
                    children = e.get("children", [])
                    child_html_inner = ""
                    if children:
                        _phase_colors_html = {"breach": "#ff0040", "dork": "#ff6600",
                                              "scrape": "#cc00ff", "hash_crack": "#cc00ff"}
                        child_html_inner = '<div style="margin-top:4px;font-size:10px;color:#888">↳ reinjected: '
                        parts_ch = []
                        for ch in children[:6]:
                            ph  = ch.get("found_in", "?")
                            col = _phase_colors_html.get(ph, "#888")
                            parts_ch.append(
                                f'<span style="color:{col}">[{_sp(ph)}] {_sp(ch.get("asset",""))}</span>'
                            )
                        child_html_inner += ", ".join(parts_ch)
                        if len(children) > 6:
                            child_html_inner += f" +{len(children)-6} more"
                        child_html_inner += "</div>"
                    # Recurse into processed children
                    child_log_entries = [log_by_key_html[ch["asset"].lower()]
                                         for ch in children
                                         if ch.get("asset","").lower() in log_by_key_html]
                    child_tree = _build_pivot_html(child_log_entries) if child_log_entries else ""
                    html += (
                        f'<div class="pivot-node pivot-{found_in}">'
                        f'<span style="color:{src_color};font-size:10px">[{found_in.upper()}]</span> '
                        f'<span class="pivot-asset">{_sp(e["asset"])}</span> '
                        f'<span style="color:#888;font-size:10px">({_sp(e["qtype"])})</span>'
                        + (f' <span style="color:#555;font-size:10px">← {_sp(e["parent"])}</span>' if e.get("parent") else "")
                        + (f'<div class="pivot-stats">{" &nbsp;|&nbsp; ".join(stats_parts)}</div>' if stats_parts else "")
                        + child_html_inner
                        + (f'<div class="pivot-children">{child_tree}</div>' if child_tree else "")
                        + '</div>'
                    )
                return html

            roots_html = [e for e in pivot_log if e["depth"] == 0]
            pivot_tree_html = _build_pivot_html(roots_html)
            pivot_section = (
                f'<div class="section"><h2>&#128260; Pivot Tree ({len(pivot_log)} nodes)</h2>'
                f'{pivot_tree_html}</div>'
            )
        else:
            pivot_section = ""

        # ── Discovered Assets section ─────────────────────────────────
        discovered_assets = data.get("discovered_assets", []) or []
        _phase_badge_colors = {
            "breach":     "#ff0040",
            "dork":       "#ff6600",
            "scrape":     "#cc00ff",
            "hash_crack": "#cc00ff",
            "seed":       "#00ff41",
        }
        da_rows = ""
        for da in discovered_assets:
            phase     = da.get("phase", "?")
            ref       = da.get("ref", "")
            ref_html  = (f'<a href="{_sp(ref)}" style="color:#00ff41" target="_blank">{_sp(ref[:80])}</a>'
                         if ref.startswith("http") else _sp(ref[:100]))
            badge_col = _phase_badge_colors.get(phase, "#888")
            da_rows += (
                f"<tr>"
                f"<td style='color:#00ccff'>{_sp(da.get('asset',''))}</td>"
                f"<td style='color:#aaa'>{_sp(da.get('qtype',''))}</td>"
                f"<td><span style='color:{badge_col};font-weight:bold'>{_sp(phase.upper())}</span></td>"
                f"<td style='font-size:11px'>{ref_html}</td>"
                f"<td style='color:#888'>{_sp(da.get('parent',''))}</td>"
                f"<td style='color:#888'>{da.get('depth',0)}</td>"
                f"</tr>"
            )
        discovered_section = (
            f'<div class="section"><h2>&#128270; Discovered Assets ({len(discovered_assets)} new identifiers reinjected)</h2>'
            f'<table><thead><tr><th>Asset</th><th>Type</th><th>Phase</th><th>Reference (Source / URL / Paste)</th><th>Discovered From</th><th>Depth</th></tr></thead>'
            f'<tbody>{da_rows if da_rows else "<tr><td colspan=6 style=text-align:center>No pivot assets discovered</td></tr>"}</tbody></table></div>'
        )

        page = (f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>NOX Framework — {_sp(target)}</title><style>{css}</style></head><body>'
                f'<div class="header"><h1>[ NOX Framework ]</h1><p>Target: {_sp(target)} &nbsp;|&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")} &nbsp;|&nbsp; v{VERSION}</p></div>'
                f'<div class="section"><h2>&#128203; Executive Summary</h2><div class="stats">{kpi_html}</div>'
                f'<h3>Risk Heatmap</h3><table><thead><tr><th>Level</th><th>Distribution</th><th>#</th></tr></thead><tbody>{heatmap_rows}</tbody></table>'
                f'<h3>Password Patterns</h3><table><thead><tr><th>Pattern</th><th>Count</th><th>Prevalence</th></tr></thead><tbody>{pw_rows}</tbody></table>'
                f'<div class="hvt-box"><h3>&#9888; High-Value Targets ({s["hvt_count"]})</h3><ul>{hvt_items}</ul></div></div>'
                f'<div class="section"><h2>&#128680; Top Threats</h2><table><thead><tr><th>Identity</th><th>Password</th><th>Hash</th><th>IP</th><th>Phone</th><th>Domain</th><th>Source</th><th>Date</th><th>Risk</th><th>Flag</th></tr></thead><tbody>{threat_rows}</tbody></table></div>'
                f'{pivot_section}'
                f'{discovered_section}'
                f'{doc_section}'
                f'{dork_section}'
                f'{scrape_section}'
                f'<div class="section"><h2>Credential Records (top 500)</h2><table><thead><tr><th>Email</th><th>Username</th><th>Password</th><th>Hash</th><th>IP</th><th>Phone</th><th>Domain</th><th>Source</th><th>Date</th><th>Risk</th></tr></thead><tbody>{cred_rows}</tbody></table></div>'
                f'</body></html>')
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(page)
        out("ok", f"HTML report saved: {path}")

    @staticmethod
    def to_markdown(data: dict, path: str) -> None:
        records = data.get("records",[])
        target  = data.get("target","Unknown")
        s       = AdvancedReporter._build_summary(records)
        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _r = AdvancedReporter._raw  # strip control chars, no HTML escaping for markdown
        lines   = ["# NOX Framework Report","",f"**Target:** `{_r(target)}`  ",f"**Generated:** {ts}  ",f"**Version:** {VERSION}","","---","## Executive Summary","","| Metric | Value |","|--------|-------|",f"| Compromised Identities | **{s['total_identities']}** |",f"| Total Records | **{s['total_records']}** |",f"| Stealer Logs | **{s['stealer_count']}** |",f"| High-Value Targets | **{s['hvt_count']}** |","","### Risk Distribution","","| Level | Count |","|-------|-------|"]
        for lvl, cnt in s["buckets"].items():
            if cnt: lines.append(f"| {lvl} | {cnt} |")
        lines += ["","### Password Patterns","","| Pattern | Count |","|---------|-------|"]
        for p, c in s["pw_patterns"]: lines.append(f"| {p} | {c} |")
        if s["hvt_list"]:
            lines += ["","### ⚠ High-Value Targets",""]
            for v in s["hvt_list"]: lines.append(f"- `{_r(v)}`")
        lines += ["","---","## Top Threats","","| Identity | Password | Hash | IP | Phone | Domain | Source | Date | Risk |","|----------|----------|------|----|-------|--------|--------|------|------|"]
        for r in s["top_threats"]:
            hvt = " ⚑" if HVTAnalyzer.is_hvt(r) else ""
            lines.append(
                f"| {_r(_rec_get(r,'email') or _rec_get(r,'username'))}{hvt}"
                f" | {_r(_rec_get(r,'password'))}"
                f" | {_r((_rec_get(r,'password_hash') or '')[:20])}"
                f" | {_r(_rec_get(r,'ip_address') or '')}"
                f" | {_r(_rec_get(r,'phone') or '')}"
                f" | {_r(_rec_get(r,'domain') or '')}"
                f" | {_r(_rec_get(r,'source'))}"
                f" | {_r(_rec_get(r,'breach_date'))}"
                f" | {_rec_get(r,'risk_score')} |"
            )
        lines += ["","---","## Records (top 200)","","| Email | Username | Password | Hash | IP | Phone | Domain | Source | Date | Risk |","|-------|----------|----------|------|----|-------|--------|--------|------|------|"]
        for r in records[:200]:
            lines.append(
                f"| {_r(_rec_get(r,'email'))}"
                f" | {_r(_rec_get(r,'username') or '')}"
                f" | {_r(_rec_get(r,'password') or '')}"
                f" | {_r((_rec_get(r,'password_hash') or '')[:20])}"
                f" | {_r(_rec_get(r,'ip_address') or '')}"
                f" | {_r(_rec_get(r,'phone') or '')}"
                f" | {_r(_rec_get(r,'domain') or '')}"
                f" | {_r(_rec_get(r,'source'))}"
                f" | {_r(_rec_get(r,'breach_date'))}"
                f" | {_rec_get(r,'risk_score')} |"
            )

        # ── Dork results ──────────────────────────────────────────────
        dork_results = data.get("dork_results", []) or []
        lines += ["","---",f"## Dork Results ({len(dork_results)} hits)",""]
        if dork_results:
            lines += ["| URL / Title | Snippet | Dork Query | Engine |","|-------------|---------|------------|--------|"]
            for h in dork_results:
                url     = _r(h.get("url", h.get("title", "")))
                snippet = _r(h.get("snippet", "")[:100])
                dork_q  = _r(h.get("dork", "")[:80])
                engine  = _r(h.get("engine", ""))
                link    = f"[{url[:80]}]({url})" if url.startswith("http") else url[:80]
                lines.append(f"| {link} | {snippet} | {dork_q} | {engine} |")
        else:
            lines.append("_No dork hits._")

        # ── Scrape results ────────────────────────────────────────────
        scrape_results = data.get("scrape_results", {}) or {}

        pastes = scrape_results.get("pastes", [])
        lines += ["","---",f"## Scrape — Pastes ({len(pastes)})",""]
        if pastes:
            lines += ["| Site | Paste / Link | Patterns |","|------|-------------|----------|"]
            paste_links = {
                "Pastebin": "https://pastebin.com/{}",
                "Rentry":   "https://rentry.co/{}",
                "Hastebin": "https://hastebin.com/{}",
                "DPaste":   "https://dpaste.org/{}",
                "Ghostbin": "https://ghostbin.com/paste/{}",
                "JustPaste":"https://justpaste.it/{}",
                "ControlC": "https://controlc.com/{}",
                "Paste2":   "https://paste2.org/raw/{}",
                "PastebinPro": "https://pastebin.com/{}",
            }
            for p in pastes:
                site = _r(p.get("site", ""))
                pid  = p.get("id", "")
                title = _r(p.get("title", pid)[:60])
                tmpl  = paste_links.get(p.get("site", ""), "")
                link  = f"[{title or pid}]({tmpl.format(pid)})" if tmpl and pid else (title or _r(pid))
                pats  = _r(", ".join(f"{k}({len(v)})" for k, v in (p.get("patterns") or {}).items()))
                lines.append(f"| {site} | {link} | {pats} |")
        else:
            lines.append("_No pastes found._")

        creds_scraped = scrape_results.get("credentials", [])
        lines += ["","---",f"## Scrape — Extracted Credentials ({len(creds_scraped)})",""]
        if creds_scraped:
            lines += ["| Raw Credential | Source | Paste ID |","|----------------|--------|----------|"]
            for c in creds_scraped:
                lines.append(f"| `{_r(c.get('raw','')[:100])}` | {_r(c.get('source',''))} | {_r(c.get('paste_id',''))} |")
        else:
            lines.append("_No credentials extracted._")

        tg_hits = scrape_results.get("telegram", [])
        lines += ["","---",f"## Scrape — Telegram CTI ({len(tg_hits)})",""]
        if tg_hits:
            lines += ["| Channel | Message (excerpt) | Patterns |","|---------|-------------------|----------|"]
            for t in tg_hits:
                ch   = _r(t.get("channel", ""))
                text = _r(t.get("text", "")[:150])
                pats = _r(", ".join(f"{k}({len(v)})" for k, v in (t.get("patterns") or {}).items()))
                link = f"[t.me/s/{ch}](https://t.me/s/{ch})"
                lines.append(f"| {link} | {text} | {pats} |")
        else:
            lines.append("_No Telegram hits._")

        mc_hits = scrape_results.get("dork_misconfigs", [])
        lines += ["","---",f"## Scrape — Misconfigurations ({len(mc_hits)})",""]
        if mc_hits:
            lines += ["| URL | Title | Dork |","|-----|-------|------|"]
            for m in mc_hits:
                url_m   = _r(m.get("url", ""))
                title_m = _r(m.get("title", "")[:60])
                dork_m  = _r(m.get("dork", "")[:60])
                link_m  = f"[{url_m[:60]}]({url_m})" if url_m.startswith("http") else url_m[:60]
                lines.append(f"| {link_m} | {title_m} | {dork_m} |")
        else:
            lines.append("_No misconfigurations found._")

        # ── Pivot Tree ────────────────────────────────────────────────
        pivot_log = data.get("pivot_log", []) or []
        if pivot_log:
            lines += ["","---",f"## Pivot Tree ({len(pivot_log)} nodes)","",
                      "| Depth | Asset | Type | Found In | Parent | Breach | Dorks | Scrape | Children | Cracked |",
                      "|-------|-------|------|----------|--------|--------|-------|--------|----------|---------|"]
            # J4: sort by (depth, parent, asset) for readable depth-first narrative
            for e in sorted(pivot_log, key=lambda x: (x.get("depth", 0), x.get("parent") or "", x.get("asset", ""))):
                cracked_str  = _r(", ".join(e.get("cracked", [])[:3]))
                children     = e.get("children", [])
                children_str = _r(", ".join(
                    f"{ch.get('asset','')}[{ch.get('found_in','?')}]"
                    for ch in children[:4]
                ))
                if len(children) > 4:
                    children_str += f" +{len(children)-4}"
                lines.append(
                    f"| {e['depth']}"
                    f" | `{_r(e['asset'])}`"
                    f" | {_r(e['qtype'])}"
                    f" | {_r(e.get('found_in', e.get('source','?')))}"
                    f" | {_r(e.get('parent') or '')}"
                    f" | {e['records']}"
                    f" | {e['dorks']}"
                    f" | {e['scrape']}"
                    f" | {children_str}"
                    f" | {cracked_str} |"
                )

        # ── Discovered Assets ─────────────────────────────────────────
        discovered_assets = data.get("discovered_assets", []) or []
        lines += ["","---",f"## Discovered Assets ({len(discovered_assets)} new identifiers reinjected)",""]
        if discovered_assets:
            lines += ["| Asset | Type | Phase | Reference (Source / URL / Paste) | Discovered From | Depth |",
                      "|-------|------|-------|----------------------------------|-----------------|-------|"]
            for da in discovered_assets:
                ref  = _r(da.get("ref", ""))
                link = f"[{ref[:70]}]({ref})" if ref.startswith("http") else ref[:80]
                lines.append(
                    f"| `{_r(da.get('asset',''))}`"
                    f" | {_r(da.get('qtype',''))}"
                    f" | **{_r(da.get('phase','?')).upper()}**"
                    f" | {link}"
                    f" | {_r(da.get('parent',''))}"
                    f" | {da.get('depth',0)} |"
                )
        else:
            lines.append("_No pivot assets discovered._")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        out("ok", f"Markdown saved: {path}")


# =======================================================================
# REPORTER FACADE
# =======================================================================
class Reporter:
    @staticmethod
    def _resolve_path(path: str, fmt: str) -> str:
        """If path is not absolute, place it under REPORT_DIR."""
        p = Path(path)
        if not p.is_absolute():
            p = REPORT_DIR / p
        return str(p)

    @staticmethod
    def to_json(data: dict, path: str) -> None:
        path = Reporter._resolve_path(path, "json")
        if _HAS_REPORTING:
            _rep_json(data, path); return
        def ser(o):
            if isinstance(o, (Severity, Enum)): return o.name
            if isinstance(o, Record): return o.to_dict()
            return str(o)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=ser)
        out("ok", f"JSON report saved: {path}")

    @staticmethod
    def to_csv(records: list, path: str) -> None:
        path = Reporter._resolve_path(path, "csv")
        if not records: return
        fields = ["email","password","password_hash","username","domain","ip_address","phone","breach_name","breach_date","severity","risk_score","is_hvt","data_types","persistence_score"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in records:
                row = dict(r) if isinstance(r,dict) else r.to_dict()
                if isinstance(row.get("severity"), Severity): row["severity"] = row["severity"].name
                if isinstance(row.get("data_types"), list): row["data_types"] = ", ".join(row["data_types"])
                w.writerow(row)
        out("ok", f"CSV saved: {path}")

    @staticmethod
    def to_html(data: dict, path: str) -> None:
        path = Reporter._resolve_path(path, "html")
        if _HAS_REPORTING:
            _rep_html(data, path); return
        AdvancedReporter.to_html(data, path)

    @staticmethod
    def to_markdown(data: dict, path: str) -> None:
        path = Reporter._resolve_path(path, "md")
        AdvancedReporter.to_markdown(data, path)

    @staticmethod
    def to_pdf(data: dict, path: str, investigator_id: str = "NOX-AUTO") -> None:
        path = Reporter._resolve_path(path, "pdf")
        if _HAS_REPORTING:
            # D1: _rep_pdf raises RuntimeError if fpdf2 is missing — let it propagate
            try:
                _rep_pdf(data, path, investigator_id=investigator_id)
            except RuntimeError as e:
                out("err", str(e))
            return
        # ForensicReporter (fpdf2, full forensic layout) — primary path
        try:
            import fpdf as _fpdf_check; del _fpdf_check  # noqa: F401
            ForensicReporter.generate(data, path, investigator_id=investigator_id)
            return
        except ImportError:
            pass
        # Fallback: weasyprint HTML→PDF
        if not weasyprint:
            # D1: explicit error — no silent return with no output file
            out("err", "No PDF library found. Install fpdf2: pip install fpdf2")
            return
        tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
        tmp_name = tmp.name
        tmp.close()
        try:
            AdvancedReporter.to_html(data, tmp_name)
            weasyprint(tmp_name).write_pdf(path)
            out("ok", f"PDF saved: {path}")
        finally:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


# =======================================================================
# INTERACTIVE REPL
# =======================================================================
class REPL:
    def __init__(self) -> None:
        self.config    = NoxConfig()
        self.db        = NoxDB()
        self.orc       = Orchestrator(self.config, self.db)
        self._last     = None
        self._last_full = None
        # Investigation session state
        self.session_state: Dict[str, Any] = {
            "investigator_id": os.environ.get("NOX_INVESTIGATOR_ID", "NOX-AUTO"),
            "targets_scanned": [],
            "pivot_chain":     [],
        }
        self._menu_items = [
            ("autoscan",      "Full scan + pivot + dork + scrape + analyze"),
            ("scan",          "Quick breach intelligence scan"),
            ("dork",          "Google dorking for leaked data"),
            ("scrape",        "Deep paste/web scraping + Telegram indexing"),
            ("crack",         "Identify and crack a hash"),
            ("analyze",       "Deep password strength analysis"),
            ("graph",         "Forensic graph of last scan"),
            ("visualize",     "ASCII relationship map (Target → Data → Pivots)"),
            ("pivot <n>",     "Re-scan using result #n as new seed"),
            ("search <q>",    "Filter in-memory records by keyword"),
            ("sources",       "List loaded plugins with input_type, confidence, key status"),
            ("export",        "Export last results as HTML (or: export json/csv/md/pdf)"),
            ("tor",           "Toggle Tor routing"),
            ("proxy",         "Set proxy"),
            ("config",        "Configure threads/timeout"),
            ("clear",         "Clear screen"),
            ("help",          "Show this help"),
            ("quit",          "Exit NOX"),
        ]

    def _show_menu(self) -> None:
        print(f"\n  {C.G}NOX Interactive Menu:{C.W}")
        for i, (cmd, desc) in enumerate(self._menu_items, 1):
            print(f"  {C.Y}{i:2}.{C.W} {cmd:<12} - {desc}")
        print()

    def run(self) -> None:
        self._banner()
        self._show_menu()
        while True:
            try:
                raw = input(f"\n{C.G}nox{C.W}> ").strip()
                if not raw:
                    continue
                if raw.isdigit():
                    num = int(raw)
                    if 1 <= num <= len(self._menu_items):
                        cmd_full = self._menu_items[num-1][0]
                        cmd = cmd_full.split()[0]  # strip any <n> suffix
                        # Commands that need a target/argument prompt
                        _needs_arg = {"autoscan","scan","dork","scrape","crack","analyze",
                                      "export","config","proxy","pivot","search"}
                        if cmd in _needs_arg:
                            if cmd == "crack":
                                arg = input(f"  {C.DM}Hash: {C.W}").strip()
                            elif cmd == "analyze":
                                arg = input(f"  {C.DM}Password: {C.W}").strip()
                            elif cmd in ("config", "proxy"):
                                arg = input(f"  {C.DM}Argument: {C.W}").strip()
                            elif cmd in ("pivot", "search"):
                                arg = input(f"  {C.DM}Argument: {C.W}").strip()
                            elif cmd == "export":
                                arg = input(f"  {C.DM}Format [html/json/csv/md/pdf]: {C.W}").strip() or "html"
                            else:
                                arg = input(f"  {C.DM}Target: {C.W}").strip()
                        else:
                            arg = ""
                        self._dispatch(cmd, arg)
                    else:
                        out("warn", f"Invalid number: {num}")
                else:
                    parts = raw.split(None, 1)
                    cmd   = parts[0].lower()
                    arg   = parts[1] if len(parts) > 1 else ""
                    self._dispatch(cmd, arg)
            except KeyboardInterrupt:
                print()
                out("info", "Interrupted. Type 'quit' to exit.")
            except EOFError:
                break
            except Exception as e:
                out("err", f"Error: {e}")

    def _dispatch(self, cmd: str, arg: str) -> None:
        if cmd in ("quit","exit","q"):
            out("info", "Exiting.")
            # B3: flush DB background thread before exit
            try:
                self.db.close()
            except Exception:
                pass
            sys.exit(0)
        elif cmd in ("help","h","?"):
            self._help()
        elif cmd == "autoscan":
            self._fullscan(arg or input(f"  {C.DM}Target: {C.W}").strip())
        elif cmd == "scan":
            self._scan(arg or input(f"  {C.DM}Target: {C.W}").strip())
        elif cmd == "dork":
            self._dork(arg or input(f"  {C.DM}Target: {C.W}").strip())
        elif cmd == "scrape":
            self._scrape(arg or input(f"  {C.DM}Target: {C.W}").strip())
        elif cmd == "crack":
            self._crack(arg or input(f"  {C.DM}Hash: {C.W}").strip())
        elif cmd == "analyze":
            self._analyze(arg or input(f"  {C.DM}Password: {C.W}").strip())
        elif cmd in ("sources", "list-sources"):
            self._sources()
        elif cmd == "export":
            self._export(arg)
        elif cmd == "tor":
            self._tor()
        elif cmd == "proxy":
            self._proxy(arg)
        elif cmd == "config":
            self._config(arg)
        elif cmd == "graph":
            self._graph()
        elif cmd in ("visualize", "vis"):
            self._visualize()
        elif cmd == "pivot":
            self._pivot(arg)
        elif cmd == "search":
            self._search(arg or input(f"  {C.DM}Query: {C.W}").strip())
        elif cmd == "clear":
            os.system("clear" if os.name != "nt" else "cls")
        elif cmd == "menu":
            self._show_menu()
        elif cmd == "banner":
            self._banner()
        else:
            out("warn", f"Unknown command: {cmd}. Type 'help' or 'menu' for options.")

    def _banner(self) -> None:
        opsec_proxy = self.config.proxy or self.config.use_tor
        if opsec_proxy:
            opsec_label = f"{C.G}[OPSEC: PROTECTED]{C.X}"
        elif getattr(self.config, "allow_leak", False):
            opsec_label = f"{C.R}[OPSEC: UNPROTECTED]{C.X}"
        else:
            opsec_label = f"{C.Y}[OPSEC: GUARDIAN]{C.X}"
        print(f"""
{C.G}
    ███╗   ██╗ ██████╗ ██╗  ██╗
    ████╗  ██║██╔═══██╗╚██╗██╔╝
    ██╔██╗ ██║██║   ██║ ╚███╔╝
    ██║╚██╗██║██║   ██║ ██╔██╗
    ██║ ╚████║╚██████╔╝██╔╝ ██╗
    ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
{C.W}
    Cyber Threat Intelligence Framework  {C.Y}v{VERSION}{C.W}
    {C.DM}120+ JSON plugin sources | Async Core | Pivot Engine | JA3 TLS | HVT Detection{C.W}
    {opsec_label}
""")

    def _help(self) -> None:
        self._show_menu()
        out("info", "\nYou can also type commands directly (e.g., 'scan user@example.com').")

    def _scan(self, arg: str) -> None:
        if not arg: out("warn","No target specified."); return
        self._last      = self.orc.scan(arg)
        analysis        = CredAnalyzer.analyze(self._last)
        HVTAnalyzer.annotate(self._last)
        hvt_records     = HVTAnalyzer.filter_hvt(self._last)
        prev = self._last_full or {}
        self._last_full = {
            "target":            arg,
            "records":           self._last,
            "analysis":          analysis,
            "hvt_records":       hvt_records,
            "dork_results":      prev.get("dork_results", []),
            "scrape_results":    prev.get("scrape_results", {}),
            "pivot_chain":       [arg],
            "pivot_log":         [],
            "discovered_assets": [],
            "scan_meta":         {"pivot_depth": 0, "nodes_discovered": len(self._last)},
        }
        self.session_state["targets_scanned"].append(arg)

        W   = 62
        rs  = analysis.get("risk_score", 0)
        sev = analysis.get("severity", {})
        col = C.R if rs > 60 else C.Y if rs > 30 else C.G
        badge = (f"{C.R}[CRITICAL]{C.X}" if rs > 60 or sev.get("critical", 0) > 0
                 else f"{C.Y}[HIGH]{C.X}" if rs > 30 or sev.get("high", 0) > 0
                 else f"{C.G}[MEDIUM]{C.X}")

        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.G}  BREACH SCAN RESULTS{C.X}  {badge}")
        print(f"  {C.DM}  Target: {arg}{C.X}")
        print(f"  {C.G}{'━'*W}{C.X}")

        # ── Stats grid ────────────────────────────────────────────────
        total   = analysis.get("total_records", 0)
        unique  = analysis.get("unique_records", total)
        emails  = analysis.get("unique_emails", 0)
        pw_cnt  = analysis.get("passwords_found", 0)
        stealer = analysis.get("stealer_logs", 0)
        hvt_cnt = analysis.get("hvt_count", 0)
        reused  = len(analysis.get("reused_passwords", {}))

        print(f"\n  {'Records':<26} {total}  {C.DM}({unique} unique){C.X}")
        print(f"  {'Unique Emails':<26} {emails}")
        print(f"  {'Passwords Exposed':<26} {C.R}{pw_cnt}{C.X}")
        print(f"  {'Stealer Logs':<26} {C.R}{stealer}{C.X}")
        print(f"  {'High-Value Targets':<26} {C.O}{hvt_cnt}{C.X}")
        print(f"  {'Password Reuse':<26} {C.Y if reused else C.DM}{reused} password(s) reused{C.X}")
        print(f"  {'Risk Score':<26} {col}{rs}/100{C.X}")
        print(f"  {'Severity':<26} "
              f"{C.R}{sev.get('critical',0)} CRIT{C.X}  "
              f"{C.Y}{sev.get('high',0)} HIGH{C.X}  "
              f"{sev.get('medium',0)} MED  "
              f"{C.DM}{sev.get('low',0)} LOW{C.X}")

        # ── Top exposed credentials ───────────────────────────────────
        creds = [(r, _rec_get(r, "password")) for r in self._last if _rec_get(r, "password")]
        if creds:
            print(f"\n  {C.Y}┌─ TOP EXPOSED CREDENTIALS ({len(creds)} total) {'─'*(W-38)}┐{C.X}")
            for r, pw in creds[:8]:
                em      = (_rec_get(r, "email") or _rec_get(r, "username") or "—")[:38]
                src     = _rec_get(r, "source") or ""
                breach  = _rec_get(r, "breach_name") or ""
                rs_r    = _rec_get(r, "risk_score") or 0
                rc      = C.R if float(rs_r) >= 70 else C.Y if float(rs_r) >= 40 else C.W
                masked  = pw[:2] + "●" * min(len(pw) - 2, 8) if len(pw) > 2 else "●●●●"
                ref_tag = f"  {C.DM}[{breach or src}]{C.X}" if (breach or src) else ""
                print(f"  {C.Y}│{C.X}  {C.CY}{em:<38}{C.X}  {rc}{masked:<12}{C.X}  {rc}risk:{rs_r}{C.X}{ref_tag}")
                extra = self._record_assets(r)
                if extra: print(f"  {C.Y}│{C.X}     {extra}")
            if len(creds) > 8:
                print(f"  {C.Y}│{C.X}  {C.DM}… and {len(creds)-8} more — use 'export' for the full list{C.X}")
            print(f"  {C.Y}└{'─'*(W-2)}┘{C.X}")

        # ── Non-credential assets (IPs, phones, domains, usernames, hashes) ──
        other = [r for r in self._last if not _rec_get(r, "password")]
        if other:
            print(f"\n  {C.B}┌─ DISCOVERED ASSETS ({len(other)}) {'─'*(W-22)}┐{C.X}")
            for r in other[:10]:
                ident  = _rec_get(r, "email") or _rec_get(r, "username") or _rec_get(r, "ip_address") or _rec_get(r, "domain") or "—"
                src    = _rec_get(r, "source") or ""
                breach = _rec_get(r, "breach_name") or ""
                rs_r   = _rec_get(r, "risk_score") or 0
                ref    = breach or src
                print(f"  {C.B}│{C.X}  {C.CY}{ident:<38}{C.X}  {C.DM}risk:{rs_r}  [{ref[:22]}]{C.X}")
                extra = self._record_assets(r)
                if extra: print(f"  {C.B}│{C.X}     {extra}")
            if len(other) > 10:
                print(f"  {C.B}│{C.X}  {C.DM}… and {len(other)-10} more — use 'export' for the full list{C.X}")
            print(f"  {C.B}└{'─'*(W-2)}┘{C.X}")

        # ── HVT alert ─────────────────────────────────────────────────
        hvt = [r for r in self._last if HVTAnalyzer.is_hvt(r)]
        if hvt:
            print(f"\n  {C.O}⚑  HIGH-VALUE TARGETS ({len(hvt)}){C.X}")
            for r in hvt[:5]:
                ident = _rec_get(r, "email") or _rec_get(r, "username") or "—"
                rs_r  = _rec_get(r, "risk_score") or ""
                print(f"  {C.O}→{C.X}  {ident:<45}  {C.Y}risk: {rs_r}{C.X}")
            if len(hvt) > 5:
                print(f"  {C.DM}  … and {len(hvt)-5} more{C.X}")

        # ── Password reuse ────────────────────────────────────────────
        reused_map = analysis.get("reused_passwords", {})
        if reused_map:
            print(f"\n  {C.R}⚠  PASSWORD REUSE DETECTED{C.X}")
            for pw, cnt in list(reused_map.items())[:4]:
                masked = pw[:2] + "●" * (len(pw) - 2) if len(pw) > 2 else "●●●●"
                print(f"  {C.R}→{C.X}  {masked}  reused {cnt}× across breaches")

        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.DM}Use 'graph' for full report  |  'export pdf/html/json' for forensic output{C.X}\n")

    def _fullscan(self, arg: str) -> None:
        if not arg: out("warn","No target specified."); return
        out("info", f"[autoscan] Starting full scan + pivot + dork + scrape for: {arg}")
        # Seed the pivot chain immediately so it's visible even if the scan fails
        if arg not in self.session_state["pivot_chain"]:
            self.session_state["pivot_chain"].append(arg)
        result = {"target": arg, "records": [], "dork_results": [], "scrape_results": {},
                  "hvt_records": [], "pivot_chain": [arg], "pivot_log": [], "discovered_assets": [], "scan_meta": {}}
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    result = ex.submit(asyncio.run, self.orc.fullscan(arg, pivot=not self.config.no_pivot)).result(timeout=600)
            else:
                result = asyncio.run(self.orc.fullscan(arg, pivot=not self.config.no_pivot))
        finally:
            self._last      = result.get("records", [])
            self._last_full = result
            self.session_state["targets_scanned"].append(arg)
            for node in result.get("pivot_chain", [arg]):
                if node not in self.session_state["pivot_chain"]:
                    self.session_state["pivot_chain"].append(node)

        scan_meta = result.get("scan_meta", {}) or {}
        elapsed   = scan_meta.get("elapsed_seconds")
        depth     = scan_meta.get("pivot_depth", 0)
        nodes     = scan_meta.get("nodes_discovered", 0)
        analysis  = result.get("analysis") or CredAnalyzer.analyze(self._last)
        rs_total  = analysis.get("risk_score", 0)
        sev       = analysis.get("severity", {})
        col       = C.R if rs_total > 60 else C.Y if rs_total > 30 else C.G
        badge     = (f"{C.R}[CRITICAL]{C.X}" if rs_total > 60 or sev.get("critical", 0) > 0
                     else f"{C.Y}[HIGH]{C.X}" if rs_total > 30 or sev.get("high", 0) > 0
                     else f"{C.G}[MEDIUM]{C.X}")
        W = 62

        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.G}  AUTOSCAN COMPLETE{C.X}  {badge}  {C.DM}target: {arg}{C.X}")
        print(f"  {C.G}{'━'*W}{C.X}")

        # ── Summary stats ─────────────────────────────────────────────
        dork_count   = len(result.get("dork_results", []) or [])
        scrape_r     = result.get("scrape_results", {}) or {}
        paste_count  = len(scrape_r.get("pastes", []))
        cred_sc_cnt  = len(scrape_r.get("credentials", []))
        tg_count     = len(scrape_r.get("telegram", []))
        mc_count     = len(scrape_r.get("dork_misconfigs", []))

        print(f"\n  {'Records':<26} {analysis.get('total_records', len(self._last or []))}"
              f"  {C.DM}({analysis.get('unique_records', 0)} unique){C.X}")
        print(f"  {'Passwords Exposed':<26} {C.R}{analysis.get('passwords_found', 0)}{C.X}")
        print(f"  {'Stealer Logs':<26} {C.R}{analysis.get('stealer_logs', 0)}{C.X}")
        print(f"  {'High-Value Targets':<26} {C.O}{analysis.get('hvt_count', 0)}{C.X}")
        print(f"  {'Dork Hits':<26} {C.O}{dork_count}{C.X}")
        print(f"  {'Pastes Found':<26} {C.P}{paste_count}{C.X}")
        if cred_sc_cnt: print(f"  {'Scraped Credentials':<26} {C.R}{cred_sc_cnt}{C.X}")
        if tg_count:    print(f"  {'Telegram Hits':<26} {C.CY}{tg_count}{C.X}")
        if mc_count:    print(f"  {'Misconfigurations':<26} {C.O}{mc_count}{C.X}")
        print(f"  {'Nodes Discovered':<26} {nodes}")
        print(f"  {'Pivot Depth':<26} {depth}")
        if elapsed is not None:     print(f"  {'Elapsed':<26} {elapsed:.1f}s")
        da_cnt = len(result.get("discovered_assets", []) or [])
        if da_cnt:      print(f"  {'Reinjected Assets':<26} {C.CY}{da_cnt}{C.X}")
        print(f"  {'Risk Score':<26} {col}{rs_total}/100{C.X}")
        print(f"  {'Severity':<26} "
              f"{C.R}{sev.get('critical',0)} CRIT{C.X}  "
              f"{C.Y}{sev.get('high',0)} HIGH{C.X}  "
              f"{sev.get('medium',0)} MED")

        # ── High-Value Targets ────────────────────────────────────────
        hvt = result.get("hvt_records", [])
        if hvt:
            print(f"\n  {C.O}{'─'*W}{C.X}")
            print(f"  {C.O}⚑  HIGH-VALUE TARGETS  ({len(hvt)}){C.X}")
            print(f"  {C.O}{'─'*W}{C.X}")
            for r in hvt[:10]:
                ident = _rec_get(r, "email") or _rec_get(r, "username") or "—"
                rs    = _rec_get(r, "risk_score")
                print(f"  {C.R}→{C.X}  {C.W}{ident:<45}{C.X}  {C.Y}risk: {rs}{C.X}")
                extra = self._record_assets(r)
                if extra: print(f"       {extra}")
            if len(hvt) > 10:
                print(f"  {C.DM}  … and {len(hvt)-10} more — use 'graph' or 'export' for the full list{C.X}")

        # ── Discovered Assets (flat provenance table) ─────────────────
        # ── Pivot Tree ────────────────────────────────────────────────
        pivot_log        = result.get("pivot_log", [])
        discovered_assets = result.get("discovered_assets", [])
        if pivot_log:
            print(f"\n  {C.CY}{'─'*W}{C.X}")
            print(f"  {C.CY}  PIVOT TREE  ({len(pivot_log)} nodes){C.X}")
            print(f"  {C.CY}{'─'*W}{C.X}")
            self._print_pivot_tree(pivot_log, result)
        else:
            # No avalanche engine — flat display
            recs = self._last or []
            cred_recs  = [r for r in recs if _rec_get(r, "password")]
            other_recs = [r for r in recs if not _rec_get(r, "password")]
            if cred_recs:
                print(f"\n  {C.R}{'─'*W}{C.X}")
                print(f"  {C.R}[!]  EXPOSED CREDENTIALS  ({len(cred_recs)}){C.X}")
                print(f"  {C.R}{'─'*W}{C.X}")
                for r in cred_recs[:12]:
                    em  = (_rec_get(r, "email") or _rec_get(r, "username") or "—")[:40]
                    pw  = _rec_get(r, "password") or ""
                    src = _rec_get(r, "source") or ""
                    rs_r = _rec_get(r, "risk_score") or 0
                    masked = pw[:2] + "●" * min(len(pw) - 2, 8) if len(pw) > 2 else "●●●●"
                    rc = C.R if float(rs_r) >= 70 else C.Y if float(rs_r) >= 40 else C.W
                    print(f"  {C.R}→{C.X}  {C.CY}{em:<40}{C.X}  {rc}{masked}{C.X}  {C.DM}[{src[:18]}] risk:{rs_r}{C.X}")
                    extra = self._record_assets(r)
                    if extra: print(f"       {extra}")
                if len(cred_recs) > 12:
                    print(f"  {C.DM}  … and {len(cred_recs)-12} more — use 'export'{C.X}")
            if other_recs:
                print(f"\n  {C.B}{'─'*W}{C.X}")
                print(f"  {C.B}[~]  DISCOVERED ASSETS  ({len(other_recs)}){C.X}")
                print(f"  {C.B}{'─'*W}{C.X}")
                for r in other_recs[:12]:
                    ident = _rec_get(r, "email") or _rec_get(r, "username") or "—"
                    src   = _rec_get(r, "source") or ""
                    rs_r  = _rec_get(r, "risk_score") or 0
                    print(f"  {C.B}→{C.X}  {C.CY}{ident:<40}{C.X}  {C.DM}[{src[:18]}] risk:{rs_r}{C.X}")
                    extra = self._record_assets(r)
                    if extra: print(f"       {extra}")
                if len(other_recs) > 12:
                    print(f"  {C.DM}  … and {len(other_recs)-12} more — use 'export'{C.X}")

        # ── Flat discovered assets table ──────────────────────────────
        if discovered_assets:
            _phase_col = {"breach": C.R, "dork": C.O, "scrape": C.P,
                          "hash_crack": C.P, "seed": C.G}
            print(f"\n  {C.B}{'─'*W}{C.X}")
            print(f"  {C.B}  DISCOVERED ASSETS  ({len(discovered_assets)} new identifiers){C.X}")
            print(f"  {C.B}{'─'*W}{C.X}")
            print(f"  {C.DM}  {'ASSET':<38} {'TYPE':<10} {'PHASE':<10} {'FOUND IN / REF'}{C.X}")
            print(f"  {C.DM}  {'─'*38} {'─'*10} {'─'*10} {'─'*30}{C.X}")
            for da in discovered_assets[:50]:
                pc  = _phase_col.get(da["phase"], C.DM)
                ref = da.get("ref", "")[:55]
                print(f"  {C.CY}  {da['asset']:<38}{C.X} {C.DM}{da['qtype']:<10}{C.X} "
                      f"{pc}{da['phase']:<10}{C.X} {C.DM}{ref}{C.X}")
            if len(discovered_assets) > 50:
                print(f"  {C.DM}  … and {len(discovered_assets)-50} more — use 'export' for full list{C.X}")

        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.DM}Use 'graph' for full intelligence report  |  'export pdf/html/json' for forensic output{C.X}\n")

    def _print_pivot_tree(self, pivot_log: list, result: dict) -> None:
        """Print the full pivot tree with per-node phase findings and reinjection details."""
        log_by_key = {e["asset"].lower(): e for e in pivot_log}

        # Index breach records by the scanned asset (matched by email/username/phone/domain)
        all_recs = result.get("records", []) or []
        recs_by_asset: Dict[str, list] = {}
        for r in all_recs:
            # A record belongs to the asset whose value matches the record's identity fields
            for fname in ("email", "username", "phone", "domain", "ip_address"):
                v = _rec_get(r, fname)
                if v:
                    recs_by_asset.setdefault(v.lower(), []).append(r)
                    break  # one record → one bucket

        # Index dork/scrape hits by pivot_asset tag
        dork_by_asset: Dict[str, list] = {}
        for h in result.get("dork_results", []) or []:
            dork_by_asset.setdefault(h.get("pivot_asset", "").lower(), []).append(h)

        scrape_by_asset: Dict[str, list] = {}
        for cat in ("credentials", "pastes", "telegram", "dork_misconfigs"):
            for item in (result.get("scrape_results", {}) or {}).get(cat, []):
                if isinstance(item, dict):
                    scrape_by_asset.setdefault(
                        item.get("pivot_asset", "").lower(), []
                    ).append((cat, item))

        phase_colors = {
            "seed":       C.G,
            "breach":     C.R,
            "dork":       C.O,
            "scrape":     C.P,
            "hash_crack": C.P,
            "pivot":      C.CY,
        }

        def _print_node(entry: dict, prefix: str, is_last: bool) -> None:
            asset    = entry["asset"]
            qtype    = entry["qtype"]
            found_in = entry.get("found_in", entry.get("source", "?"))
            n_rec    = entry["records"]
            n_dork   = entry["dorks"]
            n_sc     = entry["scrape"]
            cracked  = entry.get("cracked") or []
            children = entry.get("children", [])  # list of dicts: {asset,qtype,found_in,ref}

            conn = "└─" if is_last else "├─"
            fc   = phase_colors.get(found_in, C.DM)
            tag  = f"{fc}[{found_in.upper()}]{C.X}"
            hvt_flag = ""
            # Check if this asset appears in HVT records
            for r in (result.get("hvt_records", []) or []):
                if ((_rec_get(r, "email") or _rec_get(r, "username") or "") == asset):
                    hvt_flag = f"  {C.O}⚑HVT{C.X}"
                    break

            print(f"  {prefix}{C.DM}{conn}{C.X} {tag} {C.W}{asset}{C.X}  {C.DM}({qtype}){C.X}{hvt_flag}")
            cp = prefix + ("     " if is_last else "│    ")

            # Stats
            stats = []
            if n_rec:   stats.append(f"{C.R}{n_rec} breach{C.X}")
            if n_dork:  stats.append(f"{C.O}{n_dork} dork{C.X}")
            if n_sc:    stats.append(f"{C.P}{n_sc} scrape{C.X}")
            if cracked: stats.append(f"{C.P}cracked→{', '.join(cracked[:2])}{C.X}")
            if stats:
                print(f"  {cp}  {C.DM}results:{C.X} {' | '.join(stats)}")

            # Breach records for this asset
            key = asset.lower()
            asset_recs = recs_by_asset.get(key, [])
            cred_recs  = [r for r in asset_recs if _rec_get(r, "password")]
            other_recs = [r for r in asset_recs if not _rec_get(r, "password")]
            for r in cred_recs[:4]:
                em     = (_rec_get(r, "email") or _rec_get(r, "username") or "—")[:32]
                pw     = _rec_get(r, "password") or ""
                src    = _rec_get(r, "source") or ""
                rs_r   = float(_rec_get(r, "risk_score") or 0)
                masked = pw[:2] + "●" * min(len(pw)-2, 6) if len(pw) > 2 else "●●●●"
                rc     = C.R if rs_r >= 70 else C.Y if rs_r >= 40 else C.W
                extra  = self._record_assets(r)
                print(f"  {cp}  {C.R}breach{C.X} {C.CY}{em}{C.X}  {rc}{masked}{C.X}  "
                      f"{C.DM}[{src[:20]}] risk:{rs_r:.0f}{C.X}")
                if extra: print(f"  {cp}         {extra}")
            if len(cred_recs) > 4:
                print(f"  {cp}  {C.DM}… +{len(cred_recs)-4} more credentials{C.X}")
            for r in other_recs[:2]:
                ident = _rec_get(r, "email") or _rec_get(r, "username") or "—"
                extra = self._record_assets(r)
                src   = _rec_get(r, "source") or ""
                print(f"  {cp}  {C.B}asset{C.X}  {C.CY}{ident}{C.X}  {C.DM}[{src[:20]}]{C.X}")
                if extra: print(f"  {cp}         {extra}")
            if len(other_recs) > 2:
                print(f"  {cp}  {C.DM}… +{len(other_recs)-2} more assets{C.X}")

            # Dork hits for this asset
            for h in dork_by_asset.get(key, [])[:3]:
                url  = h.get("url", "")[:70]
                dork = h.get("dork", "")[:60]
                print(f"  {cp}  {C.O}dork{C.X}   {C.DM}{url or dork}{C.X}")
                if url and dork:
                    print(f"  {cp}         {C.DM}query: {dork[:60]}{C.X}")
            if len(dork_by_asset.get(key, [])) > 3:
                print(f"  {cp}  {C.DM}… +{len(dork_by_asset[key])-3} more dork hits{C.X}")

            # Scrape items for this asset
            for cat, item in scrape_by_asset.get(key, [])[:3]:
                if cat == "credentials":
                    print(f"  {cp}  {C.R}cred{C.X}   {item.get('raw','')[:65]}")
                elif cat == "telegram":
                    print(f"  {cp}  {C.CY}tg{C.X}     [{item.get('channel','')}] {item.get('text','')[:55]}")
                elif cat == "pastes":
                    pats = ", ".join(f"{k}({len(v)})" for k,v in (item.get("patterns") or {}).items())
                    print(f"  {cp}  {C.P}paste{C.X}  [{item.get('site','')}] {item.get('id','')[:30]}  {C.DM}{pats}{C.X}")
                elif cat == "dork_misconfigs":
                    print(f"  {cp}  {C.O}misc{C.X}   {item.get('url', item.get('title',''))[:65]}")
            if len(scrape_by_asset.get(key, [])) > 3:
                print(f"  {cp}  {C.DM}… +{len(scrape_by_asset[key])-3} more scrape items{C.X}")

            # Children — show what was discovered and from which phase
            if children:
                print(f"  {cp}  {C.DM}↳ reinjected {len(children)} new asset(s):{C.X}")
                for ch in children[:8]:
                    ch_asset = ch.get("asset", "")
                    ch_qt    = ch.get("qtype", "")
                    ch_phase = ch.get("found_in", "?")
                    ch_ref   = ch.get("ref", "")[:55]
                    ch_color = phase_colors.get(ch_phase, C.DM)
                    # Show whether this child was itself processed (has a log entry)
                    processed = "✓" if ch_asset.lower() in log_by_key else "…"
                    print(f"  {cp}    {processed} {ch_color}[{ch_phase}]{C.X} "
                          f"{C.CY}{ch_asset}{C.X}  {C.DM}({ch_qt})  ref: {ch_ref}{C.X}")
                if len(children) > 8:
                    print(f"  {cp}    {C.DM}… +{len(children)-8} more{C.X}")

            # Recurse into child log entries
            child_log_entries = [log_by_key[ch["asset"].lower()]
                                 for ch in children
                                 if ch.get("asset","").lower() in log_by_key]
            for i, child_entry in enumerate(child_log_entries):
                _print_node(child_entry, cp, is_last=(i == len(child_log_entries)-1))

        roots = [e for e in pivot_log if e["depth"] == 0]
        for i, root in enumerate(roots):
            _print_node(root, "", is_last=(i == len(roots)-1))

    def _dork(self, arg: str) -> None:
        if not arg: out("warn","No target specified."); return
        results = self.orc.dork(arg)
        prev = self._last_full or {}
        self._last_full = {
            "target":            arg if not prev.get("target") else prev["target"],
            "records":           prev.get("records", self._last or []),
            "analysis":          prev.get("analysis", {}),
            "hvt_records":       prev.get("hvt_records", []),
            "dork_results":      results,
            "scrape_results":    prev.get("scrape_results", {}),
            "pivot_chain":       prev.get("pivot_chain", [arg]),
            "pivot_log":         prev.get("pivot_log", []),
            "discovered_assets": prev.get("discovered_assets", []),
            "scan_meta":         prev.get("scan_meta", {}),
        }
        if not self._last:
            self._last = self._last_full["records"]

        W = 62
        print(f"\n  {C.O}{'━'*W}{C.X}")
        print(f"  {C.O}  DORK RESULTS{C.X}  {C.DM}target: {arg}{C.X}")
        print(f"  {C.O}{'━'*W}{C.X}")

        if not results:
            print(f"\n  {C.DM}  No results found.{C.X}")
        else:
            # Group by engine
            by_engine: Dict[str, list] = {}
            for r in results:
                eng = r.get("engine", "Unknown")
                by_engine.setdefault(eng, []).append(r)

            print(f"\n  {C.W}Total hits: {C.O}{len(results)}{C.X}  "
                  f"{C.DM}engines: {', '.join(f'{e}({len(v)})' for e, v in by_engine.items())}{C.X}\n")

            for i, r in enumerate(results[:20], 1):
                title   = (r.get("title") or r.get("dork") or "")[:65]
                url     = r.get("url", "")
                snippet = r.get("snippet", "")[:110]
                engine  = r.get("engine", "")
                dork_q  = r.get("dork", "")[:60]
                eng_tag = f"  {C.DM}[{engine}]{C.X}" if engine else ""
                print(f"  {C.O}{i:2}.{C.X}  {C.W}{title}{C.X}{eng_tag}")
                if url:
                    print(f"       {C.CY}{url[:80]}{C.X}")
                if snippet:
                    print(f"       {C.DM}{snippet}{C.X}")
                if dork_q and dork_q != title:
                    print(f"       {C.DM}dork: {dork_q}{C.X}")
                print()

            if len(results) > 20:
                print(f"  {C.DM}  … and {len(results)-20} more — use 'export' for the full list{C.X}")

        print(f"  {C.O}{'━'*W}{C.X}")
        print(f"  {C.DM}Use 'export html/pdf/json' to save the full dork report.{C.X}\n")

    def _scrape(self, arg: str) -> None:
        if not arg: out("warn","No target specified."); return
        results = self.orc.scrape(arg)
        prev = self._last_full or {}
        self._last_full = {
            "target":            arg if not prev.get("target") else prev["target"],
            "records":           prev.get("records", self._last or []),
            "analysis":          prev.get("analysis", {}),
            "hvt_records":       prev.get("hvt_records", []),
            "dork_results":      prev.get("dork_results", []),
            "scrape_results":    results,
            "pivot_chain":       prev.get("pivot_chain", [arg]),
            "pivot_log":         prev.get("pivot_log", []),
            "discovered_assets": prev.get("discovered_assets", []),
            "scan_meta":         prev.get("scan_meta", {}),
        }
        if not self._last:
            self._last = self._last_full["records"]

        pastes  = results.get("pastes", [])
        creds   = results.get("credentials", [])
        hashes  = results.get("hashes", [])
        tg      = results.get("telegram", [])
        mc      = results.get("dork_misconfigs", [])
        total   = len(pastes) + len(creds) + len(tg) + len(mc)

        W = 62
        print(f"\n  {C.P}{'━'*W}{C.X}")
        print(f"  {C.P}  SCRAPE RESULTS{C.X}  {C.DM}target: {arg}{C.X}")
        print(f"  {C.P}{'━'*W}{C.X}")

        # ── Summary row ───────────────────────────────────────────────
        print(f"\n  {'Pastes':<20} {C.P}{len(pastes)}{C.X}")
        print(f"  {'Credentials':<20} {C.R}{len(creds)}{C.X}")
        print(f"  {'Hashes':<20} {C.Y}{len(hashes)}{C.X}")
        print(f"  {'Telegram Hits':<20} {C.CY}{len(tg)}{C.X}")
        print(f"  {'Misconfigurations':<20} {C.O}{len(mc)}{C.X}")

        # ── Pastes ────────────────────────────────────────────────────
        _paste_url_tmpl = {
            "Pastebin": "https://pastebin.com/{}", "Rentry": "https://rentry.co/{}",
            "Hastebin": "https://hastebin.com/{}", "DPaste": "https://dpaste.org/{}",
            "Ghostbin": "https://ghostbin.com/paste/{}", "JustPaste": "https://justpaste.it/{}",
            "ControlC": "https://controlc.com/{}", "Paste2": "https://paste2.org/raw/{}",
        }
        if pastes:
            print(f"\n  {C.P}┌─ PASTES ({len(pastes)}) {'─'*(W-14)}┐{C.X}")
            for p in pastes[:10]:
                site  = p.get("site", "")
                pid   = p.get("id", "")
                title = (p.get("title") or pid)[:45]
                pats  = ", ".join(f"{k}({len(v)})" for k, v in (p.get("patterns") or {}).items())
                tmpl  = _paste_url_tmpl.get(site, "")
                url   = tmpl.format(pid) if tmpl and pid else ""
                pat_tag = f"  {C.DM}{pats}{C.X}" if pats else ""
                print(f"  {C.P}│{C.X}  {C.DM}[{site}]{C.X}  {title}{pat_tag}")
                if url:
                    print(f"  {C.P}│{C.X}  {C.CY}  {url}{C.X}")
            if len(pastes) > 10:
                print(f"  {C.P}│{C.X}  {C.DM}… and {len(pastes)-10} more{C.X}")
            print(f"  {C.P}└{'─'*(W-2)}┘{C.X}")

        # ── Extracted credentials ─────────────────────────────────────
        if creds:
            print(f"\n  {C.R}┌─ EXTRACTED CREDENTIALS ({len(creds)}) {'─'*(W-26)}┐{C.X}")
            for c in creds[:12]:
                raw = c.get("raw", "")[:75]
                src = c.get("source", "")
                src_tag = f"  {C.DM}[{src}]{C.X}" if src else ""
                print(f"  {C.R}│{C.X}  {C.R}{raw}{C.X}{src_tag}")
            if len(creds) > 12:
                print(f"  {C.R}│{C.X}  {C.DM}… and {len(creds)-12} more — use 'export' for the full list{C.X}")
            print(f"  {C.R}└{'─'*(W-2)}┘{C.X}")

        # ── Telegram CTI ──────────────────────────────────────────────
        if tg:
            print(f"\n  {C.CY}┌─ TELEGRAM CTI ({len(tg)}) {'─'*(W-18)}┐{C.X}")
            for t in tg[:6]:
                ch   = t.get("channel", "")
                text = t.get("text", "")[:65]
                pats = ", ".join(f"{k}({len(v)})" for k, v in (t.get("patterns") or {}).items())
                pat_tag = f"  {C.DM}{pats}{C.X}" if pats else ""
                print(f"  {C.CY}│{C.X}  {C.DM}[{ch}]{C.X}  {text}{pat_tag}")
            if len(tg) > 6:
                print(f"  {C.CY}│{C.X}  {C.DM}… and {len(tg)-6} more{C.X}")
            print(f"  {C.CY}└{'─'*(W-2)}┘{C.X}")

        # ── Misconfigurations ─────────────────────────────────────────
        if mc:
            print(f"\n  {C.O}┌─ MISCONFIGURATIONS ({len(mc)}) {'─'*(W-22)}┐{C.X}")
            for m in mc[:6]:
                title = m.get("title", "")[:55]
                url   = m.get("url", "")[:70]
                dork  = m.get("dork", "")[:55]
                print(f"  {C.O}│{C.X}  {C.W}{title}{C.X}")
                if url:
                    print(f"  {C.O}│{C.X}  {C.DM}{url}{C.X}")
                if dork and dork != title:
                    print(f"  {C.O}│{C.X}  {C.DM}dork: {dork}{C.X}")
            if len(mc) > 6:
                print(f"  {C.O}│{C.X}  {C.DM}… and {len(mc)-6} more{C.X}")
            print(f"  {C.O}└{'─'*(W-2)}┘{C.X}")

        if total == 0:
            print(f"\n  {C.DM}  No results found.{C.X}")

        print(f"\n  {C.P}{'━'*W}{C.X}")
        print(f"  {C.DM}Use 'export html/pdf/json' to save the full scrape report.{C.X}\n")

    def _crack(self, arg: str) -> None:
        if not arg: out("warn","No hash specified."); return
        out("info", f"  Cracking: {arg}")
        result = self.orc.crack(arg)
        out("info", f"  Possible types: {', '.join(t[0] for t in result.get('types',[]))}")
        if result.get("plaintext"):
            out("ok", f"  ✓ CRACKED: {result['plaintext']}")
            out("info", f"  Method: {result['method']}")
        else:
            out("warn", "  Could not crack this hash with available methods.")

    def _analyze(self, arg: str) -> None:
        if not arg: out("warn","No password specified."); return
        r = self.orc.analyze_pass(arg)
        print(f"\n  {C.G}Password Analysis{C.W}\n  {'─'*40}")
        print(f"  Password:  {C.Y}{r['password']}{C.W}")
        print(f"  Length:    {r['length']}")
        print(f"  Charsets:  {', '.join(r['charsets'])}")
        print(f"  Entropy:   {r['entropy']} bits")
        print(f"  Score:     {r['score']}/100 ({r['strength']})")
        if r["patterns"]:
            print(f"\n  {C.R}Patterns Detected:{C.W}")
            for p in r["patterns"]: print(f"    ⚠ {p}")
        print(f"\n  {C.G}Crack Time Estimates:{C.W}")
        for label, time_str in r["crack_times"].items():
            print(f"    {label:<30} {time_str}")

    def _sources(self) -> None:
        """
        --list-sources / REPL 'sources': debug/operator view.
        Shows every plugin with input_type, confidence, key status, and load errors.
        """
        # Ensure orchestrator and source orchestrator are initialised
        if self.orc._source_orchestrator is None:
            self.orc._source_orchestrator = SourceOrchestrator(
                asyncio.Semaphore(self.orc.config.concurrency), self.db, self.orc.config
            )

        # Scan sources dir directly to count total JSON files (including failed ones)
        json_files = list(SOURCE_DIR.glob("*.json"))
        total_files = len(json_files)

        # Track load failures by attempting to parse each file
        failed: List[str] = []
        for jf in json_files:
            try:
                json.loads(jf.read_text(encoding="utf-8"))
            except Exception as exc:
                failed.append(f"{jf.name}: {exc}")

        self.orc._source_orchestrator._ensure_loaded()
        all_sources = (
            self.orc._source_orchestrator._nox_sources
            + self.orc._source_orchestrator._fs_providers
            + self.orc._source_orchestrator._py_providers
        )
        loaded = len(all_sources)
        skipped = total_files - loaded  # files that parsed but produced no source (e.g. key missing)

        W = 62
        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.G}  PLUGIN DEBUG — LOADED SOURCES{C.X}")
        print(f"  {C.G}{'━'*W}{C.X}")
        print(f"\n  {C.W}Total JSON files in sources/:{C.X}  {total_files}")
        print(f"  {C.G}Loaded:{C.X}                       {loaded}")
        if skipped:
            print(f"  {C.Y}Skipped (key missing/invalid):{C.X} {skipped}")
        if failed:
            print(f"  {C.R}Parse errors:{C.X}                 {len(failed)}")
        print()

        if not all_sources:
            out("err", "No plugins loaded. Run: python build_sources.py")
            return

        # Column header
        print(f"  {C.DM}{'#':>3}  {'NAME':<28} {'INPUT':<10} {'CONF':>5}  {'KEY STATUS'}{C.X}")
        print(f"  {C.DM}{'─'*3}  {'─'*28} {'─'*10} {'─'*5}  {'─'*30}{C.X}")

        for i, src in enumerate(all_sources, 1):
            defn        = getattr(src, "_def", {}) or {}
            name        = src.name
            input_type  = defn.get("input_type", "any")
            conf        = defn.get("confidence", "")
            conf_str    = f"{conf:.2f}" if isinstance(conf, float) else (str(conf) if conf else "  —  ")

            # Key status
            slots       = defn.get("api_key_slots", [])
            key_name    = (defn.get("required_api_key_name", "")
                           or (slots[0].strip("{}") if slots else ""))
            needs_key   = getattr(src, "needs_key", bool(key_name))

            if not needs_key:
                key_col = f"{C.G}public (no key){C.X}"
            else:
                api_key = getattr(src, "_api_key", "") or ""
                if api_key:
                    masked  = f"****{api_key[-4:]}" if len(api_key) >= 4 else "****"
                    key_col = f"{C.G}configured ({masked}){C.X}"
                else:
                    key_col = f"{C.R}NOT configured  [{key_name}]{C.X}"

            # Colour name by key status
            name_col = (C.G if (not needs_key or api_key) else C.Y) + f"{name:<28}" + C.X
            print(f"  {C.DM}{i:>3}.{C.X}  {name_col} {C.DM}{input_type:<10}{C.X} {C.CY}{conf_str:>5}{C.X}  {key_col}")

        # Parse errors detail
        if failed:
            print(f"\n  {C.R}Parse errors:{C.X}")
            for err in failed:
                print(f"    {C.R}✗{C.X} {err}")

        print(f"\n  {C.DM}Tip: set keys directly in ~/.config/nox-cli/apikeys.json (chmod 0600).{C.X}")
        print(f"  {C.G}{'━'*W}{C.X}\n")

    def _export(self, arg: str) -> None:
        if not self._last and self._last_full:
            self._last = self._last_full.get("records", [])
        # Allow export even with no breach records if dork/scrape results exist
        full = self._last_full or {}
        has_dork   = bool(full.get("dork_results"))
        has_scrape = bool(full.get("scrape_results"))
        if not self._last and not has_dork and not has_scrape:
            out("warn", "  No results to export. Run a scan, dork, or scrape first."); return
        parts = arg.split() if arg else []
        fmt = None
        remaining = []
        i = 0
        while i < len(parts):
            if parts[i] == "--format" and i + 1 < len(parts):
                fmt = parts[i + 1]; i += 2
            elif parts[i].startswith("--format="):
                fmt = parts[i].split("=", 1)[1]; i += 1
            else:
                remaining.append(parts[i]); i += 1
        _known = {"json", "csv", "html", "md", "pdf"}
        if fmt is None and remaining and remaining[0].lower() in _known:
            fmt = remaining.pop(0)
        fmt  = (fmt or "html").lower()
        path = remaining[0] if remaining else f"nox_report_{int(time.time())}.{fmt}"
        data = full if isinstance(full, dict) and ("records" in full or has_dork or has_scrape) \
               else {"target": "unknown", "records": self._last}
        # Ensure records key always present
        if "records" not in data:
            data = dict(data); data["records"] = self._last
        inv  = self.session_state.get("investigator_id", "NOX-AUTO")
        if fmt == "json":   Reporter.to_json(data, path)
        elif fmt == "csv":
            resolved = Reporter._resolve_path(path, "csv")
            Reporter.to_csv(self._last, resolved)
            # G4: derive base from the resolved (absolute) path so companion files
            # land in REPORT_DIR, not the current working directory
            self._export_csv_extras(data, resolved)
        elif fmt == "html": Reporter.to_html(data, path)
        elif fmt == "md":   Reporter.to_markdown(data, path)
        elif fmt == "pdf":  Reporter.to_pdf(data, path, investigator_id=inv)
        else: out("warn", f"  Unknown format: {fmt}. Use json/csv/html/md/pdf")

    @staticmethod
    def _export_csv_extras(data: dict, base_path: str) -> None:
        """Write dork and scrape results as companion CSV files alongside the main breach CSV."""
        import csv as _csv
        base = base_path.rsplit(".", 1)[0]

        dork_results = data.get("dork_results", []) or []
        if dork_results:
            dork_path = f"{base}_dorks.csv"
            with open(dork_path, "w", newline="", encoding="utf-8") as f:
                w = _csv.DictWriter(f, fieldnames=["url", "title", "snippet", "dork", "engine"], extrasaction="ignore")
                w.writeheader()
                w.writerows(dork_results)
            out("ok", f"Dork results CSV saved: {dork_path}")

        scrape = data.get("scrape_results", {}) or {}
        pastes  = scrape.get("pastes", [])
        creds   = scrape.get("credentials", [])
        tg      = scrape.get("telegram", [])
        mc      = scrape.get("dork_misconfigs", [])

        if pastes:
            p_path = f"{base}_pastes.csv"
            with open(p_path, "w", newline="", encoding="utf-8") as f:
                w = _csv.DictWriter(f, fieldnames=["site", "id", "title", "query"], extrasaction="ignore")
                w.writeheader()
                w.writerows(pastes)
            out("ok", f"Pastes CSV saved: {p_path}")
        if creds:
            c_path = f"{base}_scraped_creds.csv"
            with open(c_path, "w", newline="", encoding="utf-8") as f:
                w = _csv.DictWriter(f, fieldnames=["raw", "source", "paste_id"], extrasaction="ignore")
                w.writeheader()
                w.writerows(creds)
            out("ok", f"Scraped credentials CSV saved: {c_path}")
        if tg:
            t_path = f"{base}_telegram.csv"
            with open(t_path, "w", newline="", encoding="utf-8") as f:
                w = _csv.DictWriter(f, fieldnames=["channel", "text"], extrasaction="ignore")
                w.writeheader()
                w.writerows(tg)
            out("ok", f"Telegram hits CSV saved: {t_path}")
        if mc:
            m_path = f"{base}_misconfigs.csv"
            with open(m_path, "w", newline="", encoding="utf-8") as f:
                w = _csv.DictWriter(f, fieldnames=["url", "title", "dork"], extrasaction="ignore")
                w.writeheader()
                w.writerows(mc)
            out("ok", f"Misconfigurations CSV saved: {m_path}")

        discovered_assets = data.get("discovered_assets", []) or []
        if discovered_assets:
            da_path = f"{base}_discovered_assets.csv"
            with open(da_path, "w", newline="", encoding="utf-8") as f:
                w = _csv.DictWriter(f, fieldnames=["asset", "qtype", "phase", "ref", "parent", "depth"], extrasaction="ignore")
                w.writeheader()
                w.writerows(discovered_assets)
            out("ok", f"Discovered assets CSV saved: {da_path}")

    def _config(self, arg: str) -> None:
        parts = arg.split(None, 1) if arg else []
        if len(parts) < 2:
            out("info", "  Config: threads, timeout, tor, proxy")
            out("dim",  "  Usage: config <key> <value>"); return
        k, v = parts
        try:
            if k == "threads":   self.config.max_threads = self.config.concurrency = int(v)
            elif k == "timeout": self.config.timeout = int(v)
            elif k == "tor":
                self.config.use_tor = v.lower() in ("true","1","yes","on")
                if self.config.use_tor: self.config.proxy = f"socks5h://127.0.0.1:{self.config.tor_socks}"
                self._refresh_session()
            elif k == "proxy":
                self.config.proxy = v if v != "none" else None
                self._refresh_session()
            else:
                out("warn", f"  Unknown config key: {k}"); return
        except ValueError:
            out("err", f"  Invalid value for {k}: {v!r}"); return
        out("ok", f"  {k} = {v}")

    def _tor(self) -> None:
        self.config.use_tor = not self.config.use_tor
        status = "ENABLED" if self.config.use_tor else "DISABLED"
        out("ok" if self.config.use_tor else "warn", f"  Tor routing: {status}")
        if self.config.use_tor:
            self.config.proxy = f"socks5h://127.0.0.1:{self.config.tor_socks}"
        else:
            self.config.proxy = None
        self._refresh_session()

    def _proxy(self, arg: str) -> None:
        if not arg:
            out("info", f"  Current proxy: {self.config.proxy or 'None'}")
            out("dim",  "  Usage: proxy <url> | proxy none"); return
        self.config.proxy = None if arg.lower() == "none" else arg
        out("ok", f"  Proxy {'disabled' if not self.config.proxy else f'set: {arg}'}")
        self._refresh_session()

    def _refresh_session(self) -> None:
        self.orc.session                  = Session(self.config)
        self.orc.dork_engine.s            = self.orc.session
        self.orc.scrape_engine.s          = self.orc.session
        self.orc.hash_engine._session     = self.orc.session
        # G2: also rebuild dorking_engine so it picks up the new proxy/Tor config
        self.orc.dorking_engine = DorkingEngine(self.config.concurrency, self.orc.db, self.config)

    # ── Investigation Dashboard ────────────────────────────────────────────

    @staticmethod
    def _risk_badge(analysis: dict) -> str:
        rs = analysis.get("risk_score", 0) if analysis else 0
        sev = analysis.get("severity", {}) if analysis else {}
        if rs > 60 or sev.get("critical", 0) > 0:
            return f"{C.R}[CRITICAL]{C.W}"
        if rs > 30 or sev.get("high", 0) > 0:
            return f"{C.Y}[HIGH]{C.W}"
        return f"{C.G}[MEDIUM]{C.W}"

    def _graph(self) -> None:
        """Mini forensic report — printed after autoscan or on demand."""
        if not self._last and self._last_full:
            self._last = self._last_full.get("records", [])
        full = self._last_full or {}
        if not full.get("target"):
            out("warn", "No results loaded. Run a scan, dork, or scrape first."); return
        if self._last is None:
            self._last = []

        full     = self._last_full or {}
        target   = full.get("target", "unknown")
        analysis = full.get("analysis") or {}
        badge    = self._risk_badge(analysis)
        W        = 62

        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.G}  NOX INTELLIGENCE REPORT{C.X}  {badge}")
        print(f"  {C.G}{'━'*W}{C.X}")
        ts = full.get("timestamp") or ""
        print(f"  Target   : {C.BD}{target}{C.X}")
        if ts:
            print(f"  Timestamp: {C.DM}{ts}{C.X}")

        rs  = analysis.get("risk_score", 0)
        sev = analysis.get("severity", {})
        col = C.R if rs > 60 else C.Y if rs > 30 else C.G
        print(f"\n  {C.Y}[ EXECUTIVE SUMMARY ]{C.X}")

        scan_meta   = full.get("scan_meta", {}) or {}
        pivot_depth = scan_meta.get("pivot_depth", 0)
        nodes       = scan_meta.get("nodes_discovered", 0)
        elapsed     = scan_meta.get("elapsed_seconds")
        dork_count  = len(full.get("dork_results", []) or [])
        scrape_r    = full.get("scrape_results", {}) or {}
        paste_cnt   = len(scrape_r.get("pastes", []))
        cred_sc_cnt = len(scrape_r.get("credentials", []))
        tg_cnt      = len(scrape_r.get("telegram", []))
        mc_cnt      = len(scrape_r.get("dork_misconfigs", []))

        print(f"  Records          : {analysis.get('total_records', len(self._last or []))}"
              f"  {C.DM}({analysis.get('unique_records',0)} unique){C.X}")
        print(f"  Unique Emails    : {analysis.get('unique_emails', 0)}")
        print(f"  Passwords Found  : {C.R}{analysis.get('passwords_found', 0)}{C.X}")
        print(f"  Stealer Logs     : {C.R}{analysis.get('stealer_logs', 0)}{C.X}")
        print(f"  HVT Accounts     : {C.O}{analysis.get('hvt_count', 0)}{C.X}")
        if dork_count:  print(f"  Dork Hits        : {C.O}{dork_count}{C.X}")
        if paste_cnt:   print(f"  Pastes           : {C.P}{paste_cnt}{C.X}")
        if cred_sc_cnt: print(f"  Scraped Creds    : {C.R}{cred_sc_cnt}{C.X}")
        if tg_cnt:      print(f"  Telegram Hits    : {C.CY}{tg_cnt}{C.X}")
        if mc_cnt:      print(f"  Misconfigs       : {C.O}{mc_cnt}{C.X}")
        if nodes:       print(f"  Nodes Discovered : {nodes}")
        if pivot_depth: print(f"  Pivot Depth      : {pivot_depth}")
        if elapsed is not None:     print(f"  Scan Duration    : {elapsed:.1f}s")
        da_cnt = len(full.get("discovered_assets", []) or [])
        if da_cnt:      print(f"  Reinjected Assets: {C.CY}{da_cnt}{C.X}")
        print(f"  Risk Score       : {col}{rs}/100{C.X}")
        print(f"  Severity         : {C.R}{sev.get('critical',0)} CRIT{C.X}  "
              f"{C.Y}{sev.get('high',0)} HIGH{C.X}  {sev.get('medium',0)} MED")

        # Pivot chain — prefer the one from the fullscan result (avalanche order)
        pivot_log = full.get("pivot_log", [])
        chain = full.get("pivot_chain") or self.session_state.get("pivot_chain", [])

        if pivot_log:
            print(f"\n  {C.Y}[ PIVOT TREE ({len(pivot_log)} nodes) ]{C.X}")
            self._print_pivot_tree(pivot_log, full)
            # Show discovered assets after pivot tree
            discovered_assets = full.get("discovered_assets", []) or []
            if discovered_assets:
                _phase_col = {"breach": C.R, "dork": C.O, "scrape": C.P,
                              "hash_crack": C.P, "seed": C.G}
                print(f"\n  {C.Y}[ DISCOVERED ASSETS ({len(discovered_assets)} new identifiers) ]{C.X}")
                print(f"  {C.DM}  {'ASSET':<38} {'TYPE':<10} {'PHASE':<10} REFERENCE{C.X}")
                for da in discovered_assets[:30]:
                    pc  = _phase_col.get(da["phase"], C.DM)
                    ref = da.get("ref", "")[:55]
                    print(f"  {C.CY}  {da['asset']:<38}{C.X} {C.DM}{da['qtype']:<10}{C.X} "
                          f"{pc}{da['phase']:<10}{C.X} {C.DM}{ref}{C.X}")
                if len(discovered_assets) > 30:
                    print(f"  {C.DM}  … and {len(discovered_assets)-30} more — use 'export'{C.X}")
        else:
            # No pivot log — flat display
            if len(chain) > 1:
                print(f"\n  {C.Y}[ PIVOT CHAIN ({len(chain)} nodes) ]{C.X}")
                for i, node in enumerate(chain[:20]):
                    pfx = "  " if i == 0 else "  ↳ "
                    print(f"  {C.DM}{pfx}{C.X}{C.CY}{node}{C.X}")
                if len(chain) > 20:
                    print(f"  {C.DM}  … and {len(chain)-20} more nodes{C.X}")

            hvt = full.get("hvt_records", [])
            if hvt:
                print(f"\n  {C.Y}[ HIGH-VALUE TARGETS ]{C.X}")
                for r in hvt[:8]:
                    ident = _rec_get(r, "email") or _rec_get(r, "username") or "—"
                    rs_r  = _rec_get(r, "risk_score") or ""
                    rs_tag = f"  {C.Y}risk:{rs_r}{C.X}" if rs_r else ""
                    print(f"  {C.R}⚑{C.X} {ident}{rs_tag}")

            creds = [(r, _rec_get(r, "password")) for r in self._last if _rec_get(r, "password")]
            other_assets = [r for r in self._last if not _rec_get(r, "password") and
                            (_rec_get(r, "email") or _rec_get(r, "username") or
                             _rec_get(r, "ip_address") or _rec_get(r, "phone"))]
            if creds:
                print(f"\n  {C.Y}[ EXPOSED CREDENTIALS ]{C.X}")
                for r, pw in creds[:10]:
                    em  = _rec_get(r, "email") or _rec_get(r, "username") or "—"
                    src = _rec_get(r, "source") or ""
                    masked = pw[:2] + "●" * min(len(pw) - 2, 8) if len(pw) > 2 else "●●●●"
                    print(f"  {C.R}→{C.X} {C.CY}{em}{C.X}  {C.R}{masked}{C.X}  {C.DM}[{src}]{C.X}")
                    extra = REPL._record_assets(r)
                    if extra: print(f"      {extra}")
                if len(creds) > 10:
                    print(f"  {C.DM}  … and {len(creds)-10} more — use 'export'{C.X}")
            if other_assets:
                print(f"\n  {C.Y}[ DISCOVERED ASSETS ({len(other_assets)}) ]{C.X}")
                for r in other_assets[:15]:
                    ident = _rec_get(r, "email") or _rec_get(r, "username") or "—"
                    src   = _rec_get(r, "source") or ""
                    print(f"  {C.Y}→{C.X} {C.CY}{ident}{C.X}  {C.DM}← {src}{C.X}")
                    extra = REPL._record_assets(r)
                    if extra: print(f"      {extra}")
                if len(other_assets) > 15:
                    print(f"  {C.DM}  … and {len(other_assets)-15} more — use 'export'{C.X}")

            reused = analysis.get("reused_passwords", {})
            if reused:
                print(f"\n  {C.Y}[ PASSWORD REUSE ]{C.X}")
                for pw, cnt in list(reused.items())[:5]:
                    masked = pw[:2] + "●" * (len(pw) - 2) if len(pw) > 2 else "●●●●"
                    print(f"  {C.R}⚠{C.X}  {masked}  → reused {cnt}× across breaches")

            dorks = full.get("dork_results", [])
            if dorks:
                print(f"\n  {C.Y}[ DORK FINDINGS ({len(dorks)}) ]{C.X}")
                for d in dorks[:5]:
                    url = d.get("url", "") or d.get("title", "")
                    dork_q = d.get("dork", "")[:50]
                    print(f"  {C.Y}→{C.X} {C.DM}{url[:70]}{C.X}")
                    if dork_q: print(f"    {C.DM}dork: {dork_q}{C.X}")
                if len(dorks) > 5:
                    print(f"  {C.DM}  … and {len(dorks)-5} more — use 'export'{C.X}")

            scrape        = full.get("scrape_results", {}) or {}
            scraped_creds = scrape.get("credentials", [])
            tg            = scrape.get("telegram", [])
            misconfigs    = scrape.get("dork_misconfigs", [])
            pastes        = scrape.get("pastes", [])
            if scraped_creds or tg or misconfigs or pastes:
                print(f"\n  {C.Y}[ SCRAPE FINDINGS ]{C.X}")
                if pastes:
                    print(f"  Pastes       : {C.P}{len(pastes)}{C.X}")
                    for p in pastes[:3]:
                        print(f"    {C.P}→{C.X} [{p.get('site','')}] {p.get('id','')[:30]}")
                if scraped_creds:
                    print(f"  Credentials  : {C.R}{len(scraped_creds)}{C.X}")
                    for c in scraped_creds[:5]:
                        print(f"    {C.R}→{C.X} {c.get('raw','')[:70]}")
                if tg:
                    print(f"  Telegram     : {C.CY}{len(tg)}{C.X}")
                    for t in tg[:3]:
                        print(f"    {C.CY}→{C.X} [{t.get('channel','')}] {t.get('text','')[:60]}")
                if misconfigs:
                    print(f"  Misconfigs   : {C.O}{len(misconfigs)}{C.X}")
                    for m in misconfigs[:3]:
                        print(f"    {C.O}→{C.X} {m.get('title','')[:60]}")

        # ── Discovered Assets (flat provenance) ───────────────────────
        discovered_assets = full.get("discovered_assets", []) or []
        if discovered_assets:
            _phase_col = {"breach": C.R, "dork": C.O, "scrape": C.P,
                          "hash_crack": C.P, "seed": C.G}
            print(f"\n  {C.Y}[ DISCOVERED ASSETS ({len(discovered_assets)} new identifiers) ]{C.X}")
            print(f"  {C.DM}  {'ASSET':<38} {'TYPE':<10} {'PHASE':<10} REFERENCE{C.X}")
            for da in discovered_assets[:30]:
                pc  = _phase_col.get(da["phase"], C.DM)
                ref = da.get("ref", "")[:55]
                print(f"  {C.CY}  {da['asset']:<38}{C.X} {C.DM}{da['qtype']:<10}{C.X} "
                      f"{pc}{da['phase']:<10}{C.X} {C.DM}{ref}{C.X}")
            if len(discovered_assets) > 30:
                print(f"  {C.DM}  … and {len(discovered_assets)-30} more — use 'export'{C.X}")

        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.DM}Use 'export pdf/html/json' for the full forensic report.{C.X}\n")

    def _pivot(self, arg: str) -> None:
        if not self._last:
            out("warn", "No results loaded. Run a scan first."); return
        if not arg or not arg.strip().isdigit():
            out("warn", "Usage: pivot <index>  (see [pivot N] hints in graph output)"); return
        idx = int(arg.strip()) - 1
        if not (0 <= idx < len(self._last)):
            out("warn", f"Index out of range. Valid: 1–{len(self._last)}"); return
        r    = self._last[idx]
        seed = (_rec_get(r, "email") or _rec_get(r, "username") or
                _rec_get(r, "phone") or _rec_get(r, "domain") or "")
        if not seed:
            out("warn", "Selected record has no pivotable identifier."); return
        out("pivot", f"Pivoting → async fullscan on: {C.CY}{seed}{C.X}")
        self._fullscan(seed)

    def _visualize(self) -> None:
        """
        ASCII Relationship Map: Target → Linked Data → Pivot Points.
        Shows the full investigation session chain and cross-links.
        """
        full_data = self._last_full or {}
        if not self._last and self._last_full:
            self._last = self._last_full.get("records", [])
        if not full_data.get("target"):
            out("warn", "No results loaded. Run a scan, dork, or scrape first."); return
        if self._last is None:
            self._last = []

        target  = (self._last_full or {}).get("target", "unknown")
        chain   = self.session_state.get("pivot_chain", [])
        scanned = self.session_state.get("targets_scanned", [])

        # Collect linked data
        emails, phones, usernames, addresses, passwords = (
            set(), set(), set(), set(), set()
        )
        source_map: Dict[str, str] = {}  # value → source name
        for r in self._last:
            for attr, bucket in [("email", emails), ("phone", phones),
                                  ("username", usernames), ("password", passwords)]:
                v = _rec_get(r, attr)
                if v:
                    bucket.add(v)
                    source_map[v] = _rec_get(r, "source") or ""
            addr = getattr(r, "address", "") or ""
            if addr:
                addresses.add(addr)

        W = 70
        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.G}  INVESTIGATION RELATIONSHIP MAP{C.X}  "
              f"[{self.session_state.get('investigator_id','NOX-AUTO')}]")
        print(f"  {C.G}{'━'*W}{C.X}\n")

        # Session pivot chain
        if len(chain) > 1:
            print(f"  {C.Y}Pivot Chain:{C.X}")
            for i, t in enumerate(chain):
                arrow = "  " if i == 0 else "  ↳ "
                print(f"  {C.DM}{arrow}{C.X}{C.CY}{t}{C.X}")
            print()

        # Central target node
        print(f"  {C.G}◉{C.X} {C.BD}{target}{C.X}")

        # Linked data branches
        groups = [
            ("Emails",     sorted(emails)[:8],     C.CY),
            ("Phones",     sorted(phones)[:6],      C.CY),
            ("Usernames",  sorted(usernames)[:6],   C.G),
            ("Addresses",  sorted(addresses)[:4],   C.Y),
            ("Passwords",  sorted(passwords)[:5],   C.R),
        ]
        active_groups = [(lbl, vals, col) for lbl, vals, col in groups if vals]

        for gi, (label, values, color) in enumerate(active_groups):
            is_last_group = (gi == len(active_groups) - 1)
            grp_pfx  = "  └─" if is_last_group else "  ├─"
            cont_pfx = "     " if is_last_group else "  │  "
            print(f"  {C.DM}{grp_pfx}{C.X} {C.P}[{label}]{C.X}")
            for vi, v in enumerate(values):
                is_last_val = (vi == len(values) - 1)
                val_pfx = f"{cont_pfx}  └─" if is_last_val else f"{cont_pfx}  ├─"
                src_tag = f" {C.DM}← {source_map.get(v,'')[:20]}{C.X}" if source_map.get(v) else ""
                # Mark as pivot point if it appears in scanned targets
                pivot_tag = f" {C.Y}[PIVOT]{C.X}" if v in scanned else ""
                print(f"  {C.DM}{val_pfx}{C.X} {color}{v}{C.X}{src_tag}{pivot_tag}")

        # ── Dork results branch ───────────────────────────────────────
        full_data    = self._last_full or {}
        dork_results = full_data.get("dork_results", []) or []
        if dork_results:
            print(f"\n  {C.Y}◈ Dork Findings ({len(dork_results)}){C.X}")
            for d in dork_results[:8]:
                title = d.get("title","") or d.get("dork","")
                url   = d.get("url","")
                print(f"  {C.DM}  ├─{C.X} {C.O}{title[:60]}{C.X}")
                if url:
                    print(f"  {C.DM}  │   {url[:70]}{C.X}")
            if len(dork_results) > 8:
                print(f"  {C.DM}  └─ … and {len(dork_results)-8} more{C.X}")

        # ── Scrape results branch ─────────────────────────────────────
        scrape_results = full_data.get("scrape_results", {}) or {}
        pastes   = scrape_results.get("pastes", [])
        creds_sc = scrape_results.get("credentials", [])
        tg_hits  = scrape_results.get("telegram", [])
        mc_hits  = scrape_results.get("dork_misconfigs", [])
        if pastes or creds_sc or tg_hits or mc_hits:
            total_scrape = len(pastes) + len(creds_sc) + len(tg_hits) + len(mc_hits)
            print(f"\n  {C.P}◈ Scrape Findings ({total_scrape}){C.X}")
            if pastes:
                print(f"  {C.DM}  ├─{C.X} {C.P}[Pastes: {len(pastes)}]{C.X}")
                for p in pastes[:3]:
                    print(f"  {C.DM}  │   ├─{C.X} [{p.get('site','')}] {p.get('id','')[:40]}")
                if len(pastes) > 3:
                    print(f"  {C.DM}  │   └─ … and {len(pastes)-3} more{C.X}")
            if creds_sc:
                print(f"  {C.DM}  ├─{C.X} {C.R}[Credentials: {len(creds_sc)}]{C.X}")
                for c in creds_sc[:3]:
                    print(f"  {C.DM}  │   ├─{C.X} {C.R}{c.get('raw','')[:60]}{C.X}")
                if len(creds_sc) > 3:
                    print(f"  {C.DM}  │   └─ … and {len(creds_sc)-3} more{C.X}")
            if tg_hits:
                print(f"  {C.DM}  ├─{C.X} {C.CY}[Telegram: {len(tg_hits)}]{C.X}")
                for t in tg_hits[:3]:
                    print(f"  {C.DM}  │   ├─{C.X} {C.CY}[{t.get('channel','')}]{C.X} {t.get('text','')[:50]}")
                if len(tg_hits) > 3:
                    print(f"  {C.DM}  │   └─ … and {len(tg_hits)-3} more{C.X}")
            if mc_hits:
                print(f"  {C.DM}  └─{C.X} {C.O}[Misconfigs: {len(mc_hits)}]{C.X}")
                for m in mc_hits[:3]:
                    print(f"  {C.DM}      ├─{C.X} {C.O}{m.get('title','')[:60]}{C.X}")
                if len(mc_hits) > 3:
                    print(f"  {C.DM}      └─ … and {len(mc_hits)-3} more{C.X}")

        # ── Discovered / reinjected assets branch ────────────────────
        discovered_assets = full_data.get("discovered_assets", []) or []
        if discovered_assets:
            _phase_col = {"breach": C.R, "dork": C.O, "scrape": C.P, "hash_crack": C.P}
            print(f"\n  {C.B}◈ Reinjected Assets ({len(discovered_assets)}){C.X}")
            for da in discovered_assets[:12]:
                pc  = _phase_col.get(da["phase"], C.DM)
                ref = da.get("ref", "")[:50]
                print(f"  {C.DM}  ├─{C.X} {pc}[{da['phase']}]{C.X} "
                      f"{C.CY}{da['asset']}{C.X}  {C.DM}({da['qtype']})  ← {ref}{C.X}")
            if len(discovered_assets) > 12:
                print(f"  {C.DM}  └─ … and {len(discovered_assets)-12} more — use 'export'{C.X}")

        print(f"\n  {C.G}{'━'*W}{C.X}")
        print(f"  {C.DM}Targets scanned: {len(scanned)} | "
              f"Records: {len(self._last or [])} | "
              f"Tip: 'export --format pdf' for forensic report{C.X}\n")

    def _search(self, query: str) -> None:
        if not query:
            out("warn", "Usage: search <keyword>"); return
        if not self._last:
            out("warn", "No results in memory. Run a scan first."); return
        q = query.lower()
        hits = [r for r in self._last
                if q in str(_rec_get(r, "email") or "").lower()
                or q in str(_rec_get(r, "username") or "").lower()
                or q in str(_rec_get(r, "password") or "").lower()
                or q in str(_rec_get(r, "domain") or "").lower()
                or q in str(_rec_get(r, "source") or "").lower()]
        if not hits:
            out("warn", f"No records match '{query}'."); return
        out("ok", f"  {len(hits)} match(es) for '{query}':\n")
        for i, r in enumerate(hits[:30], 1):
            em  = _rec_get(r, "email") or _rec_get(r, "username") or "—"
            pw  = _rec_get(r, "password")
            ph  = _rec_get(r, "phone")
            src = _rec_get(r, "source") or ""
            line = f"  {C.DM}{i:3}.{C.W} {C.CY}{em}{C.W}"
            if pw:  line += f"  {C.R}pw:{pw}{C.W}"
            if ph:  line += f"  {C.CY}☎ {ph}{C.W}"
            if src: line += f"  {C.DM}[{src}]{C.W}"
            print(line)
        print()

    @staticmethod
    def _record_assets(r: Any) -> str:
        """Return a compact string of every non-empty asset field in a record."""
        parts = []
        for label, key in [("ip", "ip_address"), ("phone", "phone"),
                            ("domain", "domain"), ("name", "full_name"),
                            ("addr", "address")]:
            v = _rec_get(r, key)
            if v: parts.append(f"{C.DM}{label}:{C.X}{v}")
        ph = _rec_get(r, "password_hash")
        ht = _rec_get(r, "hash_type")
        if ph and not _rec_get(r, "password"):
            parts.append(f"{C.DM}hash[{ht or '?'}]:{C.X}{ph[:20]}…")
        dt = _rec_get(r, "data_types") or []
        if isinstance(dt, list) and dt:
            parts.append(f"{C.DM}[{', '.join(dt[:3])}]{C.X}")
        return "  ".join(parts)

    def _print_summary(self, a: dict) -> None:
        if not a: return
        badge = self._risk_badge(a)
        print(f"\n  {C.G}{'═'*55}{C.W}")
        print(f"  {C.G}CTI RESULTS SUMMARY{C.W}  {badge}")
        print(f"  {C.G}{'═'*55}{C.W}")
        print(f"  Total Records:          {a.get('total_records',0)}")
        print(f"  Unique (deduped):       {a.get('unique_records',a.get('total_records',0))}")
        print(f"  Unique Emails:          {a.get('unique_emails',0)}")
        print(f"  Passwords Found:        {C.R}{a.get('passwords_found',0)}{C.W}")
        print(f"  Stealer Logs:           {C.R}{a.get('stealer_logs',0)}{C.W}")
        print(f"  High-Value Targets:     {C.O}{a.get('hvt_count',0)}{C.W}")
        print(f"  Password Reuse:         {len(a.get('reused_passwords',{}))}")
        print(f"  Avg Persistence Score:  {a.get('avg_persistence',0.0)}")
        # Show dork/scrape counts if available (autoscan)
        full = self._last_full or {}
        dork_count = len(full.get("dork_results", []) or [])
        scrape     = full.get("scrape_results", {}) or {}
        paste_count = len(scrape.get("pastes", []))
        cred_count  = len(scrape.get("credentials", []))
        tg_count    = len(scrape.get("telegram", []))
        mc_count    = len(scrape.get("dork_misconfigs", []))
        if dork_count:
            print(f"  Dork Hits:              {C.O}{dork_count}{C.W}")
        if paste_count or cred_count or tg_count or mc_count:
            print(f"  Scraped Pastes:         {C.P}{paste_count}{C.W}")
            if cred_count: print(f"  Scraped Credentials:    {C.R}{cred_count}{C.W}")
            if tg_count:   print(f"  Telegram Hits:          {C.CY}{tg_count}{C.W}")
            if mc_count:   print(f"  Misconfigurations:      {C.O}{mc_count}{C.W}")
        rs  = a.get("risk_score",0)
        col = C.R if rs > 60 else C.Y if rs > 30 else C.G
        print(f"  Risk Score:             {col}{rs}/100{C.W}")
        sev = a.get("severity",{})
        print(f"\n  Severity: {C.R}■ {sev.get('critical',0)} CRITICAL{C.W}  {C.Y}■ {sev.get('high',0)} HIGH{C.W}  ■ {sev.get('medium',0)} MEDIUM")
        profiles = a.get("profiles",[])
        if profiles:
            max_stuffing = max((p.get("stuffing_risk","LOW") for p in profiles), key=lambda x: {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}.get(x,0), default="LOW")
            col = C.R if max_stuffing=="CRITICAL" else C.Y if max_stuffing in ("HIGH","MEDIUM") else C.G
            print(f"  Credential Stuffing:    {col}{max_stuffing}{C.W}")
        reused = a.get("reused_passwords",{})
        if reused:
            print(f"\n  {C.R}Password Reuse Detected:{C.W}")
            for pw, cnt in list(reused.items())[:5]:
                masked = pw[:2]+"*"*(len(pw)-2) if len(pw)>4 else "****"
                print(f"    {masked} → used {cnt}x across breaches")


# =======================================================================
# 1. API & SECRETS MANAGEMENT
# =======================================================================
import configparser as _configparser


class ConfigManager:
    """
    Unified API key manager — delegates to sources/helpers/config_handler.py
    (XDG JSON store at ~/.config/nox-cli/apikeys.json) when available,
    with a legacy config.ini fallback.

    Resolution order: env-var → apikeys.json → config.ini → ''
    """

    _cache: Dict[str, str] = {}
    _INI_PATHS = [HOME_NOX / "config.ini", Path("/etc/nox/config.ini")]
    # B4: track apikeys.json mtime to detect external edits
    _store_mtime: float = 0.0

    @classmethod
    def _invalidate_if_changed(cls) -> None:
        """B4: clear cache if apikeys.json was modified externally."""
        if not _HAS_CONFIG_HANDLER or _ExtConfigManager is None:
            return
        try:
            from sources.helpers.config_handler import _APIKEYS_FILE  # type: ignore
            if _APIKEYS_FILE and _APIKEYS_FILE.exists():
                mtime = _APIKEYS_FILE.stat().st_mtime
                if mtime != cls._store_mtime:
                    cls._cache.clear()
                    cls._store_mtime = mtime
                    if _ExtConfigManager._store is not None:
                        _ExtConfigManager._store = None
                        _ExtConfigManager._cache.clear()
        except Exception:
            pass

    @classmethod
    def get(cls, key_name: str) -> str:
        cls._invalidate_if_changed()
        if key_name in cls._cache:
            return cls._cache[key_name]
        # 1. Delegate to external handler (XDG JSON store)
        if _HAS_CONFIG_HANDLER and _ExtConfigManager is not None:
            val = _ExtConfigManager.get(key_name)
            if val:
                cls._cache[key_name] = val
                return val
        # 2. Environment variable
        val = os.environ.get(key_name) or os.environ.get(f"NOX_{key_name}", "")
        # 3. Legacy config.ini
        if not val:
            for p in cls._INI_PATHS:
                if p.exists():
                    cfg = _configparser.ConfigParser()
                    cfg.read(str(p))
                    val = cfg.get("api_keys", key_name, fallback="")
                    if val:
                        break
        if val == UNIVERSAL_PLACEHOLDER:
            val = ""
        cls._cache[key_name] = val
        return val

    @classmethod
    def write(cls, key_name: str, value: str) -> None:
        """Persist a key — prefers the XDG JSON store, falls back to config.ini."""
        if _HAS_CONFIG_HANDLER and _ExtConfigManager is not None:
            _ExtConfigManager.set(key_name, value)
            cls._cache[key_name] = value
            return
        # Legacy: write to config.ini
        _write_path = HOME_NOX / "config.ini"
        _write_path.parent.mkdir(parents=True, exist_ok=True)
        cfg = _configparser.ConfigParser()
        if _write_path.exists():
            cfg.read(str(_write_path))
        if "api_keys" not in cfg:
            cfg["api_keys"] = {}
        cfg["api_keys"][key_name] = value
        with open(_write_path, "w") as fh:
            cfg.write(fh)
        cls._cache[key_name] = value


# =======================================================================
# 2. EXTREME MODULARITY — JSON Source Engine
# =======================================================================

class JSONSourceLoader(AsyncSource):
    """
    Dynamically loads a custom breach source defined by a JSON file in
    ~/.nox/sources/.  Each file must contain:

        {
          "name":    "MySource",
          "url":     "https://api.example.com/search?q={query}",
          "method":  "GET",          // or "POST"
          "headers": {"X-Key": "{api_key}"},
          "payload": {},             // POST body template (optional)
          "api_key_env": "MY_API_KEY",  // env-var / config.ini key (optional)
          "extract": {
              "mode":     "json",    // "json" or "regex"
              "root":     "results", // JSON path to list (dot-separated)
              "email":    "email",
              "password": "password",
              "username": "username",
              "phone":    "phone",
              "hash":     "hash"
          }
        }

    For regex mode, each field value is a regex pattern with one capture group.
    """

    _SOURCES_DIR = SOURCE_DIR

    def __init__(self, semaphore: asyncio.Semaphore, db: "DB", config: "NoxConfig",
                 definition: dict) -> None:
        super().__init__(semaphore, db, config)
        self._def = definition
        self.name = definition.get("name", "JSONSource")
        env_key   = definition.get("api_key_env", "")
        self._api_key = ConfigManager.get(env_key) if env_key else ""
        self.needs_key = bool(env_key)
        self.ok_email = self.ok_user = self.ok_domain = self.ok_phone = True

    async def async_search(self, session, query: str, qtype: str) -> List[Record]:
        if self.needs_key and not self._api_key:
            logger.debug("JSONSourceLoader[%s]: API key missing, skipping.", self.name)
            return []
        try:
            return await self._fetch(session, query)
        except Exception as exc:
            logger.debug("JSONSourceLoader[%s]: %s", self.name, exc)
            return []

    async def _fetch(self, session, query: str) -> List[Record]:
        d       = self._def
        url     = d["url"].replace("{query}", urllib.parse.quote(query, safe="")).replace("{api_key}", self._api_key)
        headers = {k: v.replace("{api_key}", self._api_key) for k, v in d.get("headers", {}).items()}
        method  = d.get("method", "GET").upper()
        payload = {k: v.replace("{query}", query).replace("{api_key}", self._api_key)
                   for k, v in d.get("payload", {}).items()}

        if method == "POST":
            status, text, _ = await self._post(session, url, json_data=payload or None,
                                                data=payload if not payload else None,
                                                headers=headers)
        else:
            status, text, _ = await self._get(session, url, headers=headers)

        if status not in range(200, 300) or not text:
            return []

        ext = d.get("extract", {})
        mode = ext.get("mode", "json")
        if mode == "regex":
            return self._extract_regex(text, ext, query)
        return self._extract_json(text, ext, query)

    def _extract_json(self, text: str, ext: dict, query: str) -> List[Record]:
        try:
            data = json.loads(text)
        except Exception:
            return []
        # Navigate to root list
        root_path = ext.get("root", "")
        for key in (root_path.split(".") if root_path else []):
            if isinstance(data, dict):
                data = data.get(key, [])
        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []
        records = []
        for item in data[:100]:
            if not isinstance(item, dict):
                continue
            records.append(self._rec(
                email    = str(item.get(ext.get("email",    "email"),    "") or ""),
                password = str(item.get(ext.get("password", "password"), "") or ""),
                username = str(item.get(ext.get("username", "username"), "") or ""),
                phone    = str(item.get(ext.get("phone",    "phone"),    "") or ""),
                password_hash = str(item.get(ext.get("hash", "hash"),   "") or ""),
                breach_name = self.name,
                data_types  = [self.name, "Credentials"],
                raw_data    = item,
            ))
        return records

    def _extract_regex(self, text: str, ext: dict, query: str) -> List[Record]:
        field_patterns = {f: ext[f] for f in ("email","password","username","phone","hash") if f in ext}
        # Find all matches per field
        field_values: Dict[str, List[str]] = {}
        for fname, pattern in field_patterns.items():
            field_values[fname] = re.findall(pattern, text)
        # Zip into records (align by index)
        max_len = max((len(v) for v in field_values.values()), default=0)
        records = []
        for i in range(min(max_len, 100)):
            records.append(self._rec(
                email    = field_values.get("email",    [""])[i] if i < len(field_values.get("email",    [])) else "",
                password = field_values.get("password", [""])[i] if i < len(field_values.get("password", [])) else "",
                username = field_values.get("username", [""])[i] if i < len(field_values.get("username", [])) else "",
                phone    = field_values.get("phone",    [""])[i] if i < len(field_values.get("phone",    [])) else "",
                password_hash = field_values.get("hash", [""])[i] if i < len(field_values.get("hash",    [])) else "",
                breach_name = self.name,
                data_types  = [self.name, "Credentials"],
            ))
        return records

    @classmethod
    def load_all(cls, semaphore: asyncio.Semaphore, db: "DB", config: "NoxConfig") -> List["JSONSourceLoader"]:
        """Scan ~/.nox/sources/ and return one loader per valid .json file."""
        cls._SOURCES_DIR.mkdir(parents=True, exist_ok=True)
        loaders = []
        for jf in cls._SOURCES_DIR.glob("*.json"):
            try:
                definition = json.loads(jf.read_text(encoding="utf-8"))
                loaders.append(cls(semaphore, db, config, definition))
                logger.info("JSONSourceLoader: loaded %s", jf.name)
            except Exception as exc:
                logger.warning("JSONSourceLoader: failed to load %s — %s", jf.name, exc)
        return loaders


# =======================================================================
# 3. DeHashEngine & ReputationEngine
# =======================================================================

class DeHashEngine:
    """
    Queries MD5/SHA1 hashes found during scans against de-hashing APIs.
    Requires DEHASHED_API_KEY (email:api_key format) or DEHASH_API_KEY.
    Gracefully skips if key is absent.
    """

    def __init__(self, db: "DB", config: "NoxConfig") -> None:
        self._db     = db
        self._config = config
        self._key    = (ConfigManager.get("DEHASHED_API_KEY")
                        or ConfigManager.get("DEHASH_API_KEY")
                        or db.get_key("dehashed"))

    async def dehash_records(self, session, records: List[Record]) -> List[Record]:
        """Attempt to crack any unhashed passwords found in records."""
        if not self._key:
            return records
        hashes = {r.password_hash for r in records if r.password_hash and not r.password}
        if not hashes:
            return records
        sem = asyncio.Semaphore(5)
        tasks = [self._lookup(session, sem, h) for h in list(hashes)[:20]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        crack_map: Dict[str, str] = {}
        for res in results:
            if isinstance(res, tuple):
                crack_map[res[0]] = res[1]
        for r in records:
            if r.password_hash in crack_map:
                r.password = crack_map[r.password_hash]
                r.data_types = list(set(r.data_types + ["DeHashed"]))
        return records

    async def _lookup(self, session, sem: asyncio.Semaphore, h: str):
        cached = self._db.get_plain(h)
        if cached:
            return (h, cached)
        try:
            auth = base64.b64encode(self._key.encode()).decode() if ":" in self._key else self._key
            url  = f"https://api.dehashed.com/search?query=hashed_password:{h}&size=1"
            hdrs = {"Accept": "application/json", "Authorization": f"Basic {auth}"}
            async with sem:
                to = aiohttp_mod.ClientTimeout(total=self._config.timeout) if aiohttp_mod else None
                async with session.get(url, headers=hdrs, timeout=to, ssl=_SSL_CTX) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data.get("entries", []):
                            pw = entry.get("password", "")
                            if pw:
                                self._db.store_hash(h, "unknown", pw, "DeHashed")
                                return (h, pw)
        except Exception as exc:
            logger.debug("DeHashEngine._lookup %s: %s", h[:16], exc)
        return (h, "")


class ReputationEngine:
    """
    Checks IP/Domain targets via VirusTotal.
    Requires VIRUSTOTAL_API_KEY. Gracefully skips if absent.
    """

    _VT_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, config: "NoxConfig") -> None:
        self._config = config
        self._key    = (ConfigManager.get("VIRUSTOTAL_API_KEY")
                        or ConfigManager.get("VT_API_KEY"))

    async def check(self, session, target: str, qtype: str) -> Optional[dict]:
        """Return VirusTotal summary dict or None if key missing / not applicable."""
        if not self._key or qtype not in ("ip", "domain", "url"):
            return None
        try:
            if qtype == "ip":
                url = f"{self._VT_URL}/ip_addresses/{target}"
            elif qtype == "domain":
                url = f"{self._VT_URL}/domains/{target}"
            else:
                encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
                url = f"{self._VT_URL}/urls/{encoded}"
            hdrs = {"x-apikey": self._key}
            to   = aiohttp_mod.ClientTimeout(total=self._config.timeout) if aiohttp_mod else None
            async with session.get(url, headers=hdrs, timeout=to, ssl=_SSL_CTX) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = (data.get("data", {})
                                 .get("attributes", {})
                                 .get("last_analysis_stats", {}))
                    return {
                        "target":     target,
                        "malicious":  stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless":   stats.get("harmless", 0),
                        "source":     "VirusTotal",
                    }
        except Exception as exc:
            logger.debug("ReputationEngine.check %s: %s", target, exc)
        return None


# =======================================================================
# 4. PROFESSIONAL PDF REPORTING (fpdf2)
# =======================================================================

def _pdf_report(data: dict, path: str) -> None:
    """
    Generate a professional PDF report using fpdf2.
    Layout: Title Page → Executive Summary → Entities Table → Raw Evidence.
    Falls back gracefully if fpdf2 is not installed.
    """
    try:
        from fpdf import FPDF  # type: ignore
    except ImportError:
        out("warn", "fpdf2 not installed. Run: pip install fpdf2")
        return

    records = data.get("records", [])
    target  = data.get("target", "Unknown")
    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = AdvancedReporter._build_summary(records)

    class _PDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(100, 100, 100)
            self.cell(0, 6, f"NOX Framework v{VERSION}  |  CONFIDENTIAL", align="R")
            self.ln(4)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 6, f"Page {self.page_no()}", align="C")

    pdf = _PDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)

    # ── Title Page ────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(10, 10, 10)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_y(80)
    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(0, 255, 65)
    pdf.cell(0, 14, "NOX FRAMEWORK REPORT", align="C")
    pdf.ln(10)

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(200, 200, 200)
    pdf.cell(0, 8, f"Target: {target}", align="C")
    pdf.ln(7)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 7, f"Generated: {ts}", align="C")
    pdf.ln(5)
    pdf.cell(0, 7, "FOR AUTHORISED USE ONLY", align="C")

    # ── Executive Summary ─────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(0, 0, 0)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_draw_color(0, 200, 50)
    pdf.set_line_width(0.5)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(4)

    max_risk = max((float(_rec_get(r, "risk_score") or 0) for r in records), default=0.0)
    kpis = [
        ("Compromised Identities", summary["total_identities"]),
        ("Total Records",          summary["total_records"]),
        ("Stealer Logs",           summary["stealer_count"]),
        ("High-Value Targets",     summary["hvt_count"]),
        ("Max Risk Score",         f"{max_risk:.1f} / 100"),
    ]
    pdf.set_font("Helvetica", "B", 10)
    for label, value in kpis:
        pdf.set_fill_color(245, 245, 245)
        pdf.cell(90, 8, label, border=1, fill=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(85, 8, str(value), border=1, ln=True)
        pdf.set_font("Helvetica", "B", 10)
    pdf.ln(6)

    # Risk distribution
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Risk Distribution", ln=True)
    pdf.set_font("Helvetica", "B", 9)
    for col, w in [("Level", 40), ("Count", 30), ("Bar", 105)]:
        pdf.set_fill_color(30, 30, 30)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(w, 7, col, border=1, fill=True)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)
    total_b = max(sum(summary["buckets"].values()), 1)
    colours = {"Critical": (220,0,30), "High": (220,100,0), "Medium": (200,180,0),
               "Low": (0,150,50), "Info": (100,100,100)}
    for level, count in summary["buckets"].items():
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(40, 6, level, border=1)
        pdf.cell(30, 6, str(count), border=1)
        bar_w = int(count / total_b * 100)
        x, y  = pdf.get_x(), pdf.get_y()
        pdf.cell(105, 6, "", border=1)
        if bar_w:
            r2, g2, b2 = colours.get(level, (100,100,100))
            pdf.set_fill_color(r2, g2, b2)
            pdf.rect(x + 1, y + 1, bar_w, 4, "F")
        pdf.ln()
    pdf.ln(4)

    # HVT list
    if summary["hvt_list"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"High-Value Targets ({summary['hvt_count']})", ln=True)
        pdf.set_font("Helvetica", "", 9)
        for hvt in summary["hvt_list"][:20]:
            pdf.cell(0, 5, f"  \u26a0  {hvt}", ln=True)
        pdf.ln(3)

    # ── Discovered Entities Table ─────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Discovered Entities", ln=True)
    pdf.set_draw_color(0, 200, 50)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(4)

    col_widths = [55, 40, 35, 25, 25]
    headers    = ["Identity", "Source", "Breach", "Date", "Risk"]
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(30, 30, 30)
    pdf.set_text_color(255, 255, 255)
    for h, w in zip(headers, col_widths):
        pdf.cell(w, 7, h, border=1, fill=True)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    for rec in records[:200]:
        ident = (_rec_get(rec, "email") or _rec_get(rec, "username") or "—")[:30]
        src   = (_rec_get(rec, "source") or "")[:20]
        bn    = (_rec_get(rec, "breach_name") or "")[:20]
        bd    = (_rec_get(rec, "breach_date") or "")[:10]
        rs_v  = f"{float(_rec_get(rec, 'risk_score') or 0):.1f}"
        risk  = float(_rec_get(rec, "risk_score") or 0)
        if risk >= 90:   pdf.set_fill_color(255, 220, 220)
        elif risk >= 70: pdf.set_fill_color(255, 240, 220)
        else:            pdf.set_fill_color(255, 255, 255)
        pdf.set_font("Helvetica", "", 7)
        for val, w in zip([ident, src, bn, bd, rs_v], col_widths):
            pdf.cell(w, 5, val, border=1, fill=True)
        pdf.ln()

    # ── Raw Evidence ──────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Raw Evidence — Passwords & Metadata", ln=True)
    pdf.set_draw_color(0, 200, 50)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Courier", "", 7)
    for rec in records[:300]:
        pw   = _rec_get(rec, "password")
        meta = getattr(rec, "metadata", {}) or {}
        if not pw and not meta:
            continue
        ident = (_rec_get(rec, "email") or _rec_get(rec, "username") or "—")[:40]
        line  = f"{ident}"
        if pw:
            line += f"  pw:{pw[:40]}"
        if meta.get("author"):
            line += f"  author:{meta['author'][:20]}"
        pdf.cell(0, 4, line[:120], ln=True)

    pdf.output(path)
    out("ok", f"PDF report saved: {path}")


# =======================================================================
# PLUGIN SYSTEM — Vault, FileSystemProvider, SourceOrchestrator
# =======================================================================
import importlib as _importlib


class Vault:
    """
    Thin compatibility shim — delegates entirely to ConfigManager (apikeys.json).
    Canonical key store: ~/.config/nox-cli/apikeys.json (chmod 0600).
    """

    _cache: Dict[str, str] = {}

    @classmethod
    def get(cls, key: str) -> str:
        if key in cls._cache:
            return cls._cache[key]
        val = ConfigManager.get(key) or ""
        cls._cache[key] = val
        return val

    @classmethod
    def set(cls, key: str, value: str, prefer_nox_dir: bool = True) -> None:
        ConfigManager.write(key, value)
        cls._cache[key] = value

    @classmethod
    def autodehash(cls, records: List["Record"], db: "DB") -> List["Record"]:
        """
        AutoDehash hook: for any record with a hash but no plaintext,
        attempt a lookup via DEHASH_API_KEY if available.
        Uses the existing DB hash cache to avoid redundant API calls.
        """
        key = cls.get("DEHASH_API_KEY") or cls.get("DEHASHED_API_KEY")
        if not key:
            return records
        for r in records:
            if r.password_hash and not r.password:
                cached = db.get_plain(r.password_hash)
                if cached:
                    r.password = cached
                    continue
                # Synchronous fallback lookup via requests/urllib
                try:
                    auth = base64.b64encode(key.encode()).decode() if ":" in key else key
                    url  = (f"https://api.dehashed.com/search"
                            f"?query=hashed_password:{r.password_hash}&size=1")
                    hdrs = {"Accept": "application/json",
                            "Authorization": f"Basic {auth}",
                            "User-Agent": "NOX Framework"}
                    if requests:
                        resp = requests.get(url, headers=hdrs, timeout=10, verify=True)
                        data = resp.json() if resp.status_code == 200 else {}
                    else:
                        req  = urllib.request.Request(url, headers=hdrs)
                        raw  = urllib.request.urlopen(req, timeout=10)
                        data = json.loads(raw.read().decode())
                    for entry in data.get("entries", []):
                        pw = entry.get("password", "")
                        if pw:
                            r.password = pw
                            db.store_hash(r.password_hash, r.hash_type or "unknown", pw, "Vault/AutoDehash")
                            break
                except Exception as exc:
                    logger.debug("Vault.autodehash %s: %s", r.password_hash[:12], exc)
        return records


class Config:
    """
    General settings loader from config.ini.
    Lookup order: $HOME/.nox/config.ini → /etc/nox/config.ini.

    config.ini format:
        [settings]
        concurrency = 20
        timeout     = 30
        stealth     = true
        rate_limit_lo = 0.5
        rate_limit_hi = 2.0
    """

    _INI_PATHS = [HOME_NOX / "config.ini", Path("/etc/nox/config.ini")]
    _cache: Dict[str, Any] = {}

    @classmethod
    def _ini_path(cls) -> Optional[Path]:
        for p in cls._INI_PATHS:
            if p.exists():
                return p
        return None

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        if key in cls._cache:
            return cls._cache[key]
        ini = cls._ini_path()
        if ini:
            cp = _configparser.ConfigParser()
            cp.read(str(ini))
            val = cp.get("settings", key, fallback=None)
            if val is not None:
                # Auto-cast booleans and numbers
                if val.lower() in ("true", "false"):
                    val = val.lower() == "true"
                else:
                    try:
                        val = int(val)
                    except ValueError:
                        try:
                            val = float(val)
                        except ValueError:
                            pass
                cls._cache[key] = val
                return val
        cls._cache[key] = default
        return default

    @classmethod
    def apply(cls, nox_config: "NoxConfig") -> "NoxConfig":
        """Overlay config.ini values onto a NoxConfig instance."""
        if not cls._ini_path():
            return nox_config
        nox_config.concurrency = nox_config.max_threads = cls.get("concurrency", nox_config.concurrency)
        nox_config.timeout     = cls.get("timeout",     nox_config.timeout)
        nox_config.stealth     = cls.get("stealth",     nox_config.stealth)
        lo = cls.get("rate_limit_lo", nox_config.rate_limit[0])
        hi = cls.get("rate_limit_hi", nox_config.rate_limit[1])
        nox_config.rate_limit  = (lo, hi)
        return nox_config


class FileSystemProvider(AsyncSource):
    """
    Loads a single breach source from a JSON definition file in
    ~/.config/nox/providers/.

    JSON schema:
        {
          "name":                 "MySource",
          "api_url":              "https://api.example.com/search?q={query}",
          "request_type":         "GET",
          "headers":              {"Authorization": "Bearer {api_key}"},
          "payload":              {},
          "regex_pattern":        "(\\S+@\\S+):(\\S+)",   // optional; groups: email, password
          "json_root":            "results",               // dot-path to list in JSON response
          "field_map":            {"email":"email","password":"password"},
          "required_api_key_name": "MY_SOURCE_API_KEY"    // Vault key name
        }
    """

    PROVIDERS_DIR = HOME_NOX / "providers"

    def __init__(self, semaphore: asyncio.Semaphore, db: "DB",
                 config: "NoxConfig", definition: dict) -> None:
        super().__init__(semaphore, db, config)
        self._def     = definition
        self.name     = definition.get("name", "FSProvider")
        key_name      = definition.get("required_api_key_name", "")
        self._api_key = Vault.get(key_name) if key_name else ""
        self.needs_key = bool(key_name)
        self.ok_email = self.ok_user = self.ok_domain = self.ok_phone = True

    async def async_search(self, session, query: str, qtype: str) -> List[Record]:
        if self.needs_key and not self._api_key:
            logger.debug("FileSystemProvider[%s]: key missing, skipping.", self.name)
            return []
        try:
            return await self._fetch(session, query)
        except Exception as exc:
            logger.debug("FileSystemProvider[%s]: %s", self.name, exc)
            return []

    async def _fetch(self, session, query: str) -> List[Record]:
        d   = self._def
        url = (d["api_url"]
               .replace("{query}", urllib.parse.quote(query, safe=""))
               .replace("{api_key}", self._api_key))
        hdrs = {k: v.replace("{api_key}", self._api_key)
                for k, v in d.get("headers", {}).items()}
        method  = d.get("request_type", "GET").upper()
        payload = {k: v.replace("{query}", query).replace("{api_key}", self._api_key)
                   for k, v in d.get("payload", {}).items()}

        if method == "POST":
            status, text, _ = await self._post(session, url,
                                                json_data=payload or None,
                                                headers=hdrs)
        else:
            status, text, _ = await self._get(session, url, headers=hdrs)

        if status not in range(200, 300) or not text:
            return []

        regex = d.get("regex_pattern", "")
        if regex:
            return self._by_regex(text, regex)
        return self._by_json(text, d.get("json_root", ""),
                             d.get("field_map", {}))

    def _by_regex(self, text: str, pattern: str) -> List[Record]:
        records = []
        for m in re.finditer(pattern, text):
            groups = m.groups()
            records.append(self._rec(
                email    = groups[0] if len(groups) > 0 else "",
                password = groups[1] if len(groups) > 1 else "",
                breach_name = self.name,
                data_types  = [self.name, "Credentials"],
            ))
        return records[:100]

    def _by_json(self, text: str, root: str, field_map: dict) -> List[Record]:
        try:
            data = json.loads(text)
        except Exception:
            return []
        for key in (root.split(".") if root else []):
            if isinstance(data, dict):
                data = data.get(key, [])
        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []
        records = []
        for item in data[:100]:
            if not isinstance(item, dict):
                continue
            records.append(self._rec(
                email    = str(item.get(field_map.get("email",    "email"),    "") or ""),
                password = str(item.get(field_map.get("password", "password"), "") or ""),
                username = str(item.get(field_map.get("username", "username"), "") or ""),
                phone    = str(item.get(field_map.get("phone",    "phone"),    "") or ""),
                password_hash = str(item.get(field_map.get("hash", "hash"),   "") or ""),
                breach_name = self.name,
                data_types  = [self.name, "Credentials"],
                raw_data    = item,
            ))
        return records

    @classmethod
    def load_all(cls, semaphore: asyncio.Semaphore, db: "DB",
                 config: "NoxConfig") -> List["FileSystemProvider"]:
        cls.PROVIDERS_DIR.mkdir(parents=True, exist_ok=True)
        providers = []
        for jf in cls.PROVIDERS_DIR.glob("*.json"):
            try:
                defn = json.loads(jf.read_text(encoding="utf-8"))
                providers.append(cls(semaphore, db, config, defn))
                logger.info("FileSystemProvider: loaded %s", jf.name)
            except Exception as exc:
                logger.warning("FileSystemProvider: failed %s — %s", jf.name, exc)
        return providers


class NoxSourceProvider(FileSystemProvider):
    """
    Extended FileSystemProvider that handles the build_sources.py JSON schema:
    - Headers already have keys resolved (passed via _slot_keys)
    - Supports input_type filtering (skip source if query type doesn't match)
    - Handles api_key_slots rotation
    """

    def __init__(self, semaphore: asyncio.Semaphore, db: "DB",
                 config: "NoxConfig", definition: dict) -> None:
        super().__init__(semaphore, db, config, definition)
        self._input_type  = definition.get("input_type", "")
        self._slot_keys   = definition.get("_slot_keys", {})
        self._confidence  = definition.get("confidence", 0.5)
        # For sources with api_key_slots, check if any key is configured
        slots = definition.get("api_key_slots", [])
        if slots and not self._api_key:
            # Try each slot
            for slot in slots:
                key_name = slot.strip("{}")
                val = ConfigManager.get(key_name)
                if val:
                    self._api_key = val
                    break
        self.needs_key = bool(slots)

    async def async_search(self, session, query: str, qtype: str) -> List[Record]:
        # Filter by input_type if specified ('any' or '' means accept all qtypes)
        if self._input_type and self._input_type != "any" and qtype and self._input_type != qtype:
            return []
        if self.needs_key and not self._api_key:
            logger.debug("NoxSourceProvider[%s]: key missing, skipping.", self.name)
            return []
        try:
            return await self._fetch(session, query)
        except Exception as exc:
            logger.debug("NoxSourceProvider[%s]: %s", self.name, exc)
            return []

    async def _fetch(self, session, query: str) -> List[Record]:
        d   = self._def
        # Headers are already resolved in _load_nox_sources; just substitute {query}
        hdrs = {k: v.replace("{query}", urllib.parse.quote(query, safe=""))
                for k, v in d.get("headers", {}).items()}
        url = (d["api_url"]
               .replace("{query}", urllib.parse.quote(query, safe=""))
               .replace("{api_key}", self._api_key or ""))
        # Also substitute any remaining {KEY_NAME} placeholders in URL
        for slot_name, slot_val in self._slot_keys.items():
            url = url.replace(f"{{{slot_name}}}", slot_val or "")

        method  = d.get("request_type", "GET").upper()

        def _sub(obj):
            """Recursively substitute {query} in payload (handles nested dicts/lists)."""
            if isinstance(obj, str):
                return obj.replace("{query}", query).replace("{target}", query)
            if isinstance(obj, dict):
                return {k: _sub(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_sub(v) for v in obj]
            return obj

        payload = _sub(d.get("payload") or {})

        if method == "POST":
            status, text, _ = await self._post(session, url,
                                                json_data=payload or None,
                                                headers=hdrs)
        else:
            status, text, _ = await self._get(session, url, headers=hdrs)

        if status not in range(200, 300) or not text:
            return []

        regex = d.get("regex_pattern", "")
        if regex:
            return self._by_regex(text, regex)
        return self._by_json(text, d.get("json_root", ""), d.get("field_map", {}))


class SourceOrchestrator:
    """
    Plugin-based source manager — 100% dynamic, zero hardcoded sources.

    Loads all intelligence sources exclusively from:
      1. ~/.nox/sources/*.json  — primary plugin directory (build_sources.py output)
      2. ~/.nox/providers/*.json — extended FileSystemProvider plugins
      3. ~/.nox/providers/plugin_*.py — dynamic importlib plugins

    FATAL if sources/ is empty: prints a clear error and aborts the scan.
    """

    # Spec-required path: ~/.nox/sources/
    SOURCES_DIR = SOURCE_DIR

    def __init__(self, semaphore: asyncio.Semaphore, db: "DB",
                 config: "NoxConfig") -> None:
        self._sem    = semaphore
        self._db     = db
        self._config = config
        self._nox_sources: List[AsyncSource]   = []  # from ~/.nox/sources/
        self._fs_providers: List[AsyncSource]  = []  # from ~/.nox/providers/
        self._py_providers: List[AsyncSource]  = []  # importlib .py plugins
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._nox_sources  = self._load_nox_sources()
        self._fs_providers = FileSystemProvider.load_all(self._sem, self._db, self._config)
        self._py_providers = self._load_py_plugins()
        self._loaded = True

        total = len(self._nox_sources) + len(self._fs_providers) + len(self._py_providers)
        if total == 0:
            print(
                f"\n  {C.BD}{C.R}[FATAL] No JSON plugins found in sources/. "
                f"Please run build_sources.py first.{C.X}\n"
            )
            logger.critical("[FATAL] No JSON plugins found in sources/. Run build_sources.py.")

    def _load_nox_sources(self) -> List[AsyncSource]:
        """
        Scan ~/.nox/sources/*.json.  Handles both the build_sources.py schema
        (endpoint/{target}, normalization_map, selectors, api_key_slots) and the
        legacy FileSystemProvider schema (api_url/{query}, field_map, json_root).
        """
        self.SOURCES_DIR.mkdir(parents=True, exist_ok=True)
        json_files = list(self.SOURCES_DIR.glob("*.json"))
        if not json_files:
            return []
        sources: List[AsyncSource] = []
        for jf in json_files:
            try:
                raw = json.loads(jf.read_text(encoding="utf-8"))
                slots = raw.get("api_key_slots", [])
                # Derive primary key name from slots (strip {})
                derived_key_name = (
                    raw.get("required_api_key_name", "")
                    or (slots[0].strip("{}") if slots else "")
                )
                # Resolve all key names from slots for header substitution
                slot_keys = {s.strip("{}"): ConfigManager.get(s.strip("{}")) for s in slots}

                # Build headers: replace {KEY_NAME} placeholders with actual key values
                raw_headers = raw.get("headers", {})
                resolved_headers = {}
                for k, v in raw_headers.items():
                    for slot_name, slot_val in slot_keys.items():
                        v = v.replace(f"{{{slot_name}}}", slot_val or "")
                    resolved_headers[k] = v

                # Normalise endpoint: {target} → {query} for FileSystemProvider compat
                endpoint = raw.get("endpoint", raw.get("api_url", ""))
                endpoint = endpoint.replace("{target}", "{query}")

                # Build field_map from normalization_map (inverted: output_field → source_field)
                norm_map = raw.get("normalization_map", {})
                field_map = raw.get("field_map", {})
                if norm_map and not field_map:
                    # normalization_map: {"email": "email_address"} means source field "email_address" → our "email"
                    field_map = {our_field: src_field for our_field, src_field in norm_map.items()
                                 if our_field in ("email", "password", "username", "phone", "hash")}

                # json_root from selectors (e.g. "$.entries" → "entries")
                selectors = raw.get("selectors", {})
                json_root = raw.get("json_root", "")
                if not json_root and selectors:
                    # Take first selector value, strip "$." prefix
                    first_sel = next(iter(selectors.values()), "")
                    if first_sel.startswith("$."):
                        # Handle "$.entries" → "entries", "$.*.Name" → "" (complex path, skip)
                        parts = first_sel[2:].split(".")
                        json_root = parts[0] if len(parts) == 1 else ""

                defn = {
                    "name":                  raw.get("name", jf.stem),
                    "api_url":               endpoint,
                    "request_type":          raw.get("method", raw.get("request_type", "GET")),
                    "headers":               resolved_headers,
                    "regex_pattern":         raw.get("regex_pattern", ""),
                    "json_root":             json_root,
                    "field_map":             field_map,
                    "required_api_key_name": derived_key_name,
                    "api_key_slots":         slots,
                    "input_type":            raw.get("input_type", ""),
                    "output_type":           raw.get("output_type", []),
                    "pivot_types":           raw.get("pivot_types", []),
                    "confidence":            raw.get("confidence", 0.5),
                    # payload_template → payload for POST sources
                    "payload":               raw.get("payload_template") or raw.get("payload") or {},
                    # Pass resolved slot keys so FileSystemProvider can use them
                    "_slot_keys":            slot_keys,
                }
                sources.append(NoxSourceProvider(self._sem, self._db, self._config, defn))
                logger.debug("SourceOrchestrator: loaded %s", jf.name)
            except Exception as exc:
                logger.warning("SourceOrchestrator: failed %s — %s", jf.name, exc)
        logger.info("SourceOrchestrator: loaded %d sources from sources/", len(sources))
        return sources

    def _load_py_plugins(self) -> List[AsyncSource]:
        """Dynamically import plugin_*.py files via importlib."""
        plugins: List[AsyncSource] = []
        for py_file in FileSystemProvider.PROVIDERS_DIR.glob("plugin_*.py"):
            try:
                spec   = _importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = _importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "create"):
                    inst = module.create(self._sem, self._db, self._config)
                    if isinstance(inst, list):
                        plugins.extend(inst)
                    elif inst is not None:
                        plugins.append(inst)
                    logger.info("SourceOrchestrator: loaded plugin %s", py_file.name)
            except Exception as exc:
                logger.warning("SourceOrchestrator: plugin %s failed — %s", py_file.name, exc)
        return plugins

    def get_sources(self, session: "Session", qtype: str) -> List[AsyncSource]:
        """Return plugin sources applicable to qtype, pre-filtered to avoid creating unnecessary tasks."""
        self._ensure_loaded()
        sources: List[AsyncSource] = []
        for src in self._nox_sources:
            input_type = getattr(src, "_input_type", "")
            if not input_type or input_type == "any" or not qtype or input_type == qtype:
                sources.append(src)
        sources.extend(self._fs_providers)
        sources.extend(self._py_providers)
        return sources

    def plugin_count(self) -> int:
        self._ensure_loaded()
        return len(self._nox_sources) + len(self._fs_providers) + len(self._py_providers)


# =======================================================================
# FORENSIC REPORTER (fpdf2)
# =======================================================================

def _pdf_safe(s: str, maxlen: int = 200) -> str:
    """
    Sanitise a string for fpdf2 core fonts (latin-1 subset).
    1. Strip control characters and binary garbage.
    2. Replace non-latin-1 characters with '?' to prevent UnicodeEncodeError.
    3. Truncate to maxlen to prevent cell overflow.
    """
    if not s:
        return ""
    # Strip control chars (same regex as AdvancedReporter._CTRL_RE)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", s)
    return s[:maxlen].encode("latin-1", errors="replace").decode("latin-1")


class ForensicReporter:
    """
    Professional forensic PDF report using fpdf2.

    Sections:
      1. Case Metadata  — Timestamp, Investigator ID, Target
      2. Executive Summary — Risk Score (0–10 scale), severity breakdown
      3. Categorized Findings — Credentials, PII, Dorked Documents
      4. Dork Results — URL, snippet, dork query, engine
      5. Scrape Results — Pastes (with links), extracted credentials, Telegram CTI, misconfigs
      6. Identity Graph — ASCII relationship map
    """

    @staticmethod
    def generate(data: dict, path: str, investigator_id: str = "NOX-AUTO") -> None:
        try:
            from fpdf import FPDF  # type: ignore
        except ImportError:
            out("warn", "fpdf2 not installed. Run: pip install fpdf2")
            return

        records = data.get("records", [])
        target  = data.get("target", "Unknown")
        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        summary = AdvancedReporter._build_summary(records)

        # Risk score normalised to 0–10
        max_risk = max((float(_rec_get(r, "risk_score") or 0) for r in records), default=0.0)
        risk_10  = round(max_risk / 10, 1)

        # Categorise findings
        credentials = [r for r in records if _rec_get(r, "password") or _rec_get(r, "password_hash")]
        pii         = [r for r in records if _rec_get(r, "phone") or _rec_get(r, "name")
                       or getattr(r, "address", "")]
        dorked      = [r for r in records if _rec_get(r, "source") == "DorkingEngine"]

        class _PDF(FPDF):
            def header(self):
                self.set_font("Helvetica", "B", 8)
                self.set_text_color(120, 120, 120)
                self.cell(0, 5, "NOX Framework - FORENSIC REPORT - CONFIDENTIAL", align="R")
                self.ln(3)

            def footer(self):
                self.set_y(-12)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(150, 150, 150)
                self.cell(0, 5, _pdf_safe(f"Page {self.page_no()} | Case: {target[:40]}"), align="C")

        pdf = _PDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_margins(15, 15, 15)

        # ── 1. Case Metadata ─────────────────────────────────────────
        pdf.add_page()
        pdf.set_fill_color(15, 15, 15)
        pdf.rect(0, 0, 210, 297, "F")

        pdf.set_y(70)
        pdf.set_font("Helvetica", "B", 28)
        pdf.set_text_color(0, 220, 60)
        pdf.cell(0, 12, "FORENSIC INTELLIGENCE REPORT", align="C")
        pdf.ln(8)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(200, 200, 200)
        pdf.cell(0, 8, _pdf_safe(f"Target: {target}"), align="C")
        pdf.ln(6)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(140, 140, 140)
        for line in [f"Timestamp: {ts}",
                     f"Investigator ID: {investigator_id}",
                     f"Framework: NOX Framework v{VERSION}",
                     "Classification: RESTRICTED - Authorised Use Only"]:
            pdf.cell(0, 6, _pdf_safe(line), align="C")
            pdf.ln(5)

        # ── 2. Executive Summary ─────────────────────────────────────
        pdf.add_page()
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.set_draw_color(0, 180, 50)
        pdf.set_line_width(0.4)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)

        # Risk score gauge (0–10)
        risk_colour = (200, 0, 30) if risk_10 >= 8 else (220, 110, 0) if risk_10 >= 5 else (0, 160, 50)
        pdf.set_font("Helvetica", "B", 11)
        kpis = [
            ("Risk Score (0-10)",        f"{risk_10}  {'#' * int(risk_10)}{'-' * (10 - int(risk_10))}"),
            ("Compromised Identities",   str(summary["total_identities"])),
            ("Total Records",            str(summary["total_records"])),
            ("Stealer Logs",             str(summary["stealer_count"])),
            ("High-Value Targets",       str(summary["hvt_count"])),
            ("Credential Records",       str(len(credentials))),
            ("PII Records",              str(len(pii))),
            ("Dorked Documents",         str(len(dorked))),
        ]
        for label, value in kpis:
            pdf.set_fill_color(245, 245, 245)
            pdf.cell(90, 7, _pdf_safe(label), border=1, fill=True)
            if label.startswith("Risk"):
                pdf.set_text_color(*risk_colour)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(85, 7, _pdf_safe(value), border=1, ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "B", 11)
        pdf.ln(5)

        # Severity breakdown
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Severity Breakdown", ln=True)
        _sev_colours = {"Critical":(220,0,30),"High":(220,100,0),
                        "Medium":(200,180,0),"Low":(0,150,50),"Info":(100,100,100)}
        total_b = max(sum(summary["buckets"].values()), 1)
        for level, count in summary["buckets"].items():
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(35, 6, _pdf_safe(level), border=1)
            pdf.cell(20, 6, str(count), border=1)
            bar_w = int(count / total_b * 120)
            x, y  = pdf.get_x(), pdf.get_y()
            pdf.cell(125, 6, "", border=1)
            if bar_w:
                rc, gc, bc = _sev_colours.get(level, (100,100,100))
                pdf.set_fill_color(rc, gc, bc)
                pdf.rect(x + 1, y + 1, bar_w, 4, "F")
            pdf.ln()

        # ── 3. Categorized Findings ──────────────────────────────────
        for section_title, section_records, cols in [
            ("Credentials", credentials[:150],
             [("Identity", 55), ("Password", 45), ("Source", 35), ("Risk", 20), ("Date", 25)]),
            ("PII Records", pii[:100],
             [("Identity", 55), ("Phone", 35), ("Name", 40), ("Source", 30), ("Risk", 20)]),
            ("Dorked Documents", dorked[:80],
             [("URL", 100), ("Author", 40), ("Type", 20), ("Risk", 20)]),
        ]:
            if not section_records:
                continue
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 9, _pdf_safe(f"Findings - {section_title}"), ln=True)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(3)

            # Header row
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30)
            pdf.set_text_color(255, 255, 255)
            for col_name, col_w in cols:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)

            for rec in section_records:
                rs = float(_rec_get(rec, "risk_score") or 0)
                pdf.set_fill_color(255, 230, 230) if rs >= 90 else \
                    pdf.set_fill_color(255, 245, 230) if rs >= 70 else \
                    pdf.set_fill_color(255, 255, 255)
                pdf.set_font("Helvetica", "", 7)

                ident = _pdf_safe(_rec_get(rec, "email") or _rec_get(rec, "username") or "-", 35)
                src   = _pdf_safe(_rec_get(rec, "source") or "", 20)
                rs_s  = f"{rs:.0f}"
                bd    = _pdf_safe(_rec_get(rec, "breach_date") or "", 10)

                if section_title == "Credentials":
                    pw = _pdf_safe(_rec_get(rec, "password") or _rec_get(rec, "password_hash") or "", 30)
                    for val, w in zip([ident, pw, src, rs_s, bd], [c[1] for c in cols]):
                        pdf.cell(w, 5, val, border=1, fill=True)
                elif section_title == "PII Records":
                    ph   = _pdf_safe(_rec_get(rec, "phone") or "", 20)
                    name = _pdf_safe(_rec_get(rec, "name") or getattr(rec, "full_name", "") or "", 25)
                    for val, w in zip([ident, ph, name, src, rs_s], [c[1] for c in cols]):
                        pdf.cell(w, 5, val, border=1, fill=True)
                else:  # Dorked
                    meta = getattr(rec, "metadata", {}) or {}
                    rd   = getattr(rec, "raw_data", {}) or {}
                    url  = _pdf_safe(rd.get("url", "") if isinstance(rd, dict) else "", 65)
                    auth = _pdf_safe(meta.get("author", ""), 25)
                    ext  = _pdf_safe((url.rsplit(".", 1)[-1].split("?")[0] if "." in url else ""), 10)
                    for val, w in zip([url, auth, ext, rs_s], [c[1] for c in cols]):
                        pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()

        # ── 4. Dork Results ──────────────────────────────────────────
        dork_results = data.get("dork_results", []) or []
        if dork_results:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 9, _pdf_safe(f"Dork Results ({len(dork_results)} hits)"), ln=True)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30)
            pdf.set_text_color(255, 255, 255)
            for col_name, col_w in [("URL / Title", 90), ("Snippet", 55), ("Engine", 20), ("Dork Query", 15)]:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)
            for h in dork_results[:200]:
                pdf.set_fill_color(245, 245, 255)
                pdf.set_font("Helvetica", "", 7)
                url     = _pdf_safe(h.get("url", h.get("title", "")), 60)
                snippet = _pdf_safe(h.get("snippet", ""), 38)
                engine  = _pdf_safe(h.get("engine", ""), 12)
                dork_q  = _pdf_safe(h.get("dork", ""), 12)
                for val, w in zip([url, snippet, engine, dork_q], [90, 55, 20, 15]):
                    pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()

        # ── 5. Scrape Results ────────────────────────────────────────
        scrape_results = data.get("scrape_results", {}) or {}
        pastes      = scrape_results.get("pastes", [])
        creds_sc    = scrape_results.get("credentials", [])
        tg_hits     = scrape_results.get("telegram", [])
        mc_hits     = scrape_results.get("dork_misconfigs", [])

        if pastes or creds_sc or tg_hits or mc_hits:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 9, "Scrape Results", ln=True)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(3)

            paste_links = {
                "Pastebin": "https://pastebin.com/{}",
                "Rentry":   "https://rentry.co/{}",
                "Hastebin": "https://hastebin.com/{}",
                "DPaste":   "https://dpaste.org/{}",
                "Ghostbin": "https://ghostbin.com/paste/{}",
                "JustPaste":"https://justpaste.it/{}",
                "ControlC": "https://controlc.com/{}",
                "Paste2":   "https://paste2.org/raw/{}",
                "PastebinPro": "https://pastebin.com/{}",
            }

            if pastes:
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 7, _pdf_safe(f"Pastes ({len(pastes)})"), ln=True)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
                for col_name, col_w in [("Site", 25), ("Paste ID / Link", 80), ("Patterns Found", 75)]:
                    pdf.cell(col_w, 6, col_name, border=1, fill=True)
                pdf.ln(); pdf.set_text_color(0, 0, 0)
                for p in pastes[:100]:
                    pdf.set_fill_color(245, 245, 245); pdf.set_font("Helvetica", "", 7)
                    site  = _pdf_safe(p.get("site", ""), 15)
                    pid   = p.get("id", "")
                    tmpl  = paste_links.get(p.get("site", ""), "")
                    link  = _pdf_safe(tmpl.format(pid) if tmpl and pid else pid, 55)
                    pats  = _pdf_safe(", ".join(f"{k}({len(v)})" for k, v in (p.get("patterns") or {}).items()), 50)
                    for val, w in zip([site, link, pats], [25, 80, 75]):
                        pdf.cell(w, 5, val, border=1, fill=True)
                    pdf.ln()
                pdf.ln(3)

            if creds_sc:
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 7, _pdf_safe(f"Extracted Credentials ({len(creds_sc)})"), ln=True)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
                for col_name, col_w in [("Raw Credential", 120), ("Source", 30), ("Paste ID", 30)]:
                    pdf.cell(col_w, 6, col_name, border=1, fill=True)
                pdf.ln(); pdf.set_text_color(0, 0, 0)
                for c in creds_sc[:150]:
                    pdf.set_fill_color(255, 240, 240); pdf.set_font("Helvetica", "", 7)
                    raw = _pdf_safe(c.get("raw", ""), 80)
                    src = _pdf_safe(c.get("source", ""), 20)
                    pid = _pdf_safe(c.get("paste_id", ""), 20)
                    for val, w in zip([raw, src, pid], [120, 30, 30]):
                        pdf.cell(w, 5, val, border=1, fill=True)
                    pdf.ln()
                pdf.ln(3)

            if tg_hits:
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 7, _pdf_safe(f"Telegram CTI ({len(tg_hits)})"), ln=True)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
                for col_name, col_w in [("Channel / Link", 50), ("Message Excerpt", 100), ("Patterns", 30)]:
                    pdf.cell(col_w, 6, col_name, border=1, fill=True)
                pdf.ln(); pdf.set_text_color(0, 0, 0)
                for t in tg_hits[:80]:
                    pdf.set_fill_color(245, 245, 255); pdf.set_font("Helvetica", "", 7)
                    link = _pdf_safe(f"t.me/s/{t.get('channel','')}", 35)
                    text = _pdf_safe(t.get("text", ""), 70)
                    pats = _pdf_safe(", ".join(f"{k}({len(v)})" for k, v in (t.get("patterns") or {}).items()), 25)
                    for val, w in zip([link, text, pats], [50, 100, 30]):
                        pdf.cell(w, 5, val, border=1, fill=True)
                    pdf.ln()
                pdf.ln(3)

            if mc_hits:
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 7, _pdf_safe(f"Misconfigurations ({len(mc_hits)})"), ln=True)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
                for col_name, col_w in [("URL", 90), ("Title", 60), ("Dork", 30)]:
                    pdf.cell(col_w, 6, col_name, border=1, fill=True)
                pdf.ln(); pdf.set_text_color(0, 0, 0)
                for m in mc_hits[:80]:
                    pdf.set_fill_color(255, 245, 230); pdf.set_font("Helvetica", "", 7)
                    url_m   = _pdf_safe(m.get("url", ""), 60)
                    title_m = _pdf_safe(m.get("title", ""), 40)
                    dork_m  = _pdf_safe(m.get("dork", ""), 25)
                    for val, w in zip([url_m, title_m, dork_m], [90, 60, 30]):
                        pdf.cell(w, 5, val, border=1, fill=True)
                    pdf.ln()

        # ── 6. Discovered Assets ─────────────────────────────────────
        discovered_assets = data.get("discovered_assets", []) or []
        if discovered_assets:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 9, _pdf_safe(f"Discovered Assets ({len(discovered_assets)} reinjected identifiers)"), ln=True)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
            for col_name, col_w in [("Asset", 65), ("Type", 20), ("Phase", 20), ("Reference (Source/URL/Paste)", 55), ("From", 20)]:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln(); pdf.set_text_color(0, 0, 0)
            _phase_fills = {"breach": (255,230,230), "dork": (255,245,220),
                            "scrape": (245,230,255), "hash_crack": (245,230,255)}
            for da in discovered_assets[:300]:
                phase = da.get("phase", "?")
                pdf.set_fill_color(*_phase_fills.get(phase, (245, 245, 245)))
                pdf.set_font("Helvetica", "", 7)
                for val, w in zip([
                    _pdf_safe(da.get("asset", ""), 45),
                    _pdf_safe(da.get("qtype", ""), 12),
                    _pdf_safe(phase, 12),
                    _pdf_safe(da.get("ref", ""), 38),
                    _pdf_safe(da.get("parent", ""), 14),
                ], [65, 20, 20, 55, 20]):
                    pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()

        # ── 7. Pivot Tree ─────────────────────────────────────────────
        pivot_log = data.get("pivot_log", []) or []
        if pivot_log:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 9, _pdf_safe(f"Pivot Tree ({len(pivot_log)} nodes)"), ln=True)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(30, 30, 30); pdf.set_text_color(255, 255, 255)
            for col_name, col_w in [("D", 8), ("Asset", 55), ("Type", 18), ("Phase", 18), ("Parent", 40), ("Breach", 12), ("Dorks", 12), ("Scrape", 12), ("Cracked", 5)]:
                pdf.cell(col_w, 6, col_name, border=1, fill=True)
            pdf.ln(); pdf.set_text_color(0, 0, 0)
            for e in pivot_log[:300]:
                pdf.set_fill_color(245, 245, 245); pdf.set_font("Helvetica", "", 7)
                cracked_str = _pdf_safe(", ".join(e.get("cracked", [])[:2]), 10)
                for val, w in zip([
                    str(e.get("depth", 0)),
                    _pdf_safe(e.get("asset", ""), 38),
                    _pdf_safe(e.get("qtype", ""), 12),
                    _pdf_safe(e.get("found_in", ""), 12),
                    _pdf_safe(e.get("parent") or "", 28),
                    str(e.get("records", 0)),
                    str(e.get("dorks", 0)),
                    str(e.get("scrape", 0)),
                    cracked_str,
                ], [8, 55, 18, 18, 40, 12, 12, 12, 5]):
                    pdf.cell(w, 5, val, border=1, fill=True)
                pdf.ln()

        # ── 8. Identity Graph Placeholder ────────────────────────────
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 9, "Identity Relationship Map", ln=True)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)

        emails    = sorted({_rec_get(r, "email")    for r in records if _rec_get(r, "email")})[:8]
        phones    = sorted({_rec_get(r, "phone")    for r in records if _rec_get(r, "phone")})[:6]
        usernames = sorted({_rec_get(r, "username") for r in records if _rec_get(r, "username")})[:6]
        passwords = sorted({_rec_get(r, "password") for r in records if _rec_get(r, "password")})[:5]

        pdf.set_font("Courier", "", 8)
        pdf.set_fill_color(245, 255, 245)
        pdf.rect(15, pdf.get_y(), 180, 120, "F")
        pdf.set_xy(18, pdf.get_y() + 3)

        graph_lines = [_pdf_safe(f"[*] TARGET: {target}")]
        for grp, items, label in [
            (emails,    emails,    "email"),
            (phones,    phones,    "phone"),
            (usernames, usernames, "username"),
            (passwords, passwords, "password"),
        ]:
            if not items:
                continue
            graph_lines.append(f"  +-- [{label}]")
            for i, v in enumerate(items):
                pfx = "  |   \\--" if i == len(items) - 1 else "  |   +--"
                graph_lines.append(_pdf_safe(f"{pfx} {v}", 80))

        for line in graph_lines[:30]:
            pdf.cell(0, 4, line, ln=True)
            pdf.set_x(18)

        pdf.output(path)
        out("ok", f"Forensic PDF saved: {path}")


# =======================================================================
# CLI ENTRY POINT
# =======================================================================
def main() -> None:
    initialize_environment()
    _base = os.path.basename(sys.argv[0])
    _prog = os.environ.get("NOX_PROG_NAME") or (f"python3 {_base}" if _base.endswith(".py") else _base)
    parser = argparse.ArgumentParser(
        prog=_prog,
        description=f"NOX v{VERSION} — OSINT Breach Intelligence (120+ JSON plugin sources)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            lambda p: f"""Examples:
  {p}                          Interactive mode
  {p} -t user@email.com        Scan email
  {p} -t example.com           Scan domain
  {p} -t example.com --fullscan Full assault + pivot
  {p} --dork user@email.com    Google dorking
  {p} --scrape user@email.com  Web scraping + Telegram
  {p} --crack <hash>           Crack a hash
  {p} --analyze "P@ssw0rd"     Password analysis
  {p} --list-sources           List loaded plugins with key status
"""
        )(_prog))
    parser.add_argument("-t","--target",   help="Target to scan")
    parser.add_argument("-i","--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--version",       action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--autoscan",      action="store_true", help="Full autoscan: scan+pivot+dork+scrape (no args needed, uses -t)")
    parser.add_argument("--fullscan",      action="store_true", help="Full scan+pivot (alias for --autoscan without dork/scrape)")
    parser.add_argument("--no-pivot",      action="store_true", help="Disable recursive pivot enrichment")
    parser.add_argument("--depth",         type=int, default=None, metavar="N", help="Avalanche pivot depth (default: 2)")
    parser.add_argument("--dork",          metavar="TARGET", help="Google dorking")
    parser.add_argument("--scrape",        metavar="TARGET", help="Web scraping + Telegram indexing")
    parser.add_argument("--crack",         metavar="HASH",   help="Crack a hash (WARNING: submits hash to public rainbow-table APIs — use --no-online-crack to disable)")
    parser.add_argument("--no-online-crack", action="store_true",
                        help="Disable online rainbow-table APIs for hash cracking (local wordlist only, no data sent to third parties)")
    parser.add_argument("--analyze",       metavar="PASS",   help="Analyze password")
    parser.add_argument("--list-sources",  action="store_true", help="List loaded plugins with input_type, confidence, key status")
    parser.add_argument("--tor",           action="store_true", help="Enable Tor")
    parser.add_argument("--proxy",         metavar="URL",    help="HTTP/S or SOCKS5 proxy URL")
    parser.add_argument("--allow-leak",    action="store_true",
                        help="Bypass fail-safe: allow direct connection if proxy/Tor is unavailable (OPSEC risk)")
    parser.add_argument("--guardian-off",  action="store_true",
                        help="Alias for --allow-leak: disable Guardian OPSEC kill-switch (direct connection)")
    parser.add_argument("--reset-sources", action="store_true",
                        help="Force resync of all source plugins from package (overwrites user modifications)")
    parser.add_argument("--threads",       type=int, default=20, help="Max concurrency")
    parser.add_argument("--timeout",       type=int, default=15, help="Request timeout")
    parser.add_argument("-o","--output",   metavar="FILE",   help="Output file")
    parser.add_argument("--format",        choices=["json","csv","html","md","pdf"], default="json", help="Output format")
    parser.add_argument("--diff",          action="store_true",
                        help="Compare current scan against the last cached scan and highlight new findings only")

    args   = parser.parse_args()
    config = NoxConfig()
    # Apply ~/.nox/config.ini settings before CLI args (CLI takes precedence)
    Config.apply(config)
    if args.tor:
        config.use_tor = True
        config.proxy   = f"socks5h://127.0.0.1:{config.tor_socks}"
    if args.proxy:
        config.proxy = args.proxy
    # K2: --guardian-off is an alias for --allow-leak
    config.allow_leak      = args.allow_leak or getattr(args, "guardian_off", False)
    config.no_online_crack = getattr(args, "no_online_crack", False)
    config.max_threads = config.concurrency = args.threads
    config.timeout     = args.timeout
    # A9/I3: store no_pivot and depth in config so REPL and AvalancheScanner can read them
    config.no_pivot    = args.no_pivot
    if getattr(args, "depth", None) is not None:
        config.pivot_depth = args.depth

    db  = NoxDB()
    try:
        _main_run(args, config, db)
    finally:
        db.close()


def _main_run(args, config: NoxConfig, db: NoxDB) -> None:
    orc = Orchestrator(config, db)

    # --list-sources
    if getattr(args, "list_sources", False):
        repl = REPL.__new__(REPL)
        repl.orc = orc
        repl.db  = db
        repl.config = config
        repl._sources()
        return

    # B6: --reset-sources forces a full resync from package
    if getattr(args, "reset_sources", False):
        import shutil as _shutil
        candidate = _PKG_ROOT / "sources"
        if not candidate.is_dir():
            candidate = Path("/usr/share/nox-cli/sources")
        if candidate.is_dir():
            count = 0
            for jf in candidate.glob("*.json"):
                dst = SOURCE_DIR / jf.name
                try:
                    _shutil.copy2(jf, dst)
                    count += 1
                except OSError:
                    pass
            out("ok", f"Reset {count} source plugins from package.")
        else:
            out("warn", "Package sources directory not found.")
        return

    if args.crack:
        if getattr(config, "no_online_crack", False):
            out("warn", "Online rainbow-table APIs disabled (--no-online-crack). Local wordlist only.")
        result = orc.crack(args.crack)
        out("info", f"Types: {', '.join(t[0] for t in result.get('types',[]))}")
        if result.get("plaintext"): out("ok", f"CRACKED: {result['plaintext']} (via {result['method']})")
        else: out("warn", "Could not crack.")
        return

    if args.analyze:
        repl = REPL.__new__(REPL)
        repl.orc = orc
        repl._analyze(args.analyze)
        return

    if args.dork:
        results = orc.dork(args.dork)
        out("ok", f"Dorking: {len(results)} results")
        for i, r in enumerate(results[:20], 1):
            title   = (r.get('title','') or r.get('dork',''))[:70]
            url     = r.get("url", "")
            snippet = r.get("snippet", "")[:100]
            dork_q  = r.get("dork", "")[:60]
            engine  = r.get("engine", "")
            eng_tag = f"  {C.DM}[{engine}]{C.X}" if engine else ""
            print(f"  {C.Y}{i:2}.{C.W} {title}{eng_tag}")
            if url:     print(f"      {C.DM}{url[:80]}{C.X}")
            if snippet: print(f"      {C.DM}{snippet}{C.X}")
            if dork_q and dork_q != title: print(f"      {C.DM}dork: {dork_q}{C.X}")
        if len(results) > 20:
            print(f"  {C.DM}  … and {len(results)-20} more — use -o for full export{C.X}")
        if args.output:
            data = {"target": args.dork, "records": [], "dork_results": results, "scrape_results": {}}
            if args.format == "json":   Reporter.to_json(data, args.output)
            elif args.format == "html": Reporter.to_html(data, args.output)
            elif args.format == "md":   Reporter.to_markdown(data, args.output)
            elif args.format == "pdf":  Reporter.to_pdf(data, args.output)
            elif args.format == "csv":
                resolved = Reporter._resolve_path(args.output, "csv")
                import csv as _csv
                with open(resolved, "w", newline="", encoding="utf-8") as f:
                    w = _csv.DictWriter(f, fieldnames=["url","title","snippet","dork","engine"], extrasaction="ignore")
                    w.writeheader(); w.writerows(results)
                out("ok", f"Dork CSV saved: {resolved}")
        return

    if args.scrape:
        results = orc.scrape(args.scrape)
        pastes = results.get('pastes',[]); creds = results.get('credentials',[])
        tg = results.get('telegram',[]); mc = results.get('dork_misconfigs',[])
        out("ok", f"Pastes: {len(pastes)} | Credentials: {len(creds)} | "
                  f"Hashes: {len(results.get('hashes',[]))} | Telegram: {len(tg)} | Misconfigs: {len(mc)}")
        _ptmpl = {"Pastebin":"https://pastebin.com/{}","Rentry":"https://rentry.co/{}",
                  "Hastebin":"https://hastebin.com/{}","DPaste":"https://dpaste.org/{}"}
        for p in pastes[:8]:
            pid = p.get("id",""); site = p.get("site","")
            url = _ptmpl.get(site,"").format(pid) if _ptmpl.get(site) and pid else ""
            pats = ", ".join(f"{k}({len(v)})" for k,v in (p.get("patterns") or {}).items())
            print(f"  {C.P}[paste]{C.W} [{site}] {(p.get('title') or pid)[:50]}  {C.DM}{pats}{C.X}")
            if url: print(f"    {C.DM}{url}{C.X}")
        if len(pastes) > 8: print(f"  {C.DM}  … and {len(pastes)-8} more pastes{C.X}")
        for c in creds[:12]:
            src = c.get("source",""); pid = c.get("paste_id","")
            ref = f"[{src or pid}]" if (src or pid) else ""
            print(f"  {C.R}[cred]{C.W} {c.get('raw','')[:80]}  {C.DM}{ref}{C.X}")
        if len(creds) > 12: print(f"  {C.DM}  … and {len(creds)-12} more credentials{C.X}")
        for t in tg[:5]:
            pats = ", ".join(f"{k}({len(v)})" for k,v in (t.get("patterns") or {}).items())
            print(f"  {C.CY}[tg]{C.W} [{t.get('channel','')}] {t.get('text','')[:70]}  {C.DM}{pats}{C.X}")
        if len(tg) > 5: print(f"  {C.DM}  … and {len(tg)-5} more telegram hits{C.X}")
        for m in mc[:5]:
            print(f"  {C.O}[misc]{C.W} {m.get('title','')[:60]}")
            if m.get("url"): print(f"    {C.DM}{m['url'][:80]}{C.X}")
            if m.get("dork"): print(f"    {C.DM}dork: {m['dork'][:60]}{C.X}")
        if len(mc) > 5: print(f"  {C.DM}  … and {len(mc)-5} more misconfigs{C.X}")
        if args.output:
            data = {"target": args.scrape, "records": [], "dork_results": [], "scrape_results": results}
            if args.format == "json":   Reporter.to_json(data, args.output)
            elif args.format == "html": Reporter.to_html(data, args.output)
            elif args.format == "md":   Reporter.to_markdown(data, args.output)
            elif args.format == "pdf":  Reporter.to_pdf(data, args.output)
            elif args.format == "csv":
                REPL._export_csv_extras(data, Reporter._resolve_path(args.output, "csv"))
        return

    if args.target:
        if args.autoscan or args.fullscan:
            try:
                result  = asyncio.run(orc.fullscan(args.target, pivot=not args.no_pivot))
            except KeyboardInterrupt:
                print()
                out("warn", "Scan interrupted.")
                sys.exit(0)
            records = result.get("records",[])
        else:
            records = orc.scan(args.target)
            HVTAnalyzer.annotate(records)
            result  = {
                "target":            args.target,
                "records":           records,
                "analysis":          CredAnalyzer.analyze(records),
                "hvt_records":       HVTAnalyzer.filter_hvt(records),
                "dork_results":      [],
                "scrape_results":    {},
                "pivot_chain":       [args.target],
                "pivot_log":         [],
                "discovered_assets": [],
                "scan_meta":         {"pivot_depth": 0, "nodes_discovered": len(records)},
            }
        analysis = result.get("analysis") or CredAnalyzer.analyze(records)

        # ── --diff: surface only new findings vs last cached scan ──
        if getattr(args, "diff", False):
            try:
                prev_rows = db.get_creds(args.target)
                prev_keys = {
                    hashlib.sha256(
                        f"{r.get('email','') or r.get('username','')}:{r.get('password','')}".encode()
                    ).hexdigest()
                    for r in prev_rows
                }
                new_records = [
                    r for r in records
                    if hashlib.sha256(
                        f"{r.email or r.username}:{r.password}".encode()
                    ).hexdigest() not in prev_keys
                ]
                out("info", f"--diff: {len(new_records)} new findings vs last cached scan ({len(records) - len(new_records)} already known)")
                records = new_records
                result["records"] = new_records
            except Exception as _de:
                out("warn", f"--diff failed, showing full results: {_de}")
        repl = REPL.__new__(REPL)
        repl.orc = orc
        repl.db  = db
        repl.config = config
        repl._last_full = result
        repl._last = records
        repl._print_summary(analysis)
        if args.autoscan or args.fullscan:
            dorks = result.get("dork_results",[])
            if dorks:
                out("info", f"Dorking Results: {len(dorks)}")
                for d in dorks[:10]:
                    title = (d.get('title','') or d.get('dork',''))[:70]
                    print(f"  {C.Y}→{C.W} {title}")
                    if d.get("url"): print(f"    {C.DM}{d['url'][:80]}{C.X}")
                if len(dorks) > 10:
                    print(f"  {C.DM}  … and {len(dorks)-10} more — use -o for full export{C.X}")
            scrape = result.get("scrape_results",{})
            creds  = scrape.get("credentials",[])
            if creds:
                out("info", f"Scraped Credentials: {len(creds)}")
                for c in creds[:10]:
                    print(f"  {C.R}→{C.W} {c.get('raw','')}")
                if len(creds) > 10:
                    print(f"  {C.DM}  … and {len(creds)-10} more{C.X}")
            tg = scrape.get("telegram",[])
            if tg:
                out("info", f"Telegram Hits: {len(tg)}")
                for t in tg[:5]:
                    print(f"  {C.CY}→{C.W} [{t.get('channel','')}] {t.get('text','')[:80]}")
                if len(tg) > 5:
                    print(f"  {C.DM}  … and {len(tg)-5} more{C.X}")
            mc = scrape.get("dork_misconfigs",[])
            if mc:
                out("info", f"Misconfigurations: {len(mc)}")
                for m in mc[:5]:
                    print(f"  {C.O}→{C.W} {m.get('title','')[:70]}")
                if len(mc) > 5:
                    print(f"  {C.DM}  … and {len(mc)-5} more{C.X}")
            da = result.get("discovered_assets", [])
            if da:
                out("info", f"Reinjected Assets: {len(da)}")
                _pc = {"breach": C.R, "dork": C.O, "scrape": C.P, "hash_crack": C.P}
                for d in da[:15]:
                    pc = _pc.get(d.get("phase",""), C.DM)
                    print(f"  {pc}[{d.get('phase','?')}]{C.W} {d.get('asset','')}  "
                          f"{C.DM}({d.get('qtype','')})  ← {d.get('ref','')[:60]}{C.X}")
                if len(da) > 15:
                    print(f"  {C.DM}  … and {len(da)-15} more — use -o for full export{C.X}")
        if args.output:
            if args.format == "json":   Reporter.to_json(result, args.output)
            elif args.format == "csv":
                Reporter.to_csv(records, args.output)
                REPL._export_csv_extras(result, Reporter._resolve_path(args.output, "csv"))
            elif args.format == "html": Reporter.to_html(result, args.output)
            elif args.format == "md":   Reporter.to_markdown(result, args.output)
            elif args.format == "pdf":  Reporter.to_pdf(result, args.output)
        return

    # Interactive mode
    repl = REPL()
    repl.orc    = orc
    repl.config = config
    repl.db     = db
    repl.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        out("warn", "Interrupted.")
        sys.exit(0)
