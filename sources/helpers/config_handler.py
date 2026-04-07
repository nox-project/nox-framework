"""
sources/helpers/config_handler.py — NOX Framework
Unified credential management via ~/.config/nox-cli/apikeys.json (XDG).

Priority: environment variable → apikeys.json → None
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

# ── Shared constant — import this everywhere instead of a raw string ───
UNIVERSAL_PLACEHOLDER = "INSERT_API_KEY_HERE"

# ── XDG config path ────────────────────────────────────────────────────
_CONFIG_DIR   = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "nox-cli"
_APIKEYS_FILE = _CONFIG_DIR / "apikeys.json"

# ── Complete service registry ──────────────────────────────────────────
# Format: key_name → {"display": str, "public": bool}
# public=True  → no key needed, always active
# public=False → requires a real API key (goes into apikeys.json)
SERVICE_REGISTRY: Dict[str, Dict] = {
    # ── Public / keyless ──────────────────────────────────────────────
    "alienvault_otx_domain":   {"display": "AlienVault OTX (Domain)",   "public": True},
    "alienvault_otx_ip":       {"display": "AlienVault OTX (IP)",        "public": True},
    "alienvault_otx_malware":  {"display": "AlienVault OTX (Malware)",   "public": True},
    "alienvault_otx_user":     {"display": "AlienVault OTX (User)",      "public": True},
    "anubis_subdomains":       {"display": "Anubis Subdomains",          "public": True},
    "bgpview_ip":              {"display": "BGPView IP",                 "public": True},
    "checkleaked":             {"display": "CheckLeaked",                "public": True},
    "crt_sh":                  {"display": "crt.sh",                     "public": True},
    "cve_search":              {"display": "CVE Search",                 "public": True},
    "cxsecurity":              {"display": "CXSecurity",                 "public": True},
    "duckduckgo_api":          {"display": "Google / DDG Dorks",         "public": True},
    "emailrep_io":             {"display": "EmailRep.io",                "public": True},
    "github_users":            {"display": "GitHub Users",               "public": True},
    "gitlab_search":           {"display": "GitLab Search",              "public": True},
    "gravatar":                {"display": "Gravatar",                   "public": True},
    "hackernews_user":         {"display": "HackerNews User",            "public": True},
    "hackertarget_dnslookup":  {"display": "HackerTarget DNS Lookup",    "public": True},
    "hackertarget_hostsearch": {"display": "HackerTarget Host Search",   "public": True},
    "hackertarget_reverseip":  {"display": "HackerTarget Reverse IP",    "public": True},
    "hackertarget_whois":      {"display": "WHOIS (HackerTarget)",       "public": True},
    "hudsonrock_osint":        {"display": "HudsonRock OSINT",           "public": True},
    "ipapi_co":                {"display": "ipapi.co",                   "public": True},
    "ipinfo_io":               {"display": "IPInfo.io",                  "public": True},
    "ipvigilante":             {"display": "IPVigilante",                "public": True},
    "keybase_lookup":          {"display": "Keybase Lookup",             "public": True},
    "keybase_proofs":          {"display": "Keybase Proofs",             "public": True},
    "maltiverse_ip":           {"display": "Maltiverse IP",              "public": True},
    "npm_user":                {"display": "NPM User",                   "public": True},
    "packetstorm":             {"display": "PacketStorm",                "public": True},
    "phishtank_check":         {"display": "PhishTank",                  "public": True},
    "pulsedive":               {"display": "Pulsedive (Free)",           "public": True},
    "pypi_user":               {"display": "PyPI User",                  "public": True},
    "reddit_user":             {"display": "Reddit User",                "public": True},
    "robtex_ip":               {"display": "Robtex IP",                  "public": True},
    "scamwatcher":             {"display": "ScamWatcher",                "public": True},
    "social_scan":             {"display": "Social Scan",                "public": True},
    "sublist3r_api":           {"display": "Sublist3r API",              "public": True},
    "threatcrowd_domain":      {"display": "ThreatCrowd (Domain)",       "public": True},
    "threatcrowd_email":       {"display": "ThreatCrowd (Email)",        "public": True},
    "threatminer_domain":      {"display": "ThreatMiner (Domain)",       "public": True},
    "threatminer_ip":          {"display": "ThreatMiner (IP)",           "public": True},
    "urlscan_search":          {"display": "URLScan.io",                 "public": True},
    "vigilante_pw":            {"display": "Vigilante.pw",               "public": True},
    "wayback_machine":         {"display": "Wayback Machine",            "public": True},
    # ── Private / key-required ────────────────────────────────────────
    "ABSTRACT_API_KEY":         {"display": "Abstract Email Validation", "public": False},
    "ABUSEIPDB_API_KEY":        {"display": "AbuseIPDB",                 "public": False},
    "ANYRUN_API_KEY":           {"display": "Any.run",                   "public": False},
    "BA_API_KEY":               {"display": "BreachAware",               "public": False},
    "BD_API_KEY":               {"display": "BreachDirectory",           "public": False},
    "BINARYEDGE_API_KEY":       {"display": "BinaryEdge",                "public": False},
    "BING_API_KEY":             {"display": "Bing Search API",           "public": False},
    "CENSYS_AUTH_BASE64":       {"display": "Censys",                    "public": False},
    "CIRCL_AUTH_BASE64":        {"display": "CIRCL.lu PDNS",             "public": False},
    "CIT0DAY_API_KEY":          {"display": "Cit0day",                   "public": False},
    "CLEARBIT_API_KEY":         {"display": "Clearbit Enrich",           "public": False},
    "CRIMINALIP_API_KEY":       {"display": "CriminalIP",                "public": False},
    "DEHASHED_AUTH_BASE64":     {"display": "Dehashed",                  "public": False},
    "DNSDB_API_KEY":            {"display": "DNSDB Passive DNS",         "public": False},
    "DT_AUTH_BASE64":           {"display": "DomainTools WHOIS",         "public": False},
    "EXTREME_API_KEY":          {"display": "Extreme IP Lookup",         "public": False},
    "FLP_API_KEY":              {"display": "FraudLabsPro",              "public": False},
    "FOFA_API_KEY":             {"display": "FOFA",                      "public": False},
    "FOFA_EMAIL":              {"display": "FOFA (account email)",      "public": False},
    "FULLCONTACT_API_KEY":      {"display": "FullContact",               "public": False},
    "GITHUB_TOKEN":             {"display": "GitHub (Code/Repo Search)", "public": False},
    "GOOGLE_API_KEY":           {"display": "Google Safe Browsing",      "public": False},
    "GOOGLE_CX_KEY":            {"display": "Google Custom Search (API key)", "public": False},
    "GOOGLE_CX_ID":            {"display": "Google Custom Search (CX ID)",   "public": False},
    "GREYNOISE_API_KEY":        {"display": "GreyNoise",                 "public": False},
    "HASHES_API_KEY":           {"display": "Hashes.org",                "public": False},
    "HIBP_API_KEY":             {"display": "HaveIBeenPwned",            "public": False},
    "HIPPO_API_KEY":            {"display": "EmailHippo",                "public": False},
    "HUNTER_API_KEY":           {"display": "Hunter.io",                 "public": False},
    "HYBRID_API_KEY":           {"display": "Hybrid Analysis",           "public": False},
    "INTELX_API_KEY":           {"display": "IntelX",                    "public": False},
    "INTEZER_API_KEY":          {"display": "Intezer",                   "public": False},
    "IPDATA_API_KEY":           {"display": "IPData.co",                 "public": False},
    "IPGEO_API_KEY":            {"display": "IPGeolocation.io",          "public": False},
    "IPINFODB_API_KEY":         {"display": "IPInfoDB",                  "public": False},
    "IPQS_API_KEY":             {"display": "IPQualityScore",            "public": False},
    "IPSTACK_API_KEY":          {"display": "IPStack",                   "public": False},
    "JOE_API_KEY":              {"display": "Joe Sandbox",               "public": False},
    "LEAKCHECK_API_KEY":        {"display": "LeakCheck",                 "public": False},
    "LEAKIX_API_KEY":           {"display": "LeakIX",                    "public": False},
    "LEAKSTATS_API_KEY":        {"display": "LeakStats.pw",              "public": False},
    "MAILBOX_API_KEY":          {"display": "Mailboxlayer",              "public": False},
    "MALSHARE_API_KEY":         {"display": "MalShare",                  "public": False},
    "METADEFENDER_API_KEY":     {"display": "MetaDefender",              "public": False},
    "MISP_API_KEY":             {"display": "MISP",                      "public": False},
    "NUMVERIFY_API_KEY":        {"display": "Numverify",                 "public": False},
    "ONYPHE_API_KEY":           {"display": "Onyphe",                    "public": False},
    "PASSIVETOTAL_AUTH_BASE64": {"display": "PassiveTotal / RiskIQ",     "public": False},
    "PIPL_API_KEY":             {"display": "Pipl",                      "public": False},
    "PULSEDIVE_API_KEY":        {"display": "Pulsedive (Premium)",       "public": False},
    "RF_TOKEN":                 {"display": "Recorded Future",           "public": False},
    "SECURITYTRAILS_API_KEY":   {"display": "SecurityTrails",            "public": False},
    "SHODAN_API_KEY":           {"display": "Shodan",                    "public": False},
    "SNUSBASE_API_KEY":         {"display": "Snusbase",                  "public": False},
    "SPYCLOUD_API_KEY":         {"display": "SpyCloud",                  "public": False},
    "SPYONWEB_API_KEY":         {"display": "SpyOnWeb",                  "public": False},
    "SPYSE_API_KEY":            {"display": "Spyse",                     "public": False},
    "TC_API_KEY":               {"display": "ThreatConnect",             "public": False},
    "TINES_API_KEY":            {"display": "Tines Breach",              "public": False},
    "TP_API_KEY":               {"display": "ThreatPortal",              "public": False},
    "TWITTER_BEARER_TOKEN":     {"display": "Twitter / X API v2",        "public": False},
    "URLVOID_API_KEY":          {"display": "URLVoid",                   "public": False},
    "VIEWDNS_API_KEY":          {"display": "ViewDNS",                   "public": False},
    "VIRUSTOTAL_API_KEY":       {"display": "VirusTotal",                "public": False},
    "VULNERS_API_KEY":          {"display": "Vulners",                   "public": False},
    "WF_API_KEY":               {"display": "WhoisFreaks",               "public": False},
    "WHOISXML_API_KEY":         {"display": "WhoisXML API",              "public": False},
    "WHOXY_API_KEY":            {"display": "Whoxy WHOIS",               "public": False},
    "ZEROBOUNCE_API_KEY":       {"display": "ZeroBounce",                "public": False},
    "ZOOMEYE_API_KEY":          {"display": "ZoomEye",                   "public": False},
}

_PRIVATE_KEYS = {k: v for k, v in SERVICE_REGISTRY.items() if not v["public"]}


# ── Store helpers ──────────────────────────────────────────────────────

def _default_store() -> Dict[str, str]:
    """Return a dict of all private service keys set to UNIVERSAL_PLACEHOLDER."""
    return {k: UNIVERSAL_PLACEHOLDER for k in _PRIVATE_KEYS}


def _write_store(data: Dict[str, str]) -> None:
    """Atomically write data to apikeys.json with chmod 0600."""
    try:
        _CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        _CONFIG_DIR.chmod(0o700)
        tmp = _APIKEYS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=4, sort_keys=True), encoding="utf-8")
        tmp.replace(_APIKEYS_FILE)
        _APIKEYS_FILE.chmod(0o600)
    except PermissionError as exc:
        raise RuntimeError(f"[config_handler] Cannot write {_APIKEYS_FILE}: {exc}") from exc


def _load_store() -> Dict[str, str]:
    """Load apikeys.json, creating it with defaults if absent. Self-heals on corrupt files."""
    _CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    _CONFIG_DIR.chmod(0o700)
    if not _APIKEYS_FILE.exists():
        print("  \033[92m[+]\033[0m Initializing NOX Environment in ~/.config/nox-cli/")
        _write_store(_default_store())
        return _default_store()
    try:
        text = _APIKEYS_FILE.read_text(encoding="utf-8").strip()
        if not text:
            raise json.JSONDecodeError("Empty file", "", 0)
        data = json.loads(text)
        if not isinstance(data, dict):
            raise json.JSONDecodeError("Root is not a JSON object", text, 0)
        # Back-fill keys added in newer versions
        new_keys = {k: UNIVERSAL_PLACEHOLDER for k in _PRIVATE_KEYS if k not in data}
        if new_keys:
            data.update(new_keys)
            _write_store(data)
        return data
    except json.JSONDecodeError:
        bak = _APIKEYS_FILE.with_suffix(".json.bak")
        _APIKEYS_FILE.rename(bak)
        print(f"[!] Malformed apikeys.json detected — backed up to {bak.name} and reset to defaults.")
        defaults = _default_store()
        _write_store(defaults)
        return defaults
    except PermissionError as exc:
        raise RuntimeError(f"[config_handler] Cannot read {_APIKEYS_FILE}: {exc}") from exc


# ── ConfigManager ──────────────────────────────────────────────────────

class ConfigManager:
    """
    Unified API key manager.

    Resolution order per key:
      1. Environment variable (exact key name)
      2. ~/.config/nox-cli/apikeys.json
      3. Returns None if value equals UNIVERSAL_PLACEHOLDER or is absent
    """

    _cache: Dict[str, Optional[str]] = {}
    _store: Optional[Dict[str, str]] = None

    @classmethod
    def _get_store(cls) -> Dict[str, str]:
        if cls._store is None:
            cls._store = _load_store()
        return cls._store

    @classmethod
    def get_key(cls, key_name: str) -> Optional[str]:
        """Return the configured value, or None if missing/placeholder."""
        if key_name in cls._cache:
            return cls._cache[key_name]
        val = os.environ.get(key_name, "") or cls._get_store().get(key_name, "")
        result = None if (not val or val == UNIVERSAL_PLACEHOLDER) else val
        cls._cache[key_name] = result
        return result

    # Backward-compatible alias used by nox.py internals
    get = get_key

    @classmethod
    def set(cls, key_name: str, value: str) -> None:
        """Persist a key to apikeys.json and update the in-memory cache."""
        store = cls._get_store()
        store[key_name] = value
        _write_store(store)
        cls._cache[key_name] = None if value == UNIVERSAL_PLACEHOLDER else value

    @classmethod
    def config_path(cls) -> Path:
        return _APIKEYS_FILE
