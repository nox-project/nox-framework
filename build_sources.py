"""
build_sources.py — NOX Framework · Production Source Builder
Generates individual JSON plugin files for every intelligence source.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ── Shared placeholder constant ────────────────────────────────────────
# Import from config_handler so the string is defined in exactly one place.
# Fall back to the literal if the helper isn't on sys.path yet (e.g. bare
# invocation before sources/ exists).
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from sources.helpers.config_handler import (
        UNIVERSAL_PLACEHOLDER,
        _APIKEYS_FILE,
        _default_store,
        _write_store,
    )
except ImportError:
    UNIVERSAL_PLACEHOLDER = "INSERT_API_KEY_HERE"
    _APIKEYS_FILE = None
    _default_store = None
    _write_store = None

# ---------------------------------------------------------------------------
# Pydantic Schema
# ---------------------------------------------------------------------------

HttpMethod   = Literal["GET", "POST", "PUT", "DELETE"]
InputType    = Literal["email", "ip", "domain", "hash", "username", "phone", "url", "cve", "any"]
ReliabilityScore = Literal[1, 2, 3, 4, 5]


class SourceConfig(BaseModel):
    # ── Mandatory core ──────────────────────────────────────────────────────
    name:          str
    category:      str
    endpoint:      str
    method:        HttpMethod
    requires_auth: bool
    selectors:     Dict[str, str]

    # ── Request plumbing ────────────────────────────────────────────────────
    rate_limit:       float                    = 1.0
    headers:          Dict[str, str]           = Field(default_factory=dict)
    payload_template: Optional[Dict[str, Any]] = None
    api_key_slots:    List[str]                = Field(default_factory=list)

    # ── Typing & pivoting ───────────────────────────────────────────────────
    input_type:       InputType                = "any"
    output_type:      List[str]                = Field(default_factory=list)
    normalization_map: Dict[str, str]          = Field(default_factory=dict)
    tags:             List[str]                = Field(default_factory=list)

    # ── Resilience ──────────────────────────────────────────────────────────
    health_check_url:  str
    expected_status:   int                     = 200
    reliability_score: ReliabilityScore        = 5
    is_volatile:       Optional[bool]          = None          # omitted when False
    bypass_required:   Optional[List[str]]     = None          # omitted when empty
    user_agent_type:   Optional[str]           = None          # omitted when absent
    backup_endpoints:  List[str]               = Field(default_factory=list)
    # H2: optional confidence override — when set, takes precedence over formula
    confidence:        Optional[float]         = None

    @field_validator("reliability_score")
    @classmethod
    def _score_range(cls, v: int) -> int:
        if not 1 <= v <= 5:
            raise ValueError("reliability_score must be 1–5")
        return v

    @model_validator(mode="after")
    def _validate_source(self) -> "SourceConfig":
        # H1: GET endpoints must contain {target} placeholder
        if self.method.upper() == "GET" and "{target}" not in self.endpoint:
            raise ValueError(
                f"'{self.name}': GET endpoint must contain {{target}} placeholder: {self.endpoint!r}"
            )
        # L3: volatile sources must have reliability_score ≤ 4 (was > 3, now > 4)
        if self.is_volatile and self.reliability_score > 4:
            raise ValueError(
                f"'{self.name}': is_volatile sources must have reliability_score ≤ 4"
            )
        return self

    def to_json(self) -> str:
        data = self.model_dump(exclude_none=True)
        # Drop is_volatile / bypass_required / user_agent_type when falsy
        for key in ("is_volatile", "bypass_required", "user_agent_type"):
            if not data.get(key):
                data.pop(key, None)
        # H2: use explicit confidence if set, otherwise derive from reliability_score
        data["confidence"] = (
            round(self.confidence, 2)
            if self.confidence is not None
            else round(0.4 + (self.reliability_score - 1) * 0.15, 2)
        )
        return json.dumps(data, indent=4)


# ---------------------------------------------------------------------------
# Builder helpers  (_base → requires_auth=False, _auth → requires_auth=True)
# ---------------------------------------------------------------------------

def _mk(
    name: str, category: str, endpoint: str, method: HttpMethod,
    selectors: Dict[str, str], *,
    requires_auth: bool,
    rate_limit: float = 1.0,
    headers: Optional[Dict[str, str]] = None,
    payload_template: Optional[Dict[str, Any]] = None,
    api_key_slots: Optional[List[str]] = None,
    input_type: InputType = "any",
    output_type: Optional[List[str]] = None,
    normalization_map: Optional[Dict[str, str]] = None,
    tags: Optional[List[str]] = None,
    health_check_url: Optional[str] = None,
    expected_status: int = 200,
    reliability_score: ReliabilityScore = 5,
    is_volatile: bool = False,
    bypass_required: Optional[List[str]] = None,
    user_agent_type: Optional[str] = None,
    backup_endpoints: Optional[List[str]] = None,
) -> SourceConfig:
    return SourceConfig(
        name=name, category=category, endpoint=endpoint, method=method,
        requires_auth=requires_auth, selectors=selectors,
        rate_limit=rate_limit,
        headers=headers or {},
        payload_template=payload_template,
        api_key_slots=api_key_slots or [],
        input_type=input_type,
        output_type=output_type or [],
        normalization_map=normalization_map or {},
        tags=tags or [],
        health_check_url=health_check_url or endpoint.split("{")[0].rstrip("/?"),
        expected_status=expected_status,
        reliability_score=reliability_score,
        is_volatile=is_volatile or None,
        bypass_required=bypass_required or None,
        user_agent_type=user_agent_type,
        backup_endpoints=backup_endpoints or [],
    )


def _base(name, category, endpoint, method, selectors, **kw) -> SourceConfig:
    return _mk(name, category, endpoint, method, selectors, requires_auth=False, **kw)


def _auth(name, category, endpoint, method, selectors, **kw) -> SourceConfig:
    return _mk(name, category, endpoint, method, selectors, requires_auth=True, **kw)


# ---------------------------------------------------------------------------
# FREE / PUBLIC SOURCES
# ---------------------------------------------------------------------------

FREE_PUBLIC_SOURCES: List[SourceConfig] = [

    _base("crt_sh", "certificate_transparency",
          "https://crt.sh/?q={target}&output=json", "GET",
          {"domains": "$.*.name_value"},
          headers={"Accept": "application/json"},
          input_type="domain", output_type=["domain"],
          normalization_map={"name_value": "domain"},
          tags=["passive", "fast"],
          health_check_url="https://crt.sh", reliability_score=5),

    _base("hackertarget_hostsearch", "dns_recon",
          "https://api.hackertarget.com/hostsearch/?q={target}", "GET",
          {"hosts": "text_lines"},
          input_type="domain", output_type=["ip", "domain"],
          tags=["passive", "fast"],
          health_check_url="https://api.hackertarget.com", reliability_score=4),

    _base("hackertarget_reverseip", "dns_recon",
          "https://api.hackertarget.com/reverseiplookup/?q={target}", "GET",
          {"domains": "text_lines"},
          input_type="ip", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://api.hackertarget.com", reliability_score=4),

    _base("hackertarget_dnslookup", "dns_recon",
          "https://api.hackertarget.com/dnslookup/?q={target}", "GET",
          {"records": "text_lines"},
          input_type="domain", output_type=["ip"],
          tags=["passive", "fast"],
          health_check_url="https://api.hackertarget.com", reliability_score=4),

    _base("hackertarget_whois", "whois",
          "https://api.hackertarget.com/whois/?q={target}", "GET",
          {"raw": "text_lines"},
          input_type="domain", output_type=["email", "domain"],
          tags=["passive"],
          health_check_url="https://api.hackertarget.com", reliability_score=4),

    _base("alienvault_otx_domain", "threat_intel",
          "https://otx.alienvault.com/api/v1/indicators/domain/{target}/general", "GET",
          {"pulses": "$.pulse_info.count", "tags": "$.tags"},
          input_type="domain", output_type=["domain", "ip"],
          tags=["passive", "threat"],
          health_check_url="https://otx.alienvault.com", reliability_score=5),

    _base("alienvault_otx_ip", "threat_intel",
          "https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general", "GET",
          {"asn": "$.asn", "country": "$.country_name"},
          input_type="ip", output_type=["domain"],
          tags=["passive", "threat"],
          health_check_url="https://otx.alienvault.com", reliability_score=5),

    _base("alienvault_otx_malware", "threat_intel",
          "https://otx.alienvault.com/api/v1/indicators/file/{target}/analysis", "GET",
          {"malware": "$.analysis.malware"},
          input_type="hash", output_type=["hash"],
          tags=["passive", "threat"],
          health_check_url="https://otx.alienvault.com", reliability_score=5),

    _base("alienvault_otx_user", "social",
          "https://otx.alienvault.com/api/v1/users/{target}/general", "GET",
          {"pulses": "$.pulse_count"},
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://otx.alienvault.com", reliability_score=5),

    _base("urlscan_search", "url_analysis",
          "https://urlscan.io/api/v1/search/?q={target}", "GET",
          {"urls": "$.results[*].page.url"},
          rate_limit=2.0,
          input_type="domain", output_type=["url", "ip", "domain"],
          tags=["passive"],
          health_check_url="https://urlscan.io", reliability_score=5),

    _base("threatcrowd_email", "threat_intel",
          "https://www.threatcrowd.org/searchApi/v2/email/report/?email={target}", "GET",
          {"domains": "$.domains"},
          rate_limit=5.0,
          input_type="email", output_type=["domain"],
          tags=["passive", "threat"],
          health_check_url="https://www.threatcrowd.org", reliability_score=3,
          is_volatile=True, bypass_required=["cloudflare"], user_agent_type="browser"),

    _base("threatcrowd_domain", "threat_intel",
          "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}", "GET",
          {"ips": "$.resolutions[*].ip_address"},
          rate_limit=5.0,
          input_type="domain", output_type=["ip"],
          tags=["passive", "threat"],
          health_check_url="https://www.threatcrowd.org", reliability_score=3,
          is_volatile=True, bypass_required=["cloudflare"], user_agent_type="browser"),

    _base("pulsedive", "threat_intel",
          "https://pulsedive.com/api/info.php?indicator={target}", "GET",
          {"risk": "$.risk", "threats": "$.threats"},
          rate_limit=2.0,
          input_type="any", output_type=["domain", "ip"],
          tags=["passive", "threat"],
          health_check_url="https://pulsedive.com", reliability_score=4),

    _base("hudsonrock_osint", "breach_data",
          "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?username={target}", "GET",
          {"stealers": "$.stealers"},
          input_type="username", output_type=["email", "domain"],
          normalization_map={"stealers": "breach_record"},
          tags=["passive", "stealth"],
          health_check_url="https://cavalier.hudsonrock.com", reliability_score=4),

    _base("ipinfo_io", "geolocation",
          "https://ipinfo.io/{target}/json", "GET",
          {"org": "$.org", "city": "$.city"},
          input_type="ip", output_type=["domain"],
          normalization_map={"org": "asn_org", "city": "geo_city"},
          tags=["passive", "fast"],
          health_check_url="https://ipinfo.io", reliability_score=5),

    _base("ipapi_co", "geolocation",
          "https://ipapi.co/{target}/json/", "GET",
          {"asn": "$.asn", "org": "$.org"},
          headers={"User-Agent": "Mozilla/5.0"},
          input_type="ip", output_type=["domain"],
          normalization_map={"asn": "asn_number", "org": "asn_org"},
          tags=["passive", "fast"],
          health_check_url="https://ipapi.co", reliability_score=4),

    _base("bgpview_ip", "network",
          "https://api.bgpview.io/ip/{target}", "GET",
          {"prefixes": "$.data.prefixes[*].prefix"},
          input_type="ip", output_type=["ip"],
          tags=["passive", "infrastructure"],
          health_check_url="https://api.bgpview.io", reliability_score=4),

    _base("emailrep_io", "email_rep",
          "https://emailrep.io/{target}", "GET",
          {"reputation": "$.reputation"},
          rate_limit=2.0,
          input_type="email", output_type=["email"],
          normalization_map={"reputation": "email_reputation"},
          tags=["passive", "fast"],
          health_check_url="https://emailrep.io", reliability_score=4),

    _base("github_users", "social",
          "https://api.github.com/users/{target}", "GET",
          {"bio": "$.bio", "blog": "$.blog"},
          rate_limit=2.0, headers={"User-Agent": "NOX"},
          input_type="username", output_type=["username", "domain"],
          tags=["passive", "fast"],
          health_check_url="https://api.github.com", reliability_score=5),

    _base("reddit_user", "social",
          "https://www.reddit.com/user/{target}/about.json", "GET",
          {"karma": "$.data.total_karma"},
          rate_limit=2.0, headers={"User-Agent": "NOX"},
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://www.reddit.com", reliability_score=4),

    _base("gravatar", "social",
          "https://www.gravatar.com/{target}.json", "GET",
          {"name": "$.entry[0].displayName"},
          rate_limit=2.0,
          input_type="email", output_type=["username"],
          tags=["passive"],
          health_check_url="https://www.gravatar.com", reliability_score=4),

    _base("anubis_subdomains", "dns_recon",
          "https://jldc.me/anubis/subdomains/{target}", "GET",
          {"subdomains": "$.*"},
          input_type="domain", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://jldc.me", reliability_score=3, is_volatile=True),

    _base("sublist3r_api", "dns_recon",
          "https://api.sublist3r.com/search.php?domain={target}", "GET",
          {"subdomains": "$.*"},
          input_type="domain", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://api.sublist3r.com", reliability_score=3, is_volatile=True),

    _base("keybase_lookup", "social",
          "https://keybase.io/_/api/1.0/user/lookup.json?username={target}", "GET",
          {"id": "$.them[0].id"},
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://keybase.io", reliability_score=4),

    _base("keybase_proofs", "social",
          "https://keybase.io/_/api/1.0/user/lookup.json?usernames={target}", "GET",
          {"proofs": "$.them[0].proofs_summary.all[*].namestr"},
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://keybase.io", reliability_score=4),

    _base("maltiverse_ip", "threat_intel",
          "https://api.maltiverse.com/ip/{target}", "GET",
          {"classification": "$.classification"},
          input_type="ip", output_type=["ip"],
          tags=["passive", "threat"],
          health_check_url="https://api.maltiverse.com", reliability_score=3),

    _base("threatminer_domain", "threat_intel",
          "https://api.threatminer.org/v2/domain.php?q={target}&rt=1", "GET",
          {"ips": "$.results"},
          input_type="domain", output_type=["ip"],
          tags=["passive", "threat"],
          health_check_url="https://api.threatminer.org", reliability_score=3, is_volatile=True),

    _base("threatminer_ip", "threat_intel",
          "https://api.threatminer.org/v2/host.php?q={target}&rt=1", "GET",
          {"urls": "$.results"},
          input_type="ip", output_type=["url"],
          tags=["passive", "threat"],
          health_check_url="https://api.threatminer.org", reliability_score=3, is_volatile=True),

    _base("robtex_ip", "network",
          "https://freeapi.robtex.com/ipquery/{target}", "GET",
          {"as": "$.asname"},
          input_type="ip", output_type=["domain"],
          tags=["passive", "fast"],
          health_check_url="https://freeapi.robtex.com", reliability_score=4),

    _base("wayback_machine", "archive",
          "https://archive.org/wayback/available?url={target}", "GET",
          {"snapshot": "$.archived_snapshots.closest.url"},
          input_type="url", output_type=["url"],
          tags=["passive"],
          health_check_url="https://archive.org", reliability_score=5),

    _base("ipvigilante", "geolocation",
          "https://ipvigilante.com/json/{target}", "GET",
          {"city": "$.data.city_name"},
          input_type="ip", output_type=["ip"],
          tags=["passive"],
          health_check_url="https://ipvigilante.com", reliability_score=3, is_volatile=True),

    _base("pypi_user", "social",
          "https://pypi.org/pypi/{target}/json", "GET",
          {"info": "$.info"},
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://pypi.org", reliability_score=5),

    _base("npm_user", "social",
          "https://registry.npmjs.org/-/v1/search?text=maintainer:{target}", "GET",
          {"packages": "$.objects[*].package.name"},
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://registry.npmjs.org", reliability_score=5),

    _base("gitlab_search", "social",
          "https://gitlab.com/api/v4/users?username={target}", "GET",
          {"id": "$.[*].id"},
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://gitlab.com", reliability_score=5),

    _base("hackernews_user", "social",
          "https://hacker-news.firebaseio.com/v0/user/{target}.json", "GET",
          {"karma": "$.karma"},
          input_type="username", output_type=["username"],
          tags=["passive", "fast"],
          health_check_url="https://hacker-news.firebaseio.com", reliability_score=5),

    _base("scamwatcher", "threat_intel",
          "https://www.scamwatcher.com/scam/search?q={target}", "GET",
          {"results": "text_lines"},
          headers={"User-Agent": "Mozilla/5.0"},
          input_type="any", output_type=["domain"],
          tags=["passive", "threat"],
          health_check_url="https://www.scamwatcher.com", reliability_score=2, is_volatile=True),

    _base("phishtank_check", "threat_intel",
          "https://checkurl.phishtank.com/checkurl/", "POST",
          {"in_database": "$.results.in_database"},
          input_type="url", output_type=["url"],
          payload_template={"url": "{target}", "format": "json"},
          tags=["passive", "threat"],
          health_check_url="https://checkurl.phishtank.com", reliability_score=4),

    _base("duckduckgo_api", "search",
          "https://api.duckduckgo.com/?q={target}&format=json", "GET",
          {"abstract": "$.Abstract"},
          input_type="any", output_type=["url"],
          tags=["passive", "fast"],
          health_check_url="https://api.duckduckgo.com", reliability_score=5),

    _base("cve_search", "vulns",
          "https://cve.circl.lu/api/cve/{target}", "GET",
          {"summary": "$.summary"},
          input_type="cve", output_type=["cve"],
          normalization_map={"summary": "vuln_description"},
          tags=["passive"],
          health_check_url="https://cve.circl.lu", reliability_score=4),

    _base("cxsecurity", "vulns",
          "https://cxsecurity.com/cvejson.php?cve={target}", "GET",
          {"title": "$.title"},
          input_type="cve", output_type=["cve"],
          tags=["passive"],
          health_check_url="https://cxsecurity.com", reliability_score=3, is_volatile=True),

    _base("packetstorm", "vulns",
          "https://packetstormsecurity.com/search/?q={target}", "GET",
          {"results": "text_lines"},
          input_type="any", output_type=["url"],
          tags=["passive"],
          health_check_url="https://packetstormsecurity.com", reliability_score=4),

    _base("checkleaked", "breaches",
          "https://api.checkleaked.cc/check/{target}", "GET",
          {"found": "$.found"},
          input_type="email", output_type=["email"],
          tags=["passive", "stealth"],
          health_check_url="https://api.checkleaked.cc", reliability_score=2, is_volatile=True,
          backup_endpoints=["https://checkleaked.cc/api/check/{target}"]),

    _base("scylla_sh_search", "breaches",
          "https://scylla.sh/search?q={target}", "GET",
          {"results": "$.*"},
          input_type="email", output_type=["email", "domain"],
          tags=["passive", "stealth"],
          health_check_url="https://scylla.sh", reliability_score=2, is_volatile=True,
          backup_endpoints=["https://scylla.sh/api/search?q={target}"]),

    _base("vigilante_pw", "breaches",
          "https://vigilante.pw/api/search?q={target}", "GET",
          {"results": "$.results"},
          input_type="email", output_type=["email"],
          tags=["passive", "stealth"],
          health_check_url="https://vigilante.pw", reliability_score=2, is_volatile=True),
]

# ---------------------------------------------------------------------------
# AUTHENTICATED / PREMIUM SOURCES
# ---------------------------------------------------------------------------

AUTHENTICATED_PREMIUM_SOURCES: List[SourceConfig] = [

    # ── Scanners ─────────────────────────────────────────────────────────────

    _auth("shodan_host", "scanners",
          "https://api.shodan.io/shodan/host/{target}?key={SHODAN_API_KEY}", "GET",
          {"ports": "$.ports", "vulns": "$.vulns"},
          api_key_slots=["{SHODAN_API_KEY}"],
          input_type="ip", output_type=["domain", "vuln"],
          normalization_map={"ports": "open_ports", "vulns": "cve_list"},
          tags=["passive", "infrastructure"],
          health_check_url="https://api.shodan.io", reliability_score=5),

    _auth("shodan_search", "scanners",
          "https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={target}", "GET",
          {"ips": "$.matches[*].ip_str"},
          api_key_slots=["{SHODAN_API_KEY}"],
          input_type="domain", output_type=["ip"],
          normalization_map={"ip_str": "ip_address"},
          tags=["passive", "infrastructure"],
          health_check_url="https://api.shodan.io", reliability_score=5),

    _auth("shodan_dns", "dns_recon",
          "https://api.shodan.io/dns/domain/{target}?key={SHODAN_API_KEY}", "GET",
          {"subdomains": "$.subdomains"},
          api_key_slots=["{SHODAN_API_KEY}"],
          input_type="domain", output_type=["domain"],
          tags=["passive", "infrastructure"],
          health_check_url="https://api.shodan.io", reliability_score=5),

    _auth("shodan_exploits", "vulns",
          "https://exploits.shodan.io/api/search?query={target}&key={SHODAN_API_KEY}", "GET",
          {"total": "$.total"},
          api_key_slots=["{SHODAN_API_KEY}"],
          input_type="cve", output_type=["cve"],
          tags=["passive"],
          health_check_url="https://exploits.shodan.io", reliability_score=5),

    _auth("censys_hosts", "scanners",
          "https://search.censys.io/api/v2/hosts/search?q={target}", "GET",
          {"results": "$.result.hits[*].ip"},
          headers={"Authorization": "Basic {CENSYS_AUTH_BASE64}"},
          api_key_slots=["{CENSYS_AUTH_BASE64}"],
          input_type="domain", output_type=["ip"],
          normalization_map={"ip": "ip_address"},
          tags=["passive", "infrastructure"],
          health_check_url="https://search.censys.io", reliability_score=5),

    _auth("binaryedge_exposed", "scanners",
          "https://api.binaryedge.io/v2/query/ip/{target}", "GET",
          {"ports": "$.events[*].port"},
          headers={"X-Key": "{BINARYEDGE_API_KEY}"},
          api_key_slots=["{BINARYEDGE_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"port": "open_port"},
          tags=["passive", "infrastructure"],
          health_check_url="https://api.binaryedge.io", reliability_score=4),

    _auth("binaryedge_dns", "dns_recon",
          "https://api.binaryedge.io/v2/query/domains/subdomain/{target}", "GET",
          {"subs": "$.subs"},
          headers={"X-Key": "{BINARYEDGE_API_KEY}"},
          api_key_slots=["{BINARYEDGE_API_KEY}"],
          input_type="domain", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://api.binaryedge.io", reliability_score=4),

    _auth("zoomeye_host", "scanners",
          "https://api.zoomeye.org/host/search?query={target}", "GET",
          {"hosts": "$.matches[*].ip"},
          headers={"API-KEY": "{ZOOMEYE_API_KEY}"},
          api_key_slots=["{ZOOMEYE_API_KEY}"],
          input_type="domain", output_type=["ip"],
          tags=["passive", "infrastructure"],
          health_check_url="https://api.zoomeye.org", reliability_score=4),

    _auth("fofa_info", "scanners",
          "https://fofa.info/api/v1/search/all?email={FOFA_EMAIL}&key={FOFA_API_KEY}&qbase64={target}", "GET",
          {"results": "$.results"},
          api_key_slots=["{FOFA_API_KEY}", "{FOFA_EMAIL}"],
          input_type="domain", output_type=["ip", "domain"],
          tags=["passive", "infrastructure"],
          health_check_url="https://fofa.info", reliability_score=4),

    _auth("spyse_domain", "scanners",
          "https://api.spyse.com/v1/domain/details/{target}", "GET",
          {"asn": "$.data.asn"},
          headers={"Authorization": "Bearer {SPYSE_API_KEY}"},
          api_key_slots=["{SPYSE_API_KEY}"],
          input_type="domain", output_type=["ip"],
          tags=["passive"],
          health_check_url="https://api.spyse.com", reliability_score=3),

    _auth("spyse_ip", "scanners",
          "https://api.spyse.com/v1/ip/details/{target}", "GET",
          {"geo": "$.data.geo"},
          headers={"Authorization": "Bearer {SPYSE_API_KEY}"},
          api_key_slots=["{SPYSE_API_KEY}"],
          input_type="ip", output_type=["ip"],
          tags=["passive"],
          health_check_url="https://api.spyse.com", reliability_score=3),

    _auth("onyphe_datascan", "scanners",
          "https://www.onyphe.io/api/v2/simple/datascan/{target}", "GET",
          {"results": "$.results"},
          headers={"Authorization": "apikey {ONYPHE_API_KEY}"},
          api_key_slots=["{ONYPHE_API_KEY}"],
          input_type="ip", output_type=["ip", "domain"],
          tags=["passive", "infrastructure"],
          health_check_url="https://www.onyphe.io", reliability_score=4),

    _auth("criminalip_asset", "scanners",
          "https://api.criminalip.io/v1/asset/ip/report?ip={target}", "GET",
          {"score": "$.score"},
          headers={"x-api-key": "{CRIMINALIP_API_KEY}"},
          api_key_slots=["{CRIMINALIP_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"score": "risk_score"},
          tags=["passive", "threat"],
          health_check_url="https://api.criminalip.io", reliability_score=4),

    # ── Threat Intel ─────────────────────────────────────────────────────────

    _auth("virustotal_domain", "threat_intel",
          "https://www.virustotal.com/api/v3/domains/{target}", "GET",
          {"malicious": "$.data.attributes.last_analysis_stats.malicious"},
          rate_limit=15.0, headers={"x-apikey": "{VIRUSTOTAL_API_KEY}"},
          api_key_slots=["{VIRUSTOTAL_API_KEY}"],
          input_type="domain", output_type=["domain"],
          normalization_map={"malicious": "malicious_count"},
          tags=["passive", "threat"],
          health_check_url="https://www.virustotal.com", reliability_score=5),

    _auth("virustotal_ip", "threat_intel",
          "https://www.virustotal.com/api/v3/ip_addresses/{target}", "GET",
          {"reputation": "$.data.attributes.reputation"},
          rate_limit=15.0, headers={"x-apikey": "{VIRUSTOTAL_API_KEY}"},
          api_key_slots=["{VIRUSTOTAL_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"reputation": "vt_reputation"},
          tags=["passive", "threat"],
          health_check_url="https://www.virustotal.com", reliability_score=5),

    _auth("greynoise_community", "threat_intel",
          "https://api.greynoise.io/v3/community/{target}", "GET",
          {"noise": "$.noise", "classification": "$.classification"},
          headers={"key": "{GREYNOISE_API_KEY}"},
          api_key_slots=["{GREYNOISE_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"noise": "is_noise", "classification": "threat_class"},
          tags=["passive", "threat"],
          health_check_url="https://api.greynoise.io", reliability_score=5),

    _auth("abuseipdb", "threat_intel",
          "https://api.abuseipdb.com/api/v2/check?ipAddress={target}", "GET",
          {"score": "$.data.abuseConfidenceScore"},
          headers={"Key": "{ABUSEIPDB_API_KEY}"},
          api_key_slots=["{ABUSEIPDB_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"abuseConfidenceScore": "abuse_score"},
          tags=["passive", "threat"],
          health_check_url="https://api.abuseipdb.com", reliability_score=5),

    _auth("pulsedive_analyze", "threat_intel",
          "https://pulsedive.com/api/analyze.php?value={target}", "GET",
          {"risk": "$.risk"},
          headers={"key": "{PULSEDIVE_API_KEY}"},
          api_key_slots=["{PULSEDIVE_API_KEY}"],
          input_type="any", output_type=["ip", "domain"],
          normalization_map={"risk": "risk_level"},
          tags=["passive", "threat"],
          health_check_url="https://pulsedive.com", reliability_score=4),

    _auth("metadefender_ip", "threat_intel",
          "https://api.metadefender.com/v4/ip/{target}", "GET",
          {"lookup": "$.lookup_results"},
          headers={"apikey": "{METADEFENDER_API_KEY}"},
          api_key_slots=["{METADEFENDER_API_KEY}"],
          input_type="ip", output_type=["ip"],
          tags=["passive", "threat"],
          health_check_url="https://api.metadefender.com", reliability_score=4),

    _auth("recordedfuture_ip", "threat_intel",
          "https://api.recordedfuture.com/v2/ip/{target}", "GET",
          {"risk": "$.data.risk.score"},
          headers={"X-RFToken": "{RF_TOKEN}"},
          api_key_slots=["{RF_TOKEN}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"score": "rf_risk_score"},
          tags=["passive", "threat"],
          health_check_url="https://api.recordedfuture.com", reliability_score=5),

    _auth("vulners_search", "threat_intel",
          "https://vulners.com/api/v3/search/lucene/?query={target}", "GET",
          {"results": "$.data.search[*]._source.title"},
          headers={"X-Vulners-Api-Key": "{VULNERS_API_KEY}"},
          api_key_slots=["{VULNERS_API_KEY}"],
          input_type="cve", output_type=["cve"],
          tags=["passive"],
          health_check_url="https://vulners.com", reliability_score=4),

    _auth("urlvoid", "threat_intel",
          "https://api.urlvoid.com/api1000/{URLVOID_API_KEY}/host/{target}", "GET",
          {"detections": "$.detections"},
          api_key_slots=["{URLVOID_API_KEY}"],
          input_type="domain", output_type=["domain"],
          tags=["passive", "threat"],
          health_check_url="https://api.urlvoid.com", reliability_score=4),

    _auth("fraudlabspro", "threat_intel",
          "https://api.fraudlabspro.com/v1/ip/check?key={FLP_API_KEY}&ip={target}", "GET",
          {"fraud": "$.fraudlabspro_score"},
          api_key_slots=["{FLP_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"fraudlabspro_score": "fraud_score"},
          tags=["passive", "threat"],
          health_check_url="https://api.fraudlabspro.com", reliability_score=4),

    _auth("google_safebrowsing", "threat_intel",
          "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}", "POST",
          {"matches": "$.matches"},
          api_key_slots=["{GOOGLE_API_KEY}"],
          input_type="url", output_type=["url"],
          payload_template={"client": {"clientId": "nox", "clientVersion": "1.0"},
                            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                                           "platformTypes": ["ANY_PLATFORM"],
                                           "threatEntryTypes": ["URL"],
                                           "threatEntries": [{"url": "{target}"}]}},
          tags=["passive", "threat"],
          health_check_url="https://safebrowsing.googleapis.com", reliability_score=5),

    _auth("threatconnect_search", "threat_intel",
          "https://api.threatconnect.com/v2/indicators/{target}", "GET",
          {"data": "$.data"},
          headers={"Authorization": "TC {TC_API_KEY}:{TC_SIGNATURE}"},
          api_key_slots=["{TC_API_KEY}"],
          input_type="any", output_type=["ip", "domain"],
          tags=["passive", "threat"],
          health_check_url="https://api.threatconnect.com", reliability_score=4),

    _auth("threatportal", "threat_intel",
          "https://threatportal.io/api/v1/search?q={target}", "GET",
          {"results": "$.results"},
          headers={"Authorization": "Bearer {TP_API_KEY}"},
          api_key_slots=["{TP_API_KEY}"],
          input_type="any", output_type=["ip", "domain"],
          tags=["passive", "threat"],
          health_check_url="https://threatportal.io", reliability_score=3, is_volatile=True),

    _auth("malshare", "threat_intel",
          "https://malshare.com/api.php?api_key={MALSHARE_API_KEY}&action=search&query={target}", "GET",
          {"hashes": "$.*"},
          api_key_slots=["{MALSHARE_API_KEY}"],
          input_type="hash", output_type=["hash"],
          tags=["passive", "threat"],
          health_check_url="https://malshare.com", reliability_score=3),

    _auth("hybrid_analysis", "threat_intel",
          "https://www.hybrid-analysis.com/api/v2/search/hash", "POST",
          {"verdict": "$.verdict"},
          headers={"api-key": "{HYBRID_API_KEY}"},
          api_key_slots=["{HYBRID_API_KEY}"],
          input_type="hash", output_type=["hash"],
          payload_template={"hash": "{target}"},
          normalization_map={"verdict": "malware_verdict"},
          tags=["passive", "threat", "heavy"],
          health_check_url="https://www.hybrid-analysis.com", reliability_score=4),

    _auth("joesandbox", "threat_intel",
          "https://www.joesandbox.com/api/v2/analysis/search?q={target}", "GET",
          {"id": "$.[*].id"},
          headers={"X-JoeSandbox-Api-Key": "{JOE_API_KEY}"},
          api_key_slots=["{JOE_API_KEY}"],
          input_type="hash", output_type=["hash"],
          tags=["passive", "threat", "heavy"],
          health_check_url="https://www.joesandbox.com", reliability_score=4),

    _auth("anyrun", "threat_intel",
          "https://api.any.run/v1/analysis?hash={target}", "GET",
          {"tasks": "$.tasks"},
          headers={"Authorization": "API-Key {ANYRUN_API_KEY}"},
          api_key_slots=["{ANYRUN_API_KEY}"],
          input_type="hash", output_type=["hash"],
          tags=["passive", "threat", "heavy"],
          health_check_url="https://api.any.run", reliability_score=4),

    _auth("intezer", "threat_intel",
          "https://analyze.intezer.com/api/v2-0/get-analysis-by-hash/{target}", "GET",
          {"result": "$.result"},
          headers={"Authorization": "Bearer {INTEZER_API_KEY}"},
          api_key_slots=["{INTEZER_API_KEY}"],
          input_type="hash", output_type=["hash"],
          tags=["passive", "threat"],
          health_check_url="https://analyze.intezer.com", reliability_score=4),

    _auth("misp_search", "threat_intel",
          "{MISP_URL}/attributes/restSearch", "POST",
          {"attributes": "$.Attribute[*].value"},
          headers={"Authorization": "{MISP_API_KEY}", "Content-Type": "application/json"},
          api_key_slots=["{MISP_API_KEY}"],
          input_type="any", output_type=["ip", "domain", "hash"],
          payload_template={"returnFormat": "json", "value": "{target}"},
          tags=["passive", "threat"],
          health_check_url="{MISP_URL}", reliability_score=4),
]

AUTHENTICATED_PREMIUM_SOURCES += [

    # ── Breaches ─────────────────────────────────────────────────────────────

    _auth("hibp_breached", "breaches",
          "https://haveibeenpwned.com/api/v3/breachedaccount/{target}", "GET",
          {"breaches": "$.*.Name"},
          rate_limit=1.5,
          headers={"hibp-api-key": "{HIBP_API_KEY}", "User-Agent": "NOX-Framework"},
          api_key_slots=["{HIBP_API_KEY}"],
          input_type="email", output_type=["email", "domain"],
          normalization_map={"Name": "breach_name"},
          tags=["passive", "stealth"],
          health_check_url="https://haveibeenpwned.com", reliability_score=5),

    _auth("dehashed", "breaches",
          "https://api.dehashed.com/search?query={target}", "GET",
          {"entries": "$.entries"},
          headers={"Authorization": "Basic {DEHASHED_AUTH_BASE64}", "Accept": "application/json"},
          api_key_slots=["{DEHASHED_AUTH_BASE64}"],
          input_type="email", output_type=["email", "username", "ip"],
          normalization_map={"email": "email_address", "username": "username",
                             "password": "plaintext_password", "hashed_password": "password_hash",
                             "ip_address": "ip_address", "name": "full_name"},
          tags=["passive", "stealth"],
          health_check_url="https://api.dehashed.com", reliability_score=5),

    _auth("snusbase", "breaches",
          "https://api.snusbase.com/data/search", "POST",
          {"leaks": "$.results"},
          headers={"Auth": "{SNUSBASE_API_KEY}", "Content-Type": "application/json"},
          api_key_slots=["{SNUSBASE_API_KEY}"],
          input_type="email", output_type=["email", "username"],
          payload_template={"terms": ["{target}"], "types": ["email"]},
          normalization_map={"email": "email_address", "username": "username",
                             "password": "plaintext_password", "hash": "password_hash"},
          tags=["passive", "stealth"],
          health_check_url="https://api.snusbase.com", reliability_score=4),

    _auth("intelx_search", "breaches",
          "https://2.intelx.io/intelligent/search", "POST",
          {"id": "$.id"},
          headers={"x-key": "{INTELX_API_KEY}"},
          api_key_slots=["{INTELX_API_KEY}"],
          input_type="email", output_type=["email", "domain"],
          payload_template={"term": "{target}", "buckets": [], "lookuplevel": 0,
                            "maxresults": 100, "timeout": 0, "datefrom": "", "dateto": "",
                            "sort": 4, "media": 0, "terminate": []},
          tags=["passive", "stealth"],
          health_check_url="https://2.intelx.io", reliability_score=5),

    _auth("intelx_phone", "breaches",
          "https://2.intelx.io/phone/search?phone={target}", "GET",
          {"results": "$.results"},
          headers={"x-key": "{INTELX_API_KEY}"},
          api_key_slots=["{INTELX_API_KEY}"],
          input_type="phone", output_type=["phone"],
          tags=["passive"],
          health_check_url="https://2.intelx.io", reliability_score=5),

    _auth("leakcheck", "breaches",
          "https://leakcheck.io/api/v2/query/{target}", "GET",
          {"sources": "$.sources"},
          headers={"X-API-Key": "{LEAKCHECK_API_KEY}"},
          api_key_slots=["{LEAKCHECK_API_KEY}"],
          input_type="email", output_type=["email"],
          normalization_map={"sources": "breach_sources"},
          tags=["passive", "stealth"],
          health_check_url="https://leakcheck.io", reliability_score=4),

    _auth("spycloud_breach", "breaches",
          "https://api.spycloud.io/enterprise-v2/breach/data/emails/{target}", "GET",
          {"results": "$.results"},
          headers={"X-API-Key": "{SPYCLOUD_API_KEY}"},
          api_key_slots=["{SPYCLOUD_API_KEY}"],
          input_type="email", output_type=["email", "username", "ip"],
          normalization_map={"email": "email_address", "username": "username",
                             "password": "plaintext_password", "ip_addresses": "ip_address"},
          tags=["passive", "stealth"],
          health_check_url="https://api.spycloud.io", reliability_score=5),

    _auth("leakix_search", "breaches",
          "https://leakix.net/api/search?q={target}", "GET",
          {"leaks": "$.[*].event_source"},
          headers={"api-key": "{LEAKIX_API_KEY}"},
          api_key_slots=["{LEAKIX_API_KEY}"],
          input_type="domain", output_type=["domain", "ip"],
          tags=["passive"],
          health_check_url="https://leakix.net", reliability_score=4),

    _auth("breachdirectory", "breaches",
          "https://breachdirectory.com/api/search?key={BD_API_KEY}&email={target}", "GET",
          {"found": "$.found"},
          api_key_slots=["{BD_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive", "stealth"],
          health_check_url="https://breachdirectory.com", reliability_score=4),

    _auth("breachaware", "breaches",
          "https://api.breachaware.com/v1/search?query={target}", "GET",
          {"breaches": "$.breaches"},
          headers={"X-API-KEY": "{BA_API_KEY}"},
          api_key_slots=["{BA_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive", "stealth"],
          health_check_url="https://api.breachaware.com", reliability_score=3, is_volatile=True),

    _auth("tines_breach", "breaches",
          "https://api.tines.com/breaches/{target}", "GET",
          {"breaches": "$.breaches"},
          headers={"Authorization": "Bearer {TINES_API_KEY}"},
          api_key_slots=["{TINES_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive"],
          health_check_url="https://api.tines.com", reliability_score=3),

    _auth("leakstats_pw", "breaches",
          "https://leakstats.net/api/password/{target}", "GET",
          {"count": "$.count"},
          headers={"api-key": "{LEAKSTATS_API_KEY}"},
          api_key_slots=["{LEAKSTATS_API_KEY}"],
          input_type="hash", output_type=["hash"],
          tags=["passive"],
          health_check_url="https://leakstats.net", reliability_score=3, is_volatile=True),

    _base("leak_lookup", "breaches",
          "https://leak-lookup.com/api/search", "POST",
          {"results": "$.message"},
          input_type="email", output_type=["email"],
          payload_template={"query": "{target}", "type": "email_address"},
          tags=["passive", "stealth"],
          health_check_url="https://leak-lookup.com", reliability_score=3, is_volatile=True),

    _auth("cit0day", "breaches",
          "https://cit0day.in/api/v1/search?query={target}", "GET",
          {"results": "$.results"},
          headers={"Authorization": "Bearer {CIT0DAY_API_KEY}"},
          api_key_slots=["{CIT0DAY_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive", "stealth"],
          health_check_url="https://cit0day.in", reliability_score=2, is_volatile=True),

    # ── DNS Recon ─────────────────────────────────────────────────────────────

    _auth("securitytrails_sub", "dns_recon",
          "https://api.securitytrails.com/v1/domain/{target}/subdomains", "GET",
          {"subdomains": "$.subdomains"},
          headers={"APIKEY": "{SECURITYTRAILS_API_KEY}"},
          api_key_slots=["{SECURITYTRAILS_API_KEY}"],
          input_type="domain", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://api.securitytrails.com", reliability_score=5),

    _auth("securitytrails_history", "dns_recon",
          "https://api.securitytrails.com/v1/history/{target}/dns/a", "GET",
          {"history": "$.records[*].values[*].ip"},
          headers={"APIKEY": "{SECURITYTRAILS_API_KEY}"},
          api_key_slots=["{SECURITYTRAILS_API_KEY}"],
          input_type="domain", output_type=["ip"],
          normalization_map={"ip": "historical_ip"},
          tags=["passive"],
          health_check_url="https://api.securitytrails.com", reliability_score=5),

    _auth("circl_lu_pdns", "dns_recon",
          "https://www.circl.lu/pdns/query/{target}", "GET",
          {"resolutions": "$.[*].rdata"},
          headers={"Authorization": "Basic {CIRCL_AUTH_BASE64}"},
          api_key_slots=["{CIRCL_AUTH_BASE64}"],
          input_type="domain", output_type=["ip"],
          tags=["passive"],
          health_check_url="https://www.circl.lu", reliability_score=4),

    _auth("viewdns_reverse_ip", "dns_recon",
          "https://api.viewdns.info/reverseip/?host={target}&apikey={VIEWDNS_API_KEY}&output=json", "GET",
          {"domains": "$.response.domains[*].name"},
          api_key_slots=["{VIEWDNS_API_KEY}"],
          input_type="ip", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://api.viewdns.info", reliability_score=4),

    _auth("dnsdb_pdns", "dns_recon",
          "https://api.dnsdb.info/lookup/rrset/name/{target}", "GET",
          {"rdata": "$.[*].rdata"},
          headers={"X-API-Key": "{DNSDB_API_KEY}"},
          api_key_slots=["{DNSDB_API_KEY}"],
          input_type="domain", output_type=["ip"],
          tags=["passive"],
          health_check_url="https://api.dnsdb.info", reliability_score=5),

    _auth("spyonweb", "dns_recon",
          "https://api.spyonweb.com/v1/summary/{target}?access_token={SPYONWEB_API_KEY}", "GET",
          {"adsense": "$.result.adsense"},
          api_key_slots=["{SPYONWEB_API_KEY}"],
          input_type="domain", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://api.spyonweb.com", reliability_score=3),

    # ── WHOIS ─────────────────────────────────────────────────────────────────

    _auth("passivetotal_whois", "whois",
          "https://api.passivetotal.org/v2/whois?query={target}", "GET",
          {"registrar": "$.registrar"},
          headers={"Authorization": "Basic {PASSIVETOTAL_AUTH_BASE64}"},
          api_key_slots=["{PASSIVETOTAL_AUTH_BASE64}"],
          input_type="domain", output_type=["email", "domain"],
          normalization_map={"registrar": "registrar_name"},
          tags=["passive"],
          health_check_url="https://api.passivetotal.org", reliability_score=4),

    _auth("whoisxml_api", "whois",
          "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXML_API_KEY}&domainName={target}&outputFormat=JSON", "GET",
          {"created": "$.WhoisRecord.createdDate"},
          api_key_slots=["{WHOISXML_API_KEY}"],
          input_type="domain", output_type=["email", "domain"],
          normalization_map={"createdDate": "registration_date"},
          tags=["passive"],
          health_check_url="https://www.whoisxmlapi.com", reliability_score=5),

    _auth("whoxy_whois", "whois",
          "https://api.whoxy.com/?key={WHOXY_API_KEY}&whois={target}", "GET",
          {"registrar": "$.registrar_name"},
          api_key_slots=["{WHOXY_API_KEY}"],
          input_type="domain", output_type=["email", "domain"],
          tags=["passive"],
          health_check_url="https://api.whoxy.com", reliability_score=4),

    _auth("whois_freaks", "whois",
          "https://whoisfreaks.com/api/v1/whois?apiKey={WF_API_KEY}&whois=live&domainName={target}", "GET",
          {"emails": "$.whois_record.registrant_contact.email_address"},
          api_key_slots=["{WF_API_KEY}"],
          input_type="domain", output_type=["email"],
          tags=["passive"],
          health_check_url="https://whoisfreaks.com", reliability_score=4),

    _auth("domaintools_whois", "whois",
          "https://api.domaintools.com/v1/{target}/whois/", "GET",
          {"whois": "$.response.whois.record"},
          headers={"Authorization": "Basic {DT_AUTH_BASE64}"},
          api_key_slots=["{DT_AUTH_BASE64}"],
          input_type="domain", output_type=["email", "domain"],
          tags=["passive"],
          health_check_url="https://api.domaintools.com", reliability_score=5),

    # ── Enrichment ────────────────────────────────────────────────────────────

    _auth("clearbit_enrich", "enrichment",
          "https://person.clearbit.com/v2/people/find?email={target}", "GET",
          {"full_name": "$.name.fullName"},
          headers={"Authorization": "Bearer {CLEARBIT_API_KEY}"},
          api_key_slots=["{CLEARBIT_API_KEY}"],
          input_type="email", output_type=["username", "domain"],
          normalization_map={"fullName": "full_name"},
          tags=["passive"],
          health_check_url="https://person.clearbit.com", reliability_score=4),

    _auth("fullcontact", "enrichment",
          "https://api.fullcontact.com/v3/person.enrich", "POST",
          {"social": "$.socialProfiles"},
          headers={"Authorization": "Bearer {FULLCONTACT_API_KEY}"},
          api_key_slots=["{FULLCONTACT_API_KEY}"],
          input_type="email", output_type=["username", "domain"],
          payload_template={"email": "{target}"},
          tags=["passive"],
          health_check_url="https://api.fullcontact.com", reliability_score=4),

    _auth("passivetotal_enrich", "enrichment",
          "https://api.passivetotal.org/v2/enrichment?query={target}", "GET",
          {"tags": "$.tags"},
          headers={"Authorization": "Basic {PASSIVETOTAL_AUTH_BASE64}"},
          api_key_slots=["{PASSIVETOTAL_AUTH_BASE64}"],
          input_type="domain", output_type=["domain"],
          tags=["passive"],
          health_check_url="https://api.passivetotal.org", reliability_score=4),

    _auth("pipl_search", "enrichment",
          "https://api.pipl.com/search/?email={target}&key={PIPL_API_KEY}", "GET",
          {"person": "$.person"},
          api_key_slots=["{PIPL_API_KEY}"],
          input_type="email", output_type=["username", "domain", "phone"],
          tags=["passive"],
          health_check_url="https://api.pipl.com", reliability_score=4),

    # ── Email Reputation ──────────────────────────────────────────────────────

    _auth("ipqualityscore_email", "email_rep",
          "https://ipqualityscore.com/api/json/email/{IPQS_API_KEY}/{target}", "GET",
          {"fraud_score": "$.fraud_score"},
          api_key_slots=["{IPQS_API_KEY}"],
          input_type="email", output_type=["email"],
          normalization_map={"fraud_score": "email_fraud_score"},
          tags=["passive", "fast"],
          health_check_url="https://ipqualityscore.com", reliability_score=4),

    _auth("emailhippo", "email_rep",
          "https://api.emailhippo.com/v3/verify?apiKey={HIPPO_API_KEY}&email={target}", "GET",
          {"status": "$.meta.status"},
          api_key_slots=["{HIPPO_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive", "fast"],
          health_check_url="https://api.emailhippo.com", reliability_score=4),

    _auth("zerobounce", "email_rep",
          "https://api.zerobounce.net/v2/validate?api_key={ZEROBOUNCE_API_KEY}&email={target}", "GET",
          {"status": "$.status"},
          api_key_slots=["{ZEROBOUNCE_API_KEY}"],
          input_type="email", output_type=["email"],
          normalization_map={"status": "email_validity"},
          tags=["passive", "fast"],
          health_check_url="https://api.zerobounce.net", reliability_score=4),

    _auth("hunter_verify", "email_rep",
          "https://api.hunter.io/v2/email-verifier?email={target}&api_key={HUNTER_API_KEY}", "GET",
          {"result": "$.data.result"},
          api_key_slots=["{HUNTER_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive", "fast"],
          health_check_url="https://api.hunter.io", reliability_score=4),

    _auth("mailboxlayer", "email_rep",
          "http://apilayer.net/api/check?access_key={MAILBOX_API_KEY}&email={target}", "GET",
          {"score": "$.score"},
          api_key_slots=["{MAILBOX_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive"],
          health_check_url="http://apilayer.net", reliability_score=3),

    _auth("abstract_email", "email_rep",
          "https://emailvalidation.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY}&email={target}", "GET",
          {"quality": "$.quality_score"},
          api_key_slots=["{ABSTRACT_API_KEY}"],
          input_type="email", output_type=["email"],
          tags=["passive", "fast"],
          health_check_url="https://emailvalidation.abstractapi.com", reliability_score=4),

    # ── Discovery / Social ────────────────────────────────────────────────────

    _auth("hunter_io", "discovery",
          "https://api.hunter.io/v2/domain-search?domain={target}&api_key={HUNTER_API_KEY}", "GET",
          {"emails": "$.data.emails[*].value"},
          api_key_slots=["{HUNTER_API_KEY}"],
          input_type="domain", output_type=["email"],
          normalization_map={"value": "email_address"},
          tags=["passive"],
          health_check_url="https://api.hunter.io", reliability_score=5),

    _auth("twitter_v2", "social",
          "https://api.twitter.com/2/users/by/username/{target}", "GET",
          {"id": "$.data.id"},
          headers={"Authorization": "Bearer {TWITTER_BEARER_TOKEN}"},
          api_key_slots=["{TWITTER_BEARER_TOKEN}"],
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://api.twitter.com", reliability_score=4),

    _auth("github_code_search", "code",
          "https://api.github.com/search/code?q={target}", "GET",
          {"urls": "$.items[*].html_url"},
          headers={"Authorization": "token {GITHUB_TOKEN}"},
          api_key_slots=["{GITHUB_TOKEN}"],
          input_type="any", output_type=["url"],
          tags=["passive"],
          health_check_url="https://api.github.com", reliability_score=5),

    _auth("github_search_repos", "social",
          "https://api.github.com/search/repositories?q={target}", "GET",
          {"total": "$.total_count"},
          headers={"Authorization": "token {GITHUB_TOKEN}"},
          api_key_slots=["{GITHUB_TOKEN}"],
          input_type="username", output_type=["username"],
          tags=["passive"],
          health_check_url="https://api.github.com", reliability_score=5),

    # ── Geolocation ───────────────────────────────────────────────────────────

    _auth("ipstack", "geolocation",
          "http://api.ipstack.com/{target}?access_key={IPSTACK_API_KEY}", "GET",
          {"country": "$.country_name"},
          api_key_slots=["{IPSTACK_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"country_name": "geo_country"},
          tags=["passive", "fast"],
          health_check_url="http://api.ipstack.com", reliability_score=4),

    _auth("ipgeolocation_io", "geolocation",
          "https://api.ipgeolocation.io/ipgeo?apiKey={IPGEO_API_KEY}&ip={target}", "GET",
          {"isp": "$.isp"},
          api_key_slots=["{IPGEO_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"isp": "asn_org"},
          tags=["passive", "fast"],
          health_check_url="https://api.ipgeolocation.io", reliability_score=4),

    _auth("ipdata_co", "geolocation",
          "https://api.ipdata.co/{target}?api-key={IPDATA_API_KEY}", "GET",
          {"threat": "$.threat"},
          api_key_slots=["{IPDATA_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"threat": "threat_info"},
          tags=["passive", "fast"],
          health_check_url="https://api.ipdata.co", reliability_score=4),

    _auth("extreme_ip_lookup", "geolocation",
          "https://extreme-ip-lookup.com/json/{target}?key={EXTREME_API_KEY}", "GET",
          {"org": "$.org"},
          api_key_slots=["{EXTREME_API_KEY}"],
          input_type="ip", output_type=["ip"],
          tags=["passive"],
          health_check_url="https://extreme-ip-lookup.com", reliability_score=3),

    _auth("ipinfodb", "geolocation",
          "http://api.ipinfodb.com/v3/ip-city/?key={IPINFODB_API_KEY}&ip={target}&format=json", "GET",
          {"city": "$.cityName"},
          api_key_slots=["{IPINFODB_API_KEY}"],
          input_type="ip", output_type=["ip"],
          normalization_map={"cityName": "geo_city"},
          tags=["passive"],
          health_check_url="http://api.ipinfodb.com", reliability_score=3),

    # ── Phone ─────────────────────────────────────────────────────────────────

    _auth("numverify", "phone",
          "http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={target}", "GET",
          {"valid": "$.valid", "carrier": "$.carrier"},
          api_key_slots=["{NUMVERIFY_API_KEY}"],
          input_type="phone", output_type=["phone"],
          normalization_map={"valid": "phone_valid", "carrier": "phone_carrier"},
          tags=["passive"],
          health_check_url="http://apilayer.net", reliability_score=4),

    # ── Hashes ────────────────────────────────────────────────────────────────

    _auth("hashes_org", "hashes",
          "https://hashes.org/api.php?key={HASHES_API_KEY}&query={target}", "GET",
          {"found": "$.results"},
          api_key_slots=["{HASHES_API_KEY}"],
          input_type="hash", output_type=["hash"],
          tags=["passive"],
          health_check_url="https://hashes.org", reliability_score=3),

    # ── Search ────────────────────────────────────────────────────────────────

    _auth("google_search_custom", "search",
          "https://www.googleapis.com/customsearch/v1?key={GOOGLE_CX_KEY}&cx={GOOGLE_CX_ID}&q={target}", "GET",
          {"items": "$.items[*].link"},
          api_key_slots=["{GOOGLE_CX_KEY}", "{GOOGLE_CX_ID}"],
          input_type="any", output_type=["url"],
          tags=["passive"],
          health_check_url="https://www.googleapis.com", reliability_score=5),

    _auth("bing_search_api", "search",
          "https://api.bing.microsoft.com/v7.0/search?q={target}", "GET",
          {"urls": "$.webPages.value[*].url"},
          headers={"Ocp-Apim-Subscription-Key": "{BING_API_KEY}"},
          api_key_slots=["{BING_API_KEY}"],
          input_type="any", output_type=["url"],
          tags=["passive"],
          health_check_url="https://api.bing.microsoft.com", reliability_score=5),
]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_nox_sources(output_dir: str = None) -> None:
    # H3: resolve output_dir relative to this script's location, not CWD.
    # This ensures `python /opt/nox-cli/build_sources.py` from any directory
    # always writes to /opt/nox-cli/sources/ instead of ./sources/.
    if output_dir is None:
        output_dir = str(Path(__file__).resolve().parent / "sources")
    os.makedirs(output_dir, exist_ok=True)

    all_sources: List[SourceConfig] = FREE_PUBLIC_SOURCES + AUTHENTICATED_PREMIUM_SOURCES
    errors: List[str] = []
    written = 0

    for src in all_sources:
        dest    = os.path.join(output_dir, f"{src.name}.json")
        payload = src.to_json()

        tmp_fd, tmp_path = tempfile.mkstemp(dir=output_dir, suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp_path, dest)
            written += 1
        except Exception as exc:
            os.unlink(tmp_path)
            errors.append(f"[ERROR] '{src.name}': {exc}")

    print(f"Done. {written}/{len(all_sources)} source files written to '{output_dir}/'.")
    if errors:
        print("\nErrors:")
        for e in errors:
            print(" ", e)

    # ── Remove orphaned JSON plugins (§2.3) ───────────────────────────
    # Any .json in sources/ not produced by this build is stale and would
    # be silently loaded at runtime by SourceOrchestrator. Remove it.
    expected_filenames = {f"{src.name}.json" for src in all_sources}
    removed = 0
    for fname in os.listdir(output_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(output_dir, fname)
        if os.path.isfile(fpath) and fname not in expected_filenames:
            try:
                os.unlink(fpath)
                print(f"[cleanup] Removed orphaned plugin: {fname}")
                removed += 1
            except OSError as exc:
                print(f"[WARN] Could not remove orphaned plugin {fname}: {exc}")
    if removed:
        print(f"[cleanup] {removed} orphaned plugin(s) removed.")

    # ── Seed apikeys.json (never overwrites an existing file) ──────────
    if _APIKEYS_FILE is not None and _default_store is not None and _write_store is not None:
        if not _APIKEYS_FILE.exists():
            try:
                _write_store(_default_store())
                print(f"Created API key template: {_APIKEYS_FILE}")
                print(f"  All {len(_default_store())} private keys set to '{UNIVERSAL_PLACEHOLDER}'.")
                print("  Edit that file to configure your keys before scanning.")
            except Exception as exc:
                print(f"[WARN] Could not create apikeys.json: {exc}")
        else:
            print(f"API key file already exists — not overwritten: {_APIKEYS_FILE}")


if __name__ == "__main__":
    build_nox_sources()
