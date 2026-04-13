# Changelog

All notable changes to NOX are documented here.

## [1.0.1] — 2026-04-13

### Sources
- **Removed:** `cit0day` (HTML fingerprint challenge, no JSON response), `vigilante_pw` (redirects to dehashed.com), `scylla_sh_search` (domain parked, permanently unreachable)
- **Restored:** `proxynova_comb` (live, returns valid JSON — was incorrectly removed)
- **Fixed:** `leak_lookup` now requires API key (`LEAK_LOOKUP_API_KEY`) — provider removed unauthenticated access
- **Fixed:** `intelx_search` two-phase poll implemented — plugin previously submitted the search job but never polled for results, returning 0 records for all queries
- **Fixed:** `hudsonrock_osint` missing `User-Agent` header added — endpoint returns 403 without a browser UA
- **Removed:** `HASHES_API_KEY` registry entry — hashes.org shut down in 2023; `HASHES_COM_API_KEY` is the correct active slot
- **Added:** `LEAK_LOOKUP_API_KEY` to service registry

### Engine
- **Fixed:** `bypass_required` field in source plugins now enforced at runtime — sources declaring `["cloudflare"]` bypass are skipped when `curl_cffi` is absent (previously the field was parsed but never read)
- **Fixed:** Guardian proxy auto-fetch updated to ProxyScrape v3 API (v2 deprecated Q1 2026); `proxy-list.download` replaced with `proxifly` free list

### Dependencies
- **Updated:** `requests>=2.32.3` (CVE fixes)

### README
- Source count updated: 123 active plugins

### Dependencies
- **Updated:** `aiohttp` minimum pin raised to `>=3.13.5` (connection-pool stability fixes under high concurrency)
- **Added:** `zstandard>=0.23.0` — enables native zstd decompression in aiohttp for Cloudflare/Fastly CDN responses

### Engine
- **Updated:** `Accept-Encoding` header now includes `zstd` (`gzip, deflate, br, zstd`) to match Chrome 124+ behaviour

## [1.0.1] — 2026-04-11

### Sources
- **Added 9 new sources:** `proxynova_comb` (COMB breach search, free), `shodan_internetdb` (IP intel, free), `circl_hashlookup` (NSRL hash lookup, free), `ipapi_is` (IP geolocation, free), `threatfox` (abuse.ch IOC database), `urlhaus` (abuse.ch malware URLs), `malwarebazaar` (abuse.ch hash lookup), `fullhunt_subdomains` (attack surface), `netlas_search` (internet scanner)
- **Removed 7 dead sources:** `threatcrowd_email`, `threatcrowd_domain` (DNS dead), `spyse_domain`, `spyse_ip` (API shut down), `hashes_org` (DNS dead), `leakstats_pw` (DNS dead), `checkleaked` (endpoint gone)
- **Fixed:** `dehashed` endpoint migrated from `/search` to `/v2/search`
- **Fixed:** `hudsonrock_osint` endpoint corrected to `search-by-email` with `input_type: email` (was `search-by-login` with `input_type: username`)
- **Fixed:** `scylla_sh_search` migrated from dead `scylla.sh` to active `scylla.so`
- **Fixed:** `emailrep_io` now requires API key (`EMAILREP_API_KEY`) — free unauthenticated tier removed by provider
- **Fixed:** `duckduckgo_api` repurposed from dead DDG Instant Answer API to SearXNG JSON search

### Engine
- **Fixed:** POST 429 `Retry-After` cap was 4s (should be 30s, matching GET path)
- **Fixed:** Linear retry backoff replaced with exponential backoff + jitter in all 4 retry paths (`_get`, `_post`, `Session.get`, `Session.post`)
- **Fixed:** `--reset-sources` now removes orphaned plugins from `~/.nox/sources/` in addition to copying new ones
- **Fixed:** DDG HTML scraper replaced with SearXNG JSON API across all call sites — DDG HTML endpoint bot-blocked since 2025
- **Fixed:** SearXNG instance pool updated: `searx.be` (403), `search.bus-hit.me` (DNS dead), `searxng.site` (SSL error) replaced with 6 active instances; pool extracted to module-level `_SEARX_INSTANCES` constant
- **Fixed:** All 11 dead paste site APIs removed from `ScrapeEngine.PASTE_SITES`; paste intelligence now routed through SearXNG dorks and IntelX

### WAF Resilience
- **Updated:** User-Agent pool updated to Chrome/135, Firefox/136, Edge/135 (was Chrome/131, Firefox/133)
- **Added:** `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform` Client Hints headers for Chromium-based UAs
- **Fixed:** `_CH_UA_MAP` ordering — Edge UA now correctly gets `"Microsoft Edge"` brand (was getting `"Google Chrome"` due to dict iteration order)
- **Fixed:** `_search()` sync method no longer passes `use_cloudscraper=True` to SearXNG JSON API calls

### Hash Cracking
- **Removed 6 dead/paywalled cracker APIs:** nitrxgen (DNS dead), hash.help (DNS dead), hashkiller (403), hashes.com free path (404), md5decrypt (403), cmd5 (paywalled — returns `CMD5-ERROR:-1` for all hashes)
- **Added:** Local rockyou wordlist as primary crack path (no external calls, no rate limits, no data leakage)
- **Added:** `hashes.com` keyed API as external fallback (`HASHES_COM_API_KEY`)

### Dependencies
- **Added:** `brotli>=1.1.0` — required for aiohttp to decompress `br`-encoded responses

### Config
- **Added 7 new API key slots:** `EMAILREP_API_KEY`, `HASHES_COM_API_KEY`, `THREATFOX_API_KEY`, `URLHAUS_API_KEY`, `MALWAREBAZAAR_API_KEY`, `FULLHUNT_API_KEY`, `NETLAS_API_KEY`

## [1.0.0] — 2026-04-02

### Initial Release

- 124 Pydantic v2-validated JSON source plugins across breach, network, OSINT, and threat-intel categories
- Fully async execution engine (`asyncio` + `aiohttp`) with JA3 TLS fingerprinting and per-request jitter
- `--autoscan` pipeline: breach scan → recursive identity pivot (depth 2) → Google/DDG dorking → paste/Telegram scraping
- `--fullscan`: breach scan + pivot only
- `--scan` / REPL `scan`: breach sources only
- Guardian Proxy Engine: automatic proxy rotation with fail-safe kill-switch
- Risk scoring engine (0–100) with time-decay, source confidence weighting, persistence multipliers, and HVT detection
- Recursive Avalanche Engine: every discovered asset re-injected as a new scan seed across breach, dork, and scrape concurrently
- Union-Find identity clustering across all breach records
- Forensic PDF/HTML/JSON/CSV/Markdown reporting with Executive Summary dashboard
- Hash identification and multi-engine cracking (dictionary + mutations + online rainbow tables)
- Deep password strength analysis with entropy, leet-speak detection, and crack-time estimates
- Interactive REPL with full feature parity with the CLI
- Full audit logging: all scan events mirrored to `~/.nox/logs/nox.log`
- Isolated `.deb` packaging for Kali Linux (PEP 668 compliant — zero system pollution)
- `~/.config/nox-cli/apikeys.json` credential store (chmod 0600)
