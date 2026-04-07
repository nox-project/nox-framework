# Changelog

All notable changes to NOX are documented here.

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
