<div align="center">

```
    ███╗   ██╗ ██████╗ ██╗  ██╗
    ████╗  ██║██╔═══██╗╚██╗██╔╝
    ██╔██╗ ██║██║   ██║ ╚███╔╝
    ██║╚██╗██║██║   ██║ ██╔██╗
    ██║ ╚████║╚██████╔╝██╔╝ ██╗
    ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
```

**Cyber Threat Intelligence Framework**

[![Status](https://img.shields.io/badge/Status-v1.0.1-success)](https://github.com/nox-project/nox-framework/releases/tag/v1.0.1)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE.txt)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![BlackArch](https://img.shields.io/badge/BlackArch-Available-1E1E2E?logo=archlinux&logoColor=white)](https://blackarch.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/nox-project/nox-framework)
[![Sources](https://img.shields.io/badge/Sources-126-red)](https://github.com/nox-project/nox-framework)

*OSINT framework for red teaming, digital forensics, and corporate exposure analysis.*

</div>

---

## Introduction

NOX is a purpose-built cyber threat intelligence engine designed for operators who require speed, operational security, and depth in a single cohesive framework. It is not a wrapper around existing tools — it is a fully async, plugin-driven intelligence platform with a strict separation between execution logic and source definitions.

| Capability | Detail |
|-|-|
| ⚡ **Async Execution Engine** | Massively parallel scanning across 126 intelligence feeds with no sequential bottlenecks and no blocking I/O. |
| 🛡️ **Guardian Engine** | Integrated OPSEC layer with automatic proxy rotation and SOCKS5 support. Fail-safe kill-switch halts all traffic if the transport circuit is unavailable. |
| 🧠 **Risk Scoring** | Dynamic 0–100 scoring with time-decay, source confidence weighting, password complexity analysis, persistence multipliers, and HVT detection. |
| 🔗 **Recursive Avalanche Engine** | Every discovered asset — username, email, cracked password, phone — is automatically re-injected as a new scan seed. Per-asset pipeline runs sequentially (breach → crack → dork → scrape); child assets run concurrently. Identifiers from all four phases feed the pivot queue. Global deduplication and configurable depth cap prevent runaway recursion. |
| 🔍 **Autoscan** | Single command triggers breach scan + recursive pivot + dorking + paste scraping — fully automated, no manual chaining. |

---

## Features

| Feature | Description |
|-|-|
| **126 JSON Plugin Sources** | Every intelligence source is a JSON plugin. The execution engine contains zero hardcoded source logic. |
| **Async Core** | Full `asyncio` event loop with JA3 fingerprinting, SSL session management, per-request jitter, and configurable concurrency. |
| **Autoscan Pipeline** | `--autoscan` triggers: breach scan → recursive pivot → Google/Bing/SearXNG dorking → paste/Telegram scraping — all in one command. |
| **Recursive Avalanche Engine** | Every identifier discovered — from breach records, dork hits, or scraped paste/Telegram content — is re-injected as a new seed. Per-asset pipeline is sequential (breach → crack → dork → scrape); child assets run concurrently via `asyncio.gather`. A global `seen_assets` set prevents infinite loops. Concurrency and depth are fully configurable at runtime via `--threads` and `--depth`. |
| **Hash Pivoting** | Hashes found in breach data are automatically identified (MD5/SHA1/SHA256/NTLM/bcrypt) and cracked via concurrent background API queries. Cracked plaintexts are injected into the pivot queue as password-recycling seeds. Failures are logged silently — the scan never stops. |
| **Guardian Proxy Engine** | Zero-config OPSEC layer: reads `proxies.txt` if present; otherwise auto-fetches and validates a high-anonymity proxy pool in-memory. Full SOCKS5/HTTP/S and Tor support. |
| **API Key Rotation** | `api_key_slots` per source — NOX round-robins across multiple keys to bypass per-key rate limits. |
| **Identity Graphing** | Union-Find correlation engine unifies breach records into identity clusters across all sources, using type-aware pivot classification. |
| **Enterprise Forensic Reports** | Professional PDF/HTML/JSON/CSV/Markdown reports with Executive Summary dashboard (Total Time, Nodes Discovered, Cleartext Passwords, Pivot Depth), interactive Pivot Chain Visualization, and strict data sanitization — no technical noise in output. JSON exports are self-describing with a full metadata block. |
| **HVT Detection** | Auto-flags C-level, Admin, DevOps, and government domain accounts as High-Value Targets. |
| **Dorking Engine** | Passive document discovery via Google/Bing/SearXNG dorks with PDF/Office metadata extraction. |
| **Scraping Engine** | Paste site indexing, Telegram CTI channel monitoring, credential extraction, and misconfiguration discovery. Each autoscan asset gets a dedicated scrape session — no shared state. |
| **Proxy / Tor** | SOCKS5, HTTP/S proxy, full Tor routing via `stem`, and automatic Guardian fallback. SOCKS5 proxies are validated and routed correctly via `aiohttp-socks`. |
| **Secure Key Store** | API keys managed via `~/.config/nox-cli/apikeys.json` (chmod 0600). Unconfigured keys are silently skipped. Keys set via environment variable are picked up automatically without restarting. |
| **System Logging** | All scan events, phase completions, pivot discoveries, API events, rate-limits, and crack attempts are written to `~/.nox/logs/nox.log`. Only actionable intelligence reaches the terminal. |
| **Plugin Debug** | `--list-sources` prints a full operator debug table: plugin name, input type, confidence score, key status (configured / not configured / public), and any JSON parse errors. |

---

## Architecture

### Plugin-Driven Design

NOX operates on a strict separation of concerns: `nox.py` is a **pure, agnostic execution engine** — it handles async I/O, JA3 fingerprinting, SSL session management, recursive pivoting, and result correlation. It contains no hardcoded intelligence logic.

All intelligence is defined as **JSON plugins** in `sources/`. These plugins are the sole source of truth for what NOX queries, how it authenticates, and what it extracts. The build tool `build_sources.py` is the only authorised way to create or modify them.

```
build_sources.py  ──►  sources/*.json  ──►  nox.py (runtime loader)
   [Builder]              [Plugins]           [Execution Engine]
```

> [!IMPORTANT]
> **`sources/*.json` files are auto-generated artifacts. Never edit them directly.**
> All source additions and modifications must be made in `build_sources.py` and applied by running `python build_sources.py`. Manual edits will be overwritten on the next build.

#### Source Schema

```json
{
  "name": "MyPrivateDB",
  "endpoint": "https://api.myprivatedb.com/search?q={target}",
  "method": "GET",
  "headers": { "Authorization": "Bearer {MY_API_KEY}" },
  "regex_pattern": "([\\w.+-]+@[\\w-]+\\.[\\w.]+):([\\S]+)",
  "required_api_key_name": "MY_API_KEY",
  "api_key_slots": ["{MY_API_KEY}"],
  "input_type": "email",
  "output_type": ["username", "ip"],
  "pivot_types": ["email", "username"],
  "confidence": 0.9
}
```

Supported fields: `name`, `endpoint`, `method`, `headers`, `regex_pattern` (or `json_root` + `normalization_map`), `required_api_key_name`, `api_key_slots`, `input_type`, `output_type`, `pivot_types`, `confidence`.

---

### Autoscan Pipeline

`--autoscan` (CLI) / `autoscan` (REPL) executes the full intelligence pipeline in a single command:

```
For each asset (seed + every discovered identifier):
  ├─ Phase 1 — Breach Scan
  │     126 sources queried in parallel (async)
  │
  ├─ Phase 2 — Hash Crack (non-blocking, concurrent)
  │     Hashes found in breach data → rainbow-table APIs → cracked plaintext
  │     → password-recycling breach scan
  │
  ├─ Phase 3 — Dorking
  │     Google/Bing/SearXNG dorks → leaked docs, .env files, SQL dumps
  │     → new identifiers extracted and re-injected
  │
  └─ Phase 4 — Scraping
        Pastebin, IntelX, Telegram CTI channels → credential extraction
        → new identifiers extracted and re-injected

All identifiers discovered in phases 1–4 are re-injected as new seeds.
Child assets are processed concurrently via asyncio.gather.
```

`scan` (without `--autoscan`) runs Phase 1 only — breach sources, no pivot/dork/scrape.

---

### Recursive Avalanche Engine

Every identifier discovered during a scan — from breach records, dork hits, or scraped paste/Telegram content — is treated as a new intelligence seed. For each asset, the engine runs four phases sequentially: breach scan → hash crack → dork → scrape. Identifiers extracted from **all four phases** are harvested and re-injected as new seeds. Child assets are then processed concurrently via `asyncio.gather`.

```
target@company.com
  └─► [Breach] username: j.doe      ──► [Breach + Crack + Dork + Scrape]
  │         └─► github.com/jdoe     ──► [Breach + Crack + Dork + Scrape]
  └─► [Breach] hash: 5f4dcc...      ──► [AutoCrack] → "password123"
  │         └─► [Breach] password-recycling scan across all sources
  └─► [Dork] new@email.com          ──► [Breach + Crack + Dork + Scrape]
  └─► [Scrape/paste] admin@corp.com ──► [Breach + Crack + Dork + Scrape]
```

- **`seen_assets` set** — global deduplication; no identifier is ever processed twice, regardless of which phase discovered it
- **Global semaphore** — single shared concurrency cap across the entire discovery tree, respecting `--threads`
- **`--depth N`** — configurable pivot depth (default: 2); hard backstop prevents runaway recursion
- **`--no-pivot`** — disable recursive enrichment for a fast breach-only scan

---

### Hash Pivoting

When a hash is found in breach data during `--autoscan`:

1. Hash type is identified (MD5/NTLM, SHA1, SHA256, bcrypt)
2. Multiple rainbow-table APIs are queried **concurrently** in a background task
3. **If cracked** — plaintext is logged, the record is updated, and the password is injected into the pivot queue for password-recycling analysis across all breach sources
4. **If not cracked** — failure is logged to `nox_system.log`, the hash is preserved in the report, and pivoting on all other assets continues immediately

The crack process is fully non-blocking. A timeout or API failure never pauses the scan. Use `--no-online-crack` to restrict cracking to the local wordlist only (no data sent to third-party APIs).

---

### Guardian Proxy Engine

The Guardian Engine is NOX's zero-config OPSEC layer. It activates automatically when no `--proxy` or `--tor` flag is supplied.

**Resolution order:**

1. **`proxies.txt`** — if present in the working directory, NOX loads and rotates through the listed proxies.
2. **Dynamic fetch** — if `proxies.txt` is absent, the Guardian Engine fetches a fresh list of high-anonymity public proxies, validates each one, and holds the validated pool in-memory for the session. Nothing is written to disk.
3. **Direct connection** — if no valid proxies are found, NOX falls back to a direct connection and emits a warning.

> [!WARNING]
> Public proxy pools are inherently untrusted infrastructure. For sensitive engagements, always supply a controlled proxy via `--proxy` or route through Tor via `--tor`.

| Flag | Behaviour |
|-|-|
| `--proxy <url>` | Route all traffic through the specified HTTP/S or SOCKS5 proxy. Disables Guardian. |
| `--tor` | Route all traffic through Tor (requires `tor` service on port 9050). Disables Guardian. |
| `--guardian-off` | Bypass the OPSEC kill-switch and connect directly. |
| *(no flag)* | Guardian Engine activates automatically. |

---

### Reporting

All report formats include an **Executive Summary dashboard**:

| Metric | Description |
|-|-|
| Total Time | Wall-clock duration of the full scan |
| Nodes Discovered | Unique identities surfaced across all sources |
| Cleartext Passwords | Plaintext credentials found or cracked |
| Pivot Depth | Depth reached by the recursive avalanche engine |

Reports also include a **Pivot Chain Visualization** showing the full relational path from initial seed to final discovery:

```
[seed@corp.com] -> [LeakA / username:jdoe] -> [Dork: leaked .env] -> [new@email.com]
```

JSON exports include a `_meta` block with `scan_id`, `target`, `timestamp`, `nox_version`, and `pivot_depth_reached` — making every export self-describing for ingestion into case management platforms.

All output is sanitized — proxy errors, timeouts, and tracebacks are stripped. Only actionable intelligence is included.

---

## Filesystem Layout

```
~/.nox/
├── sources/               # Auto-generated JSON source plugins
├── reports/               # Generated forensic reports
├── logs/                  # Runtime log (nox.log)
├── wordlists/             # Hash cracking wordlists
├── vault/                 # Secure storage
└── nox_cache.db           # Forensic persistence database (SQLite)

~/.config/nox-cli/
├── apikeys.json           # API keys — chmod 0600, never committed to VCS
└── logs/
    └── nox_system.log     # Silent system log: API events, rate-limits, crack attempts

# .deb install (isolated venv)
/opt/nox-cli/
├── nox.py
├── build_sources.py
├── requirements.txt
├── sources/
└── .venv/                 # Isolated Python environment (PEP 668 compliant)
```

---

## Prerequisites

- **Python 3.8+**
- **pip** (`python3-pip` on Debian/Kali)
- **Tor** *(optional)* — required only for `--tor`. On Kali: `sudo apt install tor -y`. The `tor` service must be running on port `9050`.

---

## Installation

### Option 1: Debian / Kali Linux — Isolated .deb (Recommended)

Download the `.deb` package from the [Releases page](https://github.com/nox-project/nox-framework/releases), then run:

```bash
sudo dpkg -i nox-cli_*_all.deb
nox-cli --help
```

The post-install script automatically:
1. Creates an isolated virtual environment at `/opt/nox-cli/.venv`
2. Installs all Python dependencies inside the venv (PEP 668 compliant — zero system pollution)
3. Builds the 126 source plugins
4. Links `/usr/bin/nox-cli` → `/opt/nox-cli/nox-wrapper.sh`

### Option 2: From Source

```bash
git clone https://github.com/nox-project/nox-framework.git
cd nox-framework
pip install -r requirements.txt
python build_sources.py
python3 nox.py
```

---

## Quick Start

**Step 1 — Build source plugins** *(from source only — .deb does this automatically)*

```bash
python build_sources.py
```

**Step 2 — Configure API keys**

`build_sources.py` creates `~/.config/nox-cli/apikeys.json` on first run, pre-populated with every supported service. The file is `chmod 0600` and is never committed to VCS.

This is the **single canonical key store** — all sources read from it at runtime.

```bash
# Edit the file directly
nano ~/.config/nox-cli/apikeys.json

# Or inspect plugin status and key configuration
nox-cli --list-sources
```

> [!NOTE]
> Any key set to `INSERT_API_KEY_HERE` or `""` is treated as unconfigured — that source is silently skipped. Sources without a key requirement are always active.
>
> **Load priority:** environment variable (e.g. `export HIBP_API_KEY=xxx`) → `~/.config/nox-cli/apikeys.json`

**Step 3 — Execute**

> [!NOTE]
> **OPSEC Kill-Switch:** By default, NOX activates the Guardian Engine (auto proxy rotation). Use `--guardian-off` to connect directly.

```bash
# Breach scan — input type auto-detected (email / domain / ip / username / hash / phone)
nox-cli -t target@company.com

# Full autoscan: breach + recursive pivot + dork + scrape
nox-cli -t target@company.com --autoscan

# Autoscan with Tor routing
nox-cli -t target@company.com --autoscan --tor

# Autoscan with SOCKS5 proxy + PDF report
nox-cli -t target@company.com --autoscan --proxy socks5://127.0.0.1:1080 -o report.pdf --format pdf

# Autoscan with custom pivot depth
nox-cli -t target@company.com --autoscan --depth 3

# Breach scan only — no pivot, no dork, no scrape
nox-cli -t target@company.com --no-pivot

# Domain scan
nox-cli -t company.com

# Hash identification and cracking
nox-cli --crack 5f4dcc3b5aa765d61d8327deb882cf99

# Hash cracking — local wordlist only, no third-party API calls
nox-cli --crack 5f4dcc3b5aa765d61d8327deb882cf99 --no-online-crack

# Password strength analysis
nox-cli --analyze "P@ssw0rd123"

# Google dorking
nox-cli --dork target@company.com

# Paste / Telegram scraping
nox-cli --scrape target@company.com

# Compare scan against last cached result — show only new findings
nox-cli -t target@company.com --diff

# Plugin debug: loaded sources, input types, confidence, key status
nox-cli --list-sources

# Force resync of source plugins from package
nox-cli --reset-sources
```

---

## CLI Reference

```
usage: nox-cli [-h] [-t TARGET] [-i] [--version]
               [--autoscan] [--fullscan] [--no-pivot] [--depth N]
               [--dork TARGET] [--scrape TARGET]
               [--crack HASH] [--no-online-crack]
               [--analyze PASS] [--list-sources] [--reset-sources]
               [--tor] [--proxy URL] [--guardian-off] [--allow-leak]
               [--threads N] [--timeout N]
               [-o FILE] [--format {json,csv,html,md,pdf}]
               [--diff]

  -t, --target TARGET     Target to scan (auto-detected type)
  -i, --interactive       Launch interactive REPL
  --version               Show version and exit
  --autoscan              Full pipeline: breach + pivot + dork + scrape
  --fullscan              Breach + pivot only (no dork/scrape)
  --no-pivot              Disable recursive pivot enrichment
  --depth N               Avalanche pivot depth (default: 2)
  --dork TARGET           Google/Bing/SearXNG dorking for leaked documents
  --scrape TARGET         Paste site + Telegram scraping
  --crack HASH            Identify and crack a hash
  --no-online-crack       Local wordlist only — no data sent to third-party APIs
  --analyze PASS          Deep password strength analysis
  --list-sources          Plugin debug: input type, confidence, key status
  --reset-sources         Force resync of source plugins from package
  --tor                   Route all traffic through Tor (port 9050)
  --proxy URL             HTTP/S or SOCKS5 proxy URL
  --guardian-off          Bypass OPSEC kill-switch (direct connection)
  --allow-leak            Allow direct connection if proxy/Tor is unavailable
  --threads N             Concurrency limit (default: 20)
  --timeout N             Request timeout in seconds (default: 15)
  -o, --output FILE       Output file path
  --format FORMAT         Output format: json, csv, html, md, pdf
  --diff                  Show only new findings vs last cached scan
```

---

## REPL

Launch the interactive REPL with no arguments:

```bash
nox-cli
```

```
Command        Description
-----------    ---------------------------------------------------------------
autoscan       Full pipeline: breach + pivot + dork + scrape
scan           Breach intelligence scan only
dork           Google/Bing/SearXNG dorking for leaked documents
scrape         Paste site + Telegram scraping
crack          Identify and crack a hash
analyze        Deep password strength analysis
graph          ASCII identity graph of last scan
visualize      ASCII relationship map (Target → Data → Pivots)
pivot <n>      Re-scan using result #n as new pivot seed
search <q>     Filter in-memory records by keyword
sources        Plugin debug: input type, confidence, key status
export         Export results (json / csv / html / md / pdf)
tor            Toggle Tor routing on/off
proxy          Set or clear proxy URL
config         Configure threads / timeout / depth
help           Show this menu
quit           Exit NOX
```

**Examples:**

```
nox> autoscan target@company.com
nox> graph
nox> visualize
nox> pivot 3
nox> search admin
nox> export pdf investigation.pdf
nox> sources
nox> config threads 30
nox> config depth 3
nox> proxy socks5://127.0.0.1:1080
nox> tor
```

---

## Source Management

### Adding a Source

**1. Define in `build_sources.py`:**

```python
_auth("NewIntelDB", "breaches",
      "https://api.newinteldb.com/v1/search?q={target}", "GET",
      {"results": "$.results"},
      headers={"X-API-Key": "{NEWINTELDB_API_KEY}"},
      api_key_slots=["{NEWINTELDB_API_KEY}"],
      normalization_map={"email": "email", "password": "password"},
      input_type="email",
      output_type=["username", "ip"],
      confidence=0.85)
```

**2. Rebuild:**

```bash
python build_sources.py
```

> [!NOTE]
> The builder validates every source at build time: GET endpoints must contain `{target}`, volatile sources must have `reliability_score ≤ 4`, and the `confidence` field can be set explicitly to override the formula-derived value.

---

## Building the .deb Package

```bash
gem install fpm
bash build_deb.sh
sudo dpkg -i dist/nox-cli_*_all.deb
```

---

## Legal Disclaimer

> [!WARNING]
> **NOX is intended exclusively for:**
> - Authorised penetration testing and red team engagements with explicit written consent
> - Corporate exposure analysis on assets you own or are contracted to assess
> - Digital forensics and incident response
> - Academic and security research in controlled, isolated environments
>
> **Unauthorised use of this tool against systems, networks, or individuals without explicit written permission is a criminal offence** under the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030), the Computer Misuse Act 1990 (CMA), and equivalent legislation in all major jurisdictions worldwide.
>
> The authors and contributors of NOX accept **no liability** for any direct, indirect, incidental, or consequential damages arising from misuse of this software. By downloading, installing, or executing NOX, you unconditionally agree to comply with all applicable local, national, and international laws, and to only target systems and data for which you hold explicit, documented authorisation.
>
> **If you do not agree to these terms, do not use this software.**

---

## License

[Apache License 2.0](LICENSE.txt)
