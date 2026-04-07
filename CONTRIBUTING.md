# Contributing to NOX

## Before You Start

NOX is a security tool. All contributions must comply with the [Legal Disclaimer](README.md#legal-disclaimer) and the [Apache 2.0 License](LICENSE.txt).

## Adding an Intelligence Source

All sources are defined exclusively in `build_sources.py`. Never edit `sources/*.json` directly — they are auto-generated artifacts.

1. Add a `_base()` (public) or `_auth()` (API key required) call in `build_sources.py`
2. Run `python build_sources.py` to regenerate and validate all plugins
3. Verify with `nox-cli --sources`

## Code Style

- Python 3.8+ compatible
- No new runtime dependencies without justification in the PR
- All async I/O through `aiohttp` — no `requests` in hot paths
- Error handling: log at `DEBUG`, never crash the scan loop

## Pull Request Checklist

- [ ] `python3 -m py_compile nox.py` passes
- [ ] `python build_sources.py` completes without errors
- [ ] No credentials, API keys, or personal data in the diff
- [ ] `sources/*.json` regenerated if `build_sources.py` was modified

## Reporting Bugs

Open a GitHub issue with:
- NOX version (`nox-cli --version`)
- Python version
- Minimal reproduction steps
- Expected vs actual behaviour
