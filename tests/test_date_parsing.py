"""Tests for _parse_breach_date — ISO-8601, offset, written, slash, year-only."""
import pytest
from datetime import datetime, timezone

from nox import _parse_breach_date


class TestParseBreachDate:
    """Validate that _parse_breach_date handles all known date formats."""

    def test_none_input(self):
        assert _parse_breach_date(None) is None

    def test_empty_string(self):
        assert _parse_breach_date("") is None

    def test_whitespace_only(self):
        assert _parse_breach_date("   ") is None

    # ── ISO-8601 variants ─────────────────────────────────────────────
    def test_iso_basic(self):
        dt = _parse_breach_date("2024-03-22")
        assert dt == datetime(2024, 3, 22, tzinfo=timezone.utc)

    def test_iso_datetime(self):
        dt = _parse_breach_date("2024-03-22T10:15:30")
        assert dt.year == 2024
        assert dt.month == 3
        assert dt.hour == 10

    def test_iso_with_z(self):
        dt = _parse_breach_date("2024-03-22T10:15:30.123Z")
        assert dt is not None
        assert dt.year == 2024
        assert dt.tzinfo is not None

    def test_iso_with_offset(self):
        dt = _parse_breach_date("2023-11-05T14:30:00+02:00")
        assert dt is not None
        assert dt.year == 2023
        assert dt.month == 11

    def test_iso_space_separator(self):
        dt = _parse_breach_date("2024-03-22 10:15:30")
        assert dt.year == 2024

    # ── Slash-separated ───────────────────────────────────────────────
    def test_mm_dd_yyyy(self):
        dt = _parse_breach_date("03/22/2024")
        assert dt is not None
        assert dt.year == 2024

    # ── Year only ─────────────────────────────────────────────────────
    def test_year_only(self):
        dt = _parse_breach_date("2018")
        assert dt == datetime(2018, 1, 1, tzinfo=timezone.utc)

    # ── Written / rare formats (require dateutil) ─────────────────────
    def test_written_format(self):
        dt = _parse_breach_date("March 5th, 2020")
        assert dt is not None
        assert dt.year == 2020
        assert dt.month == 3
        assert dt.day == 5

    def test_slash_yyyy_mm_dd(self):
        dt = _parse_breach_date("2021/10/05")
        assert dt is not None
        assert dt.year == 2021

    # ── Timezone always present ───────────────────────────────────────
    def test_tz_always_set(self):
        """Every successfully parsed date must carry a timezone."""
        samples = [
            "2024-03-22", "2024-03-22T10:15:30", "2018",
            "03/22/2024", "March 5th, 2020",
        ]
        for s in samples:
            dt = _parse_breach_date(s)
            assert dt is not None, f"Failed to parse: {s}"
            assert dt.tzinfo is not None, f"Missing tzinfo for: {s}"
