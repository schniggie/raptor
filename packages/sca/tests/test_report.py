"""Tests for ``packages.sca.report``."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from packages.sca.findings import build_vuln_findings
from packages.sca.models import (
    AffectedRange,
    Advisory,
    CVSSScore,
    Confidence,
    Dependency,
    HygieneFinding,
    PinStyle,
)
from packages.sca.osv import OsvResult
from packages.sca.report import (
    render_markdown_report,
    write_markdown_report,
)


def _dep(name: str = "lodash", version: str = "4.17.20",
         direct: bool = True) -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version=version,
        declared_in=Path("/repo/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=direct,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv(osv_id: str = "GHSA-x", severity: str = "critical",
         score: float = 9.8) -> Advisory:
    return Advisory(
        osv_id=osv_id,
        aliases=["CVE-2099-9999"],
        summary="Test advisory summary.",
        details="Long detail block " * 60,
        affected=[AffectedRange(type="ECOSYSTEM",
                                events=[{"introduced": "0"}, {"fixed": "5"}])],
        severity=CVSSScore(score=score,
                           vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           severity=severity),         # type: ignore[arg-type]
        fixed_versions=["5.0.0"],
        references=["https://example.com/", "https://other.example/"],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


def _hygiene(kind: str = "lockfile_drift",
             severity: str = "high") -> HygieneFinding:
    return HygieneFinding(
        finding_id=f"sca:hygiene:{kind}:npm:lodash:/repo/package.json",
        kind=kind,         # type: ignore[arg-type]
        dependency=_dep(),
        detail="manifest pins 4.17.20 but lockfile resolves 4.17.21",
        severity=severity,         # type: ignore[arg-type]
        confidence=Confidence("high", reason="exact pin disagrees"),
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_empty_report_states_no_findings(tmp_path: Path) -> None:
    md = render_markdown_report(
        target=tmp_path,
        deps_analysed=42,
        vuln_findings=[],
        hygiene_findings=[],
    )
    assert "No vulnerabilities" in md
    assert "Dependencies analysed: **42**" in md


def test_report_includes_severity_table_and_kev_badge() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[_adv()])],
    )
    findings[0].in_kev = True
    findings[0].epss = 0.97
    md = render_markdown_report(
        target=Path("/repo"),
        deps_analysed=10,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "## Summary" in md
    assert "| Critical | 1 |" in md
    assert "**KEV**" in md
    assert "EPSS 0.97" in md


def test_findings_are_sorted_by_severity_then_kev_then_epss() -> None:
    d_low = _dep(name="low-pkg")
    d_med = _dep(name="med-pkg")
    d_kev = _dep(name="kev-pkg")
    d_hi  = _dep(name="hi-pkg")
    findings = []
    findings.extend(build_vuln_findings(
        [d_low], [OsvResult(d_low.key(), [_adv("GHSA-l", "low", 3.0)])],
    ))
    findings.extend(build_vuln_findings(
        [d_med], [OsvResult(d_med.key(), [_adv("GHSA-m", "medium", 5.5)])],
    ))
    f_kev = build_vuln_findings(
        [d_kev], [OsvResult(d_kev.key(), [_adv("GHSA-k", "high", 7.5)])],
    )[0]
    f_kev.in_kev = True
    findings.append(f_kev)
    findings.extend(build_vuln_findings(
        [d_hi], [OsvResult(d_hi.key(), [_adv("GHSA-h", "high", 7.0)])],
    ))

    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=4,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    # KEV-tagged high comes before non-KEV high, both come before
    # medium and low.
    pos_kev = md.index("kev-pkg")
    pos_high = md.index("hi-pkg")
    pos_med = md.index("med-pkg")
    pos_low = md.index("low-pkg")
    assert pos_kev < pos_high < pos_med < pos_low


def test_long_advisory_detail_truncated() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "truncated; see findings.json" in md


def test_hygiene_section_rendered() -> None:
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=[],
        hygiene_findings=[_hygiene()],
    )
    assert "## Hygiene findings" in md
    assert "lockfile_drift" in md


def test_cache_stats_when_provided() -> None:
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=10,
        vuln_findings=[],
        hygiene_findings=[],
        cache_hits=8,
        cache_misses=2,
    )
    assert "8 hits / 2 misses" in md
    assert "80%" in md


def test_no_emoji_or_red_green_indicators() -> None:
    """CLAUDE.md mandates no perspective-dependent colour glyphs."""
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=build_vuln_findings(
            [_dep()], [OsvResult(_dep().key(), [_adv()])],
        ),
        hygiene_findings=[_hygiene()],
    )
    for forbidden in ("🔴", "🟢"):
        assert forbidden not in md


def test_write_markdown_report_atomic(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    write_markdown_report(out, "# x\n")
    assert out.read_text() == "# x\n"
    assert all(p.suffix != ".tmp" for p in tmp_path.iterdir())


def test_advisory_text_with_ansi_or_bidi_is_sanitised() -> None:
    """OSV-supplied advisory text could carry ANSI escapes or BIDI
    overrides; the renderer must strip them so the markdown is safe to
    paste into terminals / chat / code review."""
    d = _dep()
    a = _adv()
    a.summary = "danger \x1b[31mred\x1b[0m and \u202emalicious\u202c text"
    a.details = "\x07line\u200b break"
    findings = build_vuln_findings([d], [OsvResult(d.key(), [a])])
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    # Raw escape bytes don't appear.
    assert "\x1b[" not in md
    assert "\u202e" not in md and "\u202c" not in md
    assert "\u200b" not in md
    assert "\x07" not in md
    # The visible text survives.
    assert "danger" in md and "red" in md and "malicious" in md
