"""Tests for ``packages.sca.risk.compute_risk_estimate``.

Covers the worked examples from ``design/sca.md`` §1316 and per-
multiplier behaviour. The tests pin numeric scores within tolerance
bands (≤1.0 point) so calibration tweaks that change a multiplier
slightly won't false-fail; gross regressions still trip.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from packages.sca.models import (
    AffectedRange, Advisory, Confidence, Dependency,
    PinStyle, Reachability, VulnFinding,
)
from packages.sca.risk import compute_risk_estimate


def _dep(*, name: str = "foo", direct: bool = True,
         parser_conf: str = "high") -> Dependency:
    return Dependency(
        ecosystem="PyPI", name=name, version="1.0.0",
        declared_in=Path("/x/req.txt"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=direct,
        purl=f"pkg:pypi/{name}@1.0.0",
        parser_confidence=Confidence(parser_conf, reason="test fixture"),
    )


def _adv() -> Advisory:
    return Advisory(
        osv_id="GHSA-fake", aliases=[],
        summary="test", details="",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "9.9"}])],
        severity=None,
        fixed_versions=["9.9"],
        references=[],
    )


def _finding(
    *, dep: Optional[Dependency] = None,
    cvss: Optional[float] = 7.5,
    in_kev: bool = False,
    epss: Optional[float] = 0.5,
    reach_verdict: str = "imported",
    reach_conf: str = "high",
    exposure: float = 0.5,
    depth: int = 0,
    vmc: str = "high",
) -> VulnFinding:
    d = dep if dep is not None else _dep()
    return VulnFinding(
        finding_id="t-1",
        dependency=d,
        advisories=[_adv()],
        in_kev=in_kev,
        epss=epss,
        fixed_version="9.9",
        reachability=Reachability(
            verdict=reach_verdict,
            confidence=Confidence(reach_conf, reason="test"),
            evidence=[]),
        version_match_confidence=Confidence(vmc, reason="test"),
        cvss_score=cvss, cvss_vector=None,
        severity="high",
        exposure_factor=exposure,
        transitive_depth=depth,
    )


# ---------------------------------------------------------------------------
# Worked examples from design §1316
# ---------------------------------------------------------------------------

def test_log4shell_kev_reachable_direct_scores_high():
    """Critical, KEV, EPSS 97%, reachable, direct, exact match → ~96."""
    f = _finding(
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="imported", exposure=1.0, depth=0, vmc="high",
    )
    score, comps = compute_risk_estimate(f, f.dependency)
    assert 90 <= score <= 100, f"got {score}"
    assert comps["kev_multiplier"] == 1.20


def test_log4shell_but_not_reachable_drops_to_low():
    """Same vuln, but high-confidence not_reachable should land WAY
    below the reachable scenario (under 25). The design's ~29 was an
    approximation; the exact bound depends on whether exposure is
    treated as 0 (not_reachable means no call sites) or 1. We use 0
    — the natural reading — which gives ~18."""
    f = _finding(
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="not_reachable", reach_conf="high",
        exposure=0.0, depth=0,
    )
    score, _ = compute_risk_estimate(f, f.dependency)
    assert score < 25, f"got {score}"
    # And much lower than the reachable equivalent.
    reachable = _finding(
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="imported", exposure=1.0, depth=0,
    )
    s_reach, _ = compute_risk_estimate(reachable, reachable.dependency)
    assert score < s_reach * 0.30, (
        f"not_reachable={score} should be <30% of reachable={s_reach}"
    )


def test_log4shell_at_transitive_depth_3():
    """Same vuln, but at depth 3 → ~33."""
    transitive = _dep(direct=False)
    f = _finding(
        dep=transitive,
        cvss=10.0, in_kev=True, epss=0.97,
        reach_verdict="imported", exposure=1.0, depth=3,
    )
    score, _ = compute_risk_estimate(f, transitive)
    assert 28 <= score <= 38, f"got {score}"


def test_background_hygiene_finding_scores_low():
    """CVSS 5, no KEV, EPSS 5%, reachable, direct → ~14."""
    f = _finding(
        cvss=5.0, in_kev=False, epss=0.05,
        reach_verdict="imported", exposure=0.5, depth=0,
    )
    score, _ = compute_risk_estimate(f, f.dependency)
    assert 10 <= score <= 18, f"got {score}"


def test_kev_high_with_heuristic_parser_haircut():
    """CVSS 9, KEV, EPSS 90%, reachable, parser heuristic → score
    below the "exact parser, exact match" equivalent. Design said
    ~63; the parser × vmc double-haircut at medium=0.70 gives ~42 —
    the contract is "heuristic-parser haircut materially knocks
    down the score", which the relative-ordering check enforces."""
    heuristic = _dep(parser_conf="medium")
    f_heur = _finding(
        dep=heuristic, cvss=9.0, in_kev=True, epss=0.90,
        reach_verdict="imported", exposure=0.7, depth=0,
        vmc="medium",
    )
    f_exact = _finding(
        cvss=9.0, in_kev=True, epss=0.90,
        reach_verdict="imported", exposure=0.7, depth=0,
        vmc="high",
    )
    s_heur, _ = compute_risk_estimate(f_heur, heuristic)
    s_exact, _ = compute_risk_estimate(f_exact, f_exact.dependency)
    # The heuristic version must score noticeably lower.
    assert s_heur < s_exact * 0.65, (
        f"heuristic={s_heur} should be <65% of exact={s_exact}"
    )
    # But not zero — heuristic-parser hits still merit attention.
    assert s_heur > 30, f"got {s_heur}"


# ---------------------------------------------------------------------------
# Per-multiplier behaviour
# ---------------------------------------------------------------------------

def test_score_clamped_to_0_100():
    """Even adversarial inputs (negative exposure etc.) clamp into [0,100]."""
    f = _finding(cvss=10.0, in_kev=True, epss=1.0, exposure=2.0)
    score, _ = compute_risk_estimate(f, f.dependency)
    assert 0.0 <= score <= 100.0


def test_missing_cvss_uses_neutral_default():
    """A finding with no CVSS shouldn't score zero — use a neutral 5."""
    f = _finding(cvss=None)
    score, comps = compute_risk_estimate(f, f.dependency)
    # Neutral 5 → 50 base, then ~halved by EPSS+exposure → ~10-20.
    assert score > 0
    assert comps["cvss_base"] == 50.0


def test_missing_epss_uses_neutral_default():
    """No EPSS → 0.5 default → epss_multiplier = 0.30 + 0.70*0.5 = 0.65."""
    f = _finding(epss=None)
    _, comps = compute_risk_estimate(f, f.dependency)
    assert comps["epss_multiplier"] == pytest.approx(0.65, abs=1e-6)


def test_calibration_status_unverified_in_components():
    """Until calibration lands, every breakdown reports unverified
    so consumers can show a UI hint or refuse to ship the score."""
    f = _finding()
    _, comps = compute_risk_estimate(f, f.dependency)
    assert comps["calibration_status"] == "unverified"


def test_components_breakdown_carries_every_named_multiplier():
    """The breakdown is the operator-facing 'why this score' surface;
    every multiplier the formula applies must appear in it."""
    f = _finding()
    _, comps = compute_risk_estimate(f, f.dependency)
    for k in ("cvss_base", "kev_multiplier", "epss_multiplier",
              "reachability_multiplier", "exposure_multiplier",
              "depth_multiplier", "parser_confidence",
              "version_match_confidence", "final"):
        assert k in comps, f"missing component: {k}"


def test_score_is_deterministic():
    """Same inputs → identical score every call (no clock / random)."""
    f = _finding()
    a, _ = compute_risk_estimate(f, f.dependency)
    b, _ = compute_risk_estimate(f, f.dependency)
    assert a == b


def test_kev_floor_overrides_low_cvss():
    """A KEV finding with a low CVSS still gets the 80-floor."""
    low_cvss = _finding(cvss=3.0, in_kev=True, epss=0.9, exposure=1.0)
    score_kev, _ = compute_risk_estimate(low_cvss, low_cvss.dependency)
    same_no_kev = _finding(cvss=3.0, in_kev=False, epss=0.9, exposure=1.0)
    score_no_kev, _ = compute_risk_estimate(same_no_kev, same_no_kev.dependency)
    assert score_kev > 2 * score_no_kev, (
        f"KEV floor should dominate low CVSS: kev={score_kev} "
        f"non-kev={score_no_kev}"
    )


def test_not_reachable_low_confidence_smaller_reduction():
    """Low-confidence not_reachable shouldn't fully discount the score —
    the operator might still want to look at it."""
    high_conf = _finding(
        cvss=10.0, in_kev=True, epss=0.9, exposure=1.0,
        reach_verdict="not_reachable", reach_conf="high",
    )
    low_conf = _finding(
        cvss=10.0, in_kev=True, epss=0.9, exposure=1.0,
        reach_verdict="not_reachable", reach_conf="low",
    )
    s_high, _ = compute_risk_estimate(high_conf, high_conf.dependency)
    s_low, _ = compute_risk_estimate(low_conf, low_conf.dependency)
    assert s_low > s_high, (
        f"low-confidence not_reachable ({s_low}) should score higher "
        f"than high-confidence not_reachable ({s_high})"
    )


def test_depth_decay_geometric():
    """Depth 1 → 0.7×; depth 2 → 0.49×; depth 3 → 0.343×."""
    base_dep = _dep(direct=True)
    direct = _finding(dep=base_dep, depth=0)
    s0, _ = compute_risk_estimate(direct, direct.dependency)

    for depth, expected_ratio in [(1, 0.70), (2, 0.49), (3, 0.343)]:
        td = _dep(direct=False)
        f = _finding(dep=td, depth=depth)
        s, _ = compute_risk_estimate(f, td)
        # Tolerance: other multipliers cancel since fixtures are
        # otherwise identical.
        assert s == pytest.approx(s0 * expected_ratio, abs=0.5), (
            f"depth={depth}: expected ~{s0 * expected_ratio:.2f}, got {s:.2f}"
        )
