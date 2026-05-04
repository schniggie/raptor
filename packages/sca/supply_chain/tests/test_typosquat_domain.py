"""Tests for the domain-typosquat detector."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.supply_chain.typosquat_domain import scan_target


def _manifests(target: Path) -> list:
    return [Manifest(
        path=target / "package.json", ecosystem="npm", is_lockfile=False,
    )]


def test_distance_1_typosquat_fires_high(tmp_path: Path) -> None:
    """Trivy attack pattern: ``aquasecurtiy.org`` (distance 1 from
    ``aquasecurity.org``) → high severity."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://aquasecurtiy.org/payload'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].suspect_host == "aquasecurtiy.org"
    assert out[0].nearest_popular == "aquasecurity.org"
    assert out[0].distance == 1
    assert out[0].severity == "high"


def test_exact_popular_host_not_flagged(tmp_path: Path) -> None:
    """``github.com`` IS the popular host — must not flag."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "config.json").write_text(
        '{"url": "https://github.com/repo"}\n', encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_distance_2_medium_severity(tmp_path: Path) -> None:
    """``glthlb.com`` (two substitutions from ``github.com``,
    distance 2) → medium."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.js").write_text(
        "fetch('https://glthlb.com/api')\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].distance == 2
    assert out[0].severity == "medium"


def test_far_distance_not_flagged(tmp_path: Path) -> None:
    """A genuinely-different host shouldn't false-positive."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://example.com/api'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_test_directory_excluded(tmp_path: Path) -> None:
    """URLs in ``tests/`` are usually fixtures — skip."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.py").write_text(
        "URL = 'https://aquasecurtiy.org/payload'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_localhost_skipped(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'http://localhost:8080/api'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_orchestrator_emits_finding(tmp_path: Path) -> None:
    """End-to-end through the supply-chain orchestrator."""
    from packages.sca.models import Dependency, Confidence, PinStyle
    from packages.sca.supply_chain import evaluate

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://aquasecurtiy.org/p'\n", encoding="utf-8")
    deps = [Dependency(
        ecosystem="npm", name="x", version="1.0",
        declared_in=tmp_path / "package.json",
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:npm/x@1.0",
        parser_confidence=Confidence("high", reason="t"),
    )]
    findings = evaluate(tmp_path, _manifests(tmp_path), deps)
    kinds = {f.kind for f in findings}
    assert "typosquat_domain" in kinds
