"""Tests for the ``libexec/raptor-sca-gate`` script.

The gate is implemented as a libexec Python script — we import it
directly via the harness's ``sys.path`` (the script also lives on the
filesystem and is exec'able, but the test focuses on the threshold
logic, not the invocation surface).
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType

import pytest

_GATE_PATH = Path(__file__).resolve().parents[3] / "libexec" / "raptor-sca-gate"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    """Load the libexec script as a module despite its suffix-less name."""
    loader = SourceFileLoader("raptor_sca_gate", str(_GATE_PATH))
    spec = importlib.util.spec_from_loader("raptor_sca_gate", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _write_findings(tmp_path: Path, rows: list) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# --findings mode
# ---------------------------------------------------------------------------

def test_pass_when_no_findings(tmp_path: Path, gate) -> None:
    p = _write_findings(tmp_path, [])
    assert gate.main(["--findings", str(p)]) == 0


def test_fail_above_severity_threshold(tmp_path: Path, gate) -> None:
    p = _write_findings(tmp_path, [
        {"vuln_type": "sca:vulnerable_dependency",
         "severity": "critical",
         "description": "boom",
         "sca": {"in_kev": False}},
    ])
    assert gate.main(["--findings", str(p), "--severity", "high"]) == 1


def test_pass_below_severity_threshold(tmp_path: Path, gate) -> None:
    p = _write_findings(tmp_path, [
        {"vuln_type": "sca:vulnerable_dependency",
         "severity": "low",
         "description": "minor",
         "sca": {"in_kev": False}},
    ])
    assert gate.main(["--findings", str(p), "--severity", "high"]) == 0


def test_fail_on_kev_overrides_severity(tmp_path: Path, gate) -> None:
    """A KEV-listed CVE flags even when its severity is below the floor."""
    p = _write_findings(tmp_path, [
        {"vuln_type": "sca:vulnerable_dependency",
         "severity": "low",
         "description": "kev-low",
         "sca": {"in_kev": True}},
    ])
    rc = gate.main(["--findings", str(p), "--severity", "high",
                    "--fail-on-kev"])
    assert rc == 1


def test_supply_chain_threshold_separate(tmp_path: Path, gate) -> None:
    """Supply-chain findings only fail when their threshold is set."""
    p = _write_findings(tmp_path, [
        {"vuln_type": "sca:supply_chain:install_hook_suspicious",
         "severity": "high",
         "description": "curl|sh"},
    ])
    # Without --fail-on-supply-chain, this passes:
    assert gate.main(["--findings", str(p), "--severity", "critical"]) == 0
    # With --fail-on-supply-chain, fails:
    assert gate.main(["--findings", str(p), "--severity", "critical",
                      "--fail-on-supply-chain", "high"]) == 1


def test_hygiene_threshold_separate(tmp_path: Path, gate) -> None:
    p = _write_findings(tmp_path, [
        {"vuln_type": "sca:hygiene:lockfile_drift",
         "severity": "high",
         "description": "drift"},
    ])
    assert gate.main(["--findings", str(p), "--severity", "critical"]) == 0
    rc = gate.main(["--findings", str(p), "--severity", "critical",
                    "--fail-on-hygiene", "high"])
    assert rc == 1


def test_unknown_vuln_type_ignored(tmp_path: Path, gate) -> None:
    p = _write_findings(tmp_path, [
        {"vuln_type": "scan:something_else", "severity": "critical",
         "description": "from a different tool"},
    ])
    assert gate.main(["--findings", str(p)]) == 0


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

def test_missing_target_and_findings_returns_2(gate) -> None:
    assert gate.main([]) == 2


def test_findings_path_does_not_exist(tmp_path: Path, gate) -> None:
    assert gate.main(["--findings", str(tmp_path / "missing.json")]) == 2


def test_findings_corrupt_json(tmp_path: Path, gate) -> None:
    p = tmp_path / "findings.json"
    p.write_text("{ not json", encoding="utf-8")
    assert gate.main(["--findings", str(p)]) == 2


def test_findings_not_a_list(tmp_path: Path, gate) -> None:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps({"results": []}), encoding="utf-8")
    assert gate.main(["--findings", str(p)]) == 2


# ---------------------------------------------------------------------------
# Pipeline mode (target → run pipeline → evaluate)
# ---------------------------------------------------------------------------

def test_pipeline_mode_clean_repo_passes(tmp_path: Path, gate) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "package.json").write_text(
        '{"dependencies": {"@types/node": "20.10.5"}}',
        encoding="utf-8",
    )
    rc = gate.main([str(target), "--offline",
                    "--out", str(tmp_path / "out")])
    assert rc == 0


def test_pipeline_mode_target_not_a_dir_returns_2(tmp_path: Path, gate) -> None:
    f = tmp_path / "file"
    f.write_text("x")
    assert gate.main([str(f)]) == 2
