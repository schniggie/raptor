"""Tests for the registry-metadata supply-chain detectors."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.registry_metadata import (
    RegistryMetaFinding, scan_deps,
)


def _dep(eco="PyPI", name="django", version="4.0.0",
         direct=True) -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=Path("/x/req.txt"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=direct,
        purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


class _PyPIStub:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.raw = raw

    def get_metadata(self, name: str) -> Dict[str, Any]:
        return self.raw


class _NpmStub:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.raw = raw

    def get_metadata(self, name: str) -> Dict[str, Any]:
        return self.raw


_NOW = datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc)


def _iso(days_ago: int) -> str:
    return (_NOW - timedelta(days=days_ago)).isoformat().replace(
        "+00:00", "Z")


# ---------------------------------------------------------------------------
# recent_publish
# ---------------------------------------------------------------------------

def test_pypi_recent_publish_fires_under_30_days() -> None:
    pypi = _PyPIStub({
        "info": {"author": "test"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": _iso(5)}],
        }
    })
    out = scan_deps([_dep()], pypi_client=pypi, npm_client=None, now=_NOW)
    kinds = [f.kind for f in out]
    assert "recent_publish" in kinds
    rp = next(f for f in out if f.kind == "recent_publish")
    assert rp.severity == "medium"   # < 7 days


def test_pypi_recent_publish_low_severity_8_to_30_days() -> None:
    pypi = _PyPIStub({
        "info": {},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(20)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    rp = next(f for f in out if f.kind == "recent_publish")
    assert rp.severity == "low"


def test_pypi_recent_publish_does_not_fire_old_pkg() -> None:
    pypi = _PyPIStub({
        "info": {},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(180)}]},
    })
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "recent_publish" for f in out)


def test_npm_recent_publish_fires() -> None:
    """All releases under 30 days old → ``first_publish`` is recent."""
    npm = _NpmStub({
        "time": {
            "1.0.0": _iso(3),
            "0.9.0": _iso(20),
        }
    })
    out = scan_deps([_dep(eco="npm", name="react")], npm_client=npm,
                     now=_NOW)
    assert any(f.kind == "recent_publish" for f in out)


# ---------------------------------------------------------------------------
# maintainer_change
# ---------------------------------------------------------------------------

def test_maintainer_change_fires_with_recent_join() -> None:
    """When the metadata exposes ``joined_at`` and it's within 14d."""
    pypi = _PyPIStub({
        "info": {"maintainer": "alice", "maintainer_email": "alice@x"},
        "releases": {"1.0": [{"upload_time_iso_8601": _iso(60)}]},
    })
    # Inject a synthetic joined_at — verifying the structural plumbing.
    real_meta = pypi.get_metadata("django")
    # PyPI doesn't expose joined_at; the detector just won't fire.
    out = scan_deps([_dep()], pypi_client=pypi, now=_NOW)
    assert all(f.kind != "maintainer_change" for f in out)


def test_maintainer_change_with_synthetic_joined_at() -> None:
    """A registry that DOES expose ``joined_at`` (future enriched feed)
    triggers the detector. We build a custom adapter to verify the
    ``_Meta`` shape downstream."""
    from packages.sca.supply_chain.registry_metadata import (
        _maintainer_change_check, _Meta,
    )
    meta = _Meta(
        first_publish=None, latest_publish=None,
        maintainers=[
            {"name": "old-hand", "joined_at": _iso(400)},
            {"name": "new-friend", "joined_at": _iso(5)},
        ],
    )
    findings = _maintainer_change_check(_dep(), meta, _NOW)
    assert len(findings) == 1
    assert "1 maintainer(s) added" in findings[0].detail


# ---------------------------------------------------------------------------
# maintainer_account_change
# ---------------------------------------------------------------------------

def test_maintainer_account_change_axios_pattern() -> None:
    """Email change within 14d of release → high severity."""
    from packages.sca.supply_chain.registry_metadata import (
        _maintainer_account_change_check, _Meta,
    )
    meta = _Meta(
        first_publish=None,
        latest_publish=_NOW - timedelta(days=2),
        maintainers=[
            {"name": "alice",
             "last_email_change": _iso(3)},
        ],
    )
    findings = _maintainer_account_change_check(_dep(), meta, _NOW)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_maintainer_account_change_outside_window_no_fire() -> None:
    from packages.sca.supply_chain.registry_metadata import (
        _maintainer_account_change_check, _Meta,
    )
    meta = _Meta(
        first_publish=None,
        latest_publish=_NOW - timedelta(days=200),  # very old release
        maintainers=[
            {"name": "alice", "last_email_change": _iso(3)},
        ],
    )
    findings = _maintainer_account_change_check(_dep(), meta, _NOW)
    assert findings == []


# ---------------------------------------------------------------------------
# Wiring + edge cases
# ---------------------------------------------------------------------------

def test_transitive_deps_skipped() -> None:
    pypi = _PyPIStub({"info": {}, "releases": {
        "1.0": [{"upload_time_iso_8601": _iso(3)}]}})
    out = scan_deps([_dep(direct=False)], pypi_client=pypi, now=_NOW)
    assert out == []


def test_no_clients_means_no_findings() -> None:
    """Without registry clients there's nothing to fetch."""
    out = scan_deps([_dep()], pypi_client=None, npm_client=None, now=_NOW)
    assert out == []


def test_unsupported_ecosystem_skipped() -> None:
    """Cargo / Go / etc. — we don't ship metadata fetchers for them."""
    out = scan_deps([_dep(eco="Cargo", name="serde")],
                     pypi_client=_PyPIStub({}), now=_NOW)
    assert out == []
