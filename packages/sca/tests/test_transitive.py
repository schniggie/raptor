"""Tests for ``packages.sca.transitive.expand_missing_transitives``.

The orchestrator is a thin coordinator over (b) cascade resolver and
(c) registry-metadata walk. The two underlying mechanisms have their
own dedicated test suites; here we exercise the per-(ecosystem,
project_dir) decision tree:

  - sibling lockfile present → skip
  - --no-resolve-transitive AND no fallback → skip
  - cascade succeeds → emit cascade_resolver-tagged deps
  - cascade fails AND fallback enabled → emit metadata_walk-tagged deps
  - cascade fails AND fallback disabled → emit skip status

Mocks: cascade resolver via ``get_resolver`` patch; metadata walker
via direct ``walk_transitive`` patch. No real network or subprocess
fires.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from unittest.mock import MagicMock

import pytest

from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.resolvers import ResolverResult
from packages.sca.transitive import (
    TransitiveStatus,
    expand_missing_transitives,
)


def _manifest(eco: str, path: Path, *, is_lockfile: bool = False) -> Manifest:
    return Manifest(path=path, ecosystem=eco, is_lockfile=is_lockfile)


def _direct(eco: str, name: str, version: str, host: Path) -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=host, scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT,
        direct=True, purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _transitive_dep(eco: str, name: str, version: str,
                     host: Path, source_kind: str = "lockfile") -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=host, scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=False,
        purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
        source_kind=source_kind,
    )


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------

def test_skips_when_sibling_lockfile_present(tmp_path):
    """A manifest with a sibling lockfile already on disk → skip
    transitive expansion; the lockfile parser handled it."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [
        _manifest("PyPI", proj / "requirements.txt"),
        _manifest("PyPI", proj / "Pipfile.lock", is_lockfile=True),
    ]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]
    deps, statuses = expand_missing_transitives(manifests, direct)
    assert deps == []
    assert len(statuses) == 1
    assert statuses[0].method == "skipped_lockfile_present"
    assert "Pipfile.lock" in (statuses[0].reason or "")


def test_skips_when_resolver_disabled_and_no_fallback(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]
    deps, statuses = expand_missing_transitives(
        manifests, direct,
        enable_resolver=False, enable_metadata_fallback=False,
    )
    assert deps == []
    assert statuses[0].method == "skipped_resolver_disabled"


# ---------------------------------------------------------------------------
# Cascade resolver path (mode b)
# ---------------------------------------------------------------------------

def test_cascade_succeeds_emits_cascade_tagged_deps(tmp_path, monkeypatch):
    """When cascade resolver succeeds, transitives are emitted with
    source_kind="cascade_resolver" so operators can distinguish from
    a checked-in lockfile."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("a==1.0\n", encoding="utf-8")
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    # Stub the resolver: pretend pip-compile produced a pinned reqs
    # file containing both the direct dep AND a transitive.
    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=True, available=True,
        proposed_lockfile=b"a==1.0\nb==2.0\n",
    )
    monkeypatch.setattr(
        "packages.sca.transitive.get_resolver"
        if False else "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)

    assert len(deps) == 1
    assert deps[0].name == "b"
    assert deps[0].version == "2.0"
    assert deps[0].source_kind == "cascade_resolver"
    assert deps[0].direct is False
    assert statuses[0].method == "cascade_resolver"
    assert statuses[0].deps_added == 1


def test_cascade_resolver_unavailable_falls_through(tmp_path, monkeypatch):
    """No toolchain → resolver returns is_available=False → cascade
    falls through. With fallback off, status records the skip."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = False
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)
    assert deps == []
    assert statuses[0].method == "skipped_no_method_succeeded"


def test_cascade_resolver_fails_falls_through(tmp_path, monkeypatch):
    """Resolver runs but exits non-zero (registry refused / can't
    satisfy). Fall through to skip status (no fallback)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=False, available=True,
        error="ResolutionImpossible: a requires b<1, c requires b>=2",
    )
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)
    assert deps == []
    assert statuses[0].method == "skipped_no_method_succeeded"


# ---------------------------------------------------------------------------
# Metadata-walk fallback (mode c)
# ---------------------------------------------------------------------------

def test_fallback_to_metadata_walk_when_cascade_fails(tmp_path, monkeypatch):
    """Cascade unavailable + fallback enabled → metadata walk fires,
    deps emitted with source_kind=metadata_walk."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    # Cascade unavailable.
    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = False
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    # Stub the metadata walker.
    from packages.sca.registry_metadata_walk import WalkResult
    walked = [_transitive_dep("PyPI", "b", "2.0",
                                proj / "requirements.txt",
                                source_kind="metadata_walk")]
    monkeypatch.setattr(
        "packages.sca.registry_metadata_walk.walk_transitive",
        lambda deps, **kw: WalkResult(
            deps_added=walked, visits=1, cache_hits=0,
            cache_misses=1, failures=0,
        ),
    )

    deps, statuses = expand_missing_transitives(
        manifests, direct,
        http=MagicMock(),
        enable_metadata_fallback=True,
    )
    assert len(deps) == 1
    assert deps[0].source_kind == "metadata_walk"
    assert statuses[0].method == "metadata_walk"
    assert "approximate" in (statuses[0].reason or "").lower()


def test_no_metadata_fallback_when_http_not_provided(tmp_path, monkeypatch):
    """Even with --fallback-registry-metadata, walk needs http.
    Without it, fall through to skip."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = False
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(
        manifests, direct,
        http=None,                 # no http
        enable_metadata_fallback=True,
    )
    assert deps == []
    assert statuses[0].method == "skipped_no_method_succeeded"


# ---------------------------------------------------------------------------
# Dedup against direct deps
# ---------------------------------------------------------------------------

def test_dedup_against_direct_deps(tmp_path, monkeypatch):
    """If cascade output includes a dep that's ALSO already declared
    direct, don't re-emit it as a transitive — operator already saw
    it via the manifest."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [
        _direct("PyPI", "a", "1.0", proj / "requirements.txt"),
        _direct("PyPI", "b", "2.0", proj / "requirements.txt"),
    ]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    # Cascade output includes both direct deps + a new transitive.
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=True, available=True,
        proposed_lockfile=b"a==1.0\nb==2.0\nc==3.0\n",
    )
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, _ = expand_missing_transitives(manifests, direct)
    names = {d.name for d in deps}
    assert names == {"c"}     # b stripped (already direct)


# ---------------------------------------------------------------------------
# Multi-ecosystem orchestration
# ---------------------------------------------------------------------------

def test_per_ecosystem_independent_decisions(tmp_path, monkeypatch):
    """A project with PyPI + npm: PyPI cascade succeeds, npm has no
    toolchain → falls back. Each ecosystem reports its own status."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [
        _manifest("PyPI", proj / "requirements.txt"),
        _manifest("npm", proj / "package.json"),
    ]
    direct = [
        _direct("PyPI", "a", "1.0", proj / "requirements.txt"),
        _direct("npm", "lodash", "4.17.21", proj / "package.json"),
    ]

    def fake_get_resolver(eco, project_dir=None):
        r = MagicMock()
        if eco == "PyPI":
            r.is_available.return_value = True
            r.dry_run.return_value = ResolverResult(
                ecosystem="PyPI", success=True, available=True,
                proposed_lockfile=b"a==1.0\npy_trans==1.0\n",
            )
        else:
            r.is_available.return_value = False
        return r

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver", fake_get_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)
    by_eco = {s.ecosystem: s for s in statuses}
    assert by_eco["PyPI"].method == "cascade_resolver"
    assert by_eco["npm"].method == "skipped_no_method_succeeded"
    # PEP 503: parser normalises "py_trans" → "py-trans".
    assert any(d.name == "py-trans" for d in deps)
    assert all(d.ecosystem != "npm" for d in deps)
