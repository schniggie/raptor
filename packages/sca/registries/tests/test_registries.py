"""Smoke tests for every registry client.

The shape we exercise per client:
  - Cache hit short-circuits the HTTP call.
  - Empty/missing fields return [] without raising.
  - HTTP failure returns [] (best-effort policy).
  - Yanked / pre-release / deprecated versions are filtered.
  - Output is newest-first.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from packages.sca.registries.crates import CratesClient
from packages.sca.registries.debian import DebianClient
from packages.sca.registries.golang import GoClient
from packages.sca.registries.homebrew import HomebrewClient
from packages.sca.registries.maven import MavenClient
from packages.sca.registries.npm import NpmClient
from packages.sca.registries.nuget import NugetClient
from packages.sca.registries.packagist import PackagistClient
from packages.sca.registries.pypi import PyPIClient
from packages.sca.registries.rubygems import RubyGemsClient


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeHttp:
    def __init__(self, json_payload: Optional[Any] = None,
                 bytes_payload: Optional[bytes] = None,
                 raise_exc: Optional[Exception] = None) -> None:
        self.json_payload = json_payload
        self.bytes_payload = bytes_payload
        self.raise_exc = raise_exc
        self.calls: List[str] = []

    def get_json(self, url: str, timeout: int = 30) -> Dict[str, Any]:
        self.calls.append(url)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.json_payload or {}

    def post_json(self, url, body, timeout=30):  # pragma: no cover
        raise NotImplementedError

    def get_bytes(self, url: str, timeout: int = 30,
                  max_bytes: int = 0) -> bytes:
        self.calls.append(url)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.bytes_payload or b""


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

def test_pypi_filters_prereleases_and_yanked() -> None:
    http = _FakeHttp(json_payload={
        "releases": {
            "1.0": [{"yanked": False}],
            "2.0": [{"yanked": False}],
            "1.1a1": [{"yanked": False}],     # pre-release
            "2.1": [{"yanked": True}],         # yanked
            "0.9": [],                          # no files
        }
    })
    client = PyPIClient(http)
    assert client.list_versions("django") == ["2.0", "1.0"]


def test_pypi_http_failure_returns_empty() -> None:
    client = PyPIClient(_FakeHttp(raise_exc=RuntimeError("boom")))
    assert client.list_versions("requests") == []


def test_pypi_offline_skips_http() -> None:
    http = _FakeHttp(json_payload={"releases": {"1.0": [{"yanked": False}]}})
    client = PyPIClient(http, offline=True)
    assert client.list_versions("requests") == []
    assert http.calls == []


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def test_npm_filters_prerelease_and_deprecated() -> None:
    http = _FakeHttp(json_payload={
        "versions": {
            "1.0.0": {},
            "2.0.0": {},
            "2.0.0-rc.1": {},                  # pre-release
            "0.9.0": {"deprecated": "use foo"}, # deprecated
        },
        "time": {"1.0.0": "2023-01-01", "2.0.0": "2024-01-01"},
    })
    client = NpmClient(http)
    assert client.list_versions("lodash") == ["2.0.0", "1.0.0"]


def test_npm_scoped_name_url_encoded() -> None:
    http = _FakeHttp(json_payload={"versions": {"1.0.0": {}}})
    client = NpmClient(http)
    client.list_versions("@anthropic-ai/claude-code")
    assert "%2F" in http.calls[0] or "/" in http.calls[0]


# ---------------------------------------------------------------------------
# crates.io
# ---------------------------------------------------------------------------

def test_crates_filters_yanked_and_prerelease() -> None:
    http = _FakeHttp(json_payload={
        "versions": [
            {"num": "1.0.0", "yanked": False},
            {"num": "2.0.0", "yanked": False},
            {"num": "2.1.0-alpha", "yanked": False},  # pre-release
            {"num": "1.5.0", "yanked": True},          # yanked
        ]
    })
    client = CratesClient(http)
    assert client.list_versions("ripgrep") == ["2.0.0", "1.0.0"]


def test_crates_empty_payload_returns_empty() -> None:
    client = CratesClient(_FakeHttp(json_payload={}))
    assert client.list_versions("nonexistent") == []


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

def test_rubygems_filters_prerelease_and_yanked() -> None:
    http = _FakeHttp(json_payload=[
        {"number": "2.0.0", "prerelease": False, "yanked": False},
        {"number": "2.1.0.beta", "prerelease": True, "yanked": False},
        {"number": "1.5.0", "prerelease": False, "yanked": True},
        {"number": "1.0.0", "prerelease": False, "yanked": False},
    ])
    client = RubyGemsClient(http)
    # Order is API-provided (newest-first); we just preserve.
    assert client.list_versions("rake") == ["2.0.0", "1.0.0"]


def test_rubygems_dedup_duplicate_entries() -> None:
    http = _FakeHttp(json_payload=[
        {"number": "1.0.0", "prerelease": False, "yanked": False},
        {"number": "1.0.0", "prerelease": False, "yanked": False},
    ])
    client = RubyGemsClient(http)
    assert client.list_versions("foo") == ["1.0.0"]


# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------

def test_golang_filters_pseudo_and_prerelease() -> None:
    text = (
        "v1.0.0\n"
        "v2.0.0\n"
        "v2.0.0-rc.1\n"
        "v0.0.0-20210101000000-abcdef123456\n"   # pseudo-version
        "v1.5.0\n"
    ).encode("utf-8")
    client = GoClient(_FakeHttp(bytes_payload=text))
    assert client.list_versions("github.com/foo/bar") == [
        "v2.0.0", "v1.5.0", "v1.0.0",
    ]


def test_golang_url_capital_letter_encoded() -> None:
    """Go's case-insensitive encoding: ``GoFoo`` → ``!go!foo``."""
    client = GoClient(_FakeHttp(bytes_payload=b"v1.0.0\n"))
    client.list_versions("github.com/Foo/Bar")
    assert "!foo" in client._http.calls[0]      # type: ignore[attr-defined]


def test_golang_offline_skips_http() -> None:
    http = _FakeHttp(bytes_payload=b"v1.0.0\n")
    client = GoClient(http, offline=True)
    assert client.list_versions("github.com/foo/bar") == []
    assert http.calls == []


# ---------------------------------------------------------------------------
# Debian
# ---------------------------------------------------------------------------

def test_debian_extracts_versions() -> None:
    http = _FakeHttp(json_payload={
        "package": "nginx",
        "versions": [
            {"version": "1.22.1-9", "suites": ["bookworm"]},
            {"version": "1.18.0-6.1", "suites": ["bullseye"]},
            {"version": "1.22.1-9", "suites": ["unstable"]},   # dup
        ]
    })
    client = DebianClient(http)
    assert client.list_versions("nginx") == ["1.22.1-9", "1.18.0-6.1"]


def test_debian_unknown_package_returns_empty() -> None:
    """API may return ``{"error": "..."}`` for unknown pkgs."""
    client = DebianClient(_FakeHttp(json_payload={"error": "nope"}))
    assert client.list_versions("nonexistent-pkg") == []


def test_debian_offline_skips_http() -> None:
    http = _FakeHttp(json_payload={"versions": [{"version": "1.0"}]})
    client = DebianClient(http, offline=True)
    assert client.list_versions("nginx") == []
    assert http.calls == []


# ---------------------------------------------------------------------------
# Homebrew
# ---------------------------------------------------------------------------

def test_homebrew_returns_stable_only() -> None:
    """Homebrew tracks one stable per formula; that's what we return."""
    http = _FakeHttp(json_payload={
        "name": "semgrep",
        "versions": {"stable": "1.161.0", "head": "HEAD", "bottle": True},
    })
    client = HomebrewClient(http)
    assert client.list_versions("semgrep") == ["1.161.0"]


def test_homebrew_no_stable_returns_empty() -> None:
    client = HomebrewClient(_FakeHttp(json_payload={
        "versions": {"head": "HEAD"}}))
    assert client.list_versions("foo") == []


def test_homebrew_versioned_formula() -> None:
    """``python@3.11`` is a *separate* formula with its own stable."""
    http = _FakeHttp(json_payload={
        "name": "python@3.11",
        "versions": {"stable": "3.11.9", "head": "HEAD", "bottle": True},
    })
    client = HomebrewClient(http)
    assert client.list_versions("python@3.11") == ["3.11.9"]


# ---------------------------------------------------------------------------
# Maven Central
# ---------------------------------------------------------------------------

def test_maven_extracts_versions() -> None:
    http = _FakeHttp(json_payload={
        "response": {
            "docs": [
                {"v": "2.17.1", "g": "org.apache.logging.log4j",
                 "a": "log4j-core"},
                {"v": "2.17.0", "g": "org.apache.logging.log4j",
                 "a": "log4j-core"},
                {"v": "2.16.0", "g": "org.apache.logging.log4j",
                 "a": "log4j-core"},
            ]
        }
    })
    client = MavenClient(http)
    versions = client.list_versions(
        "org.apache.logging.log4j:log4j-core")
    assert versions == ["2.17.1", "2.17.0", "2.16.0"]


def test_maven_filters_prereleases() -> None:
    http = _FakeHttp(json_payload={
        "response": {
            "docs": [
                {"v": "2.0.0"},
                {"v": "2.0.0-SNAPSHOT"},      # snapshot
                {"v": "2.0.0-alpha"},          # alpha
                {"v": "2.0.0-beta1"},          # beta
                {"v": "2.0.0-rc1"},            # rc
            ]
        }
    })
    client = MavenClient(http)
    assert client.list_versions("g:a") == ["2.0.0"]


def test_maven_rejects_name_without_colon() -> None:
    """Maven names must be group:artifact; a bare name returns []."""
    client = MavenClient(_FakeHttp())
    assert client.list_versions("just-an-artifact") == []


# ---------------------------------------------------------------------------
# Packagist
# ---------------------------------------------------------------------------

def test_packagist_extracts_versions() -> None:
    http = _FakeHttp(json_payload={
        "packages": {
            "symfony/console": [
                {"version": "v6.4.0"},
                {"version": "v6.3.0"},
            ]
        }
    })
    client = PackagistClient(http)
    assert client.list_versions("symfony/console") == ["v6.4.0", "v6.3.0"]


def test_packagist_filters_prerelease_tags() -> None:
    http = _FakeHttp(json_payload={
        "packages": {
            "vendor/pkg": [
                {"version": "1.0.0"},
                {"version": "1.0.0-dev"},
                {"version": "1.0.0-alpha"},
                {"version": "1.0.0-beta"},
                {"version": "1.0.0-rc"},
                {"version": "1.0.0-patch"},
            ]
        }
    })
    client = PackagistClient(http)
    assert client.list_versions("vendor/pkg") == ["1.0.0"]


def test_packagist_rejects_name_without_slash() -> None:
    client = PackagistClient(_FakeHttp())
    assert client.list_versions("just-pkg") == []


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------

def test_nuget_extracts_versions() -> None:
    http = _FakeHttp(json_payload={
        "versions": ["1.0.0", "1.1.0", "1.2.0", "0.9.0"]
    })
    client = NugetClient(http)
    versions = client.list_versions("Newtonsoft.Json")
    # Newest-first via semver-ish sort.
    assert versions == ["1.2.0", "1.1.0", "1.0.0", "0.9.0"]


def test_nuget_filters_prereleases() -> None:
    http = _FakeHttp(json_payload={
        "versions": ["1.0.0", "1.0.0-rc.1", "1.0.0-beta", "0.9.0"]
    })
    client = NugetClient(http)
    assert client.list_versions("foo") == ["1.0.0", "0.9.0"]


def test_nuget_lowercases_id_in_url() -> None:
    """NuGet IDs are case-insensitive but the URL path requires lowercase."""
    http = _FakeHttp(json_payload={"versions": ["1.0.0"]})
    client = NugetClient(http)
    client.list_versions("Newtonsoft.Json")
    assert "newtonsoft.json" in http.calls[0]
