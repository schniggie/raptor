"""Tests for ``packages.sca.kev``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from core.json import JsonCache
from core.http import HttpError
from packages.sca.kev import KEV_URL, KevClient


class FakeHttp:
    def __init__(self, payload: Dict[str, Any] | None = None,
                 error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error
        self.gets: list[str] = []

    def post_json(self, *a, **k):
        raise NotImplementedError

    def get_json(self, url: str, timeout: int = 30) -> dict:
        self.gets.append(url)
        if self.error:
            raise self.error
        return self.payload or {}

    def get_bytes(self, *a, **k):
        raise NotImplementedError


_PAYLOAD = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
        {"cveID": "CVE-2017-5638"},
    ],
}


def test_contains_known_cve(tmp_path: Path) -> None:
    http = FakeHttp(payload=_PAYLOAD)
    kev = KevClient(http, JsonCache(root=tmp_path))
    assert kev.contains("CVE-2021-44228") is True
    assert kev.contains("cve-2021-44228") is True   # case-insensitive
    assert kev.contains("CVE-9999-99999") is False


def test_contains_loads_lazily(tmp_path: Path) -> None:
    http = FakeHttp(payload=_PAYLOAD)
    kev = KevClient(http, JsonCache(root=tmp_path))
    assert kev.is_loaded() is False
    assert http.gets == []
    kev.contains("CVE-2021-44228")
    assert kev.is_loaded() is True
    assert http.gets == [KEV_URL]


def test_warm_cache_skips_network(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    http1 = FakeHttp(payload=_PAYLOAD)
    KevClient(http1, cache).contains("CVE-2021-44228")
    http2 = FakeHttp(payload={})    # would fail to find anything
    kev2 = KevClient(http2, cache)
    assert kev2.contains("CVE-2021-44228") is True
    assert http2.gets == []


def test_network_error_degrades_gracefully(tmp_path: Path) -> None:
    http = FakeHttp(error=HttpError("offline"))
    kev = KevClient(http, JsonCache(root=tmp_path))
    assert kev.contains("CVE-2021-44228") is False
    assert kev.is_loaded() is True


def test_offline_cold_cache_returns_false(tmp_path: Path) -> None:
    http = FakeHttp(error=HttpError("should not be called"))
    kev = KevClient(http, JsonCache(root=tmp_path), offline=True)
    assert kev.contains("CVE-2021-44228") is False
    assert http.gets == []


def test_malformed_payload_yields_empty_set(tmp_path: Path) -> None:
    http = FakeHttp(payload={"unexpected": "shape"})
    kev = KevClient(http, JsonCache(root=tmp_path))
    assert kev.contains("CVE-2021-44228") is False
    assert kev.is_loaded() is True


def test_empty_id_returns_false(tmp_path: Path) -> None:
    kev = KevClient(FakeHttp(payload=_PAYLOAD), JsonCache(root=tmp_path))
    assert kev.contains("") is False
