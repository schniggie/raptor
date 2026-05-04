"""Tests for ``packages.sca.epss``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from core.json import JsonCache
from packages.sca.epss import EPSS_URL, EpssClient
from core.http import HttpError


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


def test_basic_lookup(tmp_path: Path) -> None:
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97559"}]}
    http = FakeHttp(payload=payload)
    epss = EpssClient(http, JsonCache(root=tmp_path))
    result = epss.scores(["CVE-2021-44228"])
    assert result == {"CVE-2021-44228": 0.97559}


def test_score_convenience_method(tmp_path: Path) -> None:
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97559"}]}
    epss = EpssClient(FakeHttp(payload=payload), JsonCache(root=tmp_path))
    assert epss.score("CVE-2021-44228") == 0.97559


def test_missing_cve_omitted_from_result(tmp_path: Path) -> None:
    payload = {"data": []}
    epss = EpssClient(FakeHttp(payload=payload), JsonCache(root=tmp_path))
    result = epss.scores(["CVE-9999-99999"])
    assert result == {}


def test_warm_cache_skips_network(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97559"}]}
    EpssClient(FakeHttp(payload=payload), cache).scores(["CVE-2021-44228"])
    http2 = FakeHttp(payload={})
    epss2 = EpssClient(http2, cache)
    assert epss2.scores(["CVE-2021-44228"]) == {"CVE-2021-44228": 0.97559}
    assert http2.gets == []


def test_no_score_sentinel_avoids_refetch(tmp_path: Path) -> None:
    """A CVE the API has no data for is cached as a sentinel so the
    next run doesn't refetch it."""
    cache = JsonCache(root=tmp_path)
    EpssClient(FakeHttp(payload={"data": []}), cache).scores(["CVE-X"])
    http2 = FakeHttp(payload={"data": [{"cve": "CVE-X", "epss": "0.5"}]})
    epss2 = EpssClient(http2, cache)
    # Sentinel is honoured: empty result, no network call.
    assert epss2.scores(["CVE-X"]) == {}
    assert http2.gets == []


def test_network_error_returns_empty(tmp_path: Path) -> None:
    epss = EpssClient(FakeHttp(error=HttpError("boom")),
                      JsonCache(root=tmp_path))
    assert epss.scores(["CVE-2021-44228"]) == {}


def test_offline_cold_cache_returns_empty(tmp_path: Path) -> None:
    http = FakeHttp(error=HttpError("should not be called"))
    epss = EpssClient(http, JsonCache(root=tmp_path), offline=True)
    assert epss.scores(["CVE-2021-44228"]) == {}
    assert http.gets == []


def test_dedup_normalises_case(tmp_path: Path) -> None:
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97"}]}
    http = FakeHttp(payload=payload)
    epss = EpssClient(http, JsonCache(root=tmp_path))
    epss.scores(["CVE-2021-44228", "cve-2021-44228"])
    # Only one CVE in the URL.
    assert http.gets[0].count("CVE-2021-44228") == 1


def test_batch_chunking_caps_url_length(tmp_path: Path) -> None:
    payload = {"data": [{"cve": f"CVE-2021-{i:05d}", "epss": "0.5"}
                        for i in range(150)]}
    http = FakeHttp(payload=payload)
    epss = EpssClient(http, JsonCache(root=tmp_path))
    epss.scores([f"CVE-2021-{i:05d}" for i in range(150)])
    assert len(http.gets) == 2   # chunked at 100


def test_invalid_score_skipped(tmp_path: Path) -> None:
    payload = {"data": [
        {"cve": "CVE-A", "epss": "not-a-number"},
        {"cve": "CVE-B", "epss": "0.5"},
    ]}
    epss = EpssClient(FakeHttp(payload=payload), JsonCache(root=tmp_path))
    assert epss.scores(["CVE-A", "CVE-B"]) == {"CVE-B": 0.5}
