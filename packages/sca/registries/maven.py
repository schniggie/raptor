"""Maven Central registry client.

Fetches ``https://search.maven.org/solrsearch/select?q=g:<group>+AND+a:<artifact>&core=gav&rows=200&wt=json``
and returns versions newest-first, with non-stable / classifier-only
artifacts filtered out.

Maven artifacts are keyed on ``groupId:artifactId``. Callers pass that
combined form via ``list_versions("group:artifact")``.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import List, Optional

from core.json import JsonCache
from core.http import HttpClient

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "maven-versions"
_DEFAULT_TTL = 24 * 3600


class MavenClient:
    """List versions from Maven Central's solrsearch API."""

    ecosystem = "Maven"

    def __init__(
        self,
        http: HttpClient,
        cache: Optional[JsonCache] = None,
        *,
        ttl_seconds: int = _DEFAULT_TTL,
        offline: bool = False,
    ) -> None:
        self._http = http
        self._cache = cache
        self._ttl = ttl_seconds
        self._offline = offline
        # Private-registry override (RAPTOR_SCA_MAVEN_REGISTRY).
        # Maven mirrors typically expose ``/solrsearch/select`` and
        # ``/maven2/`` paths (the same shape as Maven Central). When
        # the operator's mirror diverges (Artifactory's pattern is
        # ``/artifactory/api/search/...``), the env var should
        # contain a base URL whose ``/solrsearch/select?q=...``
        # path resolves correctly.
        from ..private_registry import get as _get_override
        over = _get_override("Maven")
        self._base_url = (
            over.base_url.rstrip("/") if over and over.base_url
            else "https://search.maven.org"
        )
        self._auth_header = over.auth_header if over else None

    def _request_headers(self) -> Optional[dict]:
        if self._auth_header:
            return {"Authorization": self._auth_header}
        return None

    def list_versions(self, name: str) -> List[str]:
        if ":" not in name:
            logger.debug("sca.registries.maven: name %r missing group:artifact",
                          name)
            return []
        group, artifact = name.split(":", 1)

        cache_key = f"{_CACHE_KEY_PREFIX}:{name}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if cached is not None:
                return list(cached)

        if self._offline:
            return []

        # ``core=gav`` returns one row per group:artifact:version (versus
        # ``core=ga`` which collapses to the latest). 200 rows is enough
        # for almost every artifact; very long histories will be capped.
        q = (f"g:{urllib.parse.quote(group)}+AND+"
             f"a:{urllib.parse.quote(artifact)}")
        url = (f"{self._base_url}/solrsearch/select?q={q}"
               f"&core=gav&rows=200&wt=json")
        try:
            data = self._http.get_json(
                url, headers=self._request_headers(),
            )
        except Exception as e:                # noqa: BLE001
            logger.warning("sca.registries.maven: fetch failed for %r: %s",
                           name, e)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _extract_versions(data: dict) -> List[str]:
    """Pull versions from the Maven Central solr response.

    Shape (abridged):
        {
          "response": {
            "docs": [
              {"v": "2.17.1", "g": "...", "a": "...", "timestamp": ...},
              ...
            ]
          }
        }
    """
    docs = (data.get("response") or {}).get("docs") or []
    if not isinstance(docs, list):
        return []
    seen: set = set()
    out: List[str] = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        v = d.get("v")
        if not isinstance(v, str) or v in seen:
            continue
        # Drop pre-release-style artifacts (alpha, beta, rc, snapshot).
        # Maven coords are looser than semver; we use a substring sniff
        # rather than a strict parse.
        lo = v.lower()
        if any(tag in lo for tag in (
                "snapshot", "alpha", "beta", "-rc", ".rc",
                "-cr", ".cr", "milestone", "-m", ".m")):
            # The trailing "-m" / ".m" check would false-positive on
            # legitimate versions with an "m" suffix; gate on a
            # following digit.
            if any(t in lo for t in ("snapshot", "alpha", "beta",
                                       "milestone")):
                continue
            import re as _re
            if _re.search(r"[-.](rc|cr|m)\d+", lo):
                continue
        seen.add(v)
        out.append(v)
    # Solr returns newest-first by default; preserve.
    return out


__all__ = ["MavenClient"]
