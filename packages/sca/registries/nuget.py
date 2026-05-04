"""NuGet (.NET) registry client.

Fetches the ``api.nuget.org`` flat-container index for a package — the
simplest endpoint that returns just a version list with no pagination:

    https://api.nuget.org/v3-flatcontainer/<lowercase_id>/index.json

Returns versions newest-first with pre-releases (any version containing
``-``) filtered out.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.json import JsonCache
from core.http import HttpClient

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "nuget-versions"
_DEFAULT_TTL = 24 * 3600


class NugetClient:
    """List versions from NuGet's flat-container."""

    ecosystem = "NuGet"

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

    def list_versions(self, name: str) -> List[str]:
        # NuGet IDs are case-insensitive but the URL path requires
        # lowercase.
        canon = name.lower()
        cache_key = f"{_CACHE_KEY_PREFIX}:{canon}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if cached is not None:
                return list(cached)

        if self._offline:
            return []

        try:
            data = self._http.get_json(
                f"https://api.nuget.org/v3-flatcontainer/{canon}/index.json")
        except Exception as e:                # noqa: BLE001
            logger.warning("sca.registries.nuget: fetch failed for %r: %s",
                           name, e)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _extract_versions(data: dict) -> List[str]:
    """Pull versions from the NuGet flat-container response.

    Shape:
        {"versions": ["1.0.0", "1.1.0", "1.2.0-rc.1", ...]}
    """
    raw = data.get("versions") or []
    if not isinstance(raw, list):
        return []
    out = [v for v in raw if isinstance(v, str) and "-" not in v]
    # Newest-first using semver-ish ordering.
    out.sort(key=_semver_key, reverse=True)
    return out


def _semver_key(v: str):
    """Best-effort semver tuple."""
    parts = v.split(".")
    out = []
    for p in parts:
        try:
            out.append((0, int(p)))
        except ValueError:
            out.append((1, p))
    return tuple(out)


__all__ = ["NugetClient"]
