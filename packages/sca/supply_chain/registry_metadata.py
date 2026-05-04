"""Registry-metadata supply-chain detectors.

Three detectors that all share the per-package metadata fetched from
the upstream registry — bundled here so we make one HTTP call per dep
across the suite:

  - ``recent_publish`` — first publish < 30 days ago.
  - ``maintainer_change`` — any maintainer added in the last 14 days
    (the xz pattern: a long-tail maintainer addition that ultimately
    introduced a backdoor years later).
  - ``maintainer_account_change`` — a maintainer's email changed within
    14 days of a new release (the Axios npm pattern, March 2026).

Each emits an ``RegistryMetaFinding`` row consumed by ``__init__.py``'s
orchestrator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import Confidence, Dependency

logger = logging.getLogger(__name__)


_RECENT_PUBLISH_DAYS = 30
_MAINTAINER_CHANGE_DAYS = 14


@dataclass
class RegistryMetaFinding:
    """One detector hit from the registry-metadata bundle."""

    kind: str                                # "recent_publish" |
                                              # "maintainer_change" |
                                              # "maintainer_account_change"
    dependency: Dependency
    detail: str
    evidence: Dict[str, Any]
    severity: str
    confidence: Confidence


def scan_deps(
    deps: Iterable[Dependency],
    *,
    pypi_client=None,
    npm_client=None,
    now: Optional[datetime] = None,
) -> List[RegistryMetaFinding]:
    """Run all three registry-metadata detectors over direct deps only.

    ``pypi_client`` and ``npm_client`` are the canonical
    ``packages/sca/registries/{pypi,npm}.py`` clients — passed in so
    callers can wire ``offline``, ``cache``, etc. consistently with the
    rest of the run.
    """
    now = now or datetime.now(timezone.utc)
    out: List[RegistryMetaFinding] = []
    for dep in deps:
        if not dep.direct:
            continue
        meta = _fetch(dep, pypi_client=pypi_client, npm_client=npm_client)
        if meta is None:
            continue
        out.extend(_recent_publish_check(dep, meta, now))
        out.extend(_maintainer_change_check(dep, meta, now))
        out.extend(_maintainer_account_change_check(dep, meta, now))
    return out


# ---------------------------------------------------------------------------
# Per-ecosystem metadata adapter
# ---------------------------------------------------------------------------

@dataclass
class _Meta:
    """Normalised view of a package's registry metadata."""

    first_publish: Optional[datetime]
    latest_publish: Optional[datetime]
    maintainers: List[Dict[str, Any]] = field(default_factory=list)
    # ``[{name, email, joined_at?, last_email_change?}, ...]``


def _fetch(
    dep: Dependency, *, pypi_client, npm_client,
) -> Optional[_Meta]:
    if dep.ecosystem == "PyPI" and pypi_client is not None:
        raw = pypi_client.get_metadata(dep.name)
        return _from_pypi(raw) if raw else None
    if dep.ecosystem == "npm" and npm_client is not None:
        raw = npm_client.get_metadata(dep.name)
        return _from_npm(raw) if raw else None
    # Other ecosystems: no metadata source wired in this layer yet.
    return None


def _from_pypi(raw: dict) -> _Meta:
    """Normalise PyPI's JSON shape.

    PyPI publish timestamps live under ``releases[<ver>][i].upload_time_iso_8601``.
    Maintainer info isn't published as structured data — only the
    project-page listing of authors. We surface ``info.author`` /
    ``info.maintainer`` as a best-effort single entry.
    """
    info = raw.get("info") or {}
    releases = raw.get("releases") or {}
    timestamps: List[datetime] = []
    if isinstance(releases, dict):
        for files in releases.values():
            if not isinstance(files, list):
                continue
            for f in files:
                if not isinstance(f, dict):
                    continue
                ts = _parse_iso(f.get("upload_time_iso_8601"))
                if ts:
                    timestamps.append(ts)
    maintainers: List[Dict[str, Any]] = []
    for field_name in ("maintainer", "author"):
        n = info.get(field_name)
        if isinstance(n, str) and n.strip():
            email_field = f"{field_name}_email"
            maintainers.append({
                "name": n.strip(),
                "email": (info.get(email_field) or "").strip() or None,
            })
    return _Meta(
        first_publish=min(timestamps) if timestamps else None,
        latest_publish=max(timestamps) if timestamps else None,
        maintainers=maintainers,
    )


def _from_npm(raw: dict) -> _Meta:
    """Normalise npm registry shape.

    npm publishes per-version timestamps under ``time.<ver>``. The full
    maintainer list is in ``maintainers``.
    """
    times = raw.get("time") or {}
    timestamps: List[datetime] = []
    if isinstance(times, dict):
        for k, v in times.items():
            # ``created`` and ``modified`` are also in ``time``; skip.
            if k in ("created", "modified"):
                continue
            if isinstance(v, str):
                ts = _parse_iso(v)
                if ts:
                    timestamps.append(ts)
    raw_maint = raw.get("maintainers") or []
    maintainers: List[Dict[str, Any]] = []
    if isinstance(raw_maint, list):
        for m in raw_maint:
            if isinstance(m, dict):
                maintainers.append({
                    "name": m.get("name", ""),
                    "email": m.get("email", ""),
                })
    return _Meta(
        first_publish=min(timestamps) if timestamps else None,
        latest_publish=max(timestamps) if timestamps else None,
        maintainers=maintainers,
    )


# ---------------------------------------------------------------------------
# Detector: recent_publish
# ---------------------------------------------------------------------------

def _recent_publish_check(
    dep: Dependency, meta: _Meta, now: datetime,
) -> List[RegistryMetaFinding]:
    if meta.first_publish is None:
        return []
    age_days = (now - meta.first_publish).days
    if age_days >= _RECENT_PUBLISH_DAYS:
        return []
    detail = (
        f"package {dep.ecosystem}:{dep.name} was first published "
        f"{age_days} days ago — under the {_RECENT_PUBLISH_DAYS}-day "
        f"threshold for recent-publish review"
    )
    return [RegistryMetaFinding(
        kind="recent_publish",
        dependency=dep,
        detail=detail,
        evidence={"first_publish": meta.first_publish.isoformat(),
                  "age_days": age_days},
        severity="medium" if age_days < 7 else "low",
        confidence=Confidence("high",
                               reason="registry publish timestamp"),
    )]


# ---------------------------------------------------------------------------
# Detector: maintainer_change (recent maintainer addition)
# ---------------------------------------------------------------------------

def _maintainer_change_check(
    dep: Dependency, meta: _Meta, now: datetime,
) -> List[RegistryMetaFinding]:
    """Heuristic: when registry metadata exposes per-maintainer
    ``joined_at`` (npm doesn't, but a future enriched feed could), flag
    additions within ``_MAINTAINER_CHANGE_DAYS``.

    Today no major registry exposes per-maintainer add-dates in the
    static metadata, so this detector is a placeholder that fires only
    when the data is present. The `evidence_quotes` shape is ready for
    when it is.
    """
    recent: List[Dict[str, Any]] = []
    cutoff = now - timedelta(days=_MAINTAINER_CHANGE_DAYS)
    for m in meta.maintainers:
        joined = m.get("joined_at")
        if isinstance(joined, str):
            ts = _parse_iso(joined)
            if ts and ts >= cutoff:
                recent.append(m)
    if not recent:
        return []
    return [RegistryMetaFinding(
        kind="maintainer_change",
        dependency=dep,
        detail=(f"{len(recent)} maintainer(s) added to "
                f"{dep.ecosystem}:{dep.name} in the last "
                f"{_MAINTAINER_CHANGE_DAYS} days"),
        evidence={"recent_maintainers": [
            {k: v for k, v in m.items() if k != "email"}
            for m in recent
        ]},
        severity="low",                          # long-tail signal; S/N is poor
        confidence=Confidence(
            "medium",
            reason="registry maintainer-add timestamp",
        ),
    )]


# ---------------------------------------------------------------------------
# Detector: maintainer_account_change
# ---------------------------------------------------------------------------

def _maintainer_account_change_check(
    dep: Dependency, meta: _Meta, now: datetime,
) -> List[RegistryMetaFinding]:
    """Heuristic for the Axios pattern: maintainer email changed within
    ``_MAINTAINER_CHANGE_DAYS`` of a new release.

    Triggered when ``last_email_change`` (custom enrichment field; not
    in vanilla npm/PyPI metadata) AND ``latest_publish`` are both within
    the window. Like `maintainer_change`, this fires only when the data
    is present — currently a structural placeholder ready for richer
    feeds to plug in.
    """
    if meta.latest_publish is None:
        return []
    cutoff = now - timedelta(days=_MAINTAINER_CHANGE_DAYS)
    if meta.latest_publish < cutoff:
        return []
    suspect: List[Dict[str, Any]] = []
    for m in meta.maintainers:
        chg = m.get("last_email_change")
        if isinstance(chg, str):
            ts = _parse_iso(chg)
            if ts and ts >= cutoff:
                suspect.append({"name": m.get("name"),
                                "changed_at": chg})
    if not suspect:
        return []
    return [RegistryMetaFinding(
        kind="maintainer_account_change",
        dependency=dep,
        detail=(f"{len(suspect)} maintainer email change(s) within "
                f"{_MAINTAINER_CHANGE_DAYS} days of release "
                f"({meta.latest_publish.isoformat()})"),
        evidence={
            "latest_publish": meta.latest_publish.isoformat(),
            "suspect_maintainers": suspect,
        },
        severity="high",                         # narrow + actionable
        confidence=Confidence(
            "high",
            reason="email-change-within-release-window pattern",
        ),
    )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    s = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


__all__ = ["RegistryMetaFinding", "scan_deps"]
