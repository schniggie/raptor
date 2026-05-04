"""Typosquat candidate detector.

For each direct dep, computes Damerau-Levenshtein distance against the
bundled per-ecosystem popular-names list. A name within distance 1 or
2 of a popular package is flagged as a candidate; an *exact* match is
trusted (the dep IS the popular package).

Limits & honesty:

- The bundled list ships ~80–100 names per ecosystem — far short of
  the 5k target the design doc anticipates. False negatives are
  inevitable for less-trafficked names. Add to ``data/popular/<eco>.json``
  to extend coverage; the file is JSON for that reason.
- We use a string-only check; ``lodash`` vs ``lodaash`` flags, but
  ``lodash`` (correct) vs ``loadsh`` (transposed) needs the Damerau
  variant — included.
- Scope-name typosquats are normalised: ``@types/node`` is compared
  against the popular list both as itself and as ``types/node`` (some
  attackers omit the ``@``). The package name kept on the finding is
  the original.
"""

from __future__ import annotations

import json as _json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Dependency

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "popular"

# Distances above this are not interesting; below it we always flag
# (with severity scaled by distance).
_MAX_DISTANCE = 2

# Per-ecosystem popular-name caches. Loaded lazily and re-used.
_POPULAR_BY_ECO: Dict[str, List[str]] = {}


@dataclass(frozen=True)
class TyposquatFinding:
    dependency: Dependency
    nearest_popular: str
    distance: int
    severity: str
    confidence: Confidence


def scan_deps(deps: Iterable[Dependency]) -> List[TyposquatFinding]:
    """Run the candidate check on every direct dep."""
    out: List[TyposquatFinding] = []
    for d in deps:
        if not d.direct:
            continue
        finding = _check_one(d)
        if finding is not None:
            out.append(finding)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _check_one(dep: Dependency) -> Optional[TyposquatFinding]:
    popular = _load_popular(dep.ecosystem)
    if not popular:
        return None

    name_norm = dep.name.lower()
    # Full name is in the popular list → it IS the popular package.
    if name_norm in popular:
        return None

    candidates = [name_norm]
    if name_norm.startswith("@") and "/" in name_norm:
        candidates.append(name_norm.split("/", 1)[1])

    best: Optional[Tuple[int, str]] = None
    for cand in candidates:
        for pop in popular:
            if cand == pop:
                # Bare-form exact match inside a non-popular scope. This
                # is the ``@evil/lodash`` shape — scoped-namespace squat
                # rather than a typo. Distance 0 is the strongest signal
                # we have.
                if best is None or 0 < best[0]:
                    best = (0, pop)
                continue
            d = _damerau_levenshtein(cand, pop, _MAX_DISTANCE + 1)
            if d > _MAX_DISTANCE:
                continue
            if best is None or d < best[0]:
                best = (d, pop)

    if best is None:
        return None

    distance, nearest = best
    if distance == 0:
        severity = "high"
        confidence_reason = (
            f"bare form matches popular '{nearest}'; "
            "scoped-name namespace squat shape"
        )
        confidence_level = "high"
    elif distance == 1:
        severity = "high"
        confidence_reason = (
            f"distance-1 from popular '{nearest}'; "
            "may be a legitimate package or a typosquat"
        )
        confidence_level = "medium"
    else:
        severity = "medium"
        confidence_reason = (
            f"distance-{distance} from popular '{nearest}'; "
            "may be a legitimate package or a typosquat"
        )
        confidence_level = "low"

    return TyposquatFinding(
        dependency=dep,
        nearest_popular=nearest,
        distance=distance,
        severity=severity,
        confidence=Confidence(confidence_level, reason=confidence_reason),
    )


def _load_popular(ecosystem: str) -> List[str]:
    if ecosystem in _POPULAR_BY_ECO:
        return _POPULAR_BY_ECO[ecosystem]
    path = _DATA_DIR / f"{ecosystem}.json"
    if not path.exists():
        _POPULAR_BY_ECO[ecosystem] = []
        return []
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError) as e:
        logger.warning("sca.supply_chain.typosquat: failed to load %s: %s",
                       path, e)
        _POPULAR_BY_ECO[ecosystem] = []
        return []
    if not isinstance(data, list):
        _POPULAR_BY_ECO[ecosystem] = []
        return []
    cleaned = [n.lower() for n in data if isinstance(n, str)]
    _POPULAR_BY_ECO[ecosystem] = cleaned
    return cleaned


def _damerau_levenshtein(a: str, b: str, cutoff: int) -> int:
    """Optimal-string-alignment distance with early-exit ``cutoff``.

    Returns ``cutoff`` (the cap) when the true distance exceeds it.
    Standard implementation: row-by-row DP with a single character of
    look-back to handle adjacent transpositions.
    """
    la, lb = len(a), len(b)
    if abs(la - lb) >= cutoff:
        return cutoff
    if la == 0:
        return min(lb, cutoff)
    if lb == 0:
        return min(la, cutoff)

    prev_prev = list(range(lb + 1))
    prev = [0] * (lb + 1)
    cur = [0] * (lb + 1)
    for i in range(1, la + 1):
        cur, prev, prev_prev = [0] * (lb + 1), cur, prev
        cur[0] = i
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(
                prev[j] + 1,           # deletion
                cur[j - 1] + 1,        # insertion
                prev[j - 1] + cost,    # substitution
            )
            if (i > 1 and j > 1
                    and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev_prev[j - 2] + 1)
            if cur[j] < row_min:
                row_min = cur[j]
        if row_min >= cutoff:
            return cutoff
    return min(cur[lb], cutoff)


__all__ = ["TyposquatFinding", "scan_deps"]
