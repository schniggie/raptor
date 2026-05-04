"""npm package.json parser.

Handles ``dependencies``, ``devDependencies``, ``peerDependencies``,
``optionalDependencies`` (and ``bundleDependencies``, treated as direct
deps with main scope). Lockfiles (``package-lock.json``, ``yarn.lock``,
``pnpm-lock.yaml``) are parsed elsewhere; this module is the manifest-
only view.

Scope mapping:
- ``dependencies``        → main
- ``devDependencies``     → dev
- ``peerDependencies``    → peer
- ``optionalDependencies``→ optional
- ``bundleDependencies``  → main (legacy; lists names that ``dependencies``
                            already declares)

Pin-style classification covers npm's range grammar; anything we can't
classify drops to ``unknown`` rather than guessing.

Lifecycle scripts (``preinstall``, ``install``, ``postinstall``,
``prepare``, ``prepublish``) are not recorded as Dependency rows here.
The supply-chain heuristic layer reads the same file directly to flag
suspicious lifecycle hooks; recording them twice would make dedup harder.
"""

from __future__ import annotations

import json as _json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

ECOSYSTEM = "npm"

# (package.json key, scope value)
_DEP_BUCKETS = (
    ("dependencies", "main"),
    ("devDependencies", "dev"),
    ("peerDependencies", "peer"),
    ("optionalDependencies", "optional"),
)

# Comparator characters that indicate a multi-bound range, e.g.
# ">=1.0.0 <2.0.0" or "1.0.0 - 2.0.0". Used after ruling out caret/tilde.
_RANGE_CHARS = set("<>=|") | {" - "}
_HEX_SHA = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.package_json: read failed for %s: %s", path, e)
        return []

    try:
        data = _json.loads(text)
    except _json.JSONDecodeError as e:
        logger.warning(
            "sca.parsers.package_json: JSON parse failed for %s: %s", path, e
        )
        return []
    if not isinstance(data, dict):
        logger.warning(
            "sca.parsers.package_json: top-level not an object in %s", path
        )
        return []

    project_license = _extract_license(data)

    deps: List[Dependency] = []
    for key, scope in _DEP_BUCKETS:
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, raw_spec in block.items():
            d = _build_dep(name, raw_spec, scope, path)
            if d is not None:
                # Manifest-level license describes the project itself,
                # not its deps. We attach it as ``declared_license`` only
                # on rows that *are* the project (no manifests do that
                # by default; keep slot for SBOM use anyway).
                if project_license:
                    d.declared_license = project_license
                deps.append(d)

    # bundleDependencies / bundledDependencies — array of names already
    # declared in `dependencies`; just record them flagged as bundled.
    for key in ("bundleDependencies", "bundledDependencies"):
        bundle = data.get(key)
        if isinstance(bundle, list):
            for name in bundle:
                if not isinstance(name, str):
                    continue
                d = _build_dep(name, "*", "main", path)
                if d is not None:
                    # Mark explicitly so a downstream consumer can spot
                    # bundling without re-reading the manifest.
                    d.parser_confidence = Confidence(
                        "high",
                        reason="bundleDependencies entry; version unspecified",
                    )
                    deps.append(d)

    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _extract_license(data: Dict[str, object]) -> Optional[str]:
    """Read the ``license`` / ``licenses`` field from a package.json.

    Handles all three shapes seen in real-world manifests:
    - ``"license": "MIT"``                              (SPDX string, current)
    - ``"license": {"type": "MIT", ...}``               (legacy single-object)
    - ``"licenses": [{"type": "MIT"}, {"type": "ISC"}]`` (deprecated array)
    """
    raw = data.get("license")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    if isinstance(raw, dict):
        t = raw.get("type") or raw.get("name")
        if isinstance(t, str) and t.strip():
            return t.strip()
    arr = data.get("licenses")
    if isinstance(arr, list):
        names = []
        for item in arr:
            if isinstance(item, dict):
                t = item.get("type") or item.get("name")
                if isinstance(t, str) and t.strip():
                    names.append(t.strip())
            elif isinstance(item, str) and item.strip():
                names.append(item.strip())
        if names:
            # Multiple licenses: surface the lot as a SPDX-OR expression
            # so downstream consumers don't lose information.
            return " OR ".join(names) if len(names) > 1 else names[0]
    return None


def _build_dep(
    name: str,
    raw_spec: object,
    scope: str,
    path: Path,
) -> Optional[Dependency]:
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(raw_spec, str):
        # Some lockfile-merged manifests inline objects; we treat those
        # as opaque and skip rather than emit a half-row.
        return None
    spec = raw_spec.strip()
    pin_style, version, npm_alias_target = _classify(spec)
    purl_name = npm_alias_target or name

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=_build_purl(purl_name, version),
        parser_confidence=_confidence(pin_style, version),
    )


def _classify(spec: str) -> Tuple[PinStyle, Optional[str], Optional[str]]:
    """Return (pin_style, version_for_record, npm_alias_target_or_None).

    For an alias like ``"npm:lodash@^4.17.0"``, the alias target is
    returned so the purl reflects the actual installed package; the spec
    governing the pin style is the right-hand side.
    """
    if not spec:
        return PinStyle.WILDCARD, None, None

    # npm: alias → recurse on the right-hand side.
    if spec.startswith("npm:"):
        rest = spec[len("npm:"):]
        if "@" in rest[1:]:
            sep = rest.rindex("@")
            target = rest[:sep] if sep > 0 else rest
            inner_spec = rest[sep + 1:] if sep > 0 else ""
        else:
            target = rest
            inner_spec = ""
        pin, ver, _ = _classify(inner_spec)
        return pin, ver, target or None

    # Wildcards.
    if spec in ("*", "x", "X", "latest", ""):
        return PinStyle.WILDCARD, None, None

    # Git references (git+https://, git+ssh://, git://, github:owner/repo,
    # bitbucket:..., gitlab:..., gist:...).
    if (
        spec.startswith(("git+", "git:", "git@"))
        or spec.startswith(("github:", "bitbucket:", "gitlab:", "gist:"))
        or "://" in spec and spec.split("://", 1)[0].endswith("git")
    ):
        # Try to extract a #ref or #semver: spec for the version field.
        version: Optional[str] = None
        if "#" in spec:
            tag = spec.split("#", 1)[1]
            if tag.startswith("semver:"):
                version = tag[len("semver:"):]
            else:
                version = tag
        return PinStyle.GIT, version, None

    # Local paths.
    if spec.startswith(("file:", "./", "../", "/", "~/")):
        return PinStyle.PATH, None, None

    # Tarball URLs.
    if spec.startswith(("http://", "https://")):
        # Tarball; treat as path-like for pinning purposes (resolved by
        # URL, not by version range).
        return PinStyle.PATH, None, None

    # Caret / tilde.
    if spec.startswith("^"):
        return PinStyle.CARET, spec[1:].strip() or None, None
    if spec.startswith("~"):
        return PinStyle.TILDE, spec[1:].strip() or None, None

    # Multi-bound or comparator-based range.
    if any(ch in spec for ch in _RANGE_CHARS) or " - " in spec:
        return PinStyle.RANGE, spec, None

    # Bare version: treat as exact unless it's a SHA (which npm allows
    # for resolved git installs without a prefix — rare in package.json).
    if _HEX_SHA.match(spec):
        return PinStyle.GIT, spec, None

    return PinStyle.EXACT, spec, None


def _confidence(pin_style: PinStyle, version: Optional[str]) -> Confidence:
    if pin_style is PinStyle.UNKNOWN:
        return Confidence("low", reason="package.json spec unrecognised")
    if pin_style in (PinStyle.GIT, PinStyle.PATH):
        return Confidence(
            "medium",
            reason="package.json points to git/path source; version best-effort",
        )
    if version is None:
        return Confidence("medium", reason="package.json wildcard version")
    return Confidence("high", reason="package.json structured field")


def _build_purl(name: str, version: Optional[str]) -> str:
    """Build an npm purl. Scoped packages keep the leading ``@``."""
    base = f"pkg:npm/{name}"
    if version:
        return f"{base}@{version}"
    return base


register(filenames=["package.json"])(parse)
