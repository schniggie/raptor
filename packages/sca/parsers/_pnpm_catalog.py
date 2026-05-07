"""pnpm-workspace.yaml catalog resolution.

pnpm 9 added the ``catalog:`` mechanism: a workspace can declare
shared version pins in ``pnpm-workspace.yaml`` and reference them
from each member ``package.json`` as ``"react": "catalog:"`` or
``"react": "catalog:react17"``.

Without resolving the catalog, the spec ``"catalog:"`` is opaque:
SCA can't classify the pin style, can't query OSV, can't emit a
useful purl.

This module discovers the project's ``pnpm-workspace.yaml`` (by
walking up from a given ``package.json`` path), parses its
``catalog`` (default) and ``catalogs.<name>`` sections, and exposes
a tiny resolver that maps a ``catalog:[<name>]`` spec to its
declared version range.

YAML parsing degrades gracefully when ``yaml`` (PyYAML) isn't
available — returns an empty resolver, the spec stays unresolved
in the consumer, the operator sees an UNKNOWN-pin row in their
report.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# Per-root cache: ``{repo_root: {catalog_name_or_default:
# {package: version_spec}}}``. ``""`` is the default catalog.
# Consulted across parser invocations within the same process so
# every package.json in a workspace pays the YAML parse once.
_CATALOG_CACHE: Dict[Path, Dict[str, Dict[str, str]]] = {}


def find_workspace_root(start: Path) -> Optional[Path]:
    """Walk up from ``start`` looking for ``pnpm-workspace.yaml``.

    ``start`` is typically the directory containing a member
    ``package.json``. Returns the directory containing the YAML, or
    None if no such ancestor exists. Stops at the filesystem root.
    """
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    while True:
        if (cur / "pnpm-workspace.yaml").is_file():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def get_catalogs(root: Path) -> Dict[str, Dict[str, str]]:
    """Return ``{catalog_name: {package: version_spec}}`` for the
    workspace rooted at ``root``. Empty dict on missing or
    malformed YAML.
    """
    root = root.resolve()
    cached = _CATALOG_CACHE.get(root)
    if cached is not None:
        return cached
    catalogs = _parse_catalogs(root / "pnpm-workspace.yaml")
    _CATALOG_CACHE[root] = catalogs
    return catalogs


def resolve_catalog_spec(
    spec: str, package_name: str, catalogs: Dict[str, Dict[str, str]],
) -> Optional[str]:
    """Resolve a ``catalog:[<name>]`` spec to its declared version.

    ``spec`` is the full string, e.g. ``"catalog:"`` (default
    catalog) or ``"catalog:react17"`` (named catalog).
    ``package_name`` is the dependency's name — pnpm catalogs are
    keyed by package name within each catalog.

    Returns the version-spec string from the catalog (e.g.
    ``"^18.2.0"``), or None if the catalog or package isn't
    declared.
    """
    if not spec.startswith("catalog:"):
        return None
    name = spec[len("catalog:"):].strip()
    cat_key = name or ""              # default catalog uses empty key
    return (catalogs.get(cat_key) or {}).get(package_name)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _parse_catalogs(path: Path) -> Dict[str, Dict[str, str]]:
    """Read the YAML and return the catalog map.

    Schema (pnpm 9):

      .. code-block:: yaml

         catalog:
           react: ^18.2.0
           lodash: 4.17.21
         catalogs:
           react17:
             react: ^17.0.0
             react-dom: ^17.0.0

    Either of ``catalog`` (default) or ``catalogs`` (named) may be
    absent. The default catalog is keyed under ``""`` in the
    returned dict; named catalogs use their declared name.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        logger.debug(
            "sca.parsers._pnpm_catalog: PyYAML not installed; "
            "catalog references stay unresolved",
        )
        return {}

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        logger.warning(
            "sca.parsers._pnpm_catalog: parse failed for %s: %s",
            path, e,
        )
        return {}

    if not isinstance(data, dict):
        return {}

    out: Dict[str, Dict[str, str]] = {}
    default = data.get("catalog")
    if isinstance(default, dict):
        out[""] = {
            k: v for k, v in default.items()
            if isinstance(k, str) and isinstance(v, str)
        }
    named = data.get("catalogs")
    if isinstance(named, dict):
        for cat_name, entries in named.items():
            if not isinstance(cat_name, str) or not isinstance(entries, dict):
                continue
            out[cat_name] = {
                k: v for k, v in entries.items()
                if isinstance(k, str) and isinstance(v, str)
            }
    return out


def _clear_cache() -> None:
    """Test helper — clear the per-root catalog cache."""
    _CATALOG_CACHE.clear()


__all__ = [
    "find_workspace_root",
    "get_catalogs",
    "resolve_catalog_spec",
]
