"""Tests for B10 — npm workspaces / pnpm catalogs / Yarn Berry
resolutions / npm overrides.

These exercise the spec shapes and project-wide pin fields that
modern monorepo / hierarchical-version-config setups use.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.sca.models import PinStyle
from packages.sca.parsers._pnpm_catalog import (
    _clear_cache,
    find_workspace_root,
    get_catalogs,
    resolve_catalog_spec,
)
from packages.sca.parsers.package_json import (
    _flatten_overrides,
    _strip_descriptor,
    parse,
)


@pytest.fixture(autouse=True)
def _clear_catalog_cache():
    """The catalog cache is module-global. Tests must start clean."""
    _clear_cache()
    yield
    _clear_cache()


def _write_pkg(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data))
    return path


# ---------------------------------------------------------------------------
# workspace: prefix
# ---------------------------------------------------------------------------


def test_workspace_caret_recorded_as_path(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"@my/internal": "workspace:^1.0.0"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.PATH
    assert d.version is None


def test_workspace_star(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"shared": "workspace:*"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.PATH
    assert d.version is None


def test_workspace_path_form(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"local": "workspace:./pkgs/local"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.PATH
    assert d.version is None


# ---------------------------------------------------------------------------
# pnpm catalog resolution
# ---------------------------------------------------------------------------


def test_catalog_default_resolved(tmp_path):
    """Default ``catalog:`` resolves via pnpm-workspace.yaml's
    top-level ``catalog`` map."""
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "catalog:\n  react: ^18.2.0\n",
    )
    sub = tmp_path / "packages" / "app"
    sub.mkdir(parents=True)
    pkg = _write_pkg(sub / "package.json", {
        "dependencies": {"react": "catalog:"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.CARET
    assert d.version == "18.2.0"


def test_catalog_named_resolved(tmp_path):
    """``catalog:react17`` resolves via the ``catalogs.react17``
    section."""
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "catalogs:\n  react17:\n    react: ^17.0.0\n",
    )
    sub = tmp_path / "packages" / "legacy"
    sub.mkdir(parents=True)
    pkg = _write_pkg(sub / "package.json", {
        "dependencies": {"react": "catalog:react17"},
    })
    [d] = parse(pkg)
    assert d.version == "17.0.0"


def test_catalog_unresolved_no_yaml(tmp_path):
    """No pnpm-workspace.yaml in any ancestor → emit UNKNOWN-pin
    row so the operator at least sees the dep name."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"react": "catalog:"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.UNKNOWN
    assert d.version is None
    assert "could not be resolved" in d.parser_confidence.reason


def test_catalog_unresolved_missing_entry(tmp_path):
    """YAML exists but the catalog doesn't declare the package —
    same UNKNOWN-pin fallback."""
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "catalog:\n  vue: ^3.0.0\n",
    )
    pkg = _write_pkg(tmp_path / "package.json", {
        "dependencies": {"react": "catalog:"},
    })
    [d] = parse(pkg)
    assert d.pin_style == PinStyle.UNKNOWN
    assert d.parser_confidence.level == "low"


# ---------------------------------------------------------------------------
# pnpm catalog parser internals
# ---------------------------------------------------------------------------


def test_find_workspace_root_walks_up(tmp_path):
    (tmp_path / "pnpm-workspace.yaml").write_text("catalog: {}\n")
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    assert find_workspace_root(deep) == tmp_path


def test_find_workspace_root_returns_none_when_absent(tmp_path):
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    assert find_workspace_root(deep) is None


def test_get_catalogs_caches_per_root(tmp_path):
    """Second call shouldn't re-read the YAML file."""
    yaml_path = tmp_path / "pnpm-workspace.yaml"
    yaml_path.write_text("catalog:\n  a: ^1.0\n")
    first = get_catalogs(tmp_path)
    yaml_path.unlink()
    # File gone, but cached map should still be returned identically.
    second = get_catalogs(tmp_path)
    assert first == second
    assert "" in first and first[""]["a"] == "^1.0"


def test_get_catalogs_returns_empty_on_missing_yaml(tmp_path):
    assert get_catalogs(tmp_path) == {}


def test_resolve_catalog_spec_default():
    catalogs = {"": {"react": "^18.0"}}
    assert resolve_catalog_spec("catalog:", "react", catalogs) == "^18.0"


def test_resolve_catalog_spec_named():
    catalogs = {"react17": {"react": "^17.0"}}
    assert resolve_catalog_spec(
        "catalog:react17", "react", catalogs,
    ) == "^17.0"


def test_resolve_catalog_spec_returns_none_when_missing():
    catalogs = {"": {"react": "^18.0"}}
    assert resolve_catalog_spec(
        "catalog:react17", "react", catalogs,
    ) is None
    assert resolve_catalog_spec(
        "catalog:", "lodash", catalogs,
    ) is None


def test_resolve_catalog_spec_returns_none_for_non_catalog():
    assert resolve_catalog_spec("^1.0.0", "react", {}) is None


# ---------------------------------------------------------------------------
# resolutions / overrides
# ---------------------------------------------------------------------------


def test_overrides_flat(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "overrides": {
            "lodash": "4.17.21",
            "minimist": "1.2.6",
        },
    })
    deps = parse(pkg)
    by_name = {d.name: d for d in deps}
    assert "lodash" in by_name
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].source_kind == "override"
    assert by_name["lodash"].direct is True
    assert by_name["minimist"].source_kind == "override"


def test_resolutions_yarn_classic(tmp_path):
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "resolutions": {
            "@types/react": "18.0.0",
        },
    })
    deps = parse(pkg)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "@types/react"
    assert d.version == "18.0.0"
    assert d.source_kind == "override"


def test_resolutions_yarn_berry_descriptor_key(tmp_path):
    """Yarn Berry resolutions keys can carry a descriptor:
    ``"foo@npm:^1.0": "1.0.5"``. The descriptor is stripped to
    leave just the package name."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "resolutions": {
            "lodash@npm:^4.0.0": "4.17.21",
        },
    })
    deps = parse(pkg)
    assert len(deps) == 1
    assert deps[0].name == "lodash"
    assert deps[0].version == "4.17.21"


def test_overrides_nested_with_root_pin(tmp_path):
    """``"foo": {".": "1.0", "bar": "2.0"}`` — the ``"."`` is the
    tree-root pin; nested entries flatten into separate rows."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "overrides": {
            "foo": {".": "1.0.0", "bar": "2.0.0"},
        },
    })
    deps = parse(pkg)
    by_name = {d.name: d for d in deps}
    assert by_name["foo"].version == "1.0.0"
    assert by_name["bar"].version == "2.0.0"


def test_overrides_alongside_dependencies(tmp_path):
    """Both ``dependencies`` and ``overrides`` populate; each emits
    its own row, distinguishable by source_kind."""
    pkg = _write_pkg(tmp_path / "package.json", {
        "name": "app",
        "dependencies": {"react": "^18.0.0"},
        "overrides": {"react": "18.2.0"},
    })
    deps = parse(pkg)
    sources = {(d.name, d.source_kind, d.version) for d in deps}
    assert ("react", "manifest", "18.0.0") in sources
    assert ("react", "override", "18.2.0") in sources


# ---------------------------------------------------------------------------
# _flatten_overrides + _strip_descriptor
# ---------------------------------------------------------------------------


def test_flatten_overrides_handles_mixed_shapes():
    block = {
        "lodash": "4.17.21",
        "react": {".": "18.2.0", "react-dom": "18.2.0"},
        "@types/node": "20.0.0",
    }
    flat = _flatten_overrides(block)
    pairs = sorted(flat)
    assert pairs == [
        ("@types/node", "20.0.0"),
        ("lodash", "4.17.21"),
        ("react", "18.2.0"),
        ("react-dom", "18.2.0"),
    ]


def test_flatten_overrides_skips_non_string_values():
    """A bogus ``"foo": 42`` shouldn't crash or emit a row."""
    flat = _flatten_overrides({"foo": 42, "bar": "1.0"})
    assert flat == [("bar", "1.0")]


def test_strip_descriptor_plain():
    assert _strip_descriptor("lodash") == "lodash"


def test_strip_descriptor_with_npm_prefix():
    assert _strip_descriptor("lodash@npm:^4.0.0") == "lodash"


def test_strip_descriptor_scoped():
    assert _strip_descriptor("@types/react@npm:^18.0") == "@types/react"


def test_strip_descriptor_scoped_no_descriptor():
    assert _strip_descriptor("@types/react") == "@types/react"
