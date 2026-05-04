"""Regression tests for discovery exclusion rules."""

from __future__ import annotations

from pathlib import Path

from packages.sca.discovery import EXCLUDED_DIR_NAMES, find_manifests


def test_top_level_packages_dir_not_excluded(tmp_path: Path) -> None:
    """`packages/` is a legitimate monorepo layout (raptor, rush, lerna).

    A previous version of the exclude list dropped it silently, hiding
    real manifests. Guard against the regression.
    """
    repo = tmp_path / "proj"
    (repo / "packages" / "web").mkdir(parents=True)
    (repo / "packages" / "web" / "requirements.txt").write_text(
        "django==4.2.7\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.31.0\n",
                                            encoding="utf-8")

    manifests = find_manifests(repo)
    paths = {str(m.path.relative_to(repo)) for m in manifests}
    assert "packages/web/requirements.txt" in paths
    assert "requirements.txt" in paths


def test_node_modules_still_excluded(tmp_path: Path) -> None:
    """``node_modules`` must stay excluded — it's vendored deps."""
    repo = tmp_path / "proj"
    (repo / "node_modules" / "lodash").mkdir(parents=True)
    (repo / "node_modules" / "lodash" / "package.json").write_text(
        '{"name":"lodash","version":"4.17.21"}\n', encoding="utf-8")
    (repo / "package.json").write_text(
        '{"name":"app","dependencies":{"lodash":"^4"}}\n', encoding="utf-8")

    manifests = find_manifests(repo)
    paths = {str(m.path.relative_to(repo)) for m in manifests}
    assert "package.json" in paths
    assert not any("node_modules" in p for p in paths)


def test_packages_not_in_excludes() -> None:
    """Belt-and-braces: bare 'packages' must not be in EXCLUDED_DIR_NAMES."""
    assert "packages" not in EXCLUDED_DIR_NAMES
