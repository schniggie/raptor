"""Tests for the hash-pin rewriter (GitHub Actions workflow refs)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from packages.sca.hash_pin import hash_pin_workflows


class _FakeProc(subprocess.CompletedProcess):
    def __init__(self, returncode: int, stdout: str = "",
                 stderr: str = "") -> None:
        super().__init__(args=[], returncode=returncode,
                          stdout=stdout, stderr=stderr)


def _patch_ls_remote(monkeypatch, mapping):
    """``mapping`` is ``{(owner_repo, ref): sha}`` — fake ls-remote output."""
    def fake_run(cmd, **kwargs):
        if cmd[:2] != ["git", "ls-remote"]:
            return _FakeProc(returncode=1)
        # ``git ls-remote https://github.com/owner/repo.git ref refs/tags/ref refs/heads/ref``
        url = cmd[2]
        # Parse owner/repo from URL.
        slug = url.replace("https://github.com/", "").replace(
            ".git", "")
        if "@github.com/" in url:
            slug = url.split("@github.com/", 1)[1].replace(".git", "")
        ref = cmd[3] if len(cmd) >= 4 else ""
        sha = mapping.get((slug, ref))
        if sha is None:
            return _FakeProc(returncode=0, stdout="")
        return _FakeProc(returncode=0,
                          stdout=f"{sha}\trefs/tags/{ref}\n")
    monkeypatch.setattr(subprocess, "run", fake_run)


def test_pins_uses_ref_to_sha(monkeypatch, tmp_path: Path) -> None:
    """``actions/checkout@v4`` resolves to a SHA and gets rewritten."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@v3\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/checkout", "v4"): "0" * 40,
        ("actions/setup-node", "v3"): "1" * 40,
    })
    result = hash_pin_workflows(tmp_path, write=True)
    assert len(result.changes) == 2
    assert (workflows / "ci.yml").read_text().count("@" + "0" * 40) == 1
    assert (workflows / "ci.yml").read_text().count("@" + "1" * 40) == 1
    # Original ref preserved as comment.
    assert "# was v4" in (workflows / "ci.yml").read_text()


def test_already_sha_skipped(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    sha = "abcdef" + "0" * 34
    (workflows / "ci.yml").write_text(
        f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{sha}\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {})
    result = hash_pin_workflows(tmp_path, write=True)
    assert result.changes == []


def test_unresolvable_ref_skipped(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: nonexistent/action@v99\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {})  # no entries → empty stdout
    result = hash_pin_workflows(tmp_path, write=True)
    assert result.changes == []
    assert len(result.skipped) == 1


def test_dry_run_does_not_write(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    body = "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"
    (workflows / "ci.yml").write_text(body, encoding="utf-8")
    _patch_ls_remote(monkeypatch, {("actions/checkout", "v4"): "a" * 40})
    result = hash_pin_workflows(tmp_path, write=False)
    assert len(result.changes) == 1                         # plan computed
    # File untouched.
    assert (workflows / "ci.yml").read_text() == body


def test_local_action_skipped(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - uses: ./.github/actions/local\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {})
    result = hash_pin_workflows(tmp_path, write=True)
    assert result.changes == []
    assert result.skipped == []                             # not a candidate


def test_subpath_action(monkeypatch, tmp_path: Path) -> None:
    """``org/action/sub@ref`` — subpath preserved through the rewrite."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/cache/restore@v3\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/cache", "v3"): "c" * 40,
    })
    result = hash_pin_workflows(tmp_path, write=True)
    assert len(result.changes) == 1
    text = (workflows / "ci.yml").read_text()
    assert f"actions/cache/restore@{'c' * 40}" in text


def test_no_workflows_dir(tmp_path: Path) -> None:
    result = hash_pin_workflows(tmp_path)
    assert result.changes == []
    assert result.skipped == []
