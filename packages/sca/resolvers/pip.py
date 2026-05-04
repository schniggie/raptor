"""pip resolver wrapper.

Uses ``pip-compile`` (from pip-tools) when available, falling back to
``pip install --dry-run`` otherwise. ``pip-compile`` is the canonical
way to deterministically resolve a ``requirements.in``-style spec into
a fully-pinned ``requirements.txt`` without actually installing
anything; ``pip install --dry-run`` (pip 23.0+) is the lighter
alternative when pip-tools isn't installed.

Neither path executes install hooks — pip doesn't run them on
``--dry-run`` for wheel-only deps, and we don't allow source-dist
fallback (``--only-binary=:all:`` where supported).
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


class PipResolver:
    """``pip-compile`` (preferred) or ``pip install --dry-run`` wrapper."""

    ecosystem = "PyPI"
    # pypi.org for JSON metadata, files.pythonhosted.org for the
    # actual wheels pip-compile / pip download for resolution.
    # Some org pip configs use a private mirror; the sandbox will
    # surface that as a proxy refusal, which is the right failure
    # mode (reveals an unallowed dep source).
    proxy_hosts = ("pypi.org", "files.pythonhosted.org")

    def is_available(self) -> bool:
        # pip itself ships with every Python install; require a usable
        # one to claim availability.
        return _check_tool(["pip", "--version"])

    def matches(self, project_dir: Path) -> bool:
        # pip is the fallback resolver for the PyPI ecosystem — it
        # matches anything with a pip-style manifest. PoetryResolver
        # is registered before pip and steals projects with a
        # ``[tool.poetry]`` section in pyproject.toml.
        return _find_pip_manifest(project_dir) is not None

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="pip not found in PATH",
            )

        manifest = _find_pip_manifest(project_dir)
        if manifest is None:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=("no requirements*.txt or pyproject.toml in "
                       f"{project_dir}"),
            )

        # Prefer pip-compile when present — it's deterministic and
        # produces a clean fully-pinned output we return as the lockfile.
        if _check_tool(["pip-compile", "--version"]):
            return self._run_pip_compile(project_dir, manifest, timeout)
        # Fallback: pip install --dry-run. Returns success/failure but
        # no lockfile artefact (pip writes to site-packages on success;
        # --dry-run prevents that).
        return self._run_pip_dry(project_dir, manifest, timeout)

    # ----- internals -----

    def _run_pip_compile(
        self, project_dir: Path, manifest: Path, timeout: int,
    ) -> ResolverResult:
        try:
            proc = _run(
                ["pip-compile", "--quiet", "--output-file", "-",
                  str(manifest.relative_to(project_dir))],
                cwd=project_dir,
                timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"pip-compile timed out after {timeout}s",
            )
        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                        or "pip-compile exited non-zero"),
                raw_output=raw,
            )
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=proc.stdout.encode("utf-8"),
            raw_output=raw,
        )

    def _run_pip_dry(
        self, project_dir: Path, manifest: Path, timeout: int,
    ) -> ResolverResult:
        cmd = [
            "pip", "install", "--dry-run", "--quiet",
            "-r", str(manifest.relative_to(project_dir)),
            "--only-binary=:all:",     # avoid sdist setup.py runs
        ]
        try:
            proc = _run(cmd, cwd=project_dir, timeout=timeout,
                        proxy_hosts=self.proxy_hosts)
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"pip install --dry-run timed out after {timeout}s",
            )
        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                        or "pip install --dry-run exited non-zero"),
                raw_output=raw,
            )
        # No lockfile to read; success is the signal.
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=None,
            raw_output=raw,
        )


def _find_pip_manifest(project_dir: Path) -> Optional[Path]:
    """Return the path to a top-level pip-style manifest, if any."""
    candidates = [
        project_dir / "requirements.txt",
        project_dir / "requirements-dev.txt",
        project_dir / "requirements.in",
        project_dir / "pyproject.toml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


__all__ = ["PipResolver"]
