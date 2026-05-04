"""Module-level reachability for Go module deps.

Walks ``*.go`` files outside ``*_test.go`` and ``vendor/`` trees,
extracts ``import "<module-path>"`` statements (single + parenthesised
block forms), and matches each module path against the dep's name.

Match semantics: a dep ``github.com/foo/bar`` is "imported" when any
import path is exactly that, OR is a sub-package of it
(``github.com/foo/bar/sub`` counts).
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

# Single-line: ``import "foo"`` (with optional alias prefix).
_IMPORT_SINGLE_RE = re.compile(
    r'^\s*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"',
    re.MULTILINE,
)
# Block form: ``import (\n  "foo"\n  alias "bar"\n)``
_IMPORT_BLOCK_RE = re.compile(
    r"^\s*import\s*\(\s*([^)]*)\)",
    re.MULTILINE | re.DOTALL,
)
_BLOCK_LINE_RE = re.compile(
    r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"',
    re.MULTILINE,
)


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> Dict[str, List[Tuple[Path, int, bool]]]:
    """Return ``{import_path: [(file, line, is_test), ...]}``."""
    target = target.resolve()
    out: Dict[str, List[Tuple[Path, int, bool]]] = {}
    for go_file in _walk_go_sources(target, max_depth=max_depth):
        is_test = _is_test_file(go_file)
        try:
            text = go_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("sca.reachability.gomod: skip %s (%s)", go_file, e)
            continue
        for path, line in _imports_in(text):
            out.setdefault(path, []).append((go_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: Dict[str, List[Tuple[Path, int, bool]]],
    *,
    target: Optional[Path] = None,
) -> Reachability:
    """Look up ``dep_name`` (a Go module path) in the scan."""
    # Match exact OR any sub-path. Cheap loop over scan keys; in practice
    # scans rarely exceed a few hundred unique imports.
    matches: List[Tuple[Path, int, bool]] = []
    prefix = dep_name.rstrip("/") + "/"
    for path, hits in scan.items():
        if path == dep_name or path.startswith(prefix):
            matches.extend(hits)

    if not matches:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=f"no `import \"{dep_name}\"` found",
            ),
            evidence=[],
        )
    non_test = [h for h in matches if not h[2]]
    if non_test:
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "high",
                reason="import found in non-test Go source",
            ),
            evidence=_format_evidence(non_test, target=target),
        )
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="module referenced only by *_test.go files",
        ),
        evidence=_format_evidence(matches, target=target),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _imports_in(text: str) -> Iterable[Tuple[str, int]]:
    # Single-line.
    for m in _IMPORT_SINGLE_RE.finditer(text):
        yield m.group(1), text.count("\n", 0, m.start()) + 1
    # Block form.
    for block in _IMPORT_BLOCK_RE.finditer(text):
        block_start = block.start()
        body = block.group(1)
        for line_m in _BLOCK_LINE_RE.finditer(body):
            line_no = (text.count("\n", 0, block_start)
                        + body.count("\n", 0, line_m.start()) + 1)
            yield line_m.group(1), line_no


def _walk_go_sources(
    target: Path, *, max_depth: int,
) -> Iterable[Path]:
    root_depth = len(target.parts)
    skip_dirs = {"vendor", "node_modules", ".git", "__pycache__", "out"}
    for dirpath, dirnames, filenames in os.walk(str(target), followlinks=False):
        cur = Path(dirpath)
        if len(cur.parts) - root_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if fn.endswith(".go"):
                yield cur / fn


def _is_test_file(path: Path) -> bool:
    return path.name.endswith("_test.go")


def _format_evidence(
    hits: List[Tuple[Path, int, bool]],
    *,
    target: Optional[Path],
    cap: int = 5,
) -> List[str]:
    out: List[str] = []
    for f, line, _ in hits[:cap]:
        rel = (f.relative_to(target) if target and target in f.parents
                else f)
        out.append(f"{rel}:{line}")
    if len(hits) > cap:
        out.append(f"... (+{len(hits) - cap} more)")
    return out
