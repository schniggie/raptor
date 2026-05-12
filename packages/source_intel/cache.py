"""Content-addressed cache for :class:`SourceIntelResult`.

Phase 2 ships an in-memory cache; persistence to disk lands in axis-N
PRs when cocci run-cost becomes the dominant cross-stage cost.

Cache key composition:

  rules_hash :  sha256 of the contents of every ``.cocci`` file under
                the rules dir, sorted by name. Captures rule-corpus
                version.
  target_hash : sha256 of the target's source-file tree (file names +
                content hashes), bounded for cost.
  schema_version : module-level constant, bumped when the result shape
                changes meaningfully.

Cache miss → re-run analyze; hit → load result. The cache key
includes target so multiple targets co-exist; the schema_version
guards against stale shapes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

from packages.source_intel.analyze import SCHEMA_VERSION, SourceIntelResult


@dataclass
class SourceIntelCache:
    """In-memory cache mapping (target, rules_hash) → result.

    Process-local; thread-safe under the GIL for our usage (analyze is
    a long-running spatch invocation but the cache get/put is atomic
    dict ops). Not durable — restart loses cached entries. Persistence
    to disk is deferred per ``project_source_intel_kickoff.md``.
    """

    _entries: Dict[Tuple[str, str], SourceIntelResult] = field(default_factory=dict)

    def get(
        self,
        target: Path,
        rules_dir: Optional[Path] = None,
    ) -> Optional[SourceIntelResult]:
        """Lookup. Returns None on miss."""
        key = self._key_for(target, rules_dir)
        return self._entries.get(key)

    def put(
        self,
        target: Path,
        rules_dir: Optional[Path],
        result: SourceIntelResult,
    ) -> None:
        """Store result under (target, rules_hash)."""
        key = self._key_for(target, rules_dir)
        self._entries[key] = result

    def invalidate(self) -> None:
        """Clear all entries — used on schema-version bumps or when
        the caller knows the rule set or target has changed mid-run."""
        self._entries.clear()

    def size(self) -> int:
        return len(self._entries)

    @staticmethod
    def _key_for(
        target: Path,
        rules_dir: Optional[Path],
    ) -> Tuple[str, str]:
        target_hash = _hash_target_tree(Path(target))
        rules_hash = _hash_rules_dir(
            Path(rules_dir) if rules_dir else None
        )
        # Schema version is part of the key so a SCHEMA_VERSION bump
        # invalidates the cache even when target + rules unchanged.
        return (
            f"{target_hash}:v{SCHEMA_VERSION}",
            rules_hash,
        )


# =====================================================================
# Hashing helpers
# =====================================================================


_C_CPP_EXTS: Tuple[str, ...] = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
)


def _hash_target_tree(target: Path) -> str:
    """SHA-256 of every C/C++ source file under target, by sorted path.

    For non-directory targets, hashes the single file. For missing
    targets, returns a constant sentinel hash so cache misses are
    deterministic.

    Bounded: walks up to 5000 files (kernel-scale safety).
    """
    if not target.exists():
        return "missing"

    h = hashlib.sha256()
    if target.is_file():
        h.update(b"FILE\x00")
        h.update(str(target).encode("utf-8"))
        h.update(b"\x00")
        h.update(_file_hash(target).encode("utf-8"))
        return h.hexdigest()

    h.update(b"DIR\x00")
    files = []
    for entry in target.rglob("*"):
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _C_CPP_EXTS:
            continue
        files.append(entry)
        if len(files) >= 5000:
            break
    for path in sorted(files, key=lambda p: str(p)):
        h.update(str(path.relative_to(target)).encode("utf-8"))
        h.update(b"\x00")
        h.update(_file_hash(path).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def _hash_rules_dir(rules_dir: Optional[Path]) -> str:
    """SHA-256 of every .cocci file under rules_dir, sorted by name.

    Returns ``"default"`` when rules_dir is None — the caller will use
    the shipped rules directory, which is hashed via this function on
    a real path at analyze time.
    """
    if rules_dir is None:
        return "default-rules"
    if not rules_dir.exists():
        return "missing-rules"

    h = hashlib.sha256()
    files = sorted(rules_dir.rglob("*.cocci"), key=lambda p: str(p))
    for path in files:
        h.update(str(path.relative_to(rules_dir)).encode("utf-8"))
        h.update(b"\x00")
        h.update(_file_hash(path).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def _file_hash(path: Path) -> str:
    """SHA-256 of a single file's contents."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return "read-error"
    return h.hexdigest()
