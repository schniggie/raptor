"""Semver comparator.

Used by npm, Cargo, Go (with leading 'v' tolerated). Implements the
ordering rules from https://semver.org/ — three-component MAJOR.MINOR.PATCH
plus optional pre-release and build-metadata suffixes. Build metadata is
ignored for ordering (per spec). Pre-release order is dot-separated
identifier comparison (numeric < non-numeric).

For Go pseudo-versions (e.g., v0.0.0-20210320205559-abc123), we compare
on the full string after stripping the leading 'v'; the timestamp segment
is lexicographically ordered by spec.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple


# v-prefixed (Go), or plain semver, with optional pre-release and build.
# Accepts short forms (1, 1.2, 1.2.3); missing components default to 0.
# Strict semver requires three components but real-world advisory data
# (and Go pseudo-versions) often ships shorter forms.
_SEMVER_RE = re.compile(
    r"""
    ^
    v?                                # tolerate leading v (Go)
    (?P<major>\d+)
    (?:\.(?P<minor>\d+))?
    (?:\.(?P<patch>\d+))?
    (?:-(?P<pre>[0-9A-Za-z.-]+))?     # pre-release
    (?:\+(?P<build>[0-9A-Za-z.-]+))?  # build metadata (ignored for ordering)
    $
    """,
    re.VERBOSE,
)


def parse(version: str) -> Tuple[int, int, int, Optional[List[str]]]:
    """Parse version into (major, minor, patch, pre).

    Missing minor / patch default to 0. pre is a list of dot-separated
    identifiers, or None when absent. Build metadata is dropped (per
    semver spec, ignored for ordering).
    """
    m = _SEMVER_RE.match(version.strip())
    if not m:
        raise ValueError(f"not a semver version: {version!r}")
    pre = m.group("pre")
    return (
        int(m.group("major")),
        int(m.group("minor") or "0"),
        int(m.group("patch") or "0"),
        pre.split(".") if pre else None,
    )


def compare(a: str, b: str) -> int:
    """Return -1, 0, 1 per semver ordering."""
    if a == b:
        return 0
    pa = parse(a)
    pb = parse(b)
    # Compare major.minor.patch numerically.
    for x, y in zip(pa[:3], pb[:3]):
        if x != y:
            return -1 if x < y else 1
    # Pre-release: a version with pre is < the same version without.
    a_pre, b_pre = pa[3], pb[3]
    if a_pre is None and b_pre is None:
        return 0
    if a_pre is None:
        return 1
    if b_pre is None:
        return -1
    # Both pre — compare identifier by identifier.
    for ai, bi in zip(a_pre, b_pre):
        c = _compare_identifier(ai, bi)
        if c != 0:
            return c
    # All compared equal so far — shorter wins per spec.
    if len(a_pre) != len(b_pre):
        return -1 if len(a_pre) < len(b_pre) else 1
    return 0


def _compare_identifier(a: str, b: str) -> int:
    """Compare two pre-release identifiers per semver spec.

    Numeric identifiers always have lower precedence than alphanumeric ones.
    Numeric identifiers are compared numerically; alphanumeric ones lexically.
    """
    a_num = a.isdigit()
    b_num = b.isdigit()
    if a_num and b_num:
        ai, bi = int(a), int(b)
        if ai == bi:
            return 0
        return -1 if ai < bi else 1
    if a_num and not b_num:
        return -1
    if b_num and not a_num:
        return 1
    if a == b:
        return 0
    return -1 if a < b else 1
