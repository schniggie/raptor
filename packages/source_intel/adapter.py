""":class:`Validator` adapter — wires source_intel into the corpus runner.

Phase 2 substrate ships a minimal verdict policy: source_intel is
fundamentally a SIDECAR (evidence, not verdict), so the Validator
returns ``UNCERTAIN`` for findings where structural evidence is
inconclusive — which is most findings until axes 2-7 ship. Specific
explicit-verdict cases:

  * Finding's function annotated WUR (literal or known alias) AND
    finding cites an unchecked-return-class CWE (CWE-252/CWE-476):
    EXPLOITABLE — author intent supports the claim. (Build-flag
    enforcement caveats are recorded in evidence but don't gate
    the verdict.)
  * All other cases: UNCERTAIN.

This minimal policy intentionally leaves room for axes 2-7 to refine
the verdict via the same Validator. The corpus runner records the
UNCERTAIN bucket separately — it doesn't contribute to precision /
recall, so Phase 2 lands without harming the V2 baseline.

Wire via:
    libexec/raptor-corpus-run --output source_intel.csv \\
        --validator packages.source_intel.adapter:SourceIntelValidator
    libexec/raptor-corpus-metrics source_intel.csv
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional, Tuple

from core.dataflow.finding import Finding
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.analyze import (
    GRADE_DOMINATES,
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    KIND_ACCESS,
    KIND_ALLOC_SIZE,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_NONNULL,
    KIND_NORETURN,
    KIND_RETURNS_NONNULL,
    KIND_WUR,
    AbortEvidence,
    AllocationEvidence,
    AttributeEvidence,
    SourceIntelResult,
    analyze,
)
from packages.source_intel.cache import SourceIntelCache

logger = logging.getLogger(__name__)


# Per-attribute-kind CWE relevance: only emit a verdict signal when
# the finding's rule_id is in the relevant set for the observed
# attribute. This keeps the verdict policy scoped — WUR evidence on
# a use-after-free finding does NOT support EXPLOITABLE.
_KIND_RELEVANT_RULE_PREFIXES: Dict[str, Tuple[str, ...]] = {
    KIND_WUR: (
        "cpp/null-dereference",
        "cpp/uncontrolled-",        # uncontrolled-allocation-size, etc.
        "cpp/unchecked-return",
        "cpp/unbounded-write",
        "c/null-dereference",
    ),
    KIND_NONNULL: (
        "cpp/null-dereference",
        "c/null-dereference",
    ),
    # alloc_size is mostly informational for memory-corruption findings:
    # tells the LLM "this function's return is a buffer of size N",
    # which is highly relevant when reasoning about CWE-120 / CWE-122
    # (where the bug is over-running an allocated buffer).
    KIND_ALLOC_SIZE: (
        "cpp/unbounded-write",
        "cpp/uncontrolled-",        # uncontrolled-allocation-size
    ),
    # returns_nonnull is relevant when the finding is about a NULL deref:
    # caller may have skipped a null check trusting the annotation; if
    # the annotation is wrong, the deref fires.
    KIND_RETURNS_NONNULL: (
        "cpp/null-dereference",
        "c/null-dereference",
    ),
    # noreturn is informational for the verdict policy — knowing a
    # function aborts on the path SUPPORTS a not-exploitable verdict
    # (DoS-only). But Phase 2-3 never emit NOT_EXPLOITABLE; we leave
    # noreturn evidence to surface via render strings only, with no
    # rule-id-relevance dispatch yet. Empty tuple → no verdict-relevant
    # rule prefixes.
    KIND_NORETURN: (),
    # malloc by itself is informational (mostly co-applied with
    # alloc_size). Leave verdict policy to alloc_size; malloc surfaces
    # via render strings only.
    KIND_MALLOC: (),
    # no_stack_protector marks a hardening hole. Relevant verdict
    # signal for stack-buffer-overflow CWE classes — finding gains
    # support when the buggy function explicitly opts out of canary
    # insertion.
    KIND_NO_STACK_PROTECTOR: (
        "cpp/unbounded-write",
        "cpp/uncontrolled-",
    ),
    # access declares pointer-parameter intent; relevant for CWE-120
    # / CWE-787 (the compiler may bounds-check operations against the
    # annotated parameter under FORTIFY_SOURCE).
    KIND_ACCESS: (
        "cpp/unbounded-write",
        "cpp/uncontrolled-",
    ),
}

# Back-compat — Phase 2 tests imported this name; preserved as the
# union over all kinds, which matches the Phase 2 single-kind
# semantics (Phase 2 dispatch was wur-only).
_WUR_RELEVANT_RULE_PREFIXES = _KIND_RELEVANT_RULE_PREFIXES[KIND_WUR]


# Repo-relative path prefixes that source_intel can scan; anything else
# (out-of-tree-fixture or absolute) is treated per the file's own path.
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


class SourceIntelValidator:
    """:class:`Validator` implementation driven by source_intel cocci
    evidence.

    Zero-arg construction works (for ``--validator`` import spec). The
    cache is shared across :meth:`validate` calls so repeated finding
    references to the same target tree amortize the cocci-run cost.
    """

    def __init__(
        self,
        repo_root: Optional[Path] = None,
        cache: Optional[SourceIntelCache] = None,
    ) -> None:
        self._repo_root = repo_root or _DEFAULT_REPO_ROOT
        self._cache = cache or SourceIntelCache()

    def validate(self, finding: Finding) -> ValidatorVerdict:
        """Return EXPLOITABLE when WUR-class evidence backs the claim;
        UNCERTAIN otherwise. NEVER NOT_EXPLOITABLE in Phase 2 — that
        would require axis 2 (proximity) or axis 4 (privilege gradient)
        evidence to support a confident refutation.
        """
        target = self._target_for_finding(finding)
        if target is None:
            return ValidatorVerdict.UNCERTAIN

        result = self._cache.get(target)
        if result is None:
            try:
                result = analyze(target)
            except Exception:  # noqa: BLE001 — never let analyze crash the runner
                logger.exception("source_intel analyze failed for %s", target)
                return ValidatorVerdict.UNCERTAIN
            self._cache.put(target, None, result)

        return self._verdict_from_result(finding, result)

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------

    def _target_for_finding(self, finding: Finding) -> Optional[Path]:
        """Derive the target directory to scan from the finding's
        source file path.

        Heuristic: walk up from ``finding.source.file_path`` (resolved
        relative to repo root) to find a directory containing a build
        marker (``Makefile`` / ``compile_commands.json`` / ``.config``).
        Falls back to the file's immediate parent when no marker found.

        Returns None when the path can't be resolved — corpus replay
        on an unclonied out-of-tree fixture lands here.
        """
        file_path = (finding.source.file_path or "").strip()
        if not file_path:
            return None

        candidate = Path(file_path)
        if not candidate.is_absolute():
            candidate = (self._repo_root / candidate).resolve()

        if not candidate.exists():
            return None

        # If candidate is a file, walk up looking for build markers.
        if candidate.is_file():
            cur = candidate.parent
            for _ in range(8):  # bounded walk; kernel trees ~4 deep
                if (
                    (cur / "Makefile").is_file()
                    or (cur / "compile_commands.json").is_file()
                    or (cur / ".config").is_file()
                    or (cur / "Kbuild").is_file()
                ):
                    return cur
                if cur == cur.parent:
                    break
                cur = cur.parent
            return candidate.parent

        return candidate

    def _verdict_from_result(
        self,
        finding: Finding,
        result: SourceIntelResult,
    ) -> ValidatorVerdict:
        """Apply the verdict policy in four passes:

        1. **Dead-code check (Phase 7):** if PR-4's function_inventory
           reports the finding's enclosing function has zero callers
           in the target AND it's static, the bug is unreachable —
           return NOT_EXPLOITABLE with dead_code rationale.

        2. **Abort-dominance check (Phase 5a):** if an abort-class call
           sits in the same function as the finding's sink AND the
           finding's rule_id is memory-corruption-class, the bug
           primitive aborts before exploitation — return
           NOT_EXPLOITABLE.

        3. **Unchecked-allocation check (Phase 6a, axis 3):** if the
           finding's source line is at an allocator call site we
           emitted as `unchecked_alloc_*` AND the rule_id is
           null-deref-class, the structural unchecked-alloc evidence
           directly supports the finding — return EXPLOITABLE.

        4. **Attribute-evidence check (Phase 3-3d):** EXPLOITABLE when
           an attribute observation references a function named in the
           finding's snippet AND the rule_id is kind-relevant.

        Default: UNCERTAIN.
        """
        if result.is_skipped:
            return ValidatorVerdict.UNCERTAIN

        if _finding_in_dead_code(finding, self._repo_root):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _abort_dominates_finding(finding, result):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _unchecked_alloc_supports_finding(finding, result):
            return ValidatorVerdict.EXPLOITABLE

        snippet = (
            (finding.source.snippet or "")
            + " "
            + (finding.sink.snippet or "")
        )

        for ev in result.attributes:
            if not ev.function_name:
                continue
            if ev.function_name not in snippet:
                continue
            if _rule_id_is_relevant_for_kind(finding.rule_id, ev.kind):
                return ValidatorVerdict.EXPLOITABLE

        return ValidatorVerdict.UNCERTAIN


def _rule_id_is_relevant_for_kind(rule_id: str, kind: str) -> bool:
    """Check whether ``rule_id`` is in the relevance set for ``kind``."""
    return any(rule_id.startswith(prefix)
               for prefix in _KIND_RELEVANT_RULE_PREFIXES.get(kind, ()))


def _rule_id_is_wur_relevant(rule_id: str) -> bool:
    """Back-compat shim — Phase 2 callers / tests."""
    return _rule_id_is_relevant_for_kind(rule_id, KIND_WUR)


# Rule prefixes for which unchecked-allocation evidence directly
# supports the finding. Currently null-deref family — the typical
# manifestation of an unchecked alloc-result is a NULL deref.
_NULL_DEREF_RULE_PREFIXES: Tuple[str, ...] = (
    "cpp/null-dereference",
    "c/null-dereference",
)


def _finding_in_dead_code(finding: Finding, repo_root: Path) -> bool:
    """Compose with PR-4's ``packages.coccinelle.prereqs.gather_prereqs``
    to detect whether the finding's enclosing function is dead code
    (static, defined but not called anywhere in the target).

    Returns True iff:
      * the finding's sink file is C/C++ source
      * `_enclosing_function` resolves the sink to a function name F
      * F is declared `static` (file-local linkage)
      * PR-4 prereqs reports F as defined AND with zero callers

    The `static` requirement is critical: a non-static function whose
    callers happen to live in OTHER files (not in our target subset)
    would otherwise be wrongly flagged as dead. The classic example
    is a kernel driver entry-point function whose only caller is in
    a different translation unit. `static` linkage means the function
    is file-scoped — no callers in this file → genuinely unreachable.

    Skips silently when PR-4 isn't available (minimal install).
    """
    try:
        from packages.coccinelle.prereqs import gather_prereqs
    except ImportError:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path or not sink_line:
        return False

    # Resolve to absolute for the function-bounds heuristic + cache
    # comparison with PR-4 prereqs output.
    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((repo_root / sink_path).resolve())

    from packages.source_intel.analyze import _enclosing_function
    finding_fn = _enclosing_function(sink_path_abs, sink_line)
    if not finding_fn:
        return False

    if not _function_is_static(sink_path_abs, finding_fn):
        return False

    # Find the target directory (same heuristic as
    # _target_for_finding — file's parent or build-marker directory).
    target = Path(sink_path_abs).parent
    if not target.is_dir():
        return False

    facts = gather_prereqs(target)
    if facts.is_skipped:
        return False
    # Function must be defined AND have zero callers in the target.
    if not facts.function_exists(finding_fn):
        return False
    if facts.function_has_callers(finding_fn):
        return False
    # Final guard: PR-4's function_inventory.cocci only tracks direct
    # `funcname(args)` invocations. It misses function-pointer uses
    # (kernel struct ops vtables: `.mgmt_tx = brcmf_cfg80211_mgmt_tx,`,
    # callback registration: `register_handler(my_handler);`,
    # array-of-callbacks). A static function referenced as a pointer
    # IS reachable — skip the dead-code verdict.
    if _function_referenced_as_pointer(target, finding_fn):
        return False
    return True


def _function_referenced_as_pointer(
    target: Path, function_name: str
) -> bool:
    """Best-effort: scan ``target`` (file or dir) for non-call uses of
    ``function_name``. Returns True if the name appears in a context
    consistent with function-pointer use (vtable assignment, callback
    registration, address-of, array element).

    Patterns:
      * ``.field = funcname[,;}]``       — struct vtable assignment
      * ``= funcname[,;}]``              — bare initializer
      * ``& funcname\\b``                 — address-of
      * ``( funcname [,)]``              — passed as argument
      * ``\\bfuncname [,;]``              — array element / list

    Conservative file traversal: limited to ``.c`` / ``.h`` / ``.cc``
    / ``.cpp`` / ``.hpp`` to bound cost on noisy targets.
    """
    import re as _re
    fn = _re.escape(function_name)
    # Single regex covering the common pointer-use shapes. Each
    # alternative requires ``function_name`` is NOT followed by ``(``
    # — otherwise it is just a normal call PR-4 would have caught.
    pat = _re.compile(
        r"(?:[.=&,(]\s*" + fn + r"|^\s*" + fn + r")"
        r"(?!\s*\()"  # NOT a call
        r"(?:\s*[,;)}]|\s*$|\s+\w)",
        _re.MULTILINE,
    )
    EXTS = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hxx"}
    if target.is_file():
        files = [target]
    else:
        files = [p for p in target.rglob("*") if p.suffix in EXTS]
    for path in files:
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        # Strip the function's own definition line so we don't
        # match it as a self-reference. Cheap heuristic: skip lines
        # containing both the name AND `(` AND `{` on same line, OR
        # a trailing `(` (signature line). Better: filter in pattern
        # via the `(?!\s*\()` negative lookahead — already done.
        if pat.search(text):
            return True
    return False


def _function_is_static(file_path: str, function_name: str) -> bool:
    """Best-effort: scan ``file_path`` for a line beginning with
    ``static`` and containing ``function_name(``.

    Conservative: returns False when uncertain. Static-detection
    failure ALWAYS keeps a non-static function from being marked
    dead, which is the safe direction (avoids false positives on
    cross-TU-callable functions).
    """
    try:
        with open(file_path, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        return False
    # Match `static [optional return-type tokens] funcname(`
    import re as _re
    pat = _re.compile(
        r"^\s*static\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+|\*\s*)*"
        + _re.escape(function_name) + r"\s*\(",
        _re.MULTILINE,
    )
    return bool(pat.search(text))


def _unchecked_alloc_supports_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-3 evidence directly supports an EXPLOITABLE
    verdict on this finding:

    * finding's rule_id is null-deref-class, AND
    * an unchecked-allocation site sits at the finding's source line
      (within a small line-tolerance for column / multi-statement
      mismatches).

    Phase 6a only matches the field-assignment shape (cocci's
    ``unchecked_alloc_field`` rule). Local-variable and nested-field
    shapes wait for axis-3-expansion.
    """
    rid = finding.rule_id or ""
    if not any(rid.startswith(p) for p in _NULL_DEREF_RULE_PREFIXES):
        return False
    if not result.allocations:
        return False

    src_path = finding.source.file_path or ""
    src_line = finding.source.line or 0
    if not src_path or not src_line:
        return False

    src_path_abs = src_path
    if not Path(src_path).is_absolute():
        src_path_abs = str((_DEFAULT_REPO_ROOT / src_path).resolve())

    # Tight tolerance — the cocci match's line should be within a
    # handful of lines of the finding's source. The fixture path
    # (relative) and the cocci-emitted path (absolute) are normalised
    # via the path-resolution above.
    _SRC_LINE_TOLERANCE = 3

    for ae in result.allocations:
        alloc_path, alloc_line = ae.location
        if alloc_path != src_path_abs:
            continue
        if abs(alloc_line - src_line) > _SRC_LINE_TOLERANCE:
            continue
        return True

    return False


# Memory-corruption rule_id prefixes — findings in these CWE classes
# may have their primitive aborted by an upstream abort-class call.
# CWE-78 / CWE-89 (injection) findings don't benefit from this signal
# because the exploitation primitive doesn't depend on continued
# execution of the C-language process state.
_MEMORY_CORRUPTION_RULE_PREFIXES: Tuple[str, ...] = (
    "cpp/null-dereference",
    "cpp/use-after-free",
    "cpp/double-free",
    "cpp/unbounded-write",
    "cpp/uncontrolled-",
    "c/null-dereference",
)


def _abort_dominates_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-2 evidence supports NOT_EXPLOITABLE:

    * finding's rule_id is memory-corruption-class, AND
    * an abort-class call site sits in the same function as the
      finding's sink (Phase 5a same_function grade is enough;
      later phases will require same_path / dominates grade).

    The finding's enclosing function is derived from sink (file, line)
    via the same regex-based heuristic that ``analyze.py`` applies to
    abort sites — both sides use the same logic so attributions match
    when they exist.
    """
    rid = finding.rule_id or ""
    if not any(rid.startswith(p) for p in _MEMORY_CORRUPTION_RULE_PREFIXES):
        return False
    if not result.aborts:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path:
        return False

    # Normalise sink_path to absolute so it can be compared against
    # the abort's location (which carries the absolute path that
    # analyze passed to spatch). Relative paths in Finding records
    # are resolved against repo root.
    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    # Determine the finding's enclosing function (best-effort).
    from packages.source_intel.analyze import _enclosing_function
    finding_fn = _enclosing_function(sink_path_abs, sink_line) if sink_line else None

    # Phase 5a: NOT_EXPLOITABLE requires same-function AND tight line
    # proximity. `same_function` alone is too weak for big functions
    # (kernel functions routinely run 4000+ lines, so an abort
    # somewhere in the function doesn't dominate the bug primitive
    # 3000 lines later). Documented in the abort_proximate.cocci
    # rule header as a known limitation; later grades (`same_path`,
    # `dominates`) computed by axis-2-expansion will drop this
    # proximity requirement.
    _SAME_FUNCTION_LINE_PROXIMITY = 50

    for ab in result.aborts:
        # Require the abort to be in the same file as the finding's
        # sink (cross-file abort isn't proximate for our purposes).
        abort_path, abort_line = ab.location
        if abort_path != sink_path_abs:
            continue
        # Phase 5a grade gate — same_function with line proximity,
        # or any stronger grade (same_path / dominates) when those
        # ship in axis-2-expansion.
        if ab.grade == GRADE_SAME_FUNCTION:
            # Same-function + tight proximity → confident dominance.
            if not sink_line:
                continue
            if abs(abort_line - sink_line) > _SAME_FUNCTION_LINE_PROXIMITY:
                continue
            # Both function names known: must match exactly.
            if finding_fn and ab.enclosing_function:
                if ab.enclosing_function == finding_fn:
                    return True
                continue
            # At least one name unknown — accept on tight proximity
            # alone. The line check (≤50) already filters out the
            # mega-function false positives that motivated this gate.
            return True
        elif ab.grade in (GRADE_SAME_PATH, GRADE_DOMINATES):
            # Stronger grades — function-name check is sufficient
            # without the line-proximity gate (cocci has done the
            # path-dominance work).
            if finding_fn and ab.enclosing_function:
                if ab.enclosing_function == finding_fn:
                    return True

    return False
