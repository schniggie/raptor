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
from typing import Optional

from core.dataflow.finding import Finding
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.analyze import SourceIntelResult, analyze
from packages.source_intel.cache import SourceIntelCache

logger = logging.getLogger(__name__)


# CWE classes where source_intel axis 1 (warn_unused_result) gives a
# meaningful verdict signal. Other CWEs surface evidence via the
# render module but don't drive verdict.
_WUR_RELEVANT_RULE_PREFIXES = (
    "cpp/null-dereference",
    "cpp/uncontrolled-",        # uncontrolled-allocation-size, etc.
    "cpp/unchecked-return",
    "cpp/unbounded-write",
    "c/null-dereference",
)


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
        """Apply the Phase 2 verdict policy."""
        if result.is_skipped:
            return ValidatorVerdict.UNCERTAIN

        if not _rule_id_is_wur_relevant(finding.rule_id):
            return ValidatorVerdict.UNCERTAIN

        # Match the finding's function to a WUR observation, if any.
        # Phase 2 finding records don't carry an explicit `function`
        # field — we derive it from the source step's snippet via
        # the simplest possible heuristic: scan the snippet for any
        # observed WUR function name.
        snippet = (finding.source.snippet or "") + " " + (finding.sink.snippet or "")
        for ev in result.wur_functions:
            if ev.function_name and ev.function_name in snippet:
                return ValidatorVerdict.EXPLOITABLE

        return ValidatorVerdict.UNCERTAIN


def _rule_id_is_wur_relevant(rule_id: str) -> bool:
    """Check whether a finding's rule_id is in the WUR-relevant set."""
    return any(rule_id.startswith(prefix)
               for prefix in _WUR_RELEVANT_RULE_PREFIXES)
