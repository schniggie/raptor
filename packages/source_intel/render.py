"""Render :class:`SourceIntelResult` evidence into prompt-friendly
strings for Stage D / `/exploit` / `/agentic` consumers.

The output is a list of human-readable lines; ordering puts the
strongest signal first (literal observations before alias-only).
Consumers concatenate the lines into a structured block under
TaintedString / UntrustedBlock envelopes per the project's prompt-
envelope discipline.

Three styles surfaced in Phase 2:
  * ``stage_d`` — evidence supporting/against a Stage D ruling
  * ``exploit_plan`` — constraints to plan around for /exploit
  * ``agentic_variant`` — seed candidates for variant hunting

For substrate, all three render the same content with style-specific
phrasing. Axes 2-7 may diverge per style when their evidence
classes have distinct interpretations per consumer.
"""

from __future__ import annotations

from typing import List, Optional

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import SourceIntelResult, WurEvidence


_STYLES = ("stage_d", "exploit_plan", "agentic_variant")


def derive_evidence_strings(
    result: SourceIntelResult,
    finding_function: Optional[str] = None,
    build_flags: Optional[BuildFlagsContext] = None,
    style: str = "stage_d",
    max_lines: Optional[int] = None,
) -> List[str]:
    """Render source_intel evidence for a finding into prompt lines.

    Args:
      result: the per-target SourceIntelResult
      finding_function: the function the finding cites (used to filter
        WUR evidence to relevant functions; when None, all observations
        surface)
      build_flags: per-target build-flag context (for compile-enforcement
        interpretation of WUR — `__must_check` is binding only if
        `-Werror=unused-result` was on)
      style: "stage_d" | "exploit_plan" | "agentic_variant" — chooses
        framing. Substrate ships identical content per style; axis-N
        PRs can diverge.
      max_lines: cap the number of returned lines (for context-tight
        prompt budgets); None = no cap.

    Returns an empty list when the result is skipped or carries no
    relevant evidence — consumers can render "no source_intel signal"
    or omit the block entirely.
    """
    if style not in _STYLES:
        raise ValueError(f"unknown style: {style!r} (expected one of {_STYLES})")

    lines: List[str] = []

    if result.is_skipped:
        # Surface the skip reason so consumers know there was no
        # evidence at all — distinct from "evidence ran and found
        # nothing." This is critical: consumers MUST NOT interpret
        # an empty block as "unhardened".
        lines.append(
            f"Source_intel skipped: {result.skipped_reason}. "
            f"No evidence either way."
        )
        return _truncate(lines, max_lines)

    # Filter WUR observations to the finding's function when supplied.
    wur_obs = list(result.wur_functions)
    if finding_function:
        wur_obs = [
            ev for ev in wur_obs
            if ev.function_name == finding_function
        ]
    # Literal observations first, then known-alias.
    wur_obs.sort(key=lambda ev: 0 if ev.match_source == "literal" else 1)

    for ev in wur_obs:
        lines.append(_render_wur_line(ev, build_flags, style))

    # When source_intel ran but found nothing relevant — emit an
    # explicit "no signal" line so the consumer prompt template
    # carries the absence acknowledgement.
    if not lines:
        lines.append(
            "Source_intel ran; no warn_unused_result evidence for "
            f"{finding_function or '<finding function>'}. "
            f"Absence of evidence is NOT evidence of unhardened code."
        )

    return _truncate(lines, max_lines)


# =====================================================================
# Per-evidence-kind line builders
# =====================================================================


def _render_wur_line(
    ev: WurEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """One line of WUR evidence, framed per consumer style.

    The enforcement-status caveat depends on build flags:
      * `-Werror=unused-result` known True → "compile-enforced"
      * `-Werror=unused-result` known False → "author intent only;
        warning was suppressed"
      * None / build_flags absent → "advisory; enforcement depends
        on build flags not in evidence"
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )
    src_text = (
        "literal __attribute__((warn_unused_result))"
        if ev.match_source == "literal"
        else f"known alias `{ev.raw_match}`"
    )

    enforcement = _enforcement_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author intent — must-check contract"
    elif style == "exploit_plan":
        prefix = "Constraint — caller-must-check contract"
    else:  # agentic_variant
        prefix = "Variant hint — must-check signal"

    return (
        f"{prefix}: {fn_text} annotated as warn_unused_result via "
        f"{src_text}. {enforcement}"
    )


def _enforcement_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    """Compose the compile-enforcement caveat from build flag context."""
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "Compile-enforcement status unknown (build flags not in "
            "evidence); advisory only."
        )
    if build_flags.werror_unused_result is True:
        return (
            "Build flags include -Werror=unused-result — "
            "compile-enforced; callers that ignore the return "
            "would not compile."
        )
    if build_flags.werror_unused_result is False:
        return (
            "Build flags include -Wno-error=unused-result — "
            "warning suppressed; advisory only."
        )
    return (
        "Build flags observed but -Werror=unused-result not set; "
        "advisory unless -Werror is added."
    )


# =====================================================================
# Helpers
# =====================================================================


def _truncate(lines: List[str], max_lines: Optional[int]) -> List[str]:
    """Cap line count for tight prompt budgets."""
    if max_lines is None or len(lines) <= max_lines:
        return lines
    return lines[:max_lines]
