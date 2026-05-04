"""End-to-end orchestration for ``/sca``.

Runs the mechanical pipeline:

    discover → parse → join → (canonicalise) ─┬─ OSV
                                              ├─ KEV
                                              ├─ EPSS
                                              └─ build VulnFindings
              hygiene (mechanical only) ──────┘
                                              │
                                              ▼
                                  findings.json + report.md

Public entry: ``run_sca(target, output_dir, options)`` returns a
``RunResult`` with counts and the paths of the artefacts written.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from core.json import JsonCache
from . import SCA_CACHE_ROOT
from .discovery import find_manifests
from .epss import EpssClient
from .findings import build_vuln_findings, write_findings_json
from .hygiene import evaluate as evaluate_hygiene
from core.http import HttpClient
from . import default_client
from .join import join as join_deps
from .kev import KevClient
from .models import (
    Dependency,
    HygieneFinding,
    Manifest,
    VulnFinding,
)
from .osv import OsvClient
from .parsers import parse_manifest
from .reachability import scan as scan_reachability
from .report import render_markdown_report, write_markdown_report
from .sarif import write_sarif
from .sbom import write_sbom_json
from .supply_chain import evaluate as evaluate_supply_chain
from . import suppressions as _suppressions

try:                                       # pragma: no cover — env-dependent
    from core.coverage.record import write_record as _coverage_write_record
    _HAS_COVERAGE = True
except ImportError:
    _HAS_COVERAGE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Options + result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RunOptions:
    """Knobs controlling a ``/sca`` run.

    ``offline`` and ``no_cache`` compose: ``--offline --no-cache`` will
    refuse the network *and* refuse stale cache, so the run reports
    only what it can derive without external data.
    """

    offline: bool = False
    no_cache: bool = False
    cache_root: Optional[Path] = None
    enable_kev: bool = True
    enable_epss: bool = True
    enable_reachability: bool = True
    enable_supply_chain: bool = True
    enable_suppressions: bool = True
    include_commented: bool = False     # surface commented `# pkg==X`
                                         # lines as info-severity findings
    enable_inline_installs: bool = True  # extract pip/apt/yum/dnf/apk
                                         # installs from Dockerfile,
                                         # devcontainer.json, shell scripts
                                         # and GHA workflows
    use_offline_db: bool = False         # route ``--offline`` lookups
                                         # through OsvOfflineDB when set
    offline_db_path: Optional[Path] = None  # location of the sqlite3 DB;
                                         # defaults to ``<cache>/osv.sqlite``
    enable_transitive_expansion: bool = False  # cascade resolver for
                                                # manifests without a
                                                # sibling lockfile.
                                                # ``False`` is the
                                                # in-process / test default
                                                # — engaging the resolver
                                                # spins up the sandbox + a
                                                # real subprocess; tests
                                                # that drive run_sca
                                                # directly opt in
                                                # explicitly. The CLI's
                                                # default-on shape lives
                                                # in cli.py via the
                                                # inverted ``--no-resolve-
                                                # transitive`` flag.
    fallback_registry_metadata: bool = False   # mode (c) — when (b)
                                                # can't run, optionally
                                                # walk registry metadata
                                                # to approximate the
                                                # transitive set.
                                                # Default off because
                                                # approximate findings
                                                # add operator triage
                                                # cost; opt in via
                                                # ``--fallback-registry-metadata``.


@dataclass
class RunResult:
    """Summary of a completed ``/sca`` run."""

    target: Path
    output_dir: Path
    findings_path: Path
    report_path: Path
    sbom_path: Path
    sarif_path: Path
    deps_analysed: int
    vuln_findings: int
    hygiene_findings: int
    supply_chain_findings: int
    suppressed_findings: int
    in_kev: int
    cache_hits: int
    cache_misses: int
    # Per-(ecosystem, project_dir) status for transitive-dep expansion.
    # Empty when expansion was disabled or no manifests qualified.
    # The summary prints a one-line digest; the report's report.md
    # gets the full breakdown.
    transitive_statuses: List = field(default_factory=list)
    transitive_added: int = 0


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_sca(
    target: Path,
    output_dir: Path,
    options: Optional[RunOptions] = None,
    *,
    http: Optional[HttpClient] = None,
    cache: Optional[JsonCache] = None,
) -> RunResult:
    """Execute the mechanical SCA pipeline end-to-end.

    Parameters are explicit rather than read from ``argparse`` so the
    CLI layer is a thin wrapper and tests can drive the pipeline
    directly with stubbed HTTP and isolated caches.
    """
    options = options or RunOptions()
    target = target.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if cache is None:
        cache = JsonCache(root=options.cache_root or SCA_CACHE_ROOT)
    if http is None:
        http = default_client()

    # Apply --no-cache by zeroing TTLs at every client level. This
    # avoids special-casing every caller; a TTL of 0 forces a refetch
    # while still letting fresh in-process state be reused.
    osv_query_ttl = 0 if options.no_cache else 24 * 3600
    osv_vuln_ttl = 0 if options.no_cache else 24 * 3600
    kev_ttl = 0 if options.no_cache else 24 * 3600
    epss_ttl = 0 if options.no_cache else 24 * 3600

    # 1. Discover + parse + join. Per-parser opts are toggled via
    #    module-level setters before walking — the dispatch table
    #    doesn't thread per-call options through itself.
    from .parsers import requirements as _req_parser
    _req_parser.set_include_commented(options.include_commented)
    manifests = find_manifests(target)
    if not options.enable_inline_installs:
        manifests = [m for m in manifests if m.ecosystem != "Inline"]
    raw_deps: List[Dependency] = []
    for m in manifests:
        raw_deps.extend(parse_manifest(m))

    # 1a. Transitive expansion — for manifests without a sibling
    #     lockfile, run the matching cascade resolver in the sandbox
    #     (mode b) to produce a real lockfile and ingest its
    #     transitive set. ``--no-resolve-transitive`` disables b;
    #     ``--fallback-registry-metadata`` enables c (registry-walk
    #     approximation) when b can't run. The new transitives merge
    #     into raw_deps before join so they get OSV-queried alongside
    #     direct deps.
    transitive_statuses: List = []
    if options.enable_transitive_expansion or options.fallback_registry_metadata:
        from .transitive import expand_missing_transitives
        new_transitives, transitive_statuses = expand_missing_transitives(
            manifests, raw_deps,
            http=http, cache=cache,
            enable_resolver=options.enable_transitive_expansion,
            enable_metadata_fallback=options.fallback_registry_metadata,
        )
        if new_transitives:
            logger.info(
                "sca.pipeline: transitive expansion added %d dep(s) "
                "across %d ecosystem(s)",
                len(new_transitives),
                len({d.ecosystem for d in new_transitives}),
            )
            raw_deps.extend(new_transitives)

    joined = join_deps(raw_deps)
    logger.info("sca.pipeline: %d manifests, %d deps after join",
                len(manifests), len(joined))

    # 2. Hygiene (mechanical, no network).
    hygiene_findings = evaluate_hygiene(manifests, joined)

    # 2a. Supply-chain mechanical heuristics (install hooks, typosquat,
    #     project-tree artefacts).
    supply_chain_findings = []
    if options.enable_supply_chain:
        # Construct registry clients for the metadata-driven detectors
        # (recent_publish / maintainer_change / maintainer_account_change).
        # Same offline + cache config as the OSV path.
        from .registries.npm import NpmClient
        from .registries.pypi import PyPIClient
        sc_pypi = PyPIClient(http, cache, offline=options.offline)
        sc_npm = NpmClient(http, cache, offline=options.offline)
        supply_chain_findings = evaluate_supply_chain(
            target, manifests, joined,
            pypi_client=sc_pypi,
            npm_client=sc_npm,
        )

    # 3. Canonical dep set: lockfile-preferred, deduped per (eco, name, ver).
    canonical = select_canonical_for_osv(joined)

    # 4. OSV lookup.
    offline_db = None
    if options.use_offline_db:
        from .osv_offline import OsvOfflineDB
        if options.offline_db_path is not None:
            db_path = options.offline_db_path
        elif options.cache_root is not None:
            db_path = options.cache_root / "osv.sqlite"
        else:
            db_path = SCA_CACHE_ROOT / "osv.sqlite"
        offline_db = OsvOfflineDB(db_path, http=http)
        # Refresh per-ecosystem zips for the ecosystems we discovered.
        ecosystems_in_use = {d.ecosystem for d in canonical}
        offline_db.ensure_fresh(ecosystems_in_use)

    osv_client = OsvClient(
        http, cache,
        offline=options.offline,
        query_ttl=osv_query_ttl, vuln_ttl=osv_vuln_ttl,
        offline_db=offline_db,
    )
    osv_results = osv_client.query_batch(canonical)

    # 5. KEV / EPSS enrichment (best-effort; degrades on failure).
    kev: Optional[KevClient] = None
    epss: Optional[EpssClient] = None
    if options.enable_kev:
        kev = KevClient(http, cache, offline=options.offline,
                        ttl_seconds=kev_ttl)
    if options.enable_epss:
        epss = EpssClient(http, cache, offline=options.offline,
                          ttl_seconds=epss_ttl)

    # 6. Reachability — skip if disabled or when no advisories were
    #    found (saves a tree walk on clean projects). Pass http +
    #    cache + the set of CVE-bearing dep keys so the orchestrator
    #    can engage tier-3 wheel-metadata fetch for PyPI deps that
    #    came up not_reachable from the static curated map / PEP 503
    #    heuristic — but only for the specific deps that have an
    #    advisory matched against them.
    reachability_map = None
    if options.enable_reachability and any(r.advisories for r in osv_results):
        cve_dep_keys = {
            r.dep_key for r in osv_results if r.advisories
        }
        reachability_map = scan_reachability(
            target, canonical,
            http=http, cache=cache, cve_dep_keys=cve_dep_keys,
        )
        # Augment with /understand context-map when present — promotes
        # ``imported`` to ``likely_called`` for deps imported at sink
        # sites and bumps confidence on entry-point / boundary matches.
        from .understand_bridge import annotate_all, load_context_map
        ctx = load_context_map(target, run_dir=output_dir)
        if ctx is not None:
            reachability_map = annotate_all(reachability_map, ctx)
            logger.info("sca.pipeline: /understand context-map "
                         "augmented %d reachability verdicts",
                         len(reachability_map))

    # 7. Build VulnFindings.
    vuln_findings = build_vuln_findings(
        canonical, osv_results, kev=kev, epss=epss,
        reachability=reachability_map,
    )

    # 7a. Apply operator suppression overlay (`.raptor-sca-suppress.yml`).
    suppressed_total = 0
    if options.enable_suppressions:
        entries = _suppressions.load(target / _suppressions.SUPPRESS_FILENAME)
        if entries:
            suppressed_total = (
                _suppressions.apply_to_findings(vuln_findings, entries)
                + _suppressions.apply_to_findings(hygiene_findings, entries)
                + _suppressions.apply_to_findings(supply_chain_findings, entries)
            )
            logger.info(
                "sca.pipeline: %d finding(s) suppressed by %s",
                suppressed_total, _suppressions.SUPPRESS_FILENAME,
            )

    # 8. Write artefacts.
    findings_path = output_dir / "findings.json"
    report_path = output_dir / "report.md"
    write_findings_json(
        findings_path,
        vuln_findings=vuln_findings,
        hygiene_findings=hygiene_findings,
        supply_chain_findings=supply_chain_findings,
    )
    md = render_markdown_report(
        target=target,
        deps_analysed=len(joined),
        vuln_findings=vuln_findings,
        hygiene_findings=hygiene_findings,
        supply_chain_findings=supply_chain_findings,
        cache_hits=cache.hits,
        cache_misses=cache.misses,
    )
    write_markdown_report(report_path, md)

    sbom_path = output_dir / "sbom.cdx.json"
    write_sbom_json(
        sbom_path,
        deps=joined,
        vuln_findings=vuln_findings,
        target_name=target.name,
    )

    # Re-read the rows we just wrote — SARIF emission consumes the
    # canonical row shape, including the suppression overlay.
    import json as _json_mod
    rows = _json_mod.loads(findings_path.read_text(encoding="utf-8"))
    sarif_path = output_dir / "findings.sarif"
    write_sarif(sarif_path, target=target, rows=rows)

    # 9. Best-effort coverage record: files examined = manifests +
    #    reachability evidence (sources that genuinely informed verdicts).
    _maybe_write_coverage(output_dir, target, manifests, vuln_findings)

    return RunResult(
        target=target,
        output_dir=output_dir,
        findings_path=findings_path,
        report_path=report_path,
        sbom_path=sbom_path,
        sarif_path=sarif_path,
        deps_analysed=len(joined),
        vuln_findings=len(vuln_findings),
        hygiene_findings=len(hygiene_findings),
        supply_chain_findings=len(supply_chain_findings),
        suppressed_findings=suppressed_total,
        transitive_statuses=transitive_statuses,
        transitive_added=sum(s.deps_added for s in transitive_statuses),
        in_kev=sum(1 for f in vuln_findings
                   if f.in_kev and not f.suppressed),
        cache_hits=cache.hits,
        cache_misses=cache.misses,
    )


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------

def _maybe_write_coverage(
    output_dir: Path,
    target: Path,
    manifests: List[Manifest],
    vuln_findings: List[VulnFinding],
) -> None:
    """Emit ``coverage-sca.json`` listing every file that materially
    influenced the run. Best-effort: missing core.coverage module is fine.
    """
    if not _HAS_COVERAGE:
        return
    from datetime import datetime, timezone

    files: set[str] = set()
    for m in manifests:
        files.add(_relpath(m.path, target))
    for f in vuln_findings:
        for evidence in f.reachability.evidence:
            # Evidence lines look like ``src/x.py:10`` or with a
            # ``[test]`` tag — strip both before recording.
            head = evidence.split(":", 1)[0].split(" ", 1)[0]
            if head:
                files.add(head)
    if not files:
        return
    record = {
        "tool": "sca",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }
    try:
        _coverage_write_record(output_dir, record, tool_name="sca")
    except Exception:                      # noqa: BLE001
        logger.debug(
            "sca.pipeline: coverage record write failed", exc_info=True,
        )


def _relpath(path: Path, target: Path) -> str:
    try:
        return str(path.relative_to(target))
    except ValueError:
        return str(path)


def select_canonical_for_osv(
    deps: Iterable[Dependency],
) -> List[Dependency]:
    """Pick the most authoritative dep row per ``(ecosystem, name, version)``.

    Rules:
    - Lockfile rows are preferred over manifest rows: the resolved
      version is what's actually installed.
    - When multiple lockfile rows exist with *different* versions for
      the same ``(ecosystem, name)`` (e.g., npm hoists multiple copies),
      keep both — they're independent installs.
    - When only manifest rows exist for a name, keep them with their
      declared version (best-effort; loose pins may produce false
      positives, callers should treat those as candidates).
    - Rows without a usable version are dropped — OSV needs a concrete
      version string to match.

    Output preserves first-seen order for stable test output.
    """
    by_name: dict[tuple[str, str], List[Dependency]] = defaultdict(list)
    order: List[tuple[str, str]] = []
    for d in deps:
        key = (d.ecosystem, d.name)
        if key not in by_name:
            order.append(key)
        by_name[key].append(d)

    out: List[Dependency] = []
    seen_versions: set[tuple[str, str, str]] = set()
    for key in order:
        rows = by_name[key]
        lockfile_versions = [r for r in rows
                             if r.is_lockfile and r.version is not None]
        if lockfile_versions:
            for r in lockfile_versions:
                triple = (key[0], key[1], r.version or "")
                if triple in seen_versions:
                    continue
                seen_versions.add(triple)
                out.append(r)
            continue
        manifest_versions = [r for r in rows
                             if not r.is_lockfile and r.version is not None]
        if manifest_versions:
            r = manifest_versions[0]
            triple = (key[0], key[1], r.version or "")
            if triple not in seen_versions:
                seen_versions.add(triple)
                out.append(r)
    return out


__all__ = ["RunOptions", "RunResult", "run_sca", "select_canonical_for_osv"]
