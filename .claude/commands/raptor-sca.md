---
description: Software Composition Analysis — find vulnerable dependencies, gate CI, plan upgrades
---

# RAPTOR Software Composition Analysis

You are helping the user analyse a project's third-party dependencies for known vulnerabilities, supply-chain red flags, and hygiene issues.

## Your task

1. **Identify the target**: Ask which directory/repository to scan if not specified.

2. **Pick the right sub-command**:
   - **Default — analyse the whole project**: `libexec/raptor-sca <target>`
     Walks every manifest+lockfile, queries OSV/KEV/EPSS, runs reachability + supply-chain + hygiene checks, emits `findings.json`, `report.md`, and `sbom.cdx.json`.
   - **Pre-add evaluation of one package**: `libexec/raptor-sca review <ecosystem> <name> <version>`
     Quick verdict (Clean / Review / Block) before `npm install` / `pip install`.
   - **Forward-looking upgrade impact**: `libexec/raptor-sca whatif <ecosystem> <name> <from> <to>`
     What an upgrade resolves vs introduces; supports `--candidate` for multi-target tables.
   - **Auto-generate upgrade patches**: `libexec/raptor-sca update --findings <out>/findings.json [--allow-major]`
     Reads a previous run's findings and writes a `proposed/` directory of rewritten manifests.
   - **CI / pre-commit gate**: `libexec/raptor-sca-gate <target> --severity high --fail-on-kev`
     Mechanical-only fast path; exits 0/1 by threshold for build hooks.

3. **Analyse results**:
   - Read `<out>/report.md` for a human-readable severity-sorted view.
   - For tooling, parse `<out>/findings.json` (canonical schema, tagged `sca:vulnerable_dependency` / `sca:hygiene:<kind>` / `sca:supply_chain:<kind>`).
   - For SBOM consumers, read `<out>/sbom.cdx.json` (CycloneDX 1.5 with VEX block).
   - Surface critical and KEV-listed CVEs first; the report orders them that way.

4. **Help apply fixes**:
   - Run `update` to generate `proposed/` rewrites.
   - Show the diff (`git diff proposed/`) so the operator can review before applying.
   - Note which deps got skipped and why (Maven property references, npm git URLs, etc.).

## Example commands

Full analyse:
```bash
libexec/raptor-sca /path/to/project
```

CI gate that fails on any KEV-listed CVE or high-severity finding:
```bash
libexec/raptor-sca-gate /path/to/project --severity high --fail-on-kev
```

Pre-add review:
```bash
libexec/raptor-sca review npm lodash 4.17.21
libexec/raptor-sca review PyPI django 4.2.10
libexec/raptor-sca review Maven org.springframework:spring-core 6.1.0
```

Upgrade impact comparison:
```bash
libexec/raptor-sca whatif npm lodash 4.17.4 4.17.21
libexec/raptor-sca whatif npm lodash 4.17.4 \
    --candidate 4.17.10 --candidate 4.17.21 --candidate 4.18.0
```

Plan upgrades from a previous run:
```bash
libexec/raptor-sca /path/to/project --out /tmp/sca-run
libexec/raptor-sca update --findings /tmp/sca-run/findings.json \
    --out /tmp/sca-update --allow-major
git diff --no-index /path/to/project /tmp/sca-update/proposed
```

Offline mode (cache only — useful in CI when egress is restricted):
```bash
libexec/raptor-sca /path/to/project --offline
```

## Outputs

| File | Shape | Consumer |
|---|---|---|
| `findings.json` | List of findings (canonical schema) | other RAPTOR tools, CI |
| `report.md` | Severity-sorted markdown | humans |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | Dependency-Track, CycloneDX CLI |
| `coverage-sca.json` | Files examined | RAPTOR coverage layer |
| `proposed/` (update) | Rewritten manifests | operator review then `git apply` |
| `changes.json` / `changes.md` (update) | Per-change record | review |

## Important notes

- Always use absolute paths for the target.
- 10 manifest/lockfile formats supported: `pom.xml`, `build.gradle`, `gradle.lockfile`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`.
- 8 ecosystems queried via OSV: Maven / npm / PyPI / Cargo / Go / RubyGems / NuGet / Packagist.
- KEV (CISA known-exploited) and EPSS (FIRST.org probability) are always checked when network is available; both degrade gracefully on outage.
- Reachability is **module-level** (Python AST + npm import sweep) — flags whether the dep is imported in non-test code, not whether the vulnerable function is called.
- All optional dependencies (`defusedxml`, `packaging`, `tomli` on 3.10-, `PyYAML`) degrade gracefully — missing one only narrows ecosystem coverage.

## Exit codes

- Analyse / sub-commands: 0 success, 2 invalid args, 3 internal error.
- Gate (`raptor-sca-gate`): 0 below threshold, 1 above threshold (build-fail).
- Review: 0 clean, 1 review-needed, 2 block.
- Whatif: 0 net-positive trade, 1 mixed/regression.
