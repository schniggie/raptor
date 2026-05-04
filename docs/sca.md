# /sca — Software Composition Analysis

Mechanical-tier dep scanner: extract every dep from a project, match against OSV / KEV / EPSS, surface hygiene + supply-chain heuristics, propose hardening patches.

## Quick start

```bash
# Full analysis: produces findings.json, report.md, sbom.cdx.json, findings.sarif
libexec/raptor-sca /path/to/project

# Pin every loose dep to the latest safe version
libexec/raptor-sca harden /path/to/project --git-patch
cd /path/to/project && git apply <out-dir>/upgrade.patch

# CI gate: exit 1 if any dep could be hardened
libexec/raptor-sca harden /path/to/project --check
```

## Sub-commands

| Sub-command | Purpose |
|---|---|
| `analyse` (default) | Walk the target, match every dep against OSV/KEV/EPSS, write findings.json + report.md + sbom.cdx.json + findings.sarif |
| `harden` | Pin loose deps to the latest *safe* version; KEV / CVSS / EPSS-aware ranking |
| `update` | Reactive: bump only deps that have a current CVE finding |
| `whatif` | "What would change if I bumped X to Y?" |
| `review` | Single-dep lookup |
| `diff` | Compare two findings.json files |
| `verify` | Round-trip check on a findings file |
| `render` | Re-render a findings file as report.md |
| `purl` | Build a purl from `(ecosystem, name, version)` |
| `health` | Probe every registry client; report reachability |

## What gets scanned

**Manifests + lockfiles** (parsed by `parsers/`):

- Python: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `setup.py`, `setup.cfg`
- Node.js: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `shrinkwrap.json`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`
- Rust: `Cargo.toml`, `Cargo.lock`
- Go: `go.mod`, `go.sum`
- Ruby: `Gemfile`, `Gemfile.lock`
- .NET: `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json`
- PHP: `composer.json`, `composer.lock`

**Inline-install sources** (parsed by `parsers/inline_installs.py`):

- `Dockerfile`, `Containerfile`, `Dockerfile.<x>`, `*.dockerfile`
- `devcontainer.json` / `.devcontainer.json` — `postCreateCommand` / `onCreateCommand` / etc.
- `*.sh`, `*.bash`
- `.github/workflows/*.yml` — `run:` block bodies

Recognised commands across all four shapes:
`pip` / `pipx` / `uv pip` / `apt` / `apt-get` / `yum` / `dnf` / `apk` / `npm` / `npx` / `bunx` / `yarn` / `pnpm` / `cargo install` / `gem install` / `brew install` / `go install` / `dotnet add package` / `nuget install` / `Install-Package` / `composer require`.

## Output artefacts

Every analyse run produces:

| File | Format | Audience |
|---|---|---|
| `findings.json` | RAPTOR findings schema | other RAPTOR commands (`/validate`, `/patch`) |
| `report.md` | human-readable | operators |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | SBOM consumers, dependency-track, etc. |
| `findings.sarif` | SARIF 2.1.0 | GitHub / GitLab / IDE integrations |

`harden` adds:

| File | Format | Audience |
|---|---|---|
| `candidates.json` | structured plan | `--self-test` + a future LLM impact-analysis tier (LLM impact analysis) |
| `report.md` | human-readable | operators |
| `proposed/` | rewritten manifest copies | `git apply` source |
| `upgrade.patch` | git-applyable unified diff | operator / CI |

## Data sources

| Source | Use | Cache |
|---|---|---|
| OSV.dev (`/v1/query`, `/v1/vulns/<id>`) | advisory + affected ranges | 24h disk |
| CISA KEV catalogue | known-exploited filter | 24h disk |
| FIRST.org EPSS | exploitation probability | 24h disk |
| Per-ecosystem registries | version listing for harden | 24h disk |

Registries supported by harden: PyPI, npm, crates.io, RubyGems, Go (proxy.golang.org), Maven Central, Packagist, NuGet, Debian Sources, Homebrew. Run `sca health` to probe all ten in one shot.

## Common flags

### analyse

```
--include-commented       parse `# pkg==X` lines as deps (info severity)
--no-inline-installs      skip Dockerfile/sh/GHA inline install extraction
--no-supply-chain         skip mechanical supply-chain heuristics
--no-reachability         skip module-level reachability scan
--no-kev / --no-epss      skip the named enrichment
--offline                 skip network; cache-only
```

### harden

```
--allow-major             bump deps that cross a major-version boundary
--allow-major-without-review  apply major bumps without LLM review (dangerous)
--allow-degraded          apply best-effort candidates (residual advisories)
--pin-only                only bump already-exact-pinned deps; don't tighten loose pins
--ecosystems PyPI,npm     allowlist; other ecosystems planned but not patched
--check                   exit 0 if no actionable candidates, 1 otherwise (CI gate)
--git-patch               write upgrade.patch
--apply                   apply the patch directly via `git apply` (refuses if not a git repo)
--self-test               apply to a temp clone, re-plan, assert idempotency
--offline                 cache-only
```

## Status semantics

`harden` classifies each candidate into one of:

| Status | Meaning |
|---|---|
| `promoted` | clean upgrade; goes into the patch by default |
| `degraded_safety` | no fully-clean version exists; picked the least-worst by `(any_in_kev, max_severity, max_epss, count)` — gated behind `--allow-degraded` |
| `up_to_date` | dep is already at the latest safe in its range |
| `review_required` | bump exists but crosses a major boundary; gated behind `--allow-major-without-review` (or wait for LLM impact analysis — a future LLM impact-analysis tier) |
| `skipped_loose_pin` | `--pin-only` set + dep is `>=`/`^`/`~` pinned |
| `unsupported_manifest` | the file shape has no rewriter (rare today; only go.mod, Cargo.toml-like cases) |
| `no_versions` | registry returned no versions (404 or genuinely unknown package) |
| `registry_unsupported` | ecosystem has no registry client yet |
| `needs_network` | `--offline` and no cached versions |

## Severity-aware ranking (degraded_safety)

When no fully-clean version exists, harden picks the *least worst* candidate by these keys, in priority order:

1. **`any_in_kev`** — KEV-listed advisories are actively exploited; their presence outranks every other signal.
2. **`max_severity`** — highest CVSS severity ordinal (none/low/medium/high/critical) across the candidate's residual advisories.
3. **`max_epss`** — exploitation probability per FIRST.org. Within the same severity tier, lower EPSS wins.
4. **Advisory count** — fewer is better.
5. **Newest** — input order; final tiebreaker.

A version with one critical RCE outranks a version with three mediums. A version with a KEV-listed CVE outranks any non-KEV candidate regardless of CVSS / EPSS.

## CI patterns

### Hard gate: no actionable hardening

```yaml
- run: libexec/raptor-sca harden $PROJECT --check --ecosystems PyPI,npm
  # exits 1 if any PyPI/npm dep could be bumped
```

### Soft gate: track over time

```yaml
- run: |
    libexec/raptor-sca $PROJECT --out before-${{github.sha}}
    libexec/raptor-sca harden $PROJECT --apply
    libexec/raptor-sca $PROJECT --out after-${{github.sha}}
    libexec/raptor-sca diff before-*/findings.json after-*/findings.json
```

### Pre-flight: registries reachable

```yaml
- run: libexec/raptor-sca health
  # exits 1 if any registry is unreachable; useful behind a corporate proxy
```

## Limitations + follow-ups

- **No LLM tier (Tier B)** — typosquat-by-extrapolation, postinstall LLM review, maintainer-trust review, and upgrade impact analysis are deferred to Follow-ups #6 (inline-install LLM review) and #7 (upgrade impact analysis).
- **Sandboxing** — registry HTTP calls go through `packages/sca/http.py` directly today. The sandbox seam will be retrofitted once `core/sandbox/` lands.
- **Recent-publish + maintainer-change supply-chain checks** — need extra registry metadata (publish dates, maintainer lists). Deferred until sandbox lands.
- **Variable-expanded inline installs** (`PKG="x=1"; apt install $PKG`) — would need a mini shell interpreter; deferred to a future LLM tier.
- **`update --apply`** — `update` outputs a patch but doesn't auto-apply (unlike `harden`). Would mirror harden's flag.
- **Maven `mvn install:install-file`** — not yet rewritable; rare in inline contexts.
