"""RAPTOR SCA Package — Software Composition Analysis.

Houses the SCA-specific config that the rest of the package threads
into otherwise-generic ``core.http`` / ``core.json.cache`` machinery:

  - :data:`SCA_USER_AGENT` — pinned user-agent so /sca traffic is
    identifiable in OSV / KEV / EPSS rate-limit logs.
  - :data:`SCA_CACHE_ROOT` — default disk-cache root under
    ``~/.raptor/cache/sca/``. Callers thread this as the explicit
    fallback when the operator passes ``--cache-root`` as None.
  - :data:`SCA_ALLOWED_HOSTS` — the full set of registries / vuln
    feeds /sca needs to reach. Anything outside this set is refused
    by the in-process egress proxy: a parser or registry-client
    compromise can't exfiltrate beyond the hosts the operator
    already implicitly trusts (they're how the project's deps were
    installed in the first place). Adding a new registry client
    requires adding its host here.
  - :func:`default_client` — single seam where the HTTP backend is
    chosen. Always returns an :class:`~core.http.egress_backend.EgressClient`
    routed through ``core.sandbox.proxy`` with the allowlist above.
"""

from __future__ import annotations

from pathlib import Path

from core.http import HttpClient
from core.http.egress_backend import EgressClient

SCA_USER_AGENT = "raptor-sca/0.1 (+https://github.com/gadievron/raptor)"
SCA_CACHE_ROOT = Path.home() / ".raptor" / "cache" / "sca"

# The full set of hosts /sca needs to reach for vuln data + registry
# metadata. Ordered by purpose for readability; the egress proxy treats
# the set as flat. Every host appears verbatim in at least one client's
# URL constant under packages/sca/{osv,kev,epss}.py or
# packages/sca/registries/.
SCA_ALLOWED_HOSTS = (
    # Vulnerability feeds
    "api.osv.dev",
    "osv-vulnerabilities.storage.googleapis.com",   # OSV offline-DB zip mirror
    "www.cisa.gov",                                 # KEV feed
    "api.first.org",                                # EPSS scores
    # NVD — pre-fix this was missing from the allowlist
    # despite being a primary CVE-data source consumed by
    # the SCA verification path (see packages/nvd/client.py).
    # SCA runs that depended on NVD lookups (cve_diff oracle,
    # NVD-only CVEs not in OSV) silently returned no data
    # because the sandbox blocked the egress; operators saw
    # empty NVD sections in reports without diagnostic
    # explanation.
    "services.nvd.nist.gov",
    # Registry metadata (harden / typosquat / supply-chain heuristics)
    "pypi.org",
    "registry.npmjs.org",
    "crates.io",
    "rubygems.org",
    "proxy.golang.org",
    "search.maven.org",
    "repo.packagist.org",
    "api.nuget.org",
    "sources.debian.org",
    "formulae.brew.sh",
    # GHSA — GitHub's security advisory feed; not the same
    # data as OSV's GHSA mirror (slight latency + occasional
    # advisories that GitHub publishes before OSV ingests).
    "raw.githubusercontent.com",
    # Source-archive downloads (version-diff review + wheel-metadata fallback)
    "files.pythonhosted.org",                       # PyPI sdist/wheel archives
    "static.crates.io",                             # Cargo crate tarballs
    "sum.golang.org",                               # Go module checksums
    "repo.maven.apache.org",                        # Maven/Gradle source jars
    "repo1.maven.org",                              # Maven Central mirror
    "api.github.com",                               # GHA ref→SHA resolution
)


def default_client() -> HttpClient:
    """Return the default HttpClient for /sca.

    Always routes through the in-process egress proxy at
    :mod:`core.sandbox.proxy` with :data:`SCA_ALLOWED_HOSTS` enforced
    by the proxy. The proxy is a process-wide singleton with UNION
    semantics on the allowlist — multiple subsystems calling this
    function (or constructing their own EgressClients) all share the
    same proxy and the same allowlist union.

    Tests bypass this seam by injecting an HttpClient directly via
    dependency injection (``run_sca(..., http=StubHttp(...))``); they
    never trigger proxy startup.
    """
    return EgressClient(SCA_ALLOWED_HOSTS, user_agent=SCA_USER_AGENT)


__all__ = [
    "SCA_ALLOWED_HOSTS",
    "SCA_CACHE_ROOT",
    "SCA_USER_AGENT",
    "default_client",
]
