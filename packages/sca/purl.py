"""``/sca purl`` — tiny utility that prints a canonical purl.

Useful as glue for shell scripts: build cache keys, construct
CycloneDX ``bom-ref`` values, or hand the string to other tooling.

    sca purl npm   lodash                                  4.17.21
    sca purl PyPI  django                                  4.2.10
    sca purl Maven org.apache.logging.log4j:log4j-core     2.17.1
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    print(f"pkg:{args.ecosystem.lower()}/{args.name}@{args.version}")
    return 0


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sca purl",
        description="Print a canonical purl for the given dependency coords.",
    )
    p.add_argument("ecosystem",
                   help='ecosystem name (e.g., "npm", "PyPI", "Maven")')
    p.add_argument("name",
                   help='package name (Maven uses "groupId:artifactId")')
    p.add_argument("version", help="exact version")
    return p.parse_args(argv)


if __name__ == "__main__":               # pragma: no cover
    sys.exit(main(sys.argv[1:]))


__all__ = ["main"]
