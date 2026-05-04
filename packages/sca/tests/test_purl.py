"""Tests for ``packages.sca.purl`` (the ``/sca purl`` utility)."""

from __future__ import annotations

import pytest

from packages.sca import purl


def test_npm(capsys) -> None:
    rc = purl.main(["npm", "lodash", "4.17.21"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "pkg:npm/lodash@4.17.21"


def test_pypi_lowercases_ecosystem(capsys) -> None:
    purl.main(["PyPI", "django", "4.2.10"])
    assert capsys.readouterr().out.strip() == "pkg:pypi/django@4.2.10"


def test_maven_with_colon_in_name(capsys) -> None:
    purl.main(["Maven", "org.apache.logging.log4j:log4j-core", "2.17.1"])
    out = capsys.readouterr().out.strip()
    assert out == "pkg:maven/org.apache.logging.log4j:log4j-core@2.17.1"


def test_scoped_npm_package(capsys) -> None:
    purl.main(["npm", "@types/node", "20.10.5"])
    assert capsys.readouterr().out.strip() == "pkg:npm/@types/node@20.10.5"


def test_missing_args_returns_2() -> None:
    with pytest.raises(SystemExit) as exc:
        purl.main(["npm"])
    assert exc.value.code == 2
