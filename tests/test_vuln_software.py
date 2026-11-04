from __future__ import annotations

import pytest

from kale.core import InvalidInputError, Severity
from kale.modules.vuln.module import prioritize
from kale.modules.vuln.software import CPE_PRODUCTS, NPM_PACKAGES, cpe_escape, parse_software
from kale.modules.vuln.sources import Epss, KevEntry, Vulnerability


@pytest.mark.parametrize(
    ("value", "cpes"),
    [
        (
            "nginx@1.18.0",
            (
                "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            ),
        ),
        ("PHP@7.4.3", ("cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*",)),
        ("openssh@8.2p1", ("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*",)),
        ("openssh@9.6", ("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",)),
        ("joomla@3.9.0", ("cpe:2.3:a:joomla:joomla\\!:3.9.0:*:*:*:*:*:*:*",)),
        ("openssl@1.1.1k", ("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",)),
    ],
)
def test_kalkan_products_become_cpe_names(value: str, cpes: tuple[str, ...]) -> None:
    query = parse_software(value)
    assert query.cpes == cpes
    assert query.purl is None


@pytest.mark.parametrize(
    ("value", "purl"),
    [
        ("jquery@1.12.4", "pkg:npm/jquery@1.12.4"),
        ("angularjs@1.5.8", "pkg:npm/angular@1.5.8"),
        ("vue@2.6.14", "pkg:npm/vue@2.6.14"),
    ],
)
def test_javascript_libraries_go_to_osv(value: str, purl: str) -> None:
    query = parse_software(value)
    assert query.purl == purl
    assert query.cpes == ()


def test_every_kalkan_product_is_mapped() -> None:
    from kalkan.scanner.softwaredb import SoftwareDatabase

    database = SoftwareDatabase.bundled()
    assert set(database.products) <= {*CPE_PRODUCTS, *NPM_PACKAGES}


def test_explicit_cpe_and_purl() -> None:
    cpe = "cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*"
    assert parse_software(cpe).cpes == (cpe,)
    assert parse_software(cpe).display == "nginx 1.20.1"
    query = parse_software("pkg:npm/lodash@4.17.20")
    assert query.purl == "pkg:npm/lodash@4.17.20"
    assert query.display == "npm/lodash 4.17.20"
    assert parse_software("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar").purl


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("nginx", "product@version"),
        ("@1.0", "product@version"),
        ("frobnicator@1.0", "no CPE mapping for 'frobnicator'"),
        ("nginx@1.0 beta", "not a version"),
        ("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "needs a version"),
        ("cpe:2.3:a:f5:nginx", "not a CPE 2.3"),
        ("pkg:npm/lodash", "needs a type, a name and a version"),
        ("pkg:lodash@1.0", "needs a type, a name and a version"),
    ],
)
def test_unusable_values(value: str, message: str) -> None:
    with pytest.raises(InvalidInputError, match=message):
        parse_software(value)


def test_cpe_escape() -> None:
    assert cpe_escape("1.0:beta") == "1.0\\:beta"
    assert cpe_escape("2.4.41") == "2.4.41"


def vuln(score: float | None = None, severity: str | None = None) -> Vulnerability:
    return Vulnerability(
        id="CVE-2021-23017",
        summary="s",
        source="nvd",
        link="l",
        cvss_score=score,
        cvss_version="3.1" if score is not None else None,
        severity=severity,
    )


KEV = KevEntry("2021-12-10", True, "Apply updates.", "2021-12-24", "Log4j")


@pytest.mark.parametrize(
    ("vulnerability", "kev", "epss", "priority", "reason"),
    [
        (
            vuln(5.0),
            KEV,
            None,
            Severity.CRITICAL,
            "Known Exploited Vulnerabilities catalog since 2021-12-10, used in ransomware",
        ),
        (vuln(5.0), None, Epss(0.42, 0.99), Severity.HIGH, "EPSS 42%"),
        (vuln(9.8), None, Epss(0.01, 0.5), Severity.HIGH, "CVSS 3.1 9.8"),
        (vuln(7.5), None, None, Severity.MEDIUM, "CVSS 3.1 7.5"),
        (vuln(5.3), None, None, Severity.LOW, "CVSS 3.1 5.3"),
        (vuln(severity="CRITICAL"), None, None, Severity.HIGH, "Rated critical"),
        (vuln(severity="HIGH"), None, None, Severity.MEDIUM, "Rated high"),
        (vuln(severity="MEDIUM"), None, None, Severity.LOW, "Rated medium"),
        (vuln(), None, None, Severity.LOW, "No score"),
    ],
)
def test_priority_policy(
    vulnerability: Vulnerability,
    kev: KevEntry | None,
    epss: Epss | None,
    priority: Severity,
    reason: str,
) -> None:
    got, why = prioritize(vulnerability, kev, epss)
    assert got is priority
    assert reason in why


def test_cvss_alone_never_makes_a_vulnerability_critical() -> None:
    assert prioritize(vuln(10.0), None, None)[0] is Severity.HIGH
