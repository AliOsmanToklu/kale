"""Turn a ``software`` observable into a vulnerability database query.

Three spellings are understood:

* ``product@version`` with a product name Kalkan fingerprints (``nginx@1.18.0``): server
  software is mapped to its NVD CPE names, JavaScript libraries to their npm package
  (GitHub's advisories cover them far better than NVD, which has no CPE for Vue.js).
* a CPE 2.3 name with a version (``cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*``): sent to NVD.
* a package URL with a version (``pkg:npm/lodash@4.17.20``): sent to OSV, which covers
  the package ecosystems (npm, PyPI, Maven, Go, crates.io, Packagist, ...).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from kale.core import InvalidInputError

# Kalkan's product keys -> NVD CPE vendor:product. Some products moved vendor over the
# years (nginx -> F5, MySQL -> Oracle), so a product can need more than one name.
# Every name was checked against the NVD CPE dictionary.
CPE_PRODUCTS: dict[str, tuple[str, ...]] = {
    "apache": ("apache:http_server",),
    "drupal": ("drupal:drupal",),
    "exim": ("exim:exim",),
    "iis": ("microsoft:internet_information_services",),
    "joomla": ("joomla:joomla\\!",),
    "mariadb": ("mariadb:mariadb",),
    "mysql": ("oracle:mysql", "mysql:mysql"),
    "nginx": ("f5:nginx", "nginx:nginx"),
    "openssh": ("openbsd:openssh",),
    "openssl": ("openssl:openssl",),
    "php": ("php:php",),
    "proftpd": ("proftpd:proftpd",),
    "tomcat": ("apache:tomcat",),
    "wordpress": ("wordpress:wordpress",),
}
# Kalkan's client-side libraries -> npm package names (looked up in OSV)
NPM_PACKAGES: dict[str, str] = {
    "angularjs": "angular",
    "bootstrap": "bootstrap",
    "jquery": "jquery",
    "vue": "vue",
}

# CPE 2.3 formatted strings escape these characters in attribute values
_CPE_SPECIAL = re.compile(r"([\\!\"#$%&'()*+,/:;<=>?@\[\]^`{|}~])")
# OpenSSH writes "8.2p1"; NVD stores the portable release "p1" as the CPE update field
_OPENSSH_PORTABLE = re.compile(r"^(\d+\.\d+)(p\d+)$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+~-]*$")


@dataclass(frozen=True, slots=True)
class SoftwareQuery:
    display: str  # "nginx 1.18.0"
    cpes: tuple[str, ...] = ()  # NVD queries
    purl: str | None = None  # OSV query


def cpe_escape(value: str) -> str:
    return _CPE_SPECIAL.sub(r"\\\1", value)


def parse_software(value: str) -> SoftwareQuery:
    """Raises ``InvalidInputError`` for values no database can be asked about."""
    text = value.strip()
    if text.startswith("pkg:"):
        return _purl(text)
    if text.lower().startswith("cpe:2.3:"):
        return _cpe(text)
    product, at, version = text.rpartition("@")
    if not at or not product or not version:
        raise InvalidInputError(
            f"software must look like product@version, a CPE 2.3 name or a purl: {value!r}"
        )
    key = product.strip().lower()
    if key not in CPE_PRODUCTS and key not in NPM_PACKAGES:
        known = ", ".join(sorted({*CPE_PRODUCTS, *NPM_PACKAGES}))
        raise InvalidInputError(
            f"no CPE mapping for {product!r} (known: {known}); pass a CPE 2.3 name or a purl"
        )
    version = version.strip()
    if not _VERSION.match(version):
        raise InvalidInputError(f"not a version: {version!r}")
    if key in NPM_PACKAGES:
        return SoftwareQuery(
            display=f"{key} {version}", purl=f"pkg:npm/{NPM_PACKAGES[key]}@{version}"
        )
    return SoftwareQuery(
        display=f"{key} {version}",
        cpes=tuple(_cpe_name(vendor_product, key, version) for vendor_product in CPE_PRODUCTS[key]),
    )


def _cpe_name(vendor_product: str, product: str, version: str) -> str:
    update = "*"
    if product == "openssh" and (match := _OPENSSH_PORTABLE.match(version)):
        version, update = match.groups()
    return f"cpe:2.3:a:{vendor_product}:{cpe_escape(version)}:{update}:*:*:*:*:*:*"


def _cpe(text: str) -> SoftwareQuery:
    # split on colons that are not escaped
    parts = re.split(r"(?<!\\):", text)
    if len(parts) != 13 or parts[2] not in ("a", "o", "h"):
        raise InvalidInputError(f"not a CPE 2.3 formatted string: {text!r}")
    if parts[5] in ("*", "-", ""):
        raise InvalidInputError(f"the CPE name needs a version: {text!r}")
    return SoftwareQuery(display=f"{parts[4]} {parts[5]}", cpes=(text,))


def _purl(text: str) -> SoftwareQuery:
    body = text.split("#", 1)[0].split("?", 1)[0]
    name, at, version = body.rpartition("@")
    if not at or not version or "/" not in name:
        raise InvalidInputError(f"the package URL needs a type, a name and a version: {text!r}")
    return SoftwareQuery(display=f"{name.removeprefix('pkg:')} {version}", purl=text)
