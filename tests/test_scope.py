from __future__ import annotations

import pytest

from kale.core import InvalidInputError, Kind, Observable, OutOfScopeError, Scope


def obs(kind: Kind, value: str) -> Observable:
    return Observable(kind=kind, value=value)


def test_parse_accepts_domains_wildcards_networks_and_comments() -> None:
    scope = Scope.parse(
        [
            "# engagement 2026-11",
            "Example.com",
            "*.example.org  # staging",
            "",
            "203.0.113.0/24",
            "2001:db8::1",
        ]
    )
    assert scope.domains == {"example.com", "example.org"}
    assert [str(n) for n in scope.networks] == ["203.0.113.0/24", "2001:db8::1/128"]
    assert not scope.empty
    assert Scope.parse(["# nothing"]).empty


def test_parse_rejects_garbage() -> None:
    with pytest.raises(InvalidInputError, match="invalid scope entry"):
        Scope.parse(["not a domain!"])


# Scope checks need publicly routable addresses: the documentation ranges (203.0.113.0/24,
# 2001:db8::/32) count as reserved. No test sends traffic anywhere.
PUBLIC_V4 = "8.8.8.0/24"


@pytest.mark.parametrize(
    "target",
    [
        obs(Kind.DOMAIN, "example.com"),
        obs(Kind.DOMAIN, "shop.example.com"),
        obs(Kind.URL, "https://WWW.Example.com:8443/login"),
        obs(Kind.IP, "8.8.8.77"),
        obs(Kind.URL, "http://8.8.8.9/"),
    ],
)
def test_targets_inside_scope(target: Observable) -> None:
    Scope.parse(["example.com", PUBLIC_V4]).check(target)


@pytest.mark.parametrize(
    "target",
    [
        obs(Kind.DOMAIN, "evilexample.com"),  # suffix match must stop at a dot
        obs(Kind.DOMAIN, "example.com.attacker.net"),
        obs(Kind.IP, "9.9.9.9"),
        obs(Kind.IP, "2606:4700::1111"),  # IPv6 against an IPv4 network
        obs(Kind.URL, "https://other.org"),
    ],
)
def test_targets_outside_scope(target: Observable) -> None:
    with pytest.raises(OutOfScopeError, match="not in the authorized scope"):
        Scope.parse(["example.com", PUBLIC_V4]).check(target)


def test_documentation_addresses_count_as_reserved() -> None:
    with pytest.raises(OutOfScopeError, match="private or reserved"):
        Scope.parse(["203.0.113.0/24"]).check(obs(Kind.IP, "203.0.113.7"))


def test_private_addresses_need_explicit_permission() -> None:
    target = obs(Kind.IP, "10.0.0.5")
    with pytest.raises(OutOfScopeError, match="private or reserved"):
        Scope.parse(["10.0.0.0/8"]).check(target)
    Scope.parse(["10.0.0.0/8"], allow_private=True).check(target)
    with pytest.raises(OutOfScopeError, match="private or reserved"):
        Scope.parse(["10.0.0.0/8"]).check(obs(Kind.URL, "http://127.0.0.1:8000"))


def test_scope_covers_only_network_targets() -> None:
    with pytest.raises(OutOfScopeError, match="not file"):
        Scope.parse(["example.com"]).check(obs(Kind.FILE, "auth.log"))


def test_url_with_invalid_hostname_is_invalid_input() -> None:
    with pytest.raises(InvalidInputError, match="hostname"):
        Scope.parse(["example.com"]).check(obs(Kind.URL, "https://bad..host/"))


SERVER = Scope.parse(["example.com", "8.8.8.0/24"])


def test_covers_subdomains_and_subnets() -> None:
    assert SERVER.covers("shop.example.com") and SERVER.covers("*.example.com")
    assert SERVER.covers("example.com") and SERVER.covers("8.8.8.128/25")
    assert not SERVER.covers("evilexample.com")
    assert not SERVER.covers("8.8.0.0/16")
    assert not SERVER.covers("2001:4860::/32")


def test_covers_rejects_garbage() -> None:
    with pytest.raises(InvalidInputError, match="invalid scope entry"):
        SERVER.covers("not a domain!")


def test_narrow_lists_every_wider_entry() -> None:
    with pytest.raises(
        InvalidInputError, match=r"not covered by the server scope: example\.com, other\.org"
    ):
        Scope.parse(["shop.example.com"]).narrow(["example.com", "other.org", "shop.example.com"])


def test_narrow_returns_the_requested_scope() -> None:
    assert SERVER.narrow(["shop.example.com"]).domains == {"shop.example.com"}


def test_private_needs_server_permission() -> None:
    with pytest.raises(InvalidInputError, match="private addresses"):
        Scope.parse(["10.0.0.0/8"]).narrow(["10.1.0.0/16"], allow_private=True)
    allowed = Scope.parse(["10.0.0.0/8"], allow_private=True)
    assert allowed.narrow(["10.1.0.0/16"], allow_private=True).allow_private


def test_entries_round_trip() -> None:
    assert SERVER.entries() == ["example.com", "8.8.8.0/24"]
    assert Scope.parse(SERVER.entries()) == SERVER
