from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from collections.abc import Callable, Iterable


AddressResolver = Callable[[str, int], Iterable[str]]
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)


class PublicWebUrlError(ValueError):
    """Raised when a URL is not safe for public-web retrieval."""


class PublicWebUrlPolicy:
    """Require HTTP(S) URLs whose host resolves exclusively to public addresses."""

    def __init__(self, resolver: AddressResolver | None = None):
        self._resolver = resolver or _resolve_addresses

    def validate(self, url: str) -> str:
        rejection = self.rejection_reason(url)
        if rejection:
            raise PublicWebUrlError(rejection)
        return url

    def rejection_reason(self, url: object) -> str | None:
        """Return a printable rejection reason without raising for untrusted URLs."""
        if not isinstance(url, str):
            return "public-web URL must be a string"
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port
            hostname = parsed.hostname
            username = parsed.username
            password = parsed.password
        except (TypeError, UnicodeError, ValueError) as exc:
            detail = str(exc).strip()
            return f"invalid public-web URL: {detail}" if detail else "invalid public-web URL"
        if parsed.scheme.casefold() not in {"http", "https"}:
            return "public-web URL must use HTTP or HTTPS"
        if not hostname:
            return "public-web URL requires a host"
        if username is not None or password is not None:
            return "public-web URL must not contain credentials"

        hostname = hostname.rstrip(".").casefold()
        if hostname == "localhost" or hostname.endswith(".localhost"):
            return "public-web URL must not target localhost"
        addresses, address_error = _literal_or_resolved_addresses(
            hostname,
            port or (443 if parsed.scheme.casefold() == "https" else 80),
            self._resolver,
        )
        if address_error:
            return address_error
        if not addresses:
            return "public-web host resolved to no addresses"
        blocked = sorted(str(address) for address in addresses if not address.is_global)
        if blocked:
            return f"public-web host resolved to a non-public address: {', '.join(blocked)}"
        return None


def _literal_or_resolved_addresses(
    hostname: str,
    port: int,
    resolver: AddressResolver,
) -> tuple[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...], str | None]:
    literal, literal_error = _parse_address_literal(hostname)
    if literal_error:
        return (), literal_error
    if literal is not None:
        return (literal,), None
    if not _is_dns_hostname(hostname):
        return (), "public-web URL has an invalid hostname"
    try:
        values = resolver(hostname, port)
    except OSError as exc:
        detail = str(exc).strip()
        suffix = f": {detail}" if detail else ""
        return (), f"public-web host could not be resolved safely ({type(exc).__name__}){suffix}"
    try:
        addresses = tuple(dict.fromkeys(ipaddress.ip_address(value) for value in values))
    except ValueError:
        return (), "public-web resolver returned an invalid address"
    return addresses, None


def _parse_address_literal(
    hostname: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | None, str | None]:
    parts = hostname.split(".")
    if len(parts) == 4 and all(part.isascii() and part.isdecimal() for part in parts):
        if any(len(part) > 1 and part.startswith("0") for part in parts):
            return None, "public-web URL contains an ambiguous IPv4 address"
        octets = tuple(int(part) for part in parts)
        if any(value > 255 for value in octets):
            return None, "public-web URL contains an invalid IPv4 address"
        return ipaddress.IPv4Address(bytes(octets)), None
    if ":" in hostname:
        try:
            return ipaddress.IPv6Address(hostname), None
        except ValueError:
            return None, "public-web URL contains an invalid IPv6 address"
    return None, None


def _is_dns_hostname(hostname: str) -> bool:
    if not hostname.isascii() or len(hostname) > 253:
        return False
    labels = hostname.split(".")
    return all(_DNS_LABEL.fullmatch(label) for label in labels)


def _resolve_addresses(hostname: str, port: int) -> tuple[str, ...]:
    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(str(record[4][0]) for record in records))
