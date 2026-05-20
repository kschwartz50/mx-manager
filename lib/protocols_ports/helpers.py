"""Normalization helpers for the MX protocols-ports slice.

This module is the single source of truth for Junos CLI vocabulary that
maps protocol names, service port names, and ICMP type/code names to their
numeric equivalents.  It intentionally has **no dependencies on any other
lib module** so that it can be imported freely by parsers, factories, and
the firewall slice without creating circular imports.

Public API
----------
ProtocolMap     — IP protocol name ↔ number lookups
PortMap         — Well-known service port name ↔ number lookups
IcmpTypeMap     — ICMP type name ↔ number lookups
IcmpCodeMap     — ICMP code name ↔ number lookups (type-agnostic; code
                  names used by Junos are unique enough in practice)

normalize_protocol(token)   — given "tcp" or "6", returns a NormalizedProtocol
normalize_port_token(token) — given "ssh", "443", "10000-19999", returns a
                              NormalizedPort

Design notes
------------
- All lookups are case-insensitive (tokens are lowercased before lookup).
- Unknown tokens do not raise exceptions; they return ``None`` or leave
  fields unpopulated so the caller can emit a warning and continue.
- Note: VRRP is IANA protocol 112.  The SRX helpers incorrectly record it
  as 11 (NVP-II).  This file uses the correct IANA value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


# ---------------------------------------------------------------------------
# Protocol map
# ---------------------------------------------------------------------------


class ProtocolMap:
    """IP protocol name ↔ number lookups.

    All Junos MX protocol names observed in firewall filter configs are
    included.  IANA-correct numbers are used throughout.
    """

    _name_to_number = {
        "ah": 51,        # Authentication Header
        "egp": 8,        # Exterior Gateway Protocol
        "esp": 50,       # Encapsulating Security Payload
        "gre": 47,       # Generic Routing Encapsulation
        "icmp": 1,       # Internet Control Message Protocol
        "icmpv6": 58,    # ICMPv6
        "igmp": 2,       # Internet Group Management Protocol
        "igp": 9,        # Any private interior gateway protocol (historically IGRP)
        "ipip": 4,       # IP-in-IP encapsulation
        "ipv6": 41,      # IPv6 encapsulation
        "ospf": 89,      # Open Shortest Path First
        "pgm": 113,      # Pragmatic General Multicast
        "pim": 103,      # Protocol Independent Multicast
        "rdp": 27,       # Reliable Data Protocol
        "rsvp": 46,      # Resource Reservation Protocol
        "sctp": 132,     # Stream Control Transmission Protocol
        "tcp": 6,        # Transmission Control Protocol
        "udp": 17,       # User Datagram Protocol
        "vrrp": 112,     # Virtual Router Redundancy Protocol (IANA 112, NOT 11)
    }

    _number_to_name = {v: k for k, v in _name_to_number.items()}

    @classmethod
    def get_number(cls, name: str) -> Optional[int]:
        """Return the protocol number for a name, or None if unknown."""
        return cls._name_to_number.get(name.strip().lower())

    @classmethod
    def get_name(cls, number: int) -> Optional[str]:
        """Return the canonical protocol name for a number, or None if unknown."""
        return cls._number_to_name.get(number)

    @classmethod
    def resolve(cls, token: str) -> Tuple[Optional[str], Optional[int]]:
        """Resolve a token (name or numeric string) to (canonical_name, number).

        Returns (None, None) when the token is entirely unrecognized.
        """
        t = token.strip().lower()
        try:
            num = int(t)
            name = cls.get_name(num)
            return name, num
        except ValueError:
            num = cls.get_number(t)
            if num is not None:
                return t, num
            return None, None

    @classmethod
    def contains(cls, token: str) -> bool:
        """Return True if the token (name or number string) is known."""
        name, num = cls.resolve(token)
        return num is not None


# ---------------------------------------------------------------------------
# Port / service map
# ---------------------------------------------------------------------------


class PortMap:
    """Well-known TCP/UDP service port name ↔ number lookups.

    Covers the Junos-recognized service names observed in MX firewall
    filter configs, plus a broad set of common services for completeness.
    """

    _name_to_number = {
        # Core internet services
        "ftp-data": 20,
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "domain": 53,       # DNS
        "dns": 53,
        "dhcp": 67,
        "dhcp-client": 68,
        "tftp": 69,
        "http": 80,
        "kerberos": 88,
        "pop3": 110,
        "sunrpc": 111,
        "ident": 113,
        "nntp": 119,
        "ntp": 123,
        "netbios-ns": 137,
        "netbios-dgm": 138,
        "netbios-ssn": 139,
        "snmp": 161,
        "snmptrap": 162,
        "bgp": 179,
        "ldap": 389,
        "https": 443,
        "smb": 445,
        "ldp": 646,
        "tacacs": 49,
        "radius": 1812,
        "radius-acct": 1813,
        "nfs": 2049,
        "bfd": 3784,
        "bfd-multihop": 4784,
        "netconf": 830,
        "xmpp": 5269,
        "syslog": 514,
        "rip": 520,
        "irc": 194,
    }

    _number_to_name = {v: k for k, v in _name_to_number.items()}

    @classmethod
    def get_number(cls, name: str) -> Optional[int]:
        """Return the port number for a service name, or None if unknown."""
        return cls._name_to_number.get(name.strip().lower())

    @classmethod
    def get_name(cls, number: int) -> Optional[str]:
        """Return the canonical service name for a port number, or None."""
        return cls._number_to_name.get(number)

    @classmethod
    def resolve(cls, token: str) -> Tuple[Optional[str], Optional[int]]:
        """Resolve a token (service name or numeric string) to (canonical_name, number).

        For numeric-only tokens where no service name is registered, returns
        (None, number) — the number is authoritative even without a name.
        Returns (None, None) only for entirely unparseable tokens.
        """
        t = token.strip().lower()
        try:
            num = int(t)
            name = cls.get_name(num)
            return name, num
        except ValueError:
            num = cls.get_number(t)
            if num is not None:
                return t, num
            return None, None

    @classmethod
    def contains(cls, token: str) -> bool:
        name, num = cls.resolve(token)
        return num is not None


# ---------------------------------------------------------------------------
# ICMP type and code maps
# ---------------------------------------------------------------------------


class IcmpTypeMap:
    """ICMP type name ↔ number lookups.

    These are the Junos names used in ``<icmp-type>`` match conditions.
    """

    _name_to_number = {
        "echo-reply": 0,
        "unreachable": 3,
        "source-quench": 4,
        "redirect": 5,
        "echo-request": 8,
        "router-advertisement": 9,
        "router-solicit": 10,
        "time-exceeded": 11,
        "parameter-problem": 12,
        "timestamp": 13,
        "timestamp-reply": 14,
        "info-request": 15,
        "info-reply": 16,
        "mask-request": 17,
        "mask-reply": 18,
        # Aliases used by Junos CLI
        "ping": 8,   # alias for echo-request
    }

    _number_to_name = {
        0: "echo-reply",
        3: "unreachable",
        4: "source-quench",
        5: "redirect",
        8: "echo-request",
        9: "router-advertisement",
        10: "router-solicit",
        11: "time-exceeded",
        12: "parameter-problem",
        13: "timestamp",
        14: "timestamp-reply",
        15: "info-request",
        16: "info-reply",
        17: "mask-request",
        18: "mask-reply",
    }

    @classmethod
    def get_number(cls, name: str) -> Optional[int]:
        return cls._name_to_number.get(name.strip().lower())

    @classmethod
    def get_name(cls, number: int) -> Optional[str]:
        return cls._number_to_name.get(number)

    @classmethod
    def resolve(cls, token: str) -> Tuple[Optional[str], Optional[int]]:
        t = token.strip().lower()
        try:
            num = int(t)
            name = cls.get_name(num)
            return name, num
        except ValueError:
            num = cls.get_number(t)
            if num is not None:
                canonical = cls._number_to_name.get(num, t)
                return canonical, num
            return None, None


class IcmpCodeMap:
    """ICMP code name ↔ number lookups.

    Code names in Junos are used primarily within the ``unreachable`` type
    (type 3).  All other types typically use numeric codes.
    """

    _name_to_number = {
        # Type 3 — Destination Unreachable
        "network-unreachable": 0,
        "host-unreachable": 1,
        "protocol-unreachable": 2,
        "port-unreachable": 3,
        "fragmentation-needed": 4,
        "source-route-failed": 5,
        "network-unknown": 6,
        "host-unknown": 7,
        "source-host-isolated": 8,
        "network-prohibited": 9,
        "host-prohibited": 10,
        "tos-network-unreachable": 11,
        "tos-host-unreachable": 12,
        "communication-prohibited": 13,
        "host-precedence-violation": 14,
        "precedence-cutoff": 15,
        # Type 5 — Redirect
        "redirect-for-network": 0,
        "redirect-for-host": 1,
        "redirect-for-tos-and-net": 2,
        "redirect-for-tos-and-host": 3,
        # Type 11 — Time Exceeded
        "ttl-expired-in-transit": 0,
        "fragment-reassembly-exceeded": 1,
    }

    @classmethod
    def get_number(cls, name: str) -> Optional[int]:
        return cls._name_to_number.get(name.strip().lower())

    @classmethod
    def resolve(cls, token: str) -> Tuple[Optional[str], Optional[int]]:
        t = token.strip().lower()
        try:
            num = int(t)
            return None, num  # numeric codes have no canonical name independent of type
        except ValueError:
            num = cls.get_number(t)
            if num is not None:
                return t, num
            return None, None


# ---------------------------------------------------------------------------
# Token normalization API (used by factory and future firewall slice)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedProtocol:
    """Result of normalizing a protocol token."""

    raw: str
    number: Optional[int]
    canonical_name: Optional[str]


@dataclass(frozen=True)
class NormalizedPort:
    """Result of normalizing a port/service token."""

    raw: str
    kind: str  # "single" | "range" | "unknown"
    value: Optional[int] = None           # for kind="single"
    low: Optional[int] = None             # for kind="range"
    high: Optional[int] = None            # for kind="range"
    canonical_name: Optional[str] = None  # service name if known


def normalize_protocol(token: str) -> NormalizedProtocol:
    """Normalize a protocol token to its canonical name and IANA number.

    Accepts both numeric strings (``"6"``) and names (``"tcp"``).

    Examples::

        normalize_protocol("tcp")   # NormalizedProtocol(raw="tcp", number=6, canonical_name="tcp")
        normalize_protocol("6")     # NormalizedProtocol(raw="6",   number=6, canonical_name="tcp")
        normalize_protocol("vrrp")  # NormalizedProtocol(raw="vrrp", number=112, canonical_name="vrrp")
        normalize_protocol("999")   # NormalizedProtocol(raw="999", number=999, canonical_name=None)
    """
    t = token.strip()
    try:
        num = int(t)
        name = ProtocolMap.get_name(num)
        return NormalizedProtocol(raw=token, number=num, canonical_name=name)
    except ValueError:
        num = ProtocolMap.get_number(t)
        if num is not None:
            return NormalizedProtocol(raw=token, number=num, canonical_name=t.lower())
        # Unknown name — pass through without a number
        return NormalizedProtocol(raw=token, number=None, canonical_name=t.lower())


def normalize_port_token(token: str) -> NormalizedPort:
    """Normalize a port/service token to a structured NormalizedPort.

    Handles three token shapes:
    - Named service: ``"ssh"`` → single, value=22, canonical_name="ssh"
    - Numeric single: ``"443"`` → single, value=443
    - Numeric range: ``"10000-19999"`` → range, low=10000, high=19999

    Examples::

        normalize_port_token("ssh")         # kind=single, value=22, canonical_name="ssh"
        normalize_port_token("443")         # kind=single, value=443
        normalize_port_token("10000-19999") # kind=range, low=10000, high=19999
        normalize_port_token("bgp")         # kind=single, value=179, canonical_name="bgp"
    """
    t = token.strip()

    # Range: contains exactly one hyphen and both sides are digits
    if "-" in t:
        parts = t.split("-", 1)
        try:
            low, high = int(parts[0]), int(parts[1])
            return NormalizedPort(raw=token, kind="range", low=low, high=high)
        except ValueError:
            pass  # fall through to unknown

    # Numeric single
    try:
        num = int(t)
        name = PortMap.get_name(num)
        return NormalizedPort(raw=token, kind="single", value=num, canonical_name=name)
    except ValueError:
        pass

    # Named service
    num = PortMap.get_number(t)
    if num is not None:
        return NormalizedPort(raw=token, kind="single", value=num, canonical_name=t.lower())

    # Unknown named token — no number resolved
    return NormalizedPort(raw=token, kind="unknown")


# end of lib/protocols_ports/helpers.py
