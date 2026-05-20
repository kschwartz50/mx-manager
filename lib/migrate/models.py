"""PAN-OS data models for the mx-manager migrate slice.

These are the target-side blueprints used during migration from MX firewall
filters to PAN-OS security policies.  Phase 1 scope: security rules,
addresses, services, and zones.
"""

from dataclasses import dataclass, field
from typing import List, Literal, Optional


# ---------------------------------------------------------------------------
# ADDRESS MODELS
# ---------------------------------------------------------------------------


@dataclass
class PanosAddress:
    """Blueprint for a PAN-OS Address Object.

    Supports ip-netmask and ip-range.  fqdn and ip-wildcard are reserved for
    future use but modeled for completeness.
    """

    name: str
    value: str
    description: Optional[str] = None
    tag: List[str] = field(default_factory=list)
    address_type: Literal["ip-netmask", "ip-range", "fqdn", "ip-wildcard"] = (
        "ip-netmask"
    )
    valid_pan_config: bool = True


@dataclass
class PanosAddressGroup:
    """Blueprint for a static PAN-OS Address Group.

    Members may be address object names or nested address-group names.
    Prefix lists from MX are migrated as static address groups.
    """

    name: str
    static_members: List[str] = field(default_factory=list)
    description: Optional[str] = None
    tag: List[str] = field(default_factory=list)
    valid_pan_config: bool = True


# ---------------------------------------------------------------------------
# SERVICE MODELS
# ---------------------------------------------------------------------------


@dataclass
class PanosService:
    """Blueprint for a PAN-OS Service object (TCP or UDP with a port spec)."""

    name: str
    protocol: Literal["tcp", "udp"]
    port: str  # e.g. "22", "10000-19999", "0-65535"
    description: Optional[str] = None
    valid_pan_config: bool = True


@dataclass
class PanosServiceGroup:
    """Blueprint for a PAN-OS Service Group."""

    name: str
    members: List[str]
    description: Optional[str] = None
    valid_pan_config: bool = True


# ---------------------------------------------------------------------------
# TAG MODEL
# ---------------------------------------------------------------------------


@dataclass
class PanosTag:
    """Blueprint for a PAN-OS Tag object."""

    name: str
    color: str
    comments: Optional[str] = None
    valid_pan_config: bool = True


# ---------------------------------------------------------------------------
# ZONE MODEL
# ---------------------------------------------------------------------------


@dataclass
class PanosZone:
    """Blueprint for a PAN-OS Zone object.

    For this phase the zone is emitted as a minimal layer3 zone with no
    interface assignments — those are filled in after the PAN-OS side is
    built.  The zone name is the MX logical interface name (e.g. ``irb.901``,
    ``ae100.0``) sanitized for PAN-OS (forward-slashes replaced with
    underscores).
    """

    name: str
    description: Optional[str] = None
    valid_pan_config: bool = True


# ---------------------------------------------------------------------------
# SECURITY RULE MODEL
# ---------------------------------------------------------------------------


@dataclass
class PanosSecurityRule:
    """Blueprint for a PAN-OS Security Rule.

    Zones default to 'any' because MX firewall filters have no zone concept.
    """

    name: str
    from_zones: List[str]
    to_zones: List[str]
    source_addresses: List[str] = field(default_factory=list)
    destination_addresses: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    action: Literal["allow", "deny", "drop"] = "allow"
    description: Optional[str] = None
    disabled: bool = False
    tag: List[str] = field(default_factory=list)
    log_start: bool = False
    log_end: bool = False
    warnings: List[str] = field(default_factory=list)
    valid_pan_config: bool = True


# ---------------------------------------------------------------------------
# TRANSLATION RESULT WRAPPERS
# ---------------------------------------------------------------------------


@dataclass
class PolicyTranslationResult:
    """Wraps the output of a single firewall-term → security-rule translation."""

    source_name: str
    target_kind: Literal["security-rule", "skipped", "unsupported"]
    pan_name: Optional[str] = None
    value: Optional[PanosSecurityRule] = None
    warnings: List[str] = field(default_factory=list)


# end of lib/migrate/models.py
