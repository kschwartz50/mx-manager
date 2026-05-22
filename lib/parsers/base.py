"""Parser contracts for mx-manager.

This module defines the TypedDict shapes returned by concrete parsers and the
abstract base class that all MX parsers must implement.

v1 scope: interface configurations.
v2 additions: routing-instances and policy-options slices.

When additional slices are ported (zones, NAT, MPLS, bridge-domains, …), add
the corresponding TypedDicts here and the abstractmethods to BaseMXParser so
the Importer can bind to a stable contract.
"""

import sys
from abc import ABC, abstractmethod
from typing import List, Literal, Optional, TypedDict

# ``NotRequired`` landed in ``typing`` in 3.11. Fall back to
# ``typing_extensions`` for 3.10 users (the value is import-compatible).
if sys.version_info >= (3, 11):
    from typing import NotRequired
else:  # pragma: no cover - exercised only on older interpreters
    from typing_extensions import NotRequired


# --------------------------------------------------------------------------
# Interface TypedDicts
# --------------------------------------------------------------------------


class FamilyDict(TypedDict):
    """Raw parsed family data (inet, inet6, etc.)."""

    addresses: List[str]
    primary_address: NotRequired[Optional[str]]
    preferred_address: NotRequired[Optional[str]]
    # First VRRP virtual-address found on any address in this family.
    # Bare IP, no prefix-length (e.g. "159.153.132.1").  Only set for inet;
    # inet6 VRRP is uncommon on MX and not currently parsed.
    vrrp_virtual_address: NotRequired[Optional[str]]

    mtu: NotRequired[int]
    sampling_input: NotRequired[bool]
    sampling_output: NotRequired[bool]


class UnitInterfaceDict(TypedDict):
    """Raw parsed logical unit."""

    name: str
    raw_config: str

    description: NotRequired[Optional[str]]
    vlan_id: NotRequired[int]
    mtu: NotRequired[int]
    # MX units frequently carry encapsulation (vlan-bridge, vlan-ccc, etc.)
    encapsulation: NotRequired[Optional[str]]
    # Logical units may exist only for L2 switching on bridge-domains
    is_l2: NotRequired[bool]

    inet: NotRequired[FamilyDict]
    inet6: NotRequired[FamilyDict]

    # Firewall filter application — populated from <family><inet|inet6><filter>
    # stanzas.  These carry the filter *name* (string), not the UID, because
    # the firewall slice may not be ingested yet when the interface slice runs.
    filter_inet_input: NotRequired[Optional[str]]
    filter_inet_output: NotRequired[Optional[str]]
    filter_inet6_input: NotRequired[Optional[str]]
    filter_inet6_output: NotRequired[Optional[str]]


InterfaceKind = Literal[
    "physical",
    "ae",
    "loopback",
    "tunnel",
    "irb",
    "management",
]


class McAeDict(TypedDict, total=False):
    """Multi-chassis aggregated ethernet parameters (MX feature)."""

    mc_ae_id: Optional[int]
    redundancy_group: Optional[int]
    chassis_id: Optional[int]
    mode: Optional[str]
    status_control: Optional[str]


class InterfaceDict(TypedDict):
    """A flat, flexible dictionary representing any base interface stanza.

    The parser fills out whatever it finds in the XML.
    """

    name: str
    kind: InterfaceKind
    raw_config: str
    units: List[UnitInterfaceDict]

    description: NotRequired[Optional[str]]
    mtu: NotRequired[int]

    # Physical traits
    speed: NotRequired[str]
    duplex: NotRequired[str]
    member_of: NotRequired[str]  # Parent name, e.g., "ae100"

    # AE traits
    minimum_links: NotRequired[int]
    lacp_mode: NotRequired[str]
    lacp_periodic: NotRequired[str]
    mc_ae: NotRequired[McAeDict]

    # Tagging / encapsulation (base-level, MX-heavy)
    vlan_tagging: NotRequired[bool]
    flexible_vlan_tagging: NotRequired[bool]
    encapsulation: NotRequired[Optional[str]]
    native_vlan_id: NotRequired[int]


class InterfaceContainerDict(TypedDict):
    """Top-level wrapper for the parser output."""

    interfaces: List[InterfaceDict]


# --------------------------------------------------------------------------
# Routing-instance TypedDicts
# --------------------------------------------------------------------------


class NextHopDict(TypedDict):
    """Raw parsed data for a single static route next-hop."""

    kind: Literal["ip", "interface", "ip-interface", "next-table", "discard", "reject"]

    ip_address: NotRequired[Optional[str]]
    interface: NotRequired[Optional[str]]
    next_table: NotRequired[Optional[str]]

    preference: NotRequired[Optional[int]]
    metric: NotRequired[Optional[int]]
    qualified: NotRequired[bool]


class StaticRouteDict(TypedDict):
    """Raw parsed data for a static route destination."""

    destination: str
    next_hops: List[NextHopDict]
    discard: NotRequired[bool]
    reject: NotRequired[bool]
    preference: NotRequired[Optional[int]]
    tag: NotRequired[Optional[int]]
    description: NotRequired[Optional[str]]


class BgpNeighborDict(TypedDict):
    """Raw parsed data for a single BGP neighbor."""

    name: str
    local_address: NotRequired[Optional[str]]
    description: NotRequired[Optional[str]]


class BgpGroupDict(TypedDict):
    """Raw parsed data for a single BGP group."""

    name: str
    bgp_type: str
    import_policies: List[str]
    export_policies: List[str]
    neighbors: List[BgpNeighborDict]

    peer_as: NotRequired[Optional[int]]
    local_as: NotRequired[Optional[int]]
    hold_time: NotRequired[Optional[int]]
    multipath: NotRequired[bool]
    remove_private: NotRequired[bool]


class RoutingInstanceDict(TypedDict):
    """Top-level container for a routing-instance stanza."""

    name: str
    instance_type: str
    description: NotRequired[Optional[str]]
    interfaces: List[str]
    static_routes: List[StaticRouteDict]
    bgp_groups: List[BgpGroupDict]


# --------------------------------------------------------------------------
# Policy-options TypedDicts
# --------------------------------------------------------------------------


class RouteFilterDict(TypedDict):
    """Details for a route-filter match condition."""

    address: str
    match_type: Literal["exact", "orlonger", "longer", "upto", "prefix-length-range"]
    raw_config: NotRequired[str]


class PrefixListDict(TypedDict):
    """Details for a named prefix-list."""

    name: str
    prefixes: List[str]
    raw_config: str


class AsPathDict(TypedDict):
    """Details for a named AS-path regex."""

    name: str
    path: str
    raw_config: str


class PolicyTermDict(TypedDict):
    """Logic for a single term within a policy-statement."""

    name: str
    raw_config: str
    from_protocols: NotRequired[List[str]]
    from_prefix_lists: NotRequired[List[str]]
    from_route_filters: NotRequired[List[RouteFilterDict]]
    from_as_paths: NotRequired[List[str]]
    actions: List[str]
    next_hop: NotRequired[Optional[str]]


class PolicyStatementDict(TypedDict):
    """Container for a policy-statement and its terms."""

    name: str
    raw_config: str
    terms: List[PolicyTermDict]


class PolicyOptionsDict(TypedDict):
    """Container for all policy-options elements."""

    policy_statements: List[PolicyStatementDict]
    as_paths: List[AsPathDict]
    prefix_lists: List[PrefixListDict]


# --------------------------------------------------------------------------
# Protocols-ports TypedDicts
# --------------------------------------------------------------------------


class PortListEntryDict(TypedDict):
    """A single raw port token from a port-list stanza.

    The factory is responsible for normalization (name→number, range splitting,
    etc.) via ``lib.protocols_ports.helpers``.  The parser emits only the raw
    text token to keep the TypedDict boundary clean.
    """

    raw: str


class PortListDict(TypedDict):
    """Raw parsed data for a single port-list stanza."""

    name: str
    raw_config: str
    entries: List[str]   # ordered list of raw port tokens


# --------------------------------------------------------------------------
# Firewall TypedDicts
# --------------------------------------------------------------------------


class TermFromDict(TypedDict, total=False):
    """Raw parsed match conditions for a single firewall term.

    All fields are optional (``total=False``) because most terms only
    exercise a subset of possible match conditions.  The factory treats
    absent keys the same as an empty list / False.

    Inline address and port tokens are passed as raw strings; the factory
    normalizes them via ``lib.protocols_ports.helpers``.

    Cross-slice references (prefix-lists and port-lists) are name strings
    only — the factory looks up UIDs from the registry index and wires
    the edges.  The ``protocols`` field covers both ``<protocol>`` (inet)
    and ``<next-header>`` (inet6); the parser maps both to the same field.
    """

    source_prefix_lists: List[str]       # PrefixList names
    destination_prefix_lists: List[str]  # PrefixList names
    source_port_lists: List[str]         # PortList names
    destination_port_lists: List[str]    # PortList names
    source_addresses: List[str]          # CIDR strings
    destination_addresses: List[str]     # CIDR strings
    protocols: List[str]                 # raw tokens (e.g. "tcp", "6")
    ports: List[str]                     # raw tokens (either direction)
    source_ports: List[str]              # raw tokens
    destination_ports: List[str]         # raw tokens
    icmp_types: List[str]                # raw tokens (e.g. "echo-request")
    tcp_established: bool


class FirewallTermDict(TypedDict):
    """Raw parsed data for a single firewall term."""

    name: str
    raw_config: str
    from_conditions: NotRequired[TermFromDict]
    actions: List[str]          # "accept", "reject", "discard", "next-term", "sample"
    count: NotRequired[Optional[str]]   # counter name from <count>
    log: NotRequired[bool]
    syslog: NotRequired[bool]


class FirewallFilterDict(TypedDict):
    """Raw parsed data for a single named firewall filter."""

    name: str
    address_family: str          # "inet" | "inet6" | "any"
    raw_config: str
    terms: List[FirewallTermDict]


# --------------------------------------------------------------------------
# Base Parser Interface
# --------------------------------------------------------------------------


class BaseMXParser(ABC):
    """Abstract base class defining the contract for all MX config parsers.

    v1 scope: interface configurations only. Additional slices should be added
    as separate abstractmethods when implemented, so the Importer can bind to
    a stable contract.
    """

    def __init__(self, xml_data: bytes):
        self.xml_data = xml_data

    @abstractmethod
    def parse_interface_configs(self) -> List[InterfaceDict]:
        """Return a strict list of InterfaceDict objects for the InterfaceFactory."""
        ...

    @abstractmethod
    def parse_routing_instances(self) -> List[RoutingInstanceDict]:
        """Return a strict list of RoutingInstanceDict objects for the RoutingInstanceFactory."""
        ...

    @abstractmethod
    def parse_policy_options(self) -> PolicyOptionsDict:
        """Return a PolicyOptionsDict containing prefix-lists, as-paths, and statements."""
        ...

    @abstractmethod
    def parse_port_lists(self) -> List[PortListDict]:
        """Return a list of PortListDict objects for the ProtocolsPortsFactory.

        Returns an empty list when no ``<firewall><port-list>`` stanzas exist
        in the config (which is valid and common).
        """
        ...

    @abstractmethod
    def parse_firewall_filters(self) -> List[FirewallFilterDict]:
        """Return a list of FirewallFilterDict objects for the FirewallFactory.

        Covers all address-family scopes:
        * ``<firewall><filter>``               → address_family="any"
        * ``<firewall><family><inet><filter>`` → address_family="inet"
        * ``<firewall><family><inet6><filter>``→ address_family="inet6"

        Returns an empty list when no firewall stanzas exist in the config.
        """
        ...
