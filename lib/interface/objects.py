"""Dataclass hierarchy for the MX interface slice.

MX-specific differences from the srx-manager shape:

* ``InterfaceKind`` drops ``reth`` and ``fabric`` (SRX-only) and adds ``irb``
  and ``management``.
* ``AggEthInterface`` gains an optional ``mc_ae`` block (multi-chassis AE),
  which is an MX feature.
* Both base interfaces and units gain an ``encapsulation`` slot because MX
  routinely carries L2 encapsulation on logical units (vlan-bridge, vlan-ccc,
  vlan-vpls, ...). Units additionally expose an ``is_l2`` flag so exporters
  can segregate bridged units from L3-terminated ones.
* ``PhysicalInterface.member_of_type`` is narrowed to ``"ae"`` only — the
  reth/fabric parent kinds do not exist on MX.
* A new ``IrbInterface`` class represents integrated routing-and-bridging
  interfaces (the L3 gateways for MX bridge-domains and EVPN L2 services).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

from lib.registry.objects import BaseNode


# --------------------------------------------------------------------------
# Family specs
# --------------------------------------------------------------------------


@dataclass
class FamilyInetSpec:
    """IPv4 family payload for a logical unit.

    Attributes:
        addresses: All configured inet addresses in CIDR form.
        primary_address: Junos ``primary`` — used as the source for locally
            sourced broadcast/multicast and, on SRX, for NAT. The parser
            captures explicit ``<primary/>`` flags; the factory fills a
            deterministic fallback when none is set.
        preferred_address: Junos ``preferred`` — used as the default local
            source for routed traffic on the subnet.
        mtu: Optional family-level MTU override.
        sampling_input: True if input sampling is enabled at the family level.
        sampling_output: True if output sampling is enabled at the family level.
    """

    addresses: List[str] = field(default_factory=list)
    primary_address: Optional[str] = None
    preferred_address: Optional[str] = None
    mtu: Optional[int] = None
    sampling_input: bool = False
    sampling_output: bool = False


@dataclass
class FamilyInet6Spec:
    """IPv6 family payload for a logical unit."""

    addresses: List[str] = field(default_factory=list)
    primary_address: Optional[str] = None
    preferred_address: Optional[str] = None
    mtu: Optional[int] = None


# --------------------------------------------------------------------------
# Shared option specs
# --------------------------------------------------------------------------


@dataclass
class LacpOptions:
    mode: Optional[Literal["active", "passive"]] = None
    periodic: Optional[Literal["slow", "fast"]] = None


@dataclass
class McAeOptions:
    """Multi-chassis aggregated Ethernet parameters (MX-only).

    Present on ``aeN`` bundles that participate in an MC-LAG between two
    chassis. All fields are optional because MC-AE stanzas on real configs
    sometimes omit individual values (for example, ``chassis-id`` may be
    inherited from a group).
    """

    mc_ae_id: Optional[int] = None
    redundancy_group: Optional[int] = None
    chassis_id: Optional[int] = None
    mode: Optional[str] = None
    status_control: Optional[str] = None


# --------------------------------------------------------------------------
# Containers
# --------------------------------------------------------------------------


@dataclass
class InterfaceConfigRoot(BaseNode):
    """Root node for the interface slice.

    Slice-level anchor. Does not represent a concrete interface. Groups the
    two primary interface collections (``BaseInterfaceContainer`` and
    ``UnitInterfaceContainer``).

    Graph relationships:
        * ``ConfigRoot -> InterfaceConfigRoot`` via ``interface_config_root``
        * ``InterfaceConfigRoot -> BaseInterfaceContainer`` via
          ``base_interface_container``
        * ``InterfaceConfigRoot -> UnitInterfaceContainer`` via
          ``unit_interface_container``
    """

    type: str = "InterfaceConfigRoot"


@dataclass
class BaseInterfaceContainer(BaseNode):
    """Container node for all base interface objects.

    Organizational grouping of parent/base interfaces. Membership
    relationships between base interfaces (e.g. AE -> Physical) do NOT
    terminate on this container; those remain direct graph edges.

    Graph relationships:
        * ``InterfaceConfigRoot -> BaseInterfaceContainer`` via
          ``base_interface_container``
        * ``BaseInterfaceContainer -> BaseInterfaceNode`` via ``base_interface``
    """

    type: str = "BaseInterfaceContainer"


@dataclass
class UnitInterfaceContainer(BaseNode):
    """Container node for all logical unit interface objects.

    Organizational grouping only. A unit's real parent-child relationship to
    its owning base interface is represented separately by ``interface_unit``.

    Graph relationships:
        * ``InterfaceConfigRoot -> UnitInterfaceContainer`` via
          ``unit_interface_container``
        * ``UnitInterfaceContainer -> UnitInterface`` via ``unit_interface``
    """

    type: str = "UnitInterfaceContainer"


# --------------------------------------------------------------------------
# Base interface node + concrete kinds
# --------------------------------------------------------------------------

InterfaceKind = Literal[
    "physical",
    "ae",
    "loopback",
    "tunnel",
    "irb",
    "management",
]


@dataclass
class BaseInterfaceNode(BaseNode):
    """Pure data container for base interface attributes.

    Extends the srx-manager shape with fields that MX frequently sets at the
    base-interface level:

    * ``encapsulation``: for example ``flexible-ethernet-services`` on
      physical members of AE bundles, or ``ethernet-bridge`` on units that
      are bridge-domain members.
    * ``flexible_vlan_tagging`` and ``native_vlan_id``: MX-heavy tagging
      knobs that SRX does not usually carry.
    """

    description: Optional[str] = None
    mtu: Optional[int] = None
    kind: InterfaceKind = "physical"
    encapsulation: Optional[str] = None
    vlan_tagging: bool = False
    flexible_vlan_tagging: bool = False
    native_vlan_id: Optional[int] = None
    type: str = "BaseInterfaceNode"


@dataclass
class PhysicalInterface(BaseInterfaceNode):
    kind: InterfaceKind = "physical"
    type: str = "PhysicalInterface"

    speed: str = "auto"
    duplex: str = "auto"

    # The factory wires the actual graph edge; these track the parser's
    # view of AE bundle membership. On MX, ``ae`` is the only parent kind.
    member_of_type: Optional[Literal["ae"]] = None
    member_of_parent: Optional[str] = None  # Parent name, e.g., "ae100"


@dataclass
class AggEthInterface(BaseInterfaceNode):
    kind: InterfaceKind = "ae"
    type: str = "AggEthInterface"
    member_interfaces: List[str] = field(default_factory=list)

    minimum_links: Optional[int] = None
    lacp_mode: Optional[str] = None
    lacp_periodic: Optional[str] = None

    # MX-only: present when the bundle participates in multi-chassis AE.
    mc_ae: Optional[McAeOptions] = None


@dataclass
class LoopbackInterface(BaseInterfaceNode):
    kind: InterfaceKind = "loopback"
    type: str = "LoopbackInterface"


@dataclass
class TunnelInterface(BaseInterfaceNode):
    kind: InterfaceKind = "tunnel"
    type: str = "TunnelInterface"


@dataclass
class IrbInterface(BaseInterfaceNode):
    """Integrated routing-and-bridging interface (MX).

    On MX, ``irb`` is a distinct first-class interface kind whose units act
    as L3 gateways for bridge-domains / EVPN L2 services. Units of ``irb``
    look like ordinary L3 UnitInterface nodes with inet/inet6 addresses.
    """

    kind: InterfaceKind = "irb"
    type: str = "IrbInterface"


@dataclass
class ManagementInterface(BaseInterfaceNode):
    """Out-of-band management (``fxp0`` RE management, ``em0`` chassis)."""

    kind: InterfaceKind = "management"
    type: str = "ManagementInterface"


# --------------------------------------------------------------------------
# Unit node
# --------------------------------------------------------------------------


@dataclass
class UnitInterface(BaseNode):
    """Logical interface unit node (ae100.10, irb.200, xe-0/0/0.0, lo0.0).

    MX-specific fields:

    * ``encapsulation`` captures per-unit L2 encapsulation
      (``vlan-bridge``, ``vlan-ccc``, ``vlan-vpls``, ...).
    * ``is_l2`` is True when the unit participates in an L2 service — either
      because its encapsulation is a bridging one, or because it carries
      ``family bridge``. Exporters use this to segregate bridged units from
      L3 units.
    """

    parent_name: str = ""
    unit: str = "0"

    description: Optional[str] = None
    vlan_id: Optional[int] = None

    mtu: Optional[int] = None

    # MX L2 semantics
    encapsulation: Optional[str] = None
    is_l2: bool = False

    inet: Optional[FamilyInetSpec] = None
    inet6: Optional[FamilyInet6Spec] = None

    other_families: Dict[str, Dict] = field(default_factory=dict)

    # Firewall filter application — set when the unit carries a
    # <family><inet|inet6><filter><input|output> stanza.  Values are filter
    # names (strings), not UIDs, so they survive serialisation without
    # requiring the firewall slice to be loaded first.
    filter_inet_input: Optional[str] = None
    filter_inet_output: Optional[str] = None
    filter_inet6_input: Optional[str] = None
    filter_inet6_output: Optional[str] = None

    type: str = "UnitInterface"


# end of lib/interface/objects.py
