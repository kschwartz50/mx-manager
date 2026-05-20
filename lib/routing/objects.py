"""Dataclass hierarchy for the MX routing slice.

Objects cover routing-instance constructs only: RoutingInstance, StaticRoute,
BgpGroup, BgpNeighbor.  Policy-options objects (PolicyStatement, PolicyTerm,
PrefixList, AsPath, and their containers) live in lib.policy_options.objects.

Graph relationships (read-only reference — the factory wires the edges):

    ConfigRoot -> RoutingInstance    (label: "routing_instance")
    RoutingInstance -> UnitInterface (label: "instance_interface")
    RoutingInstance -> StaticRoute   (label: "static_route", order: N)
    RoutingInstance -> BgpGroup      (label: "bgp_group")
    BgpGroup -> BgpNeighbor          (label: "bgp_neighbor")
    BgpGroup -> PolicyStatement      (label: "import_policy", order: N)
    BgpGroup -> PolicyStatement      (label: "export_policy", order: N)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional

from lib.registry.objects import BaseNode

# Junos routing-instance types seen on MX
InstanceType = Literal["virtual-router", "vrf", "forwarding", "virtual-switch", "vpls"]

# Next-hop kinds
NextHopKind = Literal[
    "ip", "interface", "ip-interface", "discard", "reject", "next-table"
]


@dataclass(frozen=True)
class NextHopSpec:
    """Value object representing a specific path for a static route."""

    kind: NextHopKind = "ip"
    ip_address: Optional[str] = None
    interface: Optional[str] = None
    next_table: Optional[str] = None
    preference: Optional[int] = None
    metric: Optional[int] = None
    qualified: bool = False


@dataclass(kw_only=True)
class StaticRoute(BaseNode):
    """Intrinsic properties of a static route destination.

    Edges: RoutingInstance -> StaticRoute (label: "static_route")
    """

    destination: str
    next_hops: List[NextHopSpec] = field(default_factory=list)
    discard: bool = False
    reject: bool = False
    preference: Optional[int] = None
    tag: Optional[int] = None
    description: Optional[str] = None
    type: str = field(default="StaticRoute")


@dataclass(kw_only=True)
class RoutingInstance(BaseNode):
    """Intrinsic properties of a Junos routing-instance.

    Edges:
        ConfigRoot -> RoutingInstance (label: "routing_instance")
        RoutingInstance -> UnitInterface (label: "instance_interface")
        RoutingInstance -> StaticRoute (label: "static_route")
    """

    instance_type: InstanceType = "virtual-router"
    description: Optional[str] = None
    type: str = field(default="RoutingInstance")


@dataclass(kw_only=True)
class BgpGroup(BaseNode):
    """Group-level BGP settings.

    Edges: RoutingInstance -> BgpGroup (label: "bgp_group")
    """

    bgp_type: Literal["internal", "external"] = "external"
    peer_as: Optional[int] = None
    local_as: Optional[int] = None
    hold_time: Optional[int] = None
    multipath: bool = False
    remove_private: bool = False
    type: str = field(default="BgpGroup")


@dataclass(kw_only=True)
class BgpNeighbor(BaseNode):
    """Peer-level BGP settings.

    Edges: BgpGroup -> BgpNeighbor (label: "bgp_neighbor")
    """

    peer_address: str
    local_address: Optional[str] = None
    description: Optional[str] = None
    type: str = field(default="BgpNeighbor")


# end of lib/routing/objects.py
