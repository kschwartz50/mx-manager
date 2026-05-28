"""Factory for building the MX interface slice graph.

Converts parsed interface dictionaries (from ``lib.parsers``) into pure graph
nodes plus labeled edges. Enforces the same three-concept separation used by
srx-manager:

1. Config grouping
   * ``InterfaceConfigRoot``
   * ``BaseInterfaceContainer``
   * ``UnitInterfaceContainer``
2. Parent/unit linkage
   * ``BaseInterfaceNode -> UnitInterface`` via ``interface_unit``
3. Base-interface membership linkage
   * ``AggEthInterface -> PhysicalInterface`` via ``member_interface``

MX-specific notes:

* Only AE is a valid parent kind for membership on MX (no reth, no fabric).
* ``encapsulation``, ``flexible_vlan_tagging``, ``vlan_tagging``, and
  ``native_vlan_id`` are captured on the base interface node.
* ``mc_ae`` is attached to ``AggEthInterface`` when the parser emitted one.
* Unit-level ``encapsulation`` and ``is_l2`` are passed through to
  ``UnitInterface`` so exporters can segregate bridged units from L3 units.
"""

import ipaddress
from typing import List, Optional, Tuple

from lib.interface.objects import (
    AggEthInterface,
    BaseInterfaceContainer,
    FamilyInet6Spec,
    FamilyInetSpec,
    InterfaceConfigRoot,
    IrbInterface,
    LoopbackInterface,
    ManagementInterface,
    McAeOptions,
    PhysicalInterface,
    TunnelInterface,
    UnitInterface,
    UnitInterfaceContainer,
)
from lib.parsers.base import InterfaceDict, UnitInterfaceDict
from lib.registry.graph import DataRegistry


# Base interface node types this factory can emit. Used for UID lookups
# during Pass 2 membership resolution.
_BASE_INTERFACE_TYPES = (
    "PhysicalInterface",
    "AggEthInterface",
    "LoopbackInterface",
    "TunnelInterface",
    "IrbInterface",
    "ManagementInterface",
)


class InterfaceFactory:
    """Builds MX interface graph content as pure nodes plus labeled edges.

    Two-pass model:
        * Pass 1 creates all base interface nodes, all unit nodes, and the
          parent/unit edges.
        * Pass 2 resolves parsed membership strings (a physical interface's
          ``member_of=ae100``) into graph-confirmed ``member_interface`` edges.
    """

    def __init__(self, registry: DataRegistry):
        """Initializes the factory.

        Args:
            registry: Shared graph/data registry used for node registration
                and relationship creation.
        """
        self.registry = registry

    def ingest_interfaces(
        self, interfaces_data: List[InterfaceDict], config_root_uid: str
    ) -> str:
        """Builds the full interface slice under the supplied config root.

        Args:
            interfaces_data: Parsed interface dictionaries from the parser.
            config_root_uid: UID of the owning ``ConfigRoot``.

        Returns:
            UID of the created ``InterfaceConfigRoot`` node.
        """
        interface_root = InterfaceConfigRoot(name="interfaces")
        interface_root_uid = self.registry.register_node(
            interface_root, f"interface-config-root|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            config_root_uid, interface_root_uid, label="interface_config_root"
        )

        base_container = BaseInterfaceContainer(name="base-interfaces")
        base_container_uid = self.registry.register_node(
            base_container, f"base-interface-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            interface_root_uid,
            base_container_uid,
            label="base_interface_container",
        )

        unit_container = UnitInterfaceContainer(name="unit-interfaces")
        unit_container_uid = self.registry.register_node(
            unit_container, f"unit-interface-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            interface_root_uid,
            unit_container_uid,
            label="unit_interface_container",
        )

        pending_memberships: List[Tuple[str, InterfaceDict]] = []

        # PASS 1: create all base interface nodes and all unit nodes
        for iface_dict in interfaces_data:
            iface_uid = self._create_base_interface_node(
                iface_dict=iface_dict,
                base_container_uid=base_container_uid,
            )

            # On MX the only membership we care about is physical -> ae.
            if iface_dict.get("kind") == "physical":
                pending_memberships.append((iface_uid, iface_dict))

            for unit_dict in iface_dict.get("units", []):
                self._create_unit_interface_node(
                    unit_dict=unit_dict,
                    parent_uid=iface_uid,
                    unit_container_uid=unit_container_uid,
                    parent_name=iface_dict["name"],
                )

        # PASS 2: resolve parsed membership strings into graph edges
        for iface_uid, iface_dict in pending_memberships:
            self._link_memberships(iface_uid=iface_uid, data=iface_dict)

        return interface_root_uid

    # ------------------------------------------------------------------
    # Pass 1: node creation
    # ------------------------------------------------------------------

    def _create_base_interface_node(
        self, iface_dict: InterfaceDict, base_container_uid: str
    ) -> str:
        """Creates one base interface node and links it to the base container.

        Intrinsic node data only — no membership resolution, no cross-slice
        inference.
        """
        kind = iface_dict.get("kind", "physical")
        name = iface_dict["name"]

        common_kwargs = dict(
            name=name,
            description=iface_dict.get("description"),
            mtu=iface_dict.get("mtu"),
            encapsulation=iface_dict.get("encapsulation"),
            vlan_tagging=iface_dict.get("vlan_tagging", False),
            flexible_vlan_tagging=iface_dict.get("flexible_vlan_tagging", False),
            native_vlan_id=iface_dict.get("native_vlan_id"),
        )

        if kind == "physical":
            node = PhysicalInterface(**common_kwargs)
            node.speed = iface_dict.get("speed", "auto")
            node.duplex = iface_dict.get("duplex", "auto")

            parent_name = iface_dict.get("member_of")
            if isinstance(parent_name, str):
                node.member_of_parent = parent_name
                if parent_name.startswith("ae"):
                    node.member_of_type = "ae"

        elif kind == "ae":
            node = AggEthInterface(**common_kwargs)
            node.minimum_links = iface_dict.get("minimum_links")
            node.lacp_mode = iface_dict.get("lacp_mode")
            node.lacp_periodic = iface_dict.get("lacp_periodic")

            mc_ae_data = iface_dict.get("mc_ae")
            if mc_ae_data:
                node.mc_ae = McAeOptions(
                    mc_ae_id=mc_ae_data.get("mc_ae_id"),
                    redundancy_group=mc_ae_data.get("redundancy_group"),
                    chassis_id=mc_ae_data.get("chassis_id"),
                    mode=mc_ae_data.get("mode"),
                    status_control=mc_ae_data.get("status_control"),
                )

        elif kind == "loopback":
            node = LoopbackInterface(**common_kwargs)

        elif kind == "tunnel":
            node = TunnelInterface(**common_kwargs)

        elif kind == "irb":
            node = IrbInterface(**common_kwargs)

        elif kind == "management":
            node = ManagementInterface(**common_kwargs)

        else:
            # Defensive fallback — unknown prefixes become physical so the
            # rest of the graph still builds cleanly.
            node = PhysicalInterface(**common_kwargs)
            node.speed = iface_dict.get("speed", "auto")
            node.duplex = iface_dict.get("duplex", "auto")

        uid = self.registry.register_node(node, f"interface|name={name}")
        self.registry.graph.add_relationship(
            base_container_uid, uid, label="base_interface"
        )
        return uid

    def _create_unit_interface_node(
        self,
        unit_dict: UnitInterfaceDict,
        parent_uid: str,
        unit_container_uid: str,
        parent_name: str,
    ) -> str:
        """Creates one unit interface node and links it to parent + container."""
        unit_value = unit_dict["name"]

        node = UnitInterface(
            name=f"{parent_name}.{unit_value}",
            parent_name=parent_name,
            unit=unit_value,
            description=unit_dict.get("description"),
            vlan_id=unit_dict.get("vlan_id"),
            mtu=unit_dict.get("mtu"),
            encapsulation=unit_dict.get("encapsulation"),
            is_l2=unit_dict.get("is_l2", False),
            filter_inet_input=unit_dict.get("filter_inet_input"),
            filter_inet_output=unit_dict.get("filter_inet_output"),
            filter_inet6_input=unit_dict.get("filter_inet6_input"),
            filter_inet6_output=unit_dict.get("filter_inet6_output"),
        )

        if "inet" in unit_dict:
            inet_data = unit_dict["inet"]
            addresses = inet_data.get("addresses", [])
            vrrp_vip = inet_data.get("vrrp_virtual_address")

            # Priority order for primary_address:
            #   1. VRRP virtual-address — this is the gateway IP clients use,
            #      so it is the most meaningful "primary" for IRB units.
            #   2. Explicit Junos <primary/> flag from the parser.
            #   3. Deterministic fallback: numerically lowest configured address.
            if vrrp_vip:
                primary = vrrp_vip
            else:
                primary = inet_data.get("primary_address")

            preferred = inet_data.get("preferred_address")

            if addresses:
                if len(addresses) == 1:
                    # Single address is both primary and preferred when no
                    # higher-priority override (VIP or explicit flag) is set.
                    # When a VRRP VIP is present it already owns primary, so
                    # skip the primary fallback but still apply preferred only
                    # if it was explicitly flagged by the parser (not the
                    # single-address shortcut — that would misleadingly mark
                    # the physical IP as "preferred" when the VIP is primary).
                    if not vrrp_vip:
                        primary = primary or addresses[0]
                        preferred = preferred or addresses[0]
                else:
                    lowest_ip = self._get_numerically_lowest_ip(addresses)
                    primary = primary or lowest_ip
                    if not vrrp_vip:
                        preferred = preferred or lowest_ip

            node.inet = FamilyInetSpec(
                addresses=addresses,
                primary_address=primary,
                preferred_address=preferred,
                vrrp_virtual_address=vrrp_vip,
                mtu=inet_data.get("mtu"),
                sampling_input=inet_data.get("sampling_input", False),
                sampling_output=inet_data.get("sampling_output", False),
            )

        if "inet6" in unit_dict:
            inet6_data = unit_dict["inet6"]
            addresses = inet6_data.get("addresses", [])

            primary = inet6_data.get("primary_address")
            preferred = inet6_data.get("preferred_address")

            if addresses:
                if len(addresses) == 1:
                    primary = primary or addresses[0]
                    preferred = preferred or addresses[0]
                else:
                    lowest_ip = self._get_numerically_lowest_ip(addresses)
                    primary = primary or lowest_ip
                    preferred = preferred or lowest_ip

            node.inet6 = FamilyInet6Spec(
                addresses=addresses,
                primary_address=primary,
                preferred_address=preferred,
                mtu=inet6_data.get("mtu"),
            )

        uid = self.registry.register_node(node, f"interface-unit|name={node.name}")

        self.registry.graph.add_relationship(
            unit_container_uid, uid, label="unit_interface"
        )
        self.registry.graph.add_relationship(parent_uid, uid, label="interface_unit")

        return uid

    def _get_numerically_lowest_ip(self, addresses: List[str]) -> Optional[str]:
        """Returns the numerically lowest CIDR from a list.

        Falls back to alphanumeric ordering if any address fails to parse
        (e.g. a malformed entry in a config dump).
        """
        if not addresses:
            return None
        try:
            return min(addresses, key=lambda x: ipaddress.ip_interface(x).ip)
        except ValueError:
            return min(addresses) if addresses else None

    # ------------------------------------------------------------------
    # Pass 2: membership resolution
    # ------------------------------------------------------------------

    def _link_memberships(self, iface_uid: str, data: InterfaceDict) -> None:
        """Resolves parsed membership strings into graph edges.

        On MX the only base-interface membership is physical -> AE.
        When a physical interface names an AE parent via ``member_of``, we
        emit a ``AggEthInterface -> PhysicalInterface`` edge labeled
        ``member_interface`` in the parent direction.
        """
        if data.get("kind") != "physical":
            return

        parent_name = data.get("member_of")
        if not parent_name:
            return

        parent_uid = self._lookup_base_interface_uid(parent_name)
        if parent_uid:
            self.registry.graph.add_relationship(
                parent_uid, iface_uid, label="member_interface"
            )

    def _lookup_base_interface_uid(self, name: str) -> Optional[str]:
        """Looks up a base interface UID by interface name.

        Limited to base interface node types. Unit interfaces are excluded.
        """
        key = f"interface|name={name}"

        for type_name in _BASE_INTERFACE_TYPES:
            uid = self.registry.index.get(type_name, {}).get(key)
            if uid:
                return uid

        return None


# end of lib/interface/factory.py
