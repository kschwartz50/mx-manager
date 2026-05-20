"""Tier 1 resolver for the MX interface slice.

Provides UID-based, graph-faithful access to interface content. Scoped to
the interface slice only — no cross-slice joins, no exporter shaping, no
reporting concerns. Those belong in a future GlobalResolver / exporter.

Graph shape this resolver reads from:

* ``InterfaceConfigRoot``
    * ``BaseInterfaceContainer``
        * ``BaseInterfaceNode`` subclasses
    * ``UnitInterfaceContainer``
        * ``UnitInterface``

Key relationships:

* ``InterfaceConfigRoot -> BaseInterfaceContainer`` via ``base_interface_container``
* ``InterfaceConfigRoot -> UnitInterfaceContainer`` via ``unit_interface_container``
* ``BaseInterfaceContainer -> BaseInterfaceNode`` via ``base_interface``
* ``UnitInterfaceContainer -> UnitInterface`` via ``unit_interface``
* ``BaseInterfaceNode -> UnitInterface`` via ``interface_unit``
* ``AggEthInterface -> PhysicalInterface`` via ``member_interface``
"""

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from lib.interface.objects import (
    AggEthInterface,
    BaseInterfaceNode,
    IrbInterface,
    ManagementInterface,
    PhysicalInterface,
    UnitInterface,
)
from lib.registry.graph import DataRegistry


class InterfaceResolver:
    """Tier 1 resolver for pure interface-slice graph access.

    Exposes only UID-based discovery and hydration. Does not resolve zones,
    routing-instances, policy usage, or any other cross-slice context — those
    would live in a later GlobalResolver-equivalent.
    """

    def __init__(self, registry: DataRegistry):
        """Initializes the resolver.

        Args:
            registry: Shared graph/data registry containing interface nodes
                and relationships.
        """
        self.r = registry

    # -------------------------------------------------------------------------
    # Slice Root + Container Discovery
    # -------------------------------------------------------------------------

    def get_interface_config_root(self, config_root_uid: str) -> Optional[str]:
        """Returns the interface slice root for a config root."""
        root_links = self.r.graph.forward_map.get(config_root_uid, {}).get(
            "interface_config_root", {}
        )
        return next(iter(root_links), None) if root_links else None

    def get_base_container(self, interface_root_uid: str) -> Optional[str]:
        """Returns the base-interface container for an interface slice root."""
        links = self.r.graph.forward_map.get(interface_root_uid, {}).get(
            "base_interface_container", {}
        )
        return next(iter(links), None) if links else None

    def get_unit_container(self, interface_root_uid: str) -> Optional[str]:
        """Returns the unit-interface container for an interface slice root."""
        links = self.r.graph.forward_map.get(interface_root_uid, {}).get(
            "unit_interface_container", {}
        )
        return next(iter(links), None) if links else None

    def get_container(self, config_root_uid: str) -> Optional[str]:
        """Backward-compatible entry point that returns the interface slice root."""
        return self.get_interface_config_root(config_root_uid)

    # -------------------------------------------------------------------------
    # Base Interface Discovery
    # -------------------------------------------------------------------------

    def get_all_base_interfaces(self, container_uid: str) -> List[str]:
        """Returns all base interface UIDs in the base-interface container."""
        return list(
            self.r.graph.forward_map.get(container_uid, {})
            .get("base_interface", {})
            .keys()
        )

    def get_member_interfaces(self, parent_uid: str) -> List[str]:
        """Returns graph-confirmed members of an AE parent.

        Reads only the graph; unresolved parser strings are ignored.
        """
        return list(
            self.r.graph.forward_map.get(parent_uid, {})
            .get("member_interface", {})
            .keys()
        )

    def get_parent_interface(self, child_uid: str) -> Optional[str]:
        """Returns the graph parent for a unit or member interface.

        * ``UnitInterface`` child -> owning ``BaseInterfaceNode`` via reverse
          ``interface_unit``
        * physical member child -> owning ``AggEthInterface`` via reverse
          ``member_interface``
        """
        rev_links = self.r.graph.reverse_map.get(child_uid, {})

        if "interface_unit" in rev_links:
            for candidate_uid in rev_links["interface_unit"].keys():
                candidate = self.r.storage.get(candidate_uid)
                if isinstance(candidate, BaseInterfaceNode):
                    return candidate_uid

        if "member_interface" in rev_links:
            for candidate_uid in rev_links["member_interface"].keys():
                candidate = self.r.storage.get(candidate_uid)
                if isinstance(candidate, BaseInterfaceNode):
                    return candidate_uid

        return None

    # -------------------------------------------------------------------------
    # Unit Discovery
    # -------------------------------------------------------------------------

    def get_all_unit_uids(self, container_uid: str) -> List[str]:
        """Returns all logical unit UIDs in the unit-interface container."""
        return list(
            self.r.graph.forward_map.get(container_uid, {})
            .get("unit_interface", {})
            .keys()
        )

    def get_units_for_interface(self, interface_uid: str) -> List[str]:
        """Returns logical units owned by a base interface."""
        return list(
            self.r.graph.forward_map.get(interface_uid, {})
            .get("interface_unit", {})
            .keys()
        )

    def get_unit_addresses(self, unit_uid: str) -> List[str]:
        """Returns all (v4 + v6) addresses configured on a unit."""
        node = self.r.storage.get(unit_uid)
        addresses: List[str] = []
        if not isinstance(node, UnitInterface):
            return addresses
        if node.inet:
            addresses.extend(node.inet.addresses)
        if node.inet6:
            addresses.extend(node.inet6.addresses)
        return addresses

    def get_unit_v4_address_context(self, unit_uid: str) -> List[str]:
        """Returns v4 addresses annotated with primary/preferred flags."""
        node = self.r.storage.get(unit_uid)
        if not isinstance(node, UnitInterface) or not node.inet:
            return []
        return self._annotate_addresses(
            node.inet.addresses,
            primary=node.inet.primary_address,
            preferred=node.inet.preferred_address,
        )

    def get_unit_v6_address_context(self, unit_uid: str) -> List[str]:
        """Returns v6 addresses annotated with primary/preferred flags."""
        node = self.r.storage.get(unit_uid)
        if not isinstance(node, UnitInterface) or not node.inet6:
            return []
        return self._annotate_addresses(
            node.inet6.addresses,
            primary=node.inet6.primary_address,
            preferred=node.inet6.preferred_address,
        )

    # -------------------------------------------------------------------------
    # Hydration
    # -------------------------------------------------------------------------

    def hydrate_unit(self, unit_uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates a unit interface using interface-slice truth only.

        MX-specific additions over srx-manager: ``encapsulation`` and
        ``is_l2`` are surfaced, because exporters need to segregate bridged
        units from L3 units.
        """
        node = self.r.storage.get(unit_uid)
        if not isinstance(node, UnitInterface):
            return None

        return {
            "uid": node.uid,
            "name": node.name,
            "unit": node.unit,
            "parent_name": node.parent_name,
            "description": node.description,
            "vlan_id": node.vlan_id,
            "mtu": node.mtu,
            "encapsulation": node.encapsulation,
            "is_l2": node.is_l2,
            "addresses": self.get_unit_addresses(unit_uid),
            "v4_address_context": self.get_unit_v4_address_context(unit_uid),
            "v6_address_context": self.get_unit_v6_address_context(unit_uid),
        }

    def hydrate_base_interface(self, iface_uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates a base interface using interface-slice truth only.

        Includes intrinsic attributes plus graph-confirmed membership
        references where relevant. MX-specific additions: ``encapsulation``,
        ``flexible_vlan_tagging``, ``vlan_tagging``, ``native_vlan_id``, and
        (on AE) ``mc_ae``.
        """
        node = self.r.storage.get(iface_uid)
        if not isinstance(node, BaseInterfaceNode):
            return None

        data: Dict[str, Any] = {
            "uid": node.uid,
            "name": node.name,
            "kind": node.kind,
            "description": node.description,
            "mtu": node.mtu,
            "encapsulation": node.encapsulation,
            "vlan_tagging": node.vlan_tagging,
            "flexible_vlan_tagging": node.flexible_vlan_tagging,
            "native_vlan_id": node.native_vlan_id,
        }

        if isinstance(node, AggEthInterface):
            data["member_interfaces"] = [
                self._lightweight_ref(member_uid)
                for member_uid in self.get_member_interfaces(iface_uid)
            ]
            data["lacp_mode"] = node.lacp_mode
            data["lacp_periodic"] = node.lacp_periodic
            data["minimum_links"] = node.minimum_links
            data["mc_ae"] = asdict(node.mc_ae) if node.mc_ae else None

        if isinstance(node, PhysicalInterface):
            data["speed"] = node.speed
            data["duplex"] = node.duplex
            data["member_of_type"] = node.member_of_type
            data["member_of_parent"] = node.member_of_parent

        # IrbInterface and ManagementInterface currently expose no extra
        # intrinsic fields beyond the shared BaseInterfaceNode set — kind
        # alone is the discriminator. Leave a seam for future extension.
        if isinstance(node, (IrbInterface, ManagementInterface)):
            pass

        return data

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _annotate_addresses(
        self,
        addresses: List[str],
        primary: Optional[str],
        preferred: Optional[str],
    ) -> List[str]:
        """Formats addresses with ``(primary)``, ``(preferred)``, or both."""
        annotated: List[str] = []
        for addr in addresses:
            if addr == primary and addr == preferred:
                annotated.append(f"{addr} (primary/preferred)")
            elif addr == primary:
                annotated.append(f"{addr} (primary)")
            elif addr == preferred:
                annotated.append(f"{addr} (preferred)")
            else:
                annotated.append(addr)
        return annotated

    def _lightweight_ref(self, uid: str) -> Dict[str, Optional[str]]:
        """Builds a lightweight reference for an interface node."""
        node = self.r.storage.get(uid)
        return {
            "uid": uid,
            "name": getattr(node, "name", None),
        }


# end of lib/interface/resolvers.py
