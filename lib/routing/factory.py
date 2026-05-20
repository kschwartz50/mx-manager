from typing import List, Optional, cast

from lib.log_utils import get_logger
from lib.parsers.base import (
    BgpGroupDict,
    RoutingInstanceDict,
    StaticRouteDict,
)
from lib.policy_options.objects import PolicyStatement
from lib.registry.graph import DataRegistry
from lib.routing.objects import (
    BgpGroup,
    BgpNeighbor,
    InstanceType,
    NextHopSpec,
    RoutingInstance,
    StaticRoute,
)

logger = get_logger(__name__)


class RoutingInstanceFactory:
    """
    Factory responsible for building Routing Instances and Static Routes.
    Leverages edge properties for route ordering.
    """

    def __init__(self, registry: DataRegistry):
        self.registry = registry

    # -------------------------------------------------------------------------
    # CRITICAL HELPER: Resolves unique keys to UIDs. Logs a warning on failure.
    # Keep this method DRY and use it across all reference resolutions in this factory.
    # Keep these at the top of the class for visibility.
    # -------------------------------------------------------------------------
    def _resolve_or_warn(
        self,
        node_type: str,
        unique_key: str,
        *,
        context: str,
        ref_name: str,
    ) -> Optional[str]:
        """
        Resolves a registry UID by unique key and logs a warning if unresolved.

        Args:
            node_type: Registry node type bucket (for example ``UnitInterface``).
            unique_key: Exact unique key used by the registry index.
            context: Human-readable context for the warning message.
            ref_name: Original parsed reference name.

        Returns:
            The resolved UID if found, otherwise None.
        """
        uid = self.registry.index.get(node_type, {}).get(unique_key)
        if uid:
            return uid

        logger.warning(
            "%s references unknown %s '%s'.",
            context,
            node_type,
            ref_name,
        )
        return None

    def _resolve_uid(self, node_type: str, unique_key: str) -> Optional[str]:
        """Resolves a registry UID by unique key without logging."""
        return self.registry.index.get(node_type, {}).get(unique_key)

    # ----------- End of critical helpers -------------------------------------

    def ingest_routing_instances(
        self, instances_data: List[RoutingInstanceDict], config_root_uid: str
    ):
        for ri_data in instances_data:
            # 1. Create and Register Routing Instance
            ri_node = RoutingInstance(
                name=ri_data["name"],
                instance_type=cast(InstanceType, ri_data["instance_type"]),
                description=ri_data.get("description"),
            )
            ri_uid = self.registry.register_node(
                ri_node, f"routing-instance|name={ri_node.name}"
            )
            self.registry.graph.add_relationship(
                config_root_uid, ri_uid, label="routing_instance"
            )

            # 2. Map Interfaces
            for iface_name in ri_data.get("interfaces", []):
                unit_uid = self._resolve_or_warn(
                    "UnitInterface",
                    f"interface-unit|name={iface_name}",
                    context=f"Routing instance '{ri_data['name']}'",
                    ref_name=iface_name,
                )
                if unit_uid:
                    self.registry.graph.add_relationship(
                        ri_uid,
                        unit_uid,
                        label="instance_interface",
                    )

            # 3. Create Static Routes (with ordering)
            for idx, route_data in enumerate(ri_data.get("static_routes", [])):
                self._create_static_route(route_data, ri_uid, idx)

            # 4. NEW: Create BGP Groups
            for group_data in ri_data.get("bgp_groups", []):
                self._create_bgp_group(group_data, ri_uid)

    def _create_bgp_group(self, data: BgpGroupDict, ri_uid: str):
        group_node = BgpGroup(
            name=data["name"],
            bgp_type=data["bgp_type"],  # type: ignore (handled by TypedDict)
            peer_as=data.get("peer_as"),
            local_as=data.get("local_as"),
        )
        group_uid = self.registry.register_node(
            group_node, f"bgp-group|ri={ri_uid}|name={group_node.name}"
        )
        self.registry.graph.add_relationship(ri_uid, group_uid, label="bgp_group")

        # Handle Policies (Idempotent registration)
        for idx, p_name in enumerate(data["import_policies"]):
            p_uid = self._ensure_policy_node(p_name)
            self.registry.graph.add_relationship(
                group_uid, p_uid, label="import_policy", order=idx
            )

        for idx, p_name in enumerate(data["export_policies"]):
            p_uid = self._ensure_policy_node(p_name)
            self.registry.graph.add_relationship(
                group_uid, p_uid, label="export_policy", order=idx
            )

        # Handle Neighbors
        for nbr_data in data["neighbors"]:
            nbr_node = BgpNeighbor(
                name=nbr_data["name"],
                peer_address=nbr_data["name"],
                local_address=nbr_data.get("local_address"),
                description=nbr_data.get("description"),
            )
            nbr_uid = self.registry.register_node(
                nbr_node, f"bgp-neighbor|group={group_uid}|ip={nbr_node.peer_address}"
            )
            self.registry.graph.add_relationship(
                group_uid, nbr_uid, label="bgp_neighbor"
            )

    def _ensure_policy_node(self, policy_name: str) -> str:
        """Returns the existing PolicyStatement UID or creates a placeholder node."""
        existing_uid = self._resolve_uid(
            "PolicyStatement",
            f"policy|name={policy_name}",
        )
        if existing_uid:
            return existing_uid

        p_node = PolicyStatement(name=policy_name)
        return self.registry.register_node(p_node, f"policy|name={policy_name}")

    def _create_static_route(self, data: StaticRouteDict, ri_uid: str, order: int):
        # Convert NextHopDicts to frozen NextHopSpec value objects
        next_hops = []
        for nh in data.get("next_hops", []):
            spec = NextHopSpec(
                kind=nh["kind"],
                ip_address=nh.get("ip_address"),
                interface=nh.get("interface"),
                next_table=nh.get("next_table"),
                preference=nh.get("preference"),
                metric=nh.get("metric"),
                qualified=nh.get("qualified", False),
            )
            next_hops.append(spec)

        route_node = StaticRoute(
            name=data["destination"],
            destination=data["destination"],
            next_hops=next_hops,
            discard=data.get("discard", False),
            reject=data.get("reject", False),
            preference=data.get("preference"),
            tag=data.get("tag"),
            description=data.get("description"),
        )

        # Unique key includes RI to allow same prefix in different VRFs
        unique_key = f"static-route|ri={ri_uid}|dest={route_node.destination}"
        route_uid = self.registry.register_node(route_node, unique_key)

        # Draw edge with order property
        self.registry.graph.add_relationship(
            ri_uid, route_uid, label="static_route", order=order
        )

    def _lookup_unit_uid(self, name: str) -> Optional[str]:
        """Resolves an interface-unit name to its UID with warning logging."""
        return self._resolve_or_warn(
            "UnitInterface",
            f"interface-unit|name={name}",
            context="Routing factory",
            ref_name=name,
        )


# end of lib/routing/factory.py
