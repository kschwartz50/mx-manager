from __future__ import annotations

from typing import (  # noqa: F401 – Literal used by get_bgp_policies
    Any,
    Dict,
    List,
    Literal,
    Optional,
)

from lib.log_utils import get_logger
from lib.policy_options.objects import PolicyStatement  # noqa
from lib.registry.graph import DataRegistry
from lib.routing.objects import (
    BgpGroup,
    BgpNeighbor,
    RoutingInstance,
    StaticRoute,
)

logger = get_logger(__name__)


class RoutingInstanceResolver:
    """
    Tier 1 slice resolver for the routing domain.

    Scope:
        - Intra-slice only
        - UID-based discovery and honest hydration
        - No cross-slice joins
    """

    def __init__(self, registry: DataRegistry):
        """
        Initializes the routing resolver.

        Args:
            registry: Shared data registry containing node storage, indexes,
                and graph edges.
        """
        self.r = registry

    # ------------------------------------------------------------------
    # Discovery methods
    # ------------------------------------------------------------------
    def get_instances(self, config_root_uid: str) -> List[str]:
        """
        Returns RoutingInstance UIDs beneath a ConfigRoot.

        Args:
            config_root_uid: UID of the ConfigRoot node.

        Returns:
            Sorted list of RoutingInstance UIDs.
        """
        uids = self._edge_uids(config_root_uid, "routing_instance")
        return self._sort_uids_by_name(uids)

    def get_instance_interfaces(self, ri_uid: str) -> List[str]:
        """
        Returns UnitInterface UIDs attached to a routing instance.

        Args:
            ri_uid: UID of the RoutingInstance node.

        Returns:
            Sorted list of UnitInterface UIDs.
        """
        uids = self._edge_uids(ri_uid, "instance_interface")
        return self._sort_uids_by_name(uids)

    def get_ordered_static_routes(self, ri_uid: str) -> List[str]:
        """
        Returns StaticRoute UIDs in graph order.

        Args:
            ri_uid: UID of the RoutingInstance node.

        Returns:
            Ordered list of StaticRoute UIDs based on edge order.
        """
        return self._ordered_edge_uids(ri_uid, "static_route")

    def get_unit_routing_instance(self, unit_uid: str) -> Optional[str]:
        """
        Reverse-looks up the routing instance for an interface unit.

        Args:
            unit_uid: UID of the UnitInterface node.

        Returns:
            UID of the parent RoutingInstance if found, otherwise None.
        """
        parents = self.r.graph.reverse_map.get(unit_uid, {}).get(
            "instance_interface", {}
        )
        if isinstance(parents, dict):
            return next(iter(parents.keys()), None)
        if isinstance(parents, set):
            return next(iter(parents), None)
        return None

    def get_bgp_groups(self, ri_uid: str) -> List[str]:
        """
        Returns BgpGroup UIDs attached to a routing instance.

        Args:
            ri_uid: UID of the RoutingInstance node.

        Returns:
            Sorted list of BgpGroup UIDs.
        """
        uids = self._edge_uids(ri_uid, "bgp_group")
        return self._sort_uids_by_name(uids)

    def get_bgp_neighbors(self, group_uid: str) -> List[str]:
        """
        Returns BgpNeighbor UIDs attached to a BGP group.

        Args:
            group_uid: UID of the BgpGroup node.

        Returns:
            Sorted list of BgpNeighbor UIDs.
        """
        uids = self._edge_uids(group_uid, "bgp_neighbor")
        return self._sort_uids_by_name(uids)

    def get_bgp_policies(
        self, group_uid: str, label: Literal["import_policy", "export_policy"]
    ) -> List[str]:
        """
        Returns PolicyStatement UIDs attached to a BGP group in graph order.

        Args:
            group_uid: UID of the BgpGroup node.
            label: Either ``import_policy`` or ``export_policy``.

        Returns:
            Ordered list of PolicyStatement UIDs based on edge order.
        """
        return self._ordered_edge_uids(group_uid, label)

    # ------------------------------------------------------------------
    # Hydration methods
    # ------------------------------------------------------------------
    def hydrate_routing_instance(
        self,
        uid: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Hydrates a RoutingInstance node by UID.

        Notes:
            Routing instance hydration itself is honest node hydration and does not expand joined context.

        Args:
            uid: UID of the RoutingInstance node.

        Returns:
            Dictionary representation of the routing instance, or None if the
            UID does not map to a RoutingInstance.
        """
        node = self.r.storage.get(uid)
        if not isinstance(node, RoutingInstance):
            return None

        return {
            "uid": node.uid,
            "name": node.name,
            "instance_type": node.instance_type,
            "description": node.description,
            "type": node.type,
        }

    def hydrate_static_route(
        self,
        uid: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Hydrates a StaticRoute node by UID.

        Notes:
            Static route hydration is honest node hydration and does not perform cross-slice joins.
        """
        node = self.r.storage.get(uid)
        if not isinstance(node, StaticRoute):
            return None

        return {
            "uid": node.uid,
            "name": node.name,
            "destination": node.destination,
            "next_hops": [
                {
                    "kind": nh.kind,
                    "ip_address": nh.ip_address,
                    "interface": nh.interface,
                    "next_table": nh.next_table,
                    "preference": nh.preference,
                    "metric": nh.metric,
                    "qualified": nh.qualified,
                }
                for nh in node.next_hops
            ],
            "discard": node.discard,
            "reject": node.reject,
            "preference": node.preference,
            "tag": node.tag,
            "description": node.description,
            "type": node.type,
        }

    def hydrate_bgp_group(
        self,
        uid: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Hydrates a BgpGroup node by UID.

        Notes:
            BGP group hydration is honest node hydration only.

        Args:
            uid: UID of the BgpGroup node.

        Returns:
            Dictionary representation of the BGP group, or None if the UID
            does not map to a BgpGroup.
        """
        node = self.r.storage.get(uid)
        if not isinstance(node, BgpGroup):
            return None

        return {
            "uid": node.uid,
            "name": node.name,
            "bgp_type": node.bgp_type,
            "peer_as": node.peer_as,
            "local_as": node.local_as,
            "hold_time": node.hold_time,
            "multipath": node.multipath,
            "remove_private": node.remove_private,
            "type": node.type,
        }

    def hydrate_bgp_neighbor(
        self,
        uid: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Hydrates a BgpNeighbor node by UID.

        Notes:
            BGP neighbor hydration is honest node hydration only.

        Args:
            uid: UID of the BgpNeighbor node.

        Returns:
            Dictionary representation of the BGP neighbor, or None if the UID
            does not map to a BgpNeighbor.
        """
        node = self.r.storage.get(uid)
        if not isinstance(node, BgpNeighbor):
            return None

        return {
            "uid": node.uid,
            "name": node.name,
            "peer_address": node.peer_address,
            "local_address": node.local_address,
            "description": node.description,
            "type": node.type,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _edge_uids(self, parent_uid: str, label: str) -> List[str]:
        """
        Returns child UIDs for a given edge label.

        This helper tolerates either set-backed edges or dict-backed edges
        with property bags.

        Args:
            parent_uid: UID of the parent node.
            label: Edge label to inspect.

        Returns:
            List of child UIDs.
        """
        edges = self.r.graph.forward_map.get(parent_uid, {}).get(label, {})
        if isinstance(edges, dict):
            return list(edges.keys())
        if isinstance(edges, set):
            return list(edges)
        return []

    def _ordered_edge_uids(self, parent_uid: str, label: str) -> List[str]:
        """
        Returns child UIDs sorted by edge order.

        Supports both direct ``order`` fields and nested ``edge_props.order``
        shapes so the resolver is resilient to graph storage details.

        Args:
            parent_uid: UID of the parent node.
            label: Edge label to inspect.

        Returns:
            Ordered list of child UIDs.
        """
        edges = self.r.graph.forward_map.get(parent_uid, {}).get(label, {})

        if isinstance(edges, set):
            return self._sort_uids_by_name(list(edges))

        if not isinstance(edges, dict):
            return []

        def _order(uid: str) -> int:
            edge_data = edges.get(uid, {})
            if not isinstance(edge_data, dict):
                return 999999
            if "order" in edge_data:
                return edge_data.get("order", 999999)
            return edge_data.get("edge_props", {}).get("order", 999999)

        return sorted(edges.keys(), key=_order)

    def _sort_uids_by_name(self, uids: List[str]) -> List[str]:
        """
        Sorts UIDs by node name.

        Args:
            uids: List of node UIDs.

        Returns:
            Sorted list of UIDs using case-insensitive node name ordering.
        """
        return sorted(
            uids,
            key=lambda uid: (
                getattr(self.r.storage.get(uid), "name", "").casefold()
                if self.r.storage.get(uid)
                else ""
            ),
        )


# end of lib/routing/resolvers.py
