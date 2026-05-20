"""Tier-1 resolver for the MX firewall slice.

Tier-1 discipline: intra-slice only, UID-based, read-only, no cross-slice
joins.  Cross-slice UIDs (PrefixList, PortList) are exposed as raw UID lists
in hydrated term dicts.  Dereferencing those UIDs to names is the
responsibility of ``FirewallContextBuilder`` in the export layer.

Graph traversal entry points:

    get_root(config_root_uid)
        -> FirewallRoot UID

    get_filter_container(root_uid)
        -> FirewallFilterContainer UID

    get_filters(container_uid)
        -> [FirewallFilter UIDs] (sorted by name)

    get_ordered_terms(filter_uid)
        -> [FirewallTerm UIDs] in ingestion order

    get_source_prefix_lists(term_uid)   -> [PrefixList UIDs]
    get_destination_prefix_lists(term_uid) -> [PrefixList UIDs]
    get_source_port_lists(term_uid)     -> [PortList UIDs]
    get_destination_port_lists(term_uid) -> [PortList UIDs]
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from lib.firewall.objects import (
    FirewallFilter,
    FirewallFilterContainer,
    FirewallRoot,
    FirewallTerm,
)
from lib.registry.graph import DataRegistry


class FirewallResolver:
    """Tier-1 slice resolver for the firewall domain."""

    def __init__(self, registry: DataRegistry):
        self.r = registry

    # ------------------------------------------------------------------
    # Container discovery
    # ------------------------------------------------------------------

    def get_root(self, config_root_uid: str) -> Optional[str]:
        """Returns the FirewallRoot UID beneath a ConfigRoot."""
        for uid in self._edge_uids(config_root_uid, "firewall_root"):
            if isinstance(self.r.storage.get(uid), FirewallRoot):
                return uid
        return None

    def get_filter_container(self, root_uid: str) -> Optional[str]:
        """Returns the FirewallFilterContainer UID beneath a FirewallRoot."""
        for uid in self._edge_uids(root_uid, "firewall_filter_container"):
            if isinstance(self.r.storage.get(uid), FirewallFilterContainer):
                return uid
        return None

    # ------------------------------------------------------------------
    # Filter and term discovery
    # ------------------------------------------------------------------

    def get_filters(self, container_uid: str) -> List[str]:
        """Returns all FirewallFilter UIDs sorted by name."""
        return self._sort_uids_by_name(
            self._edge_uids(container_uid, "firewall_filter")
        )

    def get_ordered_terms(self, filter_uid: str) -> List[str]:
        """Returns FirewallTerm UIDs in their ingestion (rule) order."""
        return self._ordered_edge_uids(filter_uid, "firewall_term")

    # ------------------------------------------------------------------
    # Cross-slice UID accessors (raw UIDs; caller resolves names)
    # ------------------------------------------------------------------

    def get_source_prefix_lists(self, term_uid: str) -> List[str]:
        return self._edge_uids(term_uid, "source_prefix_list")

    def get_destination_prefix_lists(self, term_uid: str) -> List[str]:
        return self._edge_uids(term_uid, "destination_prefix_list")

    def get_source_port_lists(self, term_uid: str) -> List[str]:
        return self._edge_uids(term_uid, "source_port_list")

    def get_destination_port_lists(self, term_uid: str) -> List[str]:
        return self._edge_uids(term_uid, "destination_port_list")

    # ------------------------------------------------------------------
    # Hydration
    # ------------------------------------------------------------------

    def hydrate_filter(self, uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates a FirewallFilter node by UID."""
        node = self.r.storage.get(uid)
        if not isinstance(node, FirewallFilter):
            return None
        return {
            "uid": node.uid,
            "name": node.name,
            "address_family": node.address_family,
            "raw_config": getattr(node, "raw_config", ""),
            "type": node.type,
        }

    def hydrate_term(self, uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates a FirewallTerm node by UID.

        Cross-slice references are returned as UID lists under
        ``*_uids`` keys.  The export-layer context builder resolves them to
        names by accessing registry storage directly.
        """
        node = self.r.storage.get(uid)
        if not isinstance(node, FirewallTerm):
            return None
        return {
            "uid": node.uid,
            "name": node.name,
            "protocols": list(node.protocols),
            "source_addresses": list(node.source_addresses),
            "destination_addresses": list(node.destination_addresses),
            "ports": list(node.ports),
            "source_ports": list(node.source_ports),
            "destination_ports": list(node.destination_ports),
            "icmp_types": list(node.icmp_types),
            "tcp_established": node.tcp_established,
            # Cross-slice UIDs — resolved to names by FirewallContextBuilder
            "source_prefix_list_uids": self.get_source_prefix_lists(uid),
            "destination_prefix_list_uids": self.get_destination_prefix_lists(uid),
            "source_port_list_uids": self.get_source_port_lists(uid),
            "destination_port_list_uids": self.get_destination_port_lists(uid),
            "actions": list(node.actions),
            "count": node.count,
            "log": node.log,
            "syslog": node.syslog,
            "type": node.type,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _edge_uids(self, parent_uid: str, label: str) -> List[str]:
        edges = self.r.graph.forward_map.get(parent_uid, {}).get(label, {})
        if isinstance(edges, dict):
            return list(edges.keys())
        if isinstance(edges, set):
            return list(edges)
        return []

    def _ordered_edge_uids(self, parent_uid: str, label: str) -> List[str]:
        """Returns target UIDs sorted by the ``order`` edge property."""
        edges = self.r.graph.forward_map.get(parent_uid, {}).get(label, {})
        if not isinstance(edges, dict):
            return list(edges) if edges else []
        return [
            uid
            for uid, _ in sorted(
                edges.items(),
                key=lambda kv: (
                    kv[1].get("order", 0) if isinstance(kv[1], dict) else 0
                ),
            )
        ]

    def _sort_uids_by_name(self, uids: List[str]) -> List[str]:
        return sorted(
            uids,
            key=lambda uid: (
                getattr(self.r.storage.get(uid), "name", "").casefold()
                if self.r.storage.get(uid)
                else ""
            ),
        )


# end of lib/firewall/resolvers.py
