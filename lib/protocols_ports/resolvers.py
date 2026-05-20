"""Resolver for the protocols-ports slice.

Tier-1 discipline: intra-slice only, UID-based, no cross-slice joins.

Graph traversal entry points:

    get_root(config_root_uid)
        -> ProtocolsPortsRoot UID

    get_port_list_container(root_uid)
        -> PortListContainer UID

    get_port_lists(container_uid)
        -> [PortList UIDs] (sorted by name)

    get_port_list_uid(name)
        -> UID of a named PortList (direct index lookup — O(1))

Normalization helpers are exposed as pass-through delegates so that the
firewall slice can import one module rather than two:

    normalize_protocol(token) -> NormalizedProtocol
    normalize_port_token(token) -> NormalizedPort
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from lib.protocols_ports.helpers import (
    NormalizedPort,
    NormalizedProtocol,
    normalize_port_token,
    normalize_protocol,
)
from lib.protocols_ports.objects import (
    PortList,
    PortListContainer,
    ProtocolsPortsRoot,
)
from lib.registry.graph import DataRegistry


class ProtocolsPortsResolver:
    """Tier-1 slice resolver for the protocols-ports domain."""

    def __init__(self, registry: DataRegistry):
        self.r = registry

    # ------------------------------------------------------------------
    # Container discovery
    # ------------------------------------------------------------------

    def get_root(self, config_root_uid: str) -> Optional[str]:
        """Returns the ProtocolsPortsRoot UID beneath a ConfigRoot."""
        for uid in self._edge_uids(config_root_uid, "protocols_ports_root"):
            if isinstance(self.r.storage.get(uid), ProtocolsPortsRoot):
                return uid
        return None

    def get_port_list_container(self, root_uid: str) -> Optional[str]:
        """Returns the PortListContainer UID beneath a ProtocolsPortsRoot."""
        for uid in self._edge_uids(root_uid, "port_list_container"):
            if isinstance(self.r.storage.get(uid), PortListContainer):
                return uid
        return None

    # ------------------------------------------------------------------
    # PortList discovery
    # ------------------------------------------------------------------

    def get_port_lists(self, container_uid: str) -> List[str]:
        """Returns sorted PortList UIDs beneath a PortListContainer."""
        return self._sort_uids_by_name(self._edge_uids(container_uid, "port_list"))

    def get_port_list_uid(self, name: str) -> Optional[str]:
        """Direct O(1) lookup of a PortList UID by name.

        Preferred over graph traversal when the firewall slice needs to
        resolve a ``source-port-list`` / ``destination-port-list`` reference.
        Returns None if the named port-list was never ingested.
        """
        return self.r.index.get("PortList", {}).get(f"port-list|name={name}")

    # ------------------------------------------------------------------
    # Hydration
    # ------------------------------------------------------------------

    def hydrate_port_list(self, uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates a PortList node by UID."""
        node = self.r.storage.get(uid)
        if not isinstance(node, PortList):
            return None
        return {
            "uid": node.uid,
            "name": node.name,
            "entries": [
                {
                    "raw": e.raw,
                    "kind": e.kind,
                    "value": e.value,
                    "low": e.low,
                    "high": e.high,
                    "canonical_name": e.canonical_name,
                }
                for e in node.entries
            ],
            "raw_config": getattr(node, "raw_config", ""),
            "type": node.type,
        }

    # ------------------------------------------------------------------
    # Normalization delegates
    # (pass-through so callers import one module)
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_protocol(token: str) -> NormalizedProtocol:
        """Delegate to helpers.normalize_protocol."""
        return normalize_protocol(token)

    @staticmethod
    def normalize_port(token: str) -> NormalizedPort:
        """Delegate to helpers.normalize_port_token."""
        return normalize_port_token(token)

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

    def _sort_uids_by_name(self, uids: List[str]) -> List[str]:
        return sorted(
            uids,
            key=lambda uid: (
                getattr(self.r.storage.get(uid), "name", "").casefold()
                if self.r.storage.get(uid)
                else ""
            ),
        )


# end of lib/protocols_ports/resolvers.py
