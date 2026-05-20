"""Factory for the protocols-ports slice.

Ingestion order: after interfaces and policy-options, before routing instances.
PortList nodes have no dependencies on other slices.

Only ``PortList`` nodes are created from config data.  The
``ProtocolAliasContainer`` and ``PortAliasContainer`` are wired into the
graph for architectural completeness but remain empty in v1 — no factory
method populates built-in CLI vocabulary as graph nodes.
"""

from __future__ import annotations

from typing import List, Optional

from lib.log_utils import get_logger
from lib.parsers.base import PortListDict
from lib.protocols_ports.helpers import normalize_port_token
from lib.protocols_ports.objects import (
    PortAliasContainer,
    PortEntry,
    PortList,
    PortListContainer,
    ProtocolAliasContainer,
    ProtocolsPortsRoot,
)
from lib.registry.graph import DataRegistry

logger = get_logger(__name__)


class ProtocolsPortsFactory:
    """Builds the protocols-ports sub-graph from parsed config data."""

    def __init__(self, registry: DataRegistry):
        self.registry = registry

    def ingest_port_lists(
        self, data: List[PortListDict], config_root_uid: str
    ) -> str:
        """Ingests port-list config and returns the ProtocolsPortsRoot UID.

        Always creates the four container nodes regardless of whether any
        port-list data exists, so the graph structure is consistent across
        configs that do and do not define port-lists.

        Args:
            data: Parsed port-list data from the parser layer.
            config_root_uid: UID of the ConfigRoot anchor.

        Returns:
            UID of the ProtocolsPortsRoot node.
        """
        # 1. Root
        root = ProtocolsPortsRoot(name="protocols-ports")
        root_uid = self.registry.register_node(
            root, f"protocols-ports-root|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            config_root_uid, root_uid, label="protocols_ports_root"
        )

        # 2. PortListContainer
        pl_container = PortListContainer(name="port-lists")
        pl_container_uid = self.registry.register_node(
            pl_container, f"port-list-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            root_uid, pl_container_uid, label="port_list_container"
        )

        # 3. ProtocolAliasContainer — reserved, empty in v1
        proto_container = ProtocolAliasContainer(name="protocol-aliases")
        proto_container_uid = self.registry.register_node(
            proto_container, f"protocol-alias-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            root_uid, proto_container_uid, label="protocol_alias_container"
        )

        # 4. PortAliasContainer — reserved, empty in v1
        port_alias_container = PortAliasContainer(name="port-aliases")
        port_alias_container_uid = self.registry.register_node(
            port_alias_container, f"port-alias-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            root_uid, port_alias_container_uid, label="port_alias_container"
        )

        # 5. Ingest user-defined PortList nodes
        for pl_data in data:
            self._create_port_list(pl_data, pl_container_uid)

        logger.info(
            "Protocols/ports ingested: %i port-list(s).", len(data)
        )
        return root_uid

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _create_port_list(self, data: PortListDict, container_uid: str) -> str:
        """Creates a PortList node and registers it under the container."""
        entries = [
            self._build_port_entry(raw_token)
            for raw_token in data.get("entries", [])
        ]

        node = PortList(
            name=data["name"],
            raw_config=data.get("raw_config", ""),
            entries=entries,
        )
        uid = self.registry.register_node(node, f"port-list|name={data['name']}")
        self.registry.graph.add_relationship(container_uid, uid, label="port_list")
        return uid

    def _build_port_entry(self, raw_token: str) -> PortEntry:
        """Converts a raw port token to a PortEntry value object."""
        normalized = normalize_port_token(raw_token)
        return PortEntry(
            raw=normalized.raw,
            kind=normalized.kind if normalized.kind != "unknown" else "single",
            value=normalized.value,
            low=normalized.low,
            high=normalized.high,
            canonical_name=normalized.canonical_name,
        )

    def _resolve_uid(self, node_type: str, unique_key: str) -> Optional[str]:
        return self.registry.index.get(node_type, {}).get(unique_key)


# end of lib/protocols_ports/factory.py
