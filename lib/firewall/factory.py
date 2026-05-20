"""Factory for the MX firewall slice.

Ingestion order contract (enforced by MXImporter):
    Firewall MUST be ingested AFTER policy-options and protocols-ports so that
    cross-slice edge wiring can resolve PrefixList and PortList UIDs that are
    already registered.  Routing instances have no dependency on firewall and
    follow afterward.

Cross-slice references
----------------------
FirewallTerm may reference:
  * ``PrefixList`` nodes  (source/destination prefix-list match conditions)
  * ``PortList`` nodes    (source/destination port-list match conditions)

Both are looked up via ``registry.index`` without importing the peer slice's
objects module, keeping this factory's imports strictly within the firewall
and protocols_ports helpers boundary.  Unresolved references emit a logged
warning and are omitted from graph edges — no placeholder nodes are created.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from lib.firewall.objects import (
    FirewallFilter,
    FirewallFilterContainer,
    FirewallRoot,
    FirewallTerm,
)
from lib.log_utils import get_logger
from lib.parsers.base import FirewallFilterDict, FirewallTermDict
from lib.protocols_ports.helpers import IcmpTypeMap, normalize_port_token, normalize_protocol
from lib.registry.graph import DataRegistry

logger = get_logger(__name__)


class FirewallFactory:
    """Builds the firewall sub-graph from parsed config data."""

    def __init__(self, registry: DataRegistry):
        self.registry = registry

    def ingest_firewall_filters(
        self, data: List[FirewallFilterDict], config_root_uid: str
    ) -> str:
        """Ingests firewall filter data and returns the FirewallRoot UID.

        Always creates the root and container nodes regardless of whether any
        filters are present, so the graph structure is consistent across
        configs that do and do not define firewall filters.

        Args:
            data:             Parsed filter data from the parser layer.
            config_root_uid:  UID of the ConfigRoot anchor.

        Returns:
            UID of the FirewallRoot node.
        """
        # 1. Root
        root = FirewallRoot(name="firewall")
        root_uid = self.registry.register_node(
            root, f"firewall-root|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            config_root_uid, root_uid, label="firewall_root"
        )

        # 2. Container
        container = FirewallFilterContainer(name="firewall-filters")
        container_uid = self.registry.register_node(
            container, f"firewall-filter-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(
            root_uid, container_uid, label="firewall_filter_container"
        )

        # 3. Filters
        for filter_data in data:
            self._create_filter(filter_data, container_uid)

        logger.info("Firewall ingested: %i filter(s).", len(data))
        return root_uid

    # ------------------------------------------------------------------
    # Filter creation
    # ------------------------------------------------------------------

    def _create_filter(self, data: FirewallFilterDict, container_uid: str) -> str:
        af = data["address_family"]
        node = FirewallFilter(
            name=data["name"],
            address_family=af,
            raw_config=data.get("raw_config", ""),
        )
        uid = self.registry.register_node(
            node, f"firewall-filter|af={af}|name={data['name']}"
        )
        self.registry.graph.add_relationship(container_uid, uid, label="firewall_filter")

        for idx, term_data in enumerate(data.get("terms", [])):
            self._create_term(term_data, uid, idx)

        return uid

    # ------------------------------------------------------------------
    # Term creation
    # ------------------------------------------------------------------

    def _create_term(
        self, data: FirewallTermDict, filter_uid: str, order: int
    ) -> str:
        from_conds = data.get("from_conditions") or {}

        term = FirewallTerm(
            name=data["name"],
            raw_config=data.get("raw_config", ""),
            # Inline normalized match conditions
            protocols=[
                self._normalize_protocol(tok)
                for tok in from_conds.get("protocols", [])
            ],
            source_addresses=list(from_conds.get("source_addresses", [])),
            destination_addresses=list(from_conds.get("destination_addresses", [])),
            ports=[
                self._normalize_port(tok)
                for tok in from_conds.get("ports", [])
            ],
            source_ports=[
                self._normalize_port(tok)
                for tok in from_conds.get("source_ports", [])
            ],
            destination_ports=[
                self._normalize_port(tok)
                for tok in from_conds.get("destination_ports", [])
            ],
            icmp_types=[
                self._normalize_icmp_type(tok)
                for tok in from_conds.get("icmp_types", [])
            ],
            tcp_established=bool(from_conds.get("tcp_established", False)),
            actions=list(data.get("actions", [])),
            count=data.get("count"),
            log=bool(data.get("log", False)),
            syslog=bool(data.get("syslog", False)),
        )
        term_uid = self.registry.register_node(
            term, f"firewall-term|filter={filter_uid}|name={data['name']}"
        )
        self.registry.graph.add_relationship(
            filter_uid, term_uid, label="firewall_term", order=order
        )

        self._wire_prefix_list_edges(term_uid, data["name"], from_conds)
        self._wire_port_list_edges(term_uid, data["name"], from_conds)

        return term_uid

    # ------------------------------------------------------------------
    # Cross-slice edge wiring
    # ------------------------------------------------------------------

    def _wire_prefix_list_edges(
        self, term_uid: str, term_name: str, from_conds: dict
    ) -> None:
        for pl_name in from_conds.get("source_prefix_lists", []):
            uid = self._resolve_prefix_list(
                pl_name,
                context=f"Firewall term '{term_name}' source-prefix-list",
            )
            if uid:
                self.registry.graph.add_relationship(
                    term_uid, uid, label="source_prefix_list"
                )

        for pl_name in from_conds.get("destination_prefix_lists", []):
            uid = self._resolve_prefix_list(
                pl_name,
                context=f"Firewall term '{term_name}' destination-prefix-list",
            )
            if uid:
                self.registry.graph.add_relationship(
                    term_uid, uid, label="destination_prefix_list"
                )

    def _wire_port_list_edges(
        self, term_uid: str, term_name: str, from_conds: dict
    ) -> None:
        for pl_name in from_conds.get("source_port_lists", []):
            uid = self._resolve_port_list(
                pl_name,
                context=f"Firewall term '{term_name}' source-port-list",
            )
            if uid:
                self.registry.graph.add_relationship(
                    term_uid, uid, label="source_port_list"
                )

        for pl_name in from_conds.get("destination_port_lists", []):
            uid = self._resolve_port_list(
                pl_name,
                context=f"Firewall term '{term_name}' destination-port-list",
            )
            if uid:
                self.registry.graph.add_relationship(
                    term_uid, uid, label="destination_port_list"
                )

    def _resolve_prefix_list(self, name: str, *, context: str) -> Optional[str]:
        uid = self.registry.index.get("PrefixList", {}).get(
            f"prefix-list|name={name}"
        )
        if uid is None:
            logger.warning(
                "%s references unknown PrefixList '%s'.", context, name
            )
        return uid

    def _resolve_port_list(self, name: str, *, context: str) -> Optional[str]:
        uid = self.registry.index.get("PortList", {}).get(
            f"port-list|name={name}"
        )
        if uid is None:
            logger.warning(
                "%s references unknown PortList '%s'.", context, name
            )
        return uid

    # ------------------------------------------------------------------
    # Normalization helpers (protocol / port / ICMP)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_protocol(token: str) -> Dict[str, Any]:
        np = normalize_protocol(token)
        return {
            "raw": np.raw,
            "number": np.number,
            "canonical_name": np.canonical_name,
        }

    @staticmethod
    def _normalize_port(token: str) -> Dict[str, Any]:
        np = normalize_port_token(token)
        return {
            "raw": np.raw,
            "kind": np.kind,
            "value": np.value,
            "low": np.low,
            "high": np.high,
            "canonical_name": np.canonical_name,
        }

    @staticmethod
    def _normalize_icmp_type(token: str) -> Dict[str, Any]:
        canonical, number = IcmpTypeMap.resolve(token)
        return {"raw": token, "number": number, "canonical_name": canonical}


# end of lib/firewall/factory.py
