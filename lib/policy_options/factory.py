"""Factory for the policy-options slice.

Ingestion order contract (enforced by the importer):
    policy-options MUST be ingested before routing instances so that BGP
    group wiring in RoutingInstanceFactory can resolve PolicyStatement nodes
    that already exist rather than creating forward-reference placeholders.
"""

from __future__ import annotations

from typing import List, Optional, cast

from lib.log_utils import get_logger
from lib.parsers.base import PolicyOptionsDict, PolicyTermDict
from lib.policy_options.objects import (
    AsPath,
    AsPathContainer,
    PolicyOptionsRoot,
    PolicyStatement,
    PolicyStatementContainer,
    PolicyTerm,
    PrefixList,
    PrefixListContainer,
)
from lib.registry.graph import DataRegistry

logger = get_logger(__name__)


class PolicyOptionsFactory:
    """Factory responsible for building the policy-options slice."""

    def __init__(self, registry: DataRegistry):
        self.registry = registry

    def _resolve_or_warn(
        self,
        node_type: str,
        unique_key: str,
        *,
        context: str,
        ref_name: str,
    ) -> Optional[str]:
        uid = self.registry.index.get(node_type, {}).get(unique_key)
        if uid:
            return uid
        logger.warning("%s references unknown %s '%s'.", context, node_type, ref_name)
        return None

    def ingest_policy_options(self, data: PolicyOptionsDict, config_root_uid: str) -> str:
        """Ingests all policy-options constructs and returns the root UID."""
        # 1. Top-level root
        root = PolicyOptionsRoot(name="policy-options")
        root_uid = self.registry.register_node(root, f"policy-options-root|root={config_root_uid}")
        self.registry.graph.add_relationship(config_root_uid, root_uid, label="policy_options_root")

        # 2. PrefixListContainer
        prefix_container = PrefixListContainer(name="prefix-lists")
        prefix_container_uid = self.registry.register_node(
            prefix_container, f"policy-options-prefix-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(root_uid, prefix_container_uid, label="prefix_list_container")

        # 3. PolicyStatementContainer
        statement_container = PolicyStatementContainer(name="policy-statements")
        statement_container_uid = self.registry.register_node(
            statement_container, f"policy-options-policy-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(root_uid, statement_container_uid, label="policy_statement_container")

        # 4. AsPathContainer
        as_path_container = AsPathContainer(name="as-paths")
        as_path_container_uid = self.registry.register_node(
            as_path_container, f"policy-options-as-path-container|root={config_root_uid}"
        )
        self.registry.graph.add_relationship(root_uid, as_path_container_uid, label="as_path_container")

        # 5. Ingest PrefixList nodes
        for pl in data["prefix_lists"]:
            node = PrefixList(name=pl["name"], prefixes=pl["prefixes"], raw_config=pl.get("raw_config", ""))
            uid = self.registry.register_node(node, f"prefix-list|name={pl['name']}")
            self.registry.graph.add_relationship(prefix_container_uid, uid, label="prefix_list")

        # 6. Ingest AsPath nodes
        for ap in data["as_paths"]:
            node = AsPath(name=ap["name"], path=ap["path"], raw_config=ap.get("raw_config", ""))
            uid = self.registry.register_node(node, f"as-path|name={ap['name']}")
            self.registry.graph.add_relationship(as_path_container_uid, uid, label="as_path")

        # 7. Ingest PolicyStatement nodes (terms wired inside)
        for ps in data["policy_statements"]:
            ps_node = PolicyStatement(name=ps["name"], raw_config=ps.get("raw_config", ""))
            ps_uid = self.registry.register_node(ps_node, f"policy|name={ps['name']}")
            self.registry.graph.add_relationship(
                statement_container_uid, ps_uid, label="policy_statement"
            )
            for idx, term_data in enumerate(ps["terms"]):
                self._create_policy_term(term_data, ps_uid, idx)

        return root_uid

    def _create_policy_term(self, data: PolicyTermDict, ps_uid: str, order: int) -> str:
        term_node = PolicyTerm(
            name=data["name"],
            raw_config=data.get("raw_config", ""),
            from_protocols=data.get("from_protocols", []),
            route_filters=cast(List[dict], data.get("from_route_filters", [])),
            actions=data["actions"],
            next_hop=data.get("next_hop"),
        )
        term_uid = self.registry.register_node(term_node, f"term|ps={ps_uid}|name={data['name']}")
        self.registry.graph.add_relationship(ps_uid, term_uid, label="policy_term", order=order)

        self._link_term_prefix_lists(term_uid, data)
        self._link_term_as_paths(term_uid, data)

        return term_uid

    def _link_term_prefix_lists(self, term_uid: str, data: PolicyTermDict) -> None:
        for pl_name in data.get("from_prefix_lists", []):
            pl_uid = self._resolve_or_warn(
                "PrefixList",
                f"prefix-list|name={pl_name}",
                context=f"Policy term '{data['name']}'",
                ref_name=pl_name,
            )
            if pl_uid:
                self.registry.graph.add_relationship(term_uid, pl_uid, label="matches_prefix_list")

    def _link_term_as_paths(self, term_uid: str, data: PolicyTermDict) -> None:
        for as_path_name in data.get("from_as_paths", []):
            as_path_uid = self._resolve_or_warn(
                "AsPath",
                f"as-path|name={as_path_name}",
                context=f"Policy term '{data['name']}'",
                ref_name=as_path_name,
            )
            if as_path_uid:
                self.registry.graph.add_relationship(term_uid, as_path_uid, label="matches_as_path")


# end of lib/policy_options/factory.py
