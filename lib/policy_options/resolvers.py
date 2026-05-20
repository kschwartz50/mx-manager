"""Resolver for the policy-options slice.

Tier-1 discipline: intra-slice only, UID-based, no cross-slice joins.

Graph traversal entry points:

    get_root(config_root_uid)
        -> PolicyOptionsRoot UID

    get_prefix_list_container(root_uid)
        -> PrefixListContainer UID

    get_as_path_container(root_uid)
        -> AsPathContainer UID

    get_policy_statement_container(root_uid)
        -> PolicyStatementContainer UID

    get_prefix_lists(pl_container_uid)      -> [PrefixList UIDs]
    get_as_paths(as_path_container_uid)     -> [AsPath UIDs]
    get_policy_statements(ps_container_uid) -> [PolicyStatement UIDs]
    get_ordered_terms(ps_uid)               -> [PolicyTerm UIDs] (ordered)
    get_term_prefix_lists(term_uid)         -> [PrefixList UIDs]
    get_term_as_paths(term_uid)             -> [AsPath UIDs]
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

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


class PolicyOptionsResolver:
    """Tier 1 slice resolver for the policy-options domain."""

    def __init__(self, registry: DataRegistry):
        self.r = registry

    # ------------------------------------------------------------------
    # Container discovery
    # ------------------------------------------------------------------

    def get_root(self, config_root_uid: str) -> Optional[str]:
        """Returns the PolicyOptionsRoot UID beneath a ConfigRoot."""
        for uid in self._edge_uids(config_root_uid, "policy_options_root"):
            if isinstance(self.r.storage.get(uid), PolicyOptionsRoot):
                return uid
        return None

    def get_prefix_list_container(self, root_uid: str) -> Optional[str]:
        """Returns the PrefixListContainer UID beneath a PolicyOptionsRoot."""
        for uid in self._edge_uids(root_uid, "prefix_list_container"):
            if isinstance(self.r.storage.get(uid), PrefixListContainer):
                return uid
        return None

    def get_as_path_container(self, root_uid: str) -> Optional[str]:
        """Returns the AsPathContainer UID beneath a PolicyOptionsRoot."""
        for uid in self._edge_uids(root_uid, "as_path_container"):
            if isinstance(self.r.storage.get(uid), AsPathContainer):
                return uid
        return None

    def get_policy_statement_container(self, root_uid: str) -> Optional[str]:
        """Returns the PolicyStatementContainer UID beneath a PolicyOptionsRoot."""
        for uid in self._edge_uids(root_uid, "policy_statement_container"):
            if isinstance(self.r.storage.get(uid), PolicyStatementContainer):
                return uid
        return None

    # ------------------------------------------------------------------
    # Leaf discovery
    # ------------------------------------------------------------------

    def get_prefix_lists(self, container_uid: str) -> List[str]:
        """Returns sorted PrefixList UIDs beneath a PrefixListContainer."""
        return self._sort_uids_by_name(self._edge_uids(container_uid, "prefix_list"))

    def get_as_paths(self, container_uid: str) -> List[str]:
        """Returns sorted AsPath UIDs beneath an AsPathContainer."""
        return self._sort_uids_by_name(self._edge_uids(container_uid, "as_path"))

    def get_policy_statements(self, container_uid: str) -> List[str]:
        """Returns sorted PolicyStatement UIDs beneath a PolicyStatementContainer."""
        return self._sort_uids_by_name(self._edge_uids(container_uid, "policy_statement"))

    def get_ordered_terms(self, ps_uid: str) -> List[str]:
        """Returns PolicyTerm UIDs for a policy statement in graph order."""
        return self._ordered_edge_uids(ps_uid, "policy_term")

    def get_term_prefix_lists(self, term_uid: str) -> List[str]:
        """Returns sorted PrefixList UIDs matched by a policy term."""
        return self._sort_uids_by_name(self._edge_uids(term_uid, "matches_prefix_list"))

    def get_term_as_paths(self, term_uid: str) -> List[str]:
        """Returns sorted AsPath UIDs matched by a policy term."""
        return self._sort_uids_by_name(self._edge_uids(term_uid, "matches_as_path"))

    def find_policy_usage(self, ps_uid: str) -> Dict[str, List[str]]:
        """Reverse-looks up where a policy statement is referenced (BGP groups)."""
        usage = self.r.graph.reverse_map.get(ps_uid, {})
        results: Dict[str, List[str]] = {}
        for label, parents in usage.items():
            if "policy" not in label:
                continue
            if isinstance(parents, dict):
                parent_uids = list(parents.keys())
            elif isinstance(parents, set):
                parent_uids = list(parents)
            else:
                parent_uids = []
            results[label] = self._sort_uids_by_name(parent_uids)
        return results

    # ------------------------------------------------------------------
    # Hydration
    # ------------------------------------------------------------------

    def hydrate_prefix_list(self, uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates a PrefixList node by UID."""
        node = self.r.storage.get(uid)
        if not isinstance(node, PrefixList):
            return None
        return {"uid": node.uid, "name": node.name, "prefixes": list(node.prefixes), "raw_config": getattr(node, "raw_config", ""), "type": node.type}

    def hydrate_as_path(self, uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates an AsPath node by UID."""
        node = self.r.storage.get(uid)
        if not isinstance(node, AsPath):
            return None
        return {"uid": node.uid, "name": node.name, "path": node.path, "raw_config": getattr(node, "raw_config", ""), "type": node.type}

    def hydrate_policy_statement(self, uid: str, include_terms: bool = False) -> Optional[Dict[str, Any]]:
        """Hydrates a PolicyStatement node by UID."""
        node = self.r.storage.get(uid)
        if not isinstance(node, PolicyStatement):
            return None
        result: Dict[str, Any] = {"uid": node.uid, "name": node.name, "raw_config": getattr(node, "raw_config", ""), "type": node.type}
        if include_terms:
            result["terms"] = [
                hydrated
                for term_uid in self.get_ordered_terms(uid)
                for hydrated in [self.hydrate_policy_term(term_uid)]
                if hydrated is not None
            ]
        return result

    def hydrate_policy_term(self, uid: str) -> Optional[Dict[str, Any]]:
        """Hydrates a PolicyTerm node by UID."""
        node = self.r.storage.get(uid)
        if not isinstance(node, PolicyTerm):
            return None
        return {
            "uid": node.uid,
            "name": node.name,
            "from_protocols": list(node.from_protocols),
            "route_filters": list(node.route_filters),
            "prefix_lists": [self._lightweight_ref(pl_uid) for pl_uid in self.get_term_prefix_lists(uid)],
            "as_paths": [self._lightweight_ref(ap_uid) for ap_uid in self.get_term_as_paths(uid)],
            "actions": list(node.actions),
            "next_hop": node.next_hop,
            "raw_config": getattr(node, "raw_config", ""),
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
        return sorted(uids, key=lambda uid: (getattr(self.r.storage.get(uid), "name", "").casefold() if self.r.storage.get(uid) else ""))

    def _lightweight_ref(self, uid: str) -> Dict[str, Any]:
        node = self.r.storage.get(uid)
        return {"uid": uid, "name": getattr(node, "name", None) if node else None}


# end of lib/policy_options/resolvers.py
