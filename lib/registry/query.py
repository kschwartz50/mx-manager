"""Graph traversal engine (Tier 3).

Decoupled from any specific configuration slice. Operates purely on labels
and nodes in the registry's underlying GraphRegistry.
"""

from typing import Any, Dict, List, Optional, Set

from lib.registry.graph import DataRegistry


class QueryEngine:
    def __init__(self, registry: DataRegistry):
        self.r = registry

    def traverse(
        self,
        start_uid: str,
        path: List[str],
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Follows a sequential path of edge labels across the graph."""
        current_uids = {start_uid}

        for label in path:
            next_step_uids: Set[str] = set()
            for uid in current_uids:
                neighbors = self.r.graph.forward_map.get(uid, {}).get(label, {})
                for n_uid in neighbors.keys():
                    if filters and not self._matches(n_uid, filters):
                        continue
                    next_step_uids.add(n_uid)

            if not next_step_uids:
                return []
            current_uids = next_step_uids

        return list(current_uids)

    def reverse_traverse(self, start_uid: str, path: List[str]) -> List[str]:
        current_uids = {start_uid}
        for label in path:
            next_step_uids: Set[str] = set()
            for uid in current_uids:
                neighbors = self.r.graph.reverse_map.get(uid, {}).get(label, {})
                next_step_uids.update(neighbors.keys())
            if not next_step_uids:
                return []
            current_uids = next_step_uids
        return list(current_uids)

    def _matches(self, uid: str, filters: Dict[str, Any]) -> bool:
        node = self.r.storage.get(uid)
        if not node:
            return False
        for attr, expected_val in filters.items():
            if getattr(node, attr, None) != expected_val:
                return False
        return True
