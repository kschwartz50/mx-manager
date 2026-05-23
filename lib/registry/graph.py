"""In-memory labeled graph structure and data registry."""

import ipaddress
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Dict

from lib.registry.objects import BaseNode

logger = logging.getLogger(__name__)


class RegistryEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(
            o,
            (
                ipaddress.IPv4Network,
                ipaddress.IPv4Address,
                ipaddress.IPv6Network,
                ipaddress.IPv6Address,
            ),
        ):
            return str(o)
        if isinstance(o, set):
            return list(o)
        return super().default(o)


class GraphRegistry:
    """Bidirectional labeled graph with edge properties.

    Forward: source_uid -> {label -> {target_uid -> {properties}}}
    Reverse: target_uid -> {label -> {source_uid -> {properties}}}
    """

    def __init__(self):
        self.forward_map: Dict[str, Dict[str, Dict[str, dict]]] = {}
        self.reverse_map: Dict[str, Dict[str, Dict[str, dict]]] = {}

    def add_relationship(
        self, source_uid: str, target_uid: str, label: str, **properties
    ):
        """Creates a bidirectionally queryable labeled edge with optional properties."""
        self.forward_map.setdefault(source_uid, {}).setdefault(label, {})[
            target_uid
        ] = properties
        self.reverse_map.setdefault(target_uid, {}).setdefault(label, {})[
            source_uid
        ] = properties

    def remove_relationship(self, source_uid: str, target_uid: str, label: str):
        """Tears down specific edges."""
        if label in self.forward_map.get(source_uid, {}):
            self.forward_map[source_uid][label].pop(target_uid, None)
        if label in self.reverse_map.get(target_uid, {}):
            self.reverse_map[target_uid][label].pop(source_uid, None)


class DataRegistry:
    """Centralized registry for all nodes and their relationships.

    - Store all nodes with unique UIDs.
    - Maintain forward and reverse relationship maps with properties.
    - Provide serialization/deserialization for persistence.
    """

    def __init__(self):
        self.storage: Dict[str, BaseNode] = {}
        self.index: Dict[str, Dict[str, str]] = {}
        self.graph = GraphRegistry()

    def register_node(self, node: BaseNode, unique_key: str) -> str:
        node_type = node.type
        self.index.setdefault(node_type, {})

        if unique_key in self.index[node_type]:
            return self.index[node_type][unique_key]

        self.storage[node.uid] = node
        self.index[node_type][unique_key] = node.uid
        return node.uid

    def save_to_json(self, filepath: Path):
        data = {
            "storage": {uid: asdict(node) for uid, node in self.storage.items()},
            "forward_map": self.graph.forward_map,
            "reverse_map": self.graph.reverse_map,
            "index": self.index,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4, cls=RegistryEncoder)
        logger.info(f"Registry snapshot saved: {filepath}")

    def load_from_json(self, filepath: Path):
        """Not implemented — raises to prevent silent data loss.

        ``save_to_json()`` serialises every node via ``dataclasses.asdict()``,
        which discards concrete type information.  Rehydrating back to the
        correct subclass (``PhysicalInterface``, ``AggEthInterface``, …)
        requires a type-registry that does not exist yet.  Until that is
        built, any caller of this method would get an empty ``self.storage``
        while ``forward_map``/``reverse_map``/``index`` point at UIDs that
        resolve to nothing — an inconsistent registry that fails silently.

        To implement properly:
            1. Add a ``_TYPE_MAP: Dict[str, type]`` that maps each ``type``
               string to its dataclass.
            2. Iterate ``data["storage"]``, look up the ``type`` field, and
               reconstruct the object with ``cls(**fields)``.
            3. Assign to ``self.storage``.
        """
        raise NotImplementedError(
            "load_from_json() is not yet implemented: storage rehydration "
            "requires a type-registry.  See the docstring for details."
        )
