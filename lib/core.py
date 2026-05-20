"""Core data structures for MX configuration objects.

Key Components:
- BaseNode: The foundational class for all configuration elements, providing
  a consistent schema for serialization and graph mapping.
- ConfigRoot: Top-level configuration file anchor for the graph.
- ScopeCtx: Scope context (platform, device_id, tenant, logical_system).
"""

import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class BaseNode:
    """The foundation for every configuration element."""

    uid: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    raw_config: str = ""
    metadata: Dict = field(default_factory=dict)
    type: str = "BaseNode"


@dataclass
class ConfigRoot(BaseNode):
    """The top-level abstraction representing the source configuration file."""

    file_path: str = ""
    type: str = "ConfigRoot"


@dataclass(frozen=True)
class ScopeCtx:
    platform: str = "mx"
    device_id: str = "device"
    tenant: Optional[str] = None
    logical_system: Optional[str] = None
