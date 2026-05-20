"""Dataclass hierarchy for the MX protocols-ports slice.

This slice owns two categories of constructs:

1. **User-defined config objects** — only ``PortList`` falls here.
   Port-lists are explicitly defined under ``<firewall>`` and are
   first-class graph nodes with factory-backed ingestion.

2. **Reserved containers** — ``ProtocolAliasContainer`` and
   ``PortAliasContainer`` exist for architectural symmetry and future
   extension.  They are wired into the graph but remain empty in v1.
   No factory code materializes built-in CLI vocabulary (``tcp``,
   ``ssh``, etc.) as graph nodes; built-ins are handled entirely by
   ``helpers.py`` normalization functions.

Graph relationships (read-only reference — the factory wires the edges):

    ConfigRoot -> ProtocolsPortsRoot            (label: "protocols_ports_root")
    ProtocolsPortsRoot -> PortListContainer     (label: "port_list_container")
    ProtocolsPortsRoot -> ProtocolAliasContainer (label: "protocol_alias_container")
    ProtocolsPortsRoot -> PortAliasContainer    (label: "port_alias_container")
    PortListContainer -> PortList               (label: "port_list")

Value objects (no graph identity):

    PortEntry — a single port or port-range entry on a PortList node.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import List, Literal, Optional

from lib.registry.objects import BaseNode

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortEntry:
    """A single port or port-range within a PortList.

    Value object — not a graph node, no UID, lives as an element of
    ``PortList.entries``.

    Attributes:
        raw:            Original config token (e.g. ``"ssh"``, ``"443"``,
                        ``"10000-19999"``).
        kind:           ``"single"`` for a single port; ``"range"`` for a range.
        value:          Resolved port number for ``kind="single"`` entries.
                        ``None`` when the token is a named service that could
                        not be resolved.
        low:            Lower bound (inclusive) for ``kind="range"`` entries.
        high:           Upper bound (inclusive) for ``kind="range"`` entries.
        canonical_name: Canonical service name for named ports (e.g.
                        ``"ssh"`` for ``"ssh"``), or ``None`` for numeric-only
                        entries.
    """

    raw: str
    kind: Literal["single", "range"]
    value: Optional[int] = None
    low: Optional[int] = None
    high: Optional[int] = None
    canonical_name: Optional[str] = None


# ---------------------------------------------------------------------------
# Container nodes
# ---------------------------------------------------------------------------


@dataclass(kw_only=True)
class ProtocolsPortsRoot(BaseNode):
    """Top-level anchor for the protocols-ports slice.

    Edges: ConfigRoot -> ProtocolsPortsRoot (label: "protocols_ports_root")
    """

    type: str = field(default="ProtocolsPortsRoot")


@dataclass(kw_only=True)
class PortListContainer(BaseNode):
    """Container holding user-defined PortList nodes.

    Edges: ProtocolsPortsRoot -> PortListContainer (label: "port_list_container")
    """

    type: str = field(default="PortListContainer")


@dataclass(kw_only=True)
class ProtocolAliasContainer(BaseNode):
    """Reserved container for user-defined protocol aliases.

    Empty in v1. Populated only when Junos config explicitly defines
    named protocol aliases — which is not supported in this parser version.

    Edges: ProtocolsPortsRoot -> ProtocolAliasContainer
           (label: "protocol_alias_container")
    """

    type: str = field(default="ProtocolAliasContainer")


@dataclass(kw_only=True)
class PortAliasContainer(BaseNode):
    """Reserved container for user-defined port aliases.

    Empty in v1. Populated only when Junos config explicitly defines
    named port aliases — which is not supported in this parser version.

    Edges: ProtocolsPortsRoot -> PortAliasContainer
           (label: "port_alias_container")
    """

    type: str = field(default="PortAliasContainer")


# ---------------------------------------------------------------------------
# Leaf nodes
# ---------------------------------------------------------------------------


@dataclass(kw_only=True)
class PortList(BaseNode):
    """A named list of ports and/or port ranges defined in config.

    Parsed from ``<firewall><port-list>`` stanzas.

    Edges: PortListContainer -> PortList (label: "port_list")

    Attributes:
        entries: Ordered list of ``PortEntry`` value objects.
    """

    entries: List[PortEntry] = field(default_factory=list)
    type: str = field(default="PortList")


# ---------------------------------------------------------------------------
# Reserved future nodes — not instantiated in v1
# ---------------------------------------------------------------------------


@dataclass(kw_only=True)
class ProtocolAlias(BaseNode):
    """Named protocol alias.

    Reserved for future use.  Not created by the v1 factory.

    Edges: ProtocolAliasContainer -> ProtocolAlias
           (label: "protocol_alias")
    """

    protocol_number: int = 0
    type: str = field(default="ProtocolAlias")


@dataclass(kw_only=True)
class PortAlias(BaseNode):
    """Named port alias.

    Reserved for future use.  Not created by the v1 factory.

    Edges: PortAliasContainer -> PortAlias (label: "port_alias")
    """

    port_number: int = 0
    type: str = field(default="PortAlias")


# end of lib/protocols_ports/objects.py
