"""Dataclass hierarchy for the MX firewall slice.

This slice owns four node types:

* ``FirewallRoot``            — top-level anchor, one per ConfigRoot
* ``FirewallFilterContainer`` — container holding all filters
* ``FirewallFilter``          — a named Junos firewall filter
* ``FirewallTerm``            — a single term (rule) within a filter

Graph relationships (wired by FirewallFactory):

    ConfigRoot
      └─[firewall_root]─> FirewallRoot
            └─[firewall_filter_container]─> FirewallFilterContainer
                    └─[firewall_filter]─> FirewallFilter
                            └─[firewall_term, order=N]─> FirewallTerm
                                    ├─[source_prefix_list]──────> PrefixList
                                    ├─[destination_prefix_list]─> PrefixList
                                    ├─[source_port_list]────────> PortList
                                    └─[destination_port_list]───> PortList

Cross-slice edges are resolved at factory time against the registry index.
Unresolved references emit a warning and are omitted (invariant 1.3).

Protocol and port match conditions are stored inline on FirewallTerm as
normalized dicts (via helpers.normalize_protocol / normalize_port_token) —
built-in CLI vocabulary is never materialized as graph nodes (invariant 7.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lib.registry.objects import BaseNode


# ---------------------------------------------------------------------------
# Container nodes
# ---------------------------------------------------------------------------


@dataclass(kw_only=True)
class FirewallRoot(BaseNode):
    """Top-level anchor for the firewall slice.

    Edges: ConfigRoot -> FirewallRoot  (label: "firewall_root")
    """

    type: str = field(default="FirewallRoot")


@dataclass(kw_only=True)
class FirewallFilterContainer(BaseNode):
    """Container holding all FirewallFilter nodes for a config.

    Edges: FirewallRoot -> FirewallFilterContainer
           (label: "firewall_filter_container")
    """

    type: str = field(default="FirewallFilterContainer")


# ---------------------------------------------------------------------------
# Leaf nodes
# ---------------------------------------------------------------------------


@dataclass(kw_only=True)
class FirewallFilter(BaseNode):
    """A named Junos firewall filter (access-list equivalent).

    Parsed from:
      * ``<firewall><filter>``                     → address_family = "any"
      * ``<firewall><family><inet><filter>``        → address_family = "inet"
      * ``<firewall><family><inet6><filter>``       → address_family = "inet6"

    Edges: FirewallFilterContainer -> FirewallFilter
           (label: "firewall_filter")
           FirewallFilter -> FirewallTerm
           (label: "firewall_term", ordered)

    Attributes:
        address_family: ``"inet"``, ``"inet6"``, or ``"any"``.
    """

    address_family: str = "inet"
    type: str = field(default="FirewallFilter")


@dataclass(kw_only=True)
class FirewallTerm(BaseNode):
    """A single term (rule) within a Junos firewall filter.

    Match conditions
    ----------------
    protocols
        Resolved from ``<protocol>`` (inet) or ``<next-header>`` (inet6)
        tokens.  Each entry is a dict::

            {"raw": "tcp", "number": 6, "canonical_name": "tcp"}

        Produced by ``helpers.normalize_protocol()``.  Unknown numeric
        protocol values are preserved; unknown names produce
        ``number=None``.

    source_addresses / destination_addresses
        Inline CIDR prefixes from ``<source-address><name>`` /
        ``<destination-address><name>`` elements.

    ports / source_ports / destination_ports
        Resolved from ``<port>``, ``<source-port>``,
        ``<destination-port>`` tokens.  Each entry is a dict::

            {"raw": "bgp", "kind": "single", "value": 179,
             "low": None, "high": None, "canonical_name": "bgp"}
            {"raw": "10000-19999", "kind": "range", "value": None,
             "low": 10000, "high": 19999, "canonical_name": None}

        Produced by ``helpers.normalize_port_token()``.

    icmp_types
        Resolved from ``<icmp-type>`` tokens.  Each entry is a dict::

            {"raw": "echo-request", "number": 8, "canonical_name": "echo-request"}

        Produced by ``helpers.IcmpTypeMap.resolve()``.

    tcp_established
        ``True`` when ``<tcp-established/>`` appears in the from clause.

    Cross-slice references (wired as labeled graph edges by the factory)
    -----------------------------------------
    source_prefix_list      → PrefixList  (edge label: "source_prefix_list")
    destination_prefix_list → PrefixList  (edge label: "destination_prefix_list")
    source_port_list        → PortList    (edge label: "source_port_list")
    destination_port_list   → PortList    (edge label: "destination_port_list")

    Actions
    -------
    actions
        List of terminal/non-terminal action strings: ``"accept"``,
        ``"reject"``, ``"discard"``, ``"next-term"``, ``"sample"``.
    count
        Counter name string when ``<count>name</count>`` is present,
        else ``None``.
    log
        ``True`` when ``<log/>`` is present in the then clause.
    syslog
        ``True`` when ``<syslog/>`` is present in the then clause.
    """

    # Inline normalized match conditions
    protocols: List[Dict[str, Any]] = field(default_factory=list)
    source_addresses: List[str] = field(default_factory=list)
    destination_addresses: List[str] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    source_ports: List[Dict[str, Any]] = field(default_factory=list)
    destination_ports: List[Dict[str, Any]] = field(default_factory=list)
    icmp_types: List[Dict[str, Any]] = field(default_factory=list)
    tcp_established: bool = False

    # Actions
    actions: List[str] = field(default_factory=list)
    count: Optional[str] = None
    log: bool = False
    syslog: bool = False

    type: str = field(default="FirewallTerm")


# end of lib/firewall/objects.py
