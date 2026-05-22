"""Junos MX configuration parser.

Targets Junos 21.x but most of the interface grammar is stable back to 17.x.
Scoped to interface configurations for v1 of mx-manager.

Key MX-vs-SRX differences this parser handles:

* MX does not have ``reth`` or ``fab`` interfaces — those are SRX HA
  constructs. They are intentionally not recognized here.
* MX frequently uses ``flexible-vlan-tagging`` instead of ``vlan-tagging``.
* MX units commonly carry an ``encapsulation`` element (vlan-bridge, vlan-ccc,
  vlan-vpls, etc.) for L2 services. We capture it and flag the unit as L2 when
  the encapsulation indicates bridging rather than L3 termination.
* MX AE bundles may carry ``mc-ae`` (multi-chassis aggregated ethernet) state.
* MX exposes ``irb`` as a distinct interface kind whose units are the L3
  gateways for bridge-domains.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from .base import (
    AsPathDict,
    BaseMXParser,
    BgpGroupDict,
    BgpNeighborDict,
    FamilyDict,
    FirewallFilterDict,
    FirewallTermDict,
    InterfaceDict,
    InterfaceKind,
    McAeDict,
    NextHopDict,
    PolicyOptionsDict,
    PolicyStatementDict,
    PolicyTermDict,
    PortListDict,
    PrefixListDict,
    RoutingInstanceDict,
    StaticRouteDict,
    TermFromDict,
    UnitInterfaceDict,
)
from .helpers import get_int, get_raw_xml, get_text, sanitize_junos_xml

# ---------------------------------------------------------------------------
# Next-hop classification helpers
# ---------------------------------------------------------------------------

# Matches dotted-decimal IPv4 addresses (and bare IPv4 with no prefix).
# IPv6 addresses always contain at least one ':'.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,}:[0-9a-fA-F:]*$")


def _classify_next_hop_text(text: str) -> str:
    """Return the NextHopKind for a plain <next-hop> text value.

    Rules (in order):
    * IPv4 dotted-decimal  → ``"ip"``
    * IPv6 colon-hex       → ``"ip"``
    * anything else        → ``"interface"``  (e.g. ``ae0.0``, ``xe-0/0/0.0``)
    """
    t = text.strip()
    if _IPV4_RE.match(t) or _IPV6_RE.match(t):
        return "ip"
    return "interface"


# L2 encapsulations seen on MX logical units. If a unit carries one of these,
# treat it as L2-only (no inet/inet6 termination expected, but we still look).
_L2_UNIT_ENCAPSULATIONS = {
    "vlan-bridge",
    "vlan-ccc",
    "vlan-tcc",
    "vlan-vpls",
    "ethernet-bridge",
    "ethernet-ccc",
    "ethernet-tcc",
    "ethernet-vpls",
    "ppp-over-ether",
}


class MXParser21x(BaseMXParser):
    """Parser for Junos 21.x MX configurations using ElementTree.

    The parser is intentionally defensive: unknown interface prefixes fall
    through to ``physical`` rather than raising, so the same parser can be
    reused for configs that happen to include a prefix we haven't mapped.
    """

    def __init__(self, xml_data: bytes):
        super().__init__(xml_data)
        try:
            self.root = ET.fromstring(sanitize_junos_xml(self.xml_data))
        except ET.ParseError as e:
            raise ValueError(f"Invalid MX XML: {e}") from e

    # ------------------------------------------------------------------
    # Interface entrypoint
    # ------------------------------------------------------------------

    def parse_interface_configs(self) -> List[InterfaceDict]:
        """Extract all base interfaces and their units from the XML.

        Notes:
            Only the top-level ``<interfaces>`` block is consumed here.
            Interfaces that exist solely under ``<groups>`` (such as ``fxp0``
            defined under the ``re0``/``re1`` management groups) are not
            materialized. If you need those, merge apply-groups first in a
            pre-pass or extend this method to walk ``<groups>`` explicitly.
        """
        interfaces: List[InterfaceDict] = []
        ifaces_root = self.root.find("./interfaces")
        if ifaces_root is None:
            return interfaces

        for iface_elem in ifaces_root.findall("interface"):
            parsed_iface = self._process_interface(iface_elem)
            if parsed_iface:
                interfaces.append(parsed_iface)

        return interfaces

    # ------------------------------------------------------------------
    # Per-interface processing
    # ------------------------------------------------------------------

    def _classify_interface_kind(self, name: str) -> InterfaceKind:
        """Map a Junos interface name to a first-class kind for the graph."""
        # Physical carriers on MX: ge, xe, et, fe, so (SONET), ce (channelized)
        if name.startswith(("ge-", "xe-", "et-", "fe-", "so-", "ce-")):
            return "physical"
        if name.startswith("ae"):
            return "ae"
        if name.startswith("irb"):
            return "irb"
        if name in ("lo0",) or name.startswith("lo"):
            return "loopback"
        if name.startswith(("gr-", "st", "ip-")):
            return "tunnel"
        # fxp = RE management, em = on-chassis management
        if name.startswith(("fxp", "em")):
            return "management"
        return "physical"

    def _process_interface(self, elem: ET.Element) -> Optional[InterfaceDict]:
        name = get_text(elem, "name")
        if not name:
            return None

        kind = self._classify_interface_kind(name)

        iface_dict: InterfaceDict = {
            "name": name,
            "kind": kind,
            "raw_config": get_raw_xml(elem),
            "units": [],
        }

        desc = get_text(elem, "description")
        if desc:
            iface_dict["description"] = desc

        mtu = get_int(elem, "mtu")
        if mtu is not None:
            iface_dict["mtu"] = mtu

        # VLAN tagging flags. Junos emits these as empty self-closing tags.
        if elem.find("vlan-tagging") is not None:
            iface_dict["vlan_tagging"] = True
        if elem.find("flexible-vlan-tagging") is not None:
            iface_dict["flexible_vlan_tagging"] = True

        nvid = get_int(elem, "native-vlan-id")
        if nvid is not None:
            iface_dict["native_vlan_id"] = nvid

        enc = get_text(elem, "encapsulation")
        if enc:
            iface_dict["encapsulation"] = enc

        # Kind-specific traits
        if kind == "physical":
            self._extract_physical_options(elem, iface_dict)
        elif kind == "ae":
            self._extract_ae_options(elem, iface_dict)

        # Units
        for unit_elem in elem.findall("unit"):
            unit_data = self._process_unit(unit_elem)
            if unit_data:
                iface_dict["units"].append(unit_data)

        return iface_dict

    # ------------------------------------------------------------------
    # Option extractors
    # ------------------------------------------------------------------

    def _extract_physical_options(
        self, elem: ET.Element, iface_dict: InterfaceDict
    ) -> None:
        """Pull AE bundle membership from gigether-options/ether-options.

        MX uses `gigether-options` for 1G and 10G and `ether-options` on some
        MPCs. Both may contain `ieee-802.3ad/bundle` naming an `aeN` parent.
        """
        for opt_tag in ("gigether-options", "ether-options"):
            opts = elem.find(opt_tag)
            if opts is None:
                continue
            ae_parent = opts.find("ieee-802.3ad/bundle")
            if ae_parent is not None and ae_parent.text:
                iface_dict["member_of"] = ae_parent.text.strip()
                return

    def _extract_ae_options(
        self, elem: ET.Element, iface_dict: InterfaceDict
    ) -> None:
        """Pull LACP, minimum-links, and MC-AE from aggregated-ether-options."""
        ae_opts = elem.find("aggregated-ether-options")
        if ae_opts is None:
            return

        min_links = get_int(ae_opts, "minimum-links")
        if min_links is not None:
            iface_dict["minimum_links"] = min_links

        self._extract_lacp(ae_opts, iface_dict)

        mc_ae = ae_opts.find("mc-ae")
        if mc_ae is not None:
            mc: McAeDict = {}
            mcid = get_int(mc_ae, "mc-ae-id")
            if mcid is not None:
                mc["mc_ae_id"] = mcid
            rg = get_int(mc_ae, "redundancy-group")
            if rg is not None:
                mc["redundancy_group"] = rg
            ch = get_int(mc_ae, "chassis-id")
            if ch is not None:
                mc["chassis_id"] = ch
            mode = get_text(mc_ae, "mode")
            if mode:
                mc["mode"] = mode
            sc = get_text(mc_ae, "status-control")
            if sc:
                mc["status_control"] = sc
            if mc:
                iface_dict["mc_ae"] = mc

    def _extract_lacp(
        self, parent_opts: ET.Element, target_dict: InterfaceDict
    ) -> None:
        """Extract LACP mode and periodic settings."""
        lacp = parent_opts.find("lacp")
        if lacp is None:
            return
        if lacp.find("active") is not None:
            target_dict["lacp_mode"] = "active"
        elif lacp.find("passive") is not None:
            target_dict["lacp_mode"] = "passive"

        periodic = get_text(lacp, "periodic")
        if periodic:
            target_dict["lacp_periodic"] = periodic

    # ------------------------------------------------------------------
    # Units
    # ------------------------------------------------------------------

    def _process_unit(self, elem: ET.Element) -> Optional[UnitInterfaceDict]:
        name = get_text(elem, "name")
        if not name:
            return None

        unit_dict: UnitInterfaceDict = {
            "name": name,
            "raw_config": get_raw_xml(elem),
        }

        desc = get_text(elem, "description")
        if desc:
            unit_dict["description"] = desc

        vlan = get_int(elem, "vlan-id")
        if vlan is not None:
            unit_dict["vlan_id"] = vlan

        mtu = get_int(elem, "mtu")
        if mtu is not None:
            unit_dict["mtu"] = mtu

        enc = get_text(elem, "encapsulation")
        if enc:
            unit_dict["encapsulation"] = enc
            if enc in _L2_UNIT_ENCAPSULATIONS:
                unit_dict["is_l2"] = True

        family = elem.find("family")
        if family is not None:
            inet = family.find("inet")
            if inet is not None:
                unit_dict["inet"] = self._process_family(inet)
                inp = get_text(inet, "filter/input/filter-name")
                if inp:
                    unit_dict["filter_inet_input"] = inp
                out = get_text(inet, "filter/output/filter-name")
                if out:
                    unit_dict["filter_inet_output"] = out

            inet6 = family.find("inet6")
            if inet6 is not None:
                unit_dict["inet6"] = self._process_family(inet6)
                inp6 = get_text(inet6, "filter/input/filter-name")
                if inp6:
                    unit_dict["filter_inet6_input"] = inp6
                out6 = get_text(inet6, "filter/output/filter-name")
                if out6:
                    unit_dict["filter_inet6_output"] = out6

            # A unit with <family><bridge/></family> is L2 even if no
            # encapsulation is set at the unit level.
            if family.find("bridge") is not None and "is_l2" not in unit_dict:
                unit_dict["is_l2"] = True

        return unit_dict

    # ------------------------------------------------------------------
    # Routing instances
    # ------------------------------------------------------------------

    def parse_routing_instances(self) -> List[RoutingInstanceDict]:
        """Extract routing instances from the XML, including the default instance.

        The default (master) routing instance has no ``<routing-instances>``
        stanza — its static routes live under ``<routing-options>`` and its
        BGP groups under ``<protocols><bgp>`` at the config root.  It is
        materialised first so it appears at the top of every export and
        resolver walk.  Named instances follow in document order.
        """
        instances: List[RoutingInstanceDict] = []

        # Always materialise the default instance first.  It is omitted only
        # when the config carries neither static routes nor BGP groups at the
        # global level (e.g. a pure L2 config file).
        default_ri = self._parse_default_routing_instance()
        if default_ri is not None:
            instances.append(default_ri)

        ri_root = self.root.find("./routing-instances")
        if ri_root is not None:
            for ri_elem in ri_root.findall("instance"):
                instances.append(self._process_routing_instance(ri_elem))
        return instances

    def _parse_default_routing_instance(self) -> Optional[RoutingInstanceDict]:
        """Materialises the implicit Junos default (master) routing instance.

        In the Junos XML schema the default routing instance has no
        ``<instance>`` stanza under ``<routing-instances>``.  Its config
        is split across two top-level stanzas:

        * ``<routing-options><static>``   — static routes for inet.0
        * ``<protocols><bgp>``            — global BGP peer groups

        Returns ``None`` when neither stanza is present so that pure-L2
        config files do not produce a spurious empty entry.
        """
        static_routes: List[StaticRouteDict] = []
        bgp_groups: List[BgpGroupDict] = []

        # 1. Global static routes
        static_root = self.root.find("./routing-options/static")
        if static_root is not None:
            for route_elem in static_root.findall("route"):
                dest = get_text(route_elem, "name")
                if dest:
                    static_routes.append(
                        self._process_static_route(dest, route_elem)
                    )

        # 2. Global BGP groups
        bgp_root = self.root.find("./protocols/bgp")
        if bgp_root is not None:
            for group_elem in bgp_root.findall("group"):
                bgp_groups.append(self._process_bgp_group(group_elem))

        if not static_routes and not bgp_groups:
            return None

        return {
            "name": "default",
            "instance_type": "master",
            "description": None,
            "interfaces": [],
            "static_routes": static_routes,
            "bgp_groups": bgp_groups,
        }

    def _process_routing_instance(self, elem: ET.Element) -> RoutingInstanceDict:
        name = get_text(elem, "name") or "unknown"

        ri_data: RoutingInstanceDict = {
            "name": name,
            "instance_type": get_text(elem, "instance-type") or "virtual-router",
            "description": get_text(elem, "description"),
            "interfaces": [],
            "static_routes": [],
            "bgp_groups": [],
        }

        # 1. Interface names (e.g. ae100.10)
        for iface_elem in elem.findall("interface/name"):
            if iface_elem.text:
                ri_data["interfaces"].append(iface_elem.text.strip())

        # 2. Static routes under routing-options/static
        static_root = elem.find("./routing-options/static")
        if static_root is not None:
            for route_elem in static_root.findall("route"):
                dest = get_text(route_elem, "name")
                if dest:
                    ri_data["static_routes"].append(
                        self._process_static_route(dest, route_elem)
                    )

        # 3. BGP groups under protocols/bgp
        bgp_root = elem.find("./protocols/bgp")
        if bgp_root is not None:
            for group_elem in bgp_root.findall("group"):
                ri_data["bgp_groups"].append(self._process_bgp_group(group_elem))

        return ri_data

    def _process_static_route(
        self, destination: str, route_elem: ET.Element
    ) -> StaticRouteDict:
        route_dict: StaticRouteDict = {
            "destination": destination,
            "next_hops": [],
            "description": get_text(route_elem, "description"),
        }

        if route_elem.find("discard") is not None:
            route_dict["discard"] = True
        if route_elem.find("reject") is not None:
            route_dict["reject"] = True

        pref = get_int(route_elem, "preference")
        if pref is not None:
            route_dict["preference"] = pref

        tag = get_int(route_elem, "tag")
        if tag is not None:
            route_dict["tag"] = tag

        # Simple next-hops: <next-hop>10.0.0.1</next-hop>
        for nh_elem in route_elem.findall("next-hop"):
            if nh_elem.text:
                val = nh_elem.text.strip()
                kind = _classify_next_hop_text(val)
                nh: NextHopDict = {"kind": kind}  # type: ignore[typeddict-item]
                if kind == "ip":
                    nh["ip_address"] = val
                else:
                    nh["interface"] = val
                route_dict["next_hops"].append(nh)

        # Next-table: <next-table>inet.0</next-table>
        next_table = get_text(route_elem, "next-table")
        if next_table:
            route_dict["next_hops"].append(
                {"kind": "next-table", "next_table": next_table}
            )

        # Qualified next-hops: carry per-path preference/metric
        for qnh_elem in route_elem.findall("qualified-next-hop"):
            qval = get_text(qnh_elem, "name")
            if not qval:
                continue
            qkind = _classify_next_hop_text(qval)
            qnh: NextHopDict = {"kind": qkind, "qualified": True}  # type: ignore[typeddict-item]
            if qkind == "ip":
                qnh["ip_address"] = qval
            else:
                qnh["interface"] = qval
            qpref = get_int(qnh_elem, "preference")
            if qpref is not None:
                qnh["preference"] = qpref
            qmetric = get_int(qnh_elem, "metric")
            if qmetric is not None:
                qnh["metric"] = qmetric
            route_dict["next_hops"].append(qnh)

        return route_dict

    def _process_bgp_group(self, elem: ET.Element) -> BgpGroupDict:
        group_name = get_text(elem, "name") or "unknown"

        bgp_data: BgpGroupDict = {
            "name": group_name,
            "bgp_type": get_text(elem, "type") or "external",
            "peer_as": get_int(elem, "peer-as"),
            "local_as": get_int(elem, "local-as/as-number"),
            "import_policies": [],
            "export_policies": [],
            "neighbors": [],
        }

        for imp in elem.findall("import"):
            if imp.text:
                bgp_data["import_policies"].append(imp.text.strip())

        for exp in elem.findall("export"):
            if exp.text:
                bgp_data["export_policies"].append(exp.text.strip())

        for nbr_elem in elem.findall("neighbor"):
            nbr_name = get_text(nbr_elem, "name")
            if nbr_name:
                nbr: BgpNeighborDict = {
                    "name": nbr_name,
                    "local_address": get_text(nbr_elem, "local-address"),
                    "description": get_text(nbr_elem, "description"),
                }
                bgp_data["neighbors"].append(nbr)

        return bgp_data

    # ------------------------------------------------------------------
    # Policy options
    # ------------------------------------------------------------------

    def parse_policy_options(self) -> PolicyOptionsDict:
        """Extract global policy-options (prefix-lists, as-paths, policy-statements)."""
        results: PolicyOptionsDict = {
            "policy_statements": [],
            "as_paths": [],
            "prefix_lists": [],
        }
        po_root = self.root.find("./policy-options")
        if po_root is None:
            return results

        # 1. Prefix lists
        for pl_elem in po_root.findall("prefix-list"):
            name = get_text(pl_elem, "name")
            if name:
                pl: PrefixListDict = {
                    "name": name,
                    "prefixes": [
                        p.text.strip()
                        for p in pl_elem.findall("prefix-list-item/name")
                        if p.text
                    ],
                    "raw_config": get_raw_xml(pl_elem),
                }
                results["prefix_lists"].append(pl)

        # 2. AS paths
        for ap_elem in po_root.findall("as-path"):
            name = get_text(ap_elem, "name")
            if name:
                ap: AsPathDict = {
                    "name": name,
                    "path": get_text(ap_elem, "path") or "",
                    "raw_config": get_raw_xml(ap_elem),
                }
                results["as_paths"].append(ap)

        # 3. Policy statements
        for ps_elem in po_root.findall("policy-statement"):
            name = get_text(ps_elem, "name")
            if not name:
                continue

            ps_data: PolicyStatementDict = {
                "name": name,
                "raw_config": get_raw_xml(ps_elem),
                "terms": [],
            }

            term_elems = ps_elem.findall("term")
            if term_elems:
                ps_data["terms"] = [
                    self._process_policy_term(t) for t in term_elems
                ]
            else:
                # Statement with no explicit terms — wrap top-level logic
                # in a synthetic "default" term so the factory always gets
                # a consistent shape.
                ps_data["terms"].append(self._process_term_less_policy(ps_elem))

            results["policy_statements"].append(ps_data)

        return results

    def _process_term_less_policy(self, ps_elem: ET.Element) -> PolicyTermDict:
        """Wraps top-level from/then logic into a synthetic ``default`` term."""
        term_data = self._process_policy_term(ps_elem)
        term_data["name"] = "default"
        return term_data

    def _process_policy_term(self, term_elem: ET.Element) -> PolicyTermDict:
        term_data: PolicyTermDict = {
            "name": get_text(term_elem, "name") or "default",
            "raw_config": get_raw_xml(term_elem),
            "actions": [],
            "from_protocols": [
                p.text.strip()
                for p in term_elem.findall("from/protocol")
                if p.text
            ],
            "from_prefix_lists": [
                p.text.strip()
                for p in term_elem.findall("from/prefix-list/name")
                if p.text
            ],
            "from_as_paths": [
                p.text.strip()
                for p in term_elem.findall("from/as-path")
                if p.text
            ],
            "from_route_filters": [],
        }

        for rf in term_elem.findall("from/route-filter"):
            addr = get_text(rf, "address")
            if addr:
                match_type = "exact"
                for child in rf:
                    if child.tag != "address":
                        match_type = child.tag
                        break
                term_data["from_route_filters"].append(
                    {
                        "address": addr,
                        "match_type": match_type,  # type: ignore[typeddict-item]
                        "raw_config": get_raw_xml(rf),
                    }
                )

        then_elem = term_elem.find("then")
        if then_elem is not None:
            for action in then_elem:
                if action.tag in ("accept", "reject", "discard", "load-balance", "next"):
                    term_data["actions"].append(action.tag)
                if action.tag == "next-hop":
                    term_data["next_hop"] = (
                        action.text.strip() if action.text else "self"
                    )

        return term_data

    # ------------------------------------------------------------------
    # Family parsing (shared by interfaces and future slices)
    # ------------------------------------------------------------------

    def _process_family(self, elem: ET.Element) -> FamilyDict:
        family_dict: FamilyDict = {"addresses": []}

        # Primary/preferred flags live as children of <address>, so we walk
        # the <address> elements directly rather than just <address/name>.
        for addr in elem.findall("address"):
            addr_name = get_text(addr, "name")
            if not addr_name:
                continue
            family_dict["addresses"].append(addr_name)
            if addr.find("primary") is not None:
                family_dict["primary_address"] = addr_name
            if addr.find("preferred") is not None:
                family_dict["preferred_address"] = addr_name
            # VRRP virtual-address: present when this address stanza carries a
            # <vrrp-group> block.  Capture the first VIP found across all
            # address stanzas in the family — multiple groups are unusual and
            # the first one is the authoritative gateway address.
            if "vrrp_virtual_address" not in family_dict:
                for vrrp_group in addr.findall("vrrp-group"):
                    vip = get_text(vrrp_group, "virtual-address")
                    if vip:
                        family_dict["vrrp_virtual_address"] = vip
                        break

        mtu = get_int(elem, "mtu")
        if mtu is not None:
            family_dict["mtu"] = mtu

        sampling = elem.find("sampling")
        if sampling is not None:
            family_dict["sampling_input"] = sampling.find("input") is not None
            family_dict["sampling_output"] = sampling.find("output") is not None

        return family_dict


    # ------------------------------------------------------------------
    # Protocols-ports slice: port-list parsing
    # ------------------------------------------------------------------

    def parse_port_lists(self) -> List[PortListDict]:
        """Parses ``<firewall><port-list>`` stanzas.

        Port-lists are global, named collections of ports and port-ranges
        defined at the ``[edit firewall]`` level.  They are distinct from
        the inline ``<port>`` / ``<destination-port>`` match conditions
        inside filter terms.

        Returns an empty list when no port-list stanzas are present, which
        is the common case for configs that use only inline port matching.
        """
        fw_root = self.root.find("./firewall")
        if fw_root is None:
            return []

        result: List[PortListDict] = []

        for pl_elem in fw_root.findall("port-list"):
            name = get_text(pl_elem, "name")
            if not name:
                continue

            # Collect raw port tokens (single ports and port-ranges).
            # Normalization (name→number, range parsing) is deferred to
            # the factory / helpers layer to keep the parser boundary clean.
            entries: List[str] = []
            for port_elem in pl_elem.findall("port"):
                raw = (port_elem.text or "").strip()
                if raw:
                    entries.append(raw)

            result.append(
                PortListDict(
                    name=name,
                    raw_config=get_raw_xml(pl_elem),
                    entries=entries,
                )
            )

        return result

    # ------------------------------------------------------------------
    # Firewall slice: filter parsing
    # ------------------------------------------------------------------

    def parse_firewall_filters(self) -> List[FirewallFilterDict]:
        """Parses all ``<firewall>`` filter stanzas.

        Handles three address-family scopes:

        * ``<firewall><filter>``                 → ``address_family="any"``
        * ``<firewall><family><inet><filter>``   → ``address_family="inet"``
        * ``<firewall><family><inet6><filter>``  → ``address_family="inet6"``

        For inet6 filters, ``<next-header>`` is treated identically to
        ``<protocol>`` — both end up in the ``protocols`` field of
        ``TermFromDict`` so the factory can normalize them uniformly.

        Returns an empty list when no ``<firewall>`` element is present.
        """
        fw_root = self.root.find("./firewall")
        if fw_root is None:
            return []

        result: List[FirewallFilterDict] = []

        # Top-level (address-family agnostic) filters
        for f_elem in fw_root.findall("filter"):
            parsed = self._parse_filter(f_elem, "any")
            if parsed:
                result.append(parsed)

        # Family-scoped filters
        for family_elem in fw_root.findall("family"):
            for af_elem in family_elem:
                af_name = af_elem.tag  # "inet" or "inet6"
                for f_elem in af_elem.findall("filter"):
                    parsed = self._parse_filter(f_elem, af_name)
                    if parsed:
                        result.append(parsed)

        return result

    def _parse_filter(
        self, f_elem: ET.Element, address_family: str
    ) -> Optional[FirewallFilterDict]:
        """Parses a single ``<filter>`` element into a ``FirewallFilterDict``."""
        name = get_text(f_elem, "name")
        if not name:
            return None

        terms: List[FirewallTermDict] = []
        for term_elem in f_elem.findall("term"):
            term = self._parse_term(term_elem)
            if term:
                terms.append(term)

        return FirewallFilterDict(
            name=name,
            address_family=address_family,
            raw_config=get_raw_xml(f_elem),
            terms=terms,
        )

    def _parse_term(self, term_elem: ET.Element) -> Optional[FirewallTermDict]:
        """Parses a single ``<term>`` element into a ``FirewallTermDict``."""
        name = get_text(term_elem, "name")
        if not name:
            return None

        from_conds = self._parse_term_from(term_elem.find("from"))
        actions, count, log_flag, syslog_flag = self._parse_term_then(
            term_elem.find("then")
        )

        return FirewallTermDict(
            name=name,
            raw_config=get_raw_xml(term_elem),
            from_conditions=from_conds,
            actions=actions,
            count=count,
            log=log_flag,
            syslog=syslog_flag,
        )

    def _parse_term_from(
        self, from_elem: Optional[ET.Element]
    ) -> TermFromDict:
        """Parses the ``<from>`` clause of a term into a ``TermFromDict``."""
        result: TermFromDict = {}

        if from_elem is None:
            return result

        # Prefix-list references (cross-slice)
        src_pls = [
            pl.findtext("name") or ""
            for pl in from_elem.findall("source-prefix-list")
            if (pl.findtext("name") or "").strip()
        ]
        if src_pls:
            result["source_prefix_lists"] = src_pls

        dst_pls = [
            pl.findtext("name") or ""
            for pl in from_elem.findall("destination-prefix-list")
            if (pl.findtext("name") or "").strip()
        ]
        if dst_pls:
            result["destination_prefix_lists"] = dst_pls

        # Port-list references (cross-slice) — uncommon but supported
        src_port_lists = [
            pl.findtext("name") or ""
            for pl in from_elem.findall("source-port-list")
            if (pl.findtext("name") or "").strip()
        ]
        if src_port_lists:
            result["source_port_lists"] = src_port_lists

        dst_port_lists = [
            pl.findtext("name") or ""
            for pl in from_elem.findall("destination-port-list")
            if (pl.findtext("name") or "").strip()
        ]
        if dst_port_lists:
            result["destination_port_lists"] = dst_port_lists

        # Inline source and destination addresses
        src_addrs = [
            (a.findtext("name") or "").strip()
            for a in from_elem.findall("source-address")
            if (a.findtext("name") or "").strip()
        ]
        if src_addrs:
            result["source_addresses"] = src_addrs

        dst_addrs = [
            (a.findtext("name") or "").strip()
            for a in from_elem.findall("destination-address")
            if (a.findtext("name") or "").strip()
        ]
        if dst_addrs:
            result["destination_addresses"] = dst_addrs

        # Protocol tokens — <protocol> (inet) and <next-header> (inet6) are
        # semantically identical; merge them into the same "protocols" list.
        protocols = [
            (e.text or "").strip()
            for e in from_elem.findall("protocol")
            if (e.text or "").strip()
        ] + [
            (e.text or "").strip()
            for e in from_elem.findall("next-header")
            if (e.text or "").strip()
        ]
        if protocols:
            result["protocols"] = protocols

        # Port tokens
        ports = [
            (e.text or "").strip()
            for e in from_elem.findall("port")
            if (e.text or "").strip()
        ]
        if ports:
            result["ports"] = ports

        src_ports = [
            (e.text or "").strip()
            for e in from_elem.findall("source-port")
            if (e.text or "").strip()
        ]
        if src_ports:
            result["source_ports"] = src_ports

        dst_ports = [
            (e.text or "").strip()
            for e in from_elem.findall("destination-port")
            if (e.text or "").strip()
        ]
        if dst_ports:
            result["destination_ports"] = dst_ports

        # ICMP type tokens
        icmp_types = [
            (e.text or "").strip()
            for e in from_elem.findall("icmp-type")
            if (e.text or "").strip()
        ]
        if icmp_types:
            result["icmp_types"] = icmp_types

        # Stateful flags
        if from_elem.find("tcp-established") is not None:
            result["tcp_established"] = True

        return result

    def _parse_term_then(
        self, then_elem: Optional[ET.Element]
    ):
        """Parses the ``<then>`` clause of a term.

        Returns:
            (actions, count, log, syslog)
            where ``actions`` is a list of action strings, ``count`` is the
            counter name string or None, ``log`` and ``syslog`` are booleans.
        """
        actions: List[str] = []
        count: Optional[str] = None
        log_flag = False
        syslog_flag = False

        if then_elem is None:
            return actions, count, log_flag, syslog_flag

        if then_elem.find("accept") is not None:
            actions.append("accept")
        if then_elem.find("reject") is not None:
            actions.append("reject")
        if then_elem.find("discard") is not None:
            actions.append("discard")
        if then_elem.find("sample") is not None:
            actions.append("sample")

        next_elem = then_elem.find("next")
        if next_elem is not None:
            # <next>term</next> means "continue to the next term"
            actions.append("next-term")

        count_elem = then_elem.find("count")
        if count_elem is not None and (count_elem.text or "").strip():
            count = count_elem.text.strip()

        if then_elem.find("log") is not None:
            log_flag = True
        if then_elem.find("syslog") is not None:
            syslog_flag = True

        return actions, count, log_flag, syslog_flag


# ---------------------------------------------------------------------------
# Junos 23.x parser
# ---------------------------------------------------------------------------


class MXParser23x(MXParser21x):
    """Parser for Junos 23.x MX configurations.

    The core XML grammar for interfaces, routing-instances, policy-options,
    and firewall filters is stable across the 21.x → 23.x range, so this
    class inherits all slice-parsing logic from ``MXParser21x`` without
    modification.

    The only override required for 23.x is ``_classify_interface_kind``,
    which adds interface prefixes that became common on newer MX line-cards
    and fixed-chassis platforms shipping with 23.x:

    * ``oe-``  — OTN Ethernet (MX2020, PTX platforms running MX OS)
    * ``ext-`` — extended/internal fabric links on MX304 and MX10008
    * ``cbp``  — control-plane bridge ports (MX10003/MX10008 internal fabric)
    * ``jsrv`` — Junos services interface (present in some 23.x system dumps)
    * ``dsc``  — discard interface (replaces /dev/null routes in some configs)
    * ``mtun`` — multicast tunnel interface (more visible in 23.x EVPN dumps)
    * ``lc-``  — line-card internal management link (MX2010/MX2020)
    * ``pip0``  — passive-monitoring interface

    All other grammar (VRRP virtual-address, firewall filter, BGP, LACP,
    MC-AE, etc.) is handled identically by the inherited 21.x methods.

    23.x-specific grammar that is NOT yet modeled
    ----------------------------------------------
    * EVPN VXLAN ``<protocols><evpn>`` and ``<bridge-domains>`` stanzas —
      these are absent from the current slice set and will require dedicated
      factory + resolver work when added.
    * BGP flow-spec ``<flow>`` route entries inside routing-instances — parsed
      as part of the generic BGP group walk but the per-flow-route detail is
      discarded; no known consumer yet.
    * Segment-routing / MPLS traffic-engineering extensions — not modeled.
    """

    def _classify_interface_kind(self, name: str) -> "InterfaceKind":
        """Extends 21.x classification with 23.x-era interface prefixes.

        Falls through to the parent method for all names not listed here,
        preserving the defensive ``"physical"`` fallback for unknowns.
        """
        # OTN Ethernet and extended fabric links (newer fixed/modular chassis)
        if name.startswith(("oe-", "ext-")):
            return "physical"

        # Internal fabric / control-plane bridge ports — model as physical;
        # they never carry user traffic but appear in full config dumps.
        if name.startswith(("cbp", "lc-")):
            return "physical"

        # Discard, multicast-tunnel, passive-monitoring, Junos-services —
        # these are all pseudo-interfaces with no meaningful L2/L3 config;
        # tunnel is the closest structural match.
        if name in ("dsc", "mtun", "pip0", "jsrv") or name.startswith(
            ("dsc", "mtun", "pip", "jsrv")
        ):
            return "tunnel"

        # Delegate everything else (ge-, xe-, et-, ae, irb, lo0, fxp, …)
        # to the unchanged 21.x classifier.
        return super()._classify_interface_kind(name)


# end of lib/parsers/junos_mx.py
