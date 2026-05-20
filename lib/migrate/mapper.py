"""MX-specific PAN-OS migration mapper.

Responsible for:
  1. Walking the MX registry graph (FirewallFilter → FirewallTerm).
  2. Materializing PAN-OS address objects from inline CIDR strings.
  3. Materializing PAN-OS address groups from PrefixList nodes.
  4. Creating PAN-OS service objects from protocol/port match conditions.
  5. Calling MxPanosTranslator to produce security rules.
  6. Deriving PAN-OS zone names from interface filter-application stanzas.
  7. Persisting the result as a structured JSON manifest.

Manifest shape (compatible with PanosGenerator):

    {
        "shared": {
            "address_objects": {},
            "address_groups": {},
            "service_objects": {},
            "service_groups": {},
        },
        "virtual_systems": {
            "vsys1": {
                "address_objects": {},
                "address_groups": {},
                "service_objects": {},
                "service_groups": {},
                "zones": {},
                "security_policies": {},
            }
        }
    }

Each bucket entry has the shape:
    {
        "post_mapped": <dataclass>,
        "warnings": [...],
        "sequence": int,    # security_policies only
    }

Zone mapping rules
------------------
* ``input`` filter on unit X  → from-zone: X,   to-zone: any
* ``output`` filter on unit X → from-zone: any,  to-zone: X
* If the same filter appears as input on [A, B] and output on [C]:
      from-zone: [A, B],  to-zone: [C]
* Filters applied exclusively on loopback units (lo*) are control-plane
  filters (PROTECT_RE, etc.).  They are logged and skipped — there is no
  PAN-OS security-policy equivalent.
* Filters not applied to any interface are also logged and skipped.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.console import Console

from lib.firewall.resolvers import FirewallResolver
from lib.interface.objects import UnitInterface
from lib.policy_options.objects import PrefixList
from lib.log_utils import get_logger
from lib.migrate.models import (
    PanosAddress,
    PanosAddressGroup,
    PanosService,
    PanosServiceGroup,
    PanosZone,
)
from lib.migrate.translator import MxPanosTranslator

console = Console()
logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Protocol routing: which protocols map to built-in PAN App-IDs vs services
# ---------------------------------------------------------------------------

# Protocols that become built-in PAN-OS App-IDs (not service objects).
# tcp and udp are excluded — they are handled as service objects.
_PROTO_TO_APP_ID: Dict[str, str] = {
    "icmp": "icmp",
    "icmpv6": "ipv6-icmp",
    "icmp6": "ipv6-icmp",
    "ospf": "ospf",
    "ospf3": "ospf",
    "gre": "gre",
    "esp": "ipsec-esp",
    "ah": "ipsec-ah",
    "vrrp": "vrrp",
    "rsvp": "rsvp",
    "pim": "pim",
    "igmp": "igmp",
    "eigrp": "eigrp",
    "bgp": "bgp",
    "47": "gre",
    "50": "ipsec-esp",
    "51": "ipsec-ah",
    "89": "ospf",
    "112": "vrrp",
}

_SERVICE_PROTOCOLS = {"tcp", "udp", "6", "17"}


class MxPanosMapper:
    """Builds a PAN-OS migration manifest from an MX registry."""

    def __init__(
        self,
        controller: Any,
        manifest_file: str = "panos_migration_manifest.json",
    ) -> None:
        self.ctl = controller
        self.registry = controller.registry
        self.manifest_file = manifest_file
        self.manifest: Dict[str, Any] = self._build_empty_manifest()
        self.output_path = self.ctl.workspace_manager.get_migration_file(manifest_file)
        self.translator = MxPanosTranslator()
        self._fw_resolver = FirewallResolver(self.registry)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def migrate_firewall_rules(self, config_root_uid: str) -> None:
        """Translates all MX firewall terms into PAN-OS security rules.

        Walk order: FirewallRoot → FirewallFilterContainer → FirewallFilter
        (alpha-sorted by filter name) → FirewallTerm (ingestion order).

        For each terminal term:
          - Inline source/destination CIDRs become PanosAddress objects.
          - source/destination_prefix_list edges become PanosAddressGroup objects
            (each prefix in the list becomes a member PanosAddress).
          - Protocol + port combinations become PanosService objects.
          - The term is translated into a PanosSecurityRule with zones derived
            from the filter's interface-application stanzas.

        Filters that are unapplied or applied only on loopback (control-plane)
        interfaces are flagged and skipped.
        """
        console.print("\n[steel_blue1]Migrating MX Firewall Rules → PAN-OS Security Policies...[/]")

        # Build the zone map before traversing filters so we can gate on it.
        zone_map, loopback_filters = self._build_filter_zone_map()

        root_uid = self._fw_resolver.get_root(config_root_uid)
        if not root_uid:
            logger.warning("No FirewallRoot found for config root %s.", config_root_uid)
            self.save_manifest()
            return

        container_uid = self._fw_resolver.get_filter_container(root_uid)
        if not container_uid:
            logger.warning("No FirewallFilterContainer found.")
            self.save_manifest()
            return

        filter_uids = self._fw_resolver.get_filters(container_uid)
        if not filter_uids:
            logger.warning("No FirewallFilter nodes found.")
            self.save_manifest()
            return

        sequence = 0

        for filter_uid in filter_uids:
            filter_data = self._fw_resolver.hydrate_filter(filter_uid)
            if not filter_data:
                continue

            filter_name = filter_data["name"]

            # --- Gate: skip control-plane (loopback) filters ---
            if filter_name in loopback_filters and filter_name not in zone_map:
                console.print(
                    f"  [yellow]Skipping[/] [bold]{filter_name}[/]  "
                    f"[dim](control-plane / loopback filter — no PAN-OS equivalent)[/]"
                )
                continue

            # --- Gate: skip unapplied filters ---
            if filter_name not in zone_map and filter_name not in loopback_filters:
                console.print(
                    f"  [yellow]Skipping[/] [bold]{filter_name}[/]  "
                    f"[dim](not applied to any interface)[/]"
                )
                continue

            zones = zone_map[filter_name]
            from_zones = zones["from_zones"] or ["any"]
            to_zones = zones["to_zones"] or ["any"]

            term_uids = self._fw_resolver.get_ordered_terms(filter_uid)

            console.print(
                f"  [dim]Filter:[/] [bold]{filter_name}[/]  "
                f"([dim]{len(term_uids)} terms  "
                f"from={from_zones}  to={to_zones}[/])"
            )

            for term_uid in term_uids:
                term_data = self._fw_resolver.hydrate_term(term_uid)
                if not term_data:
                    continue

                # Skip terms with no terminal action (e.g. pure next-term/sample).
                if not self.translator.is_terminal(term_data.get("actions", [])):
                    logger.debug(
                        "Skipping non-terminal term '%s' in filter '%s'.",
                        term_data["name"],
                        filter_name,
                    )
                    continue

                sequence += 1
                self._process_term(filter_name, term_data, sequence, from_zones, to_zones)

        console.print(
            f"\n  [bold steel_blue]Done.[/] "
            f"[dim]{sequence} rules written to manifest.[/]"
        )
        self.save_manifest()

    # ------------------------------------------------------------------
    # Term processing
    # ------------------------------------------------------------------

    def _process_term(
        self,
        filter_name: str,
        term_data: Dict[str, Any],
        sequence: int,
        from_zones: List[str],
        to_zones: List[str],
    ) -> None:
        """Processes one firewall term and adds the rule to the manifest."""
        term_name = term_data["name"]
        pan_name = self.translator.sanitize_rule_name(filter_name, term_name)

        warnings: List[str] = []

        # ------ Source addresses ------
        src_addresses, src_warnings = self._resolve_addresses(
            cidr_list=term_data.get("source_addresses", []),
            pl_uid_list=term_data.get("source_prefix_list_uids", []),
            field_label="source",
        )
        warnings.extend(src_warnings)

        # ------ Destination addresses ------
        dst_addresses, dst_warnings = self._resolve_addresses(
            cidr_list=term_data.get("destination_addresses", []),
            pl_uid_list=term_data.get("destination_prefix_list_uids", []),
            field_label="destination",
        )
        warnings.extend(dst_warnings)

        # ------ Services / Applications ------
        applications, services, svc_warnings = self._resolve_services_and_apps(
            term_data=term_data,
            rule_name=pan_name,
        )
        warnings.extend(svc_warnings)

        # ------ tcp-established note ------
        if term_data.get("tcp_established"):
            warnings.append(
                "REVIEW [tcp-established: stateful matching is handled automatically "
                "by PAN-OS; verify this rule intent]"
            )

        # ------ source-port note ------
        if term_data.get("source_ports"):
            warnings.append(
                "REVIEW [source-port: PAN-OS service objects match destination ports "
                "only; source port constraint cannot be represented directly]"
            )

        # ------ Translate ------
        action = self.translator.map_action(term_data.get("actions", []))
        log_end = bool(term_data.get("log") or term_data.get("syslog"))

        result = self.translator.translate_firewall_term(
            {
                "filter_name": filter_name,
                "term_name": term_name,
                "pan_name": pan_name,
                "from_zones": from_zones,
                "to_zones": to_zones,
                "source_addresses": src_addresses,
                "destination_addresses": dst_addresses,
                "applications": applications,
                "services": services,
                "action": action,
                "description": None,
                "log_end": log_end,
                "warnings": warnings,
            }
        )

        if result.target_kind != "security-rule" or result.value is None:
            logger.warning("Term '%s' in '%s' produced no rule.", term_name, filter_name)
            return

        bucket = self._security_policies_bucket()
        bucket[pan_name] = {
            "post_mapped": result.value,
            "warnings": result.warnings,
            "sequence": sequence,
        }

        logger.debug("  Added rule '%s' (seq %d)", pan_name, sequence)

    # ------------------------------------------------------------------
    # Address resolution
    # ------------------------------------------------------------------

    def _resolve_addresses(
        self,
        *,
        cidr_list: List[str],
        pl_uid_list: List[str],
        field_label: str,
    ) -> Tuple[List[str], List[str]]:
        """Resolves inline CIDRs and prefix-list UIDs into PAN address names.

        Returns (pan_names, warnings).
        """
        names: List[str] = []
        warnings: List[str] = []

        # Inline CIDRs
        for cidr in cidr_list:
            pan_name = self._ensure_address_object(cidr)
            if pan_name == "any":
                names.append("any")
            elif pan_name:
                names.append(pan_name)

        # Prefix lists → address groups
        for pl_uid in pl_uid_list:
            group_name, pl_warnings = self._ensure_prefix_list_address_group(pl_uid)
            if group_name:
                names.append(group_name)
            warnings.extend(pl_warnings)

        # Deduplicate while preserving order
        names = self._dedupe(names)
        return names, warnings

    def _ensure_address_object(self, cidr: str) -> str:
        """Creates a PanosAddress in the manifest for an inline CIDR.

        Returns:
            'any'            for 0.0.0.0/0 and ::/0 (semantic catch-all).
            sanitized name   for all other CIDRs.
        """
        cidr = cidr.strip()
        if not cidr:
            return ""

        if cidr in {"0.0.0.0/0", "::/0"}:
            return "any"

        pan_name = self.translator.sanitize_address_name(cidr)
        bucket = self._vsys1_address_objects_bucket()

        if pan_name not in bucket:
            addr_type = "ip-range" if "-" in cidr and "/" not in cidr else "ip-netmask"
            obj = PanosAddress(
                name=pan_name,
                value=cidr,
                address_type=addr_type,
                valid_pan_config=True,
            )
            bucket[pan_name] = {"post_mapped": obj, "warnings": []}
            logger.debug("  Created address object: %s (%s)", pan_name, cidr)

        return pan_name

    def _ensure_prefix_list_address_group(
        self, pl_uid: str
    ) -> Tuple[Optional[str], List[str]]:
        """Creates a PanosAddressGroup in the manifest for a PrefixList node.

        Each prefix in the list becomes a child PanosAddress.  If the prefix
        list uses apply-path (prefixes=[]), the group is created with no static
        members and valid_pan_config=False so the generator skips it and the
        rule is flagged for review.

        Returns (group_pan_name, warnings).
        """
        pl_node = self.registry.storage.get(pl_uid)
        if not isinstance(pl_node, PrefixList):
            return None, [f"REVIEW [prefix-list uid {pl_uid}: not found in registry]"]

        raw_name = pl_node.name
        group_name = self.translator.sanitize_prefix_list_name(raw_name)
        group_bucket = self._vsys1_address_groups_bucket()
        addr_bucket = self._vsys1_address_objects_bucket()
        warnings: List[str] = []

        if group_name in group_bucket:
            return group_name, warnings

        prefixes = list(pl_node.prefixes) if pl_node.prefixes else []

        if not prefixes:
            # Dynamic apply-path list — prefixes cannot be statically enumerated.
            warnings.append(
                f"REVIEW [prefix-list '{raw_name}': uses apply-path or has no static "
                f"prefixes; address group '{group_name}' created empty and must be "
                "populated manually]"
            )
            group_obj = PanosAddressGroup(
                name=group_name,
                static_members=[],
                description=f"MX prefix-list: {raw_name} (apply-path — review required)",
                valid_pan_config=False,
            )
            group_bucket[group_name] = {"post_mapped": group_obj, "warnings": warnings}
            return group_name, warnings

        # Static prefixes — create an address object per prefix, then the group.
        member_names: List[str] = []
        for prefix in prefixes:
            prefix = prefix.strip()
            if not prefix or prefix in {"0.0.0.0/0", "::/0"}:
                continue
            member_name = self.translator.sanitize_address_name(prefix)
            if member_name not in addr_bucket:
                obj = PanosAddress(
                    name=member_name,
                    value=prefix,
                    address_type="ip-netmask",
                    valid_pan_config=True,
                )
                addr_bucket[member_name] = {"post_mapped": obj, "warnings": []}
            member_names.append(member_name)

        member_names = self._dedupe(member_names)
        group_obj = PanosAddressGroup(
            name=group_name,
            static_members=member_names,
            description=f"MX prefix-list: {raw_name}",
            valid_pan_config=bool(member_names),
        )
        group_bucket[group_name] = {"post_mapped": group_obj, "warnings": warnings}
        logger.debug(
            "  Created address group '%s' (%d members).", group_name, len(member_names)
        )
        return group_name, warnings

    # ------------------------------------------------------------------
    # Service / application resolution
    # ------------------------------------------------------------------

    def _resolve_services_and_apps(
        self,
        *,
        term_data: Dict[str, Any],
        rule_name: str,
    ) -> Tuple[List[str], List[str], List[str]]:
        """Derives the application and service lists for a firewall term.

        Returns (application_names, service_names, warnings).

        Strategy:
          - tcp/udp protocols → PanosService objects; collected in service_names.
          - Non-tcp/udp protocols → built-in PAN App-IDs; collected in app_names.
          - Mixed terms (tcp + icmp, etc.) → service_names takes precedence per
            the PAN-OS convention; App-IDs are noted in a warning.
          - No protocol, no ports → caller normalizes to any/application-default.
        """
        protocols = term_data.get("protocols", [])  # list of dicts
        dst_ports = term_data.get("destination_ports", [])
        src_ports = term_data.get("source_ports", [])
        ports = term_data.get("ports", [])  # matches src or dst
        icmp_types = term_data.get("icmp_types", [])

        warnings: List[str] = []
        service_names: List[str] = []
        app_names: List[str] = []

        # Normalize protocol list to canonical names.
        canon_protos = self._canonical_protocols(protocols)

        service_protos = [p for p in canon_protos if p in {"tcp", "udp"}]
        app_protos = [p for p in canon_protos if p not in {"tcp", "udp"}]

        # ---- Port specs to use (prefer destination_ports, fall back to ports) ----
        effective_dst_ports = dst_ports if dst_ports else ports
        if ports and not dst_ports:
            warnings.append(
                "REVIEW [port (any-direction): migrated as destination port; "
                "verify bidirectional intent]"
            )

        # ---- Service objects for TCP/UDP ----
        for proto in service_protos:
            if effective_dst_ports:
                for port_dict in effective_dst_ports:
                    port_str = self._port_dict_to_str(port_dict)
                    svc_name = self._ensure_service(proto, port_str)
                    service_names.append(svc_name)
            else:
                # Protocol with no ports → match all ports.
                svc_name = self._ensure_service(proto, "0-65535")
                service_names.append(svc_name)

        # ---- No protocol but ports present ----
        if not canon_protos and effective_dst_ports:
            # Unknown protocol — create both tcp and udp services conservatively.
            warnings.append(
                "REVIEW [no protocol specified; created tcp and udp services for "
                "specified ports — verify intended protocol(s)]"
            )
            for proto in ("tcp", "udp"):
                for port_dict in effective_dst_ports:
                    port_str = self._port_dict_to_str(port_dict)
                    svc_name = self._ensure_service(proto, port_str)
                    service_names.append(svc_name)

        # ---- Built-in App-IDs for non-TCP/UDP protocols ----
        for proto in app_protos:
            app_id = _PROTO_TO_APP_ID.get(proto)
            if app_id:
                app_names.append(app_id)
            else:
                warnings.append(
                    f"REVIEW [protocol '{proto}': no PAN-OS App-ID mapping known; "
                    "rule uses application=any — review manually]"
                )

        # Deduplicate
        service_names = self._dedupe(service_names)
        app_names = self._dedupe(app_names)

        # ---- Consolidate into a service group if multiple services ----
        if len(service_names) > 1:
            group_name = f"{rule_name}_svc"
            group_name = self.translator.sanitize_name(group_name)
            self._ensure_service_group(group_name, service_names)
            service_names = [group_name]

        # ---- Mixed warning (app-IDs + services in same term) ----
        if service_names and app_names:
            warnings.append(
                f"REVIEW [mixed protocols: service objects take precedence; "
                f"App-IDs [{', '.join(app_names)}] are not represented — "
                "consider splitting into separate rules]"
            )
            app_names = []  # services win per PAN-OS convention

        return app_names, service_names, warnings

    def _canonical_protocols(self, protocols: List[Dict[str, Any]]) -> List[str]:
        """Extracts canonical protocol names from term protocol dicts.

        Numeric protocol numbers are normalized to named forms where known.
        """
        result: List[str] = []
        for p in protocols:
            if not isinstance(p, dict):
                continue
            canon = p.get("canonical_name") or p.get("raw") or ""
            canon = str(canon).strip().lower()

            # Normalize numeric TCP/UDP
            if canon == "6":
                canon = "tcp"
            elif canon == "17":
                canon = "udp"

            if canon:
                result.append(canon)

        return self._dedupe(result)

    def _port_dict_to_str(self, port_dict: Dict[str, Any]) -> str:
        """Converts a normalized port dict to a PAN-OS port string.

        Examples:
            {"kind": "single", "value": 22, ...}     → "22"
            {"kind": "range", "low": 10000, "high": 19999, ...} → "10000-19999"
        """
        kind = port_dict.get("kind")
        if kind == "single":
            val = port_dict.get("value")
            if val is not None:
                return str(int(val))
        elif kind == "range":
            low = port_dict.get("low")
            high = port_dict.get("high")
            if low is not None and high is not None:
                return f"{int(low)}-{int(high)}"
        # Fallback: try raw string
        raw = port_dict.get("raw", "")
        return str(raw) if raw else "0-65535"

    def _ensure_service(self, protocol: str, port_str: str) -> str:
        """Creates/reuses a PanosService in the manifest.

        Names are canonical (e.g. 'tcp_22', 'udp_53', 'tcp_0-65535') so
        identical services are shared across rules.
        """
        protocol = protocol.lower()
        svc_name = f"{protocol}_{port_str}"
        svc_name = self.translator.sanitize_name(svc_name)
        bucket = self._vsys1_service_objects_bucket()

        if svc_name not in bucket:
            pan_proto: Any = "tcp" if protocol == "tcp" else "udp"
            obj = PanosService(
                name=svc_name,
                protocol=pan_proto,
                port=port_str,
                valid_pan_config=True,
            )
            bucket[svc_name] = {"post_mapped": obj, "warnings": []}
            logger.debug("  Created service: %s", svc_name)

        return svc_name

    def _ensure_service_group(self, group_name: str, member_names: List[str]) -> str:
        """Creates/reuses a PanosServiceGroup in the manifest."""
        bucket = self._vsys1_service_groups_bucket()
        if group_name not in bucket:
            obj = PanosServiceGroup(
                name=group_name,
                members=member_names,
                valid_pan_config=True,
            )
            bucket[group_name] = {"post_mapped": obj, "warnings": []}
            logger.debug("  Created service group: %s (%d members)", group_name, len(member_names))
        return group_name

    # ------------------------------------------------------------------
    # Zone mapping
    # ------------------------------------------------------------------

    def _build_filter_zone_map(
        self,
    ) -> Tuple[Dict[str, Dict[str, List[str]]], Set[str]]:
        """Scans UnitInterface nodes and derives a filter → zone mapping.

        Returns:
            zone_map:        {filter_name: {"from_zones": [...], "to_zones": [...]}}
                             Only populated from non-loopback interfaces.
            loopback_filters: set of filter names applied exclusively on
                             loopback units (lo*) — these are control-plane
                             filters with no PAN-OS security-policy equivalent.
        """
        zone_map: Dict[str, Dict[str, List[str]]] = {}
        loopback_filters: Set[str] = set()

        for node in self.registry.storage.values():
            if not isinstance(node, UnitInterface):
                continue

            is_loopback = node.parent_name.startswith("lo")

            # Collect both inet and inet6 filter applications.
            applications = [
                ("from_zones", node.filter_inet_input),
                ("to_zones",   node.filter_inet_output),
                ("from_zones", node.filter_inet6_input),
                ("to_zones",   node.filter_inet6_output),
            ]

            for direction_key, filter_name in applications:
                if not filter_name:
                    continue

                if is_loopback:
                    loopback_filters.add(filter_name)
                    continue

                zone_name = self._sanitize_zone_name(node.name)
                self._ensure_zone(zone_name)

                if filter_name not in zone_map:
                    zone_map[filter_name] = {"from_zones": [], "to_zones": []}

                bucket_list = zone_map[filter_name][direction_key]
                if zone_name not in bucket_list:
                    bucket_list.append(zone_name)

        return zone_map, loopback_filters

    @staticmethod
    def _sanitize_zone_name(name: str) -> str:
        """Converts an MX interface unit name into a valid PAN-OS zone name.

        PAN-OS zone names: max 31 chars, no forward slashes.
        Examples: 'irb.901' → 'irb.901',  'xe-1/3/1.0' → 'xe-1_3_1.0'
        """
        return name.replace("/", "_")[:31]

    def _ensure_zone(self, zone_name: str) -> None:
        """Creates a PanosZone in the manifest if not already present."""
        bucket = self._vsys1_zones_bucket()
        if zone_name not in bucket:
            obj = PanosZone(name=zone_name, valid_pan_config=True)
            bucket[zone_name] = {"post_mapped": obj, "warnings": []}
            logger.debug("  Created zone: %s", zone_name)

    # ------------------------------------------------------------------
    # Manifest helpers
    # ------------------------------------------------------------------

    def _build_empty_manifest(self) -> Dict[str, Any]:
        return {
            "shared": {
                "address_objects": {},
                "address_groups": {},
                "service_objects": {},
                "service_groups": {},
            },
            "virtual_systems": {
                "vsys1": {
                    "display_name": "vsys1",
                    "address_objects": {},
                    "address_groups": {},
                    "service_objects": {},
                    "service_groups": {},
                    "zones": {},
                    "security_policies": {},
                }
            },
        }

    def _vsys1(self) -> Dict[str, Any]:
        return self.manifest["virtual_systems"]["vsys1"]

    def _vsys1_address_objects_bucket(self) -> Dict[str, Any]:
        return self._vsys1()["address_objects"]

    def _vsys1_address_groups_bucket(self) -> Dict[str, Any]:
        return self._vsys1()["address_groups"]

    def _vsys1_service_objects_bucket(self) -> Dict[str, Any]:
        return self._vsys1()["service_objects"]

    def _vsys1_service_groups_bucket(self) -> Dict[str, Any]:
        return self._vsys1()["service_groups"]

    def _vsys1_zones_bucket(self) -> Dict[str, Any]:
        return self._vsys1()["zones"]

    def _security_policies_bucket(self) -> Dict[str, Any]:
        return self._vsys1()["security_policies"]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_manifest(self) -> None:
        """Writes the manifest to disk as JSON."""

        def _encoder(obj: Any) -> Any:
            if is_dataclass(obj) and not isinstance(obj, type):
                return asdict(obj)
            return str(obj)

        with open(self.output_path, "w") as fh:
            json.dump(self.manifest, fh, indent=4, default=_encoder)

        console.print(
            f"  [bold steel_blue]Manifest saved:[/] {self.output_path}"
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _dedupe(values: List[str]) -> List[str]:
        """Returns de-duplicated list preserving input order."""
        seen: set = set()
        result: List[str] = []
        for v in values:
            if v not in seen:
                seen.add(v)
                result.append(v)
        return result


# end of lib/migrate/mapper.py
