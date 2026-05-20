"""PAN-OS XML generator for the mx-manager migrate slice.

Transforms the migration manifest produced by MxPanosMapper into a PAN-OS
candidate configuration XML file suitable for import into Panorama or a
standalone firewall.

Manifest compatibility: follows the same bucket layout as the srx-manager
generator so the two tools can share documentation and review patterns.

Phase 1 scope: address objects, address groups, service objects, service
groups, zones, and security policies.  Network configuration (interfaces,
virtual-routers) is out of scope and will be added in later phases.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.markup import escape

from lib.log_utils import get_logger
from lib.migrate.models import (
    PanosAddress,
    PanosAddressGroup,
    PanosSecurityRule,
    PanosService,
    PanosServiceGroup,
    PanosZone,
)

console = Console()
logger = get_logger(__name__)


class PanosGenerator:
    """Converts a PAN-OS migration manifest into an XML configuration file."""

    def __init__(self, manifest: Dict[str, Any], xml_path: Path) -> None:
        self.manifest = manifest
        self.xml_path = xml_path
        self.warnings: List[str] = []

        # Root PAN-OS config skeleton
        self.root = ET.Element(
            "config", {"version": "10.1.0", "urldb": "paloaltonetworks"}
        )
        devices = ET.SubElement(self.root, "devices")
        device_entry = ET.SubElement(
            devices, "entry", {"name": "localhost.localdomain"}
        )

        # VSYS structure
        vsys = ET.SubElement(device_entry, "vsys")
        self.vsys_entry = ET.SubElement(vsys, "entry", {"name": "vsys1"})

    # ------------------------------------------------------------------
    # Public generation methods
    # ------------------------------------------------------------------

    def generate_objects(self) -> None:
        """Generates PAN-OS XML for all address and service objects/groups."""
        console.print("[steel_blue1]Generating PAN-OS XML Objects...[/]")

        self._service_root = ET.SubElement(self.vsys_entry, "service")
        self._service_group_root = ET.SubElement(self.vsys_entry, "service-group")
        self._address_root = ET.SubElement(self.vsys_entry, "address")
        self._address_group_root = ET.SubElement(self.vsys_entry, "address-group")

        vsys1 = self.manifest.get("virtual_systems", {}).get("vsys1", {})
        shared = self.manifest.get("shared", {})

        RESERVED = {"any", "application-default"}
        emitted: set = set()

        buckets = [
            shared.get("address_objects", {}),
            shared.get("address_groups", {}),
            shared.get("service_objects", {}),
            shared.get("service_groups", {}),
            vsys1.get("address_objects", {}),
            vsys1.get("address_groups", {}),
            vsys1.get("service_objects", {}),
            vsys1.get("service_groups", {}),
        ]

        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue
            for name, data in bucket.items():
                if not isinstance(name, str):
                    continue
                if name.lower() in RESERVED:
                    continue
                if name in emitted:
                    continue
                if not isinstance(data, dict):
                    continue

                obj = data.get("post_mapped")
                if obj is None:
                    continue

                if not getattr(obj, "valid_pan_config", True):
                    reason = "; ".join(
                        str(w) for w in data.get("warnings", []) if w
                    ) or "non-deployable object"
                    logger.warning("Skipping object '%s': %s", name, reason)
                    continue

                if isinstance(obj, PanosService):
                    self._emit_service(obj)
                elif isinstance(obj, PanosServiceGroup):
                    self._emit_service_group(obj)
                elif isinstance(obj, PanosAddress):
                    self._emit_address(obj)
                elif isinstance(obj, PanosAddressGroup):
                    self._emit_address_group(obj)

                emitted.add(name)

    def generate_zones(self) -> None:
        """Generates PAN-OS XML for all zone objects in the manifest.

        Each zone is emitted as a minimal layer3 zone definition.  Interface
        assignments are intentionally omitted — they are filled in post-migration
        when PAN-OS interfaces are configured.
        """
        console.print("[steel_blue1]Generating PAN-OS Zone XML...[/]")

        vsys1 = self.manifest.get("virtual_systems", {}).get("vsys1", {})
        zone_bucket = vsys1.get("zones", {})
        if not isinstance(zone_bucket, dict) or not zone_bucket:
            return

        self._zone_root = ET.SubElement(self.vsys_entry, "zone")

        for name, data in zone_bucket.items():
            if not isinstance(data, dict):
                continue
            obj = data.get("post_mapped")
            if obj is None:
                continue
            if not getattr(obj, "valid_pan_config", True):
                continue
            if isinstance(obj, PanosZone):
                self._emit_zone(obj)

    def generate_security_policies(self) -> None:
        """Generates PAN-OS XML for all security rules in the manifest."""
        console.print("[steel_blue1]Generating PAN-OS Security Policy XML...[/]")

        vsys1 = self.manifest.get("virtual_systems", {}).get("vsys1", {})
        policy_bucket = vsys1.get("security_policies", {})
        if not isinstance(policy_bucket, dict) or not policy_bucket:
            return

        rulebase = ET.SubElement(self.vsys_entry, "rulebase")
        security = ET.SubElement(rulebase, "security")
        self._rules_root = ET.SubElement(security, "rules")

        # Emit rules in sequence order
        entries = sorted(
            policy_bucket.items(),
            key=lambda item: (
                int(item[1].get("sequence", 0)) if isinstance(item[1], dict) else 0
            ),
        )

        for name, data in entries:
            if not isinstance(data, dict):
                continue
            obj = data.get("post_mapped")
            if obj is None:
                continue
            if not getattr(obj, "valid_pan_config", True):
                reason = "; ".join(
                    str(w) for w in data.get("warnings", []) if w
                ) or "could not be serialized"
                logger.warning("Skipping rule '%s': %s", name, reason)
                continue
            if isinstance(obj, PanosSecurityRule):
                self._emit_security_rule(obj)

    def log_warnings(self) -> None:
        """Prints all warnings collected during generation."""
        for w in self.warnings:
            console.print(f"  [bold yellow]Review:[/] {w}")

    def write_xml(self) -> str:
        """Writes the XML tree to disk and returns the resolved output path."""
        tree = ET.ElementTree(self.root)
        ET.indent(tree, space="  ", level=0)
        tree.write(self.xml_path, encoding="utf-8", xml_declaration=True)
        return str(Path(self.xml_path).resolve())

    # ------------------------------------------------------------------
    # Object emitters
    # ------------------------------------------------------------------

    def _emit_zone(self, obj: PanosZone) -> None:
        entry = ET.SubElement(self._zone_root, "entry", {"name": obj.name})
        network = ET.SubElement(entry, "network")
        ET.SubElement(network, "layer3")
        if obj.description:
            ET.SubElement(entry, "description").text = obj.description
        logger.debug("  Zone: %s", obj.name)

    def _emit_address(self, obj: PanosAddress) -> None:
        entry = ET.SubElement(self._address_root, "entry", {"name": obj.name})
        ET.SubElement(entry, obj.address_type).text = obj.value
        if obj.description:
            ET.SubElement(entry, "description").text = obj.description
        logger.debug("  Address: %s", obj.name)

    def _emit_address_group(self, obj: PanosAddressGroup) -> None:
        entry = ET.SubElement(self._address_group_root, "entry", {"name": obj.name})
        static = ET.SubElement(entry, "static")
        for member in obj.static_members:
            ET.SubElement(static, "member").text = member
        if obj.description:
            ET.SubElement(entry, "description").text = obj.description
        logger.debug("  Address Group: %s (%d members)", obj.name, len(obj.static_members))

    def _emit_service(self, obj: PanosService) -> None:
        entry = ET.SubElement(self._service_root, "entry", {"name": obj.name})
        proto_root = ET.SubElement(entry, "protocol")
        proto_el = ET.SubElement(proto_root, obj.protocol)
        ET.SubElement(proto_el, "port").text = obj.port
        if obj.description:
            ET.SubElement(entry, "description").text = obj.description
        logger.debug("  Service: %s (%s/%s)", obj.name, obj.protocol, obj.port)

    def _emit_service_group(self, obj: PanosServiceGroup) -> None:
        entry = ET.SubElement(self._service_group_root, "entry", {"name": obj.name})
        members_root = ET.SubElement(entry, "members")
        for m in obj.members:
            ET.SubElement(members_root, "member").text = m
        logger.debug("  Service Group: %s", obj.name)

    # ------------------------------------------------------------------
    # Security rule emitter
    # ------------------------------------------------------------------

    def _emit_security_rule(self, obj: PanosSecurityRule) -> None:
        entry = ET.SubElement(self._rules_root, "entry", {"name": obj.name})

        from_el = ET.SubElement(entry, "from")
        for z in obj.from_zones:
            ET.SubElement(from_el, "member").text = z

        to_el = ET.SubElement(entry, "to")
        for z in obj.to_zones:
            ET.SubElement(to_el, "member").text = z

        src_el = ET.SubElement(entry, "source")
        for m in obj.source_addresses:
            ET.SubElement(src_el, "member").text = m

        dst_el = ET.SubElement(entry, "destination")
        for m in obj.destination_addresses:
            ET.SubElement(dst_el, "member").text = m

        app_el = ET.SubElement(entry, "application")
        for m in obj.applications:
            ET.SubElement(app_el, "member").text = m

        svc_el = ET.SubElement(entry, "service")
        for m in obj.services:
            ET.SubElement(svc_el, "member").text = m

        ET.SubElement(entry, "action").text = obj.action

        if obj.description:
            ET.SubElement(entry, "description").text = obj.description

        ET.SubElement(entry, "disabled").text = "yes" if obj.disabled else "no"
        ET.SubElement(entry, "log-start").text = "yes" if obj.log_start else "no"
        ET.SubElement(entry, "log-end").text = "yes" if obj.log_end else "no"

        if obj.tag:
            tag_el = ET.SubElement(entry, "tag")
            for t in obj.tag:
                ET.SubElement(tag_el, "member").text = t

        logger.debug("  Rule: %s (%s)", obj.name, obj.action)

        if obj.warnings:
            self.warnings.append(
                f"{obj.name}: {escape('; '.join(obj.warnings))}"
            )


# end of lib/migrate/generator.py
