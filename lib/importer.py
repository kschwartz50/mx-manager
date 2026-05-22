"""MX configuration importer.

v2 scope: interfaces + routing-instances + policy-options + firewall.

Parser selection is done off a lightweight version detector and a
``_parser_map`` of Junos version -> parser class. The 21.x parser covers
the MX edge fleet; older/newer Junos releases can be added by registering
additional entries.

Ingestion order matters for reference resolution:

    1. ConfigRoot registration (anchor)
    2. Version detection + parser instantiation
    3. Interfaces  ← must come before routing (RI factory resolves unit UIDs)
    4. Policy options  ← must come before routing instances (BGP wires to
       existing PolicyStatement nodes so forward-references are avoided)
    5. Protocols / ports  ← before firewall so PortList UIDs are registered
       when the firewall factory wires port-list cross-slice edges
    6. Firewall filters  ← after policy-options and protocols-ports so that
       PrefixList and PortList UIDs are available for edge wiring
    7. Routing instances
"""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Type

from lib.firewall.factory import FirewallFactory
from lib.interface.factory import InterfaceFactory
from lib.log_utils import get_logger
from lib.parsers.base import BaseMXParser
from lib.parsers.helpers import sanitize_junos_xml
from lib.parsers.junos_mx import MXParser21x, MXParser23x
from lib.policy_options.factory import PolicyOptionsFactory
from lib.protocols_ports.factory import ProtocolsPortsFactory
from lib.registry.graph import DataRegistry
from lib.registry.objects import ConfigRoot
from lib.routing.factory import RoutingInstanceFactory
from lib.workspace import WorkspaceManager

logger = get_logger(__name__)


class MXImporter:
    """Orchestrates one-shot ingestion of an MX XML config.

    The importer owns the ConfigRoot registration, version detection,
    parser instantiation, and the delegation into the interface factory.
    It does not touch the graph directly beyond creating the ConfigRoot
    anchor — slice work is delegated to slice factories.
    """

    def __init__(self, *, workspace: WorkspaceManager, registry: DataRegistry):
        logger.debug(
            f"[steel_blue1]---------- Initializing {self.__class__.__name__} ----------[/]"
        )
        self.workspace = workspace
        self.registry = registry
        self._parser_map: Dict[str, Type[BaseMXParser]] = {
            "21.x": MXParser21x,
            "23.x": MXParser23x,
        }

    def import_xml(
        self, file_path: str | Path, original_path: str | None = None
    ) -> str:
        """Imports one XML config and returns the ConfigRoot UID.

        Args:
            file_path: Path to the XML file that will actually be read.
            original_path: Optional original path used only for labeling
                (useful when the caller staged the file into ``data/source``
                and still wants to record where it came from).

        Returns:
            UID of the ``ConfigRoot`` node. All slice graph content is
            anchored to this UID.
        """
        local_path = Path(file_path)
        if not local_path.exists():
            raise FileNotFoundError(f"File not found: {local_path}")

        xml_bytes = local_path.read_bytes()
        sha256 = hashlib.sha256(xml_bytes).hexdigest()

        # Version detection runs against the sanitized bytes because the
        # raw bytes contain ``<junos:...>`` elements without a declared
        # namespace, which plain ElementTree cannot parse.
        try:
            root_et = ET.fromstring(sanitize_junos_xml(xml_bytes))
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML syntax: {e}") from e

        source_name = Path(original_path or local_path.name).stem

        # ------------------------------------------------------------------
        # 1. Register ConfigRoot — the anchor for every slice graph edge.
        # ------------------------------------------------------------------
        cfg = ConfigRoot(
            name=source_name,
            file_path=str(original_path or local_path),
            raw_config="",
            metadata={"sha256": sha256, "root_tag": root_et.tag},
        )
        config_root_uid = self.registry.register_node(
            cfg, f"config-root|sha256={sha256}"
        )

        # ------------------------------------------------------------------
        # 2. Detect Junos version and instantiate the matching parser.
        # ------------------------------------------------------------------
        version = self._detect_version(root_et)
        parser_cls = self._parser_map.get(version)
        if not parser_cls:
            raise NotImplementedError(
                f"No parser found for Junos version: {version}"
            )

        logger.info(
            "Detected Junos version [yellow]%s[/yellow] -> using %s",
            version,
            parser_cls.__name__,
        )
        parser_instance = parser_cls(xml_bytes)

        # ------------------------------------------------------------------
        # 3. Parse + ingest interfaces.
        # ------------------------------------------------------------------
        interfaces_data = parser_instance.parse_interface_configs()
        logger.info(
            "Ingesting %i interfaces via InterfaceFactory...", len(interfaces_data)
        )

        iface_factory = InterfaceFactory(self.registry)
        iface_factory.ingest_interfaces(interfaces_data, config_root_uid)
        logger.info("Interface ingestion complete.")

        # ------------------------------------------------------------------
        # 4. Parse + ingest policy options.
        #    Must run before routing instances so that BGP group wiring can
        #    link to already-registered PolicyStatement nodes rather than
        #    creating forward-reference placeholders.
        # ------------------------------------------------------------------
        policy_data = parser_instance.parse_policy_options()
        policy_factory = PolicyOptionsFactory(self.registry)
        policy_factory.ingest_policy_options(policy_data, config_root_uid)
        logger.info(
            "Policy options ingested: %i statements, %i prefix-lists, %i as-paths.",
            len(policy_data["policy_statements"]),
            len(policy_data["prefix_lists"]),
            len(policy_data["as_paths"]),
        )

        # ------------------------------------------------------------------
        # 5. Parse + ingest protocols and ports.
        #    Must come before firewall so that PortList UIDs are registered
        #    before the firewall factory attempts to wire port-list edges.
        # ------------------------------------------------------------------
        port_list_data = parser_instance.parse_port_lists()
        pp_factory = ProtocolsPortsFactory(self.registry)
        pp_factory.ingest_port_lists(port_list_data, config_root_uid)

        # ------------------------------------------------------------------
        # 6. Parse + ingest firewall filters.
        #    Must come after policy-options (PrefixList UIDs) and
        #    protocols-ports (PortList UIDs) so cross-slice edges can be
        #    wired at factory time rather than via forward-reference
        #    placeholders.
        # ------------------------------------------------------------------
        firewall_data = parser_instance.parse_firewall_filters()
        fw_factory = FirewallFactory(self.registry)
        fw_factory.ingest_firewall_filters(firewall_data, config_root_uid)
        logger.info("Firewall ingested: %i filter(s).", len(firewall_data))

        # ------------------------------------------------------------------
        # 7. Parse + ingest routing instances.
        # ------------------------------------------------------------------
        routing_data = parser_instance.parse_routing_instances()
        logger.info(
            "Ingesting %i routing instances via RoutingInstanceFactory...",
            len(routing_data),
        )
        routing_factory = RoutingInstanceFactory(self.registry)
        routing_factory.ingest_routing_instances(routing_data, config_root_uid)
        logger.info("Routing instance ingestion complete.")

        return config_root_uid

    # ----------------------------------------------------------------------
    # Version detection
    # ----------------------------------------------------------------------

    def _detect_version(self, root_et: ET.Element) -> str:
        """Detects a Junos major-version bucket from the XML.

        Looks in two common places:

        * ``<software-information><junos-version>`` (what ``show version``
          emits inside an rpc-reply)
        * ``<version>`` at the top of a ``<configuration>`` root (what
          ``show configuration | display xml`` emits)

        Returns the bucket string used as a key into ``_parser_map``.
        Unknown versions default to ``"21.x"`` because v1 is MX-only and
        the 21.x grammar is a safe baseline for 20.x-23.x configs.
        """
        # Try <software-information><junos-version>
        sw_ver = root_et.findtext(".//software-information/junos-version")
        if sw_ver:
            return self._version_to_bucket(sw_ver)

        # Try a top-level <version>
        cfg_ver = root_et.findtext("./version")
        if cfg_ver:
            return self._version_to_bucket(cfg_ver)

        # No version string found anywhere in the document.
        logger.warning(
            "Could not detect Junos version from XML — no "
            "<software-information/junos-version> or top-level <version> "
            "element found.  Falling back to '21.x' parser.  Pass a config "
            "that includes version information or add a dedicated parser "
            "bucket if grammar drift is a concern."
        )
        return "21.x"

    @staticmethod
    def _version_to_bucket(version: str) -> str:
        """Maps ``21.2R3-S4.8`` -> ``21.x``."""
        parts = version.strip().split(".")
        if not parts:
            return "21.x"
        return f"{parts[0]}.x"


# end of lib/importer.py
