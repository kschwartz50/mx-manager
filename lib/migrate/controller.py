"""Migration controller for mx-manager.

Orchestrates the two-phase PAN-OS migration workflow:

    Phase 1 — Map:
        Walks the MX registry and writes a structured JSON manifest.
        Result: data/migrations/<base>_manifest.json

    Phase 2 — Generate:
        Reads the manifest and emits a PAN-OS candidate config XML.
        Result: data/migrations/<base>_migrated.xml

Usage from the CLI or a script:

    from lib.controller import Controller
    from lib.migrate.controller import MigrationController

    ctl = Controller()
    config_root_uid = ctl.import_config("path/to/config.xml")

    migration_ctl = MigrationController(ctl, base_filename="iad1-edge01")
    manifest = migration_ctl.run_migration(config_root_uid)
    xml_path = migration_ctl.generate_xml(manifest)
"""

from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console

from typing import Any
from lib.migrate.generator import PanosGenerator
from lib.migrate.mapper import MxPanosMapper

console = Console()


class MigrationController:
    """Orchestrates the MX → PAN-OS migration workflow."""

    def __init__(self, ctl: Any, base_filename: str) -> None:
        self.ctl = ctl
        self.base_filename = base_filename

        self.manifest_name = f"{base_filename}_manifest.json"
        self.xml_name = f"{base_filename}_migrated.xml"

        self.manifest_path = self.ctl.workspace_manager.get_migration_file(
            self.manifest_name
        )
        self.xml_path = self.ctl.workspace_manager.get_migration_file(self.xml_name)

    def run_migration(self, config_root_uid: str) -> Dict[str, Any]:
        """Phase 1: maps MX firewall rules into a PAN-OS manifest.

        Args:
            config_root_uid: ConfigRoot UID returned by Controller.import_config().

        Returns:
            The populated manifest dict (also persisted to disk).
        """
        mapper = MxPanosMapper(self.ctl, manifest_file=self.manifest_name)
        mapper.migrate_firewall_rules(config_root_uid)
        return mapper.manifest

    def generate_xml(self, manifest: Dict[str, Any]) -> Optional[str]:
        """Phase 2: transforms the manifest into a PAN-OS XML config file.

        Args:
            manifest: The dict returned by run_migration().

        Returns:
            Absolute path to the written XML file, or None on error.
        """
        try:
            generator = PanosGenerator(manifest, self.xml_path)
            generator.generate_objects()
            generator.generate_zones()
            generator.generate_security_policies()
            generator.log_warnings()
            out_path = generator.write_xml()
            console.print(f"\n[bold steel_blue]XML written:[/] {out_path}")
            return out_path
        except Exception as exc:
            console.print(f"[bold red]Error:[/] Failed to generate XML: {exc}")
            return None


# end of lib/migrate/controller.py
