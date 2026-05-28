"""Top-level orchestrator for mx-manager.

Owns the per-run runtime resources (workspace, registry) and wires the
import -> registry state -> export flow so the CLI entry point stays thin.
"""

from pathlib import Path
from typing import Optional

from lib.exporter import ExcelConfigExporter, JSONConfigExporter
from lib.importer import MXImporter
from lib.log_utils import get_logger
from lib.registry.graph import DataRegistry
from lib.workspace import WorkspaceManager

logger = get_logger(__name__)


class Controller:
    """Main entry point: owns runtime state and orchestrates import/export.

    One workspace and one registry per run. Importer/Exporter are lightweight
    services that operate on those shared resources.
    """

    def __init__(
        self,
        *,
        verbose: bool = False,
        pretty: bool = True,
        base_dir: Optional[Path] = None,
    ):
        self.verbose = verbose
        self.pretty = pretty

        self.workspace_manager = WorkspaceManager(
            base_dir=str(base_dir) if base_dir is not None else "data"
        )
        self.registry = DataRegistry()

        self.importer = MXImporter(
            workspace=self.workspace_manager,
            registry=self.registry,
        )

        # Filled in by _setup_file_paths() once we know the input file.
        self.config_file_basename: Optional[str] = None
        self.registry_state_filename: Optional[str] = None
        self.json_export_filename: Optional[str] = None
        self.excel_export_filename: Optional[str] = None

    # ----------------------------------------------------------------------
    # Public workflow
    # ----------------------------------------------------------------------

    def import_config(self, file_path: str) -> str:
        """Ingests the config into the workspace and builds the registry.

        Steps:
            1. Copy the source XML into ``data/source/``.
            2. Parse + populate the in-memory registry.
            3. Persist the registry state as JSON to ``data/registry/``.

        Args:
            file_path: Path to the source XML (absolute or relative).

        Returns:
            UID of the imported ``ConfigRoot`` node.
        """
        logger.info("Workspace base_dir:     %s", self.workspace_manager.base_dir)
        logger.info("Workspace source_dir:   %s", self.workspace_manager.source_dir)
        logger.info("Workspace registry_dir: %s", self.workspace_manager.registry_dir)
        logger.info("Workspace export_dir:   %s", self.workspace_manager.export_dir)
        logger.info("Import file: %s", file_path)

        self._setup_file_paths(file_path)

        # 1) Stage the source in the workspace.
        local_copy: Path = self.workspace_manager.ingest_config(file_path)

        # 2) Parse + populate the registry.
        config_root_uid = self.importer.import_xml(local_copy, original_path=file_path)

        # 3) Persist the whole registry state for future inspection.
        if self.registry_state_filename:
            self.registry.save_to_json(Path(self.registry_state_filename))
            logger.info("Wrote registry state to: %s", self.registry_state_filename)

        logger.info("Import completed for file: %s", file_path)
        return config_root_uid

    def export_config(
        self,
        config_root_uid: str,
        excel: bool = True,
    ) -> None:
        """Writes the JSON payload (always) and optionally the Excel workbook.

        Args:
            config_root_uid: ConfigRoot UID returned by ``import_config``.
            excel: If True, also emit the ``_audit.xlsx`` workbook.
        """
        json_exporter = JSONConfigExporter(self.workspace_manager, self.registry)
        json_path = json_exporter.export_to_json(
            config_root_uid=config_root_uid,
            output_filename=self.json_export_filename,
        )
        logger.info("Wrote JSON output to: %s", json_path)

        if excel:
            excel_exporter = ExcelConfigExporter(
                self.workspace_manager, self.registry
            )
            xlsx_path = excel_exporter.export_to_excel(
                config_root_uid=config_root_uid,
                output_filename=self.excel_export_filename,
            )
            logger.info("Wrote Excel workbook to: %s", xlsx_path)

    # ----------------------------------------------------------------------
    # Internals
    # ----------------------------------------------------------------------

    def _setup_file_paths(self, file_path: str) -> None:
        """Derives registry state/export filenames from the input config basename."""
        path = Path(file_path)
        self.config_file_basename = path.stem
        logger.debug("Config file basename set to: %s", self.config_file_basename)

        self.registry_state_filename = str(
            self.workspace_manager.get_registry_file(
                f"{self.config_file_basename}_state.json"
            )
        )
        self.json_export_filename = str(
            self.workspace_manager.get_export_file(
                f"{self.config_file_basename}_export.json"
            )
        )
        self.excel_export_filename = str(
            self.workspace_manager.get_export_file(
                f"{self.config_file_basename}_audit.xlsx"
            )
        )
        logger.debug("Registry state filename: %s", self.registry_state_filename)
        logger.debug("JSON export filename: %s", self.json_export_filename)
        logger.debug("Excel export filename: %s", self.excel_export_filename)


# end of lib/controller.py
