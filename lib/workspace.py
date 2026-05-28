"""Workspace layout + file ingestion helpers."""

from pathlib import Path


class WorkspaceManager:
    """Manages the directory structure and file operations for the workspace."""

    def __init__(self, base_dir: str = "data") -> None:
        self.base_dir = Path(base_dir).resolve()
        self.source_dir = self.base_dir / "source"
        self.source_dir.mkdir(parents=True, exist_ok=True)
        self.registry_dir = self.base_dir / "registry"
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir = self.base_dir / "exports"
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def ingest_config(self, file_path: str) -> Path:
        src = Path(file_path)
        dst = self.source_dir / src.name
        dst.write_bytes(src.read_bytes())
        return dst

    def get_registry_file(self, filename: str) -> Path:
        return self.registry_dir / filename

    def get_export_file(self, filename: str) -> Path:
        return self.export_dir / filename

    def get_migration_file(self, filename: str) -> Path:
        migration_dir = self.base_dir / "migrations"
        migration_dir.mkdir(parents=True, exist_ok=True)
        return migration_dir / filename
