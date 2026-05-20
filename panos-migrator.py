#!/usr/bin/env python3
"""PAN-OS migration entrypoint for mx-manager.

Imports a Juniper MX XML configuration, populates the in-memory graph
registry, and generates PAN-OS candidate configuration artifacts:

    data/migrations/<stem>_manifest.json   — structured migration manifest
    data/migrations/<stem>_migrated.xml    — PAN-OS candidate config XML

Usage:
    python panos-migrator.py -f data/source/iad1-edge01.xml
    python panos-migrator.py -f data/source/iad1-edge01.xml -v
"""

import argparse
from pathlib import Path

from rich.console import Console

from lib.controller import Controller
from lib.log_utils import get_logger, setup_logging
from lib.migrate.controller import MigrationController

DEFAULT_SOURCE_FILE = "data/source/iad1-edge01.xml"

console = Console()


def parse_cli_args() -> argparse.Namespace:
    """Parse CLI arguments for panos-migrator."""
    parser = argparse.ArgumentParser(
        prog="panos-migrator",
        description="Import an MX config and generate PAN-OS migration artifacts.",
    )

    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        help="Path to the Junos XML configuration file",
        default=DEFAULT_SOURCE_FILE,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging output",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    setup_logging(verbose=args.verbose, pretty=True)
    logger = get_logger(__name__)

    logger.info(
        f"[steel_blue1]---------- Starting Migration: {args.file.name} ----------[/]"
    )

    repo_root = Path(__file__).resolve().parent

    xml_path = args.file if args.file.is_absolute() else repo_root / args.file
    if not xml_path.exists():
        logger.error(f"Missing: {xml_path}")
        raise SystemExit(f"Missing: {xml_path}")

    # Phase 0 — import the MX configuration into the graph registry
    ctl = Controller(verbose=args.verbose, pretty=True, base_dir=repo_root / "data")
    config_root_uid = ctl.import_config(str(xml_path))

    # Phase 1+2 — map firewall rules → manifest, then emit PAN-OS XML
    base_name = xml_path.stem
    mig_ctl = MigrationController(ctl, base_name)

    manifest = mig_ctl.run_migration(config_root_uid)
    out_path = mig_ctl.generate_xml(manifest)

    if out_path:
        console.print(
            f"\n[bold green]Success:[/] XML written to [magenta]{out_path}[/]"
        )
    else:
        console.print("\n[bold red]Failed:[/] XML generation encountered an error.")


if __name__ == "__main__":
    main()
