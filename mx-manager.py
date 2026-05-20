#!/usr/bin/env python3
"""mx-manager CLI entrypoint.

Imports a Juniper MX XML configuration, populates the in-memory graph
registry, and exports interface analysis artifacts as JSON and Excel.
"""

import argparse
from pathlib import Path

from lib.controller import Controller
from lib.log_utils import get_logger, setup_logging

DEFAULT_SOURCE_FILE = "data/source/iad1-edge01.xml"


def parse_cli_args() -> argparse.Namespace:
    """Parse CLI arguments for mx-manager."""
    parser = argparse.ArgumentParser(
        prog="mx-manager",
        description="Import a Juniper MX configuration and export analysis artifacts.",
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

    parser.add_argument(
        "--no-excel",
        action="store_true",
        help="Skip the Excel export (JSON is always written)",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    setup_logging(verbose=args.verbose, pretty=True)
    logger = get_logger("mx-manager")
    msg = "Enabled" if args.verbose else "Disabled"
    logger.info(
        f"[steel_blue1]---------- Starting {Path(__file__).name} with verbose logging: {msg}----------[/]"
    )

    repo_root = Path(__file__).resolve().parent
    logger.info(f"Repository root: {repo_root}")

    xml_path = args.file if args.file.is_absolute() else repo_root / args.file
    if not xml_path.exists():
        logger.error(f"Missing: {xml_path}")
        raise SystemExit(f"Missing: {xml_path}")

    ctl = Controller(verbose=args.verbose, pretty=True, base_dir=repo_root / "data")

    config_root_uid = ctl.import_config(str(xml_path))

    # JSON is always exported. Excel is on by default for parity with srx-manager.
    ctl.export_config(config_root_uid=config_root_uid, excel=not args.no_excel)


if __name__ == "__main__":
    main()
