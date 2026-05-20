# mx-manager

A Python CLI toolkit for importing, analyzing, and migrating **Juniper MX** router configurations.

mx-manager parses Junos XML configuration files, builds an in-memory graph of the device's interface and routing topology, and exports structured analysis artifacts. A companion tool, `panos-migrator`, generates **PAN-OS candidate configurations** from those same MX configs to assist firewall migration projects.

## Features

- Parse Junos XML configuration exports from MX series routers
- Export interface and routing analysis as **JSON** and **Excel** (`.xlsx`)
- Generate PAN-OS migration manifests and candidate XML configurations
- Rich terminal output with structured logging

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`:
  - `rich` — terminal output
  - `pandas` — tabular data handling
  - `openpyxl` — Excel export
  - `typing_extensions` — type hint backports

## Installation

```bash
git clone https://github.com/kschwartz50/mx-manager.git
cd mx-manager
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

```bash
# Analyze an MX configuration and export JSON + Excel
python mx-manager.py -f data/source/your-router.xml

# Generate PAN-OS migration artifacts
python panos-migrator.py -f data/source/your-router.xml
```

See [usage.md](usage.md) for full CLI reference and output details.

## License

See [LICENSE](LICENSE) for terms.
