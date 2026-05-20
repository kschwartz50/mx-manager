# mx-manager — Usage Guide

## Overview

mx-manager provides two CLI entry points:

| Script | Purpose |
|---|---|
| `mx-manager.py` | Import MX config → export JSON + Excel analysis |
| `panos-migrator.py` | Import MX config → generate PAN-OS migration artifacts |

Both tools expect a Junos XML configuration file as input. Place source files in `data/source/`.

---

## mx-manager.py

Imports a Juniper MX XML configuration and exports interface analysis artifacts.

### Usage

```
python mx-manager.py [-f FILE] [-v] [--no-excel]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-f`, `--file` | `data/source/iad1-edge01.xml` | Path to the Junos XML configuration file |
| `-v`, `--verbose` | off | Enable verbose logging output |
| `--no-excel` | off | Skip Excel export (JSON is always written) |

### Examples

```bash
# Run with defaults (uses data/source/iad1-edge01.xml)
python mx-manager.py

# Specify a different source file
python mx-manager.py -f data/source/my-router.xml

# Verbose output, skip Excel
python mx-manager.py -f data/source/my-router.xml -v --no-excel
```

### Output

Artifacts are written to `data/`:

- `data/export/<stem>.json` — full interface graph as structured JSON
- `data/export/<stem>.xlsx` — interface analysis workbook (unless `--no-excel`)

---

## panos-migrator.py

Imports a Juniper MX XML configuration and generates PAN-OS candidate configuration artifacts for firewall migration.

### Usage

```
python panos-migrator.py [-f FILE] [-v]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-f`, `--file` | `data/source/iad1-edge01.xml` | Path to the Junos XML configuration file |
| `-v`, `--verbose` | off | Enable verbose logging output |

### Examples

```bash
# Run migration with defaults
python panos-migrator.py

# Specify source file with verbose logging
python panos-migrator.py -f data/source/my-router.xml -v
```

### Output

Artifacts are written to `data/migrations/`:

- `data/migrations/<stem>_manifest.json` — structured migration manifest (firewall rules, address objects, etc.)
- `data/migrations/<stem>_migrated.xml` — PAN-OS candidate configuration XML

---

## Directory Layout

```
mx-manager/
├── mx-manager.py          # Analysis entrypoint
├── panos-migrator.py      # Migration entrypoint
├── requirements.txt
├── lib/                   # Core library modules
│   ├── controller.py      # Orchestrates import/export
│   ├── core.py            # Graph registry and data models
│   ├── importer.py        # Junos XML parser
│   ├── exporter.py        # JSON / Excel writer
│   ├── workspace.py       # File path management
│   └── log_utils.py       # Logging helpers
└── data/                  # Runtime data (gitignored)
    ├── source/            # Input: Junos XML files
    ├── export/            # Output: JSON and Excel artifacts
    └── migrations/        # Output: PAN-OS migration artifacts
```
