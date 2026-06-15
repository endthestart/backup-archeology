# Backup Archeology

```text
 ____             _                  _              _
| __ )  __ _  ___| | ___   _ _ __   / \   _ __ ___ | |__
|  _ \ / _` |/ __| |/ / | | | '_ \ / _ \ | '__/ __|| '_ \
| |_) | (_| | (__|   <| |_| | |_) / ___ \| | | (__ | | | |
|____/ \__,_|\___|_|\_\\__,_| .__/_/   \_\_|  \___||_| |_|
                            |_|
```

**Known-junk cleanup for backup trees. Plan first, delete carefully.**

Backup Archeology scans old backup/NAS trees, removes files you already know you
do not want, and produces reviewable plans for everything that is only
potentially disposable.

It is inspired by developer cleanup tools such as `null-e`, but is aimed at
archives instead of live workstations.

## Why

Backup systems often collect years of generated files:

| Category | Examples |
| --- | --- |
| Developer artifacts | `node_modules`, `.venv`, `__pycache__`, `target`, `build`, `dist` |
| OS junk | `.DS_Store`, `Thumbs.db`, `$RECYCLE.BIN`, `.Trash-*` |
| Caches | `.cache`, browser caches, transcode caches, shader caches |
| Runtime files | `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`, dump files |
| Review-only bloat | VM disks, backup repos, Ollama models, recovery folders |

If you exclude something from Kopia, Restic, Borg, or another backup tool, old
copies are usually cleanup candidates. Backup Archeology turns that idea into a
repeatable scan, plan, quarantine, and delete workflow.

## Installation

```bash
git clone https://github.com/endthestart/backup-archeology.git
cd backup-archeology
python -m pip install -e .
ba --version
```

No third-party runtime dependencies are required. On a machine without `pip`,
you can run the single-file CLI directly:

```bash
python3 ba.py --version
python3 ba.py scan /path/to/backups
```

## Quick Start

```bash
# Scan a backup/NAS tree into a local SQLite inventory
ba scan /path/to/backups

# Summarize safe and review-tier candidates
ba analyze

# Review known-junk candidates before action
ba review --tier safe --limit 200

# Export all candidates to CSV for sorting/filtering
ba plan --tier all --format csv --output backup-cleanup-plan.csv

# Dry-run safe cleanup
ba clean --tier safe

# Recommended first real pass: move known junk to quarantine
ba clean --tier safe --quarantine /path/to/backups/.backup-archeology-quarantine

# Permanent delete of safe candidates only
ba clean --tier safe --delete --yes
```

## Commands

| Command | Description |
| --- | --- |
| `ba scan <path>` | Build an inventory for one backup root |
| `ba analyze` | Summarize candidate counts and sizes |
| `ba review [rule]` | Print candidate paths |
| `ba validate [rule]` | Check candidates against the current filesystem |
| `ba plan [rule]` | Export candidates as CSV or JSON |
| `ba clean [rule]` | Dry-run, quarantine, or delete safe candidates |
| `ba stats` | Show inventory statistics |
| `ba list-rules` | List cleanup rules |
| `ba logo` | Print the ASCII logo |

The old `ba delete` command still exists as a compatibility alias, but `ba clean`
is the preferred command.

## Safety Model

There are two classes of output:

- `safe`: generated junk that can normally be recreated or discarded, such as
  caches, metadata, virtual environments, dependency folders, build outputs,
  runtime swap/page/dump files, and transcode/shader caches.
- `review`: large, stateful, ambiguous, or high-consequence items, such as logs,
  `.bak` files, backup repositories, VM disk images, Ollama model storage,
  pooled storage folders, recovery folders, and empty directories.

Only the `safe` tier can be permanently deleted by the CLI. Review-tier items are
meant to be exported and inspected.

## Safety Features

- Dry-run is the default cleanup action.
- Inventory is bound to one scanned root.
- Cleanup refuses paths outside the scanned root.
- Cleanup refuses the scan root itself and protected metadata paths like `.git`.
- Nested matches are collapsed so a parent directory is only counted/deleted once.
- The scanner skips its own SQLite database and quarantine directory.
- Permanent deletion is limited to the `safe` tier.
- Quarantine mode preserves relative paths for recovery.
- `analyze`, `review`, and `plan` use the inventory without touching the live
  filesystem, so they stay fast on large or network-mounted archives.
- `validate` checks candidate paths only when you ask for it, and can prune
  missing/type-changed candidates from the inventory with `--prune-stale`.
- `clean` always validates each candidate immediately before quarantine or
  deletion, then removes successful changes from the inventory.
- Every real cleanup writes a CSV manifest with action, status, path, size, rule,
  destination, and error columns.

## Safe Rules

- NAS metadata: `@eaDir`, `@Recycle`
- OS metadata: `.DS_Store`, `.AppleDouble`, `.LSOverride`, `._*`, `Thumbs.db`,
  `desktop.ini`
- OS trash/system junk: `$RECYCLE.BIN`, `System Volume Information`,
  `.Trash-*`, `.Trashes`, `.Spotlight-V100`, `.fseventsd`, and similar
- Windows runtime files: `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`,
  `DumpStack.log`, `MEMORY.DMP`, `*.dmp`
- Node: `node_modules`, project `dist`, `build`, `.next`, `.nuxt`, `.turbo`,
  `coverage`
- Python: `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`,
  `.ruff_cache`, `.tox`, `.nox`, `.ipynb_checkpoints`, bytecode
- Rust: `target` directories next to `Cargo.toml`
- Java: Maven `target` and Gradle `build` directories next to project markers
- Backup-excluded build outputs: `target`, `build`, `dist`
- Package caches: `.npm`, `_cacache`, `.pnpm-store`, `.gradle`, Yarn and pip caches
- Generic caches: `.cache`, `cache`, `Cache`, `Caches`, `GPUCache`, `Code Cache`
- Browser caches: Firefox `cache2` and `startupCache`, Chrome `Cache`,
  macOS `Library/Caches`, and similar browser cache paths
- Media and gaming caches: `.transcode`, `transcode`, `Transcode`,
  `shadercache`, `ShaderCache`
- JetBrains workspace state files: `.idea/workspace.xml`, `.idea/tasks.xml`,
  `.idea/usage.statistics.xml`
- Common Windows temp folders

## Review Rules

- Partial downloads
- Temporary and backup-looking files
- Log files
- Vendored dependency directories
- Windows recovery/repair directories: `Recovery`, `found.???`
- DrivePool-style pooled storage folders: `PoolPart.*`
- Backup repositories: `Kopia Repository`, `KopiaRepo`, `.kopia`, `restic`,
  `borg`, `Duplicati`
- JetBrains shelf directories
- Ollama model storage: `.ollama/models`
- VM disk images: `*.qcow2`, `*.vmdk`, `*.vdi`, `*.vhd`, `*.vhdx`
- Empty directories

## Suggested NAS Workflow

```bash
ba scan /Volumes/NAS/Backups
ba analyze
ba validate --tier safe
ba plan --tier all --format csv --output nas-cleanup-plan.csv
ba review --tier safe --limit 200
ba clean --tier safe --quarantine /Volumes/NAS/Backups/.backup-archeology-quarantine
```

After you are comfortable with the manifest and quarantine results, either delete
the quarantine manually or run a fresh scan followed by:

```bash
ba clean --tier safe --delete --yes
```

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m py_compile ba.py tests/test_ba.py
ba logo
```

## Disclaimer

Backup Archeology is provided as-is without warranty. Use `ba plan`, dry runs,
and quarantine mode before permanently deleting anything from an archive.

## License

MIT License
