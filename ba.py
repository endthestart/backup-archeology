#!/usr/bin/env python3
"""
Backup Archeology - safe cleanup of known junk in backup trees.

The tool is intentionally conservative about actions and explicit about plans:
scan a root once, classify known junk into safe/review tiers, export a plan,
then dry-run, quarantine, or delete only paths from the scanned inventory.
"""

import argparse
import csv
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


VERSION = "1.0.0"
LOGO = r"""
 ____             _                  _              _
| __ )  __ _  ___| | ___   _ _ __   / \   _ __ ___ | |__
|  _ \ / _` |/ __| |/ / | | | '_ \ / _ \ | '__/ __|| '_ \
| |_) | (_| | (__|   <| |_| | |_) / ___ \| | | (__ | | | |
|____/ \__,_|\___|_|\_\\__,_| .__/_/   \_\_|  \___||_| |_|
                            |_|
"""
TAGLINE = "Known-junk cleanup for backup trees. Plan first, delete carefully."

SAFE = "safe"
REVIEW = "review"
KIND_FILE = "file"
KIND_DIR = "dir"
QUARANTINE_DIR_NAME = ".backup-archeology-quarantine"

PROTECTED_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".bzr",
    ".ssh",
    ".gnupg",
}


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def canonical(path: str) -> str:
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def absolute(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def format_size(size: int) -> str:
    value = float(size or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


def parse_size(value: Optional[str]) -> int:
    if not value:
        return 0

    text = value.strip().lower()
    units = {
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "m": 1024 ** 2,
        "mb": 1024 ** 2,
        "g": 1024 ** 3,
        "gb": 1024 ** 3,
        "t": 1024 ** 4,
        "tb": 1024 ** 4,
    }

    number = text
    multiplier = 1
    for suffix, factor in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)]
            multiplier = factor
            break

    try:
        return int(float(number) * multiplier)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid size: {value}")


def is_within(path: str, root: str) -> bool:
    path = absolute(path)
    root = absolute(root)
    return path == root or path.startswith(root + os.sep)


STALE_REASONS = {
    "path no longer exists",
    "expected directory",
    "expected file",
}


def validate_candidate_state(cand: "Candidate", root: str) -> None:
    path = absolute(cand.path)
    root = absolute(root)
    if not is_within(path, root):
        raise RuntimeError("refusing path outside scanned root")
    if path == root:
        raise RuntimeError("refusing to remove scan root")
    if any(part in PROTECTED_NAMES for part in Path(path).parts):
        raise RuntimeError("refusing protected path")
    if not os.path.lexists(path):
        raise RuntimeError("path no longer exists")
    if cand.kind == KIND_DIR:
        if not os.path.isdir(path) or os.path.islink(path):
            raise RuntimeError("expected directory")
    else:
        if not os.path.isfile(path) or os.path.islink(path):
            raise RuntimeError("expected file")
        current_size = os.stat(path, follow_symlinks=False).st_size
        if current_size != cand.size:
            raise RuntimeError("file size changed since scan; rescan first")


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    category: str
    tier: str
    kind: str
    sql: str


@dataclass
class Candidate:
    path: str
    size: int
    mtime: int
    kind: str
    rule: str
    category: str
    tier: str
    description: str

    def as_dict(self, root: str) -> Dict[str, object]:
        rel = os.path.relpath(self.path, root)
        return {
            "tier": self.tier,
            "category": self.category,
            "rule": self.rule,
            "kind": self.kind,
            "size": self.size,
            "size_human": format_size(self.size),
            "mtime": self.mtime,
            "modified": datetime.fromtimestamp(self.mtime).isoformat(timespec="seconds")
            if self.mtime
            else "",
            "relative_path": "." if rel == "." else rel,
            "path": self.path,
            "description": self.description,
        }


RULES: List[Rule] = [
    Rule(
        "nas_metadata",
        "NAS recycle and metadata directories",
        "system",
        SAFE,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name IN ('@eaDir', '@Recycle')",
    ),
    Rule(
        "nas_poolpart_dirs",
        "DrivePool/pooled storage directories from backup exclude lists",
        "storage",
        REVIEW,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name GLOB 'PoolPart.*'",
    ),
    Rule(
        "os_trash_and_metadata_dirs",
        "OS trash, spotlight, recycle, and metadata directories",
        "system",
        SAFE,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE name IN (
            '$RECYCLE.BIN', 'RECYCLER', 'System Volume Information',
            '.Trash', '.Trash-1000',
            '__MACOSX', '.fseventsd', '.Spotlight-V100',
            '.DocumentRevisions-V100', '.TemporaryItems', '.Trashes',
            'Network Trash Folder', 'Temporary Items'
        )
        OR name GLOB '.Trash-*'
        """,
    ),
    Rule(
        "windows_recovery_dirs",
        "Windows recovery and filesystem repair directories",
        "system",
        REVIEW,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE name IN ('Recovery', '$SysReset', '$Windows.~BT', '$Windows.~WS', '$WinREAgent')
        OR name GLOB 'found.[0-9][0-9][0-9]'
        """,
    ),
    Rule(
        "os_metadata_files",
        "OS metadata files",
        "system",
        SAFE,
        KIND_FILE,
        """
        SELECT path, size, mtime FROM files
        WHERE name IN (
            '.DS_Store', '._.DS_Store', '.AppleDouble', '.LSOverride',
            '.VolumeIcon.icns', '.apdisk', 'Thumbs.db', 'thumbs.db',
            'ehthumbs.db', 'ehthumbs_vista.db', 'desktop.ini', 'Desktop.ini'
        )
        OR name GLOB '._*'
        """,
    ),
    Rule(
        "windows_runtime_files",
        "Windows page, hibernation, dump, and crash files",
        "system",
        SAFE,
        KIND_FILE,
        """
        SELECT path, size, mtime FROM files
        WHERE name IN (
            'pagefile.sys', 'swapfile.sys', 'hiberfil.sys',
            'DumpStack.log', 'DumpStack.log.tmp', 'MEMORY.DMP'
        )
        OR extension IN ('dmp', 'stackdump')
        """,
    ),
    Rule(
        "node_modules",
        "Node dependency directories",
        "development",
        SAFE,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name = 'node_modules'",
    ),
    Rule(
        "python_virtualenvs",
        "Python virtual environment directories",
        "development",
        SAFE,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name IN ('.venv', 'venv', '.virtualenv', '.virtualenvs')",
    ),
    Rule(
        "python_caches",
        "Python cache and test cache directories",
        "development",
        SAFE,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE name IN (
            '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
            '.tox', '.nox', '.hypothesis', '.pytype', '.ipynb_checkpoints'
        )
        """,
    ),
    Rule(
        "python_bytecode",
        "Python bytecode files",
        "development",
        SAFE,
        KIND_FILE,
        "SELECT path, size, mtime FROM files WHERE extension IN ('pyc', 'pyo')",
    ),
    Rule(
        "node_build_outputs",
        "Node project build outputs",
        "development",
        SAFE,
        KIND_DIR,
        """
        SELECT d.path, d.total_size, d.mtime
        FROM directories d
        WHERE (
            d.name IN ('.next', '.nuxt', '.turbo', 'coverage')
            OR d.name IN ('dist', 'build')
        )
        AND EXISTS (
            SELECT 1 FROM files f
            WHERE f.name = 'package.json' AND f.parent_dir = d.parent_dir
        )
        """,
    ),
    Rule(
        "rust_target",
        "Rust target directories",
        "development",
        SAFE,
        KIND_DIR,
        """
        SELECT d.path, d.total_size, d.mtime
        FROM directories d
        WHERE d.name = 'target'
        AND EXISTS (
            SELECT 1 FROM files f
            WHERE f.name = 'Cargo.toml' AND f.parent_dir = d.parent_dir
        )
        """,
    ),
    Rule(
        "java_build_outputs",
        "Maven and Gradle build directories",
        "development",
        SAFE,
        KIND_DIR,
        """
        SELECT d.path, d.total_size, d.mtime
        FROM directories d
        WHERE (
            d.name = 'target'
            AND EXISTS (
                SELECT 1 FROM files f
                WHERE f.name = 'pom.xml' AND f.parent_dir = d.parent_dir
            )
        )
        OR (
            d.name = 'build'
            AND EXISTS (
                SELECT 1 FROM files f
                WHERE f.name IN ('build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts')
                AND f.parent_dir = d.parent_dir
            )
        )
        """,
    ),
    Rule(
        "ignored_build_dirs",
        "Build output directories from backup exclude lists",
        "development",
        SAFE,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name IN ('target', 'build', 'dist')",
    ),
    Rule(
        "project_package_caches",
        "Package manager cache directories",
        "development",
        SAFE,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE name IN ('.npm', '_cacache', '.pnpm-store', '.gradle')
        OR path LIKE '%/.yarn/cache'
        OR path LIKE '%/pip/cache'
        OR path LIKE '%/pip/http'
        OR path LIKE '%/pip/wheels'
        """,
    ),
    Rule(
        "generic_cache_dirs",
        "Generic cache directories",
        "cache",
        SAFE,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE name IN ('.cache', 'cache', 'Cache', 'Caches', 'GPUCache', 'Code Cache')
        """,
    ),
    Rule(
        "media_transcode_caches",
        "Media transcode cache directories",
        "media",
        SAFE,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name IN ('.transcode', 'transcode', 'Transcode')",
    ),
    Rule(
        "gaming_shader_caches",
        "Gaming shader cache directories",
        "gaming",
        SAFE,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name IN ('shadercache', 'ShaderCache')",
    ),
    Rule(
        "browser_cache_dirs",
        "Browser cache directories",
        "cache",
        SAFE,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE path LIKE '%Chrome%Cache%'
        OR path LIKE '%Chromium%Cache%'
        OR path LIKE '%Firefox%cache%'
        OR path LIKE '%/Mozilla/Firefox/Profiles/%/cache2'
        OR path LIKE '%/Mozilla/Firefox/Profiles/%/startupCache'
        OR path LIKE '%/Google/Chrome/%/Cache'
        OR path LIKE '%Safari%Cache%'
        OR path LIKE '%Edge%Cache%'
        OR path LIKE '%/Library/Caches'
        """,
    ),
    Rule(
        "xcode_build_caches",
        "Xcode build and module cache directories",
        "development",
        SAFE,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE name IN ('DerivedData', 'ModuleCache.noindex')
        OR path LIKE '%/Xcode/Archives/%'
        """,
    ),
    Rule(
        "windows_temp_dirs",
        "Windows temporary directories",
        "system",
        SAFE,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE path LIKE '%/AppData/Local/Temp'
        OR path LIKE '%/Windows/Temp'
        OR (name = 'Prefetch' AND parent_dir LIKE '%/Windows')
        """,
    ),
    Rule(
        "jetbrains_workspace_state",
        "JetBrains workspace state files",
        "development",
        SAFE,
        KIND_FILE,
        """
        SELECT path, size, mtime FROM files
        WHERE name IN ('workspace.xml', 'tasks.xml', 'usage.statistics.xml')
        AND parent_dir LIKE '%/.idea'
        """,
    ),
    Rule(
        "jetbrains_shelf",
        "JetBrains shelf directories",
        "development",
        REVIEW,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE name = 'shelf' AND parent_dir LIKE '%/.idea'",
    ),
    Rule(
        "backup_repositories",
        "Backup tool repositories excluded from other backups",
        "backup",
        REVIEW,
        KIND_DIR,
        """
        SELECT path, total_size, mtime FROM directories
        WHERE name IN ('Kopia Repository', 'KopiaRepo', '.kopia', 'restic', 'borg', 'Duplicati')
        """,
    ),
    Rule(
        "ollama_models",
        "Ollama model storage",
        "ai",
        REVIEW,
        KIND_DIR,
        "SELECT path, total_size, mtime FROM directories WHERE path LIKE '%/.ollama/models'",
    ),
    Rule(
        "vm_disk_images",
        "Virtual machine disk images",
        "virtualization",
        REVIEW,
        KIND_FILE,
        "SELECT path, size, mtime FROM files WHERE extension IN ('qcow2', 'vmdk', 'vdi', 'vhd', 'vhdx')",
    ),
    Rule(
        "partial_downloads",
        "Incomplete download files",
        "temporary",
        REVIEW,
        KIND_FILE,
        "SELECT path, size, mtime FROM files WHERE extension IN ('part', 'partial', 'crdownload', 'download')",
    ),
    Rule(
        "temp_files",
        "Temporary and backup-looking files",
        "temporary",
        REVIEW,
        KIND_FILE,
        """
        SELECT path, size, mtime FROM files
        WHERE extension IN ('tmp', 'temp', 'bak', 'backup', 'old', 'orig', 'swp', 'swo', 'swn')
        OR name GLOB '*~'
        OR name GLOB '#*#'
        OR name GLOB '.#*'
        OR name GLOB '.~lock.*'
        """,
    ),
    Rule(
        "log_files",
        "Log files and compressed log files",
        "logs",
        REVIEW,
        KIND_FILE,
        """
        SELECT path, size, mtime FROM files
        WHERE extension = 'log'
        OR name GLOB '*.log.[0-9]'
        OR name GLOB '*.log.[0-9][0-9]'
        OR name GLOB '*.log.gz'
        OR name GLOB '*.log.bz2'
        OR name GLOB '*.log.xz'
        OR name GLOB '*.log.zst'
        """,
    ),
    Rule(
        "vendor_dirs",
        "Vendored dependency directories",
        "development",
        REVIEW,
        KIND_DIR,
        """
        SELECT d.path, d.total_size, d.mtime
        FROM directories d
        WHERE d.name = 'vendor'
        AND (
            EXISTS (SELECT 1 FROM files f WHERE f.name = 'composer.json' AND f.parent_dir = d.parent_dir)
            OR EXISTS (SELECT 1 FROM files f WHERE f.name = 'go.mod' AND f.parent_dir = d.parent_dir)
        )
        """,
    ),
    Rule(
        "empty_dirs",
        "Empty directories",
        "structure",
        REVIEW,
        KIND_DIR,
        """
        SELECT d.path, d.total_size, d.mtime
        FROM directories d
        WHERE d.total_size = 0
        AND NOT EXISTS (SELECT 1 FROM files f WHERE f.parent_dir = d.path)
        AND NOT EXISTS (SELECT 1 FROM directories child WHERE child.parent_dir = d.path)
        """,
    ),
]


def get_rule(name: str) -> Optional[Rule]:
    for rule in RULES:
        if rule.name == name:
            return rule
    return None


class Database:
    """SQLite inventory for one scanned root."""

    def __init__(self, db_path: Optional[str] = None):
        explicit_db = db_path is not None
        if db_path is None:
            if sys.platform == "win32":
                base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
                cache_dir = os.path.join(base, "backup-archeology")
            else:
                cache_dir = os.path.expanduser("~/.cache/backup-archeology")
            db_path = os.path.join(cache_dir, "inventory.db")

        self.db_path = canonical(db_path)
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            try:
                os.makedirs(db_dir, exist_ok=True)
            except OSError:
                if explicit_db:
                    raise
                fallback_dir = os.path.join(tempfile.gettempdir(), "backup-archeology")
                os.makedirs(fallback_dir, exist_ok=True)
                self.db_path = os.path.join(fallback_dir, "inventory.db")

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                extension TEXT,
                size INTEGER NOT NULL,
                mtime INTEGER,
                is_hidden INTEGER,
                is_empty INTEGER,
                parent_dir TEXT,
                depth INTEGER
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS directories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                parent_dir TEXT,
                depth INTEGER,
                total_size INTEGER DEFAULT 0,
                mtime INTEGER DEFAULT 0
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_errors (
                path TEXT NOT NULL,
                error TEXT NOT NULL
            )
            """
        )

        self._ensure_column("directories", "mtime", "INTEGER DEFAULT 0")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_name ON files(name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_dir)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dirs_name ON directories(name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dirs_parent ON directories(parent_dir)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dirs_path ON directories(path)")
        self.conn.commit()

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        cols = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    def metadata(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_metadata(self, key: str, value: object) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, str(value)),
        )

    def root_path(self) -> str:
        root = self.metadata("root_path")
        if not root:
            raise RuntimeError("No scan found. Run 'ba scan <path>' first.")
        return root

    def close(self) -> None:
        self.conn.close()


class Scanner:
    """Directory scanner with bottom-up sizes and latest-child mtimes."""

    def __init__(self, db: Database):
        self.db = db
        self.file_count = 0
        self.dir_count = 0
        self.error_count = 0
        self.total_size = 0
        self.started_at: Optional[datetime] = None
        self.files_batch: List[Tuple[object, ...]] = []
        self.dirs_batch: List[Tuple[object, ...]] = []
        self.errors_batch: List[Tuple[str, str]] = []
        self.batch_size = 5000
        self.root_path = ""
        self.internal_db_paths = set()

    def scan(self, root_path: str, progress: bool = True) -> None:
        root = canonical(root_path)
        if not os.path.isdir(root):
            raise RuntimeError(f"scan root is not a directory: {root_path}")

        self.root_path = root
        self.internal_db_paths = {
            absolute(self.db.db_path),
            absolute(self.db.db_path + "-wal"),
            absolute(self.db.db_path + "-shm"),
            absolute(self.db.db_path + "-journal"),
        }

        print(f"Scanning: {root}")
        print("Building inventory and directory sizes...")

        self.started_at = datetime.now()
        cursor = self.db.conn.cursor()
        cursor.execute("DELETE FROM files")
        cursor.execute("DELETE FROM directories")
        cursor.execute("DELETE FROM scan_errors")
        self.db.conn.commit()

        self._scan_recursive(root, progress)
        self._flush_batches()

        self.db.set_metadata("scan_date", now_iso())
        self.db.set_metadata("root_path", root)
        self.db.set_metadata("file_count", self.file_count)
        self.db.set_metadata("dir_count", self.dir_count)
        self.db.set_metadata("error_count", self.error_count)
        self.db.set_metadata("total_size", self.total_size)
        self.db.conn.commit()

        elapsed = max((datetime.now() - self.started_at).total_seconds(), 0.001)
        print("\nScan complete")
        print(f"  Files: {self.file_count:,}")
        print(f"  Directories: {self.dir_count:,}")
        print(f"  Scan errors: {self.error_count:,}")
        print(f"  Total size: {format_size(self.total_size)}")
        print(f"  Time: {elapsed:.1f}s ({self.file_count / elapsed:,.0f} files/sec)")
        print(f"  Database: {self.db.db_path}")

    def _scan_recursive(self, dirpath: str, progress: bool) -> Tuple[int, int]:
        dir_total_size = 0
        latest_mtime = 0
        depth = dirpath.count(os.sep)
        parent_dir = os.path.dirname(dirpath)

        if self._should_skip_dir(dirpath):
            return 0, 0

        try:
            dir_stat = os.stat(dirpath, follow_symlinks=False)
            latest_mtime = int(dir_stat.st_mtime)
        except (PermissionError, OSError) as exc:
            self._record_error(dirpath, str(exc))
            return 0, 0

        try:
            with os.scandir(dirpath) as entries:
                for entry in entries:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            file_path = entry.path
                            if self._should_skip_file(file_path):
                                continue

                            stat = entry.stat(follow_symlinks=False)
                            size = int(stat.st_size)
                            mtime = int(stat.st_mtime)
                            name = entry.name
                            ext = os.path.splitext(name)[1].lstrip(".").lower() if "." in name else None

                            self.files_batch.append(
                                (
                                    file_path,
                                    name,
                                    ext,
                                    size,
                                    mtime,
                                    1 if name.startswith(".") else 0,
                                    1 if size == 0 else 0,
                                    dirpath,
                                    depth,
                                )
                            )

                            dir_total_size += size
                            latest_mtime = max(latest_mtime, mtime)
                            self.total_size += size
                            self.file_count += 1

                            if progress and self.file_count % 10000 == 0:
                                elapsed = max((datetime.now() - self.started_at).total_seconds(), 0.001)
                                print(
                                    f"  {self.file_count:,} files, {self.dir_count:,} dirs "
                                    f"({self.file_count / elapsed:,.0f} files/sec)",
                                    end="\r",
                                )

                            if len(self.files_batch) >= self.batch_size:
                                self._flush_files()
                        elif entry.is_dir(follow_symlinks=False):
                            subdir_size, subdir_mtime = self._scan_recursive(entry.path, progress)
                            dir_total_size += subdir_size
                            latest_mtime = max(latest_mtime, subdir_mtime)
                    except (PermissionError, OSError) as exc:
                        self._record_error(entry.path, str(exc))
        except (PermissionError, OSError) as exc:
            self._record_error(dirpath, str(exc))

        name = os.path.basename(dirpath) or dirpath
        self.dirs_batch.append((dirpath, name, parent_dir, depth, dir_total_size, latest_mtime))
        self.dir_count += 1

        if len(self.dirs_batch) >= self.batch_size:
            self._flush_dirs()

        return dir_total_size, latest_mtime

    def _should_skip_dir(self, path: str) -> bool:
        path = absolute(path)
        if os.path.basename(path) == QUARANTINE_DIR_NAME:
            return True
        return path in self.internal_db_paths

    def _should_skip_file(self, path: str) -> bool:
        return absolute(path) in self.internal_db_paths

    def _record_error(self, path: str, error: str) -> None:
        self.error_count += 1
        self.errors_batch.append((absolute(path), error))
        if len(self.errors_batch) >= self.batch_size:
            self._flush_errors()

    def _flush_files(self) -> None:
        if not self.files_batch:
            return
        self.db.conn.executemany(
            """
            INSERT OR REPLACE INTO files
            (path, name, extension, size, mtime, is_hidden, is_empty, parent_dir, depth)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            self.files_batch,
        )
        self.files_batch = []

    def _flush_dirs(self) -> None:
        if not self.dirs_batch:
            return
        self.db.conn.executemany(
            """
            INSERT OR REPLACE INTO directories
            (path, name, parent_dir, depth, total_size, mtime)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            self.dirs_batch,
        )
        self.dirs_batch = []

    def _flush_errors(self) -> None:
        if not self.errors_batch:
            return
        self.db.conn.executemany(
            "INSERT INTO scan_errors (path, error) VALUES (?, ?)",
            self.errors_batch,
        )
        self.errors_batch = []

    def _flush_batches(self) -> None:
        self._flush_files()
        self._flush_dirs()
        self._flush_errors()
        self.db.conn.commit()


class Planner:
    def __init__(self, db: Database):
        self.db = db
        self.root = db.root_path()

    def candidates(
        self,
        tier: str = "all",
        rule_name: Optional[str] = None,
        min_size: int = 0,
        include_nested: bool = False,
    ) -> List[Candidate]:
        rules = self._select_rules(tier, rule_name)
        by_key: Dict[Tuple[str, str], Candidate] = {}

        for rule in rules:
            for row in self.db.conn.execute(rule.sql):
                cand = Candidate(
                    path=absolute(row[0]),
                    size=int(row[1] or 0),
                    mtime=int(row[2] or 0),
                    kind=rule.kind,
                    rule=rule.name,
                    category=rule.category,
                    tier=rule.tier,
                    description=rule.description,
                )
                if cand.size < min_size:
                    continue
                if not self._candidate_allowed(cand):
                    continue
                key = (cand.kind, cand.path)
                existing = by_key.get(key)
                if existing is None or self._tier_rank(cand.tier) > self._tier_rank(existing.tier):
                    by_key[key] = cand

        candidates = list(by_key.values())

        if not include_nested:
            candidates = self._collapse_nested(candidates)

        candidates.sort(key=lambda item: (-item.size, item.tier, item.category, item.path))
        return candidates

    def stats(self, candidates: Sequence[Candidate]) -> Dict[Tuple[str, str], Tuple[int, int]]:
        totals: Dict[Tuple[str, str], Tuple[int, int]] = {}
        for cand in candidates:
            key = (cand.tier, cand.category)
            count, size = totals.get(key, (0, 0))
            totals[key] = (count + 1, size + cand.size)
        return totals

    def print_analysis(self, tier: str = "all", min_size: int = 0) -> None:
        candidates = self.candidates(tier=tier, min_size=min_size)
        if not candidates:
            print("No cleanup candidates found.")
            return

        print(f"\nCleanup analysis for: {self.root}")
        print("=" * 88)
        print(f"{'Tier':8s} {'Category':15s} {'Items':>8s} {'Size':>12s}")
        print("-" * 88)
        grand_count = 0
        grand_size = 0
        for (tier_name, category), (count, size) in sorted(self.stats(candidates).items()):
            print(f"{tier_name:8s} {category:15s} {count:8,} {format_size(size):>12s}")
            grand_count += count
            grand_size += size
        print("-" * 88)
        print(f"{'total':8s} {'':15s} {grand_count:8,} {format_size(grand_size):>12s}")
        print("\nUse 'ba review --tier safe' or 'ba plan --format csv --output plan.csv' before cleaning.")

    def print_review(
        self,
        tier: str = "all",
        rule_name: Optional[str] = None,
        min_size: int = 0,
        limit: int = 50,
    ) -> None:
        candidates = self.candidates(tier=tier, rule_name=rule_name, min_size=min_size)
        if not candidates:
            print("No cleanup candidates found.")
            return

        total_size = sum(c.size for c in candidates)
        print(f"\nCandidates: {len(candidates):,} ({format_size(total_size)})")
        print(f"Root: {self.root}")
        print("-" * 88)
        for cand in candidates[:limit]:
            rel = os.path.relpath(cand.path, self.root)
            print(
                f"{cand.tier:6s} {cand.kind:4s} {format_size(cand.size):>10s} "
                f"{cand.rule:24s} {rel}"
            )
        if len(candidates) > limit:
            print(f"\n... and {len(candidates) - limit:,} more")

    def write_plan(
        self,
        output: Optional[str],
        fmt: str,
        tier: str = "all",
        rule_name: Optional[str] = None,
        min_size: int = 0,
    ) -> None:
        candidates = self.candidates(tier=tier, rule_name=rule_name, min_size=min_size)
        rows = [cand.as_dict(self.root) for cand in candidates]

        if fmt == "json":
            data = {
                "generated_at": now_iso(),
                "root": self.root,
                "count": len(rows),
                "total_size": sum(c["size"] for c in rows),
                "candidates": rows,
            }
            text = json.dumps(data, indent=2)
            if output:
                Path(output).write_text(text + "\n", encoding="utf-8")
            else:
                print(text)
        else:
            fieldnames = [
                "tier",
                "category",
                "rule",
                "kind",
                "size",
                "size_human",
                "modified",
                "relative_path",
                "path",
                "description",
            ]
            if output:
                handle = open(output, "w", newline="", encoding="utf-8")
                close = True
            else:
                handle = sys.stdout
                close = False
            try:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: row[key] for key in fieldnames})
            finally:
                if close:
                    handle.close()

        if output:
            print(f"Wrote {len(rows):,} candidates to {output}")

    def _select_rules(self, tier: str, rule_name: Optional[str]) -> List[Rule]:
        if rule_name:
            rule = get_rule(rule_name)
            if not rule:
                raise RuntimeError(f"Unknown rule: {rule_name}")
            rules = [rule]
        else:
            rules = list(RULES)

        if tier != "all":
            rules = [rule for rule in rules if rule.tier == tier]
        return rules

    def _candidate_allowed(self, cand: Candidate) -> bool:
        if not is_within(cand.path, self.root):
            return False
        if absolute(cand.path) == absolute(self.root):
            return False
        parts = set(Path(cand.path).parts)
        if parts.intersection(PROTECTED_NAMES):
            return False
        if os.path.basename(cand.path) == QUARANTINE_DIR_NAME:
            return False
        return True

    def _collapse_nested(self, candidates: Sequence[Candidate]) -> List[Candidate]:
        active_dirs: List[str] = []
        result: List[Candidate] = []

        def nested(path: str, parent: str) -> bool:
            return path == parent or path.startswith(parent + os.sep)

        entries = sorted(
            ((absolute(cand.path), cand) for cand in candidates),
            key=lambda item: (item[0], 0 if item[1].kind == KIND_DIR else 1),
        )

        for path, cand in entries:
            while active_dirs and not nested(path, active_dirs[-1]):
                active_dirs.pop()
            if active_dirs and path != active_dirs[-1]:
                continue
            result.append(cand)
            if cand.kind == KIND_DIR:
                active_dirs.append(path)
        return result

    def _tier_rank(self, tier: str) -> int:
        return {SAFE: 1, REVIEW: 2}.get(tier, 0)


class InventoryValidator:
    def __init__(self, db: Database):
        self.db = db
        self.planner = Planner(db)
        self.root = self.planner.root

    def validate(
        self,
        tier: str = "all",
        rule_name: Optional[str] = None,
        min_size: int = 0,
        prune_stale: bool = False,
        limit: int = 20,
    ) -> None:
        if not os.path.isdir(self.root):
            raise RuntimeError(f"scan root is not currently available: {self.root}")

        candidates = self.planner.candidates(tier=tier, rule_name=rule_name, min_size=min_size)
        if not candidates:
            print("No cleanup candidates found.")
            return

        ok = 0
        failures: Dict[str, int] = {}
        examples: List[Tuple[Candidate, str]] = []
        stale_paths: List[str] = []

        for cand in candidates:
            try:
                validate_candidate_state(cand, self.root)
                ok += 1
            except RuntimeError as exc:
                reason = str(exc)
                failures[reason] = failures.get(reason, 0) + 1
                if len(examples) < limit:
                    examples.append((cand, reason))
                if reason in STALE_REASONS:
                    stale_paths.append(cand.path)

        print(f"\nValidation for: {self.root}")
        print(f"  Candidates checked: {len(candidates):,}")
        print(f"  Valid: {ok:,}")
        failed = len(candidates) - ok
        print(f"  Failed: {failed:,}")
        for reason, count in sorted(failures.items(), key=lambda item: (-item[1], item[0])):
            print(f"    {reason}: {count:,}")

        if examples:
            print("\nExamples")
            print("-" * 88)
            for cand, reason in examples:
                rel = os.path.relpath(cand.path, self.root)
                print(f"{reason:42s} {cand.kind:4s} {cand.rule:24s} {rel}")

        if prune_stale:
            Cleaner(self.db)._remove_from_inventory(stale_paths)
            print(f"\nPruned stale inventory rows: {len(stale_paths):,}")
        elif stale_paths:
            print("\nUse '--prune-stale' to remove missing/type-changed candidates from the inventory.")


class Cleaner:
    def __init__(self, db: Database):
        self.db = db
        self.planner = Planner(db)
        self.root = self.planner.root

    def clean(
        self,
        action: str,
        tier: str = SAFE,
        rule_name: Optional[str] = None,
        min_size: int = 0,
        yes: bool = False,
        quarantine: Optional[str] = None,
        manifest: Optional[str] = None,
    ) -> None:
        candidates = self.planner.candidates(tier=tier, rule_name=rule_name, min_size=min_size)
        if not candidates:
            print("No cleanup candidates found.")
            return

        total_size = sum(c.size for c in candidates)
        print(f"{action.upper()} plan for: {self.root}")
        print(f"  Candidates: {len(candidates):,}")
        print(f"  Size: {format_size(total_size)}")
        print(f"  Tier: {tier}")
        if rule_name:
            print(f"  Rule: {rule_name}")

        if action == "dry-run":
            print("\nDry run only. Use '--quarantine <dir>' or '--delete --yes' to make changes.")
            return

        if action == "delete" and tier != SAFE:
            raise RuntimeError("Permanent deletion is only allowed for --tier safe. Export/review other tiers first.")

        quarantine_root = canonical(quarantine) if quarantine else None
        if quarantine_root:
            self._validate_quarantine_root(quarantine_root, candidates)

        if not yes:
            word = "DELETE" if action == "delete" else "QUARANTINE"
            confirm = input(f"\nType '{word}' to confirm: ")
            if confirm != word:
                print("Cancelled.")
                return

        manifest_path = manifest or self._default_manifest_path(action)
        rows = self._apply(candidates, action, quarantine_root, manifest_path)
        deleted_paths = [row["path"] for row in rows if row["status"] in ("deleted", "quarantined")]
        self._remove_from_inventory(deleted_paths)

        success = sum(1 for row in rows if row["status"] in ("deleted", "quarantined"))
        failed = len(rows) - success
        print(f"\nFinished: {success:,} changed, {failed:,} failed/skipped")
        print(f"Manifest: {manifest_path}")
        if quarantine_root:
            print(f"Quarantine: {quarantine_root}")

    def _apply(
        self,
        candidates: Sequence[Candidate],
        action: str,
        quarantine_root: Optional[str],
        manifest_path: str,
    ) -> List[Dict[str, object]]:
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        if quarantine_root:
            os.makedirs(quarantine_root, exist_ok=True)

        rows: List[Dict[str, object]] = []
        for cand in candidates:
            row = cand.as_dict(self.root)
            row.update({"action": action, "status": "pending", "error": "", "destination": ""})
            try:
                self._validate_candidate(cand)
                if action == "delete":
                    self._delete_path(cand)
                    row["status"] = "deleted"
                elif action == "quarantine":
                    destination = self._quarantine_path(cand, quarantine_root)
                    row["destination"] = destination
                    row["status"] = "quarantined"
                else:
                    row["status"] = "skipped"
                    row["error"] = f"unknown action: {action}"
            except Exception as exc:
                row["status"] = "failed"
                row["error"] = str(exc)
            rows.append(row)

        fieldnames = [
            "action",
            "status",
            "tier",
            "category",
            "rule",
            "kind",
            "size",
            "size_human",
            "modified",
            "relative_path",
            "path",
            "destination",
            "description",
            "error",
        ]
        with open(manifest_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: row.get(key, "") for key in fieldnames})
        return rows

    def _validate_candidate(self, cand: Candidate) -> None:
        validate_candidate_state(cand, self.root)

    def _delete_path(self, cand: Candidate) -> None:
        if cand.kind == KIND_DIR:
            shutil.rmtree(cand.path)
        else:
            os.remove(cand.path)

    def _quarantine_path(self, cand: Candidate, quarantine_root: Optional[str]) -> str:
        if not quarantine_root:
            raise RuntimeError("quarantine action requires a quarantine directory")

        rel = os.path.relpath(cand.path, self.root)
        destination = canonical(os.path.join(quarantine_root, rel))
        if not is_within(destination, quarantine_root):
            raise RuntimeError("invalid quarantine destination")
        destination = self._unique_destination(destination)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.move(cand.path, destination)
        return destination

    def _unique_destination(self, destination: str) -> str:
        if not os.path.lexists(destination):
            return destination
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        base = destination
        idx = 1
        while True:
            candidate = f"{base}.{stamp}.{idx}"
            if not os.path.lexists(candidate):
                return candidate
            idx += 1

    def _validate_quarantine_root(self, quarantine_root: str, candidates: Sequence[Candidate]) -> None:
        if not is_within(quarantine_root, self.root):
            print("Note: quarantine is outside the scanned root.")
        for cand in candidates:
            if is_within(quarantine_root, cand.path):
                raise RuntimeError("quarantine directory cannot be inside a cleanup candidate")

    def _default_manifest_path(self, action: str) -> str:
        cache_dir = os.path.dirname(self.db.db_path)
        filename = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{action}-manifest.csv"
        return os.path.join(cache_dir, filename)

    def _remove_from_inventory(self, paths: Sequence[str]) -> None:
        if not paths:
            return
        cursor = self.db.conn.cursor()
        for path in paths:
            real = absolute(path)
            cursor.execute("DELETE FROM files WHERE path = ?", (real,))
            cursor.execute("DELETE FROM directories WHERE path = ?", (real,))
            cursor.execute("DELETE FROM files WHERE path LIKE ?", (real + os.sep + "%",))
            cursor.execute("DELETE FROM directories WHERE path LIKE ?", (real + os.sep + "%",))
        self.db.conn.commit()


def list_rules() -> None:
    print("\nCleanup rules")
    print("=" * 88)
    print(f"{'Rule':26s} {'Tier':8s} {'Kind':4s} {'Category':14s} Description")
    print("-" * 88)
    for rule in RULES:
        print(f"{rule.name:26s} {rule.tier:8s} {rule.kind:4s} {rule.category:14s} {rule.description}")


def show_stats(db: Database) -> None:
    root = db.metadata("root_path") or "Unknown"
    scan_date = db.metadata("scan_date") or "Unknown"
    file_count = db.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    dir_count = db.conn.execute("SELECT COUNT(*) FROM directories").fetchone()[0]
    error_count = db.conn.execute("SELECT COUNT(*) FROM scan_errors").fetchone()[0]
    total_size = db.conn.execute("SELECT COALESCE(SUM(size), 0) FROM files").fetchone()[0]

    print("\nInventory statistics")
    print("=" * 70)
    print(f"Database: {db.db_path}")
    print(f"Root: {root}")
    print(f"Scan date: {scan_date}")
    print(f"Files: {file_count:,}")
    print(f"Directories: {dir_count:,}")
    print(f"Scan errors: {error_count:,}")
    print(f"Total file size: {format_size(total_size)}")

    rows = db.conn.execute(
        """
        SELECT extension, COUNT(*) AS count, SUM(size) AS size
        FROM files
        WHERE extension IS NOT NULL
        GROUP BY extension
        ORDER BY size DESC
        LIMIT 10
        """
    ).fetchall()
    if rows:
        print("\nTop extensions by size")
        for row in rows:
            print(f"  .{row['extension']:<18s} {row['count']:8,} files {format_size(row['size']):>12s}")


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", help="Database path (default: ~/.cache/backup-archeology/inventory.db)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Backup Archeology - clean known junk from backup trees safely",
        epilog="Start with: ba scan /path/to/backups && ba analyze",
    )
    add_common_options(parser)
    parser.add_argument("--version", action="version", version=f"backup-archeology {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a backup root and build an inventory")
    scan.add_argument("path")
    scan.add_argument("--no-progress", action="store_true", help="Disable progress output")

    analyze = sub.add_parser("analyze", help="Summarize cleanup candidates")
    analyze.add_argument("--tier", choices=("all", SAFE, REVIEW), default="all")
    analyze.add_argument("--min-size", type=parse_size, default=0)

    review = sub.add_parser("review", help="Review candidate paths")
    review.add_argument("rule", nargs="?")
    review.add_argument("--tier", choices=("all", SAFE, REVIEW), default="all")
    review.add_argument("--limit", type=int, default=50)
    review.add_argument("--min-size", type=parse_size, default=0)

    validate = sub.add_parser("validate", help="Validate cleanup candidates against the current filesystem")
    validate.add_argument("rule", nargs="?")
    validate.add_argument("--tier", choices=("all", SAFE, REVIEW), default="all")
    validate.add_argument("--limit", type=int, default=20, help="Maximum failed examples to print")
    validate.add_argument("--min-size", type=parse_size, default=0)
    validate.add_argument(
        "--prune-stale",
        action="store_true",
        help="Remove missing/type-changed candidate rows from the inventory",
    )

    plan = sub.add_parser("plan", help="Export cleanup candidates as CSV or JSON")
    plan.add_argument("rule", nargs="?")
    plan.add_argument("--tier", choices=("all", SAFE, REVIEW), default="all")
    plan.add_argument("--format", choices=("csv", "json"), default="csv")
    plan.add_argument("--output")
    plan.add_argument("--min-size", type=parse_size, default=0)

    clean = sub.add_parser("clean", help="Dry-run, quarantine, or delete cleanup candidates")
    clean.add_argument("rule", nargs="?")
    clean.add_argument("--tier", choices=(SAFE, REVIEW), default=SAFE)
    clean.add_argument("--min-size", type=parse_size, default=0)
    clean.add_argument("--quarantine", help="Move candidates to this directory instead of deleting")
    clean.add_argument("--delete", action="store_true", help="Permanently delete safe candidates")
    clean.add_argument("--yes", action="store_true", help="Skip interactive confirmation")
    clean.add_argument("--manifest", help="CSV manifest path")

    delete = sub.add_parser("delete", help="Backward-compatible alias for 'clean --delete'")
    delete.add_argument("rule", nargs="?")
    delete.add_argument("--tier", choices=(SAFE, REVIEW), default=SAFE)
    delete.add_argument("--min-size", type=parse_size, default=0)
    delete.add_argument("--no-dry-run", action="store_true", help="Actually delete; otherwise dry-run")
    delete.add_argument("--yes", action="store_true")
    delete.add_argument("--manifest")

    sub.add_parser("stats", help="Show inventory statistics")
    sub.add_parser("list-rules", help="List cleanup rules")
    sub.add_parser("list-patterns", help="Alias for list-rules")
    sub.add_parser("logo", help="Print the ASCII logo")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "logo":
        print(LOGO)
        print(TAGLINE)
        return 0

    if args.command in ("list-rules", "list-patterns"):
        list_rules()
        return 0

    db = Database(args.db)
    try:
        if args.command == "scan":
            Scanner(db).scan(args.path, progress=not args.no_progress)
        elif args.command == "analyze":
            Planner(db).print_analysis(tier=args.tier, min_size=args.min_size)
        elif args.command == "review":
            Planner(db).print_review(
                tier=args.tier,
                rule_name=args.rule,
                min_size=args.min_size,
                limit=args.limit,
            )
        elif args.command == "validate":
            InventoryValidator(db).validate(
                tier=args.tier,
                rule_name=args.rule,
                min_size=args.min_size,
                prune_stale=args.prune_stale,
                limit=args.limit,
            )
        elif args.command == "plan":
            Planner(db).write_plan(
                output=args.output,
                fmt=args.format,
                tier=args.tier,
                rule_name=args.rule,
                min_size=args.min_size,
            )
        elif args.command == "clean":
            if args.delete and args.quarantine:
                raise RuntimeError("choose either --delete or --quarantine, not both")
            action = "dry-run"
            quarantine = None
            if args.delete:
                action = "delete"
            elif args.quarantine:
                action = "quarantine"
                quarantine = args.quarantine
            Cleaner(db).clean(
                action=action,
                tier=args.tier,
                rule_name=args.rule,
                min_size=args.min_size,
                yes=args.yes,
                quarantine=quarantine,
                manifest=args.manifest,
            )
        elif args.command == "delete":
            action = "delete" if args.no_dry_run else "dry-run"
            Cleaner(db).clean(
                action=action,
                tier=args.tier,
                rule_name=args.rule,
                min_size=args.min_size,
                yes=args.yes,
                quarantine=None,
                manifest=args.manifest,
            )
        elif args.command == "stats":
            show_stats(db)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
