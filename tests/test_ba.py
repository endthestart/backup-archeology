import csv
import os
import tempfile
import unittest
from pathlib import Path

import ba


def touch(path: Path, content: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class BackupArcheologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "backup"
        self.root.mkdir()
        self.db_path = self.root / "inventory.db"
        self.db = ba.Database(str(self.db_path))

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def scan(self) -> None:
        ba.Scanner(self.db).scan(str(self.root), progress=False)

    def test_scan_excludes_own_database_files(self) -> None:
        touch(self.root / "project" / "node_modules" / "pkg" / "index.js")

        self.scan()

        rows = self.db.conn.execute(
            "SELECT path FROM files WHERE name LIKE 'inventory.db%'"
        ).fetchall()
        self.assertEqual([], rows)

    def test_safe_and_review_candidates_are_separated(self) -> None:
        touch(self.root / "project" / "package.json", "{}")
        touch(self.root / "project" / "node_modules" / "pkg" / "index.js")
        touch(self.root / "project" / "debug.log")

        self.scan()
        planner = ba.Planner(self.db)

        safe_rules = {candidate.rule for candidate in planner.candidates(tier=ba.SAFE)}
        review_rules = {candidate.rule for candidate in planner.candidates(tier=ba.REVIEW)}

        self.assertIn("node_modules", safe_rules)
        self.assertIn("log_files", review_rules)
        self.assertNotIn("log_files", safe_rules)

    def test_nested_candidates_are_collapsed(self) -> None:
        touch(self.root / "project" / "node_modules" / "pkg" / "__pycache__" / "x.pyc")

        self.scan()
        candidates = ba.Planner(self.db).candidates(tier=ba.SAFE)
        paths = {Path(candidate.path).name for candidate in candidates}

        self.assertIn("node_modules", paths)
        self.assertNotIn("__pycache__", paths)
        self.assertFalse(any(candidate.path.endswith("x.pyc") for candidate in candidates))

    def test_empty_directory_review_rule_does_not_mask_safe_children(self) -> None:
        touch(self.root / "project" / "node_modules" / "pkg" / "empty.js", "")

        self.scan()
        candidates = ba.Planner(self.db).candidates(tier="all")
        rules = {candidate.rule for candidate in candidates}

        self.assertIn("node_modules", rules)

    def test_quarantine_moves_candidates_and_writes_manifest(self) -> None:
        target = self.root / "project" / "node_modules" / "pkg" / "index.js"
        touch(target)
        self.scan()

        quarantine = Path(self.tmp.name) / "quarantine"
        manifest = Path(self.tmp.name) / "manifest.csv"

        ba.Cleaner(self.db).clean(
            action="quarantine",
            tier=ba.SAFE,
            rule_name="node_modules",
            yes=True,
            quarantine=str(quarantine),
            manifest=str(manifest),
        )

        self.assertFalse((self.root / "project" / "node_modules").exists())
        self.assertTrue((quarantine / "project" / "node_modules" / "pkg" / "index.js").exists())
        with manifest.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual("quarantined", rows[0]["status"])

    def test_delete_multiple_directories_updates_inventory(self) -> None:
        touch(self.root / "a" / "__pycache__" / "a.pyc")
        touch(self.root / "b" / "__pycache__" / "b.pyc")
        self.scan()

        manifest = Path(self.tmp.name) / "delete.csv"
        ba.Cleaner(self.db).clean(
            action="delete",
            tier=ba.SAFE,
            rule_name="python_caches",
            yes=True,
            manifest=str(manifest),
        )

        self.assertFalse((self.root / "a" / "__pycache__").exists())
        self.assertFalse((self.root / "b" / "__pycache__").exists())
        rows = self.db.conn.execute(
            "SELECT path FROM directories WHERE name = '__pycache__'"
        ).fetchall()
        self.assertEqual([], rows)

    def test_review_tier_cannot_be_permanently_deleted(self) -> None:
        touch(self.root / "debug.log")
        self.scan()

        with self.assertRaises(RuntimeError):
            ba.Cleaner(self.db).clean(
                action="delete",
                tier=ba.REVIEW,
                rule_name="log_files",
                yes=True,
                manifest=str(Path(self.tmp.name) / "delete.csv"),
            )

    def test_validate_prune_stale_removes_missing_candidate_from_inventory(self) -> None:
        target = self.root / "project" / "__pycache__" / "module.pyc"
        touch(target)
        self.scan()
        target.unlink()

        ba.InventoryValidator(self.db).validate(
            tier=ba.SAFE,
            rule_name="python_bytecode",
            prune_stale=True,
            limit=0,
        )

        rows = self.db.conn.execute("SELECT path FROM files WHERE name = 'module.pyc'").fetchall()
        self.assertEqual([], rows)

    def test_kopia_exclude_rules_cover_cross_platform_junk(self) -> None:
        safe_paths = [
            self.root / "$RECYCLE.BIN" / "item",
            self.root / "pagefile.sys",
            self.root / ".Trash-1000" / "file",
            self.root / ".DS_Store",
            self.root / "project" / ".ipynb_checkpoints" / "notebook-checkpoint.ipynb",
            self.root / "project" / "build" / "artifact.o",
            self.root / "media" / "Transcode" / "chunk",
            self.root / "game" / "ShaderCache" / "shader",
            self.root / "profile" / "Library" / "Caches" / "blob",
            self.root / "project" / ".idea" / "workspace.xml",
        ]
        review_paths = [
            self.root / "Recovery" / "WindowsRE" / "winre.wim",
            self.root / "PoolPart.123456" / "pooled-file",
            self.root / "Kopia Repository" / "index",
            self.root / ".ollama" / "models" / "blobs" / "sha256-model",
            self.root / "vm" / "disk.vmdk",
            self.root / "project" / ".idea" / "shelf" / "patch.patch",
        ]
        for path in safe_paths + review_paths:
            touch(path)

        self.scan()
        planner = ba.Planner(self.db)
        safe_rules = {candidate.rule for candidate in planner.candidates(tier=ba.SAFE)}
        review_rules = {candidate.rule for candidate in planner.candidates(tier=ba.REVIEW)}

        self.assertIn("os_trash_and_metadata_dirs", safe_rules)
        self.assertIn("windows_runtime_files", safe_rules)
        self.assertIn("os_metadata_files", safe_rules)
        self.assertIn("python_caches", safe_rules)
        self.assertIn("ignored_build_dirs", safe_rules)
        self.assertIn("media_transcode_caches", safe_rules)
        self.assertIn("gaming_shader_caches", safe_rules)
        self.assertIn("generic_cache_dirs", safe_rules)
        self.assertIn("jetbrains_workspace_state", safe_rules)

        self.assertIn("windows_recovery_dirs", review_rules)
        self.assertIn("nas_poolpart_dirs", review_rules)
        self.assertIn("backup_repositories", review_rules)
        self.assertIn("ollama_models", review_rules)
        self.assertIn("vm_disk_images", review_rules)
        self.assertIn("jetbrains_shelf", review_rules)


if __name__ == "__main__":
    unittest.main()
