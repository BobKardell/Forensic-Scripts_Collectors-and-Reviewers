import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .config import CASES_DIR, SETTINGS_PATH
from .models import CaseInfo

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(text: str) -> str:
    invalid = '<>:"/\\|?*'
    result = "".join("_" if char in invalid else char for char in text)
    return result.strip().strip(".") or "Untitled_Case"


def load_settings() -> dict:
    defaults = {
        "case_directory": str(CASES_DIR),
        "examiner": "",
        "organization": "",
        "recent_cases": [],
    }
    if SETTINGS_PATH.exists():
        try:
            loaded = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                defaults.update(loaded)
        except Exception:
            pass
    return defaults


def save_settings(settings: dict) -> None:
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def initialize_database(case: CaseInfo) -> None:
    with sqlite3.connect(case.database) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS case_info (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL,
                case_number TEXT,
                examiner TEXT,
                organization TEXT,
                description TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                schema_version INTEGER NOT NULL DEFAULT 8
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_number TEXT,
                name TEXT NOT NULL,
                evidence_type TEXT,
                source TEXT,
                custodian TEXT,
                description TEXT,
                acquired_utc TEXT,
                added_utc TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active'
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                report_type TEXT,
                file_path TEXT,
                created_utc TEXT NOT NULL,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'General',
                object_type TEXT NOT NULL DEFAULT 'General',
                object_id TEXT,
                evidence_id INTEGER,
                reference TEXT,
                notes TEXT,
                examiner TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bookmarks_category ON bookmarks(category);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_evidence ON bookmarks(evidence_id);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_created ON bookmarks(created_utc);

            CREATE TABLE IF NOT EXISTS plugin_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id TEXT NOT NULL,
                plugin_name TEXT NOT NULL,
                executable_path TEXT,
                process_id INTEGER,
                started_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_utc TEXT NOT NULL,
                examiner TEXT,
                action TEXT NOT NULL,
                object_type TEXT,
                object_id TEXT,
                details TEXT
            );


            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                transfer_utc TEXT NOT NULL,
                released_by TEXT,
                released_organization TEXT,
                received_by TEXT,
                received_organization TEXT,
                purpose TEXT,
                method TEXT,
                location TEXT,
                condition TEXT,
                comments TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS registry_definitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                artifact_name TEXT NOT NULL,
                hive TEXT NOT NULL,
                key_path TEXT NOT NULL,
                value_name TEXT,
                data_type TEXT,
                description TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                recursive INTEGER NOT NULL DEFAULT 0,
                display_order INTEGER NOT NULL DEFAULT 0,
                version TEXT NOT NULL DEFAULT '1.0',
                modified_utc TEXT NOT NULL,
                UNIQUE(artifact_name, hive, key_path, value_name)
            );
            CREATE INDEX IF NOT EXISTS idx_coc_evidence ON chain_of_custody(evidence_id);
            CREATE INDEX IF NOT EXISTS idx_registry_definitions_enabled ON registry_definitions(enabled, display_order);

            CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(event_utc);
            CREATE INDEX IF NOT EXISTS idx_evidence_number ON evidence(evidence_number);
            """
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO case_info
            (id, name, case_number, examiner, organization, description,
             created_utc, modified_utc, schema_version)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, 8)
            """,
            (
                case.name,
                case.number,
                case.examiner,
                case.organization,
                case.description,
                case.created_utc,
                utc_now(),
            ),
        )
        connection.execute(
            """
            INSERT INTO audit_log
            (event_utc, examiner, action, object_type, object_id, details)
            VALUES (?, ?, 'CASE_CREATED', 'case', '1', ?)
            """,
            (utc_now(), case.examiner, f"Created case {case.name}"),
        )



def ensure_v4_schema(database: Path) -> None:
    """Repair and upgrade both current and older case databases.

    Version 6 upgrades evidence persistence and plugin context while preserving older cases. Older case databases could
    therefore be missing tables used by the Dashboard, causing the page to
    fail while the rest of the shell appeared. This routine is intentionally
    idempotent and creates every core table before applying column upgrades.
    """
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS case_info (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL,
                case_number TEXT,
                examiner TEXT,
                organization TEXT,
                description TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                schema_version INTEGER NOT NULL DEFAULT 8
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_number TEXT,
                name TEXT NOT NULL,
                evidence_type TEXT,
                source TEXT,
                custodian TEXT,
                description TEXT,
                acquired_utc TEXT,
                added_utc TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active'
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                report_type TEXT,
                file_path TEXT,
                created_utc TEXT NOT NULL,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'General',
                object_type TEXT NOT NULL DEFAULT 'General',
                object_id TEXT,
                evidence_id INTEGER,
                reference TEXT,
                notes TEXT,
                examiner TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bookmarks_category ON bookmarks(category);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_evidence ON bookmarks(evidence_id);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_created ON bookmarks(created_utc);

            CREATE TABLE IF NOT EXISTS plugin_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id TEXT NOT NULL,
                plugin_name TEXT NOT NULL,
                executable_path TEXT,
                process_id INTEGER,
                started_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_utc TEXT NOT NULL,
                examiner TEXT,
                action TEXT NOT NULL,
                object_type TEXT,
                object_id TEXT,
                details TEXT
            );

        
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                transfer_utc TEXT NOT NULL,
                released_by TEXT,
                released_organization TEXT,
                received_by TEXT,
                received_organization TEXT,
                purpose TEXT,
                method TEXT,
                location TEXT,
                condition TEXT,
                comments TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS registry_definitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                artifact_name TEXT NOT NULL,
                hive TEXT NOT NULL,
                key_path TEXT NOT NULL,
                value_name TEXT,
                data_type TEXT,
                description TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                recursive INTEGER NOT NULL DEFAULT 0,
                display_order INTEGER NOT NULL DEFAULT 0,
                version TEXT NOT NULL DEFAULT '1.0',
                modified_utc TEXT NOT NULL,
                UNIQUE(artifact_name, hive, key_path, value_name)
            );
            CREATE INDEX IF NOT EXISTS idx_coc_evidence ON chain_of_custody(evidence_id);
            CREATE INDEX IF NOT EXISTS idx_registry_definitions_enabled ON registry_definitions(enabled, display_order);

            """
        )

        existing = {row[1] for row in connection.execute("PRAGMA table_info(evidence)")}
        additions = {
            "evidence_number": "TEXT",
            "evidence_type": "TEXT",
            "source": "TEXT",
            "custodian": "TEXT",
            "description": "TEXT",
            "acquired_utc": "TEXT",
            "status": "TEXT NOT NULL DEFAULT 'Active'",
            "root_path": "TEXT",
            "package_path": "TEXT",
            "package_sha256": "TEXT",
            "file_count": "INTEGER NOT NULL DEFAULT 0",
            "size_bytes": "INTEGER NOT NULL DEFAULT 0",
            "import_status": "TEXT NOT NULL DEFAULT 'Ready'",
            "collector_manifest": "TEXT",
            "mounted_volume": "TEXT",
            "evidence_root": "TEXT",
            "source_image": "TEXT",
            "md5": "TEXT",
            "sha1": "TEXT",
            "sha256": "TEXT",
            "notes": "TEXT",
            "modified_utc": "TEXT",
            "mounted_volume_verified": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, declaration in additions.items():
            if name not in existing:
                connection.execute(f"ALTER TABLE evidence ADD COLUMN {name} {declaration}")


        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS hive_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                hive_type TEXT NOT NULL,
                profile_name TEXT,
                file_path TEXT NOT NULL,
                discovered_utc TEXT NOT NULL,
                UNIQUE(evidence_id, hive_type, file_path),
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS registry_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                category TEXT NOT NULL DEFAULT '',
                hive_name TEXT NOT NULL DEFAULT '',
                hive_path TEXT NOT NULL DEFAULT '',
                registry_key TEXT NOT NULL DEFAULT '',
                value_name TEXT,
                value_type TEXT,
                value_data TEXT,
                decoded_data TEXT,
                key_timestamp TEXT,
                user_context TEXT,
                collection_error TEXT,
                collected_at TEXT NOT NULL DEFAULT '',
                source_tool TEXT NOT NULL DEFAULT 'Registry Artifacts Explorer',
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_hive_evidence ON hive_locations(evidence_id);
            CREATE INDEX IF NOT EXISTS idx_registry_evidence ON registry_artifacts(evidence_id);
            """
        )
        connection.execute(
            """UPDATE evidence
               SET mounted_volume=COALESCE(NULLIF(mounted_volume,''), root_path),
                   evidence_root=COALESCE(NULLIF(evidence_root,''), root_path),
                   modified_utc=COALESCE(modified_utc, added_utc)
            """
        )

        registry_existing = {row[1] for row in connection.execute("PRAGMA table_info(registry_artifacts)")}
        registry_additions = {
            "evidence_id": "INTEGER", "category": "TEXT", "hive_name": "TEXT",
            "hive_path": "TEXT", "registry_key": "TEXT", "value_name": "TEXT",
            "value_type": "TEXT", "value_data": "TEXT", "decoded_data": "TEXT",
            "key_timestamp": "TEXT", "user_context": "TEXT", "collection_error": "TEXT",
            "collected_at": "TEXT", "source_tool": "TEXT"
        }
        for name, declaration in registry_additions.items():
            if name not in registry_existing:
                connection.execute(f"ALTER TABLE registry_artifacts ADD COLUMN {name} {declaration}")

        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(event_utc)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_number ON evidence(evidence_number)")
        connection.execute(
            "UPDATE case_info SET schema_version = 8, modified_utc = ? WHERE id = 1",
            (utc_now(),),
        )

def human_size(value: int) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size):,} B" if unit == "B" else f"{size:,.2f} {unit}"
        size /= 1024
    return f"{value:,} B"

def read_case(database: Path) -> CaseInfo:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT name, case_number, examiner, organization, description, created_utc
            FROM case_info WHERE id = 1
            """
        ).fetchone()
    if not row:
        raise ValueError("This is not a valid Fraud Fighter Toolbox case database.")
    return CaseInfo(
        name=row[0],
        number=row[1] or "",
        examiner=row[2] or "",
        organization=row[3] or "",
        description=row[4] or "",
        folder=database.parent,
        database=database,
        created_utc=row[5],
    )


