#!/usr/bin/env python3
"""
Fraud Fighter Toolbox Suite v3.0

A case-management launcher for independent forensic plugins.

Architecture
------------
The main window contains only the case-management pages:
    Dashboard | Evidence | Notes | Reports | Audit Log

The left plugin rail launches each installed forensic tool in its own
independent process and window. The active case context is supplied through
environment variables:

    FFT_CASE_DB
    FFT_CASE_FOLDER
    FFT_CASE_NAME
    FFT_CASE_NUMBER
    FFT_EXAMINER

Plugins may optionally request command-line case arguments in plugin.json.

This launcher uses only Python's standard library.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
import tkinter as tk
import threading
import zipfile
import hashlib
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

APP_NAME = "Fraud Fighter Toolbox"
APP_VERSION = "4.3"

APP_DIR = Path(__file__).resolve().parent
ASSETS_DIR = APP_DIR / "assets"
PLUGINS_DIR = APP_DIR / "plugins"
SCRIPTS_DIR = APP_DIR / "Scripts"
CASES_DIR = APP_DIR / "cases"
SETTINGS_PATH = APP_DIR / "settings.json"
LOGO_PATH = ASSETS_DIR / "fraud_fighter_toolbox.png"

COLORS = {
    "navy": "#061522",
    "navy2": "#0c2235",
    "slate": "#587795",
    "slate_dark": "#3e5c78",
    "slate_light": "#dce7f0",
    "blue": "#188bd0",
    "panel": "#f2f6f9",
    "white": "#ffffff",
    "text": "#172431",
    "muted": "#607180",
    "border": "#c8d5df",
    "green": "#367d4a",
    "amber": "#a96f17",
    "red": "#a33b3b",
}


@dataclass
class CaseInfo:
    name: str
    number: str
    examiner: str
    organization: str
    description: str
    folder: Path
    database: Path
    created_utc: str


@dataclass
class PluginInfo:
    plugin_id: str
    name: str
    category: str
    description: str
    icon: str
    executable: Path
    working_directory: Path
    pass_case_arguments: bool
    enabled: bool
    version: str


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
                schema_version INTEGER NOT NULL DEFAULT 3
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

            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT,
                object_type TEXT,
                object_id TEXT,
                evidence_id INTEGER,
                reference TEXT,
                notes TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                created_by TEXT
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                report_type TEXT,
                file_path TEXT,
                created_utc TEXT NOT NULL,
                description TEXT
            );

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

            CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(event_utc);
            CREATE INDEX IF NOT EXISTS idx_evidence_number ON evidence(evidence_number);
            """
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO case_info
            (id, name, case_number, examiner, organization, description,
             created_utc, modified_utc, schema_version)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, 3)
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

    Version 4.1 only altered the evidence table. Older case databases could
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
                schema_version INTEGER NOT NULL DEFAULT 4
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

            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT,
                object_type TEXT,
                object_id TEXT,
                evidence_id INTEGER,
                reference TEXT,
                notes TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT NOT NULL,
                created_by TEXT
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                report_type TEXT,
                file_path TEXT,
                created_utc TEXT NOT NULL,
                description TEXT
            );

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
        }
        for name, declaration in additions.items():
            if name not in existing:
                connection.execute(f"ALTER TABLE evidence ADD COLUMN {name} {declaration}")

        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(event_utc)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_number ON evidence(evidence_number)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_category ON bookmarks(category)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_object ON bookmarks(object_type, object_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_created ON bookmarks(created_utc)")
        connection.execute(
            "UPDATE case_info SET schema_version = 4, modified_utc = ? WHERE id = 1",
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


def _parse_script_metadata(script_path: Path) -> dict[str, str]:
    """Read FFT metadata without importing or executing the script."""
    metadata: dict[str, str] = {}
    try:
        header = script_path.read_text(encoding="utf-8-sig", errors="replace")[:16384]
    except Exception:
        return metadata

    aliases = {
        "TITLE": "name",
        "NAME": "name",
        "CATEGORY": "category",
        "VERSION": "version",
        "DESCRIPTION": "description",
        "ICON": "icon",
        "ID": "plugin_id",
        "PASS_CASE_ARGUMENTS": "pass_case_arguments",
    }
    for source_key, target_key in aliases.items():
        patterns = [
            rf"(?im)^\s*#?\s*{source_key}\s*:\s*([^\r\n]+)",
            rf"(?im)^\s*{source_key}\s*=\s*[\"']([^\"']+)[\"']",
        ]
        for pattern in patterns:
            match = re.search(pattern, header)
            if match:
                metadata.setdefault(target_key, match.group(1).strip())
                break
    return metadata


def discover_plugins() -> list[PluginInfo]:
    """Discover legacy manifest plugins and drop-in Python scripts."""
    discovered: list[PluginInfo] = []
    seen_paths: set[Path] = set()
    PLUGINS_DIR.mkdir(exist_ok=True)
    SCRIPTS_DIR.mkdir(exist_ok=True)

    # Legacy manifest plugins remain supported.
    for manifest_path in sorted(PLUGINS_DIR.glob("*/plugin.json")):
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            executable = (manifest_path.parent / data["executable"]).resolve()
            if not executable.exists():
                continue
            discovered.append(
                PluginInfo(
                    plugin_id=str(data.get("id") or manifest_path.parent.name),
                    name=str(data.get("name") or manifest_path.parent.name),
                    category=str(data.get("category") or "Plugins"),
                    description=str(data.get("description") or ""),
                    icon=str(data.get("icon") or "■"),
                    executable=executable,
                    working_directory=manifest_path.parent,
                    pass_case_arguments=bool(data.get("pass_case_arguments", False)),
                    enabled=bool(data.get("enabled", True)),
                    version=str(data.get("version") or ""),
                )
            )
            seen_paths.add(executable)
        except Exception:
            continue

    # Every Python file in Scripts becomes a launcher option.
    for script_path in sorted(SCRIPTS_DIR.glob("*.py"), key=lambda item: item.name.lower()):
        resolved = script_path.resolve()
        if resolved in seen_paths or script_path.name.startswith("_"):
            continue
        metadata = _parse_script_metadata(script_path)
        name = metadata.get("name") or script_path.stem.replace("_", " ")
        plugin_id = metadata.get("plugin_id") or re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
        category = metadata.get("category") or "Plugins"
        pass_args = metadata.get("pass_case_arguments", "false").lower() in ("1", "true", "yes")
        discovered.append(
            PluginInfo(
                plugin_id=plugin_id,
                name=name,
                category=category,
                description=metadata.get("description", ""),
                icon=metadata.get("icon", "◆"),
                executable=resolved,
                working_directory=SCRIPTS_DIR,
                pass_case_arguments=pass_args,
                enabled=True,
                version=metadata.get("version", ""),
            )
        )
        seen_paths.add(resolved)

    unique: dict[str, PluginInfo] = {}
    for plugin in discovered:
        if plugin.enabled:
            unique.setdefault(plugin.plugin_id, plugin)
    return sorted(unique.values(), key=lambda item: (item.category.lower(), item.name.lower()))


class CreateCaseDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, settings: dict):
        super().__init__(parent)
        self.title("Create New Case")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.result: Optional[dict] = None

        self.name = tk.StringVar()
        self.number = tk.StringVar()
        self.examiner = tk.StringVar(value=settings.get("examiner", ""))
        self.organization = tk.StringVar(value=settings.get("organization", ""))
        self.location = tk.StringVar(value=settings.get("case_directory", str(CASES_DIR)))

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Create New Case", style="DialogTitle.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 16)
        )

        fields = [
            ("Case name", self.name),
            ("Case number", self.number),
            ("Examiner", self.examiner),
            ("Organization", self.organization),
        ]
        for row, (label, variable) in enumerate(fields, 1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=5)
            ttk.Entry(frame, textvariable=variable, width=52).grid(
                row=row, column=1, columnspan=2, sticky="ew", padx=(12, 0), pady=5
            )

        ttk.Label(frame, text="Case storage").grid(row=5, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.location).grid(
            row=5, column=1, sticky="ew", padx=(12, 6), pady=5
        )
        ttk.Button(frame, text="Browse…", command=self.choose_location).grid(row=5, column=2)

        ttk.Label(frame, text="Description").grid(row=6, column=0, sticky="nw", pady=5)
        self.description = tk.Text(frame, width=52, height=6, wrap="word")
        self.description.grid(row=6, column=1, columnspan=2, sticky="ew", padx=(12, 0), pady=5)

        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=0, columnspan=3, sticky="e", pady=(18, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(
            buttons,
            text="Create Case",
            style="Primary.TButton",
            command=self.submit,
        ).pack(side="right", padx=(0, 8))

        frame.columnconfigure(1, weight=1)

    def choose_location(self) -> None:
        selected = filedialog.askdirectory(parent=self)
        if selected:
            self.location.set(selected)

    def submit(self) -> None:
        if not self.name.get().strip():
            messagebox.showwarning("Case Name", "Enter a case name.", parent=self)
            return
        location = Path(self.location.get().strip())
        try:
            location.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("Storage Error", str(exc), parent=self)
            return
        self.result = {
            "name": self.name.get().strip(),
            "number": self.number.get().strip(),
            "examiner": self.examiner.get().strip(),
            "organization": self.organization.get().strip(),
            "location": location,
            "description": self.description.get("1.0", "end").strip(),
        }
        self.destroy()


class TextEntryDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, title: str, fields: list[tuple[str, str]], multiline: str = ""):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.result: Optional[dict] = None
        self.variables: dict[str, tk.StringVar] = {}

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=title, style="DialogTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 14)
        )

        row = 1
        for key, label in fields:
            variable = tk.StringVar()
            self.variables[key] = variable
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=5)
            ttk.Entry(frame, textvariable=variable, width=52).grid(
                row=row, column=1, sticky="ew", padx=(12, 0), pady=5
            )
            row += 1

        self.body: Optional[tk.Text] = None
        if multiline:
            ttk.Label(frame, text=multiline).grid(row=row, column=0, sticky="nw", pady=5)
            self.body = tk.Text(frame, width=52, height=8, wrap="word")
            self.body.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=5)
            row += 1

        buttons = ttk.Frame(frame)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(15, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Save", style="Primary.TButton", command=self.submit).pack(
            side="right", padx=(0, 8)
        )
        frame.columnconfigure(1, weight=1)

    def submit(self) -> None:
        self.result = {key: value.get().strip() for key, value in self.variables.items()}
        if self.body is not None:
            self.result["body"] = self.body.get("1.0", "end").strip()
        self.destroy()


class SuiteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1480x900")
        self.minsize(1120, 720)
        self.configure(bg=COLORS["navy"])

        self.settings = load_settings()
        self.case: Optional[CaseInfo] = None
        self.plugins: list[PluginInfo] = []
        self.logo: Optional[tk.PhotoImage] = None
        self.content: Optional[ttk.Frame] = None
        self.navigation_buttons: dict[str, ttk.Button] = {}
        self.plugin_processes: dict[str, subprocess.Popen] = {}

        self.configure_styles()
        self.protocol("WM_DELETE_WINDOW", self.close_application)
        self.show_welcome()

    def configure_styles(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", font=("Segoe UI", 10))
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("White.TFrame", background=COLORS["white"])
        style.configure("Navy.TFrame", background=COLORS["navy"])
        style.configure("Rail.TFrame", background=COLORS["navy2"])

        style.configure("TLabel", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("White.TLabel", background=COLORS["white"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"])
        style.configure("WhiteMuted.TLabel", background=COLORS["white"], foreground=COLORS["muted"])
        style.configure(
            "Title.TLabel",
            background=COLORS["panel"],
            foreground=COLORS["navy"],
            font=("Segoe UI Semibold", 22),
        )
        style.configure(
            "DialogTitle.TLabel",
            font=("Segoe UI Semibold", 18),
        )
        style.configure(
            "RailTitle.TLabel",
            background=COLORS["navy2"],
            foreground=COLORS["white"],
            font=("Segoe UI Semibold", 13),
        )
        style.configure(
            "RailMeta.TLabel",
            background=COLORS["navy2"],
            foreground="#b9c9d8",
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardTitle.TLabel",
            background=COLORS["white"],
            foreground=COLORS["navy"],
            font=("Segoe UI Semibold", 13),
        )

        style.configure(
            "Primary.TButton",
            background=COLORS["blue"],
            foreground=COLORS["white"],
            padding=(16, 10),
            borderwidth=0,
            font=("Segoe UI Semibold", 10),
        )
        style.map("Primary.TButton", background=[("active", "#0e78b7")])

        style.configure(
            "Secondary.TButton",
            background=COLORS["slate"],
            foreground=COLORS["white"],
            padding=(14, 9),
            borderwidth=0,
        )
        style.map("Secondary.TButton", background=[("active", COLORS["slate_dark"])])

        style.configure(
            "Nav.TButton",
            background=COLORS["navy2"],
            foreground="#dce7ef",
            anchor="w",
            padding=(15, 10),
            borderwidth=0,
        )
        style.map(
            "Nav.TButton",
            background=[("active", COLORS["slate_dark"])],
            foreground=[("active", COLORS["white"])],
        )
        style.configure(
            "NavSelected.TButton",
            background=COLORS["slate"],
            foreground=COLORS["white"],
            anchor="w",
            padding=(15, 10),
            borderwidth=0,
            font=("Segoe UI Semibold", 10),
        )
        style.configure(
            "Plugin.TButton",
            background=COLORS["navy2"],
            foreground="#dce7ef",
            anchor="w",
            padding=(15, 9),
            borderwidth=0,
        )
        style.map(
            "Plugin.TButton",
            background=[("active", COLORS["slate"])],
            foreground=[("active", COLORS["white"])],
        )

        style.configure(
            "Treeview",
            rowheight=27,
            background=COLORS["white"],
            fieldbackground=COLORS["white"],
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["slate"],
            foreground=COLORS["white"],
            font=("Segoe UI Semibold", 9),
            padding=(7, 7),
        )
        style.map("Treeview.Heading", background=[("active", COLORS["slate_dark"])])

        style.configure(
            "Case.TNotebook",
            background=COLORS["panel"],
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        style.configure(
            "Case.TNotebook.Tab",
            background=COLORS["slate_light"],
            foreground=COLORS["slate_dark"],
            padding=(17, 8),
            borderwidth=1,
            font=("Segoe UI Semibold", 10),
        )
        style.map(
            "Case.TNotebook.Tab",
            background=[("selected", COLORS["slate"]), ("active", "#c8d7e4")],
            foreground=[("selected", COLORS["white"]), ("active", COLORS["slate_dark"])],
            expand=[
                ("selected", (0, 0, 0, 0)),
                ("active", (0, 0, 0, 0)),
                ("!selected", (0, 0, 0, 0)),
            ],
        )

    def clear_window(self) -> None:
        for child in self.winfo_children():
            child.destroy()
        self.logo = None
        self.navigation_buttons.clear()

    def load_logo(self, width: int = 600, height: int = 470) -> Optional[tk.PhotoImage]:
        if not LOGO_PATH.exists():
            return None
        image = tk.PhotoImage(file=str(LOGO_PATH))
        divisor = max(
            1,
            (image.width() + width - 1) // width,
            (image.height() + height - 1) // height,
        )
        return image.subsample(divisor, divisor) if divisor > 1 else image

    def show_welcome(self) -> None:
        self.clear_window()
        self.case = None

        container = ttk.Frame(self, style="Navy.TFrame")
        container.pack(fill="both", expand=True)

        branding = ttk.Frame(container, style="Navy.TFrame", padding=(45, 40))
        branding.pack(side="left", fill="both", expand=True)

        actions = ttk.Frame(container, style="White.TFrame", padding=(52, 45), width=470)
        actions.pack(side="right", fill="y")
        actions.pack_propagate(False)

        self.logo = self.load_logo()
        if self.logo:
            tk.Label(branding, image=self.logo, bg=COLORS["navy"], bd=0).pack(expand=True)
        else:
            tk.Label(
                branding,
                text="FRAUD\nFIGHTER\nTOOLBOX",
                bg=COLORS["navy"],
                fg=COLORS["white"],
                font=("Segoe UI Semibold", 30),
                justify="left",
            ).pack(expand=True)

        ttk.Label(actions, text=APP_NAME, style="CardTitle.TLabel").pack(anchor="w", pady=(55, 5))
        ttk.Label(
            actions,
            text="Digital forensics. Real answers. Stronger outcomes.",
            style="WhiteMuted.TLabel",
            wraplength=350,
        ).pack(anchor="w", pady=(0, 30))

        ttk.Button(
            actions,
            text="＋  Create a New Case",
            style="Primary.TButton",
            command=self.create_case,
        ).pack(fill="x", pady=6)
        ttk.Button(
            actions,
            text="▣  Open an Existing Case",
            style="Secondary.TButton",
            command=self.open_case,
        ).pack(fill="x", pady=6)

        recent = [Path(value) for value in self.settings.get("recent_cases", [])]
        recent = [path for path in recent if path.exists()]
        if recent:
            ttk.Separator(actions).pack(fill="x", pady=24)
            ttk.Label(actions, text="Recent cases", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
            for database in recent[:5]:
                ttk.Button(
                    actions,
                    text=database.parent.name,
                    command=lambda path=database: self.load_case(path),
                ).pack(fill="x", pady=3)

        ttk.Label(
            actions,
            text=f"Version {APP_VERSION}",
            style="WhiteMuted.TLabel",
        ).pack(side="bottom", anchor="e")

    def create_case(self) -> None:
        dialog = CreateCaseDialog(self, self.settings)
        self.wait_window(dialog)
        if not dialog.result:
            return

        data = dialog.result
        folder_label = f"{data['number']}_{data['name']}" if data["number"] else data["name"]
        folder = data["location"] / safe_name(folder_label)

        if folder.exists() and any(folder.iterdir()):
            if not messagebox.askyesno(
                "Existing Folder",
                "The case folder already exists and is not empty. Use it anyway?",
                parent=self,
            ):
                return

        try:
            folder.mkdir(parents=True, exist_ok=True)
            for subfolder in ("Evidence", "Exports", "Reports", "Notes", "Temp"):
                (folder / subfolder).mkdir(exist_ok=True)

            case = CaseInfo(
                name=data["name"],
                number=data["number"],
                examiner=data["examiner"],
                organization=data["organization"],
                description=data["description"],
                folder=folder,
                database=folder / "case.sqlite",
                created_utc=utc_now(),
            )
            initialize_database(case)
            (folder / "case.json").write_text(
                json.dumps(
                    {
                        "name": case.name,
                        "case_number": case.number,
                        "examiner": case.examiner,
                        "organization": case.organization,
                        "description": case.description,
                        "database": str(case.database),
                        "created_utc": case.created_utc,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            messagebox.showerror("Case Creation Failed", str(exc), parent=self)
            return

        self.settings["case_directory"] = str(data["location"])
        self.settings["examiner"] = data["examiner"]
        self.settings["organization"] = data["organization"]
        save_settings(self.settings)
        self.load_case(case.database)

    def open_case(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Open Fraud Fighter Case",
            initialdir=self.settings.get("case_directory", str(CASES_DIR)),
            filetypes=[
                ("Fraud Fighter case", "*.sqlite"),
                ("SQLite database", "*.db"),
                ("All files", "*.*"),
            ],
        )
        if selected:
            self.load_case(Path(selected))

    def load_case(self, database: Path) -> None:
        try:
            self.case = read_case(database)
        except Exception as exc:
            messagebox.showerror("Unable to Open Case", str(exc), parent=self)
            return

        recent = [str(database)] + [
            item for item in self.settings.get("recent_cases", []) if item != str(database)
        ]
        self.settings["recent_cases"] = recent[:10]
        save_settings(self.settings)

        ensure_v4_schema(database)
        self.audit("CASE_OPENED", "case", "1", f"Opened case {self.case.name}")
        self.show_case_shell()

    def audit(self, action: str, object_type: str = "", object_id: str = "", details: str = "") -> None:
        if not self.case:
            return
        with sqlite3.connect(self.case.database) as connection:
            connection.execute(
                """
                INSERT INTO audit_log
                (event_utc, examiner, action, object_type, object_id, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (utc_now(), self.case.examiner, action, object_type, object_id, details),
            )

    def show_case_shell(self) -> None:
        self.clear_window()
        assert self.case is not None
        self.plugins = discover_plugins()

        shell = ttk.Frame(self, style="Panel.TFrame")
        shell.pack(fill="both", expand=True)

        rail = ttk.Frame(shell, style="Rail.TFrame", width=270)
        rail.pack(side="left", fill="y")
        rail.pack_propagate(False)

        # Fixed footer plus a canvas that scrolls the entire navigation pane.
        bottom = ttk.Frame(rail, style="Rail.TFrame")
        bottom.pack(side="bottom", fill="x")
        ttk.Separator(bottom).pack(fill="x", padx=12, pady=(6, 4))
        ttk.Button(bottom, text="↻   Refresh Tools", style="Nav.TButton", command=self.refresh_plugins).pack(fill="x")
        ttk.Button(bottom, text="↩   Close Case", style="Nav.TButton", command=self.close_case).pack(fill="x", pady=(0, 6))

        nav_wrap = ttk.Frame(rail, style="Rail.TFrame")
        nav_wrap.pack(side="top", fill="both", expand=True)
        nav_canvas = tk.Canvas(nav_wrap, bg=COLORS["navy2"], highlightthickness=0, bd=0)
        nav_scroll = ttk.Scrollbar(nav_wrap, orient="vertical", command=nav_canvas.yview)
        nav_holder = ttk.Frame(nav_canvas, style="Rail.TFrame")
        nav_window = nav_canvas.create_window((0, 0), window=nav_holder, anchor="nw")
        nav_holder.bind("<Configure>", lambda _e: nav_canvas.configure(scrollregion=nav_canvas.bbox("all")))
        nav_canvas.bind("<Configure>", lambda e: nav_canvas.itemconfigure(nav_window, width=e.width))
        nav_canvas.configure(yscrollcommand=nav_scroll.set)
        nav_canvas.pack(side="left", fill="both", expand=True)
        nav_scroll.pack(side="right", fill="y")

        def _wheel(event):
            if getattr(event, "delta", 0):
                nav_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            elif getattr(event, "num", None) == 4:
                nav_canvas.yview_scroll(-1, "units")
            elif getattr(event, "num", None) == 5:
                nav_canvas.yview_scroll(1, "units")
        nav_canvas.bind_all("<MouseWheel>", _wheel)
        nav_canvas.bind_all("<Button-4>", _wheel)
        nav_canvas.bind_all("<Button-5>", _wheel)

        header = ttk.Frame(nav_holder, style="Rail.TFrame", padding=(16, 17))
        header.pack(fill="x")
        ttk.Label(header, text="FRAUD FIGHTER TOOLBOX", style="RailTitle.TLabel").pack(anchor="w")
        ttk.Label(header, text=f"Version {APP_VERSION}", style="RailMeta.TLabel").pack(anchor="w")
        ttk.Separator(nav_holder).pack(fill="x", padx=12, pady=(0, 12))

        ttk.Label(nav_holder, text=self.case.name, style="RailTitle.TLabel", wraplength=225).pack(anchor="w", padx=16)
        ttk.Label(nav_holder, text=self.case.number or "No case number", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(2, 14))

        ttk.Label(nav_holder, text="CASE", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(2, 4))
        for page_id, label, symbol in [
            ("dashboard", "Dashboard", "⌂"),
            ("evidence", "Evidence Manager", "▣"),
            ("bookmarks", "Bookmarks", "★"),
            ("notes", "Notes", "✎"),
            ("reports", "Reports", "▤"),
            ("audit", "Audit Log", "☷"),
        ]:
            button = ttk.Button(nav_holder, text=f"{symbol}   {label}", style="Nav.TButton", command=lambda value=page_id: self.select_case_page(value))
            button.pack(fill="x")
            self.navigation_buttons[page_id] = button

        def plugin_matches(plugin: PluginInfo, identifiers: set[str], words: tuple[str, ...]) -> bool:
            plugin_id = plugin.plugin_id.lower()
            name = plugin.name.lower()
            category = plugin.category.lower()
            return (
                plugin_id in identifiers
                or any(word in plugin_id for word in words)
                or any(word in name for word in words)
                or any(word in category for word in words)
            )

        explorer_ids = {
            "file_explorer", "registry_explorer", "pst_explorer",
            "fraud_fighter_file_explorer", "registry_viewer", "pst_viewer",
        }
        timeline_ids = {
            "timeline", "timeline_builder", "timeline_explorer", "timeline_viewer",
        }
        explorer_tools = [
            item for item in self.plugins
            if plugin_matches(item, explorer_ids, ("file explorer", "registry explorer", "pst explorer"))
        ]
        explorer_keys = {item.plugin_id for item in explorer_tools}
        timeline_tools = [
            item for item in self.plugins
            if item.plugin_id not in explorer_keys
            and plugin_matches(item, timeline_ids, ("timeline",))
        ]
        timeline_keys = {item.plugin_id for item in timeline_tools}
        analysis_tools = [
            item for item in self.plugins
            if item.plugin_id not in explorer_keys | timeline_keys
            and (
                item.category.lower() == "analysis tools"
                or item.plugin_id.lower() in {"hex_viewer", "hex_editor", "hex_drive_viewer"}
            )
        ]
        analysis_keys = {item.plugin_id for item in analysis_tools}

        for heading_text, tools in [
            ("EXPLORERS", explorer_tools),
            ("TIMELINE", timeline_tools),
            ("ANALYSIS TOOLS", analysis_tools),
        ]:
            ttk.Separator(nav_holder).pack(fill="x", padx=12, pady=12)
            ttk.Label(nav_holder, text=heading_text, style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(0, 5))
            if tools:
                for plugin in tools:
                    ttk.Button(
                        nav_holder,
                        text=f"{plugin.icon}   {plugin.name}",
                        style="Plugin.TButton",
                        command=lambda selected=plugin: self.launch_plugin(selected),
                    ).pack(fill="x")
            else:
                ttk.Label(nav_holder, text="No tools installed", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(0, 5))

        ttk.Separator(nav_holder).pack(fill="x", padx=12, pady=12)
        ttk.Label(nav_holder, text="PLUGINS", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(0, 5))
        grouped_keys = explorer_keys | timeline_keys | analysis_keys
        plugin_tools = [item for item in self.plugins if item.plugin_id not in grouped_keys]
        for plugin in plugin_tools:
            ttk.Button(nav_holder, text=f"{plugin.icon}   {plugin.name}", style="Plugin.TButton", command=lambda selected=plugin: self.launch_plugin(selected)).pack(fill="x")

        if not self.plugins:
            ttk.Label(nav_holder, text="No tools installed", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=10)

        topbar = ttk.Frame(main, style="White.TFrame", padding=(22, 13))
        topbar.pack(fill="x")
        ttk.Label(topbar, text=self.case.name, style="CardTitle.TLabel").pack(side="left")
        ttk.Label(
            topbar,
            text=f"Examiner: {self.case.examiner or 'Not specified'}",
            style="WhiteMuted.TLabel",
        ).pack(side="right")
        ttk.Separator(main).pack(fill="x")

        self.content = ttk.Frame(main, style="Panel.TFrame", padding=22)
        self.content.pack(fill="both", expand=True)
        self.select_case_page("dashboard")

    def refresh_plugins(self) -> None:
        self.audit("PLUGINS_REFRESHED", "application", "", "Refreshed plugin discovery")
        self.show_case_shell()

    def select_case_page(self, page_id: str) -> None:
        for key, button in self.navigation_buttons.items():
            button.configure(style="NavSelected.TButton" if key == page_id else "Nav.TButton")

        if not self.content:
            return
        for child in self.content.winfo_children():
            child.destroy()

        handlers = {
            "dashboard": self.show_dashboard,
            "evidence": self.show_evidence,
            "bookmarks": self.show_bookmarks,
            "notes": self.show_notes,
            "reports": self.show_reports,
            "audit": self.show_audit,
        }
        handler = handlers.get(page_id, self.show_dashboard)
        try:
            handler()
        except Exception as exc:
            # Never leave the main pane blank. Show a useful error and keep
            # Dashboard navigation available so the examiner can recover.
            ttk.Label(self.content, text="Unable to display page", style="Title.TLabel").pack(anchor="w")
            ttk.Label(
                self.content,
                text=f"{type(exc).__name__}: {exc}",
                style="Muted.TLabel",
                wraplength=900,
            ).pack(anchor="w", pady=(8, 16))
            ttk.Button(
                self.content,
                text="Return to Dashboard",
                style="Primary.TButton",
                command=lambda: self.select_case_page("dashboard"),
            ).pack(anchor="w")

    def heading(self, title: str, subtitle: str) -> None:
        assert self.content is not None
        ttk.Label(self.content, text=title, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            self.content,
            text=subtitle,
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 18))

    def show_dashboard(self) -> None:
        assert self.case is not None and self.content is not None
        self.heading("Case Dashboard", "Manage the active case and launch forensic plugins from the left rail.")

        with sqlite3.connect(self.case.database) as connection:
            evidence_count = connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            bookmarks_count = connection.execute("SELECT COUNT(*) FROM bookmarks").fetchone()[0]
            notes_count = connection.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
            reports_count = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            runs_count = connection.execute("SELECT COUNT(*) FROM plugin_runs").fetchone()[0]

        cards = ttk.Frame(self.content, style="Panel.TFrame")
        cards.pack(fill="x", pady=(0, 20))
        for index, (value, label) in enumerate(
            [
                (evidence_count, "Evidence Items"),
                (bookmarks_count, "Bookmarks"),
                (notes_count, "Case Notes"),
                (reports_count, "Reports"),
                (runs_count, "Plugin Launches"),
            ]
        ):
            card = tk.Frame(
                cards,
                bg=COLORS["white"],
                highlightbackground=COLORS["border"],
                highlightthickness=1,
                padx=18,
                pady=14,
            )
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 5, 5))
            tk.Label(
                card,
                text=f"{value:,}",
                bg=COLORS["white"],
                fg=COLORS["navy"],
                font=("Segoe UI Semibold", 21),
            ).pack(anchor="w")
            tk.Label(
                card,
                text=label,
                bg=COLORS["white"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9),
            ).pack(anchor="w")
            cards.columnconfigure(index, weight=1)

        case_panel = tk.Frame(
            self.content,
            bg=COLORS["white"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=22,
            pady=18,
        )
        case_panel.pack(fill="x", pady=(0, 18))
        tk.Label(
            case_panel,
            text="Case Information",
            bg=COLORS["white"],
            fg=COLORS["navy"],
            font=("Segoe UI Semibold", 14),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        information = [
            ("Case name", self.case.name),
            ("Case number", self.case.number or "Not specified"),
            ("Examiner", self.case.examiner or "Not specified"),
            ("Organization", self.case.organization or "Not specified"),
            ("Case folder", str(self.case.folder)),
            ("Created", self.case.created_utc),
        ]
        for row, (label, value) in enumerate(information, 1):
            tk.Label(case_panel, text=label, bg=COLORS["white"], fg=COLORS["muted"]).grid(
                row=row, column=0, sticky="nw", padx=(0, 18), pady=3
            )
            tk.Label(
                case_panel,
                text=value,
                bg=COLORS["white"],
                fg=COLORS["text"],
                justify="left",
                wraplength=850,
            ).grid(row=row, column=1, sticky="w", pady=3)

        if self.case.description:
            tk.Label(case_panel, text="Description", bg=COLORS["white"], fg=COLORS["muted"]).grid(
                row=len(information) + 1, column=0, sticky="nw", padx=(0, 18), pady=3
            )
            tk.Label(
                case_panel,
                text=self.case.description,
                bg=COLORS["white"],
                fg=COLORS["text"],
                justify="left",
                wraplength=850,
            ).grid(row=len(information) + 1, column=1, sticky="w", pady=3)

        plugin_panel = tk.Frame(
            self.content,
            bg=COLORS["white"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=22,
            pady=16,
        )
        plugin_panel.pack(fill="both", expand=True)
        tk.Label(
            plugin_panel,
            text="Installed Plugins",
            bg=COLORS["white"],
            fg=COLORS["navy"],
            font=("Segoe UI Semibold", 14),
        ).pack(anchor="w")
        tk.Label(
            plugin_panel,
            text=(
                f"{len(self.plugins)} plugin(s) installed. Select any plugin in the left rail "
                "to launch it in a separate window."
            ),
            bg=COLORS["white"],
            fg=COLORS["muted"],
        ).pack(anchor="w", pady=(4, 0))

    def show_evidence(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Evidence Manager", "Choose a mounted source, import a Collector package, or run the Live Evidence Collector.")

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(toolbar, text="＋ Choose Mounted Source", style="Primary.TButton", command=self.add_mounted_source).pack(side="left")
        ttk.Button(toolbar, text="Import Collector ZIP", style="Secondary.TButton", command=self.import_collector_zip).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Run Live Collector", style="Secondary.TButton", command=self.run_live_collector).pack(side="left")
        ttk.Button(toolbar, text="Open in File Explorer", style="Secondary.TButton", command=self.open_selected_evidence).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Open Evidence Folder", style="Secondary.TButton", command=lambda: self.open_folder(self.case.folder / "Evidence")).pack(side="left", padx=8)

        columns = ("id", "number", "name", "type", "source", "files", "size", "status", "added")
        self.evidence_tree = ttk.Treeview(self.content, columns=columns, show="headings", selectmode="browse")
        specs = [
            ("id","ID",50),("number","Evidence No.",105),("name","Name",210),("type","Type",145),
            ("source","Source / Package",320),("files","Files",90),("size","Size",105),("status","Status",100),("added","Added UTC",190)
        ]
        for column,label,width in specs:
            self.evidence_tree.heading(column,text=label)
            self.evidence_tree.column(column,width=width,anchor="w")
        self.evidence_tree.pack(fill="both", expand=True)
        self.evidence_tree.bind("<Double-1>", lambda _e: self.open_selected_evidence())

        with sqlite3.connect(self.case.database) as connection:
            rows = connection.execute("""
                SELECT id, evidence_number, name, evidence_type,
                       COALESCE(package_path, source), file_count, size_bytes,
                       import_status, added_utc
                FROM evidence ORDER BY id DESC
            """).fetchall()
        for row in rows:
            shown = list(row)
            shown[6] = human_size(shown[6] or 0)
            self.evidence_tree.insert("", "end", values=shown)

    def run_live_collector(self) -> None:
        """Launch the Live Evidence Collector from Evidence Manager."""
        candidates = [
            item for item in self.plugins
            if item.plugin_id in ("live_evidence_collector", "evidence_collector")
            or "live evidence collector" in item.name.lower()
        ]
        if not candidates:
            messagebox.showerror(
                "Live Collector Missing",
                "No Live Evidence Collector was found. Place its Python script in the Scripts folder and include TITLE: Live Evidence Collector in its header.",
                parent=self,
            )
            return
        self.launch_plugin(candidates[0])
        self.audit("LIVE_COLLECTOR_LAUNCHED", "plugin", candidates[0].plugin_id, "Launched from Evidence Manager")

    def next_evidence_number(self) -> str:
        assert self.case is not None
        with sqlite3.connect(self.case.database) as connection:
            value = connection.execute("SELECT COALESCE(MAX(id),0)+1 FROM evidence").fetchone()[0]
        return f"E-{value:03d}"

    def choose_source_path(self) -> Optional[Path]:
        initial = "C:/" if os.name == "nt" else str(Path.home())
        selected = filedialog.askdirectory(parent=self, title="Choose Mounted Drive or Evidence Folder", initialdir=initial)
        return Path(selected) if selected else None

    def add_mounted_source(self) -> None:
        assert self.case is not None
        source = self.choose_source_path()
        if not source:
            return
        name = source.drive.rstrip(":\\/") if source.drive else source.name
        if not name:
            name = str(source)
        number = self.next_evidence_number()
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute("""
                INSERT INTO evidence
                (evidence_number, name, evidence_type, source, root_path, custodian,
                 description, acquired_utc, added_utc, status, import_status)
                VALUES (?, ?, 'Mounted Source', ?, ?, '', '', '', ?, 'Active', 'Ready')
            """, (number, name, str(source), str(source), utc_now()))
            evidence_id = cursor.lastrowid
        self.audit("EVIDENCE_SOURCE_ADDED", "evidence", str(evidence_id), f"Mounted source {source}")
        self.select_case_page("evidence")

    def import_collector_zip(self) -> None:
        assert self.case is not None
        selected = filedialog.askopenfilename(parent=self, title="Open Live Evidence Collector ZIP", filetypes=[("ZIP packages","*.zip"),("All files","*.*")])
        if not selected:
            return
        package = Path(selected)
        try:
            with zipfile.ZipFile(package, "r") as zf:
                bad = zf.testzip()
                if bad:
                    raise ValueError(f"ZIP integrity test failed at {bad}")
                names = zf.namelist()
                manifest_name = next((n for n in names if Path(n).name.lower() in ("manifest.json","collection_manifest.json")), "")
                collector_markers = ("registry", "event", "prefetch", "browser", "collection")
                is_collector = bool(manifest_name or any(any(marker in n.lower() for marker in collector_markers) for n in names))
                if not is_collector and not messagebox.askyesno("Generic ZIP", "This ZIP does not appear to contain a Live Evidence Collector manifest. Import it as generic ZIP evidence?", parent=self):
                    return
        except Exception as exc:
            messagebox.showerror("Invalid ZIP", str(exc), parent=self)
            return

        name = package.stem
        destination = self.case.folder / "Evidence" / safe_name(name)
        counter = 2
        while destination.exists():
            destination = self.case.folder / "Evidence" / f"{safe_name(name)}_{counter}"
            counter += 1
        destination.mkdir(parents=True, exist_ok=False)
        number = self.next_evidence_number()
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute("""
                INSERT INTO evidence
                (evidence_number, name, evidence_type, source, root_path, package_path,
                 custodian, description, acquired_utc, added_utc, status, import_status)
                VALUES (?, ?, ?, ?, ?, ?, '', '', '', ?, 'Active', 'Importing')
            """, (number, name, "Live Collector ZIP" if is_collector else "Generic ZIP", str(package), str(destination), str(package), utc_now()))
            evidence_id = cursor.lastrowid
        self.audit("EVIDENCE_IMPORT_STARTED", "evidence", str(evidence_id), str(package))

        progress = tk.Toplevel(self)
        progress.title("Importing Evidence")
        progress.transient(self)
        ttk.Label(progress, text=f"Importing {package.name}…", padding=18).pack()
        bar = ttk.Progressbar(progress, mode="indeterminate", length=360)
        bar.pack(padx=18, pady=(0,18)); bar.start(12)

        def worker():
            try:
                sha = hashlib.sha256()
                with package.open("rb") as fh:
                    for block in iter(lambda: fh.read(1024*1024), b""):
                        sha.update(block)
                manifest_text = ""
                with zipfile.ZipFile(package, "r") as zf:
                    root_resolved = destination.resolve()
                    for member in zf.infolist():
                        target = (destination / member.filename).resolve()
                        if root_resolved not in target.parents and target != root_resolved:
                            raise ValueError(f"Unsafe ZIP path: {member.filename}")
                    zf.extractall(destination)
                    if manifest_name:
                        try: manifest_text = zf.read(manifest_name).decode("utf-8", errors="replace")
                        except Exception: pass
                file_count=0; size_bytes=0
                for root, _dirs, files in os.walk(destination):
                    for filename in files:
                        file_count += 1
                        try: size_bytes += (Path(root)/filename).stat().st_size
                        except OSError: pass
                with sqlite3.connect(self.case.database) as connection:
                    connection.execute("""UPDATE evidence SET package_sha256=?, file_count=?, size_bytes=?, import_status='Ready', collector_manifest=? WHERE id=?""",
                                       (sha.hexdigest(), file_count, size_bytes, manifest_text, evidence_id))
                self.audit("EVIDENCE_IMPORT_COMPLETED", "evidence", str(evidence_id), f"{file_count} files; SHA256={sha.hexdigest()}")
                self.after(0, lambda: messagebox.showinfo("Import Complete", f"Imported {file_count:,} files\nDestination: {destination}\nSHA-256: {sha.hexdigest()}", parent=self))
            except Exception as exc:
                shutil.rmtree(destination, ignore_errors=True)
                with sqlite3.connect(self.case.database) as connection:
                    connection.execute("UPDATE evidence SET import_status='Failed' WHERE id=?", (evidence_id,))
                self.after(0, lambda: messagebox.showerror("Import Failed", str(exc), parent=self))
            finally:
                self.after(0, progress.destroy)
                self.after(0, lambda: self.select_case_page("evidence"))
        threading.Thread(target=worker, daemon=True).start()

    def open_selected_evidence(self) -> None:
        assert self.case is not None
        tree = getattr(self, "evidence_tree", None)
        if not tree or not tree.selection():
            messagebox.showinfo("Select Evidence", "Select an evidence item first.", parent=self)
            return
        evidence_id = tree.item(tree.selection()[0], "values")[0]
        with sqlite3.connect(self.case.database) as connection:
            row = connection.execute("SELECT id, name, root_path FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row or not row[2] or not Path(row[2]).exists():
            messagebox.showwarning("Evidence Unavailable", "The evidence path is not currently available.", parent=self)
            return
        plugin = next((item for item in self.plugins if item.plugin_id == "file_explorer"), None)
        if not plugin:
            messagebox.showerror("File Explorer Missing", "The File Explorer plugin is not installed.", parent=self)
            return
        self.launch_plugin(plugin, {"FFT_EVIDENCE_ID": str(row[0]), "FFT_EVIDENCE_NAME": row[1], "FFT_EVIDENCE_ROOT": row[2]})

    def show_bookmarks(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading(
            "Bookmarks",
            "Review bookmarked files, registry items, messages, timeline events, and other case artifacts.",
        )

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(toolbar, text="＋ Add Bookmark", style="Primary.TButton", command=self.add_bookmark).pack(side="left")
        ttk.Button(toolbar, text="Edit", style="Secondary.TButton", command=self.edit_selected_bookmark).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Delete", style="Secondary.TButton", command=self.delete_selected_bookmark).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Refresh", style="Secondary.TButton", command=lambda: self.select_case_page("bookmarks")).pack(side="left", padx=(8, 0))

        filter_frame = ttk.Frame(self.content, style="Panel.TFrame")
        filter_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(filter_frame, text="Filter:").pack(side="left")
        self.bookmark_filter = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=self.bookmark_filter, width=45)
        filter_entry.pack(side="left", padx=(8, 8))
        ttk.Button(filter_frame, text="Apply", command=self.load_bookmarks).pack(side="left")
        ttk.Button(filter_frame, text="Clear", command=self.clear_bookmark_filter).pack(side="left", padx=(6, 0))
        filter_entry.bind("<Return>", lambda _event: self.load_bookmarks())

        pane = ttk.Panedwindow(self.content, orient="vertical")
        pane.pack(fill="both", expand=True)

        list_frame = ttk.Frame(pane, style="Panel.TFrame")
        detail_frame = ttk.LabelFrame(pane, text="Bookmark Details", padding=8)
        pane.add(list_frame, weight=3)
        pane.add(detail_frame, weight=1)

        columns = ("id", "title", "category", "object_type", "evidence", "reference", "created")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")
        for column, label, width in [
            ("id", "ID", 55),
            ("title", "Title", 260),
            ("category", "Category", 130),
            ("object_type", "Object Type", 130),
            ("evidence", "Evidence ID", 90),
            ("reference", "Reference / Path", 420),
            ("created", "Created UTC", 210),
        ]:
            tree.heading(column, text=label)
            tree.column(column, width=width, anchor="w")
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        tree.bind("<<TreeviewSelect>>", self.show_bookmark_details)
        tree.bind("<Double-1>", lambda _event: self.edit_selected_bookmark())
        self.bookmark_tree = tree

        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(0, weight=1)
        details = tk.Text(detail_frame, height=8, wrap="word", state="disabled")
        details.grid(row=0, column=0, sticky="nsew")
        self.bookmark_details = details
        self.load_bookmarks()

    def clear_bookmark_filter(self) -> None:
        if hasattr(self, "bookmark_filter"):
            self.bookmark_filter.set("")
        self.load_bookmarks()

    def load_bookmarks(self) -> None:
        assert self.case is not None
        tree = getattr(self, "bookmark_tree", None)
        if not tree:
            return
        tree.delete(*tree.get_children())
        search = getattr(self, "bookmark_filter", tk.StringVar()).get().strip()
        sql = """
            SELECT id, title, COALESCE(category,''), COALESCE(object_type,''),
                   COALESCE(evidence_id,''), COALESCE(reference,''), created_utc
            FROM bookmarks
        """
        params: tuple = ()
        if search:
            sql += """
                WHERE title LIKE ? OR category LIKE ? OR object_type LIKE ?
                   OR object_id LIKE ? OR reference LIKE ? OR notes LIKE ?
            """
            token = f"%{search}%"
            params = (token, token, token, token, token, token)
        sql += " ORDER BY id DESC"
        with sqlite3.connect(self.case.database) as connection:
            rows = connection.execute(sql, params).fetchall()
        for row in rows:
            tree.insert("", "end", values=row)
        details = getattr(self, "bookmark_details", None)
        if details:
            details.configure(state="normal")
            details.delete("1.0", "end")
            details.insert("end", f"{len(rows):,} bookmark(s)")
            details.configure(state="disabled")

    def selected_bookmark_id(self) -> Optional[int]:
        tree = getattr(self, "bookmark_tree", None)
        if not tree or not tree.selection():
            return None
        try:
            return int(tree.item(tree.selection()[0], "values")[0])
        except (ValueError, TypeError, IndexError):
            return None

    def show_bookmark_details(self, _event=None) -> None:
        assert self.case is not None
        bookmark_id = self.selected_bookmark_id()
        details = getattr(self, "bookmark_details", None)
        if bookmark_id is None or details is None:
            return
        with sqlite3.connect(self.case.database) as connection:
            row = connection.execute(
                """
                SELECT title, category, object_type, object_id, evidence_id, reference,
                       notes, created_utc, modified_utc, created_by
                FROM bookmarks WHERE id=?
                """,
                (bookmark_id,),
            ).fetchone()
        if not row:
            return
        labels = [
            "Title", "Category", "Object Type", "Object ID", "Evidence ID",
            "Reference / Path", "Notes", "Created UTC", "Modified UTC", "Created By",
        ]
        details.configure(state="normal")
        details.delete("1.0", "end")
        for label, value in zip(labels, row):
            details.insert("end", f"{label}: {value or ''}\n")
        details.configure(state="disabled")

    def add_bookmark(self) -> None:
        assert self.case is not None
        dialog = TextEntryDialog(
            self,
            "Add Bookmark",
            [
                ("title", "Title"),
                ("category", "Category"),
                ("object_type", "Object Type"),
                ("object_id", "Object ID"),
                ("evidence_id", "Evidence ID"),
                ("reference", "Reference / Path"),
            ],
            multiline="Bookmark Notes",
        )
        self.wait_window(dialog)
        if not dialog.result or not dialog.result.get("title"):
            return
        evidence_text = dialog.result.get("evidence_id", "").strip()
        try:
            evidence_id = int(evidence_text) if evidence_text else None
        except ValueError:
            messagebox.showerror("Invalid Evidence ID", "Evidence ID must be a whole number.", parent=self)
            return
        now = utc_now()
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute(
                """
                INSERT INTO bookmarks
                (title, category, object_type, object_id, evidence_id, reference, notes,
                 created_utc, modified_utc, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dialog.result["title"], dialog.result.get("category", ""),
                    dialog.result.get("object_type", ""), dialog.result.get("object_id", ""),
                    evidence_id, dialog.result.get("reference", ""), dialog.result.get("body", ""),
                    now, now, self.case.examiner,
                ),
            )
            bookmark_id = cursor.lastrowid
        self.audit("BOOKMARK_ADDED", "bookmark", str(bookmark_id), dialog.result["title"])
        self.select_case_page("bookmarks")

    def edit_selected_bookmark(self) -> None:
        assert self.case is not None
        bookmark_id = self.selected_bookmark_id()
        if bookmark_id is None:
            messagebox.showinfo("Select Bookmark", "Select a bookmark first.", parent=self)
            return
        with sqlite3.connect(self.case.database) as connection:
            row = connection.execute(
                """
                SELECT title, category, object_type, object_id, evidence_id, reference, notes
                FROM bookmarks WHERE id=?
                """,
                (bookmark_id,),
            ).fetchone()
        if not row:
            return
        dialog = TextEntryDialog(
            self,
            "Edit Bookmark",
            [
                ("title", "Title"), ("category", "Category"),
                ("object_type", "Object Type"), ("object_id", "Object ID"),
                ("evidence_id", "Evidence ID"), ("reference", "Reference / Path"),
            ],
            multiline="Bookmark Notes",
        )
        values = [row[0], row[1], row[2], row[3], row[4], row[5]]
        for key, value in zip(dialog.variables, values):
            dialog.variables[key].set("" if value is None else str(value))
        if dialog.body is not None:
            dialog.body.insert("1.0", row[6] or "")
        self.wait_window(dialog)
        if not dialog.result or not dialog.result.get("title"):
            return
        evidence_text = dialog.result.get("evidence_id", "").strip()
        try:
            evidence_id = int(evidence_text) if evidence_text else None
        except ValueError:
            messagebox.showerror("Invalid Evidence ID", "Evidence ID must be a whole number.", parent=self)
            return
        with sqlite3.connect(self.case.database) as connection:
            connection.execute(
                """
                UPDATE bookmarks SET title=?, category=?, object_type=?, object_id=?,
                    evidence_id=?, reference=?, notes=?, modified_utc=? WHERE id=?
                """,
                (
                    dialog.result["title"], dialog.result.get("category", ""),
                    dialog.result.get("object_type", ""), dialog.result.get("object_id", ""),
                    evidence_id, dialog.result.get("reference", ""), dialog.result.get("body", ""),
                    utc_now(), bookmark_id,
                ),
            )
        self.audit("BOOKMARK_UPDATED", "bookmark", str(bookmark_id), dialog.result["title"])
        self.select_case_page("bookmarks")

    def delete_selected_bookmark(self) -> None:
        assert self.case is not None
        bookmark_id = self.selected_bookmark_id()
        if bookmark_id is None:
            messagebox.showinfo("Select Bookmark", "Select a bookmark first.", parent=self)
            return
        if not messagebox.askyesno("Delete Bookmark", "Delete the selected bookmark?", parent=self):
            return
        with sqlite3.connect(self.case.database) as connection:
            connection.execute("DELETE FROM bookmarks WHERE id=?", (bookmark_id,))
        self.audit("BOOKMARK_DELETED", "bookmark", str(bookmark_id), "Deleted bookmark")
        self.select_case_page("bookmarks")

    def show_notes(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Case Notes", "Store investigation notes in the active case database.")

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(
            toolbar,
            text="＋ Add Note",
            style="Primary.TButton",
            command=self.add_note,
        ).pack(side="left")

        columns = ("id", "title", "created", "modified")
        tree = ttk.Treeview(self.content, columns=columns, show="headings")
        for column, label, width in [
            ("id", "ID", 55),
            ("title", "Title", 420),
            ("created", "Created UTC", 220),
            ("modified", "Modified UTC", 220),
        ]:
            tree.heading(column, text=label)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        with sqlite3.connect(self.case.database) as connection:
            rows = connection.execute(
                "SELECT id, title, created_utc, modified_utc FROM notes ORDER BY id DESC"
            ).fetchall()
        for row in rows:
            tree.insert("", "end", values=row)

    def add_note(self) -> None:
        assert self.case is not None
        dialog = TextEntryDialog(self, "Add Case Note", [("title", "Title")], multiline="Note")
        self.wait_window(dialog)
        if not dialog.result or not dialog.result.get("title"):
            return
        now = utc_now()
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute(
                """
                INSERT INTO notes (title, body, created_utc, modified_utc)
                VALUES (?, ?, ?, ?)
                """,
                (dialog.result["title"], dialog.result.get("body", ""), now, now),
            )
            note_id = cursor.lastrowid
        self.audit("NOTE_ADDED", "note", str(note_id), dialog.result["title"])
        self.select_case_page("notes")

    def show_reports(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Reports", "Maintain generated reports and open the case report folder.")

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(
            toolbar,
            text="Open Reports Folder",
            style="Primary.TButton",
            command=lambda: self.open_folder(self.case.folder / "Reports"),
        ).pack(side="left")
        ttk.Button(
            toolbar,
            text="Register Existing Report",
            style="Secondary.TButton",
            command=self.register_report,
        ).pack(side="left", padx=8)

        columns = ("id", "title", "type", "path", "created")
        tree = ttk.Treeview(self.content, columns=columns, show="headings")
        for column, label, width in [
            ("id", "ID", 55),
            ("title", "Title", 250),
            ("type", "Type", 130),
            ("path", "File Path", 470),
            ("created", "Created UTC", 210),
        ]:
            tree.heading(column, text=label)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        with sqlite3.connect(self.case.database) as connection:
            rows = connection.execute(
                "SELECT id, title, report_type, file_path, created_utc FROM reports ORDER BY id DESC"
            ).fetchall()
        for row in rows:
            tree.insert("", "end", values=row)

    def register_report(self) -> None:
        assert self.case is not None
        selected = filedialog.askopenfilename(parent=self, title="Select Report")
        if not selected:
            return
        path = Path(selected)
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute(
                """
                INSERT INTO reports
                (title, report_type, file_path, created_utc, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (path.stem, path.suffix.lstrip(".").upper(), str(path), utc_now(), ""),
            )
            report_id = cursor.lastrowid
        self.audit("REPORT_REGISTERED", "report", str(report_id), str(path))
        self.select_case_page("reports")

    def show_audit(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Audit Log", "Review actions recorded by the suite launcher.")

        columns = ("id", "time", "examiner", "action", "object", "details")
        tree = ttk.Treeview(self.content, columns=columns, show="headings")
        for column, label, width in [
            ("id", "ID", 55),
            ("time", "Event UTC", 210),
            ("examiner", "Examiner", 150),
            ("action", "Action", 180),
            ("object", "Object", 150),
            ("details", "Details", 500),
        ]:
            tree.heading(column, text=label)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        with sqlite3.connect(self.case.database) as connection:
            rows = connection.execute(
                """
                SELECT id, event_utc, examiner, action,
                       CASE
                           WHEN object_type IS NULL OR object_type = '' THEN ''
                           ELSE object_type || ':' || COALESCE(object_id, '')
                       END,
                       details
                FROM audit_log ORDER BY id DESC
                """
            ).fetchall()
        for row in rows:
            tree.insert("", "end", values=row)

    def launch_plugin(self, plugin: PluginInfo, extra_environment: Optional[dict[str, str]] = None) -> None:
        assert self.case is not None
        existing = self.plugin_processes.get(plugin.plugin_id)
        if existing and existing.poll() is None:
            if messagebox.askyesno(
                "Plugin Already Running",
                f"{plugin.name} is already running.\n\nLaunch another instance?",
                parent=self,
            ) is False:
                return

        environment = os.environ.copy()
        environment.update(
            {
                "FFT_CASE_DB": str(self.case.database),
                "FFT_CASE_FOLDER": str(self.case.folder),
                "FFT_CASE_NAME": self.case.name,
                "FFT_CASE_NUMBER": self.case.number,
                "FFT_EXAMINER": self.case.examiner,
                "FFT_SUITE_VERSION": APP_VERSION,
            }
        )

        if extra_environment:
            environment.update(extra_environment)

        if plugin.executable.suffix.lower() == ".py":
            command = [sys.executable, str(plugin.executable)]
        else:
            command = [str(plugin.executable)]

        if plugin.pass_case_arguments:
            command.extend(
                [
                    "--case-db", str(self.case.database),
                    "--case-folder", str(self.case.folder),
                ]
            )

        try:
            process = subprocess.Popen(
                command,
                cwd=str(plugin.working_directory),
                env=environment,
            )
            self.plugin_processes[plugin.plugin_id] = process
            with sqlite3.connect(self.case.database) as connection:
                connection.execute(
                    """
                    INSERT INTO plugin_runs
                    (plugin_id, plugin_name, executable_path, process_id,
                     started_utc, status, message)
                    VALUES (?, ?, ?, ?, ?, 'Launched', ?)
                    """,
                    (
                        plugin.plugin_id,
                        plugin.name,
                        str(plugin.executable),
                        process.pid,
                        utc_now(),
                        "Launched in a separate process and window",
                    ),
                )
            self.audit(
                "PLUGIN_LAUNCHED",
                "plugin",
                plugin.plugin_id,
                f"{plugin.name}; PID {process.pid}; {plugin.executable}",
            )
        except Exception as exc:
            messagebox.showerror("Plugin Launch Failed", str(exc), parent=self)
            self.audit(
                "PLUGIN_LAUNCH_FAILED",
                "plugin",
                plugin.plugin_id,
                f"{plugin.name}: {exc}",
            )

    def open_folder(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Unable to Open Folder", str(exc), parent=self)

    def close_case(self) -> None:
        if self.case:
            self.audit("CASE_CLOSED", "case", "1", f"Closed case {self.case.name}")
        self.show_welcome()

    def close_application(self) -> None:
        if self.case:
            self.audit("APPLICATION_CLOSED", "application", "", "Suite launcher closed")
        self.destroy()


def main() -> None:
    ASSETS_DIR.mkdir(exist_ok=True)
    PLUGINS_DIR.mkdir(exist_ok=True)
    CASES_DIR.mkdir(exist_ok=True)
    SuiteApp().mainloop()


if __name__ == "__main__":
    main()
