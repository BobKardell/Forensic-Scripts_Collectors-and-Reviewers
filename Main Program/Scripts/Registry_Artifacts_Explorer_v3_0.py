#!/usr/bin/env python3
# FFT_TOOL
# TITLE: Registry Artifacts Explorer
# ID: registry_artifacts
# CATEGORY: Analysis Tools
# VERSION: 3.0.2
# DESCRIPTION: Discover and parse Windows Registry artifacts from forensic evidence.
# ICON: 🧊
# PASS_CASE_ARGUMENTS: false

from __future__ import annotations

import csv
import ctypes
import json
import os
import re
import shutil
import sqlite3
import sys
import subprocess
import tempfile
import threading
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Iterable, Optional

APP_NAME = "Registry Artifacts Explorer"
APP_VERSION = "3.0.2"

CASE_DB = Path(os.environ["FFT_CASE_DB"]) if os.environ.get("FFT_CASE_DB") else None
CASE_FOLDER = Path(os.environ["FFT_CASE_FOLDER"]) if os.environ.get("FFT_CASE_FOLDER") else None
CASE_NAME = os.environ.get("FFT_CASE_NAME", "Standalone Analysis")
CASE_NUMBER = os.environ.get("FFT_CASE_NUMBER", "")
EXAMINER = os.environ.get("FFT_EXAMINER", "")
ENV_EVIDENCE_ROOT = os.environ.get("FFT_EVIDENCE_ROOT", "")
ENV_EVIDENCE_ID = os.environ.get("FFT_EVIDENCE_ID", "")

COLORS = {
    "navy": "#061522", "navy2": "#0c2235", "blue": "#188bd0",
    "slate": "#587795", "panel": "#f2f6f9", "white": "#ffffff",
    "text": "#172431", "muted": "#607180", "border": "#c8d5df",
    "green": "#367d4a", "red": "#a33b3b",
}

DEFAULT_RULES = [
    ("Computer Information", "SYSTEM", r"ControlSet001\Control\ComputerName\ComputerName", False),
    ("Operating System", "SOFTWARE", r"Microsoft\Windows NT\CurrentVersion", False),
    ("Time Zone", "SYSTEM", r"ControlSet001\Control\TimeZoneInformation", False),
    ("Network Parameters", "SYSTEM", r"ControlSet001\Services\Tcpip\Parameters", False),
    ("Network Interfaces", "SYSTEM", r"ControlSet001\Services\Tcpip\Parameters\Interfaces", True),
    ("USB Devices", "SYSTEM", r"ControlSet001\Enum\USB", True),
    ("USB Storage", "SYSTEM", r"ControlSet001\Enum\USBSTOR", True),
    ("Mounted Devices", "SYSTEM", r"MountedDevices", False),
    ("Services", "SYSTEM", r"ControlSet001\Services", True),
    ("User Accounts", "SAM", r"SAM\Domains\Account\Users\Names", True),
    ("Profile List", "SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\ProfileList", True),
    ("Installed Software", "SOFTWARE", r"Microsoft\Windows\CurrentVersion\Uninstall", True),
    ("Installed Software 32-bit", "SOFTWARE", r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", True),
    ("Run Keys", "SOFTWARE", r"Microsoft\Windows\CurrentVersion\Run", False),
    ("RunOnce Keys", "SOFTWARE", r"Microsoft\Windows\CurrentVersion\RunOnce", False),
    ("Winlogon", "SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Winlogon", False),
    ("RecentDocs", "NTUSER.DAT", r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", True),
    ("UserAssist", "NTUSER.DAT", r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist", True),
    ("Run MRU", "NTUSER.DAT", r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", False),
    ("OpenSave MRU", "NTUSER.DAT", r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", True),
    ("Typed URLs", "NTUSER.DAT", r"Software\Microsoft\Internet Explorer\TypedURLs", False),
    ("Typed Paths", "NTUSER.DAT", r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", False),
    ("WordWheelQuery", "NTUSER.DAT", r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", False),
    ("Network Shares", "NTUSER.DAT", r"Network", True),
    ("ShellBags", "USRCLASS.DAT", r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU", True),
    ("ShellBags", "USRCLASS.DAT", r"Local Settings\Software\Microsoft\Windows\Shell\Bags", True),
    ("MuiCache", "USRCLASS.DAT", r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache", True),
    ("BAM", "SYSTEM", r"ControlSet001\Services\bam\State\UserSettings", True),
]

HIVE_NAMES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT", "AMCACHE.HVE"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return " | ".join(safe_text(item) for item in value)
    return str(value)


def rot13(text: str) -> str:
    result = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr((ord(char) - 97 + 13) % 26 + 97))
        elif "A" <= char <= "Z":
            result.append(chr((ord(char) - 65 + 13) % 26 + 65))
        else:
            result.append(char)
    return "".join(result)


def user_context_for_hive(path: Path) -> str:
    parts = list(path.parts)
    upper = [part.upper() for part in parts]
    if path.name.upper() == "NTUSER.DAT":
        return path.parent.name
    if path.name.upper() == "USRCLASS.DAT":
        try:
            local_index = upper.index("APPDATA")
            return parts[local_index - 1] if local_index else path.parent.name
        except (ValueError, IndexError):
            return path.parent.name
    return ""


@dataclass
class Rule:
    enabled: bool
    category: str
    hive: str
    key_path: str
    recursive: bool
    definition_id: int = 0
    artifact_name: str = ""
    value_name: str = ""
    description: str = ""


class RegistryArtifactsApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1500x900")
        self.minsize(1100, 700)
        self.configure(bg=COLORS["panel"])
        self.cancel_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.hives: dict[str, list[Path]] = {}
        self.rules: list[Rule] = []
        self.source_var = tk.StringVar(value=self.resolve_evidence_root())
        self.filter_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0)
        self._configure_styles()
        self._build_ui()
        self.ensure_schema()
        self.load_rules_from_database()
        self.load_results()
        if self.source_var.get():
            self.after(250, self.discover_hives)


    def resolve_evidence_root(self) -> str:
        """Resolve the mounted volume from the selected Evidence Manager row."""
        candidates: list[str] = []
        if CASE_DB and CASE_DB.exists() and ENV_EVIDENCE_ID.isdigit():
            try:
                with sqlite3.connect(CASE_DB) as con:
                    table = con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND lower(name)='evidence'"
                    ).fetchone()
                    if table:
                        table_name = table[0]
                        columns = {row[1].lower(): row[1] for row in con.execute(f'PRAGMA table_info("{table_name}")')}
                        id_column = next((columns[n] for n in ("id", "evidence_id", "evidenceid") if n in columns), None)
                        path_columns = [columns[n] for n in (
                            "mounted_volume", "mount_path", "mounted_path", "volume_root",
                            "evidence_root", "root_path", "source_image", "source_path", "source"
                        ) if n in columns]
                        if id_column and path_columns:
                            quoted = ", ".join(f'"{name}"' for name in path_columns)
                            row = con.execute(
                                f'SELECT {quoted} FROM "{table_name}" WHERE "{id_column}"=?',
                                (int(ENV_EVIDENCE_ID),),
                            ).fetchone()
                            if row:
                                candidates.extend(str(value).strip() for value in row if value and str(value).strip())
            except sqlite3.Error:
                pass
        if ENV_EVIDENCE_ROOT:
            candidates.append(ENV_EVIDENCE_ROOT)
        for candidate in candidates:
            try:
                path = Path(os.path.expandvars(candidate))
                if path.exists():
                    return str(self.normalize_volume_root(path))
            except OSError:
                continue
        return candidates[0] if candidates else ""

    @staticmethod
    def is_administrator() -> bool:
        if os.name != "nt":
            return True
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def restart_as_administrator(self) -> None:
        if os.name != "nt" or self.is_administrator():
            messagebox.showinfo("Administrator", "The plugin is already running with administrative rights.", parent=self)
            return
        script = str(Path(__file__).resolve())
        params = subprocess.list2cmdline([script] + sys.argv[1:])
        try:
            result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(Path.cwd()), 1)
            if result <= 32:
                raise OSError(f"ShellExecuteW returned {result}")
            self.destroy()
        except Exception as exc:
            messagebox.showerror("Elevation Failed", str(exc), parent=self)

    @staticmethod
    def normalize_volume_root(path: Path) -> Path:
        """Move from a selected subfolder to the mounted-volume root when possible."""
        try:
            path = path.resolve()
        except OSError:
            path = Path(os.path.abspath(str(path)))
        upper_parts = [part.upper() for part in path.parts]
        if "WINDOWS" in upper_parts:
            idx = upper_parts.index("WINDOWS")
            root = Path(*path.parts[:idx])
            if os.name == "nt" and str(root).endswith(":"):
                root = Path(str(root) + "\\")
            return root
        if "USERS" in upper_parts:
            idx = upper_parts.index("USERS")
            root = Path(*path.parts[:idx])
            if os.name == "nt" and str(root).endswith(":"):
                root = Path(str(root) + "\\")
            return root
        if path.anchor and len(path.parts) > 1:
            anchor = Path(path.anchor)
            try:
                if (anchor / "Windows").exists() or (anchor / "WINDOWS").exists():
                    return anchor
            except OSError:
                pass
        return path

    @staticmethod
    def child_case_insensitive(parent: Path, name: str) -> Optional[Path]:
        direct = parent / name
        try:
            if direct.exists():
                return direct
            wanted = name.casefold()
            for child in parent.iterdir():
                if child.name.casefold() == wanted:
                    return child
        except OSError:
            return None
        return None

    def find_windows_roots(self, starting_root: Path, errors: list[str]) -> list[Path]:
        """Find Windows installation directories without assuming drive layout or case."""
        roots: list[Path] = []
        seen: set[str] = set()

        def add(candidate: Optional[Path]) -> None:
            if not candidate:
                return
            system32 = self.child_case_insensitive(candidate, "System32")
            config = self.child_case_insensitive(system32, "config") if system32 else None
            if not config or not config.is_dir():
                return
            key = os.path.normcase(os.path.abspath(str(candidate)))
            if key not in seen:
                seen.add(key)
                roots.append(candidate)

        # Standard root and common exported-partition wrappers.
        add(self.child_case_insensitive(starting_root, "Windows"))
        add(starting_root if starting_root.name.casefold() == "windows" else None)
        try:
            for child in starting_root.iterdir():
                if not child.is_dir():
                    continue
                add(self.child_case_insensitive(child, "Windows"))
        except OSError as exc:
            errors.append(f"{starting_root}: {exc}")

        # Broader search for Windows/System32/config, bounded by pruning obvious data trees.
        ignored = {"$RECYCLE.BIN", "SYSTEM VOLUME INFORMATION", "$EXTEND", "WINSXS", "WINDOWSAPPS"}
        def onerror(exc: OSError) -> None:
            errors.append(str(exc))
        try:
            for current, dirs, _files in os.walk(starting_root, topdown=True, followlinks=False, onerror=onerror):
                current_path = Path(current)
                rel_depth = max(0, len(current_path.parts) - len(starting_root.parts))
                dirs[:] = [d for d in dirs if d.upper() not in ignored]
                if current_path.name.casefold() == "windows":
                    add(current_path)
                    dirs[:] = [d for d in dirs if d.casefold() in {"system32", "appcompat"}]
                elif rel_depth >= 5:
                    dirs[:] = []
        except OSError as exc:
            errors.append(str(exc))
        return roots

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("White.TFrame", background=COLORS["white"])
        style.configure("Navy.TFrame", background=COLORS["navy"])
        style.configure("TLabel", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("White.TLabel", background=COLORS["white"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"])
        style.configure("Header.TLabel", background=COLORS["navy"], foreground=COLORS["white"], font=("Segoe UI Semibold", 20))
        style.configure("HeaderMeta.TLabel", background=COLORS["navy"], foreground="#bfd0dc")
        style.configure("Primary.TButton", background=COLORS["blue"], foreground=COLORS["white"], padding=(13, 8), borderwidth=0)
        style.map("Primary.TButton", background=[("active", "#0e78b7")])
        style.configure("Secondary.TButton", background=COLORS["slate"], foreground=COLORS["white"], padding=(12, 8), borderwidth=0)
        style.configure("Treeview", rowheight=26, background=COLORS["white"], fieldbackground=COLORS["white"])
        style.configure("Treeview.Heading", background=COLORS["slate"], foreground=COLORS["white"], font=("Segoe UI Semibold", 9))

    def _build_ui(self) -> None:
        header = ttk.Frame(self, style="Navy.TFrame", padding=(22, 15))
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="Header.TLabel").pack(side="left")
        ttk.Label(header, text=f"Case: {CASE_NAME}  {CASE_NUMBER}", style="HeaderMeta.TLabel").pack(side="right")

        source = ttk.Frame(self, style="White.TFrame", padding=12)
        source.pack(fill="x", padx=14, pady=(14, 8))
        ttk.Label(source, text="Evidence root:", style="White.TLabel").pack(side="left")
        ttk.Entry(source, textvariable=self.source_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(source, text="Browse…", command=self.choose_source).pack(side="left")
        ttk.Button(source, text="Discover Hives", style="Secondary.TButton", command=self.discover_hives).pack(side="left", padx=6)
        if os.name == "nt" and not self.is_administrator():
            ttk.Button(source, text="Restart as Administrator", command=self.restart_as_administrator).pack(side="left", padx=(0, 6))
        ttk.Button(source, text="Collect Artifacts", style="Primary.TButton", command=self.start_collection).pack(side="left")
        self.cancel_button = ttk.Button(source, text="Cancel", command=self.cancel_collection, state="disabled")
        self.cancel_button.pack(side="left", padx=(6, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=6)
        self.summary_tab = ttk.Frame(self.notebook, style="Panel.TFrame", padding=12)
        self.rules_tab = ttk.Frame(self.notebook, style="Panel.TFrame", padding=12)
        self.results_tab = ttk.Frame(self.notebook, style="Panel.TFrame", padding=12)
        self.notebook.add(self.summary_tab, text="Summary")
        self.notebook.add(self.rules_tab, text="Artifact Rules")
        self.notebook.add(self.results_tab, text="Results")
        self._build_summary_tab()
        self._build_rules_tab()
        self._build_results_tab()

        status = ttk.Frame(self, style="White.TFrame", padding=(12, 7))
        status.pack(fill="x", side="bottom")
        ttk.Label(status, textvariable=self.status_var, style="White.TLabel").pack(side="left")
        self.progress = ttk.Progressbar(status, variable=self.progress_var, maximum=100, length=260)
        self.progress.pack(side="right")

    def _build_summary_tab(self) -> None:
        top = ttk.Frame(self.summary_tab, style="Panel.TFrame")
        top.pack(fill="x")
        self.summary_labels = {}
        self.summary_vars = {}
        for idx, (key, title) in enumerate((("hives", "Hives Found"), ("artifacts", "Artifacts"), ("errors", "Errors"), ("users", "Users"))):
            card = tk.Frame(top, bg=COLORS["white"], highlightbackground=COLORS["border"], highlightthickness=1, padx=18, pady=12)
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 5, 5))
            value_var = tk.StringVar(value="0")
            value = tk.Label(card, textvariable=value_var, bg=COLORS["white"], fg=COLORS["navy"], font=("Segoe UI Semibold", 21))
            value.pack(anchor="w")
            tk.Label(card, text=title, bg=COLORS["white"], fg=COLORS["muted"]).pack(anchor="w")
            self.summary_labels[key] = value
            self.summary_vars[key] = value_var
            top.columnconfigure(idx, weight=1)
        panel = ttk.Frame(self.summary_tab, style="White.TFrame", padding=14)
        panel.pack(fill="both", expand=True, pady=(12, 0))
        ttk.Label(panel, text="Discovered Registry Hives", style="White.TLabel", font=("Segoe UI Semibold", 13)).pack(anchor="w")
        self.hive_tree = ttk.Treeview(panel, columns=("hive", "user", "path"), show="headings")
        for col, title, width in (("hive", "Hive", 130), ("user", "User", 160), ("path", "Path", 900)):
            self.hive_tree.heading(col, text=title)
            self.hive_tree.column(col, width=width, anchor="w")
        self.hive_tree.pack(fill="both", expand=True, pady=(8, 0))

    def _build_rules_tab(self) -> None:
        toolbar = ttk.Frame(self.rules_tab, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="Add", style="Primary.TButton", command=self.add_rule).pack(side="left")
        ttk.Button(toolbar, text="Edit", command=self.edit_rule).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Delete", command=self.delete_rule).pack(side="left")
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(toolbar, text="Enable All", command=lambda: self.set_all_rules(True)).pack(side="left")
        ttk.Button(toolbar, text="Disable All", command=lambda: self.set_all_rules(False)).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Restore Defaults", command=self.restore_rules).pack(side="left")
        ttk.Button(toolbar, text="Export Definitions CSV", command=self.export_definitions).pack(side="right")
        ttk.Button(toolbar, text="Import Definitions CSV", command=self.import_definitions).pack(side="right", padx=5)
        self.rule_tree = ttk.Treeview(self.rules_tab, columns=("enabled", "category", "hive", "path", "recursive"), show="headings", selectmode="browse")
        for col, title, width in (("enabled", "Enabled", 75), ("category", "Category", 190), ("hive", "Hive", 105), ("path", "Registry Key", 700), ("recursive", "Subkeys", 80)):
            self.rule_tree.heading(col, text=title)
            self.rule_tree.column(col, width=width, anchor="w")
        self.rule_tree.pack(fill="both", expand=True)
        self.rule_tree.bind("<Double-1>", self.toggle_rule)
        self.refresh_rule_tree()

    def _build_results_tab(self) -> None:
        toolbar = ttk.Frame(self.results_tab, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(toolbar, text="Filter:").pack(side="left")
        entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=45)
        entry.pack(side="left", padx=6)
        entry.bind("<Return>", lambda _e: self.load_results())
        ttk.Button(toolbar, text="Apply", command=self.load_results).pack(side="left")
        ttk.Button(toolbar, text="Clear", command=self.clear_filter).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Export CSV", style="Secondary.TButton", command=self.export_csv).pack(side="right")
        ttk.Button(toolbar, text="Refresh", command=self.load_results).pack(side="right", padx=5)
        columns = ("id", "category", "user", "hive", "key", "value", "data", "timestamp", "error")
        self.result_tree = ttk.Treeview(self.results_tab, columns=columns, show="headings", selectmode="browse")
        specs = (("id", "ID", 55), ("category", "Artifact", 155), ("user", "User", 125), ("hive", "Hive", 85), ("key", "Registry Key", 330), ("value", "Value", 145), ("data", "Data", 330), ("timestamp", "Key Last Write", 175), ("error", "Error", 180))
        for col, title, width in specs:
            self.result_tree.heading(col, text=title, command=lambda c=col: self.sort_tree(c, False))
            self.result_tree.column(col, width=width, anchor="w")
        ybar = ttk.Scrollbar(self.results_tab, orient="vertical", command=self.result_tree.yview)
        xbar = ttk.Scrollbar(self.results_tab, orient="horizontal", command=self.result_tree.xview)
        self.result_tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.result_tree.pack(fill="both", expand=True, side="left")
        ybar.pack(side="right", fill="y")
        xbar.pack(side="bottom", fill="x")

    def choose_source(self) -> None:
        selected = filedialog.askdirectory(parent=self, title="Choose evidence root")
        if selected:
            self.source_var.set(selected)

    def ensure_schema(self) -> None:
        if not CASE_DB:
            return
        try:
            with sqlite3.connect(CASE_DB) as con:
                con.executescript("""
                CREATE TABLE IF NOT EXISTS registry_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER,
                    category TEXT NOT NULL,
                    hive_name TEXT NOT NULL,
                    hive_path TEXT NOT NULL,
                    registry_key TEXT NOT NULL,
                    value_name TEXT,
                    value_type TEXT,
                    value_data TEXT,
                    decoded_data TEXT,
                    key_timestamp TEXT,
                    user_context TEXT,
                    collection_error TEXT,
                    collected_at TEXT NOT NULL,
                    source_tool TEXT NOT NULL DEFAULT 'Registry Artifacts Explorer'
                );
                CREATE INDEX IF NOT EXISTS idx_registry_category ON registry_artifacts(category);
                CREATE INDEX IF NOT EXISTS idx_registry_timestamp ON registry_artifacts(key_timestamp);
                CREATE INDEX IF NOT EXISTS idx_registry_user ON registry_artifacts(user_context);
                CREATE INDEX IF NOT EXISTS idx_registry_evidence ON registry_artifacts(evidence_id);
                CREATE TABLE IF NOT EXISTS registry_definitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, artifact_name TEXT NOT NULL,
                    hive TEXT NOT NULL, key_path TEXT NOT NULL, value_name TEXT, data_type TEXT, description TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1, recursive INTEGER NOT NULL DEFAULT 0,
                    display_order INTEGER NOT NULL DEFAULT 0, version TEXT NOT NULL DEFAULT '1.0', modified_utc TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_registry_definitions_enabled ON registry_definitions(enabled,display_order);
                """)
        except sqlite3.Error as exc:
            messagebox.showerror("Database Error", str(exc), parent=self)

    def audit(self, action: str, details: str) -> None:
        if not CASE_DB:
            return
        try:
            with sqlite3.connect(CASE_DB) as con:
                con.execute("""INSERT INTO audit_log(event_utc, examiner, action, object_type, object_id, details)
                               VALUES (?, ?, ?, 'plugin', 'registry_artifacts', ?)""", (utc_now(), EXAMINER, action, details))
        except sqlite3.Error:
            pass

    def cache_hive_locations(self, found: dict[str, list[Path]]) -> None:
        if not CASE_DB or not ENV_EVIDENCE_ID.isdigit():
            return
        try:
            with sqlite3.connect(CASE_DB) as con:
                con.execute("""CREATE TABLE IF NOT EXISTS hive_locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL,
                    hive_type TEXT NOT NULL,
                    profile_name TEXT,
                    file_path TEXT NOT NULL,
                    discovered_utc TEXT NOT NULL,
                    UNIQUE(evidence_id, hive_type, file_path)
                )""")
                evidence_id = int(ENV_EVIDENCE_ID)
                con.execute("DELETE FROM hive_locations WHERE evidence_id=?", (evidence_id,))
                for hive_type, paths in found.items():
                    for path in paths:
                        con.execute("""INSERT OR IGNORE INTO hive_locations
                            (evidence_id,hive_type,profile_name,file_path,discovered_utc)
                            VALUES(?,?,?,?,?)""",
                            (evidence_id, hive_type, user_context_for_hive(path), str(path), utc_now()))
        except sqlite3.Error as exc:
            self.status_var.set(f"Hive discovery completed, but cache update failed: {exc}")

    def discover_hives(self) -> None:
        """Discover hives using deterministic mounted-volume paths.

        Core hives are never found by an unrestricted full-volume walk. The
        selected evidence path is normalized to its volume root, Windows
        installations are detected, and each known hive path is probed directly.
        Only user profile directories are enumerated.
        """
        selected_text = self.source_var.get().strip()
        if not selected_text:
            messagebox.showwarning("Evidence Root", "Select mounted-volume evidence on the Evidence tab first.", parent=self)
            return
        selected = Path(os.path.expandvars(selected_text))
        try:
            available = selected.exists()
        except OSError:
            available = False
        if not available:
            messagebox.showwarning("Evidence Root", f"The mounted-volume path is unavailable:\n\n{selected}", parent=self)
            return

        volume_root = self.normalize_volume_root(selected)
        self.source_var.set(str(volume_root))
        self.status_var.set("Probing standard Registry hive locations…")
        self.update_idletasks()
        found = {name: [] for name in HIVE_NAMES}
        warnings: list[str] = []
        checked: list[str] = []
        seen: set[str] = set()

        def probe(path: Optional[Path], expected_name: Optional[str] = None) -> None:
            if path is None:
                return
            checked.append(str(path))
            try:
                if not path.is_file():
                    return
            except (OSError, PermissionError) as exc:
                warnings.append(f"{path}: {exc}")
                return
            hive_name = (expected_name or path.name).upper()
            if hive_name not in HIVE_NAMES:
                return
            identity = os.path.normcase(os.path.abspath(str(path)))
            if identity not in seen:
                seen.add(identity)
                found[hive_name].append(path)

        windows_roots = self.find_windows_roots(volume_root, warnings)
        # A normal mounted Windows partition should resolve here immediately.
        if not windows_roots:
            candidate = self.child_case_insensitive(volume_root, "Windows")
            if candidate:
                windows_roots = [candidate]

        config_dirs: list[Path] = []
        for windows_dir in windows_roots:
            system32 = self.child_case_insensitive(windows_dir, "System32")
            config_dir = self.child_case_insensitive(system32, "config") if system32 else None
            if config_dir:
                config_dirs.append(config_dir)
                for name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
                    probe(config_dir / name, name)
            probe(windows_dir / "AppCompat" / "Programs" / "Amcache.hve", "AMCACHE.HVE")

        # Enumerate only known profile roots, not the entire mounted drive.
        user_roots: list[Path] = []
        for base in [volume_root] + [w.parent for w in windows_roots]:
            users = self.child_case_insensitive(base, "Users")
            if users and users not in user_roots:
                user_roots.append(users)
        for users_dir in user_roots:
            try:
                with os.scandir(users_dir) as entries:
                    profiles = [Path(entry.path) for entry in entries if entry.is_dir(follow_symlinks=False)]
            except (OSError, PermissionError) as exc:
                warnings.append(f"{users_dir}: {exc}")
                continue
            for profile in profiles:
                probe(profile / "NTUSER.DAT", "NTUSER.DAT")
                probe(profile / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat", "USRCLASS.DAT")

        self.hives = found
        self.cache_hive_locations(found)
        self.refresh_hive_tree()
        self.notebook.select(self.summary_tab)
        self.update_idletasks()
        total = sum(len(paths) for paths in found.values())
        missing_core = [name for name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY") if not found[name]]
        privilege = "Administrator" if self.is_administrator() else "Standard user"
        if total:
            status = f"Found {total:,} hive(s); {len(windows_roots)} Windows installation(s); running as {privilege}"
            if missing_core:
                status += "; missing " + ", ".join(missing_core)
            if warnings:
                status += f"; {len(warnings)} access warning(s)"
            self.status_var.set(status)
        else:
            self.status_var.set(f"No Registry hives found; running as {privilege}")

        if missing_core:
            detail = (
                f"Mounted volume: {volume_root}\n"
                f"Privilege: {privilege}\n\n"
                "Config directories checked:\n" + ("\n".join(map(str, config_dirs)) or "None detected") +
                "\n\nCore hives missing: " + ", ".join(missing_core)
            )
            if not self.is_administrator() and os.name == "nt":
                detail += "\n\nWindows denied access to one or more paths. Use Restart as Administrator and try again."
            if warnings:
                detail += "\n\nFirst access warnings:\n" + "\n".join(warnings[:10])
            messagebox.showwarning("Core Registry Hives Missing", detail, parent=self)

        self.audit(
            "REGISTRY_HIVES_DISCOVERED",
            f"Selected={selected}; VolumeRoot={volume_root}; Privilege={privilege}; "
            f"WindowsRoots={len(windows_roots)}; Hives={total}; MissingCore={','.join(missing_core)}; "
            f"Checked={len(checked)}; AccessWarnings={len(warnings)}",
        )

    def refresh_hive_tree(self) -> None:
        """Refresh the hive grid and summary cards on the Tk main thread."""
        if threading.current_thread() is not threading.main_thread():
            self.after(0, self.refresh_hive_tree)
            return

        self.hive_tree.delete(*self.hive_tree.get_children())
        users = set()
        total = 0
        for hive_name, paths in sorted(self.hives.items()):
            for path in paths:
                user = user_context_for_hive(path)
                if user:
                    users.add(user)
                self.hive_tree.insert("", "end", values=(hive_name, user, str(path)))
                total += 1

        self.summary_vars["hives"].set(f"{total:,}")
        self.summary_vars["users"].set(f"{len(users):,}")
        self.hive_tree.update_idletasks()
        self.summary_tab.update_idletasks()
        self.update_idletasks()

        # Tk can defer painting while hive discovery is completing or while a
        # warning dialog is being prepared.  Re-apply the refresh when the
        # event queue is idle so the cards and grid are visibly updated.
        self.after_idle(self._repaint_hive_summary)

    def _repaint_hive_summary(self) -> None:
        users = {
            user_context_for_hive(path)
            for paths in self.hives.values()
            for path in paths
            if user_context_for_hive(path)
        }
        total = sum(len(paths) for paths in self.hives.values())
        self.summary_vars["hives"].set(f"{total:,}")
        self.summary_vars["users"].set(f"{len(users):,}")
        self.hive_tree.update_idletasks()
        self.summary_tab.update_idletasks()

    def seed_default_rules(self, con) -> None:
        count=con.execute("SELECT COUNT(*) FROM registry_definitions").fetchone()[0]
        if count:return
        for order,(category,hive,key_path,recursive) in enumerate(DEFAULT_RULES,1):
            con.execute("INSERT INTO registry_definitions(category,artifact_name,hive,key_path,value_name,data_type,description,enabled,recursive,display_order,version,modified_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(category,category,hive,key_path,"","","Built-in Fraud Fighter definition",1,1 if recursive else 0,order,"1.0",utc_now()))

    def load_rules_from_database(self) -> None:
        if not CASE_DB:
            self.rules=[Rule(True,*v,artifact_name=v[0]) for v in DEFAULT_RULES]; return
        with sqlite3.connect(CASE_DB) as con:
            self.seed_default_rules(con)
            rows=con.execute("SELECT id,enabled,category,artifact_name,hive,key_path,COALESCE(value_name,''),COALESCE(description,''),recursive FROM registry_definitions ORDER BY display_order,id").fetchall()
        self.rules=[Rule(bool(r[1]),r[2],r[4],r[5],bool(r[8]),r[0],r[3],r[6],r[7]) for r in rows]
        if hasattr(self,'rule_tree'):self.refresh_rule_tree()

    def refresh_rule_tree(self) -> None:
        self.rule_tree.delete(*self.rule_tree.get_children())
        for index,rule in enumerate(self.rules):
            self.rule_tree.insert("","end",iid=str(index),values=("Yes" if rule.enabled else "No",rule.artifact_name or rule.category,rule.hive,rule.key_path,"Yes" if rule.recursive else "No"))

    def selected_rule(self):
        sel=self.rule_tree.selection(); return (int(sel[0]),self.rules[int(sel[0])]) if sel else (None,None)

    def persist_rule_enabled(self,rule):
        if CASE_DB and rule.definition_id:
            with sqlite3.connect(CASE_DB) as con:con.execute("UPDATE registry_definitions SET enabled=?,modified_utc=? WHERE id=?",(1 if rule.enabled else 0,utc_now(),rule.definition_id))

    def toggle_rule(self,_event=None) -> None:
        _,rule=self.selected_rule()
        if not rule:return
        rule.enabled=not rule.enabled; self.persist_rule_enabled(rule); self.refresh_rule_tree()

    def set_all_rules(self,enabled:bool) -> None:
        for rule in self.rules:rule.enabled=enabled
        if CASE_DB:
            with sqlite3.connect(CASE_DB) as con:con.execute("UPDATE registry_definitions SET enabled=?,modified_utc=?",(1 if enabled else 0,utc_now()))
        self.refresh_rule_tree()

    def rule_dialog(self,rule=None):
        win=tk.Toplevel(self); win.title("Edit Registry Definition" if rule else "Add Registry Definition"); win.transient(self); win.grab_set(); win.geometry("700x540")
        f=ttk.Frame(win,padding=18); f.pack(fill='both',expand=True); vars={}
        specs=[('artifact_name','Artifact name'),('category','Category'),('hive','Hive'),('key_path','Registry key path'),('value_name','Value name (optional)'),('description','Description'),('version','Version')]
        current={'artifact_name':getattr(rule,'artifact_name',''),'category':getattr(rule,'category',''),'hive':getattr(rule,'hive',''),'key_path':getattr(rule,'key_path',''),'value_name':getattr(rule,'value_name',''),'description':getattr(rule,'description',''),'version':'1.0'}
        for i,(key,label) in enumerate(specs):
            ttk.Label(f,text=label).grid(row=i,column=0,sticky='w',pady=5); v=tk.StringVar(value=current[key]); ttk.Entry(f,textvariable=v).grid(row=i,column=1,sticky='ew',pady=5); vars[key]=v
        enabled=tk.BooleanVar(value=getattr(rule,'enabled',True)); recursive=tk.BooleanVar(value=getattr(rule,'recursive',False)); ttk.Checkbutton(f,text='Enabled',variable=enabled).grid(row=7,column=1,sticky='w'); ttk.Checkbutton(f,text='Include subkeys recursively',variable=recursive).grid(row=8,column=1,sticky='w'); f.columnconfigure(1,weight=1)
        def save():
            if not vars['artifact_name'].get().strip() or not vars['hive'].get().strip() or not vars['key_path'].get().strip():messagebox.showwarning('Required Fields','Artifact name, hive, and key path are required.',parent=win);return
            with sqlite3.connect(CASE_DB) as con:
                vals=(vars['category'].get().strip() or vars['artifact_name'].get().strip(),vars['artifact_name'].get().strip(),vars['hive'].get().strip().upper(),vars['key_path'].get().strip(),vars['value_name'].get().strip(),'',vars['description'].get().strip(),1 if enabled.get() else 0,1 if recursive.get() else 0,vars['version'].get().strip() or '1.0',utc_now())
                if rule and rule.definition_id:con.execute("UPDATE registry_definitions SET category=?,artifact_name=?,hive=?,key_path=?,value_name=?,data_type=?,description=?,enabled=?,recursive=?,version=?,modified_utc=? WHERE id=?",vals+(rule.definition_id,))
                else:con.execute("INSERT INTO registry_definitions(category,artifact_name,hive,key_path,value_name,data_type,description,enabled,recursive,version,modified_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?)",vals)
            win.destroy(); self.load_rules_from_database(); self.audit('REGISTRY_DEFINITION_SAVED',vars['artifact_name'].get().strip())
        ttk.Button(f,text='Save',style='Primary.TButton',command=save).grid(row=9,column=1,sticky='e',pady=14)

    def add_rule(self):self.rule_dialog()
    def edit_rule(self):
        _,rule=self.selected_rule()
        if rule:self.rule_dialog(rule)
    def delete_rule(self):
        _,rule=self.selected_rule()
        if not rule:return
        if not messagebox.askyesno('Delete Definition',f'Delete {rule.artifact_name or rule.category}?',parent=self):return
        with sqlite3.connect(CASE_DB) as con:con.execute('DELETE FROM registry_definitions WHERE id=?',(rule.definition_id,))
        self.load_rules_from_database(); self.audit('REGISTRY_DEFINITION_DELETED',rule.artifact_name or rule.category)

    def restore_rules(self) -> None:
        if not CASE_DB:return
        if not messagebox.askyesno('Restore Defaults','Replace all registry definitions with the built-in defaults?',parent=self):return
        with sqlite3.connect(CASE_DB) as con:con.execute('DELETE FROM registry_definitions');self.seed_default_rules(con)
        self.load_rules_from_database(); self.audit('REGISTRY_DEFINITIONS_RESTORED','Built-in defaults restored')

    def export_definitions(self):
        if not CASE_DB:return
        path=filedialog.asksaveasfilename(parent=self,defaultextension='.csv',initialfile='registry_definitions.csv',filetypes=[('CSV','*.csv')])
        if not path:return
        with sqlite3.connect(CASE_DB) as con:rows=con.execute("SELECT category,artifact_name,hive,key_path,value_name,data_type,description,enabled,recursive,display_order,version FROM registry_definitions ORDER BY display_order,id").fetchall()
        with open(path,'w',newline='',encoding='utf-8-sig') as fh:w=csv.writer(fh);w.writerow(['Category','ArtifactName','Hive','KeyPath','ValueName','DataType','Description','Enabled','Recursive','DisplayOrder','Version']);w.writerows(rows)
        self.audit('REGISTRY_DEFINITIONS_EXPORTED',path)

    def import_definitions(self):
        if not CASE_DB:return
        path=filedialog.askopenfilename(parent=self,filetypes=[('CSV','*.csv'),('All files','*.*')])
        if not path:return
        with open(path,'r',newline='',encoding='utf-8-sig') as fh:rows=list(csv.DictReader(fh))
        added=updated=0
        with sqlite3.connect(CASE_DB) as con:
            for i,r in enumerate(rows,1):
                get=lambda *names: next((r.get(n) for n in names if r.get(n) is not None),'')
                name=get('ArtifactName','artifact_name').strip(); hive=get('Hive','hive').strip().upper(); key=get('KeyPath','key_path').strip()
                if not name or not hive or not key:continue
                existing=con.execute("SELECT id FROM registry_definitions WHERE artifact_name=? AND hive=? AND key_path=? AND COALESCE(value_name,'')=?",(name,hive,key,get('ValueName','value_name').strip())).fetchone()
                vals=(get('Category','category').strip() or name,name,hive,key,get('ValueName','value_name').strip(),get('DataType','data_type').strip(),get('Description','description').strip(),0 if get('Enabled','enabled').strip().lower() in ('0','false','no') else 1,1 if get('Recursive','recursive').strip().lower() in ('1','true','yes') else 0,int(get('DisplayOrder','display_order') or i),get('Version','version').strip() or '1.0',utc_now())
                if existing:con.execute("UPDATE registry_definitions SET category=?,artifact_name=?,hive=?,key_path=?,value_name=?,data_type=?,description=?,enabled=?,recursive=?,display_order=?,version=?,modified_utc=? WHERE id=?",vals+(existing[0],));updated+=1
                else:con.execute("INSERT INTO registry_definitions(category,artifact_name,hive,key_path,value_name,data_type,description,enabled,recursive,display_order,version,modified_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",vals);added+=1
        self.load_rules_from_database();self.audit('REGISTRY_DEFINITIONS_IMPORTED',f'{path}; added={added}; updated={updated}');messagebox.showinfo('Import Complete',f'Added: {added}\nUpdated: {updated}',parent=self)

    def start_collection(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        try:
            from Registry import Registry  # noqa: F401
        except ImportError:
            messagebox.showerror("Missing Dependency", "Install python-registry with:\n\npy -m pip install python-registry\n\nThen restart the plugin.", parent=self)
            return
        if not self.hives:
            self.discover_hives()
        if not self.hives:
            return
        enabled = [rule for rule in self.rules if rule.enabled]
        if not enabled:
            messagebox.showinfo("No Rules", "Enable at least one artifact rule.", parent=self)
            return
        self.cancel_event.clear()
        self.cancel_button.configure(state="normal")
        self.progress_var.set(0)
        self.worker = threading.Thread(target=self.collect_worker, args=(enabled,), daemon=True)
        self.worker.start()

    def cancel_collection(self) -> None:
        self.cancel_event.set()
        self.status_var.set("Cancellation requested…")
        self.cancel_button.configure(state="disabled")

    def iter_keys(self, key, recursive: bool) -> Iterable:
        yield key
        if not recursive:
            return
        try:
            stack = list(key.subkeys())
        except Exception:
            stack = []
        while stack and not self.cancel_event.is_set():
            current = stack.pop()
            yield current
            try:
                stack.extend(current.subkeys())
            except Exception:
                pass

    def decoded_value(self, category: str, value_name: str, value_data: str) -> str:
        if category == "UserAssist" and value_name:
            return rot13(value_name)
        return ""

    def collect_worker(self, rules: list[Rule]) -> None:
        from Registry import Registry
        count = errors = 0
        jobs = [(rule, path) for rule in rules for path in self.hives.get(rule.hive.upper(), [])]
        missing = [rule for rule in rules if not self.hives.get(rule.hive.upper())]
        total_jobs = max(1, len(jobs) + len(missing))
        processed_jobs = 0
        db_path = CASE_DB or Path(tempfile.gettempdir()) / "fft_registry_standalone.sqlite"
        try:
            self.ensure_schema_at(db_path)
            with sqlite3.connect(db_path) as con:
                evidence_id = int(ENV_EVIDENCE_ID) if ENV_EVIDENCE_ID.isdigit() else None
                for rule in missing:
                    if self.cancel_event.is_set(): break
                    row = (evidence_id, rule.category, rule.hive, "", rule.key_path, "", "", "", "", "", "", f"Hive {rule.hive} was not found", utc_now())
                    self.insert_row(con, row); errors += 1; processed_jobs += 1
                    self.post_progress(processed_jobs, total_jobs, count, errors, f"Missing {rule.hive}")
                for rule, hive_path in jobs:
                    if self.cancel_event.is_set(): break
                    temp_dir = Path(tempfile.mkdtemp(prefix="fft_registry_"))
                    staged = temp_dir / hive_path.name
                    try:
                        shutil.copy2(hive_path, staged)
                        registry = Registry.Registry(str(staged))
                        key = registry.open(rule.key_path)
                        user = user_context_for_hive(hive_path)
                        for current_key in self.iter_keys(key, rule.recursive):
                            if self.cancel_event.is_set(): break
                            try:
                                timestamp = current_key.timestamp().astimezone(timezone.utc).isoformat() if current_key.timestamp() else ""
                            except Exception:
                                timestamp = ""
                            try:
                                values = list(current_key.values())
                            except Exception:
                                values = []
                            if not values:
                                values = [None]
                            for value in values:
                                if value is not None and rule.value_name:
                                    try:
                                        candidate_name = value.name() or "(Default)"
                                    except Exception:
                                        candidate_name = ""
                                    if candidate_name.lower() != rule.value_name.lower():
                                        continue
                                if value is None:
                                    name = vtype = data = ""
                                else:
                                    try: name = value.name() or "(Default)"
                                    except Exception: name = ""
                                    try: vtype = value.value_type_str()
                                    except Exception: vtype = ""
                                    try: data = safe_text(value.value())
                                    except Exception as exc: data = f"<decode error: {exc}>"
                                decoded = self.decoded_value(rule.category, name, data)
                                row = (evidence_id, rule.category, rule.hive, str(hive_path), current_key.path(), name, vtype, data, decoded, timestamp, user, "", utc_now())
                                self.insert_row(con, row); count += 1
                                if count % 250 == 0: con.commit()
                    except Exception as exc:
                        row = (evidence_id, rule.category, rule.hive, str(hive_path), rule.key_path, "", "", "", "", "", user_context_for_hive(hive_path), f"{type(exc).__name__}: {exc}", utc_now())
                        self.insert_row(con, row); errors += 1
                    finally:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    processed_jobs += 1
                    con.commit()
                    self.post_progress(processed_jobs, total_jobs, count, errors, f"{rule.category}: {hive_path.name}")
            cancelled = self.cancel_event.is_set()
            self.after(0, lambda: self.collection_finished(count, errors, cancelled, db_path))
        except Exception:
            error = traceback.format_exc()
            self.after(0, lambda: messagebox.showerror("Collection Failed", error, parent=self))
            self.after(0, lambda: self.cancel_button.configure(state="disabled"))

    def ensure_schema_at(self, db_path: Path) -> None:
        with sqlite3.connect(db_path) as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS registry_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER,
                category TEXT NOT NULL, hive_name TEXT NOT NULL, hive_path TEXT NOT NULL,
                registry_key TEXT NOT NULL, value_name TEXT, value_type TEXT,
                value_data TEXT, decoded_data TEXT, key_timestamp TEXT,
                user_context TEXT, collection_error TEXT, collected_at TEXT NOT NULL,
                source_tool TEXT NOT NULL DEFAULT 'Registry Artifacts Explorer');
            """)

    def insert_row(self, con: sqlite3.Connection, row: tuple) -> None:
        con.execute("""INSERT INTO registry_artifacts(
            evidence_id, category, hive_name, hive_path, registry_key, value_name,
            value_type, value_data, decoded_data, key_timestamp, user_context,
            collection_error, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", row)

    def post_progress(self, done: int, total: int, count: int, errors: int, text: str) -> None:
        percent = min(100.0, done / total * 100)
        self.after(0, lambda: self.progress_var.set(percent))
        self.after(0, lambda: self.status_var.set(f"{text} — {count:,} artifacts, {errors:,} errors"))

    def collection_finished(self, count: int, errors: int, cancelled: bool, db_path: Path) -> None:
        self.cancel_button.configure(state="disabled")
        self.progress_var.set(100 if not cancelled else self.progress_var.get())
        self.status_var.set(f"{'Cancelled' if cancelled else 'Completed'}: {count:,} artifacts, {errors:,} errors")
        self.audit("REGISTRY_COLLECTION_COMPLETED", f"Artifacts={count}; Errors={errors}; Cancelled={cancelled}")
        self.load_results()
        self.notebook.select(self.results_tab)
        messagebox.showinfo("Registry Collection", f"Status: {'Cancelled' if cancelled else 'Complete'}\nArtifacts: {count:,}\nErrors: {errors:,}\nDatabase: {db_path}", parent=self)

    def clear_filter(self) -> None:
        self.filter_var.set("")
        self.load_results()

    def result_database(self) -> Optional[Path]:
        if CASE_DB and CASE_DB.exists():
            return CASE_DB
        candidate = Path(tempfile.gettempdir()) / "fft_registry_standalone.sqlite"
        return candidate if candidate.exists() else None

    def load_results(self) -> None:
        db = self.result_database()
        if not hasattr(self, "result_tree") or not db:
            return
        query = self.filter_var.get().strip()
        sql = """SELECT id, category, user_context, hive_name, registry_key,
                        value_name, COALESCE(NULLIF(decoded_data,''), value_data),
                        key_timestamp, collection_error
                 FROM registry_artifacts"""
        params = []
        if query:
            sql += " WHERE category LIKE ? OR user_context LIKE ? OR hive_name LIKE ? OR registry_key LIKE ? OR value_name LIKE ? OR value_data LIKE ? OR decoded_data LIKE ? OR collection_error LIKE ?"
            token = f"%{query}%"; params = [token] * 8
        sql += " ORDER BY id DESC LIMIT 50000"
        try:
            with sqlite3.connect(db) as con:
                rows = con.execute(sql, params).fetchall()
                total = con.execute("SELECT COUNT(*) FROM registry_artifacts").fetchone()[0]
                errors = con.execute("SELECT COUNT(*) FROM registry_artifacts WHERE collection_error <> ''").fetchone()[0]
            self.result_tree.delete(*self.result_tree.get_children())
            users = set()
            for row in rows:
                if row[2]: users.add(row[2])
                shown = list(row)
                shown[6] = (shown[6] or "")[:1000]
                self.result_tree.insert("", "end", values=shown)
            self.summary_vars["artifacts"].set(f"{total:,}")
            self.summary_vars["errors"].set(f"{errors:,}")
            # Do not overwrite the discovered-hive user count with the users
            # represented in filtered/legacy result rows.
            self.update_idletasks()
            self.status_var.set(f"Showing {len(rows):,} of {total:,} Registry artifact records")
        except sqlite3.Error:
            pass

    def export_csv(self) -> None:
        db = self.result_database()
        if not db:
            messagebox.showinfo("No Results", "No Registry artifact results are available.", parent=self)
            return
        default_dir = CASE_FOLDER / "Exports" if CASE_FOLDER else Path.home()
        default_dir.mkdir(parents=True, exist_ok=True)
        selected = filedialog.asksaveasfilename(parent=self, initialdir=default_dir, initialfile="registry_artifacts.csv", defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not selected: return
        with sqlite3.connect(db) as con:
            cursor = con.execute("SELECT * FROM registry_artifacts ORDER BY id")
            headers = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        with open(selected, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh); writer.writerow(headers); writer.writerows(rows)
        self.audit("REGISTRY_RESULTS_EXPORTED", selected)
        messagebox.showinfo("Export Complete", f"Exported {len(rows):,} rows to:\n{selected}", parent=self)

    def sort_tree(self, column: str, reverse: bool) -> None:
        data = [(self.result_tree.set(item, column), item) for item in self.result_tree.get_children("")]
        def key(pair):
            value = pair[0]
            try: return (0, float(value))
            except (ValueError, TypeError): return (1, str(value).lower())
        data.sort(key=key, reverse=reverse)
        for index, (_, item) in enumerate(data): self.result_tree.move(item, "", index)
        self.result_tree.heading(column, command=lambda: self.sort_tree(column, not reverse))


def main() -> None:
    app = RegistryArtifactsApp()
    app.mainloop()


if __name__ == "__main__":
    main()
