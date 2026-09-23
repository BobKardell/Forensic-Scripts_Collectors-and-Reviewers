#!/usr/bin/env python3
# FFT_TOOL
# TITLE: Registry Explorer
# ID: registry_explorer
# CATEGORY: Analysis Tools
# VERSION: 1.0.0
# DESCRIPTION: Browse, search, bookmark, and export offline Windows Registry hives.
# ICON: REG
# PASS_CASE_ARGUMENTS: false

from __future__ import annotations

import csv
import json
import os
import queue
import sqlite3
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Any, Optional

APP_NAME = "Registry Explorer"
APP_VERSION = "1.0.0"

CASE_DB = Path(os.environ["FFT_CASE_DB"]) if os.environ.get("FFT_CASE_DB") else None
EVIDENCE_ID = os.environ.get("FFT_EVIDENCE_ID", "")
EVIDENCE_ROOT = os.environ.get("FFT_EVIDENCE_ROOT", "")

COLORS = {
    "navy": "#061522", "navy2": "#0c2235", "blue": "#188bd0",
    "panel": "#f2f6f9", "white": "#ffffff", "text": "#172431",
    "muted": "#607180", "border": "#c8d5df", "green": "#367d4a",
    "red": "#a33b3b", "header": "#587795",
}

HIVE_NAMES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT", "AMCACHE.HVE"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        preview = value[:512].hex(" ")
        return preview + (" ..." if len(value) > 512 else "")
    if isinstance(value, (list, tuple)):
        return " | ".join(safe_text(item) for item in value)
    return str(value)


def user_from_hive_path(path: Path) -> str:
    parts = list(path.parts)
    upper = [p.upper() for p in parts]
    if path.name.upper() == "NTUSER.DAT":
        return path.parent.name
    if path.name.upper() == "USRCLASS.DAT":
        try:
            idx = upper.index("APPDATA")
            return parts[idx - 1] if idx > 0 else ""
        except (ValueError, IndexError):
            return ""
    return "System"


class RegistryExplorerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1500x900")
        self.minsize(1100, 700)
        self.configure(bg=COLORS["panel"])

        self.Registry = None
        self.open_hives: dict[str, Any] = {}
        self.hive_paths: dict[str, Path] = {}
        self.node_keys: dict[str, tuple[str, str]] = {}
        self.search_results: list[dict[str, str]] = []
        self.cancel_search = threading.Event()
        self.ui_queue: queue.Queue = queue.Queue()

        self.status_var = tk.StringVar(value="Ready")
        self.search_var = tk.StringVar()
        self.search_names_var = tk.BooleanVar(value=True)
        self.search_values_var = tk.BooleanVar(value=True)
        self.search_data_var = tk.BooleanVar(value=True)
        self.case_only_var = tk.BooleanVar(value=True)

        self._configure_styles()
        self._build_ui()
        self.ensure_schema()
        self.after(100, self._process_ui_queue)
        self.after(250, self.auto_discover)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=25, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=COLORS["header"], foreground="white", font=("Segoe UI", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", COLORS["header"])])
        style.configure("TNotebook.Tab", padding=(12, 6), font=("Segoe UI", 9))
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=COLORS["navy"], height=78)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="▦", bg=COLORS["navy"], fg="#7cc8f4", font=("Segoe UI Symbol", 28, "bold")).pack(side="left", padx=(20, 10))
        tk.Label(header, text=APP_NAME, bg=COLORS["navy"], fg="white", font=("Segoe UI", 22, "bold")).pack(side="left", pady=17)
        tk.Label(header, text=f"v{APP_VERSION}", bg=COLORS["navy"], fg="#a9c7dc", font=("Segoe UI", 10)).pack(side="left", padx=12, pady=(30, 0))

        toolbar = tk.Frame(self, bg=COLORS["white"], highlightbackground=COLORS["border"], highlightthickness=1)
        toolbar.pack(fill="x", padx=8, pady=8)
        ttk.Button(toolbar, text="Discover Hives", command=self.auto_discover, style="Accent.TButton").pack(side="left", padx=6, pady=7)
        ttk.Button(toolbar, text="Open Hive", command=self.open_hive_dialog).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Close Hive", command=self.close_selected_hive).pack(side="left", padx=4)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8, pady=5)
        ttk.Button(toolbar, text="Bookmark", command=self.bookmark_selected).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Export Values", command=self.export_current_values).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_selected).pack(side="left", padx=4)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 5))
        self.browser_tab = ttk.Frame(self.notebook)
        self.search_tab = ttk.Frame(self.notebook)
        self.bookmark_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.browser_tab, text="Registry Browser")
        self.notebook.add(self.search_tab, text="Search")
        self.notebook.add(self.bookmark_tab, text="Bookmarks")

        self._build_browser_tab()
        self._build_search_tab()
        self._build_bookmark_tab()

        status = tk.Frame(self, bg=COLORS["navy2"], height=28)
        status.pack(fill="x")
        status.pack_propagate(False)
        tk.Label(status, textvariable=self.status_var, bg=COLORS["navy2"], fg="white", anchor="w", font=("Segoe UI", 9)).pack(fill="x", padx=10, pady=4)

    def _build_browser_tab(self) -> None:
        paned = ttk.Panedwindow(self.browser_tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=5, pady=5)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=2)
        paned.add(right, weight=3)

        tk.Label(left, text="Registry Hives and Keys", bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=4, pady=(2, 5))
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill="both", expand=True)
        self.key_tree = ttk.Treeview(tree_frame, columns=("modified",), show="tree headings")
        self.key_tree.heading("#0", text="Hive / Key")
        self.key_tree.heading("modified", text="Last Write (UTC)")
        self.key_tree.column("#0", width=390, minwidth=180)
        self.key_tree.column("modified", width=175, minwidth=130)
        ysb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.key_tree.yview)
        xsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.key_tree.xview)
        self.key_tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.key_tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.key_tree.bind("<<TreeviewOpen>>", self.on_tree_open)
        self.key_tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        key_info = tk.Frame(right, bg=COLORS["white"], highlightbackground=COLORS["border"], highlightthickness=1)
        key_info.pack(fill="x", padx=2, pady=(0, 5))
        self.path_label = tk.Label(key_info, text="No key selected", bg=COLORS["white"], fg=COLORS["text"], anchor="w", justify="left", font=("Segoe UI", 10, "bold"), wraplength=800)
        self.path_label.pack(fill="x", padx=10, pady=(8, 2))
        self.time_label = tk.Label(key_info, text="", bg=COLORS["white"], fg=COLORS["muted"], anchor="w", font=("Segoe UI", 9))
        self.time_label.pack(fill="x", padx=10, pady=(0, 8))

        values_frame = ttk.Frame(right)
        values_frame.pack(fill="both", expand=True)
        self.value_tree = ttk.Treeview(values_frame, columns=("name", "type", "data"), show="headings")
        for col, title, width in (("name", "Value Name", 220), ("type", "Type", 125), ("data", "Data", 620)):
            self.value_tree.heading(col, text=title)
            self.value_tree.column(col, width=width, minwidth=80)
        vysb = ttk.Scrollbar(values_frame, orient="vertical", command=self.value_tree.yview)
        vxsb = ttk.Scrollbar(values_frame, orient="horizontal", command=self.value_tree.xview)
        self.value_tree.configure(yscrollcommand=vysb.set, xscrollcommand=vxsb.set)
        self.value_tree.grid(row=0, column=0, sticky="nsew")
        vysb.grid(row=0, column=1, sticky="ns")
        vxsb.grid(row=1, column=0, sticky="ew")
        values_frame.rowconfigure(0, weight=1)
        values_frame.columnconfigure(0, weight=1)
        self.value_tree.bind("<<TreeviewSelect>>", self.show_value_detail)

        detail_frame = tk.LabelFrame(right, text="Selected Value Details", bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9, "bold"))
        detail_frame.pack(fill="x", padx=2, pady=(5, 0))
        self.value_detail = tk.Text(detail_frame, height=8, wrap="word", font=("Consolas", 9), bg="white", fg=COLORS["text"])
        self.value_detail.pack(fill="both", expand=True, padx=5, pady=5)

    def _build_search_tab(self) -> None:
        top = tk.Frame(self.search_tab, bg=COLORS["panel"])
        top.pack(fill="x", padx=8, pady=8)
        tk.Label(top, text="Search:", bg=COLORS["panel"], font=("Segoe UI", 9, "bold")).pack(side="left")
        entry = ttk.Entry(top, textvariable=self.search_var, width=55)
        entry.pack(side="left", padx=6)
        entry.bind("<Return>", lambda _e: self.start_search())
        ttk.Checkbutton(top, text="Key/value names", variable=self.search_names_var).pack(side="left", padx=5)
        ttk.Checkbutton(top, text="Value data", variable=self.search_data_var).pack(side="left", padx=5)
        ttk.Button(top, text="Search All Open Hives", command=self.start_search, style="Accent.TButton").pack(side="left", padx=6)
        ttk.Button(top, text="Stop", command=self.cancel_search.set).pack(side="left", padx=3)
        ttk.Button(top, text="Export", command=self.export_search_results).pack(side="left", padx=3)

        frame = ttk.Frame(self.search_tab)
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        cols = ("hive", "user", "key", "value", "type", "data", "modified")
        self.search_tree = ttk.Treeview(frame, columns=cols, show="headings")
        widths = {"hive": 110, "user": 100, "key": 380, "value": 170, "type": 100, "data": 360, "modified": 165}
        for col in cols:
            self.search_tree.heading(col, text=col.replace("_", " ").title())
            self.search_tree.column(col, width=widths[col], minwidth=70)
        ysb = ttk.Scrollbar(frame, orient="vertical", command=self.search_tree.yview)
        xsb = ttk.Scrollbar(frame, orient="horizontal", command=self.search_tree.xview)
        self.search_tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.search_tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.search_tree.bind("<Double-1>", self.navigate_search_result)

    def _build_bookmark_tab(self) -> None:
        top = ttk.Frame(self.bookmark_tab)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Button(top, text="Refresh", command=self.load_bookmarks).pack(side="left")
        ttk.Button(top, text="Delete Selected", command=self.delete_bookmark).pack(side="left", padx=5)
        ttk.Button(top, text="Export CSV", command=self.export_bookmarks).pack(side="left")

        frame = ttk.Frame(self.bookmark_tab)
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        cols = ("id", "hive", "user", "key", "value", "data", "notes", "created")
        self.bookmark_tree = ttk.Treeview(frame, columns=cols, show="headings")
        widths = {"id": 55, "hive": 105, "user": 90, "key": 370, "value": 150, "data": 280, "notes": 250, "created": 165}
        for col in cols:
            self.bookmark_tree.heading(col, text=col.title())
            self.bookmark_tree.column(col, width=widths[col], minwidth=50)
        ysb = ttk.Scrollbar(frame, orient="vertical", command=self.bookmark_tree.yview)
        xsb = ttk.Scrollbar(frame, orient="horizontal", command=self.bookmark_tree.xview)
        self.bookmark_tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.bookmark_tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.load_bookmarks()

    def ensure_dependency(self) -> bool:
        if self.Registry is not None:
            return True
        try:
            from Registry import Registry
            self.Registry = Registry
            return True
        except ImportError:
            messagebox.showerror(
                "Missing Dependency",
                "Registry Explorer requires the python-registry package.\n\n"
                "Install it with:\n\npython -m pip install python-registry\n\n"
                "An install_dependency.bat file is included with the plugin package."
            )
            return False

    def ensure_schema(self) -> None:
        if not CASE_DB:
            return
        try:
            CASE_DB.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(CASE_DB) as con:
                con.execute("""
                    CREATE TABLE IF NOT EXISTS registry_explorer_bookmarks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        evidence_id INTEGER,
                        hive_name TEXT,
                        hive_path TEXT,
                        user_name TEXT,
                        key_path TEXT,
                        value_name TEXT,
                        value_type TEXT,
                        value_data TEXT,
                        key_last_write_utc TEXT,
                        notes TEXT,
                        created_utc TEXT NOT NULL
                    )
                """)
                con.execute("""
                    CREATE TABLE IF NOT EXISTS registry_explorer_hives (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        evidence_id INTEGER,
                        hive_name TEXT,
                        hive_path TEXT,
                        user_name TEXT,
                        opened_utc TEXT,
                        UNIQUE(evidence_id, hive_path)
                    )
                """)
                con.commit()
        except Exception:
            self.status_var.set("Database initialization failed; see console.")
            traceback.print_exc()

    def resolve_evidence_root(self) -> Optional[Path]:
        candidates: list[str] = []
        if CASE_DB and CASE_DB.exists() and EVIDENCE_ID.isdigit():
            try:
                with sqlite3.connect(CASE_DB) as con:
                    table = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND lower(name)='evidence'").fetchone()
                    if table:
                        cols = {r[1].lower(): r[1] for r in con.execute(f'PRAGMA table_info("{table[0]}")')}
                        id_col = next((cols[x] for x in ("id", "evidence_id", "evidenceid") if x in cols), None)
                        path_cols = [cols[x] for x in ("mounted_volume", "evidence_root", "root_path", "mounted_path", "mount_path") if x in cols]
                        if id_col and path_cols:
                            row = con.execute(
                                f'SELECT {", ".join(chr(34)+c+chr(34) for c in path_cols)} FROM "{table[0]}" WHERE "{id_col}"=?',
                                (int(EVIDENCE_ID),)
                            ).fetchone()
                            if row:
                                candidates.extend(str(v) for v in row if v)
            except Exception:
                traceback.print_exc()
        if EVIDENCE_ROOT:
            candidates.append(EVIDENCE_ROOT)
        for value in candidates:
            p = Path(value)
            if p.exists():
                return p
        return None

    def auto_discover(self) -> None:
        if not self.ensure_dependency():
            return
        root = self.resolve_evidence_root()
        if not root:
            if not self.open_hives:
                self.status_var.set("No mounted evidence root found. Use Open Hive to select a registry hive.")
            return
        self.status_var.set(f"Discovering registry hives under {root} ...")
        self.update_idletasks()
        found: list[Path] = []
        config = root / "Windows" / "System32" / "config"
        for name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
            p = config / name
            if p.is_file():
                found.append(p)
        amcache = root / "Windows" / "AppCompat" / "Programs" / "Amcache.hve"
        if amcache.is_file():
            found.append(amcache)
        users = root / "Users"
        if users.is_dir():
            try:
                for user_dir in users.iterdir():
                    if not user_dir.is_dir():
                        continue
                    ntuser = user_dir / "NTUSER.DAT"
                    usrclass = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
                    if ntuser.is_file():
                        found.append(ntuser)
                    if usrclass.is_file():
                        found.append(usrclass)
            except OSError:
                pass
        opened = 0
        for path in found:
            if str(path).lower() not in {str(p).lower() for p in self.hive_paths.values()}:
                if self.open_hive(path, quiet=True):
                    opened += 1
        self.status_var.set(f"Discovered {len(found)} hive file(s); opened {opened} new hive(s).")

    def open_hive_dialog(self) -> None:
        if not self.ensure_dependency():
            return
        filename = filedialog.askopenfilename(
            title="Open Offline Registry Hive",
            filetypes=[("Registry hives", "*.*"), ("All files", "*.*")]
        )
        if filename:
            self.open_hive(Path(filename))

    def open_hive(self, path: Path, quiet: bool = False) -> bool:
        if not self.ensure_dependency():
            return False
        try:
            reg = self.Registry.Registry(str(path))
            label = self.unique_hive_label(path)
            self.open_hives[label] = reg
            self.hive_paths[label] = path
            root_key = reg.root()
            root_id = self.key_tree.insert("", "end", text=label, values=(self.key_timestamp(root_key),), open=False)
            self.node_keys[root_id] = (label, "")
            self.add_dummy_if_needed(root_id, root_key)
            self.cache_hive(label, path)
            if not quiet:
                self.status_var.set(f"Opened hive: {path}")
            return True
        except Exception as exc:
            if not quiet:
                messagebox.showerror("Unable to Open Hive", f"{path}\n\n{exc}")
            return False

    def unique_hive_label(self, path: Path) -> str:
        base = path.name.upper()
        user = user_from_hive_path(path)
        label = f"{base} ({user})" if user and user != "System" else base
        candidate = label
        number = 2
        while candidate in self.open_hives:
            candidate = f"{label} #{number}"
            number += 1
        return candidate

    def cache_hive(self, label: str, path: Path) -> None:
        if not CASE_DB:
            return
        try:
            with sqlite3.connect(CASE_DB) as con:
                con.execute(
                    "INSERT OR REPLACE INTO registry_explorer_hives(evidence_id,hive_name,hive_path,user_name,opened_utc) VALUES(?,?,?,?,?)",
                    (int(EVIDENCE_ID) if EVIDENCE_ID.isdigit() else None, label, str(path), user_from_hive_path(path), utc_now())
                )
                con.commit()
        except Exception:
            traceback.print_exc()

    def add_dummy_if_needed(self, node_id: str, key: Any) -> None:
        try:
            if next(iter(key.subkeys()), None) is not None:
                self.key_tree.insert(node_id, "end", text="…")
        except Exception:
            pass

    def on_tree_open(self, _event=None) -> None:
        node = self.key_tree.focus()
        if not node or node not in self.node_keys:
            return
        children = self.key_tree.get_children(node)
        if len(children) == 1 and self.key_tree.item(children[0], "text") == "…":
            self.key_tree.delete(children[0])
            self.populate_subkeys(node)

    def populate_subkeys(self, node: str) -> None:
        label, key_path = self.node_keys[node]
        try:
            key = self.get_key(label, key_path)
            subkeys = sorted(key.subkeys(), key=lambda k: k.name().lower())
            for subkey in subkeys:
                child_path = f"{key_path}\\{subkey.name()}" if key_path else subkey.name()
                child = self.key_tree.insert(node, "end", text=subkey.name(), values=(self.key_timestamp(subkey),))
                self.node_keys[child] = (label, child_path)
                self.add_dummy_if_needed(child, subkey)
        except Exception as exc:
            self.status_var.set(f"Unable to enumerate key: {exc}")

    def get_key(self, label: str, key_path: str) -> Any:
        reg = self.open_hives[label]
        return reg.root() if not key_path else reg.open(key_path)

    def key_timestamp(self, key: Any) -> str:
        try:
            ts = key.timestamp()
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc).isoformat(timespec="seconds")
        except Exception:
            return ""

    def value_type(self, value: Any) -> str:
        for attr in ("value_type_str", "value_type"):
            try:
                item = getattr(value, attr)
                result = item() if callable(item) else item
                return str(result)
            except Exception:
                continue
        return ""

    def on_tree_select(self, _event=None) -> None:
        node = self.key_tree.focus()
        if not node or node not in self.node_keys:
            return
        label, key_path = self.node_keys[node]
        try:
            key = self.get_key(label, key_path)
            self.path_label.config(text=f"{label}\\{key_path}" if key_path else label)
            self.time_label.config(text=f"Last Write: {self.key_timestamp(key)}    Hive: {self.hive_paths[label]}")
            for item in self.value_tree.get_children():
                self.value_tree.delete(item)
            for value in key.values():
                name = value.name() or "(Default)"
                self.value_tree.insert("", "end", values=(name, self.value_type(value), safe_text(value.value())))
            self.value_detail.delete("1.0", "end")
            self.status_var.set(f"Loaded {len(key.values())} value(s).")
        except Exception as exc:
            self.status_var.set(f"Unable to read key: {exc}")

    def show_value_detail(self, _event=None) -> None:
        selected = self.value_tree.selection()
        if not selected:
            return
        values = self.value_tree.item(selected[0], "values")
        self.value_detail.delete("1.0", "end")
        self.value_detail.insert("end", f"Name: {values[0]}\nType: {values[1]}\n\nData:\n{values[2]}")

    def close_selected_hive(self) -> None:
        node = self.key_tree.focus()
        if not node:
            return
        while self.key_tree.parent(node):
            node = self.key_tree.parent(node)
        label = self.key_tree.item(node, "text")
        if label not in self.open_hives:
            return
        self.key_tree.delete(node)
        stale = [k for k, value in self.node_keys.items() if value[0] == label]
        for key in stale:
            self.node_keys.pop(key, None)
        self.open_hives.pop(label, None)
        self.hive_paths.pop(label, None)
        self.status_var.set(f"Closed hive {label}.")

    def refresh_selected(self) -> None:
        node = self.key_tree.focus()
        if not node or node not in self.node_keys:
            return
        for child in self.key_tree.get_children(node):
            self.key_tree.delete(child)
        label, path = self.node_keys[node]
        try:
            key = self.get_key(label, path)
            self.add_dummy_if_needed(node, key)
            self.key_tree.item(node, open=True)
            self.on_tree_open()
            self.on_tree_select()
        except Exception as exc:
            self.status_var.set(f"Refresh failed: {exc}")

    def current_selection(self) -> Optional[dict[str, str]]:
        node = self.key_tree.focus()
        if not node or node not in self.node_keys:
            return None
        label, key_path = self.node_keys[node]
        key = self.get_key(label, key_path)
        value_name = value_type = value_data = ""
        selected_value = self.value_tree.selection()
        if selected_value:
            row = self.value_tree.item(selected_value[0], "values")
            value_name, value_type, value_data = row[0], row[1], row[2]
        return {
            "hive": label, "hive_path": str(self.hive_paths[label]), "user": user_from_hive_path(self.hive_paths[label]),
            "key": key_path, "value": value_name, "type": value_type, "data": value_data,
            "modified": self.key_timestamp(key),
        }

    def bookmark_selected(self) -> None:
        if not CASE_DB:
            messagebox.showwarning("No Case Database", "Bookmarks require the plugin to be launched from an active case.")
            return
        try:
            item = self.current_selection()
        except Exception as exc:
            messagebox.showerror("Bookmark", str(exc))
            return
        if not item:
            messagebox.showinfo("Bookmark", "Select a registry key or value first.")
            return
        notes = self.prompt_notes()
        if notes is None:
            return
        with sqlite3.connect(CASE_DB) as con:
            con.execute("""
                INSERT INTO registry_explorer_bookmarks
                (evidence_id,hive_name,hive_path,user_name,key_path,value_name,value_type,value_data,key_last_write_utc,notes,created_utc)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (
                int(EVIDENCE_ID) if EVIDENCE_ID.isdigit() else None, item["hive"], item["hive_path"], item["user"],
                item["key"], item["value"], item["type"], item["data"], item["modified"], notes, utc_now()
            ))
            con.commit()
        self.load_bookmarks()
        self.status_var.set("Registry bookmark saved to the case database.")

    def prompt_notes(self) -> Optional[str]:
        dialog = tk.Toplevel(self)
        dialog.title("Bookmark Notes")
        dialog.geometry("520x260")
        dialog.transient(self)
        dialog.grab_set()
        tk.Label(dialog, text="Examiner notes:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(12, 4))
        text = tk.Text(dialog, wrap="word", height=8)
        text.pack(fill="both", expand=True, padx=12, pady=4)
        result: dict[str, Optional[str]] = {"value": None}
        buttons = ttk.Frame(dialog)
        buttons.pack(fill="x", padx=12, pady=10)
        def save() -> None:
            result["value"] = text.get("1.0", "end").strip()
            dialog.destroy()
        ttk.Button(buttons, text="Save", command=save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=5)
        self.wait_window(dialog)
        return result["value"]

    def load_bookmarks(self) -> None:
        if not hasattr(self, "bookmark_tree"):
            return
        for item in self.bookmark_tree.get_children():
            self.bookmark_tree.delete(item)
        if not CASE_DB or not CASE_DB.exists():
            return
        try:
            with sqlite3.connect(CASE_DB) as con:
                rows = con.execute("""
                    SELECT id,hive_name,user_name,key_path,value_name,value_data,notes,created_utc
                    FROM registry_explorer_bookmarks
                    WHERE (? IS NULL OR evidence_id=?) ORDER BY id DESC
                """, ((int(EVIDENCE_ID) if EVIDENCE_ID.isdigit() else None), (int(EVIDENCE_ID) if EVIDENCE_ID.isdigit() else None))).fetchall()
            for row in rows:
                self.bookmark_tree.insert("", "end", values=row)
        except sqlite3.Error:
            pass

    def delete_bookmark(self) -> None:
        selected = self.bookmark_tree.selection()
        if not selected or not CASE_DB:
            return
        bookmark_id = self.bookmark_tree.item(selected[0], "values")[0]
        if not messagebox.askyesno("Delete Bookmark", "Delete the selected bookmark?"):
            return
        with sqlite3.connect(CASE_DB) as con:
            con.execute("DELETE FROM registry_explorer_bookmarks WHERE id=?", (bookmark_id,))
            con.commit()
        self.load_bookmarks()

    def start_search(self) -> None:
        term = self.search_var.get().strip()
        if not term:
            messagebox.showinfo("Search", "Enter a search term.")
            return
        if not self.open_hives:
            messagebox.showinfo("Search", "Open at least one hive first.")
            return
        self.cancel_search.clear()
        self.search_results.clear()
        for item in self.search_tree.get_children():
            self.search_tree.delete(item)
        threading.Thread(target=self._search_worker, args=(term.lower(),), daemon=True).start()

    def _search_worker(self, term: str) -> None:
        self.ui_queue.put(("status", "Searching open registry hives..."))
        count = 0
        try:
            for label, reg in list(self.open_hives.items()):
                if self.cancel_search.is_set():
                    break
                count += self._search_key_recursive(label, reg.root(), "", term)
        except Exception as exc:
            self.ui_queue.put(("status", f"Search error: {exc}"))
            return
        state = "stopped" if self.cancel_search.is_set() else "completed"
        self.ui_queue.put(("status", f"Search {state}: {count:,} matching row(s)."))

    def _search_key_recursive(self, label: str, key: Any, key_path: str, term: str) -> int:
        if self.cancel_search.is_set():
            return 0
        matches = 0
        modified = self.key_timestamp(key)
        key_name_match = self.search_names_var.get() and term in (key.name() or "").lower()
        if key_name_match:
            row = self.make_search_row(label, key_path, "", "", "", modified)
            self.ui_queue.put(("search_row", row))
            matches += 1
        try:
            values = key.values()
        except Exception:
            values = []
        for value in values:
            if self.cancel_search.is_set():
                break
            name = value.name() or "(Default)"
            data = safe_text(value.value())
            name_match = self.search_names_var.get() and term in name.lower()
            data_match = self.search_data_var.get() and term in data.lower()
            if name_match or data_match:
                row = self.make_search_row(label, key_path, name, self.value_type(value), data, modified)
                self.ui_queue.put(("search_row", row))
                matches += 1
        try:
            subkeys = key.subkeys()
        except Exception:
            subkeys = []
        for subkey in subkeys:
            child_path = f"{key_path}\\{subkey.name()}" if key_path else subkey.name()
            matches += self._search_key_recursive(label, subkey, child_path, term)
        return matches

    def make_search_row(self, label: str, key_path: str, value: str, value_type: str, data: str, modified: str) -> dict[str, str]:
        return {
            "hive": label, "user": user_from_hive_path(self.hive_paths[label]), "key": key_path,
            "value": value, "type": value_type, "data": data, "modified": modified,
        }

    def _process_ui_queue(self) -> None:
        try:
            while True:
                action, payload = self.ui_queue.get_nowait()
                if action == "status":
                    self.status_var.set(payload)
                elif action == "search_row":
                    self.search_results.append(payload)
                    self.search_tree.insert("", "end", values=tuple(payload[c] for c in ("hive", "user", "key", "value", "type", "data", "modified")))
        except queue.Empty:
            pass
        self.after(100, self._process_ui_queue)

    def navigate_search_result(self, _event=None) -> None:
        selected = self.search_tree.selection()
        if not selected:
            return
        row = self.search_tree.item(selected[0], "values")
        label, key_path = row[0], row[2]
        root_nodes = self.key_tree.get_children("")
        root = next((n for n in root_nodes if self.key_tree.item(n, "text") == label), None)
        if not root:
            return
        node = root
        current = ""
        for part in [p for p in key_path.split("\\") if p]:
            self.key_tree.item(node, open=True)
            self.key_tree.focus(node)
            self.on_tree_open()
            current = f"{current}\\{part}" if current else part
            child = next((c for c in self.key_tree.get_children(node) if self.key_tree.item(c, "text") == part), None)
            if not child:
                break
            node = child
        self.key_tree.selection_set(node)
        self.key_tree.focus(node)
        self.key_tree.see(node)
        self.on_tree_select()
        self.notebook.select(self.browser_tab)

    def export_current_values(self) -> None:
        selection = self.current_selection()
        if not selection:
            messagebox.showinfo("Export", "Select a registry key first.")
            return
        rows = [self.value_tree.item(i, "values") for i in self.value_tree.get_children()]
        headers = ["Hive", "Hive Path", "User", "Key Path", "Last Write UTC", "Value Name", "Value Type", "Value Data"]
        out = [[selection["hive"], selection["hive_path"], selection["user"], selection["key"], selection["modified"], *r] for r in rows]
        self.write_csv(headers, out, "registry_values.csv")

    def export_search_results(self) -> None:
        headers = ["Hive", "User", "Key Path", "Value Name", "Value Type", "Value Data", "Last Write UTC"]
        rows = [[r[c] for c in ("hive", "user", "key", "value", "type", "data", "modified")] for r in self.search_results]
        self.write_csv(headers, rows, "registry_search_results.csv")

    def export_bookmarks(self) -> None:
        headers = ["ID", "Hive", "User", "Key Path", "Value Name", "Value Data", "Notes", "Created UTC"]
        rows = [self.bookmark_tree.item(i, "values") for i in self.bookmark_tree.get_children()]
        self.write_csv(headers, rows, "registry_bookmarks.csv")

    def write_csv(self, headers: list[str], rows: list[Any], default_name: str) -> None:
        if not rows:
            messagebox.showinfo("Export", "There are no rows to export.")
            return
        filename = filedialog.asksaveasfilename(title="Export CSV", defaultextension=".csv", initialfile=default_name, filetypes=[("CSV files", "*.csv")])
        if not filename:
            return
        with open(filename, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            writer.writerows(rows)
        self.status_var.set(f"Exported {len(rows):,} row(s) to {filename}")


def main() -> None:
    app = RegistryExplorerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
