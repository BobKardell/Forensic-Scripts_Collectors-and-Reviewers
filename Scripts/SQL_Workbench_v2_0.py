#!/usr/bin/env python3
# FFT_TOOL
# TITLE: SQL Workbench
# ID: sql_workbench
# CATEGORY: Analysis Tools
# VERSION: 2.0.0
# DESCRIPTION: Browse and query SQLite databases with current-case integration.
# ICON: 🗄
# PASS_CASE_ARGUMENTS: true

"""Fraud Fighter Toolbox SQL Workbench v2.0."""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Optional

APP_NAME = "SQL Workbench"
APP_VERSION = "2.0.0"

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

READ_ONLY_PREFIXES = ("select", "with", "pragma", "explain")
FAVORITE_TABLES = (
    "file_inventory", "artifact_inventory", "timeline", "timeline_events",
    "bookmarks", "duplicate_sets", "audit_log", "case_info", "evidence",
)


def app_settings_path() -> Path:
    return Path(__file__).resolve().with_name("sql_workbench_settings.json")


def load_settings() -> dict[str, Any]:
    defaults = {
        "geometry": "1450x900",
        "last_database": "",
        "last_sql": "",
        "main_sash": 280,
        "vertical_sash": 355,
    }
    path = app_settings_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                defaults.update(data)
        except Exception:
            pass
    return defaults


def save_settings(data: dict[str, Any]) -> None:
    try:
        app_settings_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def global_settings_directory() -> Path:
    script_dir = Path(__file__).resolve().parent
    if script_dir.name.lower() == "python scripts":
        return script_dir.parent
    for candidate in (
        script_dir.parent / "Forensics Collector Global Settings",
        script_dir / "Forensics Collector Global Settings",
        script_dir.parent,
    ):
        if (candidate / "SQL Queries").exists():
            return candidate
    return script_dir.parent


def sql_queries_directory() -> Path:
    folder = global_settings_directory() / "SQL Queries"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def first_sql_keyword(sql: str) -> str:
    text = sql.lstrip()
    while True:
        if text.startswith("--"):
            pos = text.find("\n")
            text = "" if pos < 0 else text[pos + 1:].lstrip()
            continue
        if text.startswith("/*"):
            pos = text.find("*/", 2)
            text = "" if pos < 0 else text[pos + 2:].lstrip()
            continue
        break
    match = re.match(r"([A-Za-z]+)", text)
    return match.group(1).lower() if match else ""


class SQLWorkbench(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.settings = load_settings()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry(str(self.settings.get("geometry", "1450x900")))
        self.minsize(1080, 700)
        self.configure(bg=COLORS["panel"])

        self.db_path = tk.StringVar()
        self.case_name = tk.StringVar(value=os.environ.get("FFT_CASE_NAME", "No active case"))
        self.case_number = tk.StringVar(value=os.environ.get("FFT_CASE_NUMBER", ""))
        self.examiner = tk.StringVar(value=os.environ.get("FFT_EXAMINER", ""))
        self.saved_query = tk.StringVar()
        self.read_only = tk.BooleanVar(value=True)
        self.row_limit = tk.IntVar(value=5000)
        self.status_text = tk.StringVar(value="Ready")
        self.connection_state = tk.StringVar(value="Disconnected")
        self.table_count = tk.StringVar(value="0 objects")
        self.sqlite_version = tk.StringVar(value=f"SQLite {sqlite3.sqlite_version}")
        self.current_db_name = tk.StringVar(value="No database")
        self.selected_value = tk.StringVar(value="")
        self.find_text = tk.StringVar()

        self.connection: Optional[sqlite3.Connection] = None
        self.current_columns: list[str] = []
        self.current_rows: list[tuple[str, ...]] = []
        self.query_files: dict[str, Path] = {}
        self.sort_state: dict[str, bool] = {}

        self._configure_styles()
        self._build_ui()
        self._bind_shortcuts()
        self._refresh_saved_queries()

        last_sql = str(self.settings.get("last_sql", ""))
        if last_sql:
            self.sql_editor.insert("1.0", last_sql)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Segoe UI", 9), background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("Panel.TFrame", background=COLORS["white"])
        style.configure("Header.TFrame", background=COLORS["navy"])
        style.configure("HeaderTitle.TLabel", background=COLORS["navy"], foreground=COLORS["white"], font=("Segoe UI Semibold", 20))
        style.configure("HeaderMeta.TLabel", background=COLORS["navy"], foreground=COLORS["slate_light"], font=("Segoe UI", 9))
        style.configure("Section.TLabel", background=COLORS["white"], foreground=COLORS["navy"], font=("Segoe UI Semibold", 11))
        style.configure("Muted.TLabel", background=COLORS["white"], foreground=COLORS["muted"])
        style.configure("Primary.TButton", background=COLORS["blue"], foreground=COLORS["white"], padding=(11, 7), font=("Segoe UI Semibold", 9))
        style.map("Primary.TButton", background=[("active", COLORS["slate_dark"])])
        style.configure("Secondary.TButton", background=COLORS["slate_light"], foreground=COLORS["text"], padding=(10, 7))
        style.map("Secondary.TButton", background=[("active", COLORS["border"])])
        style.configure("Treeview", background=COLORS["white"], fieldbackground=COLORS["white"], foreground=COLORS["text"], rowheight=24, bordercolor=COLORS["border"])
        style.configure("Treeview.Heading", background=COLORS["navy2"], foreground=COLORS["white"], font=("Segoe UI Semibold", 9), relief="flat")
        style.map("Treeview.Heading", background=[("active", COLORS["slate_dark"])])
        style.configure("TLabelframe", background=COLORS["white"], bordercolor=COLORS["border"])
        style.configure("TLabelframe.Label", background=COLORS["white"], foreground=COLORS["navy"], font=("Segoe UI Semibold", 10))

    def _build_ui(self) -> None:
        header = ttk.Frame(self, style="Header.TFrame", padding=(22, 17))
        header.pack(fill="x")
        left = ttk.Frame(header, style="Header.TFrame")
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="🗄  SQL Workbench", style="HeaderTitle.TLabel").pack(anchor="w")
        case_text = f"{self.case_name.get()}"
        if self.case_number.get():
            case_text += f"  •  Case {self.case_number.get()}"
        if self.examiner.get():
            case_text += f"  •  Examiner: {self.examiner.get()}"
        ttk.Label(left, text=case_text, style="HeaderMeta.TLabel").pack(anchor="w", pady=(3, 0))
        ttk.Label(header, text=f"Version {APP_VERSION}", style="HeaderMeta.TLabel").pack(side="right", anchor="ne")

        toolbar = tk.Frame(self, bg=COLORS["white"], highlightbackground=COLORS["border"], highlightthickness=1, padx=14, pady=10)
        toolbar.pack(fill="x", padx=12, pady=(12, 8))
        ttk.Button(toolbar, text="Open Current Case DB", style="Primary.TButton", command=self.open_current_case_db).pack(side="left")
        ttk.Button(toolbar, text="Open Another Database", style="Secondary.TButton", command=self.open_database).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Refresh", style="Secondary.TButton", command=self.refresh_schema).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Explain Query", style="Secondary.TButton", command=self.explain_query).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(toolbar, text="Read Only", variable=self.read_only, command=self._read_only_changed).pack(side="right")
        tk.Label(toolbar, textvariable=self.db_path, bg=COLORS["white"], fg=COLORS["muted"], anchor="e").pack(side="right", fill="x", expand=True, padx=(20, 12))

        main = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.main_pane = main

        sidebar = ttk.Frame(main, style="Panel.TFrame", padding=8)
        workspace = ttk.Frame(main, style="Panel.TFrame", padding=8)
        main.add(sidebar, weight=1)
        main.add(workspace, weight=5)

        ttk.Label(sidebar, text="Database Objects", style="Section.TLabel").pack(anchor="w")
        self.schema_tree = ttk.Treeview(sidebar, show="tree", selectmode="browse")
        sy = ttk.Scrollbar(sidebar, orient="vertical", command=self.schema_tree.yview)
        sx = ttk.Scrollbar(sidebar, orient="horizontal", command=self.schema_tree.xview)
        self.schema_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.schema_tree.pack(side="top", fill="both", expand=True, pady=(6, 0))
        sy.place(relx=1.0, rely=0.04, relheight=0.91, anchor="ne")
        sx.pack(fill="x")
        self.schema_tree.bind("<Double-1>", self._schema_double_click)
        self.schema_tree.bind("<Button-3>", self._schema_context_menu)

        self.vertical = ttk.Panedwindow(workspace, orient=tk.VERTICAL)
        self.vertical.pack(fill="both", expand=True)

        query_area = ttk.Frame(self.vertical, style="Panel.TFrame")
        result_area = ttk.Frame(self.vertical, style="Panel.TFrame")
        self.vertical.add(query_area, weight=2)
        self.vertical.add(result_area, weight=3)

        saved = ttk.Frame(query_area, style="Panel.TFrame")
        saved.pack(fill="x")
        ttk.Label(saved, text="Saved query", style="Muted.TLabel").pack(side="left")
        self.saved_combo = ttk.Combobox(saved, textvariable=self.saved_query, state="readonly", width=36)
        self.saved_combo.pack(side="left", padx=6)
        self.saved_combo.bind("<<ComboboxSelected>>", self.load_selected_query)
        ttk.Button(saved, text="Open SQL", command=self.load_query_file).pack(side="left")
        ttk.Button(saved, text="Save SQL", command=self.save_query_as).pack(side="left", padx=(6, 0))
        ttk.Button(saved, text="Clear", command=self.clear_query).pack(side="left", padx=(6, 0))
        ttk.Label(saved, text="Max rows", style="Muted.TLabel").pack(side="right", padx=(8, 4))
        ttk.Spinbox(saved, from_=100, to=1000000, increment=500, textvariable=self.row_limit, width=9).pack(side="right")

        editor_frame = ttk.LabelFrame(query_area, text="SQL Query", padding=5)
        editor_frame.pack(fill="both", expand=True, pady=(7, 5))
        self.sql_editor = ScrolledText(editor_frame, wrap="none", font=("Consolas", 10), undo=True, bg="#fbfdff", fg=COLORS["text"], insertbackground=COLORS["text"])
        self.sql_editor.pack(fill="both", expand=True)

        actions = ttk.Frame(query_area, style="Panel.TFrame")
        actions.pack(fill="x")
        ttk.Button(actions, text="Execute (F5)", style="Primary.TButton", command=self.run_query).pack(side="left")
        ttk.Button(actions, text="Export CSV", style="Secondary.TButton", command=self.export_results).pack(side="left", padx=(7, 0))
        ttk.Button(actions, text="Auto-size Columns", style="Secondary.TButton", command=self.auto_size_columns).pack(side="left", padx=(7, 0))
        ttk.Label(actions, text="Find", style="Muted.TLabel").pack(side="right", padx=(8, 4))
        find_entry = ttk.Entry(actions, textvariable=self.find_text, width=24)
        find_entry.pack(side="right")
        find_entry.bind("<Return>", lambda _e: self.find_next())

        results_frame = ttk.LabelFrame(result_area, text="Query Results", padding=5)
        results_frame.pack(fill="both", expand=True)
        self.results_tree = ttk.Treeview(results_frame, show="headings", selectmode="extended")
        ybar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        xbar = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)
        self.results_tree.bind("<Double-1>", self.show_selected_row)
        self.results_tree.bind("<Button-3>", self._result_context_menu)
        self.results_tree.bind("<<TreeviewSelect>>", self._show_selected_value)

        detail = ttk.LabelFrame(result_area, text="Selected Value / Messages", padding=5)
        detail.pack(fill="x", pady=(6, 0))
        self.output_text = ScrolledText(detail, height=6, wrap="word", font=("Consolas", 9))
        self.output_text.pack(fill="both", expand=True)

        status = tk.Frame(self, bg=COLORS["navy2"], padx=10, pady=5)
        status.pack(fill="x")
        for variable in (self.connection_state, self.table_count, self.sqlite_version, self.current_db_name):
            tk.Label(status, textvariable=variable, bg=COLORS["navy2"], fg=COLORS["white"]).pack(side="left", padx=(0, 18))
        tk.Label(status, textvariable=self.status_text, bg=COLORS["navy2"], fg=COLORS["slate_light"], anchor="e").pack(side="right", fill="x", expand=True)

        self.after(150, self._restore_sashes)

    def _restore_sashes(self) -> None:
        try:
            self.main_pane.sashpos(0, int(self.settings.get("main_sash", 280)))
            self.vertical.sashpos(0, int(self.settings.get("vertical_sash", 355)))
        except Exception:
            pass

    def _bind_shortcuts(self) -> None:
        self.bind("<F5>", lambda _e: self.run_query())
        self.bind("<Control-l>", lambda _e: self.clear_query())
        self.bind("<Control-o>", lambda _e: self.open_database())
        self.bind("<Control-Shift-O>", lambda _e: self.open_current_case_db())
        self.bind("<Control-s>", lambda _e: self.save_query_as())
        self.bind("<Control-e>", lambda _e: self.export_results())
        self.bind("<Control-f>", lambda _e: self.find_next())

    def open_current_case_db(self) -> None:
        path = os.environ.get("FFT_CASE_DB", "").strip()
        if not path:
            messagebox.showwarning("No Active Case", "No current FFT case database was supplied by the launcher.")
            return
        self._open_path(Path(path))

    def open_database(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose SQLite Database",
            filetypes=[("SQLite databases", "*.sqlite *.sqlite3 *.db *.db3"), ("All files", "*.*")],
        )
        if path:
            self._open_path(Path(path))

    def _open_path(self, path: Path) -> None:
        if not path.exists():
            messagebox.showerror("Database Error", f"Database not found:\n{path}")
            return
        self._close_connection()
        self.db_path.set(str(path))
        if not self._reopen(not self.read_only.get()):
            return
        self.connection_state.set("Connected")
        self.current_db_name.set(path.name)
        self.status_text.set(f"Opened {path}")
        self.refresh_schema()

    def _reopen(self, writable: bool) -> bool:
        path = Path(self.db_path.get().strip())
        if not str(path):
            return False
        self._close_connection()
        try:
            if writable:
                self.connection = sqlite3.connect(str(path), check_same_thread=False)
            else:
                uri = path.resolve().as_uri() + "?mode=ro"
                self.connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
                self.connection.execute("PRAGMA query_only = ON")
            self.connection.row_factory = sqlite3.Row
            return True
        except Exception as exc:
            messagebox.showerror("Database Error", str(exc))
            self.connection_state.set("Disconnected")
            return False

    def _read_only_changed(self) -> None:
        if not self.db_path.get():
            return
        writable = not self.read_only.get()
        if writable:
            if not messagebox.askyesno(
                "Enable Read-Write Mode",
                "Read-write mode can modify the database.\n\nEnable it only for a working copy or case database you intend to change.",
                icon=messagebox.WARNING,
            ):
                self.read_only.set(True)
                return
        self._reopen(writable)
        self.status_text.set("Read-only mode enabled" if self.read_only.get() else "Read-write mode enabled")

    def refresh_schema(self) -> None:
        self.schema_tree.delete(*self.schema_tree.get_children())
        if self.connection is None:
            return
        try:
            objects = self.connection.execute(
                "SELECT name,type FROM sqlite_master "
                "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
                "ORDER BY type,name COLLATE NOCASE"
            ).fetchall()
            names = {row["name"] for row in objects}
            favorites = self.schema_tree.insert("", "end", text="★ Favorites", open=True)
            for name in FAVORITE_TABLES:
                if name in names:
                    self.schema_tree.insert(favorites, "end", text=name, tags=("table",))
            tables_root = self.schema_tree.insert("", "end", text="Tables and Views", open=True)
            for obj in objects:
                name = obj["name"]
                parent = self.schema_tree.insert(tables_root, "end", text=f"{name} [{obj['type'].title()}]", open=False, tags=("table",))
                for col in self.connection.execute(f"PRAGMA table_info({quote_identifier(name)})"):
                    flags = (" PK" if col["pk"] else "") + (" NOT NULL" if col["notnull"] else "")
                    self.schema_tree.insert(parent, "end", text=f"{col['name']} — {col['type'] or '(unspecified)'}{flags}", tags=("column",))
            self.table_count.set(f"{len(objects):,} objects")
            self.status_text.set("Schema refreshed")
        except Exception as exc:
            self._show_error("Schema Error", exc)

    def _table_name_for_item(self, item: str) -> str:
        text = self.schema_tree.item(item, "text")
        if text in ("★ Favorites", "Tables and Views"):
            return ""
        return text.rsplit(" [", 1)[0]

    def _schema_double_click(self, _event=None) -> None:
        item = self.schema_tree.focus()
        if not item:
            return
        parent = self.schema_tree.parent(item)
        grandparent = self.schema_tree.parent(parent) if parent else ""
        if self.schema_tree.item(item, "tags") == ("column",):
            table = self._table_name_for_item(parent)
            column = self.schema_tree.item(item, "text").split(" — ", 1)[0]
            self.sql_editor.insert(tk.INSERT, f"{quote_identifier(table)}.{quote_identifier(column)}")
        else:
            table = self._table_name_for_item(item)
            if table:
                self.sql_editor.delete("1.0", "end")
                self.sql_editor.insert("1.0", f"SELECT *\nFROM {quote_identifier(table)}\nLIMIT 1000;")
                self.run_query()

    def _schema_context_menu(self, event) -> None:
        item = self.schema_tree.identify_row(event.y)
        if not item:
            return
        self.schema_tree.selection_set(item)
        self.schema_tree.focus(item)
        menu = tk.Menu(self, tearoff=False)
        if self.schema_tree.item(item, "tags") == ("column",):
            menu.add_command(label="Insert Column Name", command=self._schema_double_click)
        else:
            table = self._table_name_for_item(item)
            if table:
                menu.add_command(label="Open Table", command=self._schema_double_click)
                menu.add_command(label="Show Row Count", command=lambda: self._count_table(table))
        menu.tk_popup(event.x_root, event.y_root)

    def _count_table(self, table: str) -> None:
        self.sql_editor.delete("1.0", "end")
        self.sql_editor.insert("1.0", f"SELECT COUNT(*) AS row_count FROM {quote_identifier(table)};")
        self.run_query()

    def explain_query(self) -> None:
        sql = self.sql_editor.get("1.0", "end").strip()
        if not sql:
            return
        self.sql_editor.delete("1.0", "end")
        self.sql_editor.insert("1.0", "EXPLAIN QUERY PLAN\n" + sql)
        self.run_query()

    def run_query(self) -> None:
        if not self.db_path.get().strip():
            messagebox.showwarning("Database Required", "Open a SQLite database first.")
            return
        sql = self.sql_editor.get("1.0", "end").strip()
        if not sql:
            messagebox.showwarning("Query Required", "Enter a SQL query.")
            return
        keyword = first_sql_keyword(sql)
        is_read = keyword in READ_ONLY_PREFIXES
        if not is_read and self.read_only.get():
            messagebox.showwarning("Read Only", "Read-only mode is enabled. Disable it before running a modifying query.")
            return
        if not is_read and not messagebox.askyesno(
            "Confirm Database Modification",
            "This statement may modify the database. Continue?",
            icon=messagebox.WARNING,
        ):
            return
        if self.connection is None and not self._reopen(not self.read_only.get()):
            return

        self._clear_results()
        self.output_text.delete("1.0", "end")
        try:
            cursor = self.connection.cursor()
            cursor.execute(sql)
            if cursor.description:
                columns = [d[0] for d in cursor.description]
                limit = max(1, int(self.row_limit.get()))
                rows = cursor.fetchmany(limit + 1)
                truncated = len(rows) > limit
                rows = rows[:limit]
                normalized = [tuple(self._display_value(v) for v in row) for row in rows]
                self._populate_results(columns, normalized)
                msg = f"Displayed {len(normalized):,} row(s)"
                if truncated:
                    msg += f" (limited to {limit:,})"
            else:
                affected = cursor.rowcount
                self.connection.commit()
                msg = f"Rows affected: {affected:,}"
                self.refresh_schema()
            self.output_text.insert("end", msg + "\n")
            self.status_text.set(msg)
        except Exception as exc:
            try:
                self.connection.rollback()
            except Exception:
                pass
            self._show_error("SQL Query Error", exc)

    @staticmethod
    def _display_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            preview = value[:256].hex()
            return preview + (f"... ({len(value):,} bytes)" if len(value) > 256 else "")
        return str(value)

    def _populate_results(self, columns: list[str], rows: list[tuple[str, ...]]) -> None:
        self.current_columns, self.current_rows = columns, rows
        self.results_tree.configure(columns=columns)
        for column in columns:
            self.results_tree.heading(column, text=column, command=lambda c=column: self._sort_results(c))
            self.results_tree.column(column, width=140, minwidth=60, stretch=True)
        for row in rows:
            self.results_tree.insert("", "end", values=row)
        self.auto_size_columns()

    def auto_size_columns(self) -> None:
        for column in self.current_columns:
            width = max(90, min(420, len(column) * 9 + 24))
            for item in self.results_tree.get_children()[:150]:
                width = max(width, min(420, len(str(self.results_tree.set(item, column))) * 8 + 24))
            self.results_tree.column(column, width=width)

    def _clear_results(self) -> None:
        self.results_tree.delete(*self.results_tree.get_children())
        self.results_tree.configure(columns=())
        self.current_columns, self.current_rows = [], []

    def _sort_results(self, column: str) -> None:
        reverse = self.sort_state.get(column, False)
        entries = [(self.results_tree.set(item, column), item) for item in self.results_tree.get_children("")]
        def key(pair):
            value = pair[0]
            if value == "":
                return (2, "")
            try:
                return (0, float(value.replace(",", "")))
            except ValueError:
                return (1, value.lower())
        entries.sort(key=key, reverse=reverse)
        for index, (_, item) in enumerate(entries):
            self.results_tree.move(item, "", index)
        self.sort_state[column] = not reverse

    def _show_selected_value(self, _event=None) -> None:
        sel = self.results_tree.selection()
        if not sel:
            return
        values = self.results_tree.item(sel[0], "values")
        self.output_text.delete("1.0", "end")
        for column, value in zip(self.current_columns, values):
            self.output_text.insert("end", f"{column}: {value}\n")

    def show_selected_row(self, _event=None) -> None:
        sel = self.results_tree.selection()
        if not sel:
            return
        win = tk.Toplevel(self)
        win.title("Query Result Row")
        win.geometry("850x620")
        text = ScrolledText(win, wrap="word", font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        for column, value in zip(self.current_columns, self.results_tree.item(sel[0], "values")):
            text.insert("end", f"{column}\n{'-' * len(column)}\n{value}\n\n")
        text.configure(state="disabled")

    def _result_context_menu(self, event) -> None:
        item = self.results_tree.identify_row(event.y)
        column_id = self.results_tree.identify_column(event.x)
        if item:
            self.results_tree.selection_set(item)
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="Copy Cell", command=lambda: self.copy_cell(item, column_id))
        menu.add_command(label="Copy Selected Rows", command=self.copy_selected_rows)
        menu.add_command(label="Export Selected Rows", command=self.export_selected_rows)
        menu.add_separator()
        menu.add_command(label="View Row", command=self.show_selected_row)
        menu.tk_popup(event.x_root, event.y_root)

    def copy_cell(self, item: str, column_id: str) -> None:
        if not item or not column_id:
            return
        idx = int(column_id[1:]) - 1
        values = self.results_tree.item(item, "values")
        if 0 <= idx < len(values):
            self.clipboard_clear()
            self.clipboard_append(str(values[idx]))

    def copy_selected_rows(self) -> None:
        rows = [self.results_tree.item(item, "values") for item in self.results_tree.selection()]
        if not rows:
            return
        lines = ["\t".join(self.current_columns)]
        lines.extend("\t".join(map(str, row)) for row in rows)
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def find_next(self) -> None:
        needle = self.find_text.get().lower().strip()
        if not needle:
            return
        items = list(self.results_tree.get_children())
        start = 0
        selected = self.results_tree.selection()
        if selected and selected[0] in items:
            start = items.index(selected[0]) + 1
        for item in items[start:] + items[:start]:
            if any(needle in str(v).lower() for v in self.results_tree.item(item, "values")):
                self.results_tree.selection_set(item)
                self.results_tree.focus(item)
                self.results_tree.see(item)
                return
        self.status_text.set(f"No match for: {self.find_text.get()}")

    def export_results(self) -> None:
        self._export_rows(self.current_rows, "query_results.csv")

    def export_selected_rows(self) -> None:
        rows = [tuple(self.results_tree.item(item, "values")) for item in self.results_tree.selection()]
        self._export_rows(rows, "selected_query_rows.csv")

    def _export_rows(self, rows: list[tuple[str, ...]], initialfile: str) -> None:
        if not self.current_columns or not rows:
            messagebox.showinfo("No Results", "There are no rows to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Query Results",
            defaultextension=".csv",
            initialfile=initialfile,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.current_columns)
                writer.writerows(rows)
            self.status_text.set(f"Exported {len(rows):,} row(s)")
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))

    def _refresh_saved_queries(self) -> None:
        folder = sql_queries_directory()
        self.query_files.clear()
        for path in sorted(folder.rglob("*.sql"), key=lambda p: str(p).lower()):
            try:
                label = str(path.relative_to(folder)).replace("\\", "/")
            except ValueError:
                label = path.name
            self.query_files[label] = path
        self.saved_combo["values"] = list(self.query_files)
        self.status_text.set(f"Found {len(self.query_files):,} saved queries")

    def load_selected_query(self, _event=None) -> None:
        path = self.query_files.get(self.saved_query.get())
        if path:
            self._load_query_path(path)

    def load_query_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Load SQL Query",
            initialdir=str(sql_queries_directory()),
            filetypes=[("SQL files", "*.sql"), ("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self._load_query_path(Path(path))

    def _load_query_path(self, path: Path) -> None:
        try:
            content = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            messagebox.showerror("Query Load Error", str(exc))
            return
        self.sql_editor.delete("1.0", "end")
        self.sql_editor.insert("1.0", content)
        self.status_text.set(f"Loaded {path.name}")

    def save_query_as(self) -> None:
        sql = self.sql_editor.get("1.0", "end").strip()
        if not sql:
            return
        path = filedialog.asksaveasfilename(
            title="Save SQL Query",
            initialdir=str(sql_queries_directory()),
            defaultextension=".sql",
            initialfile="New_Query.sql",
            filetypes=[("SQL files", "*.sql"), ("All files", "*.*")],
        )
        if path:
            Path(path).write_text(sql + "\n", encoding="utf-8")
            self._refresh_saved_queries()

    def clear_query(self) -> None:
        self.sql_editor.delete("1.0", "end")

    def _show_error(self, title: str, exc: Exception) -> None:
        message = f"{type(exc).__name__}: {exc}"
        self.output_text.insert("end", message + "\n")
        self.status_text.set(message)
        messagebox.showerror(title, message)

    def _close_connection(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None

    def _on_close(self) -> None:
        data = {
            "geometry": self.geometry(),
            "last_database": self.db_path.get(),
            "last_sql": self.sql_editor.get("1.0", "end").strip(),
            "main_sash": self.main_pane.sashpos(0) if len(self.main_pane.panes()) > 1 else 280,
            "vertical_sash": self.vertical.sashpos(0) if len(self.vertical.panes()) > 1 else 355,
        }
        save_settings(data)
        self._close_connection()
        self.destroy()


if __name__ == "__main__":
    SQLWorkbench().mainloop()
