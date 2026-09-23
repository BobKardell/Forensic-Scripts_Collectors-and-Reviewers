# FFT_TOOL
# TITLE: Timeline Builder / Viewer
# ID: timeline_builder_viewer
# CATEGORY: Analysis Tools
# VERSION: 1.0.0
# DESCRIPTION: Build, filter, review, bookmark, and export a unified forensic timeline from case database artifacts.
# ICON: 📅

from __future__ import annotations

import csv
import json
import os
import sqlite3
import threading
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import END, BOTH, LEFT, RIGHT, X, Y, VERTICAL, HORIZONTAL
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Any, Iterable, Optional

APP_TITLE = "Timeline Builder / Viewer"
APP_VERSION = "1.0.0"
CASE_DB_ENV = os.environ.get("FFT_CASE_DB", "").strip()
EVIDENCE_ID_ENV = os.environ.get("FFT_EVIDENCE_ID", "0").strip()
EVIDENCE_NAME_ENV = os.environ.get("FFT_EVIDENCE_NAME", "").strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def normalize_timestamp(value: Any) -> str:
    """Best-effort normalization without changing forensic source data."""
    text = clean_text(value).strip()
    if not text:
        return ""
    candidate = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
        if dt.tzinfo is None:
            return dt.isoformat(sep=" ", timespec="seconds")
        return dt.astimezone(timezone.utc).isoformat(sep=" ", timespec="seconds")
    except Exception:
        return text


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


@dataclass
class TimelineRow:
    evidence_id: int
    source_table: str
    source_row_id: str
    event_time_utc: str
    event_type: str
    category: str
    source: str
    user_name: str
    computer_name: str
    description: str
    path: str
    value_data: str
    parser_name: str
    raw_data: str


class TimelineDatabase:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.ensure_schema()

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=60)
        con.row_factory = sqlite3.Row
        return con

    def ensure_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL DEFAULT 0,
                source_table TEXT NOT NULL,
                source_row_id TEXT,
                event_time_utc TEXT,
                event_type TEXT,
                category TEXT,
                source TEXT,
                user_name TEXT,
                computer_name TEXT,
                description TEXT,
                path TEXT,
                value_data TEXT,
                parser_name TEXT,
                raw_data TEXT,
                created_utc TEXT NOT NULL,
                UNIQUE(evidence_id, source_table, source_row_id, event_type, event_time_utc)
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_evidence_time
                ON timeline_events(evidence_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_timeline_category
                ON timeline_events(evidence_id, category);
            CREATE TABLE IF NOT EXISTS timeline_bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timeline_event_id INTEGER NOT NULL,
                evidence_id INTEGER NOT NULL DEFAULT 0,
                title TEXT,
                notes TEXT,
                tags TEXT,
                created_utc TEXT NOT NULL,
                modified_utc TEXT,
                UNIQUE(timeline_event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_bookmarks_evidence
                ON timeline_bookmarks(evidence_id);
            CREATE TABLE IF NOT EXISTS timeline_build_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                started_utc TEXT,
                completed_utc TEXT,
                status TEXT,
                rows_added INTEGER DEFAULT 0,
                rows_skipped INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0,
                details TEXT
            );
            """)

    def table_exists(self, con: sqlite3.Connection, table: str) -> bool:
        return con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name)=lower(?)", (table,)
        ).fetchone() is not None

    def columns(self, con: sqlite3.Connection, table: str) -> set[str]:
        return {r[1].lower() for r in con.execute(f"PRAGMA table_info({quote_ident(table)})")}

    def insert_rows(self, con: sqlite3.Connection, rows: Iterable[TimelineRow]) -> tuple[int, int]:
        added = skipped = 0
        sql = """
            INSERT OR IGNORE INTO timeline_events
            (evidence_id, source_table, source_row_id, event_time_utc, event_type,
             category, source, user_name, computer_name, description, path,
             value_data, parser_name, raw_data, created_utc)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        for row in rows:
            cur = con.execute(sql, (
                row.evidence_id, row.source_table, row.source_row_id,
                row.event_time_utc, row.event_type, row.category, row.source,
                row.user_name, row.computer_name, row.description, row.path,
                row.value_data, row.parser_name, row.raw_data, utc_now()
            ))
            if cur.rowcount:
                added += 1
            else:
                skipped += 1
        return added, skipped

    def build(self, evidence_id: int, replace: bool = False) -> dict[str, Any]:
        started = utc_now()
        totals = {"added": 0, "skipped": 0, "errors": 0, "sources": []}
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO timeline_build_runs(evidence_id,started_utc,status) VALUES(?,?,?)",
                (evidence_id, started, "Running")
            )
            run_id = cur.lastrowid
            if replace:
                con.execute("DELETE FROM timeline_events WHERE evidence_id=?", (evidence_id,))

            loaders = [
                ("forensic_artifacts", self._from_forensic_artifacts),
                ("windows_events", self._from_windows_events),
                ("file_inventory", self._from_file_inventory),
                ("registry_explorer_bookmarks", self._from_registry_bookmarks),
                ("chain_of_custody", self._from_chain_of_custody),
            ]
            for table, loader in loaders:
                if not self.table_exists(con, table):
                    continue
                try:
                    rows = list(loader(con, evidence_id))
                    added, skipped = self.insert_rows(con, rows)
                    totals["added"] += added
                    totals["skipped"] += skipped
                    totals["sources"].append({"table": table, "read": len(rows), "added": added})
                except Exception as exc:
                    totals["errors"] += 1
                    totals["sources"].append({"table": table, "error": str(exc)})

            con.execute("""
                UPDATE timeline_build_runs
                   SET completed_utc=?, status=?, rows_added=?, rows_skipped=?, errors=?, details=?
                 WHERE id=?
            """, (utc_now(), "Completed" if not totals["errors"] else "Completed with errors",
                  totals["added"], totals["skipped"], totals["errors"],
                  json.dumps(totals["sources"], ensure_ascii=False), run_id))
            con.commit()
        return totals

    def _from_forensic_artifacts(self, con: sqlite3.Connection, evidence_id: int) -> Iterable[TimelineRow]:
        cols = self.columns(con, "forensic_artifacts")
        if "evidence_id" not in cols:
            return
        for r in con.execute("SELECT * FROM forensic_artifacts WHERE evidence_id=?", (evidence_id,)):
            yield TimelineRow(
                evidence_id, "forensic_artifacts", clean_text(r["id"]),
                normalize_timestamp(r["timestamp_utc"]),
                clean_text(r["subtype"] or r["artifact_name"] or "Artifact"),
                clean_text(r["category"]), clean_text(r["source_path"]),
                clean_text(r["user_name"]), "",
                clean_text(r["description"] or r["artifact_name"]),
                clean_text(r["key_path"] or r["source_path"]),
                clean_text(r["value_data"]), clean_text(r["parser_name"]),
                clean_text(r["raw_data"])
            )

    def _from_windows_events(self, con: sqlite3.Connection, evidence_id: int) -> Iterable[TimelineRow]:
        cols = self.columns(con, "windows_events")
        rows = con.execute("SELECT * FROM windows_events WHERE evidence_id=?", (evidence_id,)) if "evidence_id" in cols else con.execute("SELECT * FROM windows_events")
        def get(r: sqlite3.Row, *names: str) -> str:
            for n in names:
                if n.lower() in cols:
                    return clean_text(r[n])
            return ""
        for r in rows:
            event_id = get(r, "event_id", "id")
            channel = get(r, "channel", "log_name")
            provider = get(r, "provider", "provider_name")
            msg = get(r, "message", "description", "event_data")
            yield TimelineRow(
                evidence_id, "windows_events", get(r, "id", "rowid"),
                normalize_timestamp(get(r, "time_created_utc", "timestamp_utc", "event_time_utc", "time_created")),
                f"Event ID {event_id}" if event_id else "Windows Event",
                "Windows Event Log", channel or provider,
                get(r, "user_sid", "user_name"), get(r, "computer", "computer_name"),
                msg, channel, get(r, "event_data", "xml"), provider,
                get(r, "raw_xml", "xml")
            )

    def _from_file_inventory(self, con: sqlite3.Connection, evidence_id: int) -> Iterable[TimelineRow]:
        cols = self.columns(con, "file_inventory")
        rows = con.execute("SELECT * FROM file_inventory WHERE evidence_id=?", (evidence_id,)) if "evidence_id" in cols else con.execute("SELECT * FROM file_inventory")
        def get(r: sqlite3.Row, *names: str) -> str:
            for n in names:
                if n.lower() in cols:
                    return clean_text(r[n])
            return ""
        for r in rows:
            rid = get(r, "id", "rowid")
            full_path = get(r, "full_path", "path")
            name = get(r, "filename", "name") or Path(full_path).name
            raw = json.dumps({k: clean_text(r[k]) for k in r.keys()}, ensure_ascii=False)
            for label, names in (
                ("File Created", ("created_utc", "created_time", "created")),
                ("File Modified", ("modified_utc", "modified_time", "modified")),
                ("File Accessed", ("accessed_utc", "accessed_time", "accessed")),
            ):
                ts = normalize_timestamp(get(r, *names))
                if ts:
                    yield TimelineRow(evidence_id, "file_inventory", rid, ts, label,
                                      "File System", name, "", "", f"{label}: {name}",
                                      full_path, get(r, "sha256", "md5"), "File Inventory", raw)

    def _from_registry_bookmarks(self, con: sqlite3.Connection, evidence_id: int) -> Iterable[TimelineRow]:
        for r in con.execute("SELECT * FROM registry_explorer_bookmarks WHERE evidence_id=?", (evidence_id,)):
            ts = normalize_timestamp(r["key_last_write_utc"])
            yield TimelineRow(
                evidence_id, "registry_explorer_bookmarks", clean_text(r["id"]), ts,
                "Registry Bookmark", "Registry", clean_text(r["hive_name"]),
                clean_text(r["user_name"]), "", clean_text(r["notes"]),
                clean_text(r["key_path"]), clean_text(r["value_data"]),
                "Registry Explorer", json.dumps(dict(r), ensure_ascii=False, default=str)
            )

    def _from_chain_of_custody(self, con: sqlite3.Connection, evidence_id: int) -> Iterable[TimelineRow]:
        cols = self.columns(con, "chain_of_custody")
        rows = con.execute("SELECT * FROM chain_of_custody WHERE evidence_id=?", (evidence_id,)) if "evidence_id" in cols else con.execute("SELECT * FROM chain_of_custody")
        for r in rows:
            d = {k.lower(): clean_text(r[k]) for k in r.keys()}
            ts = normalize_timestamp(d.get("transfer_date") or d.get("transfer_datetime") or d.get("timestamp"))
            released = d.get("released_by", "")
            received = d.get("received_by", "")
            desc = f"Custody transfer from {released or 'Unknown'} to {received or 'Unknown'}"
            yield TimelineRow(evidence_id, "chain_of_custody", d.get("id", ""), ts,
                              "Chain of Custody", "Case Activity", d.get("method", ""),
                              received, "", desc, d.get("location", ""),
                              d.get("purpose", ""), "Case Manager", json.dumps(d, ensure_ascii=False))


class BookmarkDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, title_value: str = "", notes: str = "", tags: str = ""):
        super().__init__(parent)
        self.title("Timeline Bookmark")
        self.resizable(True, True)
        self.result: Optional[tuple[str, str, str]] = None
        self.transient(parent)
        self.grab_set()
        frame = ttk.Frame(self, padding=12)
        frame.pack(fill=BOTH, expand=True)
        ttk.Label(frame, text="Title").grid(row=0, column=0, sticky="w")
        self.title_var = tk.StringVar(value=title_value)
        ttk.Entry(frame, textvariable=self.title_var, width=60).grid(row=1, column=0, sticky="ew", pady=(2, 8))
        ttk.Label(frame, text="Tags (comma separated)").grid(row=2, column=0, sticky="w")
        self.tags_var = tk.StringVar(value=tags)
        ttk.Entry(frame, textvariable=self.tags_var).grid(row=3, column=0, sticky="ew", pady=(2, 8))
        ttk.Label(frame, text="Examiner Notes").grid(row=4, column=0, sticky="w")
        self.notes = tk.Text(frame, width=70, height=10, wrap="word")
        self.notes.grid(row=5, column=0, sticky="nsew", pady=(2, 8))
        self.notes.insert("1.0", notes)
        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, sticky="e")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(buttons, text="Save", command=self.save).pack(side=RIGHT)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(5, weight=1)
        self.geometry("650x430")
        self.wait_visibility()
        self.title_var.set(title_value)

    def save(self) -> None:
        self.result = (self.title_var.get().strip(), self.notes.get("1.0", END).strip(), self.tags_var.get().strip())
        self.destroy()


class TimelineApp(tk.Tk):
    PAGE_SIZE = 1000

    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("1500x860")
        self.minsize(1050, 650)
        self.case_db = self.resolve_case_db()
        self.evidence_id = int(EVIDENCE_ID_ENV) if EVIDENCE_ID_ENV.isdigit() else 0
        self.db = TimelineDatabase(self.case_db)
        self.status_var = tk.StringVar(value="Ready")
        self.count_var = tk.StringVar(value="0 events")
        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value="All")
        self.event_type_var = tk.StringVar(value="All")
        self.start_var = tk.StringVar()
        self.end_var = tk.StringVar()
        self.bookmarks_only_var = tk.BooleanVar(value=False)
        self.offset = 0
        self.building = False
        self._configure_style()
        self._build_ui()
        self.refresh_filters()
        self.load_events(reset=True)

    def resolve_case_db(self) -> Path:
        if CASE_DB_ENV:
            return Path(CASE_DB_ENV)
        return Path.cwd() / "Timeline_Standalone.sqlite"

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Subheader.TLabel", font=("Segoe UI", 10))
        style.configure("Treeview", rowheight=24)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(14, 10))
        header.pack(fill=X)
        ttk.Label(header, text=APP_TITLE, style="Header.TLabel").pack(side=LEFT)
        evidence = EVIDENCE_NAME_ENV or f"Evidence {self.evidence_id}"
        ttk.Label(header, text=f"  •  {evidence}  •  {self.case_db}", style="Subheader.TLabel").pack(side=LEFT, padx=10)

        toolbar = ttk.Frame(self, padding=(12, 6))
        toolbar.pack(fill=X)
        ttk.Button(toolbar, text="Build / Update Timeline", command=lambda: self.start_build(False)).pack(side=LEFT)
        ttk.Button(toolbar, text="Rebuild Timeline", command=lambda: self.start_build(True)).pack(side=LEFT, padx=(6, 0))
        ttk.Button(toolbar, text="Bookmark Selected", command=self.bookmark_selected).pack(side=LEFT, padx=(18, 0))
        ttk.Button(toolbar, text="Remove Bookmark", command=self.remove_bookmark).pack(side=LEFT, padx=(6, 0))
        ttk.Button(toolbar, text="Export CSV", command=self.export_csv).pack(side=LEFT, padx=(18, 0))
        ttk.Button(toolbar, text="Refresh", command=lambda: self.load_events(reset=True)).pack(side=LEFT, padx=(6, 0))

        filters = ttk.LabelFrame(self, text="Filters", padding=8)
        filters.pack(fill=X, padx=12, pady=(2, 8))
        ttk.Label(filters, text="Search").grid(row=0, column=0, sticky="w")
        search = ttk.Entry(filters, textvariable=self.search_var, width=34)
        search.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        search.bind("<Return>", lambda _e: self.load_events(reset=True))
        ttk.Label(filters, text="Category").grid(row=0, column=1, sticky="w")
        self.category_combo = ttk.Combobox(filters, textvariable=self.category_var, state="readonly", width=22)
        self.category_combo.grid(row=1, column=1, padx=(0, 8))
        ttk.Label(filters, text="Event Type").grid(row=0, column=2, sticky="w")
        self.event_combo = ttk.Combobox(filters, textvariable=self.event_type_var, state="readonly", width=24)
        self.event_combo.grid(row=1, column=2, padx=(0, 8))
        ttk.Label(filters, text="Start (ISO/date)").grid(row=0, column=3, sticky="w")
        ttk.Entry(filters, textvariable=self.start_var, width=20).grid(row=1, column=3, padx=(0, 8))
        ttk.Label(filters, text="End (ISO/date)").grid(row=0, column=4, sticky="w")
        ttk.Entry(filters, textvariable=self.end_var, width=20).grid(row=1, column=4, padx=(0, 8))
        ttk.Checkbutton(filters, text="Bookmarks only", variable=self.bookmarks_only_var).grid(row=1, column=5, padx=(0, 8))
        ttk.Button(filters, text="Apply", command=lambda: self.load_events(reset=True)).grid(row=1, column=6)
        ttk.Button(filters, text="Clear", command=self.clear_filters).grid(row=1, column=7, padx=(6, 0))
        filters.columnconfigure(0, weight=1)

        paned = ttk.Panedwindow(self, orient=tk.VERTICAL)
        paned.pack(fill=BOTH, expand=True, padx=12, pady=(0, 8))
        upper = ttk.Frame(paned)
        lower = ttk.LabelFrame(paned, text="Event Details", padding=8)
        paned.add(upper, weight=4)
        paned.add(lower, weight=2)

        columns = ("bookmark", "time", "category", "type", "user", "source", "description", "path")
        self.tree = ttk.Treeview(upper, columns=columns, show="headings", selectmode="extended")
        headings = {
            "bookmark": "★", "time": "Time (UTC / source)", "category": "Category",
            "type": "Event Type", "user": "User", "source": "Source",
            "description": "Description", "path": "Path / Key"
        }
        widths = {"bookmark": 36, "time": 180, "category": 125, "type": 150, "user": 100,
                  "source": 170, "description": 390, "path": 330}
        for col in columns:
            self.tree.heading(col, text=headings[col], command=lambda c=col: self.sort_tree(c, False))
            self.tree.column(col, width=widths[col], minwidth=30, stretch=col in ("description", "path"))
        ybar = ttk.Scrollbar(upper, orient=VERTICAL, command=self.tree.yview)
        xbar = ttk.Scrollbar(upper, orient=HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        upper.columnconfigure(0, weight=1)
        upper.rowconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)
        self.tree.bind("<Double-1>", lambda _e: self.bookmark_selected())

        self.details = tk.Text(lower, wrap="word", height=12, font=("Consolas", 10))
        details_bar = ttk.Scrollbar(lower, orient=VERTICAL, command=self.details.yview)
        self.details.configure(yscrollcommand=details_bar.set)
        self.details.pack(side=LEFT, fill=BOTH, expand=True)
        details_bar.pack(side=RIGHT, fill=Y)

        footer = ttk.Frame(self, padding=(12, 4, 12, 10))
        footer.pack(fill=X)
        ttk.Label(footer, textvariable=self.status_var).pack(side=LEFT)
        ttk.Label(footer, textvariable=self.count_var).pack(side=RIGHT)

    def clear_filters(self) -> None:
        self.search_var.set("")
        self.category_var.set("All")
        self.event_type_var.set("All")
        self.start_var.set("")
        self.end_var.set("")
        self.bookmarks_only_var.set(False)
        self.load_events(reset=True)

    def refresh_filters(self) -> None:
        with self.db.connect() as con:
            cats = [r[0] for r in con.execute("SELECT DISTINCT category FROM timeline_events WHERE evidence_id=? AND category<>'' ORDER BY category", (self.evidence_id,))]
            types = [r[0] for r in con.execute("SELECT DISTINCT event_type FROM timeline_events WHERE evidence_id=? AND event_type<>'' ORDER BY event_type", (self.evidence_id,))]
        self.category_combo["values"] = ["All", *cats]
        self.event_combo["values"] = ["All", *types]
        if self.category_var.get() not in self.category_combo["values"]:
            self.category_var.set("All")
        if self.event_type_var.get() not in self.event_combo["values"]:
            self.event_type_var.set("All")

    def query_parts(self) -> tuple[str, list[Any]]:
        where = ["t.evidence_id=?"]
        params: list[Any] = [self.evidence_id]
        if self.category_var.get() != "All":
            where.append("t.category=?")
            params.append(self.category_var.get())
        if self.event_type_var.get() != "All":
            where.append("t.event_type=?")
            params.append(self.event_type_var.get())
        if self.start_var.get().strip():
            where.append("t.event_time_utc>=?")
            params.append(self.start_var.get().strip())
        if self.end_var.get().strip():
            where.append("t.event_time_utc<=?")
            params.append(self.end_var.get().strip())
        if self.bookmarks_only_var.get():
            where.append("b.id IS NOT NULL")
        search = self.search_var.get().strip()
        if search:
            where.append("(lower(t.description) LIKE ? OR lower(t.path) LIKE ? OR lower(t.value_data) LIKE ? OR lower(t.source) LIKE ? OR lower(t.user_name) LIKE ?)")
            token = f"%{search.lower()}%"
            params.extend([token] * 5)
        return " AND ".join(where), params

    def load_events(self, reset: bool = True) -> None:
        if reset:
            self.offset = 0
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        where, params = self.query_parts()
        sql = f"""
            SELECT t.*, b.id AS bookmark_id, b.title AS bookmark_title, b.notes AS bookmark_notes, b.tags AS bookmark_tags
              FROM timeline_events t
              LEFT JOIN timeline_bookmarks b ON b.timeline_event_id=t.id
             WHERE {where}
             ORDER BY CASE WHEN t.event_time_utc='' THEN 1 ELSE 0 END, t.event_time_utc, t.id
             LIMIT ? OFFSET ?
        """
        with self.db.connect() as con:
            rows = con.execute(sql, [*params, self.PAGE_SIZE, self.offset]).fetchall()
            total = con.execute(f"SELECT COUNT(*) FROM timeline_events t LEFT JOIN timeline_bookmarks b ON b.timeline_event_id=t.id WHERE {where}", params).fetchone()[0]
        for r in rows:
            self.tree.insert("", END, iid=str(r["id"]), values=(
                "★" if r["bookmark_id"] else "", r["event_time_utc"], r["category"], r["event_type"],
                r["user_name"], r["source"], r["description"], r["path"]
            ))
        self.count_var.set(f"Showing {len(rows):,} of {total:,} events")
        self.status_var.set("Timeline loaded")

    def show_details(self, _event: Any = None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        event_id = selected[0]
        with self.db.connect() as con:
            r = con.execute("""
                SELECT t.*, b.title AS bookmark_title, b.notes AS bookmark_notes, b.tags AS bookmark_tags
                  FROM timeline_events t LEFT JOIN timeline_bookmarks b ON b.timeline_event_id=t.id
                 WHERE t.id=?
            """, (event_id,)).fetchone()
        if not r:
            return
        lines = [
            f"Timeline Event ID: {r['id']}",
            f"Time: {r['event_time_utc']}",
            f"Category: {r['category']}",
            f"Event Type: {r['event_type']}",
            f"User: {r['user_name']}",
            f"Computer: {r['computer_name']}",
            f"Source: {r['source']}",
            f"Source Table/Row: {r['source_table']} / {r['source_row_id']}",
            f"Parser: {r['parser_name']}",
            "",
            f"Description:\n{r['description']}",
            "",
            f"Path / Key:\n{r['path']}",
            "",
            f"Value / Event Data:\n{r['value_data']}",
        ]
        if r["bookmark_title"] or r["bookmark_notes"] or r["bookmark_tags"]:
            lines += ["", "--- BOOKMARK ---", f"Title: {r['bookmark_title']}", f"Tags: {r['bookmark_tags']}", f"Notes:\n{r['bookmark_notes']}"]
        if r["raw_data"]:
            lines += ["", "--- RAW DATA ---", r["raw_data"]]
        self.details.delete("1.0", END)
        self.details.insert("1.0", "\n".join(clean_text(x) for x in lines))

    def start_build(self, replace: bool) -> None:
        if self.building:
            return
        if replace and not messagebox.askyesno("Rebuild Timeline", "Delete the existing timeline for this evidence and rebuild it?"):
            return
        self.building = True
        self.status_var.set("Building timeline from case database…")
        threading.Thread(target=self._build_worker, args=(replace,), daemon=True).start()

    def _build_worker(self, replace: bool) -> None:
        try:
            result = self.db.build(self.evidence_id, replace=replace)
            self.after(0, lambda: self._build_finished(result))
        except Exception as exc:
            details = traceback.format_exc()
            self.after(0, lambda: self._build_failed(exc, details))

    def _build_finished(self, result: dict[str, Any]) -> None:
        self.building = False
        self.refresh_filters()
        self.load_events(reset=True)
        msg = f"Timeline complete: {result['added']:,} added; {result['skipped']:,} already present; {result['errors']} source errors."
        self.status_var.set(msg)
        messagebox.showinfo("Timeline Complete", msg)

    def _build_failed(self, exc: Exception, details: str) -> None:
        self.building = False
        self.status_var.set("Timeline build failed")
        messagebox.showerror("Timeline Build Failed", f"{exc}\n\n{details}")

    def bookmark_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Bookmark", "Select a timeline event first.")
            return
        event_id = int(selected[0])
        with self.db.connect() as con:
            row = con.execute("""
                SELECT t.description, t.event_type, b.title, b.notes, b.tags
                  FROM timeline_events t LEFT JOIN timeline_bookmarks b ON b.timeline_event_id=t.id
                 WHERE t.id=?
            """, (event_id,)).fetchone()
        if not row:
            return
        dialog = BookmarkDialog(self, row["title"] or row["description"] or row["event_type"], row["notes"] or "", row["tags"] or "")
        self.wait_window(dialog)
        if dialog.result is None:
            return
        title, notes, tags = dialog.result
        with self.db.connect() as con:
            con.execute("""
                INSERT INTO timeline_bookmarks(timeline_event_id,evidence_id,title,notes,tags,created_utc,modified_utc)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(timeline_event_id) DO UPDATE SET
                    title=excluded.title, notes=excluded.notes, tags=excluded.tags, modified_utc=excluded.modified_utc
            """, (event_id, self.evidence_id, title, notes, tags, utc_now(), utc_now()))
            con.commit()
        self.load_events(reset=True)
        if self.tree.exists(str(event_id)):
            self.tree.selection_set(str(event_id))
            self.tree.see(str(event_id))
            self.show_details()

    def remove_bookmark(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        event_ids = [int(x) for x in selected]
        if not messagebox.askyesno("Remove Bookmark", f"Remove bookmarks from {len(event_ids)} selected event(s)?"):
            return
        with self.db.connect() as con:
            con.executemany("DELETE FROM timeline_bookmarks WHERE timeline_event_id=?", [(x,) for x in event_ids])
            con.commit()
        self.load_events(reset=True)

    def export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export Timeline", defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"Timeline_Evidence_{self.evidence_id}.csv"
        )
        if not path:
            return
        where, params = self.query_parts()
        sql = f"""
            SELECT t.event_time_utc,t.category,t.event_type,t.user_name,t.computer_name,
                   t.source,t.description,t.path,t.value_data,t.parser_name,t.source_table,
                   t.source_row_id,CASE WHEN b.id IS NULL THEN 0 ELSE 1 END AS bookmarked,
                   b.title AS bookmark_title,b.tags AS bookmark_tags,b.notes AS bookmark_notes
              FROM timeline_events t LEFT JOIN timeline_bookmarks b ON b.timeline_event_id=t.id
             WHERE {where}
             ORDER BY CASE WHEN t.event_time_utc='' THEN 1 ELSE 0 END,t.event_time_utc,t.id
        """
        with self.db.connect() as con, open(path, "w", newline="", encoding="utf-8-sig") as fh:
            rows = con.execute(sql, params)
            writer = csv.writer(fh)
            writer.writerow([d[0] for d in rows.description])
            count = 0
            for row in rows:
                writer.writerow(list(row))
                count += 1
        self.status_var.set(f"Exported {count:,} timeline events to {path}")
        messagebox.showinfo("Export Complete", f"Exported {count:,} events.")

    def sort_tree(self, col: str, descending: bool) -> None:
        values = [(self.tree.set(iid, col), iid) for iid in self.tree.get_children("")]
        values.sort(reverse=descending)
        for index, (_, iid) in enumerate(values):
            self.tree.move(iid, "", index)
        self.tree.heading(col, command=lambda: self.sort_tree(col, not descending))


def main() -> None:
    app = TimelineApp()
    app.mainloop()


if __name__ == "__main__":
    main()
