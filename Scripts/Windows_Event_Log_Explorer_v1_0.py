#!/usr/bin/env python3
# FFT_TOOL
# TITLE: Windows Event Log Explorer
# ID: windows_event_logs
# CATEGORY: Analysis Tools
# VERSION: 1.0.0
# DESCRIPTION: Discover, identify, parse, search, and export offline Windows event log files.
# ICON: LOG
# PASS_CASE_ARGUMENTS: false

from __future__ import annotations

import csv
import json
import os
import sqlite3
import subprocess
import tempfile
import threading
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Optional

APP_NAME = "Windows Event Log Explorer"
APP_VERSION = "1.0.0"

CASE_DB = Path(os.environ["FFT_CASE_DB"]) if os.environ.get("FFT_CASE_DB") else None
CASE_NAME = os.environ.get("FFT_CASE_NAME", "Standalone Analysis")
CASE_NUMBER = os.environ.get("FFT_CASE_NUMBER", "")
EXAMINER = os.environ.get("FFT_EXAMINER", "")
ENV_EVIDENCE_ID = os.environ.get("FFT_EVIDENCE_ID", "")
ENV_EVIDENCE_ROOT = os.environ.get("FFT_EVIDENCE_ROOT", "")

COLORS = {
    "navy": "#061522", "blue": "#188bd0", "panel": "#f2f6f9",
    "white": "#ffffff", "text": "#172431", "muted": "#607180",
    "border": "#c8d5df", "slate": "#587795", "green": "#367d4a",
    "red": "#a33b3b",
}

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value: Optional[str]) -> str:
    return "" if value is None else str(value).replace("\x00", "").strip()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@dataclass
class LogFile:
    path: Path
    channel: str
    size: int
    modified_utc: str


class WindowsEventLogExplorer(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1550x900")
        self.minsize(1100, 700)
        self.configure(bg=COLORS["panel"])

        self.source_var = tk.StringVar(value=self.resolve_evidence_root())
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0)
        self.files_count_var = tk.StringVar(value="0")
        self.events_count_var = tk.StringVar(value="0")
        self.errors_count_var = tk.StringVar(value="0")
        self.search_var = tk.StringVar()
        self.channel_var = tk.StringVar(value="All")
        self.level_var = tk.StringVar(value="All")
        self.cancel_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.log_files: list[LogFile] = []

        self._configure_styles()
        self._build_ui()
        self.ensure_schema()
        self.load_cached_files()
        self.refresh_results()
        if self.source_var.get():
            self.after(250, self.discover_logs)

    def resolve_evidence_root(self) -> str:
        candidates: list[str] = []
        if CASE_DB and CASE_DB.exists() and ENV_EVIDENCE_ID.isdigit():
            try:
                with sqlite3.connect(CASE_DB) as con:
                    table = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND lower(name)='evidence'").fetchone()
                    if table:
                        columns = {r[1].lower(): r[1] for r in con.execute(f'PRAGMA table_info("{table[0]}")')}
                        id_col = next((columns[x] for x in ("id", "evidence_id", "evidenceid") if x in columns), None)
                        path_cols = [columns[x] for x in ("mounted_volume", "mount_path", "mounted_path", "volume_root", "evidence_root", "root_path") if x in columns]
                        if id_col and path_cols:
                            row = con.execute(
                                f'SELECT {", ".join(chr(34)+x+chr(34) for x in path_cols)} FROM "{table[0]}" WHERE "{id_col}"=?',
                                (int(ENV_EVIDENCE_ID),),
                            ).fetchone()
                            if row:
                                candidates.extend(str(x).strip() for x in row if x)
            except Exception:
                pass
        if ENV_EVIDENCE_ROOT:
            candidates.append(ENV_EVIDENCE_ROOT)
        for item in candidates:
            p = Path(item)
            if p.exists():
                return str(p)
        return candidates[0] if candidates else ""

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=25, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=COLORS["slate"], foreground="white", font=("Segoe UI", 9, "bold"))
        style.configure("TNotebook.Tab", padding=(12, 7), font=("Segoe UI", 10))

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=COLORS["navy"], height=90)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text=APP_NAME, bg=COLORS["navy"], fg="white", font=("Segoe UI", 24, "bold")).pack(side="left", padx=22)
        tk.Label(header, text=f"v{APP_VERSION}", bg=COLORS["navy"], fg="#9db5c8", font=("Segoe UI", 11)).pack(side="left", pady=(18, 0))

        source = tk.Frame(self, bg=COLORS["white"], padx=18, pady=14)
        source.pack(fill="x", padx=8, pady=(18, 8))
        tk.Label(source, text="Evidence root:", bg="white", fg=COLORS["text"], font=("Segoe UI", 10)).pack(side="left")
        tk.Entry(source, textvariable=self.source_var, font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True, padx=10)
        ttk.Button(source, text="Browse", command=self.browse_root).pack(side="left", padx=3)
        ttk.Button(source, text="Discover Logs", command=self.discover_logs).pack(side="left", padx=3)
        ttk.Button(source, text="Parse All", command=self.parse_all).pack(side="left", padx=3)
        ttk.Button(source, text="Stop", command=self.stop_work).pack(side="left", padx=3)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self.summary_tab = tk.Frame(self.notebook, bg=COLORS["panel"])
        self.logs_tab = tk.Frame(self.notebook, bg=COLORS["panel"])
        self.results_tab = tk.Frame(self.notebook, bg=COLORS["panel"])
        self.errors_tab = tk.Frame(self.notebook, bg=COLORS["panel"])
        self.notebook.add(self.summary_tab, text="Summary")
        self.notebook.add(self.logs_tab, text="Log Files")
        self.notebook.add(self.results_tab, text="Events")
        self.notebook.add(self.errors_tab, text="Errors")
        self._build_summary()
        self._build_logs()
        self._build_results()
        self._build_errors()

        footer = tk.Frame(self, bg=COLORS["white"], padx=12, pady=8)
        footer.pack(fill="x")
        ttk.Progressbar(footer, variable=self.progress_var, maximum=100).pack(side="left", fill="x", expand=True, padx=(0, 12))
        tk.Label(footer, textvariable=self.status_var, bg="white", fg=COLORS["muted"], anchor="w").pack(side="left")

    def _metric_card(self, parent, title: str, variable: tk.StringVar) -> None:
        card = tk.Frame(parent, bg="white", highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(side="left", fill="both", expand=True, padx=6)
        tk.Label(card, textvariable=variable, bg="white", fg="#000", font=("Segoe UI", 24, "bold")).pack(anchor="w", padx=25, pady=(24, 4))
        tk.Label(card, text=title, bg="white", fg=COLORS["muted"], font=("Segoe UI", 10)).pack(anchor="w", padx=25, pady=(0, 20))

    def _build_summary(self) -> None:
        metrics = tk.Frame(self.summary_tab, bg=COLORS["panel"])
        metrics.pack(fill="x", padx=12, pady=16)
        self._metric_card(metrics, "Log Files Found", self.files_count_var)
        self._metric_card(metrics, "Events Parsed", self.events_count_var)
        self._metric_card(metrics, "Errors", self.errors_count_var)

        frame = tk.LabelFrame(self.summary_tab, text="Important Event Categories", bg="white", fg=COLORS["text"], font=("Segoe UI", 12, "bold"), padx=12, pady=12)
        frame.pack(fill="both", expand=True, padx=18, pady=4)
        columns = ("category", "events", "description")
        self.category_tree = ttk.Treeview(frame, columns=columns, show="headings")
        for name, width in (("category", 220), ("events", 100), ("description", 800)):
            self.category_tree.heading(name, text=name.title())
            self.category_tree.column(name, width=width, anchor="w")
        self.category_tree.pack(fill="both", expand=True)

    def _build_logs(self) -> None:
        toolbar = tk.Frame(self.logs_tab, bg=COLORS["panel"])
        toolbar.pack(fill="x", padx=12, pady=10)
        ttk.Button(toolbar, text="Parse Selected", command=self.parse_selected).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Export File List", command=self.export_file_list).pack(side="left", padx=3)
        cols = ("channel", "size", "modified", "status", "events", "path")
        self.log_tree = ttk.Treeview(self.logs_tab, columns=cols, show="headings", selectmode="extended")
        widths = {"channel":240, "size":100, "modified":170, "status":110, "events":90, "path":700}
        for c in cols:
            self.log_tree.heading(c, text=c.title())
            self.log_tree.column(c, width=widths[c], anchor="w")
        self.log_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_results(self) -> None:
        toolbar = tk.Frame(self.results_tab, bg=COLORS["panel"])
        toolbar.pack(fill="x", padx=12, pady=10)
        tk.Label(toolbar, text="Search:", bg=COLORS["panel"]).pack(side="left")
        search = tk.Entry(toolbar, textvariable=self.search_var, width=35)
        search.pack(side="left", padx=5)
        search.bind("<Return>", lambda _e: self.refresh_results())
        tk.Label(toolbar, text="Channel:", bg=COLORS["panel"]).pack(side="left", padx=(12, 0))
        self.channel_combo = ttk.Combobox(toolbar, textvariable=self.channel_var, values=["All"], width=28, state="readonly")
        self.channel_combo.pack(side="left", padx=5)
        tk.Label(toolbar, text="Level:", bg=COLORS["panel"]).pack(side="left", padx=(12, 0))
        ttk.Combobox(toolbar, textvariable=self.level_var, values=["All", "Critical", "Error", "Warning", "Information", "Verbose", "LogAlways"], width=16, state="readonly").pack(side="left", padx=5)
        ttk.Button(toolbar, text="Apply", command=self.refresh_results).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Clear", command=self.clear_filters).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Export CSV", command=self.export_events).pack(side="right", padx=3)

        cols = ("time", "channel", "event_id", "level", "provider", "computer", "user", "record_id", "message")
        self.events_tree = ttk.Treeview(self.results_tab, columns=cols, show="headings")
        widths = {"time":175, "channel":190, "event_id":75, "level":90, "provider":180, "computer":150, "user":160, "record_id":90, "message":650}
        for c in cols:
            self.events_tree.heading(c, text=c.replace("_", " ").title())
            self.events_tree.column(c, width=widths[c], anchor="w")
        self.events_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.events_tree.bind("<Double-1>", self.show_event_details)

    def _build_errors(self) -> None:
        cols = ("time", "path", "type", "message")
        self.error_tree = ttk.Treeview(self.errors_tab, columns=cols, show="headings")
        for c, w in (("time",170), ("path",550), ("type",140), ("message",700)):
            self.error_tree.heading(c, text=c.title())
            self.error_tree.column(c, width=w, anchor="w")
        self.error_tree.pack(fill="both", expand=True, padx=12, pady=12)

    def db_path(self) -> Path:
        if CASE_DB:
            return CASE_DB
        return Path(tempfile.gettempdir()) / "fft_windows_event_logs.sqlite"

    def evidence_id(self) -> int:
        return int(ENV_EVIDENCE_ID) if ENV_EVIDENCE_ID.isdigit() else 0

    def ensure_schema(self) -> None:
        with sqlite3.connect(self.db_path()) as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS windows_log_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL DEFAULT 0,
                channel TEXT, file_path TEXT NOT NULL,
                file_size INTEGER, modified_utc TEXT,
                parse_status TEXT NOT NULL DEFAULT 'Discovered',
                event_count INTEGER NOT NULL DEFAULT 0,
                file_hash_sha256 TEXT,
                discovered_utc TEXT NOT NULL,
                parsed_utc TEXT,
                UNIQUE(evidence_id, file_path)
            );
            CREATE TABLE IF NOT EXISTS windows_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL DEFAULT 0,
                log_file_id INTEGER,
                channel TEXT, provider TEXT, event_id INTEGER,
                qualifiers TEXT, level INTEGER, level_name TEXT,
                task TEXT, opcode TEXT, keywords TEXT,
                time_created_utc TEXT, record_id INTEGER,
                computer TEXT, user_sid TEXT, process_id TEXT, thread_id TEXT,
                activity_id TEXT, related_activity_id TEXT,
                message TEXT, event_data_json TEXT, xml TEXT,
                imported_utc TEXT NOT NULL,
                UNIQUE(evidence_id, channel, record_id, time_created_utc, event_id, provider)
            );
            CREATE TABLE IF NOT EXISTS windows_log_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL DEFAULT 0,
                file_path TEXT, error_type TEXT, error_message TEXT,
                recorded_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_events_time ON windows_events(time_created_utc);
            CREATE INDEX IF NOT EXISTS idx_windows_events_event_id ON windows_events(event_id);
            CREATE INDEX IF NOT EXISTS idx_windows_events_channel ON windows_events(channel);
            CREATE INDEX IF NOT EXISTS idx_windows_events_level ON windows_events(level_name);
            CREATE INDEX IF NOT EXISTS idx_windows_events_provider ON windows_events(provider);
            """)
            con.commit()

    def browse_root(self) -> None:
        selected = filedialog.askdirectory(title="Select mounted Windows volume or folder")
        if selected:
            self.source_var.set(selected)

    def discover_logs(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        root = Path(self.source_var.get().strip())
        if not root.exists():
            messagebox.showerror(APP_NAME, "The evidence root does not exist.")
            return
        self.cancel_event.clear()
        self.status_var.set("Discovering Windows event log files...")
        self.progress_var.set(0)
        self.worker = threading.Thread(target=self._discover_worker, args=(root,), daemon=True)
        self.worker.start()

    def _discover_worker(self, root: Path) -> None:
        found: list[LogFile] = []
        errors = 0
        candidates = [root / "Windows" / "System32" / "winevt" / "Logs"]
        if root.name.lower() == "logs" or root.suffix.lower() in (".evtx", ".evt"):
            candidates.insert(0, root)
        try:
            paths: list[Path] = []
            for candidate in candidates:
                if candidate.is_file():
                    paths.append(candidate)
                elif candidate.is_dir():
                    paths.extend(candidate.glob("*.evtx"))
                    paths.extend(candidate.glob("*.evt"))
            if not paths:
                paths = list(root.rglob("*.evtx")) + list(root.rglob("*.evt"))
            total = max(1, len(paths))
            with sqlite3.connect(self.db_path()) as con:
                for index, path in enumerate(sorted(set(paths)), 1):
                    if self.cancel_event.is_set():
                        break
                    try:
                        stat = path.stat()
                        channel = self.channel_from_filename(path.name)
                        modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds")
                        item = LogFile(path, channel, stat.st_size, modified)
                        found.append(item)
                        con.execute("""
                            INSERT INTO windows_log_files(evidence_id, channel, file_path, file_size, modified_utc, discovered_utc)
                            VALUES(?,?,?,?,?,?)
                            ON CONFLICT(evidence_id,file_path) DO UPDATE SET
                              channel=excluded.channel,file_size=excluded.file_size,modified_utc=excluded.modified_utc,
                              discovered_utc=excluded.discovered_utc
                        """, (self.evidence_id(), channel, str(path), stat.st_size, modified, utc_now()))
                    except Exception as exc:
                        errors += 1
                        self.record_error(str(path), exc, con)
                    if index % 20 == 0 or index == total:
                        self.after(0, self._set_progress, index * 100 / total, f"Discovered {index:,} of {total:,} files")
                con.commit()
        except Exception as exc:
            errors += 1
            self.record_error(str(root), exc)
        self.log_files = found
        self.after(0, self._after_discovery, len(found), errors)

    @staticmethod
    def channel_from_filename(name: str) -> str:
        base = Path(name).stem
        return base.replace("%4", "/")

    def _after_discovery(self, count: int, errors: int) -> None:
        self.status_var.set(f"Discovery complete: {count:,} event log files found")
        self.progress_var.set(100)
        self.load_cached_files()
        self.refresh_summary()
        self.refresh_errors()
        self.notebook.select(self.summary_tab)
        self.update_idletasks()

    def load_cached_files(self) -> None:
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        channels = ["All"]
        with sqlite3.connect(self.db_path()) as con:
            rows = con.execute("""
                SELECT id,channel,file_size,modified_utc,parse_status,event_count,file_path
                FROM windows_log_files WHERE evidence_id=? ORDER BY channel,file_path
            """, (self.evidence_id(),)).fetchall()
        for row in rows:
            self.log_tree.insert("", "end", iid=str(row[0]), values=(row[1], f"{row[2]:,}", row[3], row[4], row[5], row[6]))
            if row[1] and row[1] not in channels:
                channels.append(row[1])
        self.channel_combo["values"] = channels
        if self.channel_var.get() not in channels:
            self.channel_var.set("All")
        self.refresh_summary()

    def parse_all(self) -> None:
        ids = list(self.log_tree.get_children())
        self._start_parse(ids)

    def parse_selected(self) -> None:
        ids = list(self.log_tree.selection())
        if not ids:
            messagebox.showinfo(APP_NAME, "Select one or more log files first.")
            return
        self._start_parse(ids)

    def _start_parse(self, ids: list[str]) -> None:
        if self.worker and self.worker.is_alive():
            return
        if not ids:
            messagebox.showinfo(APP_NAME, "No Windows event log files have been discovered.")
            return
        self.cancel_event.clear()
        self.worker = threading.Thread(target=self._parse_worker, args=(ids,), daemon=True)
        self.worker.start()

    def _parse_worker(self, ids: list[str]) -> None:
        total = len(ids)
        self.after(0, self.status_var.set, f"Parsing {total:,} log files...")
        for index, file_id in enumerate(ids, 1):
            if self.cancel_event.is_set():
                break
            with sqlite3.connect(self.db_path()) as con:
                row = con.execute("SELECT file_path,channel FROM windows_log_files WHERE id=?", (int(file_id),)).fetchone()
            if not row:
                continue
            path, channel = Path(row[0]), row[1]
            try:
                count = self.parse_evtx(path, int(file_id), channel)
                with sqlite3.connect(self.db_path()) as con:
                    con.execute("UPDATE windows_log_files SET parse_status='Parsed',event_count=?,parsed_utc=? WHERE id=?", (count, utc_now(), int(file_id)))
                    con.commit()
            except Exception as exc:
                self.record_error(str(path), exc)
                with sqlite3.connect(self.db_path()) as con:
                    con.execute("UPDATE windows_log_files SET parse_status='Error' WHERE id=?", (int(file_id),))
                    con.commit()
            self.after(0, self._set_progress, index * 100 / total, f"Parsed {index:,} of {total:,}: {path.name}")
        self.after(0, self._after_parse)

    def parse_evtx(self, path: Path, log_file_id: int, channel_hint: str) -> int:
        if path.suffix.lower() == ".evt":
            raise RuntimeError("Legacy .evt files are identified but not parsed by Windows Event Log Explorer v1.0.")
        xml_documents = self.read_evtx_xml(path)
        count = 0
        with sqlite3.connect(self.db_path()) as con:
            for xml in xml_documents:
                if self.cancel_event.is_set():
                    break
                try:
                    event = self.parse_event_xml(xml, channel_hint)
                    con.execute("""
                    INSERT OR IGNORE INTO windows_events(
                      evidence_id,log_file_id,channel,provider,event_id,qualifiers,level,level_name,
                      task,opcode,keywords,time_created_utc,record_id,computer,user_sid,process_id,
                      thread_id,activity_id,related_activity_id,message,event_data_json,xml,imported_utc)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        self.evidence_id(), log_file_id, event["channel"], event["provider"], event["event_id"],
                        event["qualifiers"], event["level"], event["level_name"], event["task"], event["opcode"],
                        event["keywords"], event["time_created_utc"], event["record_id"], event["computer"],
                        event["user_sid"], event["process_id"], event["thread_id"], event["activity_id"],
                        event["related_activity_id"], event["message"], json.dumps(event["event_data"], ensure_ascii=False),
                        xml, utc_now(),
                    ))
                    count += con.total_changes > 0
                except Exception as exc:
                    self.record_error(str(path), exc, con)
            con.commit()
        return int(count)

    def read_evtx_xml(self, path: Path):
        # wevtutil is built into Windows and can read offline EVTX files without third-party packages.
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            process = subprocess.Popen(
                ["wevtutil", "qe", str(path), "/lf:true", "/f:xml", "/rd:false"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                encoding="utf-8", errors="replace", creationflags=flags,
            )
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise RuntimeError(stderr.strip() or f"wevtutil failed with exit code {process.returncode}")
            wrapped = stdout.strip()
            if not wrapped:
                return []
            # qe /f:xml usually emits a QueryList wrapper; tolerate concatenated Event documents.
            try:
                root = ET.fromstring(wrapped)
                if local_name(root.tag) == "Event":
                    return [ET.tostring(root, encoding="unicode")]
                return [ET.tostring(node, encoding="unicode") for node in root.iter() if local_name(node.tag) == "Event"]
            except ET.ParseError:
                documents = []
                start = 0
                while True:
                    pos = wrapped.find("<Event", start)
                    if pos < 0:
                        break
                    end = wrapped.find("</Event>", pos)
                    if end < 0:
                        break
                    documents.append(wrapped[pos:end + 8])
                    start = end + 8
                return documents
        try:
            from Evtx.Evtx import Evtx  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Parsing EVTX files requires Windows wevtutil or the optional python-evtx package.") from exc
        with Evtx(str(path)) as log:
            return [record.xml() for record in log.records()]

    def parse_event_xml(self, xml: str, channel_hint: str) -> dict:
        root = ET.fromstring(xml)
        system = root.find("e:System", NS)
        if system is None:
            system = next((n for n in root if local_name(n.tag) == "System"), None)
        if system is None:
            raise ValueError("Event XML does not contain a System section")

        def child(name: str):
            return next((n for n in system if local_name(n.tag) == name), None)
        def text(name: str) -> str:
            node = child(name)
            return clean_text(node.text if node is not None else "")

        provider_node = child("Provider")
        time_node = child("TimeCreated")
        exec_node = child("Execution")
        corr_node = child("Correlation")
        security_node = child("Security")
        event_id_node = child("EventID")
        level_text = text("Level")
        level = int(level_text) if level_text.isdigit() else 0
        event_data: dict[str, object] = {}
        unnamed = 0
        for section in root:
            if local_name(section.tag) not in ("EventData", "UserData"):
                continue
            for node in section.iter():
                if node is section:
                    continue
                name = node.attrib.get("Name") or local_name(node.tag)
                if name == "Data" and not node.attrib.get("Name"):
                    name = f"Data{unnamed}"
                    unnamed += 1
                value = clean_text(node.text)
                if value:
                    if name in event_data:
                        old = event_data[name]
                        event_data[name] = old + [value] if isinstance(old, list) else [old, value]
                    else:
                        event_data[name] = value
        message = self.build_message(event_data)
        return {
            "channel": text("Channel") or channel_hint,
            "provider": provider_node.attrib.get("Name", "") if provider_node is not None else "",
            "event_id": int(clean_text(event_id_node.text)) if event_id_node is not None and clean_text(event_id_node.text).isdigit() else 0,
            "qualifiers": event_id_node.attrib.get("Qualifiers", "") if event_id_node is not None else "",
            "level": level, "level_name": LEVEL_NAMES.get(level, str(level)),
            "task": text("Task"), "opcode": text("Opcode"), "keywords": text("Keywords"),
            "time_created_utc": time_node.attrib.get("SystemTime", "") if time_node is not None else "",
            "record_id": int(text("EventRecordID")) if text("EventRecordID").isdigit() else 0,
            "computer": text("Computer"),
            "user_sid": security_node.attrib.get("UserID", "") if security_node is not None else "",
            "process_id": exec_node.attrib.get("ProcessID", "") if exec_node is not None else "",
            "thread_id": exec_node.attrib.get("ThreadID", "") if exec_node is not None else "",
            "activity_id": corr_node.attrib.get("ActivityID", "") if corr_node is not None else "",
            "related_activity_id": corr_node.attrib.get("RelatedActivityID", "") if corr_node is not None else "",
            "message": message, "event_data": event_data,
        }

    @staticmethod
    def build_message(data: dict[str, object]) -> str:
        return "; ".join(f"{key}={value}" for key, value in data.items())[:4000]

    def _after_parse(self) -> None:
        self.status_var.set("Parsing complete")
        self.progress_var.set(100)
        self.load_cached_files()
        self.refresh_results()
        self.refresh_errors()
        self.refresh_summary()
        self.notebook.select(self.results_tab)
        self.update_idletasks()

    def stop_work(self) -> None:
        self.cancel_event.set()
        self.status_var.set("Stopping after the current item...")

    def _set_progress(self, value: float, text: str) -> None:
        self.progress_var.set(value)
        self.status_var.set(text)
        self.update_idletasks()

    def record_error(self, path: str, exc: BaseException, con: Optional[sqlite3.Connection] = None) -> None:
        own = con is None
        connection = con or sqlite3.connect(self.db_path())
        connection.execute("INSERT INTO windows_log_errors(evidence_id,file_path,error_type,error_message,recorded_utc) VALUES(?,?,?,?,?)",
                           (self.evidence_id(), path, type(exc).__name__, str(exc), utc_now()))
        if own:
            connection.commit(); connection.close()

    def refresh_summary(self) -> None:
        with sqlite3.connect(self.db_path()) as con:
            files = con.execute("SELECT COUNT(*) FROM windows_log_files WHERE evidence_id=?", (self.evidence_id(),)).fetchone()[0]
            events = con.execute("SELECT COUNT(*) FROM windows_events WHERE evidence_id=?", (self.evidence_id(),)).fetchone()[0]
            errors = con.execute("SELECT COUNT(*) FROM windows_log_errors WHERE evidence_id=?", (self.evidence_id(),)).fetchone()[0]
            categories = [
                ("Logon successes", "Security", 4624, "Successful account logons"),
                ("Logon failures", "Security", 4625, "Failed account logons"),
                ("Account creation", "Security", 4720, "User accounts created"),
                ("Process creation", "Security", 4688, "New processes, when process auditing is enabled"),
                ("Service installation", "System", 7045, "New Windows services installed"),
                ("System startup", "System", 6005, "Event Log service start / system startup indicator"),
                ("System shutdown", "System", 6006, "Event Log service stop / clean shutdown indicator"),
                ("Unexpected shutdown", "System", 6008, "Unexpected system shutdown"),
                ("Log cleared", "Security", 1102, "Security audit log cleared"),
                ("PowerShell script blocks", "Microsoft-Windows-PowerShell/Operational", 4104, "PowerShell script block logging"),
            ]
            results = []
            for label, channel, event_id, desc in categories:
                cnt = con.execute("SELECT COUNT(*) FROM windows_events WHERE evidence_id=? AND channel=? AND event_id=?", (self.evidence_id(), channel, event_id)).fetchone()[0]
                results.append((label, cnt, desc))
        self.files_count_var.set(f"{files:,}")
        self.events_count_var.set(f"{events:,}")
        self.errors_count_var.set(f"{errors:,}")
        for item in self.category_tree.get_children(): self.category_tree.delete(item)
        for row in results: self.category_tree.insert("", "end", values=row)

    def refresh_results(self) -> None:
        for item in self.events_tree.get_children(): self.events_tree.delete(item)
        query = """SELECT id,time_created_utc,channel,event_id,level_name,provider,computer,user_sid,record_id,message
                   FROM windows_events WHERE evidence_id=?"""
        params: list[object] = [self.evidence_id()]
        if self.channel_var.get() != "All":
            query += " AND channel=?"; params.append(self.channel_var.get())
        if self.level_var.get() != "All":
            query += " AND level_name=?"; params.append(self.level_var.get())
        term = self.search_var.get().strip()
        if term:
            query += " AND (message LIKE ? OR provider LIKE ? OR computer LIKE ? OR user_sid LIKE ? OR CAST(event_id AS TEXT) LIKE ?)"
            params.extend([f"%{term}%"] * 5)
        query += " ORDER BY time_created_utc DESC LIMIT 10000"
        with sqlite3.connect(self.db_path()) as con:
            rows = con.execute(query, params).fetchall()
        for r in rows:
            self.events_tree.insert("", "end", iid=str(r[0]), values=r[1:])
        self.refresh_summary()

    def refresh_errors(self) -> None:
        for item in self.error_tree.get_children(): self.error_tree.delete(item)
        with sqlite3.connect(self.db_path()) as con:
            rows = con.execute("SELECT recorded_utc,file_path,error_type,error_message FROM windows_log_errors WHERE evidence_id=? ORDER BY id DESC", (self.evidence_id(),)).fetchall()
        for row in rows: self.error_tree.insert("", "end", values=row)

    def clear_filters(self) -> None:
        self.search_var.set(""); self.channel_var.set("All"); self.level_var.set("All"); self.refresh_results()

    def show_event_details(self, _event=None) -> None:
        selected = self.events_tree.selection()
        if not selected: return
        with sqlite3.connect(self.db_path()) as con:
            row = con.execute("SELECT xml,event_data_json FROM windows_events WHERE id=?", (int(selected[0]),)).fetchone()
        if not row: return
        win = tk.Toplevel(self); win.title("Event Details"); win.geometry("1000x700")
        notebook = ttk.Notebook(win); notebook.pack(fill="both", expand=True)
        for title, content in (("Event Data", json.dumps(json.loads(row[1] or "{}"), indent=2, ensure_ascii=False)), ("Raw XML", row[0] or "")):
            frame = tk.Frame(notebook); notebook.add(frame, text=title)
            text = tk.Text(frame, wrap="none", font=("Consolas", 10)); text.pack(fill="both", expand=True)
            text.insert("1.0", content); text.configure(state="disabled")

    def export_events(self) -> None:
        target = filedialog.asksaveasfilename(title="Export Windows events", defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not target: return
        query = "SELECT time_created_utc,channel,event_id,level_name,provider,computer,user_sid,record_id,message,event_data_json,file_path FROM windows_events LEFT JOIN windows_log_files ON windows_events.log_file_id=windows_log_files.id WHERE windows_events.evidence_id=? ORDER BY time_created_utc"
        with sqlite3.connect(self.db_path()) as con, open(target, "w", newline="", encoding="utf-8-sig") as out:
            writer = csv.writer(out); writer.writerow(["TimeCreatedUTC","Channel","EventID","Level","Provider","Computer","UserSID","RecordID","Message","EventDataJSON","SourceFile"])
            writer.writerows(con.execute(query, (self.evidence_id(),)))
        messagebox.showinfo(APP_NAME, f"Exported events to:\n{target}")

    def export_file_list(self) -> None:
        target = filedialog.asksaveasfilename(title="Export log file list", defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not target: return
        with sqlite3.connect(self.db_path()) as con, open(target, "w", newline="", encoding="utf-8-sig") as out:
            writer = csv.writer(out); writer.writerow(["Channel","Path","Size","ModifiedUTC","ParseStatus","EventCount"])
            writer.writerows(con.execute("SELECT channel,file_path,file_size,modified_utc,parse_status,event_count FROM windows_log_files WHERE evidence_id=? ORDER BY channel", (self.evidence_id(),)))
        messagebox.showinfo(APP_NAME, f"Exported log file list to:\n{target}")


def main() -> None:
    try:
        app = WindowsEventLogExplorer()
        app.mainloop()
    except Exception:
        traceback.print_exc()
        try: messagebox.showerror(APP_NAME, traceback.format_exc())
        except Exception: pass


if __name__ == "__main__":
    main()
