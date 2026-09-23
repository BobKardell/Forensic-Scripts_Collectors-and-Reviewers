#!/usr/bin/env python3
# FFT_TOOL
# TITLE: File Explorer
# ID: file_explorer
# CATEGORY: Explorers
# VERSION: 3.0.0
# DESCRIPTION: Combined live-evidence, indexed-database, and bookmark explorer.
# ICON: 📁
# PASS_CASE_ARGUMENTS: false

from __future__ import annotations

import csv
import hashlib
import mimetypes
import os
import sqlite3
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Iterable, Optional

APP_NAME = "Fraud Fighter File Explorer"
APP_VERSION = "3.0"

COLORS = {
    "navy": "#061522", "slate": "#587795", "slate_dark": "#3e5c78",
    "slate_light": "#dce7f0", "blue": "#188bd0", "panel": "#f2f6f9",
    "white": "#ffffff", "text": "#172431", "muted": "#607180",
}

TEXT_EXTENSIONS = {
    ".txt", ".csv", ".log", ".json", ".xml", ".html", ".htm", ".ini", ".cfg",
    ".conf", ".yaml", ".yml", ".py", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".css", ".sql", ".reg", ".eml", ".md", ".rtf",
}

DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 5000

COLUMN_CANDIDATES = {
    "id": ("id", "file_id", "inventory_id"),
    "evidence_id": ("evidence_id", "evidence", "source_id"),
    "name": ("filename", "file_name", "name"),
    "extension": ("extension", "ext", "file_extension"),
    "category": ("category", "file_category", "type_category"),
    "size": ("size_bytes", "file_size", "size", "length"),
    "created": ("created_utc", "created_time", "creation_time", "created"),
    "modified": ("modified_utc", "modified_time", "last_write_time", "modified"),
    "accessed": ("accessed_utc", "accessed_time", "last_access_time", "accessed"),
    "directory": ("directory", "parent_path", "folder"),
    "path": ("full_path", "file_path", "stored_path", "path"),
    "md5": ("md5", "md5_hash"),
    "sha1": ("sha1", "sha1_hash"),
    "sha256": ("sha256", "sha256_hash"),
    "error": ("error", "scan_error", "hash_error"),
    "reviewed": ("reviewed", "review_status"),
    "notes": ("notes", "note"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def human_size(value: Any) -> str:
    try:
        size = int(value or 0)
    except (TypeError, ValueError):
        return str(value or "")
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    amount = float(size)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:,.0f} {unit}" if unit == "B" else f"{amount:,.2f} {unit}"
        amount /= 1024
    return f"{size:,} B"


def format_timestamp(value: float) -> str:
    try:
        return datetime.fromtimestamp(value).astimezone().isoformat(sep=" ", timespec="seconds")
    except Exception:
        return ""


def file_attributes(path: Path) -> str:
    attributes = []
    try:
        attrs = getattr(path.stat(), "st_file_attributes", 0)
        for mask, name in (
            (0x1, "Read-only"), (0x2, "Hidden"), (0x4, "System"),
            (0x20, "Archive"), (0x800, "Compressed"),
            (0x1000, "Offline"), (0x4000, "Encrypted"),
        ):
            if attrs & mask:
                attributes.append(name)
    except Exception:
        pass
    return ", ".join(attributes)


def calculate_hashes(path: Path) -> dict[str, str]:
    hashers = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            for hasher in hashers.values():
                hasher.update(block)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


class FileExplorerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.case_db = Path(os.environ["FFT_CASE_DB"]) if os.environ.get("FFT_CASE_DB") else None
        self.case_folder = Path(os.environ["FFT_CASE_FOLDER"]) if os.environ.get("FFT_CASE_FOLDER") else None
        self.case_name = os.environ.get("FFT_CASE_NAME", "Standalone Session")
        self.case_number = os.environ.get("FFT_CASE_NUMBER", "")
        self.examiner = os.environ.get("FFT_EXAMINER", "")
        self.evidence_id = self._safe_int(os.environ.get("FFT_EVIDENCE_ID", ""))

        self.root_folder = self._initial_root()
        self.current_folder = self.root_folder
        self.current_file: Optional[Path] = None
        self.folder_nodes: dict[str, Path] = {}
        self.hash_cache: dict[str, dict[str, str]] = {}
        self.preview_limit = 2 * 1024 * 1024

        self.db_conn: Optional[sqlite3.Connection] = None
        self.db_schema: dict[str, str] = {}
        self.db_rows: list[sqlite3.Row] = []
        self.db_offset = 0
        self.db_total = 0
        self.db_sort_key = "modified"
        self.db_sort_desc = True

        self.status_var = tk.StringVar(value="Ready")
        self.live_search_var = tk.StringVar()
        self.live_path_var = tk.StringVar(value=str(self.current_folder))
        self.db_search_var = tk.StringVar()
        self.db_extension_var = tk.StringVar(value="All")
        self.db_category_var = tk.StringVar(value="All")
        self.db_min_size_var = tk.StringVar()
        self.db_max_size_var = tk.StringVar()
        self.db_page_size_var = tk.StringVar(value=str(DEFAULT_PAGE_SIZE))
        self.db_page_var = tk.StringVar(value="Page 1")
        self.bookmark_search_var = tk.StringVar()
        self.bookmark_category_var = tk.StringVar(value="All")

        self.title(f"{APP_NAME} v{APP_VERSION} — {self.case_name}")
        self.geometry("1600x950")
        self.minsize(1150, 720)
        self.configure(bg=COLORS["panel"])
        self._configure_styles()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.audit("FILE_EXPLORER_OPENED", "Opened combined File Explorer")
        self.load_root(self.root_folder)
        self.open_database(silent=True)
        self.refresh_bookmarks()

    @staticmethod
    def _safe_int(value: str) -> Optional[int]:
        try:
            return int(value) if value.strip() else None
        except (TypeError, ValueError):
            return None

    def _initial_root(self) -> Path:
        if self.case_db and self.case_db.exists():
            try:
                with sqlite3.connect(self.case_db) as conn:
                    conn.row_factory = sqlite3.Row
                    cols = [r[1] for r in conn.execute("PRAGMA table_info(evidence)")]
                    path_col = next((c for c in ("source_path", "stored_path", "path", "evidence_path") if c in cols), None)
                    if path_col:
                        if self.evidence_id is not None:
                            row = conn.execute(
                                f"SELECT {quote_identifier(path_col)} FROM evidence WHERE id=?",
                                (self.evidence_id,),
                            ).fetchone()
                        else:
                            row = conn.execute(
                                f"SELECT {quote_identifier(path_col)} FROM evidence ORDER BY id LIMIT 1"
                            ).fetchone()
                        if row and row[0] and Path(row[0]).exists():
                            p = Path(row[0])
                            return p if p.is_dir() else p.parent
            except Exception:
                pass
        if self.case_folder and (self.case_folder / "Evidence").exists():
            return self.case_folder / "Evidence"
        return Path.home()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 9))
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("White.TFrame", background=COLORS["white"])
        style.configure("Navy.TFrame", background=COLORS["navy"])
        style.configure("TLabel", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("White.TLabel", background=COLORS["white"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"])
        style.configure("Title.TLabel", background=COLORS["navy"], foreground=COLORS["white"], font=("Segoe UI Semibold", 16))
        style.configure("HeaderMeta.TLabel", background=COLORS["navy"], foreground="#c5d3df")
        style.configure("Primary.TButton", background=COLORS["blue"], foreground=COLORS["white"], padding=(12, 8), borderwidth=0)
        style.configure("Secondary.TButton", background=COLORS["slate"], foreground=COLORS["white"], padding=(11, 7), borderwidth=0)
        style.configure("Treeview", rowheight=25, background=COLORS["white"], fieldbackground=COLORS["white"])
        style.configure("Treeview.Heading", background=COLORS["slate"], foreground=COLORS["white"], font=("Segoe UI Semibold", 9), padding=(6, 6))
        style.configure("Explorer.TNotebook.Tab", padding=(18, 9), font=("Segoe UI Semibold", 10))

    def _build_ui(self) -> None:
        header = ttk.Frame(self, style="Navy.TFrame", padding=(18, 12))
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left")
        meta = self.case_name
        if self.case_number:
            meta += f" | {self.case_number}"
        if self.examiner:
            meta += f" | Examiner: {self.examiner}"
        ttk.Label(header, text=meta, style="HeaderMeta.TLabel").pack(side="right")

        self.main_notebook = ttk.Notebook(self, style="Explorer.TNotebook")
        self.main_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.live_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame")
        self.database_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame")
        self.bookmarks_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame")
        self.main_notebook.add(self.live_tab, text="Live Evidence")
        self.main_notebook.add(self.database_tab, text="Indexed Database")
        self.main_notebook.add(self.bookmarks_tab, text="Bookmarks")

        self._build_live_tab()
        self._build_database_tab()
        self._build_bookmarks_tab()

        status = ttk.Frame(self, style="Panel.TFrame", padding=(10, 5))
        status.pack(fill="x")
        ttk.Label(status, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=180)
        self.progress.pack(side="right")

    # ---------------- LIVE EVIDENCE ----------------

    def _build_live_tab(self) -> None:
        toolbar = ttk.Frame(self.live_tab, style="Panel.TFrame", padding=(12, 10))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Choose Root…", style="Primary.TButton", command=self.choose_root).pack(side="left")
        ttk.Button(toolbar, text="Up", style="Secondary.TButton", command=self.go_up).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Refresh", style="Secondary.TButton", command=self.refresh_live).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Hash Selected", style="Secondary.TButton", command=self.hash_selected).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Export CSV", style="Secondary.TButton", command=self.export_live_csv).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Find in Database", style="Secondary.TButton", command=self.find_live_in_database).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Bookmark", style="Secondary.TButton", command=self.bookmark_live_selected).pack(side="left", padx=(8, 0))

        ttk.Label(toolbar, text="Filter:", style="Muted.TLabel").pack(side="left", padx=(20, 5))
        entry = ttk.Entry(toolbar, textvariable=self.live_search_var, width=24)
        entry.pack(side="left")
        entry.bind("<KeyRelease>", lambda _e: self.populate_files(self.current_folder))
        ttk.Entry(toolbar, textvariable=self.live_path_var).pack(side="left", fill="x", expand=True, padx=(15, 0))
        ttk.Button(toolbar, text="Go", command=self.go_to_path).pack(side="left", padx=(5, 0))

        body = ttk.Panedwindow(self.live_tab, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        left = ttk.Frame(body, style="White.TFrame", width=300)
        center = ttk.Frame(body, style="White.TFrame")
        right = ttk.Frame(body, style="White.TFrame", width=470)
        body.add(left, weight=1); body.add(center, weight=3); body.add(right, weight=2)

        ttk.Label(left, text="Folders", style="White.TLabel", font=("Segoe UI Semibold", 11)).pack(anchor="w", padx=10, pady=(10, 5))
        self.folder_tree = ttk.Treeview(left, show="tree")
        sy = ttk.Scrollbar(left, orient="vertical", command=self.folder_tree.yview)
        self.folder_tree.configure(yscrollcommand=sy.set)
        self.folder_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=(0, 8))
        sy.pack(side="right", fill="y", pady=(0, 8))
        self.folder_tree.bind("<<TreeviewOpen>>", self.expand_folder)
        self.folder_tree.bind("<<TreeviewSelect>>", self.select_folder)

        ttk.Label(center, text="Files", style="White.TLabel", font=("Segoe UI Semibold", 11)).pack(anchor="w", padx=10, pady=(10, 5))
        columns = ("name", "size", "modified", "created", "type", "attributes")
        self.file_tree = ttk.Treeview(center, columns=columns, show="headings", selectmode="browse")
        for c, label, width in (
            ("name","Name",310), ("size","Size",110), ("modified","Modified",170),
            ("created","Created",170), ("type","Type",120), ("attributes","Attributes",150)
        ):
            self.file_tree.heading(c, text=label, command=lambda col=c: self.sort_live(col, False))
            self.file_tree.column(c, width=width, anchor="w")
        sy2 = ttk.Scrollbar(center, orient="vertical", command=self.file_tree.yview)
        sx2 = ttk.Scrollbar(center, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=sy2.set, xscrollcommand=sx2.set)
        self.file_tree.pack(side="left", fill="both", expand=True, padx=(8,0), pady=(0,8))
        sy2.pack(side="right", fill="y", pady=(0,8))
        sx2.pack(side="bottom", fill="x", padx=8)
        self.file_tree.bind("<<TreeviewSelect>>", self.select_file)
        self.file_tree.bind("<Double-1>", self.open_live_selected)

        ttk.Label(right, text="File Details & Preview", style="White.TLabel", font=("Segoe UI Semibold", 11)).pack(anchor="w", padx=10, pady=(10,5))
        nb = ttk.Notebook(right)
        nb.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.live_details_text = self._text_tab(nb, "Properties")
        self.live_preview_text = self._text_tab(nb, "Preview")
        self.live_hex_text = self._text_tab(nb, "Hex")
        self.live_metadata_text = self._text_tab(nb, "Metadata")

    def _text_tab(self, notebook: ttk.Notebook, title: str) -> tk.Text:
        frame = ttk.Frame(notebook, style="White.TFrame", padding=8)
        notebook.add(frame, text=title)
        text = tk.Text(frame, wrap="none", state="disabled", bg=COLORS["white"], fg=COLORS["text"], font=("Consolas", 9))
        y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        text.grid(row=0, column=0, sticky="nsew"); y.grid(row=0,column=1,sticky="ns"); x.grid(row=1,column=0,sticky="ew")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        return text

    def load_root(self, folder: Path) -> None:
        if not folder.exists() or not folder.is_dir():
            messagebox.showerror("Invalid Folder", f"The folder does not exist:\n{folder}", parent=self)
            return
        self.root_folder = folder.resolve()
        self.current_folder = self.root_folder
        self.live_path_var.set(str(self.current_folder))
        self.folder_tree.delete(*self.folder_tree.get_children())
        self.folder_nodes.clear()
        root_id = self.folder_tree.insert("", "end", text=self.root_folder.name or str(self.root_folder), open=True)
        self.folder_nodes[root_id] = self.root_folder
        self.insert_folder_children(root_id, self.root_folder)
        self.folder_tree.selection_set(root_id)
        self.populate_files(self.root_folder)
        self.status_var.set(f"Live root: {self.root_folder}")

    def choose_root(self) -> None:
        selected = filedialog.askdirectory(parent=self, initialdir=str(self.current_folder))
        if selected:
            self.load_root(Path(selected))

    def go_up(self) -> None:
        parent = self.current_folder.parent
        if parent != self.current_folder:
            self.load_root(parent)

    def go_to_path(self) -> None:
        candidate = Path(self.live_path_var.get().strip())
        if candidate.exists() and candidate.is_dir():
            self.load_root(candidate)
        else:
            messagebox.showwarning("Invalid Path", "Enter an existing folder path.", parent=self)

    def refresh_live(self) -> None:
        self.load_root(self.root_folder)

    def insert_folder_children(self, node_id: str, folder: Path) -> None:
        for child in self.folder_tree.get_children(node_id):
            self.folder_tree.delete(child)
        try:
            for directory in sorted((p for p in folder.iterdir() if p.is_dir()), key=lambda p: p.name.lower()):
                child_id = self.folder_tree.insert(node_id, "end", text=directory.name)
                self.folder_nodes[child_id] = directory
                try:
                    if any(item.is_dir() for item in directory.iterdir()):
                        self.folder_tree.insert(child_id, "end", text="…")
                except Exception:
                    pass
        except Exception:
            pass

    def expand_folder(self, _event=None) -> None:
        item = self.folder_tree.focus()
        if item in self.folder_nodes:
            self.insert_folder_children(item, self.folder_nodes[item])

    def select_folder(self, _event=None) -> None:
        selection = self.folder_tree.selection()
        if selection and selection[0] in self.folder_nodes:
            folder = self.folder_nodes[selection[0]]
            self.current_folder = folder
            self.live_path_var.set(str(folder))
            self.populate_files(folder)

    def populate_files(self, folder: Path) -> None:
        self.file_tree.delete(*self.file_tree.get_children())
        filter_text = self.live_search_var.get().strip().lower()
        try:
            entries = sorted(folder.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except Exception as exc:
            self.status_var.set(f"Unable to read folder: {exc}")
            return
        count = 0
        for path in entries:
            if filter_text and filter_text not in path.name.lower():
                continue
            try:
                stat = path.stat()
                values = (
                    path.name, "" if path.is_dir() else human_size(stat.st_size),
                    format_timestamp(stat.st_mtime), format_timestamp(stat.st_ctime),
                    "Folder" if path.is_dir() else (path.suffix.lower().lstrip(".").upper() or "File"),
                    file_attributes(path),
                )
                iid = self.file_tree.insert("", "end", values=values, tags=(str(path),))
                count += 1
            except Exception:
                continue
        self.status_var.set(f"{count:,} item(s) in {folder}")

    def selected_live_path(self) -> Optional[Path]:
        selection = self.file_tree.selection()
        if not selection:
            return None
        tags = self.file_tree.item(selection[0]).get("tags", [])
        return Path(tags[0]) if tags else None

    def select_file(self, _event=None) -> None:
        path = self.selected_live_path()
        if not path:
            return
        self.current_file = path if path.is_file() else None
        try:
            stat = path.stat()
        except Exception:
            stat = None
        lines = [
            f"Name:       {path.name}", f"Full path:  {path}",
            f"Type:       {'Directory' if path.is_dir() else mimetypes.guess_type(path.name)[0] or path.suffix or 'Unknown'}"
        ]
        if stat:
            lines.extend([
                f"Size:       {stat.st_size:,} bytes ({human_size(stat.st_size)})",
                f"Created:    {format_timestamp(stat.st_ctime)}",
                f"Modified:   {format_timestamp(stat.st_mtime)}",
                f"Accessed:   {format_timestamp(stat.st_atime)}",
                f"Attributes: {file_attributes(path) or 'None detected'}",
            ])
        self.set_text(self.live_details_text, "\n".join(lines))
        cached = self.hash_cache.get(str(path), {})
        self.set_text(self.live_metadata_text, "\n".join([
            f"MD5:     {cached.get('md5','Not calculated')}",
            f"SHA1:    {cached.get('sha1','Not calculated')}",
            f"SHA256:  {cached.get('sha256','Not calculated')}",
        ]))
        if path.is_file():
            self.preview_file(path)
        else:
            self.set_text(self.live_preview_text, "")
            self.set_text(self.live_hex_text, "")

    def preview_file(self, path: Path) -> None:
        try:
            total = path.stat().st_size
            with path.open("rb") as handle:
                data = handle.read(min(total, self.preview_limit))
        except Exception as exc:
            self.set_text(self.live_preview_text, f"Unable to preview:\n{exc}")
            self.set_text(self.live_hex_text, "")
            return
        text = ""
        if path.suffix.lower() in TEXT_EXTENSIONS or b"\x00" not in data[:4096]:
            for enc in ("utf-8", "utf-16", "cp1252", "latin-1"):
                try:
                    text = data.decode(enc); break
                except UnicodeDecodeError:
                    continue
        if not text:
            text = "[Binary file — use Hex tab]"
        if total > len(data):
            text += f"\n\n[Preview truncated at {human_size(len(data))} of {human_size(total)}]"
        self.set_text(self.live_preview_text, text)
        lines = []
        for offset in range(0, min(len(data), 65536), 16):
            block = data[offset:offset+16]
            hp = " ".join(f"{b:02X}" for b in block)
            ap = "".join(chr(b) if 32 <= b < 127 else "." for b in block)
            lines.append(f"{offset:08X}  {hp:<47}  {ap}")
        self.set_text(self.live_hex_text, "\n".join(lines))

    def set_text(self, widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def open_live_selected(self, _event=None) -> None:
        path = self.selected_live_path()
        if not path:
            return
        if path.is_dir():
            self.current_folder = path
            self.live_path_var.set(str(path))
            self.populate_files(path)
            return
        self._open_external(path)

    def _open_external(self, path: Path, select: bool=False) -> None:
        try:
            if sys.platform.startswith("win"):
                if select:
                    subprocess.Popen(["explorer", "/select,", str(path)])
                else:
                    os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R" if select else str(path), str(path)] if select else ["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path.parent if select else path)])
        except Exception as exc:
            messagebox.showerror("Open Failed", str(exc), parent=self)

    def hash_selected(self) -> None:
        path = self.selected_live_path()
        if not path or not path.is_file():
            messagebox.showinfo("Select a File", "Select a file to calculate hashes.", parent=self)
            return
        def worker():
            self.after(0, lambda: self.progress.start(12))
            try:
                hashes = calculate_hashes(path)
                self.hash_cache[str(path)] = hashes
                self.after(0, self.select_file)
                self.after(0, lambda: self.status_var.set(f"Hashes calculated for {path.name}"))
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Hash Failed", str(exc), parent=self))
            finally:
                self.after(0, self.progress.stop)
        threading.Thread(target=worker, daemon=True).start()

    def export_live_csv(self) -> None:
        dest = filedialog.asksaveasfilename(parent=self, defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not dest:
            return
        with open(dest, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f); w.writerow(["Full Path","Name","Size","Modified","Created","Type","Attributes"])
            for iid in self.file_tree.get_children():
                item = self.file_tree.item(iid)
                tags = item.get("tags", [])
                w.writerow([tags[0] if tags else "", *item["values"]])
        self.status_var.set(f"Exported live listing to {dest}")

    def sort_live(self, column: str, reverse: bool) -> None:
        items = [(self.file_tree.set(i, column), i) for i in self.file_tree.get_children("")]
        items.sort(key=lambda p: p[0].lower(), reverse=reverse)
        for idx, (_, item) in enumerate(items):
            self.file_tree.move(item, "", idx)
        self.file_tree.heading(column, command=lambda: self.sort_live(column, not reverse))

    # ---------------- INDEXED DATABASE ----------------

    def _build_database_tab(self) -> None:
        filters = ttk.LabelFrame(self.database_tab, text="Search and Filters", padding=8)
        filters.pack(fill="x", padx=10, pady=10)
        filters.columnconfigure(1, weight=1)
        ttk.Label(filters, text="Search").grid(row=0,column=0,sticky="w")
        e = ttk.Entry(filters, textvariable=self.db_search_var)
        e.grid(row=0,column=1,sticky="ew",padx=(5,8))
        e.bind("<Return>", lambda _e: self.apply_db_filters())
        ttk.Label(filters,text="Extension").grid(row=0,column=2)
        self.db_extension_combo = ttk.Combobox(filters,textvariable=self.db_extension_var,state="readonly",width=14,values=("All",))
        self.db_extension_combo.grid(row=0,column=3,padx=5)
        ttk.Label(filters,text="Category").grid(row=0,column=4)
        self.db_category_combo = ttk.Combobox(filters,textvariable=self.db_category_var,state="readonly",width=16,values=("All",))
        self.db_category_combo.grid(row=0,column=5,padx=5)
        ttk.Label(filters,text="Min MB").grid(row=1,column=0,pady=(8,0))
        ttk.Entry(filters,textvariable=self.db_min_size_var,width=12).grid(row=1,column=1,sticky="w",pady=(8,0))
        ttk.Label(filters,text="Max MB").grid(row=1,column=2,pady=(8,0))
        ttk.Entry(filters,textvariable=self.db_max_size_var,width=12).grid(row=1,column=3,sticky="w",pady=(8,0))
        ttk.Button(filters,text="Apply",command=self.apply_db_filters).grid(row=1,column=4,sticky="ew",pady=(8,0))
        ttk.Button(filters,text="Clear",command=self.clear_db_filters).grid(row=1,column=5,sticky="ew",pady=(8,0),padx=(5,0))

        toolbar = ttk.Frame(self.database_tab, padding=(10,0,10,8))
        toolbar.pack(fill="x")
        ttk.Button(toolbar,text="Refresh",command=self.load_db_page).pack(side="left")
        ttk.Button(toolbar,text="Locate in Live Evidence",command=self.locate_db_in_live).pack(side="left",padx=5)
        ttk.Button(toolbar,text="Open File",command=self.open_db_selected).pack(side="left",padx=5)
        ttk.Button(toolbar,text="Bookmark",command=self.bookmark_db_selected).pack(side="left",padx=5)
        ttk.Button(toolbar,text="Export Page",command=self.export_db_page).pack(side="left",padx=5)
        ttk.Button(toolbar,text="Open Database…",command=self.choose_database).pack(side="right")

        pane = ttk.Panedwindow(self.database_tab, orient="vertical")
        pane.pack(fill="both", expand=True, padx=10, pady=(0,8))
        grid = ttk.Frame(pane); grid.rowconfigure(0,weight=1); grid.columnconfigure(0,weight=1)
        pane.add(grid,weight=4)
        cols=("name","extension","category","size","created","modified","accessed","md5","sha1","sha256","error","path")
        self.db_tree=ttk.Treeview(grid,columns=cols,show="headings",selectmode="extended")
        widths={"name":220,"extension":70,"category":110,"size":90,"created":145,"modified":145,"accessed":145,"md5":220,"sha1":250,"sha256":360,"error":180,"path":600}
        labels={"name":"Name","extension":"Ext","category":"Category","size":"Size","created":"Created","modified":"Modified","accessed":"Accessed","md5":"MD5","sha1":"SHA1","sha256":"SHA256","error":"Error","path":"Path"}
        for c in cols:
            self.db_tree.heading(c,text=labels[c],command=lambda k=c:self.sort_db(k))
            self.db_tree.column(c,width=widths[c],anchor="w")
        sy=ttk.Scrollbar(grid,orient="vertical",command=self.db_tree.yview); sx=ttk.Scrollbar(grid,orient="horizontal",command=self.db_tree.xview)
        self.db_tree.configure(yscrollcommand=sy.set,xscrollcommand=sx.set)
        self.db_tree.grid(row=0,column=0,sticky="nsew"); sy.grid(row=0,column=1,sticky="ns"); sx.grid(row=1,column=0,sticky="ew")
        self.db_tree.bind("<<TreeviewSelect>>",self.show_db_details)
        self.db_tree.bind("<Double-1>",lambda _e:self.open_db_selected())
        details_frame=ttk.LabelFrame(pane,text="Selected Database Record",padding=6)
        pane.add(details_frame,weight=1)
        details_frame.rowconfigure(0,weight=1);details_frame.columnconfigure(0,weight=1)
        self.db_details=tk.Text(details_frame,height=9,wrap="none",state="disabled")
        self.db_details.grid(row=0,column=0,sticky="nsew")

        nav=ttk.Frame(self.database_tab,padding=(10,0,10,8));nav.pack(fill="x")
        ttk.Button(nav,text="First",command=self.db_first).pack(side="left")
        ttk.Button(nav,text="Previous",command=self.db_previous).pack(side="left",padx=4)
        ttk.Label(nav,textvariable=self.db_page_var,width=18,anchor="center").pack(side="left")
        ttk.Button(nav,text="Next",command=self.db_next).pack(side="left")
        ttk.Label(nav,text="Rows").pack(side="left",padx=(10,3))
        cb=ttk.Combobox(nav,textvariable=self.db_page_size_var,state="readonly",values=("100","250","500","1000","2500","5000"),width=7)
        cb.pack(side="left");cb.bind("<<ComboboxSelected>>",lambda _e:self.apply_db_filters())

    def choose_database(self) -> None:
        selected=filedialog.askopenfilename(title="Select FFT Case Database",filetypes=[("SQLite","*.db *.sqlite *.sqlite3"),("All","*.*")])
        if selected:
            self.case_db=Path(selected);self.open_database()

    def open_database(self, silent: bool=False) -> None:
        if self.db_conn:
            self.db_conn.close();self.db_conn=None
        try:
            if not self.case_db or not self.case_db.exists():
                raise FileNotFoundError("No active case database is available.")
            self.db_conn=sqlite3.connect(self.case_db)
            self.db_conn.row_factory=sqlite3.Row
            self.db_conn.execute("SELECT 1 FROM file_inventory LIMIT 1")
            self._discover_db_schema()
            self._populate_db_filters()
            self.db_offset=0
            self.load_db_page()
        except Exception as exc:
            if not silent:
                messagebox.showerror("Indexed Database",str(exc),parent=self)
            self.status_var.set(f"Indexed database unavailable: {exc}")

    def _discover_db_schema(self) -> None:
        assert self.db_conn
        cols=[str(r["name"]) for r in self.db_conn.execute("PRAGMA table_info(file_inventory)")]
        lower={c.lower():c for c in cols}
        self.db_schema={}
        for logical,candidates in COLUMN_CANDIDATES.items():
            for c in candidates:
                if c.lower() in lower:
                    self.db_schema[logical]=lower[c.lower()];break
        if "name" not in self.db_schema and "path" not in self.db_schema:
            raise RuntimeError("file_inventory does not contain a recognized name or path column.")

    def _db_evidence_where(self) -> tuple[str,list[Any]]:
        if self.evidence_id is not None and "evidence_id" in self.db_schema:
            return f"WHERE {quote_identifier(self.db_schema['evidence_id'])}=?", [self.evidence_id]
        return "WHERE 1=1",[]

    def _distinct_db(self, logical: str, limit: int) -> tuple[str,...]:
        if not self.db_conn or logical not in self.db_schema:
            return ("All",)
        col=quote_identifier(self.db_schema[logical]);where,params=self._db_evidence_where()
        sql=f"SELECT DISTINCT {col} value FROM file_inventory {where} AND {col} IS NOT NULL AND TRIM(CAST({col} AS TEXT))<>'' ORDER BY value LIMIT ?"
        return tuple(["All",*[str(r["value"]) for r in self.db_conn.execute(sql,(*params,limit))]])

    def _populate_db_filters(self) -> None:
        self.db_extension_combo["values"]=self._distinct_db("extension",300)
        self.db_category_combo["values"]=self._distinct_db("category",200)
        self.db_category_combo.configure(state="readonly" if "category" in self.db_schema else "disabled")

    def _db_select(self, logical: str) -> str:
        if logical in self.db_schema:
            return f"{quote_identifier(self.db_schema[logical])} AS {quote_identifier(logical)}"
        if logical=="name" and "path" in self.db_schema:
            return f"{quote_identifier(self.db_schema['path'])} AS name"
        return f"NULL AS {quote_identifier(logical)}"

    def _db_filter(self) -> tuple[str,list[Any]]:
        where,params=self._db_evidence_where();clauses=[]
        q=self.db_search_var.get().strip()
        if q:
            searchable=[k for k in ("name","path","extension","category","md5","sha1","sha256") if k in self.db_schema]
            if searchable:
                clauses.append("("+" OR ".join(f"CAST({quote_identifier(self.db_schema[k])} AS TEXT) LIKE ?" for k in searchable)+")")
                params.extend([f"%{q}%"]*len(searchable))
        if self.db_extension_var.get()!="All" and "extension" in self.db_schema:
            clauses.append(f"{quote_identifier(self.db_schema['extension'])}=?");params.append(self.db_extension_var.get())
        if self.db_category_var.get()!="All" and "category" in self.db_schema:
            clauses.append(f"{quote_identifier(self.db_schema['category'])}=?");params.append(self.db_category_var.get())
        if "size" in self.db_schema:
            col=quote_identifier(self.db_schema["size"])
            if self.db_min_size_var.get().strip():
                clauses.append(f"CAST({col} AS INTEGER)>=?");params.append(int(float(self.db_min_size_var.get())*1024*1024))
            if self.db_max_size_var.get().strip():
                clauses.append(f"CAST({col} AS INTEGER)<=?");params.append(int(float(self.db_max_size_var.get())*1024*1024))
        if clauses: where+=" AND "+" AND ".join(clauses)
        return where,params

    def apply_db_filters(self) -> None:
        self.db_offset=0;self.load_db_page()

    def clear_db_filters(self) -> None:
        self.db_search_var.set("");self.db_extension_var.set("All");self.db_category_var.set("All")
        self.db_min_size_var.set("");self.db_max_size_var.set("");self.apply_db_filters()

    def _db_page_size(self) -> int:
        try:return max(1,min(int(self.db_page_size_var.get()),MAX_PAGE_SIZE))
        except ValueError:return DEFAULT_PAGE_SIZE

    def load_db_page(self) -> None:
        if not self.db_conn:return
        started=time.perf_counter()
        try:
            where,params=self._db_filter()
            self.db_total=int(self.db_conn.execute(f"SELECT COUNT(*) total FROM file_inventory {where}",params).fetchone()["total"])
            fields=("id","evidence_id","name","extension","category","size","created","modified","accessed","directory","path","md5","sha1","sha256","error","reviewed","notes")
            select_sql=", ".join(self._db_select(f) for f in fields)
            order=self.db_sort_key if self.db_sort_key in self.db_schema else next((x for x in ("modified","name","path","id") if x in self.db_schema),None)
            order_sql=f" ORDER BY {quote_identifier(self.db_schema[order])} {'DESC' if self.db_sort_desc else 'ASC'}" if order else ""
            rows=self.db_conn.execute(f"SELECT {select_sql} FROM file_inventory {where}{order_sql} LIMIT ? OFFSET ?",(*params,self._db_page_size(),self.db_offset)).fetchall()
            self.db_rows=rows;self.db_tree.delete(*self.db_tree.get_children())
            for i,r in enumerate(rows):
                self.db_tree.insert("", "end", iid=str(i), values=(r["name"] or "",r["extension"] or "",r["category"] or "",human_size(r["size"]),r["created"] or "",r["modified"] or "",r["accessed"] or "",r["md5"] or "",r["sha1"] or "",r["sha256"] or "",r["error"] or "",r["path"] or ""))
            page=(self.db_offset//self._db_page_size())+1;pages=max(1,(self.db_total+self._db_page_size()-1)//self._db_page_size())
            self.db_page_var.set(f"Page {page} of {pages}")
            self.status_var.set(f"{self.db_total:,} indexed files | query {time.perf_counter()-started:.3f}s")
        except Exception as exc:
            messagebox.showerror("Indexed Database",str(exc),parent=self)

    def sort_db(self,key:str)->None:
        if key not in self.db_schema:return
        if self.db_sort_key==key:self.db_sort_desc=not self.db_sort_desc
        else:self.db_sort_key=key;self.db_sort_desc=key in ("size","created","modified","accessed")
        self.db_offset=0;self.load_db_page()

    def db_first(self):self.db_offset=0;self.load_db_page()
    def db_previous(self):self.db_offset=max(0,self.db_offset-self._db_page_size());self.load_db_page()
    def db_next(self):
        if self.db_offset+self._db_page_size()<self.db_total:
            self.db_offset+=self._db_page_size();self.load_db_page()

    def selected_db_row(self)->Optional[sqlite3.Row]:
        sel=self.db_tree.selection()
        if not sel:return None
        try:return self.db_rows[int(sel[0])]
        except Exception:return None

    def show_db_details(self,_event=None)->None:
        r=self.selected_db_row();self.db_details.configure(state="normal");self.db_details.delete("1.0","end")
        if r:
            for label,key in (("Name","name"),("Path","path"),("Directory","directory"),("Extension","extension"),("Category","category"),("Size","size"),("Created","created"),("Modified","modified"),("Accessed","accessed"),("MD5","md5"),("SHA1","sha1"),("SHA256","sha256"),("Reviewed","reviewed"),("Notes","notes"),("Error","error"),("Evidence ID","evidence_id"),("Inventory ID","id")):
                v=r[key]
                if key=="size":v=f"{human_size(v)} ({v or 0} bytes)"
                self.db_details.insert("end",f"{label}: {v or ''}\n")
        self.db_details.configure(state="disabled")

    def open_db_selected(self)->None:
        r=self.selected_db_row()
        if r and r["path"]:_open=Path(str(r["path"]));self._open_external(_open)

    def locate_db_in_live(self)->None:
        r=self.selected_db_row()
        if not r or not r["path"]:return
        path=Path(str(r["path"]))
        folder=path if path.is_dir() else path.parent
        if folder.exists():
            self.main_notebook.select(self.live_tab)
            self.load_root(folder)
            for iid in self.file_tree.get_children():
                tags=self.file_tree.item(iid).get("tags",[])
                if tags and Path(tags[0])==path:
                    self.file_tree.selection_set(iid);self.file_tree.see(iid);self.select_file();break
        else:
            messagebox.showwarning("Locate File",f"The indexed path is not currently accessible:\n{path}",parent=self)

    def find_live_in_database(self)->None:
        path=self.selected_live_path()
        if not path:return
        self.main_notebook.select(self.database_tab)
        self.db_search_var.set(str(path))
        self.apply_db_filters()
        if self.db_rows:self.db_tree.selection_set("0");self.db_tree.see("0");self.show_db_details()

    def export_db_page(self)->None:
        if not self.db_rows:return
        dest=filedialog.asksaveasfilename(parent=self,defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if not dest:return
        fields=self.db_rows[0].keys()
        with open(dest,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f);w.writerow(fields)
            for r in self.db_rows:w.writerow([r[k] for k in fields])
        self.status_var.set(f"Exported database page to {dest}")

    # ---------------- BOOKMARKS ----------------

    def _build_bookmarks_tab(self)->None:
        top=ttk.Frame(self.bookmarks_tab,padding=10);top.pack(fill="x")
        ttk.Label(top,text="Search").pack(side="left")
        e=ttk.Entry(top,textvariable=self.bookmark_search_var,width=35);e.pack(side="left",padx=5)
        e.bind("<Return>",lambda _e:self.refresh_bookmarks())
        ttk.Label(top,text="Category").pack(side="left",padx=(10,3))
        self.bookmark_category_combo=ttk.Combobox(top,textvariable=self.bookmark_category_var,state="readonly",values=("All",),width=18)
        self.bookmark_category_combo.pack(side="left")
        self.bookmark_category_combo.bind("<<ComboboxSelected>>",lambda _e:self.refresh_bookmarks())
        ttk.Button(top,text="Refresh",command=self.refresh_bookmarks).pack(side="left",padx=5)
        ttk.Button(top,text="Open Reference",command=self.open_bookmark_reference).pack(side="left",padx=5)
        ttk.Button(top,text="Delete",command=self.delete_bookmark).pack(side="left",padx=5)

        pane=ttk.Panedwindow(self.bookmarks_tab,orient="vertical");pane.pack(fill="both",expand=True,padx=10,pady=(0,10))
        grid=ttk.Frame(pane);grid.rowconfigure(0,weight=1);grid.columnconfigure(0,weight=1);pane.add(grid,weight=4)
        cols=("title","category","object_type","evidence_id","reference","examiner","created")
        self.bookmark_tree=ttk.Treeview(grid,columns=cols,show="headings",selectmode="browse")
        for c,label,w in (("title","Title",220),("category","Category",120),("object_type","Type",120),("evidence_id","Evidence",80),("reference","Reference",600),("examiner","Examiner",130),("created","Created",170)):
            self.bookmark_tree.heading(c,text=label);self.bookmark_tree.column(c,width=w,anchor="w")
        sy=ttk.Scrollbar(grid,orient="vertical",command=self.bookmark_tree.yview);sx=ttk.Scrollbar(grid,orient="horizontal",command=self.bookmark_tree.xview)
        self.bookmark_tree.configure(yscrollcommand=sy.set,xscrollcommand=sx.set)
        self.bookmark_tree.grid(row=0,column=0,sticky="nsew");sy.grid(row=0,column=1,sticky="ns");sx.grid(row=1,column=0,sticky="ew")
        self.bookmark_tree.bind("<<TreeviewSelect>>",self.show_bookmark_details)
        self.bookmark_tree.bind("<Double-1>",lambda _e:self.open_bookmark_reference())
        detail=ttk.LabelFrame(pane,text="Bookmark Details",padding=6);pane.add(detail,weight=1)
        detail.rowconfigure(0,weight=1);detail.columnconfigure(0,weight=1)
        self.bookmark_details=tk.Text(detail,height=9,wrap="word",state="disabled");self.bookmark_details.grid(row=0,column=0,sticky="nsew")
        self.bookmark_rows:dict[str,sqlite3.Row]={}

    def ensure_bookmarks_schema(self,conn:sqlite3.Connection)->None:
        conn.execute("""
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
                modified_utc TEXT NOT NULL
            )
        """)
        conn.commit()

    def refresh_bookmarks(self)->None:
        self.bookmark_tree.delete(*self.bookmark_tree.get_children());self.bookmark_rows={}
        if not self.case_db or not self.case_db.exists():
            self.status_var.set("No case database available for bookmarks.");return
        try:
            with sqlite3.connect(self.case_db) as conn:
                conn.row_factory=sqlite3.Row;self.ensure_bookmarks_schema(conn)
                categories=[r[0] for r in conn.execute("SELECT DISTINCT category FROM bookmarks WHERE category IS NOT NULL AND category<>'' ORDER BY category")]
                self.bookmark_category_combo["values"]=tuple(["All",*categories])
                sql="SELECT id,title,category,object_type,object_id,evidence_id,reference,notes,examiner,created_utc,modified_utc FROM bookmarks WHERE 1=1"
                params=[]
                q=self.bookmark_search_var.get().strip()
                if q:
                    sql+=" AND (title LIKE ? OR reference LIKE ? OR notes LIKE ? OR object_type LIKE ?)";params.extend([f"%{q}%"]*4)
                if self.bookmark_category_var.get()!="All":
                    sql+=" AND category=?";params.append(self.bookmark_category_var.get())
                sql+=" ORDER BY created_utc DESC"
                for r in conn.execute(sql,params):
                    iid=str(r["id"]);self.bookmark_rows[iid]=r
                    self.bookmark_tree.insert("", "end", iid=iid, values=(r["title"],r["category"],r["object_type"],r["evidence_id"] or "",r["reference"] or "",r["examiner"] or "",r["created_utc"]))
            self.status_var.set(f"{len(self.bookmark_rows):,} bookmark(s)")
        except Exception as exc:
            self.status_var.set(f"Unable to load bookmarks: {exc}")

    def selected_bookmark(self)->Optional[sqlite3.Row]:
        sel=self.bookmark_tree.selection()
        return self.bookmark_rows.get(sel[0]) if sel else None

    def show_bookmark_details(self,_event=None)->None:
        r=self.selected_bookmark();self.bookmark_details.configure(state="normal");self.bookmark_details.delete("1.0","end")
        if r:
            for label,key in (("Title","title"),("Category","category"),("Object Type","object_type"),("Object ID","object_id"),("Evidence ID","evidence_id"),("Reference","reference"),("Notes","notes"),("Examiner","examiner"),("Created","created_utc"),("Modified","modified_utc")):
                self.bookmark_details.insert("end",f"{label}: {r[key] or ''}\n")
        self.bookmark_details.configure(state="disabled")

    def add_bookmark(self,title:str,reference:str,object_type:str,object_id:str="",notes:str="")->None:
        if not self.case_db or not self.case_db.exists():
            messagebox.showwarning("Bookmark","No active case database is available.",parent=self);return
        category=simpledialog.askstring("Bookmark Category","Category:",initialvalue="File",parent=self)
        if category is None:return
        note=simpledialog.askstring("Bookmark Notes","Notes:",initialvalue=notes,parent=self)
        if note is None:return
        now=utc_now()
        with sqlite3.connect(self.case_db) as conn:
            self.ensure_bookmarks_schema(conn)
            conn.execute("""INSERT INTO bookmarks(title,category,object_type,object_id,evidence_id,reference,notes,examiner,created_utc,modified_utc)
                            VALUES(?,?,?,?,?,?,?,?,?,?)""",(title,category or "General",object_type,object_id,self.evidence_id,reference,note,self.examiner,now,now))
            conn.commit()
        self.refresh_bookmarks();self.main_notebook.select(self.bookmarks_tab)

    def bookmark_live_selected(self)->None:
        path=self.selected_live_path()
        if path:self.add_bookmark(path.name,str(path),"File",str(path))

    def bookmark_db_selected(self)->None:
        r=self.selected_db_row()
        if r:self.add_bookmark(str(r["name"] or "Indexed File"),str(r["path"] or ""),"Indexed File",str(r["id"] or ""),str(r["notes"] or ""))

    def open_bookmark_reference(self)->None:
        r=self.selected_bookmark()
        if not r or not r["reference"]:return
        ref=str(r["reference"]);path=Path(ref)
        if path.exists():
            self._open_external(path)
        else:
            self.main_notebook.select(self.database_tab);self.db_search_var.set(ref);self.apply_db_filters()

    def delete_bookmark(self)->None:
        r=self.selected_bookmark()
        if not r or not self.case_db:return
        if not messagebox.askyesno("Delete Bookmark",f"Delete bookmark '{r['title']}'?",parent=self):return
        with sqlite3.connect(self.case_db) as conn:
            conn.execute("DELETE FROM bookmarks WHERE id=?",(r["id"],));conn.commit()
        self.refresh_bookmarks()

    def audit(self,action:str,details:str)->None:
        if not self.case_db or not self.case_db.exists():return
        try:
            with sqlite3.connect(self.case_db) as conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,event_utc TEXT NOT NULL,examiner TEXT,action TEXT NOT NULL,object_type TEXT,object_id TEXT,details TEXT)""")
                conn.execute("""INSERT INTO audit_log(event_utc,examiner,action,object_type,object_id,details) VALUES(?,?,?,'file_explorer','',?)""",(utc_now(),self.examiner,action,details))
                conn.commit()
        except Exception:pass

    def on_close(self)->None:
        self.audit("FILE_EXPLORER_CLOSED","Closed combined File Explorer")
        if self.db_conn:self.db_conn.close()
        self.destroy()


def main()->None:
    FileExplorerApp().mainloop()


if __name__=="__main__":
    main()
