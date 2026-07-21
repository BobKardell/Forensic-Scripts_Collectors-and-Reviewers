"""Standalone SQLite query workbench for Fraud Fighter Toolbox."""
from __future__ import annotations

import csv
import re
import sqlite3
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Optional

SCRIPT_NAME = "SQLite Query Workbench"
SCRIPT_CATEGORY = "Database"
SCRIPT_DESCRIPTION = "Browse SQLite schemas, run saved or ad hoc queries, and export results."
SCRIPT_AUTHOR = "Bob Kardell / ChatGPT"
SCRIPT_VERSION = "1.0"

READ_ONLY_PREFIXES = ("select", "with", "pragma", "explain")


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
            text = "" if pos < 0 else text[pos + 1 :].lstrip()
            continue
        if text.startswith("/*"):
            pos = text.find("*/", 2)
            text = "" if pos < 0 else text[pos + 2 :].lstrip()
            continue
        break
    match = re.match(r"([A-Za-z]+)", text)
    return match.group(1).lower() if match else ""


class SQLiteQueryWorkbench(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(SCRIPT_NAME)
        self.geometry("1280x820")
        self.minsize(950, 650)

        self.db_path = tk.StringVar()
        self.saved_query = tk.StringVar()
        self.allow_writes = tk.BooleanVar(value=False)
        self.row_limit = tk.IntVar(value=5000)
        self.status_text = tk.StringVar(value="Choose a SQLite database to begin.")

        self.connection: Optional[sqlite3.Connection] = None
        self.current_columns: list[str] = []
        self.current_rows: list[tuple[str, ...]] = []
        self.query_files: dict[str, Path] = {}

        self._build_ui()
        self._refresh_saved_queries()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, text=SCRIPT_NAME, font=("Segoe UI", 16, "bold")).pack(anchor=tk.W)
        ttk.Label(root, text="Browse a SQLite database, inspect tables and columns, run SQL, and export results.").pack(anchor=tk.W, pady=(2, 10))

        db_frame = ttk.LabelFrame(root, text="Database", padding=8)
        db_frame.pack(fill=tk.X)
        db_frame.columnconfigure(1, weight=1)
        ttk.Label(db_frame, text="SQLite database:").grid(row=0, column=0, sticky=tk.W, padx=(0, 8))
        ttk.Entry(db_frame, textvariable=self.db_path, state="readonly").grid(row=0, column=1, sticky=tk.EW)
        ttk.Button(db_frame, text="Open Database...", command=self.open_database).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(db_frame, text="Refresh Schema", command=self.refresh_schema).grid(row=0, column=3, padx=(8, 0))

        main = ttk.Panedwindow(root, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        schema_frame = ttk.LabelFrame(main, text="Tables and Fields", padding=6)
        query_frame = ttk.Frame(main)
        main.add(schema_frame, weight=1)
        main.add(query_frame, weight=4)

        self.schema_tree = ttk.Treeview(schema_frame, show="tree", selectmode="browse")
        schema_scroll = ttk.Scrollbar(schema_frame, orient=tk.VERTICAL, command=self.schema_tree.yview)
        self.schema_tree.configure(yscrollcommand=schema_scroll.set)
        self.schema_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        schema_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.schema_tree.bind("<Double-1>", self._schema_double_click)
        self.schema_tree.bind("<Button-3>", self._schema_context_menu)

        saved = ttk.LabelFrame(query_frame, text="Saved SQL Queries", padding=8)
        saved.pack(fill=tk.X)
        saved.columnconfigure(1, weight=1)
        ttk.Label(saved, text="Saved query:").grid(row=0, column=0, sticky=tk.W, padx=(0, 8))
        self.saved_combo = ttk.Combobox(saved, textvariable=self.saved_query, state="readonly")
        self.saved_combo.grid(row=0, column=1, sticky=tk.EW)
        self.saved_combo.bind("<<ComboboxSelected>>", self.load_selected_query)
        ttk.Button(saved, text="Refresh", command=self._refresh_saved_queries).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(saved, text="Load SQL File...", command=self.load_query_file).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(saved, text="Save Query As...", command=self.save_query_as).grid(row=0, column=4, padx=(8, 0))

        editor = ttk.LabelFrame(query_frame, text="SQL Query", padding=6)
        editor.pack(fill=tk.X, pady=(8, 0))
        self.sql_editor = ScrolledText(editor, height=10, wrap=tk.NONE, font=("Consolas", 10), undo=True)
        self.sql_editor.pack(fill=tk.BOTH, expand=True)

        actions = ttk.Frame(query_frame)
        actions.pack(fill=tk.X, pady=8)
        ttk.Button(actions, text="Run Query", command=self.run_query).pack(side=tk.LEFT)
        ttk.Button(actions, text="Clear Query", command=lambda: self.sql_editor.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(actions, text="Export Results to CSV...", command=self.export_results).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Checkbutton(actions, text="Allow write queries", variable=self.allow_writes).pack(side=tk.LEFT, padx=(18, 0))
        ttk.Label(actions, text="Max rows:").pack(side=tk.LEFT, padx=(18, 5))
        ttk.Spinbox(actions, from_=100, to=100000, increment=500, textvariable=self.row_limit, width=9).pack(side=tk.LEFT)

        results = ttk.LabelFrame(query_frame, text="Query Results", padding=6)
        results.pack(fill=tk.BOTH, expand=True)
        self.results_tree = ttk.Treeview(results, show="headings", selectmode="extended")
        vbar = ttk.Scrollbar(results, orient=tk.VERTICAL, command=self.results_tree.yview)
        hbar = ttk.Scrollbar(results, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        results.rowconfigure(0, weight=1)
        results.columnconfigure(0, weight=1)
        self.results_tree.bind("<Double-1>", self.show_selected_row)

        output = ttk.LabelFrame(query_frame, text="Messages / Text Output", padding=6)
        output.pack(fill=tk.X, pady=(8, 0))
        self.output_text = ScrolledText(output, height=6, wrap=tk.WORD, font=("Consolas", 9))
        self.output_text.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, textvariable=self.status_text, relief=tk.SUNKEN, anchor=tk.W, padding=(6, 3)).pack(fill=tk.X, pady=(8, 0))

    def open_database(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose SQLite Database",
            filetypes=[("SQLite databases", "*.sqlite *.sqlite3 *.db *.db3"), ("All files", "*.*")],
        )
        if not path:
            return
        self._close_connection()
        try:
            uri = Path(path).resolve().as_uri() + "?mode=ro"
            self.connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            messagebox.showerror("Database Error", str(exc))
            return
        self.db_path.set(path)
        self.status_text.set(f"Opened database read-only: {path}")
        self.refresh_schema()

    def _reopen(self, writable: bool) -> bool:
        path = self.db_path.get().strip()
        if not path:
            return False
        self._close_connection()
        try:
            if writable:
                self.connection = sqlite3.connect(path, check_same_thread=False)
            else:
                uri = Path(path).resolve().as_uri() + "?mode=ro"
                self.connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            return True
        except sqlite3.Error as exc:
            messagebox.showerror("Database Error", str(exc))
            return False

    def refresh_schema(self) -> None:
        self.schema_tree.delete(*self.schema_tree.get_children())
        if self.connection is None:
            return
        try:
            objects = self.connection.execute(
                "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name COLLATE NOCASE"
            ).fetchall()
            for obj in objects:
                name, object_type = obj["name"], obj["type"].title()
                parent = self.schema_tree.insert("", tk.END, text=f"{name} [{object_type}]", open=False)
                for col in self.connection.execute(f"PRAGMA table_info({quote_identifier(name)})").fetchall():
                    flags = (" PK" if col["pk"] else "") + (" NOT NULL" if col["notnull"] else "")
                    self.schema_tree.insert(parent, tk.END, text=f"{col['name']} — {col['type'] or '(unspecified)'}{flags}")
            self.status_text.set(f"Schema loaded: {len(objects):,} table(s) and view(s).")
        except sqlite3.Error as exc:
            self._show_error("Schema Error", exc)

    def _schema_double_click(self, _event=None) -> None:
        item = self.schema_tree.focus()
        if not item:
            return
        parent = self.schema_tree.parent(item)
        if parent:
            table = self.schema_tree.item(parent, "text").rsplit(" [", 1)[0]
            column = self.schema_tree.item(item, "text").split(" — ", 1)[0]
            self.sql_editor.insert(tk.INSERT, f"{quote_identifier(table)}.{quote_identifier(column)}")
        else:
            table = self.schema_tree.item(item, "text").rsplit(" [", 1)[0]
            self.sql_editor.delete("1.0", tk.END)
            self.sql_editor.insert("1.0", f"SELECT *\nFROM {quote_identifier(table)}\nLIMIT 500;")

    def _schema_context_menu(self, event) -> None:
        item = self.schema_tree.identify_row(event.y)
        if not item:
            return
        self.schema_tree.selection_set(item)
        self.schema_tree.focus(item)
        menu = tk.Menu(self, tearoff=False)
        if self.schema_tree.parent(item):
            menu.add_command(label="Insert Column Name", command=self._schema_double_click)
        else:
            menu.add_command(label="Create SELECT Query", command=self._schema_double_click)
            menu.add_command(label="Show First 500 Rows", command=lambda: self._preview_table(item))
            menu.add_command(label="Show Row Count", command=lambda: self._count_table(item))
        menu.tk_popup(event.x_root, event.y_root)

    def _preview_table(self, item: str) -> None:
        table = self.schema_tree.item(item, "text").rsplit(" [", 1)[0]
        self.sql_editor.delete("1.0", tk.END)
        self.sql_editor.insert("1.0", f"SELECT * FROM {quote_identifier(table)} LIMIT 500;")
        self.run_query()

    def _count_table(self, item: str) -> None:
        table = self.schema_tree.item(item, "text").rsplit(" [", 1)[0]
        self.sql_editor.delete("1.0", tk.END)
        self.sql_editor.insert("1.0", f"SELECT COUNT(*) AS row_count FROM {quote_identifier(table)};")
        self.run_query()

    def run_query(self) -> None:
        if not self.db_path.get().strip():
            messagebox.showwarning("Database Required", "Choose a SQLite database first.")
            return
        sql = self.sql_editor.get("1.0", tk.END).strip()
        if not sql:
            messagebox.showwarning("Query Required", "Enter a SQL query.")
            return

        keyword = first_sql_keyword(sql)
        read_only = keyword in READ_ONLY_PREFIXES
        if not read_only and not self.allow_writes.get():
            messagebox.showwarning("Write Query Blocked", "Enable 'Allow write queries' to run a modifying statement.")
            return
        if not read_only:
            if not messagebox.askyesno("Confirm Database Modification", "This query may modify the database. Continue?", icon=messagebox.WARNING):
                return
            if not self._reopen(True):
                return
        elif self.connection is None and not self._reopen(False):
            return

        self._clear_results()
        self.output_text.delete("1.0", tk.END)
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
                msg = f"Query completed. Displayed {len(normalized):,} row(s)."
                if truncated:
                    msg += f" Limited to {limit:,} rows."
            else:
                affected = cursor.rowcount
                self.connection.commit()
                msg = f"Query completed. Rows affected: {affected:,}."
            self.output_text.insert(tk.END, msg + "\n")
            self.status_text.set(msg)
        except sqlite3.Error as exc:
            try:
                self.connection.rollback()
            except Exception:
                pass
            self._show_error("SQL Query Error", exc)
        finally:
            if not read_only:
                self._reopen(False)
                self.refresh_schema()

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
            self.results_tree.heading(column, text=column, command=lambda c=column: self._sort_results(c, False))
            self.results_tree.column(column, width=min(max(len(column) * 10, 110), 320), minwidth=70)
        for row in rows:
            self.results_tree.insert("", tk.END, values=row)

    def _clear_results(self) -> None:
        self.results_tree.delete(*self.results_tree.get_children())
        self.results_tree.configure(columns=())
        self.current_columns, self.current_rows = [], []

    def _sort_results(self, column: str, reverse: bool) -> None:
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
        self.results_tree.heading(column, command=lambda: self._sort_results(column, not reverse))

    def show_selected_row(self, _event=None) -> None:
        selection = self.results_tree.selection()
        if not selection:
            return
        values = self.results_tree.item(selection[0], "values")
        win = tk.Toplevel(self)
        win.title("Query Result Row")
        win.geometry("800x600")
        text = ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for column, value in zip(self.current_columns, values):
            text.insert(tk.END, f"{column}\n{'-' * len(column)}\n{value}\n\n")
        text.configure(state=tk.DISABLED)

    def export_results(self) -> None:
        if not self.current_columns:
            messagebox.showinfo("No Results", "Run a query that returns rows before exporting.")
            return
        path = filedialog.asksaveasfilename(title="Export Query Results", defaultextension=".csv", initialfile="query_results.csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.current_columns)
                writer.writerows(self.current_rows)
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))
            return
        messagebox.showinfo("Export Complete", f"Results saved to:\n\n{path}")
        self.status_text.set(f"Exported {len(self.current_rows):,} row(s) to {path}")

    def _refresh_saved_queries(self) -> None:
        folder = sql_queries_directory()
        self.query_files.clear()
        for path in sorted(folder.rglob("*.sql"), key=lambda p: str(p).lower()):
            try:
                label = str(path.relative_to(folder)).replace("\\", "/")
            except ValueError:
                label = path.name
            self.query_files[label] = path
        labels = list(self.query_files)
        self.saved_combo["values"] = labels
        if self.saved_query.get() not in self.query_files:
            self.saved_query.set("")
        self.status_text.set(f"Found {len(labels):,} saved SQL query file(s) in {folder}")

    def load_selected_query(self, _event=None) -> None:
        path = self.query_files.get(self.saved_query.get())
        if path:
            self._load_query_path(path)

    def load_query_file(self) -> None:
        path = filedialog.askopenfilename(title="Load SQL Query", initialdir=str(sql_queries_directory()), filetypes=[("SQL files", "*.sql"), ("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self._load_query_path(Path(path))

    def _load_query_path(self, path: Path) -> None:
        try:
            content = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            messagebox.showerror("Query Load Error", str(exc))
            return
        self.sql_editor.delete("1.0", tk.END)
        self.sql_editor.insert("1.0", content)
        self.status_text.set(f"Loaded SQL query: {path}")

    def save_query_as(self) -> None:
        sql = self.sql_editor.get("1.0", tk.END).strip()
        if not sql:
            messagebox.showwarning("No Query", "Enter a SQL query first.")
            return
        path = filedialog.asksaveasfilename(title="Save SQL Query", initialdir=str(sql_queries_directory()), defaultextension=".sql", initialfile="New_Query.sql", filetypes=[("SQL files", "*.sql"), ("All files", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text(sql + "\n", encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Query Save Error", str(exc))
            return
        self._refresh_saved_queries()
        self.status_text.set(f"Saved SQL query: {path}")

    def _show_error(self, title: str, exc: Exception) -> None:
        message = f"{type(exc).__name__}: {exc}"
        self.output_text.insert(tk.END, message + "\n")
        self.status_text.set(message)
        messagebox.showerror(title, message)

    def _close_connection(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            except sqlite3.Error:
                pass
            self.connection = None

    def _on_close(self) -> None:
        self._close_connection()
        self.destroy()


if __name__ == "__main__":
    SQLiteQueryWorkbench().mainloop()
