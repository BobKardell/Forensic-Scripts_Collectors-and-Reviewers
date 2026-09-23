#!/usr/bin/env python3
# FFT_TOOL
# TITLE: Hash - Files
# ID: hash_calculator
# CATEGORY: Plugins
# VERSION: 1.0
# DESCRIPTION: Calculate forensic hash values for files.
# ICON: #
# PASS_CASE_ARGUMENTS: false

SCRIPT_NAME = "Hash File Calculator"
SCRIPT_CATEGORY = "File System"
SCRIPT_DESCRIPTION = "File Indexer."
SCRIPT_AUTHOR = "Bob Kardell / ChatGPT"
SCRIPT_VERSION = "1.0"

import csv
import hashlib
import html
import os
import queue
import sys
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

CHUNK_SIZE = 4 * 1024 * 1024
COLUMNS = [
    ("filename", "Filename", 220), ("path", "Path", 430),
    ("extension", "Extension", 85), ("size", "Size (bytes)", 110),
    ("modified", "Modified", 150), ("created", "Created", 150),
    ("md5", "MD5", 260), ("sha1", "SHA-1", 310),
    ("sha256", "SHA-256", 480), ("sha512", "SHA-512", 760),
    ("status", "Status", 130),
]


def safe_datetime(value):
    try:
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return ""


def col_name(number):
    result = ""
    while number:
        number, remainder = divmod(number - 1, 26)
        result = chr(65 + remainder) + result
    return result


def xml_escape(value):
    return html.escape(str(value), quote=False)


def write_xlsx(path, rows, headers):
    shared, lookup = [], {}

    def sidx(value):
        value = str(value)
        if value not in lookup:
            lookup[value] = len(shared)
            shared.append(value)
        return lookup[value]

    sheet_rows = []
    sheet_rows.append(
        f'<row r="1" ht="24" customHeight="1"><c r="A1" t="s" s="1"><v>{sidx("Forensic File Hash Results")}</v></c></row>'
    )
    generated = sidx(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    count = sidx(f"Files: {len(rows):,}")
    sheet_rows.append(f'<row r="2"><c r="A2" t="s" s="2"><v>{generated}</v></c><c r="B2" t="s" s="2"><v>{count}</v></c></row>')

    cells = []
    for i, header in enumerate(headers, 1):
        ref = f"{col_name(i)}4"
        cells.append(f'<c r="{ref}" t="s" s="3"><v>{sidx(header)}</v></c>')
    sheet_rows.append(f'<row r="4" ht="22" customHeight="1">{"".join(cells)}</row>')

    for row_no, row in enumerate(rows, 5):
        cells = []
        for col_no, value in enumerate(row, 1):
            ref = f"{col_name(col_no)}{row_no}"
            if col_no == 4 and isinstance(value, (int, float)):
                cells.append(f'<c r="{ref}" s="4"><v>{value}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="s" s="4"><v>{sidx(value)}</v></c>')
        sheet_rows.append(f'<row r="{row_no}">{"".join(cells)}</row>')

    last_col = col_name(len(headers))
    last_row = max(4, len(rows) + 4)
    widths = [28, 58, 12, 15, 20, 20, 35, 43, 68, 95, 18]
    cols = "".join(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i, w in enumerate(widths[:len(headers)], 1))

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""
    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""
    workbook = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Hash Results" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""
    workbook_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>"""
    styles = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="3"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="16"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>
<fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF5B9BD5"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD9E2F3"/></left><right style="thin"><color rgb="FFD9E2F3"/></right><top style="thin"><color rgb="FFD9E2F3"/></top><bottom style="thin"><color rgb="FFD9E2F3"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="5"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment vertical="top"/></xf></cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""
    shared_strings = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{len(shared)}" uniqueCount="{len(shared)}">' + ''.join(f'<si><t xml:space="preserve">{xml_escape(v)}</t></si>' for v in shared) + '</sst>'
    sheet = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<dimension ref="A1:{last_col}{last_row}"/><sheetViews><sheetView tabSelected="1" workbookViewId="0"><pane ySplit="4" topLeftCell="A5" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<sheetFormatPr defaultRowHeight="15"/><cols>{cols}</cols><sheetData>{"".join(sheet_rows)}</sheetData><autoFilter ref="A4:{last_col}{last_row}"/><mergeCells count="1"><mergeCell ref="A1:{last_col}1"/></mergeCells>
</worksheet>'''
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    core = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Forensic File Hash Results</dc:title><dc:creator>Fraud Fighter Toolbox</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified></cp:coreProperties>'''
    app = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Fraud Fighter Toolbox</Application></Properties>"""

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/styles.xml", styles)
        z.writestr("xl/sharedStrings.xml", shared_strings)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)


class HashApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{SCRIPT_NAME} v{SCRIPT_VERSION}")
        self.geometry("1450x780")
        self.minsize(1000, 620)
        self.results = []
        self.sort_reverse = {}
        self.worker = None
        self.cancel_event = threading.Event()
        self.events = queue.Queue()
        self.source_mode = tk.StringVar(value="folder")
        self.source_path = tk.StringVar()
        self.include_subdirs = tk.BooleanVar(value=True)
        self.follow_symlinks = tk.BooleanVar(value=False)
        self.hash_md5 = tk.BooleanVar(value=True)
        self.hash_sha1 = tk.BooleanVar(value=True)
        self.hash_sha256 = tk.BooleanVar(value=True)
        self.hash_sha512 = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Ready")
        self.current_file = tk.StringVar(value="")
        self.progress_value = tk.DoubleVar(value=0)
        self.build_ui()
        self.after(100, self.process_events)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_ui(self):
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", relief="sunken", anchor="w", padding=(6, 3))

        root = ttk.Frame(self, padding=10); root.pack(fill="both", expand=True)
        header = ttk.Frame(root); header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text=SCRIPT_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="MD5 • SHA-1 • SHA-256 • SHA-512").pack(side="right")

        source = ttk.LabelFrame(root, text="Source", padding=8); source.pack(fill="x", pady=(0, 8))
        modes = ttk.Frame(source); modes.pack(fill="x", pady=(0, 6))
        ttk.Radiobutton(modes, text="Single file", variable=self.source_mode, value="file", command=self.mode_changed).pack(side="left")
        ttk.Radiobutton(modes, text="Folder", variable=self.source_mode, value="folder", command=self.mode_changed).pack(side="left", padx=(15, 0))
        self.subdir_check = ttk.Checkbutton(modes, text="Include subdirectories", variable=self.include_subdirs); self.subdir_check.pack(side="left", padx=(25, 0))
        ttk.Checkbutton(modes, text="Follow symbolic links", variable=self.follow_symlinks).pack(side="left", padx=(15, 0))
        pathrow = ttk.Frame(source); pathrow.pack(fill="x")
        ttk.Entry(pathrow, textvariable=self.source_path).pack(side="left", fill="x", expand=True)
        ttk.Button(pathrow, text="Browse...", command=self.browse).pack(side="left", padx=(6, 0))

        algorithms = ttk.LabelFrame(root, text="Hash Algorithms", padding=8); algorithms.pack(fill="x", pady=(0, 8))
        ttk.Checkbutton(algorithms, text="MD5", variable=self.hash_md5).pack(side="left")
        ttk.Checkbutton(algorithms, text="SHA-1", variable=self.hash_sha1).pack(side="left", padx=18)
        ttk.Checkbutton(algorithms, text="SHA-256", variable=self.hash_sha256).pack(side="left")
        ttk.Checkbutton(algorithms, text="SHA-512", variable=self.hash_sha512).pack(side="left", padx=18)

        controls = ttk.Frame(root); controls.pack(fill="x", pady=(0, 8))
        self.start_button = ttk.Button(controls, text="Calculate Hashes", style="Primary.TButton", command=self.start_hashing); self.start_button.pack(side="left")
        self.cancel_button = ttk.Button(controls, text="Cancel", command=self.cancel_hashing, state="disabled"); self.cancel_button.pack(side="left", padx=6)
        ttk.Button(controls, text="Clear Results", command=self.clear_results).pack(side="left")
        ttk.Button(controls, text="Export CSV", command=self.export_csv).pack(side="right")
        ttk.Button(controls, text="Export Excel", command=self.export_excel).pack(side="right", padx=6)

        frame = ttk.Frame(root); frame.pack(fill="both", expand=True)
        keys = tuple(k for k, _, _ in COLUMNS)
        self.tree = ttk.Treeview(frame, columns=keys, show="headings", selectmode="extended")
        for key, label, width in COLUMNS:
            self.tree.heading(key, text=label, command=lambda c=key: self.sort_column(c))
            self.tree.column(key, width=width, minwidth=70, anchor="e" if key == "size" else "w")
        v = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        h = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v.set, xscrollcommand=h.set)
        self.tree.grid(row=0, column=0, sticky="nsew"); v.grid(row=0, column=1, sticky="ns"); h.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        self.tree.tag_configure("error", background="#FFE6E6")

        self.context = tk.Menu(self, tearoff=False)
        self.context.add_command(label="Copy Selected Rows", command=self.copy_rows)
        self.context.add_command(label="Copy Preferred Hash", command=self.copy_hash)
        self.context.add_separator(); self.context.add_command(label="Open File Location", command=self.open_location)
        self.tree.bind("<Button-3>", self.show_context)

        bottom = ttk.Frame(root); bottom.pack(fill="x", pady=(8, 0))
        ttk.Progressbar(bottom, variable=self.progress_value, maximum=100).pack(fill="x")
        ttk.Label(bottom, textvariable=self.current_file, anchor="w").pack(fill="x", pady=(3, 0))
        ttk.Label(root, textvariable=self.status, style="Status.TLabel").pack(fill="x", pady=(4, 0))
        self.mode_changed()

    def mode_changed(self):
        self.subdir_check.configure(state="disabled" if self.source_mode.get() == "file" else "normal")

    def browse(self):
        if self.source_mode.get() == "file":
            path = filedialog.askopenfilename(parent=self, title="Select File to Hash")
        else:
            path = filedialog.askdirectory(parent=self, title="Select Folder to Hash")
        if path: self.source_path.set(path)

    def selected_algorithms(self):
        out = []
        if self.hash_md5.get(): out.append("md5")
        if self.hash_sha1.get(): out.append("sha1")
        if self.hash_sha256.get(): out.append("sha256")
        if self.hash_sha512.get(): out.append("sha512")
        return out

    def start_hashing(self):
        if self.worker and self.worker.is_alive(): return
        source = self.source_path.get().strip()
        if not source: return messagebox.showinfo("Select Source", "Select a file or folder first.", parent=self)
        path = Path(source)
        if not path.exists(): return messagebox.showerror("Source Not Found", "The selected source does not exist.", parent=self)
        algorithms = self.selected_algorithms()
        if not algorithms: return messagebox.showinfo("Select Hash", "Select at least one hash algorithm.", parent=self)
        if self.source_mode.get() == "file" and not path.is_file(): return messagebox.showerror("Invalid Source", "The selected source is not a file.", parent=self)
        if self.source_mode.get() == "folder" and not path.is_dir(): return messagebox.showerror("Invalid Source", "The selected source is not a folder.", parent=self)
        settings = dict(source=source, mode=self.source_mode.get(), recursive=self.include_subdirs.get(), follow=self.follow_symlinks.get(), algorithms=algorithms)
        self.cancel_event.clear(); self.start_button.configure(state="disabled"); self.cancel_button.configure(state="normal")
        self.progress_value.set(0); self.status.set("Enumerating files...")
        self.worker = threading.Thread(target=self.worker_main, args=(settings,), daemon=True); self.worker.start()

    def worker_main(self, settings):
        try:
            source = Path(settings["source"])
            if settings["mode"] == "file": files = [source]
            else:
                files = []
                if settings["recursive"]:
                    for root, dirs, names in os.walk(source, followlinks=settings["follow"]):
                        if not settings["follow"]: dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
                        for name in names:
                            p = Path(root, name)
                            if settings["follow"] or not p.is_symlink(): files.append(p)
                else:
                    files = [p for p in source.iterdir() if p.is_file() and (settings["follow"] or not p.is_symlink())]
                files.sort(key=lambda p: str(p).lower())
            total = len(files); self.events.put(("total", total))
            for index, path in enumerate(files, 1):
                if self.cancel_event.is_set(): self.events.put(("cancelled", index - 1, total)); return
                self.events.put(("current", str(path), index, total))
                self.events.put(("result", self.hash_file(path, settings["algorithms"]), index, total))
            self.events.put(("complete", total))
        except Exception as exc: self.events.put(("fatal", str(exc)))

    def hash_file(self, path, algorithms):
        result = {k: "" for k, _, _ in COLUMNS}
        result.update(filename=path.name, path=str(path.resolve()), extension=path.suffix.lower(), size=0, status="OK")
        try:
            st = path.stat(); result["size"] = st.st_size; result["modified"] = safe_datetime(st.st_mtime); result["created"] = safe_datetime(st.st_ctime)
            hashers = {name: hashlib.new(name) for name in algorithms}
            with path.open("rb") as f:
                while True:
                    if self.cancel_event.is_set(): result["status"] = "Cancelled"; return result
                    block = f.read(CHUNK_SIZE)
                    if not block: break
                    for hasher in hashers.values(): hasher.update(block)
            for name, hasher in hashers.items(): result[name] = hasher.hexdigest()
        except PermissionError: result["status"] = "Access denied"
        except FileNotFoundError: result["status"] = "File not found"
        except OSError as exc: result["status"] = f"Error: {exc}"
        return result

    def process_events(self):
        try:
            while True:
                event = self.events.get_nowait(); kind = event[0]
                if kind == "total":
                    total = event[1]; self.status.set(f"Found {total:,} file(s).")
                    if total == 0: self.finish("No files found.")
                elif kind == "current":
                    path, index, total = event[1:]; self.current_file.set(f"{index:,} of {total:,}: {path}")
                    if total: self.progress_value.set((index - 1) / total * 100)
                elif kind == "result":
                    result, index, total = event[1:]; self.results.append(result)
                    item = self.tree.insert("", "end", values=tuple(result[k] for k, _, _ in COLUMNS))
                    if result["status"] != "OK": self.tree.item(item, tags=("error",))
                    if total: self.progress_value.set(index / total * 100)
                    self.status.set(f"Hashed {index:,} of {total:,} file(s).")
                elif kind == "complete": self.progress_value.set(100); self.finish(f"Complete. Hashed {event[1]:,} file(s).")
                elif kind == "cancelled": self.finish(f"Cancelled after {event[1]:,} of {event[2]:,} file(s).")
                elif kind == "fatal": self.finish(f"Error: {event[1]}"); messagebox.showerror("Hashing Error", event[1], parent=self)
        except queue.Empty: pass
        self.after(100, self.process_events)

    def finish(self, message):
        self.start_button.configure(state="normal"); self.cancel_button.configure(state="disabled"); self.current_file.set(""); self.status.set(message)

    def cancel_hashing(self):
        if self.worker and self.worker.is_alive(): self.cancel_event.set(); self.status.set("Cancelling...")

    def clear_results(self):
        if self.worker and self.worker.is_alive(): return messagebox.showinfo("Hashing in Progress", "Cancel hashing before clearing.", parent=self)
        self.results.clear(); [self.tree.delete(i) for i in self.tree.get_children()]; self.progress_value.set(0); self.status.set("Results cleared.")

    def sort_column(self, column):
        reverse = self.sort_reverse.get(column, False)
        def key(item):
            value = self.tree.set(item, column)
            if column == "size":
                try: return int(value)
                except ValueError: return 0
            return value.lower()
        items = list(self.tree.get_children("")); items.sort(key=key, reverse=reverse)
        for index, item in enumerate(items): self.tree.move(item, "", index)
        self.sort_reverse[column] = not reverse

    def export_rows(self): return [[r[k] for k, _, _ in COLUMNS] for r in self.results]

    def export_csv(self):
        if not self.results: return messagebox.showinfo("Export CSV", "There are no results to export.", parent=self)
        path = filedialog.asksaveasfilename(parent=self, title="Export CSV", defaultextension=".csv", filetypes=[("CSV file", "*.csv"), ("All files", "*.*")])
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f); writer.writerow([label for _, label, _ in COLUMNS]); writer.writerows(self.export_rows())
            self.status.set(f"CSV exported to {path}")
        except Exception as exc: messagebox.showerror("CSV Export Error", str(exc), parent=self)

    def export_excel(self):
        if not self.results: return messagebox.showinfo("Export Excel", "There are no results to export.", parent=self)
        path = filedialog.asksaveasfilename(parent=self, title="Export Excel", defaultextension=".xlsx", filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")])
        if not path: return
        try: write_xlsx(path, self.export_rows(), [label for _, label, _ in COLUMNS]); self.status.set(f"Excel workbook exported to {path}")
        except Exception as exc: messagebox.showerror("Excel Export Error", str(exc), parent=self)

    def show_context(self, event):
        row = self.tree.identify_row(event.y)
        if row and row not in self.tree.selection(): self.tree.selection_set(row)
        self.context.tk_popup(event.x_root, event.y_root)

    def copy_rows(self):
        selected = self.tree.selection()
        if not selected: return
        lines = ["\t".join(label for _, label, _ in COLUMNS)] + ["\t".join(map(str, self.tree.item(i, "values"))) for i in selected]
        self.clipboard_clear(); self.clipboard_append("\n".join(lines)); self.status.set(f"Copied {len(selected):,} row(s).")

    def copy_hash(self):
        selected = self.tree.selection()
        if not selected: return
        values = self.tree.item(selected[0], "values"); pos = {k: i for i, (k, _, _) in enumerate(COLUMNS)}
        for alg in ("sha256", "md5", "sha1", "sha512"):
            value = values[pos[alg]]
            if value: self.clipboard_clear(); self.clipboard_append(value); self.status.set(f"Copied {alg.upper()} hash."); return

    def open_location(self):
        selected = self.tree.selection()
        if not selected: return
        values = self.tree.item(selected[0], "values"); path = Path(values[1])
        try:
            if sys.platform.startswith("win"): os.startfile(path.parent)
            elif sys.platform == "darwin": os.system(f'open "{path.parent}"')
            else: os.system(f'xdg-open "{path.parent}"')
        except Exception as exc: messagebox.showerror("Open Location Error", str(exc), parent=self)

    def on_close(self):
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Hashing in Progress", "Cancel the active hashing job and exit?", parent=self): return
            self.cancel_event.set()
        self.destroy()


def main():
    HashApp().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
