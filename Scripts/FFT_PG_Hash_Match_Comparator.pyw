# FFT_TOOL
# TITLE: Hash - Match
# ID: hash_match
# CATEGORY: Plugins
# VERSION: 1.0.0
# DESCRIPTION: Export filtered files from an FFT file_inventory table with hashing, verification, deduplication, and manifests.
# ICON: #
# PASS_CASE_ARGUMENTS: true

import csv
import re
import tkinter as tk
from collections import defaultdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

APP_TITLE = "Hash Match Comparator"
HASH_LENGTHS = {"MD5": 32, "SHA1": 40}


def normalize_hash(value):
    if value is None:
        return ""
    return re.sub(r"[\\s:-]", "", str(value).strip().lower())


def valid_hash(value, length):
    return len(value) == length and all(c in "0123456789abcdef" for c in value)


def unique_headers(values):
    headers, used = [], set()
    for index, value in enumerate(values, 1):
        base = str(value).strip() if value is not None else ""
        base = base or f"Column_{index}"
        name, counter = base, 2
        while name in used:
            name = f"{base}_{counter}"
            counter += 1
        used.add(name)
        headers.append(name)
    return headers


def read_table(path):
    ext = Path(path).suffix.lower()

    if ext in {".xlsx", ".xlsm"}:
        try:
            from openpyxl import load_workbook
        except ImportError as exc:
            raise RuntimeError(
                "Excel support requires openpyxl.\n\n"
                "Install it with:\npython -m pip install openpyxl"
            ) from exc

        workbook = load_workbook(path, read_only=True, data_only=True)
        worksheet = workbook.active
        iterator = worksheet.iter_rows(values_only=True)

        try:
            headers = unique_headers(next(iterator))
        except StopIteration:
            workbook.close()
            return [], [], "Empty worksheet"

        rows = []
        for values in iterator:
            values = list(values) + [None] * max(0, len(headers) - len(values))
            rows.append(dict(zip(headers, values[:len(headers)])))

        title = worksheet.title
        workbook.close()
        return headers, rows, f"Worksheet: {title}"

    if ext in {".csv", ".tsv", ".txt"}:
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            sample = handle.read(8192)
            handle.seek(0)
            if ext == ".tsv":
                dialect = csv.excel_tab
            else:
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                except csv.Error:
                    dialect = csv.excel
            reader = csv.DictReader(handle, dialect=dialect)
            headers = list(reader.fieldnames or [])
            return headers, list(reader), f"Delimiter: {repr(dialect.delimiter)}"

    raise RuntimeError("Supported formats: CSV, TSV, TXT, XLSX, and XLSM.")


class HashComparator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1050x720")
        self.minsize(850, 600)

        self.hash_type = tk.StringVar(value="MD5")
        self.path1 = tk.StringVar()
        self.path2 = tk.StringVar()
        self.field1 = tk.StringVar()
        self.field2 = tk.StringVar()
        self.status = tk.StringVar(value="Load two files to begin.")

        self.headers1, self.rows1 = [], []
        self.headers2, self.rows2 = [], []
        self.matches = []

        self.build_ui()

    def build_ui(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, text=APP_TITLE, font=("Segoe UI", 16, "bold")).pack(anchor=tk.W)
        ttk.Label(
            root,
            text="Compare two tabular files using a selected MD5 or SHA1 column."
        ).pack(anchor=tk.W, pady=(2, 12))

        setup = ttk.LabelFrame(root, text="Comparison Setup", padding=12)
        setup.pack(fill=tk.X)
        setup.columnconfigure(1, weight=1)

        ttk.Label(setup, text="Hash type:").grid(row=0, column=0, sticky=tk.W, pady=4)
        ttk.Combobox(
            setup, textvariable=self.hash_type,
            values=["MD5", "SHA1"], state="readonly", width=12
        ).grid(row=0, column=1, sticky=tk.W, pady=4)

        self.add_file_controls(setup, 1, 1)
        ttk.Separator(setup).grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=8)
        self.add_file_controls(setup, 4, 2)

        buttons = ttk.Frame(root)
        buttons.pack(fill=tk.X, pady=10)
        ttk.Button(buttons, text="Run Comparison", command=self.compare).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Export Results to CSV...", command=self.export).pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Clear Results", command=self.clear).pack(side=tk.LEFT)

        result_frame = ttk.LabelFrame(root, text="Results", padding=8)
        result_frame.pack(fill=tk.BOTH, expand=True)
        self.output = ScrolledText(result_frame, wrap=tk.NONE, font=("Consolas", 10))
        self.output.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, textvariable=self.status, relief=tk.SUNKEN, anchor=tk.W, padding=5).pack(
            fill=tk.X, pady=(8, 0)
        )

    def add_file_controls(self, parent, row, number):
        path_var = self.path1 if number == 1 else self.path2
        field_var = self.field1 if number == 1 else self.field2

        ttk.Label(parent, text=f"File {number}:").grid(row=row, column=0, sticky=tk.W, pady=4)
        ttk.Entry(parent, textvariable=path_var, state="readonly").grid(
            row=row, column=1, sticky=tk.EW, padx=8, pady=4
        )
        ttk.Button(
            parent, text=f"Browse File {number}...",
            command=lambda n=number: self.load_file(n)
        ).grid(row=row, column=2, pady=4)

        ttk.Label(parent, text=f"Hash field in File {number}:").grid(
            row=row + 1, column=0, sticky=tk.W, pady=4
        )
        combo = ttk.Combobox(parent, textvariable=field_var, state="readonly")
        combo.grid(row=row + 1, column=1, columnspan=2, sticky=tk.EW, padx=8, pady=4)
        if number == 1:
            self.combo1 = combo
        else:
            self.combo2 = combo

    def guess_field(self, headers):
        target = self.hash_type.get().lower()
        for header in headers:
            lower = header.lower().replace("-", "")
            if target in lower or "hash" in lower or "checksum" in lower:
                return header
        return headers[0] if headers else ""

    def load_file(self, number):
        path = filedialog.askopenfilename(
            title=f"Choose File {number}",
            filetypes=[
                ("Supported files", "*.csv *.tsv *.txt *.xlsx *.xlsm"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            headers, rows, description = read_table(path)
        except Exception as exc:
            messagebox.showerror("File Load Error", str(exc))
            return

        if not headers:
            messagebox.showwarning("No Fields Found", "No header row was found.")
            return

        if number == 1:
            self.path1.set(path)
            self.headers1, self.rows1 = headers, rows
            self.combo1["values"] = headers
            self.field1.set(self.guess_field(headers))
        else:
            self.path2.set(path)
            self.headers2, self.rows2 = headers, rows
            self.combo2["values"] = headers
            self.field2.set(self.guess_field(headers))

        self.status.set(
            f"Loaded File {number}: {len(rows):,} rows, {len(headers):,} fields. {description}"
        )

    @staticmethod
    def describe(row, hash_field):
        preferred = ("name", "filename", "file_name", "path", "full_path", "file_path")
        lower_map = {str(k).lower(): k for k in row}
        values = []
        for key_name in preferred:
            if key_name in lower_map:
                key = lower_map[key_name]
                if row.get(key) not in (None, ""):
                    values.append(f"{key}={row[key]}")
        if values:
            return " | ".join(values)

        for key, value in row.items():
            if key != hash_field and value not in (None, ""):
                values.append(f"{key}={value}")
            if len(values) == 4:
                break
        return " | ".join(values) or "(no descriptive fields)"

    def compare(self):
        if not self.rows1 or not self.rows2:
            messagebox.showwarning("Files Required", "Load both files first.")
            return

        field1, field2 = self.field1.get(), self.field2.get()
        if not field1 or not field2:
            messagebox.showwarning("Fields Required", "Choose both hash fields.")
            return

        expected = HASH_LENGTHS[self.hash_type.get()]
        maps, invalid = [], []

        for rows, field in ((self.rows1, field1), (self.rows2, field2)):
            current = defaultdict(list)
            bad = 0
            for row_number, row in enumerate(rows, 2):
                value = normalize_hash(row.get(field))
                if not value:
                    continue
                if not valid_hash(value, expected):
                    bad += 1
                    continue
                current[value].append((row_number, row))
            maps.append(current)
            invalid.append(bad)

        common = sorted(set(maps[0]) & set(maps[1]))
        self.matches = []
        self.output.delete("1.0", tk.END)
        self.output.insert(
            tk.END,
            f"Hash Type: {self.hash_type.get()}\n"
            f"File 1: {self.path1.get()}\n"
            f"File 2: {self.path2.get()}\n"
            f"{'=' * 100}\n\n"
        )

        for value in common:
            first, second = maps[0][value], maps[1][value]
            self.output.insert(tk.END, f"MATCH: {value}\n")
            self.output.insert(tk.END, f"  File 1 occurrences: {len(first)}\n")
            for row_number, row in first:
                self.output.insert(tk.END, f"    Row {row_number}: {self.describe(row, field1)}\n")
            self.output.insert(tk.END, f"  File 2 occurrences: {len(second)}\n")
            for row_number, row in second:
                self.output.insert(tk.END, f"    Row {row_number}: {self.describe(row, field2)}\n")
            self.output.insert(tk.END, "\n")

            for row1_num, row1 in first:
                for row2_num, row2 in second:
                    self.matches.append({
                        "hash_type": self.hash_type.get(),
                        "hash_value": value,
                        "file1_path": self.path1.get(),
                        "file1_row": row1_num,
                        "file1_record": self.describe(row1, field1),
                        "file2_path": self.path2.get(),
                        "file2_row": row2_num,
                        "file2_record": self.describe(row2, field2),
                    })

        if not common:
            self.output.insert(tk.END, "No matching hash values were found.\n")

        summary = (
            f"{len(common):,} unique matching hashes; {len(self.matches):,} matched row pairs; "
            f"invalid values: File 1={invalid[0]:,}, File 2={invalid[1]:,}."
        )
        self.output.insert(tk.END, f"{'=' * 100}\n{summary}\n")
        self.status.set(summary)

    def export(self):
        if not self.matches:
            messagebox.showinfo("No Results", "There are no matching results to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".csv",
            initialfile="matching_hashes.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return

        fields = list(self.matches[0].keys())
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(self.matches)
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))
            return

        self.status.set(f"Exported {len(self.matches):,} matched row pairs to {path}")
        messagebox.showinfo("Export Complete", f"Results saved to:\n\n{path}")

    def clear(self):
        self.matches = []
        self.output.delete("1.0", tk.END)
        self.status.set("Results cleared.")


if __name__ == "__main__":
    HashComparator().mainloop()
