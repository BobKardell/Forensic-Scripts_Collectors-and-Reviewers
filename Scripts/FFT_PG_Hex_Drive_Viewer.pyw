# FFT_TOOL
# TITLE: Hex Viewer
# ID: Hex Viewer
# CATEGORY: Plugins
# VERSION: 1.0
# DESCRIPTION: Read-only hexadecimal and ASCII viewer for files and raw drives/devices.
# ICON: 🏁
# PASS_CASE_ARGUMENTS: false
from __future__ import annotations

import os
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText
from typing import BinaryIO, Optional

SCRIPT_NAME = "Hex Drive Viewer"
SCRIPT_CATEGORY = "File System"
SCRIPT_DESCRIPTION = "Read-only hexadecimal and ASCII viewer for files and raw drives/devices."
SCRIPT_AUTHOR = "Bob Kardell / ChatGPT"
SCRIPT_VERSION = "1.0"


SEARCH_CHUNK = 4 * 1024 * 1024


def parse_number(text: str) -> int:
    value = text.strip().replace(",", "").replace("_", "")
    if not value:
        raise ValueError("Enter a number.")
    if value.lower().startswith("0x"):
        return int(value, 16)
    if value.lower().endswith("h"):
        return int(value[:-1], 16)
    return int(value, 10)


def parse_hex(text: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if not cleaned:
        raise ValueError("Enter hexadecimal bytes.")
    if len(cleaned) % 2:
        raise ValueError("Hex input must contain complete byte pairs.")
    return bytes.fromhex(cleaned)


def size_text(size: Optional[int]) -> str:
    if size is None:
        return "Unknown"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            return f"{value:,.2f} {unit}"
        value /= 1024
    return f"{size:,} B"


class HexViewer(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(SCRIPT_NAME)
        self.geometry("1180x800")
        self.minsize(900, 620)

        self.path_var = tk.StringVar()
        self.info_var = tk.StringVar(value="No source open.")
        self.status_var = tk.StringVar(value="Open a file or raw device.")
        self.offset_var = tk.StringVar(value="0x0")
        self.page_var = tk.IntVar(value=4096)
        self.row_var = tk.IntVar(value=16)
        self.search_mode = tk.StringVar(value="Hex")
        self.search_var = tk.StringVar()
        self.search_start_var = tk.StringVar(value="0x0")

        self.handle: Optional[BinaryIO] = None
        self.source_size: Optional[int] = None
        self.current_offset = 0
        self.current_data = b""
        self.stop_event = threading.Event()
        self.search_thread: Optional[threading.Thread] = None

        self._build()
        self.protocol("WM_DELETE_WINDOW", self._close_app)

    def _build(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)

        ttk.Label(root, text=SCRIPT_NAME, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            root,
            text="Read-only viewer for regular files and raw drives/devices. Administrator/root access may be required.",
        ).pack(anchor="w", pady=(2, 10))

        source = ttk.LabelFrame(root, text="Source", padding=8)
        source.pack(fill="x")
        source.columnconfigure(1, weight=1)
        ttk.Label(source, text="Path:").grid(row=0, column=0, sticky="w")
        ttk.Entry(source, textvariable=self.path_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(source, text="Open File...", command=self.open_file).grid(row=0, column=2)
        ttk.Button(source, text="Open Drive / Device...", command=self.open_device).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(source, text="Close", command=self.close_source).grid(row=0, column=4, padx=(8, 0))
        ttk.Label(source, textvariable=self.info_var).grid(row=1, column=0, columnspan=5, sticky="w", pady=(6, 0))

        nav = ttk.LabelFrame(root, text="Navigation", padding=8)
        nav.pack(fill="x", pady=(8, 0))
        ttk.Label(nav, text="Offset:").pack(side="left")
        ttk.Entry(nav, textvariable=self.offset_var, width=18).pack(side="left", padx=5)
        ttk.Button(nav, text="Go", command=self.go).pack(side="left")
        ttk.Button(nav, text="Previous", command=self.previous).pack(side="left", padx=(8, 0))
        ttk.Button(nav, text="Next", command=self.next_page).pack(side="left", padx=(8, 0))
        ttk.Label(nav, text="Page bytes:").pack(side="left", padx=(18, 5))
        page_combo = ttk.Combobox(nav, textvariable=self.page_var, values=(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536), state="readonly", width=9)
        page_combo.pack(side="left")
        page_combo.bind("<<ComboboxSelected>>", lambda _e: self.read_page(self.current_offset))
        ttk.Label(nav, text="Bytes/row:").pack(side="left", padx=(18, 5))
        row_combo = ttk.Combobox(nav, textvariable=self.row_var, values=(8, 16, 24, 32), state="readonly", width=6)
        row_combo.pack(side="left")
        row_combo.bind("<<ComboboxSelected>>", lambda _e: self.read_page(self.current_offset))
        ttk.Button(nav, text="Export Range...", command=self.export_range).pack(side="right")

        search = ttk.LabelFrame(root, text="Search", padding=8)
        search.pack(fill="x", pady=(8, 0))
        ttk.Combobox(search, textvariable=self.search_mode, values=("Hex", "ASCII", "UTF-16LE"), state="readonly", width=10).pack(side="left")
        ttk.Entry(search, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Label(search, text="Start:").pack(side="left")
        ttk.Entry(search, textvariable=self.search_start_var, width=16).pack(side="left", padx=5)
        ttk.Button(search, text="Find Next", command=self.find_next).pack(side="left")
        ttk.Button(search, text="Stop", command=self.stop_search).pack(side="left", padx=(8, 0))

        frame = ttk.LabelFrame(root, text="Hex View", padding=6)
        frame.pack(fill="both", expand=True, pady=(8, 0))
        self.viewer = ScrolledText(frame, wrap="none", font=("Consolas", 10))
        self.viewer.pack(fill="both", expand=True)
        self.viewer.configure(state="disabled")

        ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w", padding=5).pack(fill="x", pady=(8, 0))

    def open_file(self) -> None:
        path = filedialog.askopenfilename(title="Open File", filetypes=[("All files", "*.*")])
        if path:
            self.open_source(path, "File")

    def open_device(self) -> None:
        if os.name == "nt":
            prompt = "Enter a raw volume or physical-drive path:\n\nExamples:\n\\\\.\\C:\n\\\\.\\PhysicalDrive0"
            initial = r"\\.\C:"
        else:
            prompt = "Enter a raw block-device path:\n\nExamples:\n/dev/sda\n/dev/nvme0n1"
            initial = "/dev/sda"
        path = simpledialog.askstring("Open Drive / Device", prompt, initialvalue=initial, parent=self)
        if path:
            self.open_source(path.strip(), "Drive / Device")

    def open_source(self, path: str, kind: str) -> None:
        self.close_source(False)
        try:
            self.handle = open(path, "rb", buffering=0)
        except OSError as exc:
            messagebox.showerror("Open Error", f"Could not open source read-only.\n\n{exc}")
            return

        self.path_var.set(path)
        self.source_size = self._get_size(path)
        self.info_var.set(f"Type: {kind} | Size: {size_text(self.source_size)} | Read-only")
        self.current_offset = 0
        self.offset_var.set("0x0")
        self.search_start_var.set("0x0")
        self.read_page(0)

    def _get_size(self, path: str) -> Optional[int]:
        if self.handle is None:
            return None
        try:
            pos = self.handle.tell()
            self.handle.seek(0, os.SEEK_END)
            size = self.handle.tell()
            self.handle.seek(pos)
            return size
        except OSError:
            try:
                return os.path.getsize(path)
            except OSError:
                return None

    def close_source(self, update: bool = True) -> None:
        self.stop_search()
        if self.handle:
            try:
                self.handle.close()
            except OSError:
                pass
        self.handle = None
        self.source_size = None
        self.current_offset = 0
        self.current_data = b""
        self.path_var.set("")
        self.info_var.set("No source open.")
        self._set_text("")
        if update:
            self.status_var.set("Source closed.")

    def read_page(self, offset: int) -> None:
        if not self.handle:
            return
        offset = max(0, offset)
        if self.source_size is not None:
            offset = min(offset, self.source_size)
        try:
            self.handle.seek(offset)
            data = self.handle.read(max(1, int(self.page_var.get())))
        except OSError as exc:
            messagebox.showerror("Read Error", str(exc))
            return
        self.current_offset = offset
        self.current_data = data
        self.offset_var.set(f"0x{offset:X}")
        self._set_text(self.render(data, offset, max(1, int(self.row_var.get()))))
        end = offset + len(data)
        self.status_var.set(f"Showing 0x{offset:X} through 0x{max(offset, end - 1):X} ({len(data):,} bytes)")

    @staticmethod
    def render(data: bytes, base: int, width: int) -> str:
        if not data:
            return "(No data at this offset.)"
        offset_width = max(8, len(f"{base + len(data):X}"))
        lines = []
        for index in range(0, len(data), width):
            row = data[index:index + width]
            hex_part = " ".join(f"{b:02X}" for b in row).ljust(width * 3 - 1)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
            lines.append(f"{base + index:0{offset_width}X}  {hex_part}  |{ascii_part}|")
        return "\n".join(lines)

    def _set_text(self, value: str) -> None:
        self.viewer.configure(state="normal")
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", value)
        self.viewer.configure(state="disabled")

    def go(self) -> None:
        try:
            self.read_page(parse_number(self.offset_var.get()))
        except ValueError as exc:
            messagebox.showerror("Invalid Offset", str(exc))

    def previous(self) -> None:
        self.read_page(self.current_offset - int(self.page_var.get()))

    def next_page(self) -> None:
        self.read_page(self.current_offset + int(self.page_var.get()))

    def _needle(self) -> bytes:
        mode = self.search_mode.get()
        value = self.search_var.get()
        if mode == "Hex":
            return parse_hex(value)
        if not value:
            raise ValueError("Enter search text.")
        return value.encode("utf-16le" if mode == "UTF-16LE" else "utf-8")

    def find_next(self) -> None:
        if not self.handle:
            messagebox.showwarning("No Source", "Open a source first.")
            return
        if self.search_thread and self.search_thread.is_alive():
            messagebox.showinfo("Search Running", "A search is already running.")
            return
        try:
            needle = self._needle()
            start = parse_number(self.search_start_var.get())
        except ValueError as exc:
            messagebox.showerror("Search Error", str(exc))
            return
        self.stop_event.clear()
        self.status_var.set("Searching...")
        self.search_thread = threading.Thread(target=self._search_worker, args=(needle, start), daemon=True)
        self.search_thread.start()

    def _search_worker(self, needle: bytes, start: int) -> None:
        if not self.handle:
            return
        overlap = max(0, len(needle) - 1)
        position = max(0, start)
        try:
            self.handle.seek(position)
            while not self.stop_event.is_set():
                block = self.handle.read(SEARCH_CHUNK)
                if not block:
                    self.after(0, lambda: self.status_var.set("No match found."))
                    return
                found = block.find(needle)
                if found >= 0:
                    absolute = position + found
                    self.after(0, lambda value=absolute: self._found(value))
                    return
                if len(block) <= overlap:
                    self.after(0, lambda: self.status_var.set("No match found."))
                    return
                position += len(block) - overlap
                self.handle.seek(position)
                self.after(0, lambda value=position: self.status_var.set(f"Searching at 0x{value:X}..."))
        except OSError as exc:
            self.after(0, lambda: messagebox.showerror("Search Error", str(exc)))

    def _found(self, offset: int) -> None:
        self.search_start_var.set(f"0x{offset + 1:X}")
        self.read_page(offset)
        self.status_var.set(f"Match found at 0x{offset:X} ({offset:,}).")
        messagebox.showinfo("Match Found", f"Offset: 0x{offset:X}\nDecimal: {offset:,}")

    def stop_search(self) -> None:
        self.stop_event.set()

    def export_range(self) -> None:
        if not self.handle:
            messagebox.showwarning("No Source", "Open a source first.")
            return
        start_text = simpledialog.askstring("Export Range", "Start offset:", initialvalue=f"0x{self.current_offset:X}", parent=self)
        if start_text is None:
            return
        length_text = simpledialog.askstring("Export Range", "Number of bytes:", initialvalue=str(len(self.current_data) or self.page_var.get()), parent=self)
        if length_text is None:
            return
        try:
            start = parse_number(start_text)
            length = parse_number(length_text)
            if start < 0 or length <= 0:
                raise ValueError("Start must be nonnegative and length must be positive.")
        except ValueError as exc:
            messagebox.showerror("Invalid Range", str(exc))
            return

        destination = filedialog.asksaveasfilename(
            title="Export Byte Range",
            defaultextension=".bin",
            initialfile=f"range_0x{start:X}_{length}_bytes.bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")],
        )
        if not destination:
            return

        try:
            self.handle.seek(start)
            remaining = length
            with open(destination, "wb") as out:
                while remaining:
                    block = self.handle.read(min(SEARCH_CHUNK, remaining))
                    if not block:
                        break
                    out.write(block)
                    remaining -= len(block)
            written = length - remaining
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))
            return

        self.status_var.set(f"Exported {written:,} bytes to {destination}")
        messagebox.showinfo("Export Complete", f"Exported {written:,} bytes.")

    def _close_app(self) -> None:
        self.close_source(False)
        self.destroy()


if __name__ == "__main__":
    HexViewer().mainloop()
