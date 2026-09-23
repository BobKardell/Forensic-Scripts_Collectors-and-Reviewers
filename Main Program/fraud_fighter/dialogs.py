from pathlib import Path
from typing import Optional
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from .config import CASES_DIR

class CreateCaseDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, settings: dict):
        super().__init__(parent)
        self.title("Create New Case")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.result: Optional[dict] = None

        self.name = tk.StringVar()
        self.number = tk.StringVar()
        self.examiner = tk.StringVar(value=settings.get("examiner", ""))
        self.organization = tk.StringVar(value=settings.get("organization", ""))
        self.location = tk.StringVar(value=settings.get("case_directory", str(CASES_DIR)))

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Create New Case", style="DialogTitle.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 16)
        )

        fields = [
            ("Case name", self.name),
            ("Case number", self.number),
            ("Examiner", self.examiner),
            ("Organization", self.organization),
        ]
        for row, (label, variable) in enumerate(fields, 1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=5)
            ttk.Entry(frame, textvariable=variable, width=52).grid(
                row=row, column=1, columnspan=2, sticky="ew", padx=(12, 0), pady=5
            )

        ttk.Label(frame, text="Case storage").grid(row=5, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.location).grid(
            row=5, column=1, sticky="ew", padx=(12, 6), pady=5
        )
        ttk.Button(frame, text="Browse…", command=self.choose_location).grid(row=5, column=2)

        ttk.Label(frame, text="Description").grid(row=6, column=0, sticky="nw", pady=5)
        self.description = tk.Text(frame, width=52, height=6, wrap="word")
        self.description.grid(row=6, column=1, columnspan=2, sticky="ew", padx=(12, 0), pady=5)

        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=0, columnspan=3, sticky="e", pady=(18, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(
            buttons,
            text="Create Case",
            style="Primary.TButton",
            command=self.submit,
        ).pack(side="right", padx=(0, 8))

        frame.columnconfigure(1, weight=1)

    def choose_location(self) -> None:
        selected = filedialog.askdirectory(parent=self)
        if selected:
            self.location.set(selected)

    def submit(self) -> None:
        if not self.name.get().strip():
            messagebox.showwarning("Case Name", "Enter a case name.", parent=self)
            return
        location = Path(self.location.get().strip())
        try:
            location.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("Storage Error", str(exc), parent=self)
            return
        self.result = {
            "name": self.name.get().strip(),
            "number": self.number.get().strip(),
            "examiner": self.examiner.get().strip(),
            "organization": self.organization.get().strip(),
            "location": location,
            "description": self.description.get("1.0", "end").strip(),
        }
        self.destroy()


class TextEntryDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, title: str, fields: list[tuple[str, str]], multiline: str = ""):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.result: Optional[dict] = None
        self.variables: dict[str, tk.StringVar] = {}

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=title, style="DialogTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 14)
        )

        row = 1
        for key, label in fields:
            variable = tk.StringVar()
            self.variables[key] = variable
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=5)
            ttk.Entry(frame, textvariable=variable, width=52).grid(
                row=row, column=1, sticky="ew", padx=(12, 0), pady=5
            )
            row += 1

        self.body: Optional[tk.Text] = None
        if multiline:
            ttk.Label(frame, text=multiline).grid(row=row, column=0, sticky="nw", pady=5)
            self.body = tk.Text(frame, width=52, height=8, wrap="word")
            self.body.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=5)
            row += 1

        buttons = ttk.Frame(frame)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(15, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Save", style="Primary.TButton", command=self.submit).pack(
            side="right", padx=(0, 8)
        )
        frame.columnconfigure(1, weight=1)

    def submit(self) -> None:
        self.result = {key: value.get().strip() for key, value in self.variables.items()}
        if self.body is not None:
            self.result["body"] = self.body.get("1.0", "end").strip()
        self.destroy()


