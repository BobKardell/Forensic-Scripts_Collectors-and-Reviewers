from __future__ import annotations
import json
import os
import sqlite3
import subprocess
import sys
import tkinter as tk
import threading
import zipfile
import hashlib
import shutil
import html
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .config import (APP_NAME, APP_VERSION, ASSETS_DIR, PLUGINS_DIR, SCRIPTS_DIR,
                     CASES_DIR, SETTINGS_PATH, LOGO_PATH, COLORS)
from .models import CaseInfo, PluginInfo
from .database import (utc_now, safe_name, load_settings, save_settings,
                       initialize_database, ensure_v4_schema, human_size, read_case)
from .plugins import discover_plugins
from .dialogs import CreateCaseDialog, TextEntryDialog

class SuiteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1480x900")
        self.minsize(1120, 720)
        self.configure(bg=COLORS["navy"])

        self.settings = load_settings()
        self.case: Optional[CaseInfo] = None
        self.plugins: list[PluginInfo] = []
        self.logo: Optional[tk.PhotoImage] = None
        self.content: Optional[ttk.Frame] = None
        self.navigation_buttons: dict[str, ttk.Button] = {}
        self.plugin_processes: dict[str, subprocess.Popen] = {}
        self.selected_evidence_id: Optional[int] = None

        self.configure_styles()
        self.protocol("WM_DELETE_WINDOW", self.close_application)
        self.show_welcome()

    def configure_styles(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", font=("Segoe UI", 10))
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("White.TFrame", background=COLORS["white"])
        style.configure("Navy.TFrame", background=COLORS["navy"])
        style.configure("Rail.TFrame", background=COLORS["navy2"])

        style.configure("TLabel", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("White.TLabel", background=COLORS["white"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"])
        style.configure("WhiteMuted.TLabel", background=COLORS["white"], foreground=COLORS["muted"])
        style.configure(
            "Title.TLabel",
            background=COLORS["panel"],
            foreground=COLORS["navy"],
            font=("Segoe UI Semibold", 22),
        )
        style.configure(
            "DialogTitle.TLabel",
            font=("Segoe UI Semibold", 18),
        )
        style.configure(
            "RailTitle.TLabel",
            background=COLORS["navy2"],
            foreground=COLORS["white"],
            font=("Segoe UI Semibold", 13),
        )
        style.configure(
            "RailMeta.TLabel",
            background=COLORS["navy2"],
            foreground="#b9c9d8",
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardTitle.TLabel",
            background=COLORS["white"],
            foreground=COLORS["navy"],
            font=("Segoe UI Semibold", 13),
        )

        style.configure(
            "Primary.TButton",
            background=COLORS["blue"],
            foreground=COLORS["white"],
            padding=(16, 10),
            borderwidth=0,
            font=("Segoe UI Semibold", 10),
        )
        style.map("Primary.TButton", background=[("active", "#0e78b7")])

        style.configure(
            "Secondary.TButton",
            background=COLORS["slate"],
            foreground=COLORS["white"],
            padding=(14, 9),
            borderwidth=0,
        )
        style.map("Secondary.TButton", background=[("active", COLORS["slate_dark"])])

        style.configure(
            "Nav.TButton",
            background=COLORS["navy2"],
            foreground="#dce7ef",
            anchor="w",
            padding=(15, 10),
            borderwidth=0,
        )
        style.map(
            "Nav.TButton",
            background=[("active", COLORS["slate_dark"])],
            foreground=[("active", COLORS["white"])],
        )
        style.configure(
            "NavSelected.TButton",
            background=COLORS["slate"],
            foreground=COLORS["white"],
            anchor="w",
            padding=(15, 10),
            borderwidth=0,
            font=("Segoe UI Semibold", 10),
        )
        style.configure(
            "Plugin.TButton",
            background=COLORS["navy2"],
            foreground="#dce7ef",
            anchor="w",
            padding=(15, 9),
            borderwidth=0,
        )
        style.map(
            "Plugin.TButton",
            background=[("active", COLORS["slate"])],
            foreground=[("active", COLORS["white"])],
        )

        style.configure(
            "Treeview",
            rowheight=27,
            background=COLORS["white"],
            fieldbackground=COLORS["white"],
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["slate"],
            foreground=COLORS["white"],
            font=("Segoe UI Semibold", 9),
            padding=(7, 7),
        )
        style.map("Treeview.Heading", background=[("active", COLORS["slate_dark"])])

        style.configure(
            "Case.TNotebook",
            background=COLORS["panel"],
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        style.configure(
            "Case.TNotebook.Tab",
            background=COLORS["slate_light"],
            foreground=COLORS["slate_dark"],
            padding=(17, 8),
            borderwidth=1,
            font=("Segoe UI Semibold", 10),
        )
        style.map(
            "Case.TNotebook.Tab",
            background=[("selected", COLORS["slate"]), ("active", "#c8d7e4")],
            foreground=[("selected", COLORS["white"]), ("active", COLORS["slate_dark"])],
            expand=[
                ("selected", (0, 0, 0, 0)),
                ("active", (0, 0, 0, 0)),
                ("!selected", (0, 0, 0, 0)),
            ],
        )

    def clear_window(self) -> None:
        for child in self.winfo_children():
            child.destroy()
        self.logo = None
        self.navigation_buttons.clear()

    def load_logo(self, width: int = 600, height: int = 470) -> Optional[tk.PhotoImage]:
        if not LOGO_PATH.exists():
            return None
        image = tk.PhotoImage(file=str(LOGO_PATH))
        divisor = max(
            1,
            (image.width() + width - 1) // width,
            (image.height() + height - 1) // height,
        )
        return image.subsample(divisor, divisor) if divisor > 1 else image

    def show_welcome(self) -> None:
        self.clear_window()
        self.case = None

        container = ttk.Frame(self, style="Navy.TFrame")
        container.pack(fill="both", expand=True)

        branding = ttk.Frame(container, style="Navy.TFrame", padding=(45, 40))
        branding.pack(side="left", fill="both", expand=True)

        actions = ttk.Frame(container, style="White.TFrame", padding=(52, 45), width=470)
        actions.pack(side="right", fill="y")
        actions.pack_propagate(False)

        self.logo = self.load_logo()
        if self.logo:
            tk.Label(branding, image=self.logo, bg=COLORS["navy"], bd=0).pack(expand=True)
        else:
            tk.Label(
                branding,
                text="FRAUD\nFIGHTER\nTOOLBOX",
                bg=COLORS["navy"],
                fg=COLORS["white"],
                font=("Segoe UI Semibold", 30),
                justify="left",
            ).pack(expand=True)

        ttk.Label(actions, text=APP_NAME, style="CardTitle.TLabel").pack(anchor="w", pady=(55, 5))
        ttk.Label(
            actions,
            text="Digital forensics. Real answers. Stronger outcomes.",
            style="WhiteMuted.TLabel",
            wraplength=350,
        ).pack(anchor="w", pady=(0, 30))

        ttk.Button(
            actions,
            text="＋  Create a New Case",
            style="Primary.TButton",
            command=self.create_case,
        ).pack(fill="x", pady=6)
        ttk.Button(
            actions,
            text="▣  Open an Existing Case",
            style="Secondary.TButton",
            command=self.open_case,
        ).pack(fill="x", pady=6)

        recent = [Path(value) for value in self.settings.get("recent_cases", [])]
        recent = [path for path in recent if path.exists()]
        if recent:
            ttk.Separator(actions).pack(fill="x", pady=24)
            ttk.Label(actions, text="Recent cases", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
            for database in recent[:5]:
                ttk.Button(
                    actions,
                    text=database.parent.name,
                    command=lambda path=database: self.load_case(path),
                ).pack(fill="x", pady=3)

        ttk.Label(
            actions,
            text=f"Version {APP_VERSION}",
            style="WhiteMuted.TLabel",
        ).pack(side="bottom", anchor="e")

    def create_case(self) -> None:
        dialog = CreateCaseDialog(self, self.settings)
        self.wait_window(dialog)
        if not dialog.result:
            return

        data = dialog.result
        folder_label = f"{data['number']}_{data['name']}" if data["number"] else data["name"]
        folder = data["location"] / safe_name(folder_label)

        if folder.exists() and any(folder.iterdir()):
            if not messagebox.askyesno(
                "Existing Folder",
                "The case folder already exists and is not empty. Use it anyway?",
                parent=self,
            ):
                return

        try:
            folder.mkdir(parents=True, exist_ok=True)
            for subfolder in ("Evidence", "Exports", "Reports", "Notes", "Temp"):
                (folder / subfolder).mkdir(exist_ok=True)

            case = CaseInfo(
                name=data["name"],
                number=data["number"],
                examiner=data["examiner"],
                organization=data["organization"],
                description=data["description"],
                folder=folder,
                database=folder / "case.sqlite",
                created_utc=utc_now(),
            )
            initialize_database(case)
            (folder / "case.json").write_text(
                json.dumps(
                    {
                        "name": case.name,
                        "case_number": case.number,
                        "examiner": case.examiner,
                        "organization": case.organization,
                        "description": case.description,
                        "database": str(case.database),
                        "created_utc": case.created_utc,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            messagebox.showerror("Case Creation Failed", str(exc), parent=self)
            return

        self.settings["case_directory"] = str(data["location"])
        self.settings["examiner"] = data["examiner"]
        self.settings["organization"] = data["organization"]
        save_settings(self.settings)
        self.load_case(case.database)

    def open_case(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Open Fraud Fighter Case",
            initialdir=self.settings.get("case_directory", str(CASES_DIR)),
            filetypes=[
                ("Fraud Fighter case", "*.sqlite"),
                ("SQLite database", "*.db"),
                ("All files", "*.*"),
            ],
        )
        if selected:
            self.load_case(Path(selected))

    def load_case(self, database: Path) -> None:
        try:
            ensure_v4_schema(database)
            self.case = read_case(database)
        except Exception as exc:
            messagebox.showerror("Unable to Open Case", str(exc), parent=self)
            return

        recent = [str(database)] + [
            item for item in self.settings.get("recent_cases", []) if item != str(database)
        ]
        self.settings["recent_cases"] = recent[:10]
        save_settings(self.settings)

        self.audit("CASE_OPENED", "case", "1", f"Opened case {self.case.name}")
        self.show_case_shell()

    def audit(self, action: str, object_type: str = "", object_id: str = "", details: str = "") -> None:
        if not self.case:
            return
        with sqlite3.connect(self.case.database) as connection:
            connection.execute(
                """
                INSERT INTO audit_log
                (event_utc, examiner, action, object_type, object_id, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (utc_now(), self.case.examiner, action, object_type, object_id, details),
            )

    def show_case_shell(self) -> None:
        self.clear_window()
        assert self.case is not None
        self.plugins = discover_plugins()

        shell = ttk.Frame(self, style="Panel.TFrame")
        shell.pack(fill="both", expand=True)

        rail = ttk.Frame(shell, style="Rail.TFrame", width=270)
        rail.pack(side="left", fill="y")
        rail.pack_propagate(False)

        # Main case-content area. This must be a Tk widget; without it, the
        # module-level main() function is accidentally used as the parent.
        main = ttk.Frame(shell, style="Panel.TFrame")
        main.pack(side="left", fill="both", expand=True)

        # Fixed footer plus a canvas that scrolls the entire navigation pane.
        bottom = ttk.Frame(rail, style="Rail.TFrame")
        bottom.pack(side="bottom", fill="x")
        ttk.Separator(bottom).pack(fill="x", padx=12, pady=(6, 4))
        ttk.Button(bottom, text="↻   Refresh Tools", style="Nav.TButton", command=self.refresh_plugins).pack(fill="x")
        ttk.Button(bottom, text="↩   Close Case", style="Nav.TButton", command=self.close_case).pack(fill="x", pady=(0, 6))

        nav_wrap = ttk.Frame(rail, style="Rail.TFrame")
        nav_wrap.pack(side="top", fill="both", expand=True)
        nav_canvas = tk.Canvas(nav_wrap, bg=COLORS["navy2"], highlightthickness=0, bd=0)
        nav_scroll = ttk.Scrollbar(nav_wrap, orient="vertical", command=nav_canvas.yview)
        nav_holder = ttk.Frame(nav_canvas, style="Rail.TFrame")
        nav_window = nav_canvas.create_window((0, 0), window=nav_holder, anchor="nw")
        nav_holder.bind("<Configure>", lambda _e: nav_canvas.configure(scrollregion=nav_canvas.bbox("all")))
        nav_canvas.bind("<Configure>", lambda e: nav_canvas.itemconfigure(nav_window, width=e.width))
        nav_canvas.configure(yscrollcommand=nav_scroll.set)
        nav_canvas.pack(side="left", fill="both", expand=True)
        nav_scroll.pack(side="right", fill="y")

        def _wheel(event):
            if getattr(event, "delta", 0):
                nav_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            elif getattr(event, "num", None) == 4:
                nav_canvas.yview_scroll(-1, "units")
            elif getattr(event, "num", None) == 5:
                nav_canvas.yview_scroll(1, "units")
        nav_canvas.bind_all("<MouseWheel>", _wheel)
        nav_canvas.bind_all("<Button-4>", _wheel)
        nav_canvas.bind_all("<Button-5>", _wheel)

        header = ttk.Frame(nav_holder, style="Rail.TFrame", padding=(16, 12))
        header.pack(fill="x")
        self.logo = self.load_logo(width=215, height=150)
        if self.logo:
            tk.Label(header, image=self.logo, bg=COLORS["navy2"], bd=0).pack(anchor="w", pady=(0, 8))
        ttk.Label(header, text="FRAUD FIGHTER TOOLBOX", style="RailTitle.TLabel").pack(anchor="w")
        ttk.Label(header, text=f"Version {APP_VERSION}", style="RailMeta.TLabel").pack(anchor="w")
        ttk.Separator(nav_holder).pack(fill="x", padx=12, pady=(0, 12))

        ttk.Label(nav_holder, text=self.case.name, style="RailTitle.TLabel", wraplength=225).pack(anchor="w", padx=16)
        ttk.Label(nav_holder, text=self.case.number or "No case number", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(2, 14))

        ttk.Label(nav_holder, text="CASE", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(2, 4))
        for page_id, label, symbol in [
            ("dashboard", "Dashboard", "⌂"),
            ("evidence", "Evidence Manager", "▣"),
            ("chain", "Chain of Custody", "⇄"),
            ("bookmarks", "Bookmarks", "★"),
            ("notes", "Notes", "✎"),
            ("reports", "Reports", "▤"),
            ("audit", "Audit Log", "☷"),
        ]:
            button = ttk.Button(nav_holder, text=f"{symbol}   {label}", style="Nav.TButton", command=lambda value=page_id: self.select_case_page(value))
            button.pack(fill="x")
            self.navigation_buttons[page_id] = button

        def add_plugin_group(title: str, tools: list[PluginInfo]) -> None:
            if not tools:
                return
            ttk.Separator(nav_holder).pack(fill="x", padx=12, pady=12)
            ttk.Label(nav_holder, text=title, style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=(0, 5))
            for tool in tools:
                ttk.Button(
                    nav_holder,
                    text=f"{tool.icon}   {tool.name}",
                    style="Plugin.TButton",
                    command=lambda selected=tool: self.launch_plugin_with_evidence(selected),
                ).pack(fill="x")

        def is_explorer(tool: PluginInfo) -> bool:
            text = f"{tool.plugin_id} {tool.name} {tool.category}".lower()
            return any(token in text for token in ("file explorer", "file_explorer", "registry explorer", "registry_explorer", "pst explorer", "pst_explorer"))

        def is_timeline(tool: PluginInfo) -> bool:
            text = f"{tool.plugin_id} {tool.name} {tool.category}".lower()
            return "timeline" in text

        explorer_tools = [tool for tool in self.plugins if is_explorer(tool)]
        timeline_tools = [tool for tool in self.plugins if is_timeline(tool) and tool not in explorer_tools]
        assigned = {tool.plugin_id for tool in explorer_tools + timeline_tools}
        analysis_tools = [
            tool for tool in self.plugins
            if tool.plugin_id not in assigned and (
                tool.category.lower() == "analysis tools"
                or any(token in f"{tool.plugin_id} {tool.name}".lower() for token in ("hex", "artifact", "analytics", "hash", "sqlite"))
            )
        ]
        assigned.update(tool.plugin_id for tool in analysis_tools)
        plugin_tools = [tool for tool in self.plugins if tool.plugin_id not in assigned]

        add_plugin_group("EXPLORERS", explorer_tools)
        add_plugin_group("TIMELINE", timeline_tools)
        add_plugin_group("ANALYSIS TOOLS", analysis_tools)
        add_plugin_group("PLUGINS", plugin_tools)

        if not self.plugins:
            ttk.Label(nav_holder, text="No tools installed", style="RailMeta.TLabel").pack(anchor="w", padx=16, pady=10)

        topbar = ttk.Frame(main, style="White.TFrame", padding=(22, 13))
        topbar.pack(fill="x")
        ttk.Label(topbar, text=self.case.name, style="CardTitle.TLabel").pack(side="left")
        ttk.Label(
            topbar,
            text=f"Examiner: {self.case.examiner or 'Not specified'}",
            style="WhiteMuted.TLabel",
        ).pack(side="right")
        ttk.Separator(main).pack(fill="x")

        self.content = ttk.Frame(main, style="Panel.TFrame", padding=22)
        self.content.pack(fill="both", expand=True)
        self.select_case_page("dashboard")

    def refresh_plugins(self) -> None:
        self.audit("PLUGINS_REFRESHED", "application", "", "Refreshed plugin discovery")
        self.show_case_shell()

    def select_case_page(self, page_id: str) -> None:
        for key, button in self.navigation_buttons.items():
            button.configure(style="NavSelected.TButton" if key == page_id else "Nav.TButton")

        if not self.content:
            return
        for child in self.content.winfo_children():
            child.destroy()

        handlers = {
            "dashboard": self.show_dashboard,
            "evidence": self.show_evidence,
            "chain": self.show_chain_of_custody,
            "bookmarks": self.show_bookmarks,
            "notes": self.show_notes,
            "reports": self.show_reports,
            "audit": self.show_audit,
        }
        handler = handlers.get(page_id, self.show_dashboard)
        try:
            handler()
        except Exception as exc:
            # Never leave the main pane blank. Show a useful error and keep
            # Dashboard navigation available so the examiner can recover.
            ttk.Label(self.content, text="Unable to display page", style="Title.TLabel").pack(anchor="w")
            ttk.Label(
                self.content,
                text=f"{type(exc).__name__}: {exc}",
                style="Muted.TLabel",
                wraplength=900,
            ).pack(anchor="w", pady=(8, 16))
            ttk.Button(
                self.content,
                text="Return to Dashboard",
                style="Primary.TButton",
                command=lambda: self.select_case_page("dashboard"),
            ).pack(anchor="w")

    def heading(self, title: str, subtitle: str) -> None:
        assert self.content is not None
        ttk.Label(self.content, text=title, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            self.content,
            text=subtitle,
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 18))

    def show_dashboard(self) -> None:
        assert self.case is not None and self.content is not None
        self.heading("Case Dashboard", "Manage the active case and launch forensic plugins from the left rail.")

        with sqlite3.connect(self.case.database) as connection:
            evidence_count = connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            bookmarks_count = connection.execute("SELECT COUNT(*) FROM bookmarks").fetchone()[0]
            notes_count = connection.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
            reports_count = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            runs_count = connection.execute("SELECT COUNT(*) FROM plugin_runs").fetchone()[0]

        cards = ttk.Frame(self.content, style="Panel.TFrame")
        cards.pack(fill="x", pady=(0, 20))
        for index, (value, label) in enumerate(
            [
                (evidence_count, "Evidence Items"),
                (bookmarks_count, "Bookmarks"),
                (notes_count, "Case Notes"),
                (reports_count, "Reports"),
                (runs_count, "Plugin Launches"),
            ]
        ):
            card = tk.Frame(
                cards,
                bg=COLORS["white"],
                highlightbackground=COLORS["border"],
                highlightthickness=1,
                padx=18,
                pady=14,
            )
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 5, 5))
            tk.Label(
                card,
                text=f"{value:,}",
                bg=COLORS["white"],
                fg=COLORS["navy"],
                font=("Segoe UI Semibold", 21),
            ).pack(anchor="w")
            tk.Label(
                card,
                text=label,
                bg=COLORS["white"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9),
            ).pack(anchor="w")
            cards.columnconfigure(index, weight=1)

        case_panel = tk.Frame(
            self.content,
            bg=COLORS["white"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=22,
            pady=18,
        )
        case_panel.pack(fill="x", pady=(0, 18))
        tk.Label(
            case_panel,
            text="Case Information",
            bg=COLORS["white"],
            fg=COLORS["navy"],
            font=("Segoe UI Semibold", 14),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        information = [
            ("Case name", self.case.name),
            ("Case number", self.case.number or "Not specified"),
            ("Examiner", self.case.examiner or "Not specified"),
            ("Organization", self.case.organization or "Not specified"),
            ("Case folder", str(self.case.folder)),
            ("Created", self.case.created_utc),
        ]
        for row, (label, value) in enumerate(information, 1):
            tk.Label(case_panel, text=label, bg=COLORS["white"], fg=COLORS["muted"]).grid(
                row=row, column=0, sticky="nw", padx=(0, 18), pady=3
            )
            tk.Label(
                case_panel,
                text=value,
                bg=COLORS["white"],
                fg=COLORS["text"],
                justify="left",
                wraplength=850,
            ).grid(row=row, column=1, sticky="w", pady=3)

        if self.case.description:
            tk.Label(case_panel, text="Description", bg=COLORS["white"], fg=COLORS["muted"]).grid(
                row=len(information) + 1, column=0, sticky="nw", padx=(0, 18), pady=3
            )
            tk.Label(
                case_panel,
                text=self.case.description,
                bg=COLORS["white"],
                fg=COLORS["text"],
                justify="left",
                wraplength=850,
            ).grid(row=len(information) + 1, column=1, sticky="w", pady=3)

        plugin_panel = tk.Frame(
            self.content,
            bg=COLORS["white"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=22,
            pady=16,
        )
        plugin_panel.pack(fill="both", expand=True)
        tk.Label(
            plugin_panel,
            text="Installed Plugins",
            bg=COLORS["white"],
            fg=COLORS["navy"],
            font=("Segoe UI Semibold", 14),
        ).pack(anchor="w")
        tk.Label(
            plugin_panel,
            text=(
                f"{len(self.plugins)} plugin(s) installed. Select any plugin in the left rail "
                "to launch it in a separate window."
            ),
            bg=COLORS["white"],
            fg=COLORS["muted"],
        ).pack(anchor="w", pady=(4, 0))

    def show_evidence(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Evidence Manager", "Choose a mounted source, import a Collector package, or run the Live Evidence Collector.")

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(toolbar, text="＋ Choose Mounted Source", style="Primary.TButton", command=self.add_mounted_source).pack(side="left")
        ttk.Button(toolbar, text="Save Evidence", style="Primary.TButton", command=self.save_selected_evidence).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Import Collector ZIP", style="Secondary.TButton", command=self.import_collector_zip).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Run Live Collector", style="Secondary.TButton", command=self.run_live_collector).pack(side="left")
        ttk.Button(toolbar, text="Open in File Explorer", style="Secondary.TButton", command=self.open_selected_evidence).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Open Evidence Folder", style="Secondary.TButton", command=lambda: self.open_folder(self.case.folder / "Evidence")).pack(side="left", padx=8)

        columns = ("id", "number", "name", "type", "source", "files", "size", "status", "added")
        self.evidence_tree = ttk.Treeview(self.content, columns=columns, show="headings", selectmode="browse")
        specs = [
            ("id","ID",50),("number","Evidence No.",105),("name","Name",210),("type","Type",145),
            ("source","Source / Package",320),("files","Files",90),("size","Size",105),("status","Status",100),("added","Added UTC",190)
        ]
        for column,label,width in specs:
            self.evidence_tree.heading(column,text=label)
            self.evidence_tree.column(column,width=width,anchor="w")
        self.evidence_tree.pack(fill="both", expand=True)
        self.evidence_tree.bind("<Double-1>", lambda _e: self.open_selected_evidence())
        self.evidence_tree.bind("<<TreeviewSelect>>", self.on_evidence_selected)

        with sqlite3.connect(self.case.database) as connection:
            rows = connection.execute("""
                SELECT id, evidence_number, name, evidence_type,
                       COALESCE(package_path, source), file_count, size_bytes,
                       import_status, added_utc
                FROM evidence ORDER BY id DESC
            """).fetchall()
        for row in rows:
            shown = list(row)
            shown[6] = human_size(shown[6] or 0)
            item = self.evidence_tree.insert("", "end", values=shown)
            if self.selected_evidence_id == row[0]:
                self.evidence_tree.selection_set(item)
                self.evidence_tree.focus(item)

    def run_live_collector(self) -> None:
        """Launch the Live Evidence Collector from Evidence Manager."""
        candidates = [
            item for item in self.plugins
            if item.plugin_id in ("live_evidence_collector", "evidence_collector")
            or "live evidence collector" in item.name.lower()
        ]
        if not candidates:
            messagebox.showerror(
                "Live Collector Missing",
                "No Live Evidence Collector was found. Place its Python script in the Scripts folder and include TITLE: Live Evidence Collector in its header.",
                parent=self,
            )
            return
        self.launch_plugin(candidates[0])
        self.audit("LIVE_COLLECTOR_LAUNCHED", "plugin", candidates[0].plugin_id, "Launched from Evidence Manager")

    def next_evidence_number(self) -> str:
        assert self.case is not None
        with sqlite3.connect(self.case.database) as connection:
            value = connection.execute("SELECT COALESCE(MAX(id),0)+1 FROM evidence").fetchone()[0]
        return f"E-{value:03d}"

    def choose_source_path(self) -> Optional[Path]:
        initial = "C:/" if os.name == "nt" else str(Path.home())
        selected = filedialog.askdirectory(parent=self, title="Choose Mounted Drive or Evidence Folder", initialdir=initial)
        return Path(selected) if selected else None

    def add_mounted_source(self) -> None:
        assert self.case is not None
        source = self.choose_source_path()
        if not source:
            return
        name = source.drive.rstrip(":\\/") if source.drive else source.name
        if not name:
            name = str(source)
        number = self.next_evidence_number()
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute("""
                INSERT INTO evidence
                (evidence_number, name, evidence_type, source, root_path, mounted_volume,
                 evidence_root, custodian, description, acquired_utc, added_utc, modified_utc,
                 status, import_status, mounted_volume_verified)
                VALUES (?, ?, 'Mounted Source', ?, ?, ?, ?, '', '', '', ?, ?, 'Active', 'Ready', ?)
            """, (number, name, str(source), str(source), str(source), str(source), utc_now(), utc_now(), int(source.exists())))
            evidence_id = cursor.lastrowid
        self.selected_evidence_id = int(evidence_id)
        self.audit("EVIDENCE_SOURCE_ADDED", "evidence", str(evidence_id), f"Mounted source {source}")
        self.select_case_page("evidence")

    def on_evidence_selected(self, _event=None) -> None:
        tree = getattr(self, "evidence_tree", None)
        if tree and tree.selection():
            try:
                self.selected_evidence_id = int(tree.item(tree.selection()[0], "values")[0])
            except (TypeError, ValueError, IndexError):
                self.selected_evidence_id = None

    def save_selected_evidence(self) -> None:
        """Persist edits for the selected evidence record to the case database."""
        assert self.case is not None
        tree = getattr(self, "evidence_tree", None)
        if tree and tree.selection():
            self.on_evidence_selected()
        if not self.selected_evidence_id:
            messagebox.showinfo("Select Evidence", "Select an evidence item to save or edit.", parent=self)
            return
        with sqlite3.connect(self.case.database) as con:
            row = con.execute(
                """SELECT name, evidence_number, evidence_type,
                          COALESCE(mounted_volume, root_path, ''),
                          COALESCE(source_image, source, ''),
                          COALESCE(description, ''), COALESCE(notes, '')
                   FROM evidence WHERE id=?""", (self.selected_evidence_id,)
            ).fetchone()
        if not row:
            messagebox.showerror("Evidence", "The selected evidence record no longer exists.", parent=self)
            return

        dialog = tk.Toplevel(self)
        dialog.title("Save Evidence")
        dialog.transient(self); dialog.grab_set(); dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=18); frame.pack(fill="both", expand=True)
        values = {
            "name": tk.StringVar(value=row[0] or ""),
            "number": tk.StringVar(value=row[1] or ""),
            "type": tk.StringVar(value=row[2] or ""),
            "mounted": tk.StringVar(value=row[3] or ""),
            "source": tk.StringVar(value=row[4] or ""),
        }
        labels = [("name","Evidence name"),("number","Evidence number"),("type","Evidence type"),("mounted","Mounted volume / evidence root"),("source","Source image or source path")]
        ttk.Label(frame, text="Save Evidence", style="DialogTitle.TLabel").grid(row=0,column=0,columnspan=3,sticky="w",pady=(0,12))
        for index,(key,label) in enumerate(labels,1):
            ttk.Label(frame,text=label).grid(row=index,column=0,sticky="w",pady=5)
            ttk.Entry(frame,textvariable=values[key],width=62).grid(row=index,column=1,sticky="ew",padx=(12,6),pady=5)
            if key == "mounted":
                def browse():
                    chosen=filedialog.askdirectory(parent=dialog,title="Choose Mounted Volume or Evidence Root")
                    if chosen: values["mounted"].set(chosen)
                ttk.Button(frame,text="Browse…",command=browse).grid(row=index,column=2,pady=5)
        ttk.Label(frame,text="Description / notes").grid(row=6,column=0,sticky="nw",pady=5)
        notes=tk.Text(frame,width=62,height=7,wrap="word"); notes.grid(row=6,column=1,columnspan=2,sticky="ew",padx=(12,0),pady=5)
        notes.insert("1.0", "\n".join(part for part in (row[5], row[6]) if part))
        def save():
            mounted=values["mounted"].get().strip()
            if not values["name"].get().strip():
                messagebox.showwarning("Evidence Name","Enter an evidence name.",parent=dialog); return
            verified=int(bool(mounted and Path(mounted).exists()))
            now=utc_now()
            with sqlite3.connect(self.case.database) as con:
                con.execute(
                    """UPDATE evidence SET name=?, evidence_number=?, evidence_type=?,
                              mounted_volume=?, evidence_root=?, root_path=?, source_image=?, source=?,
                              description=?, notes=?, modified_utc=?, mounted_volume_verified=?
                       WHERE id=?""",
                    (values["name"].get().strip(), values["number"].get().strip(), values["type"].get().strip(),
                     mounted, mounted, mounted, values["source"].get().strip(), values["source"].get().strip(),
                     notes.get("1.0","end").strip(), notes.get("1.0","end").strip(), now, verified,
                     self.selected_evidence_id))
            self.audit("EVIDENCE_SAVED", "evidence", str(self.selected_evidence_id), f"Mounted volume={mounted}; verified={bool(verified)}")
            dialog.destroy(); self.select_case_page("evidence")
            messagebox.showinfo("Evidence Saved", "The evidence information was saved to the case database.", parent=self)
        buttons=ttk.Frame(frame); buttons.grid(row=7,column=0,columnspan=3,sticky="e",pady=(15,0))
        ttk.Button(buttons,text="Cancel",command=dialog.destroy).pack(side="right")
        ttk.Button(buttons,text="Save",style="Primary.TButton",command=save).pack(side="right",padx=(0,8))
        frame.columnconfigure(1,weight=1)
        self.wait_window(dialog)

    def selected_evidence_environment(self) -> dict[str, str]:
        assert self.case is not None
        evidence_id = self.selected_evidence_id
        tree = getattr(self, "evidence_tree", None)
        if tree and tree.winfo_exists() and tree.selection():
            self.on_evidence_selected()
            evidence_id = self.selected_evidence_id
        if not evidence_id:
            with sqlite3.connect(self.case.database) as con:
                rows = con.execute("SELECT id FROM evidence ORDER BY id DESC LIMIT 2").fetchall()
            if len(rows) == 1:
                evidence_id = int(rows[0][0]); self.selected_evidence_id = evidence_id
        if not evidence_id:
            return {}
        with sqlite3.connect(self.case.database) as con:
            row = con.execute(
                """SELECT id, name, COALESCE(NULLIF(mounted_volume,''), NULLIF(evidence_root,''), NULLIF(root_path,''), source, '')
                   FROM evidence WHERE id=?""", (evidence_id,)
            ).fetchone()
        if not row:
            return {}
        return {"FFT_EVIDENCE_ID": str(row[0]), "FFT_EVIDENCE_NAME": row[1] or "", "FFT_EVIDENCE_ROOT": row[2] or ""}

    def launch_plugin_with_evidence(self, plugin: PluginInfo) -> None:
        env = self.selected_evidence_environment()
        if plugin.plugin_id == "registry_artifacts" and not env.get("FFT_EVIDENCE_ID"):
            messagebox.showinfo("Select Evidence", "Open Evidence Manager, select the mounted-volume evidence, and then launch Registry Artifacts Explorer.", parent=self)
            return
        self.launch_plugin(plugin, env)

    def import_collector_zip(self) -> None:
        assert self.case is not None
        selected = filedialog.askopenfilename(parent=self, title="Open Live Evidence Collector ZIP", filetypes=[("ZIP packages","*.zip"),("All files","*.*")])
        if not selected:
            return
        package = Path(selected)
        try:
            with zipfile.ZipFile(package, "r") as zf:
                bad = zf.testzip()
                if bad:
                    raise ValueError(f"ZIP integrity test failed at {bad}")
                names = zf.namelist()
                manifest_name = next((n for n in names if Path(n).name.lower() in ("manifest.json","collection_manifest.json")), "")
                collector_markers = ("registry", "event", "prefetch", "browser", "collection")
                is_collector = bool(manifest_name or any(any(marker in n.lower() for marker in collector_markers) for n in names))
                if not is_collector and not messagebox.askyesno("Generic ZIP", "This ZIP does not appear to contain a Live Evidence Collector manifest. Import it as generic ZIP evidence?", parent=self):
                    return
        except Exception as exc:
            messagebox.showerror("Invalid ZIP", str(exc), parent=self)
            return

        name = package.stem
        destination = self.case.folder / "Evidence" / safe_name(name)
        counter = 2
        while destination.exists():
            destination = self.case.folder / "Evidence" / f"{safe_name(name)}_{counter}"
            counter += 1
        destination.mkdir(parents=True, exist_ok=False)
        number = self.next_evidence_number()
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute("""
                INSERT INTO evidence
                (evidence_number, name, evidence_type, source, root_path, package_path,
                 custodian, description, acquired_utc, added_utc, status, import_status)
                VALUES (?, ?, ?, ?, ?, ?, '', '', '', ?, 'Active', 'Importing')
            """, (number, name, "Live Collector ZIP" if is_collector else "Generic ZIP", str(package), str(destination), str(package), utc_now()))
            evidence_id = cursor.lastrowid
        self.audit("EVIDENCE_IMPORT_STARTED", "evidence", str(evidence_id), str(package))

        progress = tk.Toplevel(self)
        progress.title("Importing Evidence")
        progress.transient(self)
        ttk.Label(progress, text=f"Importing {package.name}…", padding=18).pack()
        bar = ttk.Progressbar(progress, mode="indeterminate", length=360)
        bar.pack(padx=18, pady=(0,18)); bar.start(12)

        def worker():
            try:
                sha = hashlib.sha256()
                with package.open("rb") as fh:
                    for block in iter(lambda: fh.read(1024*1024), b""):
                        sha.update(block)
                manifest_text = ""
                with zipfile.ZipFile(package, "r") as zf:
                    root_resolved = destination.resolve()
                    for member in zf.infolist():
                        target = (destination / member.filename).resolve()
                        if root_resolved not in target.parents and target != root_resolved:
                            raise ValueError(f"Unsafe ZIP path: {member.filename}")
                    zf.extractall(destination)
                    if manifest_name:
                        try: manifest_text = zf.read(manifest_name).decode("utf-8", errors="replace")
                        except Exception: pass
                file_count=0; size_bytes=0
                for root, _dirs, files in os.walk(destination):
                    for filename in files:
                        file_count += 1
                        try: size_bytes += (Path(root)/filename).stat().st_size
                        except OSError: pass
                with sqlite3.connect(self.case.database) as connection:
                    connection.execute("""UPDATE evidence SET package_sha256=?, file_count=?, size_bytes=?, import_status='Ready', collector_manifest=? WHERE id=?""",
                                       (sha.hexdigest(), file_count, size_bytes, manifest_text, evidence_id))
                self.audit("EVIDENCE_IMPORT_COMPLETED", "evidence", str(evidence_id), f"{file_count} files; SHA256={sha.hexdigest()}")
                self.after(0, lambda: messagebox.showinfo("Import Complete", f"Imported {file_count:,} files\nDestination: {destination}\nSHA-256: {sha.hexdigest()}", parent=self))
            except Exception as exc:
                shutil.rmtree(destination, ignore_errors=True)
                with sqlite3.connect(self.case.database) as connection:
                    connection.execute("UPDATE evidence SET import_status='Failed' WHERE id=?", (evidence_id,))
                self.after(0, lambda: messagebox.showerror("Import Failed", str(exc), parent=self))
            finally:
                self.after(0, progress.destroy)
                self.after(0, lambda: self.select_case_page("evidence"))
        threading.Thread(target=worker, daemon=True).start()

    def open_selected_evidence(self) -> None:
        assert self.case is not None
        tree = getattr(self, "evidence_tree", None)
        if not tree or not tree.selection():
            messagebox.showinfo("Select Evidence", "Select an evidence item first.", parent=self)
            return
        evidence_id = tree.item(tree.selection()[0], "values")[0]
        with sqlite3.connect(self.case.database) as connection:
            row = connection.execute("SELECT id, name, COALESCE(NULLIF(mounted_volume,''), NULLIF(evidence_root,''), root_path) FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row or not row[2] or not Path(row[2]).exists():
            messagebox.showwarning("Evidence Unavailable", "The evidence path is not currently available.", parent=self)
            return
        plugin = next((item for item in self.plugins if item.plugin_id == "file_explorer"), None)
        if not plugin:
            messagebox.showerror("File Explorer Missing", "The File Explorer plugin is not installed.", parent=self)
            return
        self.launch_plugin(plugin, {"FFT_EVIDENCE_ID": str(row[0]), "FFT_EVIDENCE_NAME": row[1], "FFT_EVIDENCE_ROOT": row[2]})

    def show_chain_of_custody(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Chain of Custody", "Record, edit, and report every transfer of evidence.")
        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(toolbar, text="＋ Add Entry", style="Primary.TButton", command=lambda: self.edit_custody_entry()).pack(side="left")
        ttk.Button(toolbar, text="Edit", command=self.edit_selected_custody).pack(side="left", padx=6)
        ttk.Button(toolbar, text="Delete", command=self.delete_selected_custody).pack(side="left")
        ttk.Button(toolbar, text="Create Chain of Custody Report", style="Secondary.TButton", command=self.create_chain_report).pack(side="right")
        columns=("id","evidence","transfer","released","received","purpose","location","condition")
        self.custody_tree=ttk.Treeview(self.content,columns=columns,show="headings",selectmode="browse")
        for col,label,width in (("id","ID",50),("evidence","Evidence",180),("transfer","Transfer UTC",190),("released","Released By",150),("received","Received By",150),("purpose","Purpose",220),("location","Location",160),("condition","Condition",150)):
            self.custody_tree.heading(col,text=label); self.custody_tree.column(col,width=width,anchor="w")
        self.custody_tree.pack(fill="both",expand=True)
        self.custody_tree.bind("<Double-1>",lambda _e:self.edit_selected_custody())
        with sqlite3.connect(self.case.database) as con:
            rows=con.execute("""SELECT c.id, COALESCE(e.evidence_number||' - ','')||COALESCE(e.name,'Unassigned'), c.transfer_utc,c.released_by,c.received_by,c.purpose,c.location,c.condition FROM chain_of_custody c LEFT JOIN evidence e ON e.id=c.evidence_id ORDER BY c.transfer_utc DESC,c.id DESC""").fetchall()
        for row in rows:self.custody_tree.insert("","end",values=row)

    def edit_selected_custody(self) -> None:
        selection=getattr(self,"custody_tree",None).selection() if getattr(self,"custody_tree",None) else ()
        if not selection:
            messagebox.showinfo("Select Entry","Select a chain-of-custody entry first.",parent=self); return
        self.edit_custody_entry(int(self.custody_tree.item(selection[0],"values")[0]))

    def edit_custody_entry(self, entry_id: Optional[int]=None) -> None:
        assert self.case is not None
        with sqlite3.connect(self.case.database) as con:
            evidence=con.execute("SELECT id,COALESCE(evidence_number||' - ','')||name FROM evidence ORDER BY id").fetchall()
            row=con.execute("SELECT evidence_id,transfer_utc,released_by,released_organization,received_by,received_organization,purpose,method,location,condition,comments FROM chain_of_custody WHERE id=?",(entry_id,)).fetchone() if entry_id else None
        win=tk.Toplevel(self); win.title("Edit Chain of Custody" if entry_id else "Add Chain of Custody"); win.transient(self); win.grab_set(); win.geometry("680x650")
        frame=ttk.Frame(win,padding=18); frame.pack(fill="both",expand=True)
        fields={}; evidence_map={label:eid for eid,label in evidence}; labels=list(evidence_map)
        values=list(row) if row else [None,utc_now(),"","","","","","","","",""]
        ttk.Label(frame,text="Evidence").grid(row=0,column=0,sticky="w",pady=4); ev=tk.StringVar(value=next((lab for lab,eid in evidence_map.items() if eid==values[0]),labels[0] if labels else "")); ttk.Combobox(frame,textvariable=ev,values=labels,state="readonly").grid(row=0,column=1,sticky="ew",pady=4)
        specs=[("transfer_utc","Transfer date/time (UTC)"),("released_by","Released by"),("released_organization","Released organization"),("received_by","Received by"),("received_organization","Received organization"),("purpose","Purpose"),("method","Method"),("location","Location"),("condition","Condition")]
        for i,(key,label) in enumerate(specs,1):
            ttk.Label(frame,text=label).grid(row=i,column=0,sticky="w",pady=4); var=tk.StringVar(value=str(values[i] or "")); ttk.Entry(frame,textvariable=var).grid(row=i,column=1,sticky="ew",pady=4); fields[key]=var
        ttk.Label(frame,text="Comments").grid(row=10,column=0,sticky="nw",pady=4); comments=tk.Text(frame,height=7,wrap="word"); comments.grid(row=10,column=1,sticky="nsew",pady=4); comments.insert("1.0",str(values[10] or "")); frame.columnconfigure(1,weight=1); frame.rowconfigure(10,weight=1)
        def save():
            now=utc_now(); vals=(evidence_map.get(ev.get()),fields['transfer_utc'].get().strip() or now,fields['released_by'].get().strip(),fields['released_organization'].get().strip(),fields['received_by'].get().strip(),fields['received_organization'].get().strip(),fields['purpose'].get().strip(),fields['method'].get().strip(),fields['location'].get().strip(),fields['condition'].get().strip(),comments.get('1.0','end').strip(),now)
            with sqlite3.connect(self.case.database) as con:
                if entry_id: con.execute("UPDATE chain_of_custody SET evidence_id=?,transfer_utc=?,released_by=?,released_organization=?,received_by=?,received_organization=?,purpose=?,method=?,location=?,condition=?,comments=?,modified_utc=? WHERE id=?",vals+(entry_id,)); obj=entry_id
                else: obj=con.execute("INSERT INTO chain_of_custody(evidence_id,transfer_utc,released_by,released_organization,received_by,received_organization,purpose,method,location,condition,comments,created_utc,modified_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",vals[:-1]+(now,now)).lastrowid
            self.audit("CUSTODY_ENTRY_SAVED","chain_of_custody",str(obj),fields['purpose'].get().strip()); win.destroy(); self.select_case_page("chain")
        ttk.Button(frame,text="Save",style="Primary.TButton",command=save).grid(row=11,column=1,sticky="e",pady=(12,0))

    def delete_selected_custody(self) -> None:
        selection=getattr(self,"custody_tree",None).selection() if getattr(self,"custody_tree",None) else ()
        if not selection:return
        entry_id=int(self.custody_tree.item(selection[0],"values")[0])
        if not messagebox.askyesno("Delete Entry","Delete this chain-of-custody entry?",parent=self):return
        with sqlite3.connect(self.case.database) as con:con.execute("DELETE FROM chain_of_custody WHERE id=?",(entry_id,))
        self.audit("CUSTODY_ENTRY_DELETED","chain_of_custody",str(entry_id),""); self.select_case_page("chain")

    def create_chain_report(self) -> None:
        assert self.case is not None
        reports_dir=self.case.folder/"Reports"; reports_dir.mkdir(parents=True,exist_ok=True); stamp=utc_now().replace(":","-").replace("+00:00","Z"); path=reports_dir/f"{safe_name(self.case.name)}_Chain_of_Custody_{stamp}.html"
        with sqlite3.connect(self.case.database) as con: rows=con.execute("""SELECT COALESCE(e.evidence_number||' - ','')||COALESCE(e.name,'Unassigned'),c.transfer_utc,c.released_by,c.released_organization,c.received_by,c.received_organization,c.purpose,c.method,c.location,c.condition,c.comments FROM chain_of_custody c LEFT JOIN evidence e ON e.id=c.evidence_id ORDER BY c.transfer_utc,c.id""").fetchall()
        body=''.join('<tr>'+''.join(f'<td>{html.escape(str(v or ""))}</td>' for v in r)+'</tr>' for r in rows)
        doc=f"""<!doctype html><html><head><meta charset='utf-8'><title>Chain of Custody</title><style>body{{font-family:Segoe UI,Arial;margin:35px;color:#172431}}header{{background:#061522;color:white;padding:20px}}table{{border-collapse:collapse;width:100%;font-size:11px}}th,td{{border:1px solid #aebdca;padding:6px;vertical-align:top}}th{{background:#587795;color:white}}</style></head><body><header><h1>Fraud Fighter Toolbox</h1><div>Chain of Custody Report</div></header><p><b>Case:</b> {html.escape(self.case.name)} &nbsp; <b>Case No.:</b> {html.escape(self.case.number)}<br><b>Examiner:</b> {html.escape(self.case.examiner)} &nbsp; <b>Generated:</b> {html.escape(utc_now())}</p><table><tr><th>Evidence</th><th>Transfer UTC</th><th>Released By</th><th>Released Org.</th><th>Received By</th><th>Received Org.</th><th>Purpose</th><th>Method</th><th>Location</th><th>Condition</th><th>Comments</th></tr>{body}</table></body></html>"""
        path.write_text(doc,encoding='utf-8')
        with sqlite3.connect(self.case.database) as con: rid=con.execute("INSERT INTO reports(title,report_type,file_path,created_utc,description) VALUES(?,?,?,?,?)",(path.stem,"CHAIN OF CUSTODY",str(path),utc_now(),"Generated chain of custody report")).lastrowid
        self.audit("CHAIN_REPORT_CREATED","report",str(rid),str(path)); messagebox.showinfo("Report Created",f"Chain of custody report created:\n{path}",parent=self); self.select_case_page("reports")

    def show_bookmarks(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Bookmarks", "Review and manage bookmarked files, registry items, email records, timeline events, and other case artifacts.")

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(toolbar, text="＋ Add Bookmark", style="Primary.TButton", command=self.add_bookmark).pack(side="left")
        ttk.Button(toolbar, text="Edit", style="Secondary.TButton", command=lambda: self.edit_bookmark(tree)).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Delete", style="Secondary.TButton", command=lambda: self.delete_bookmark(tree)).pack(side="left", padx=(8, 0))

        search_var = tk.StringVar()
        category_var = tk.StringVar(value="All Categories")
        ttk.Label(toolbar, text="Search").pack(side="left", padx=(24, 5))
        search_entry = ttk.Entry(toolbar, textvariable=search_var, width=28)
        search_entry.pack(side="left")
        ttk.Label(toolbar, text="Category").pack(side="left", padx=(12, 5))
        category_combo = ttk.Combobox(toolbar, textvariable=category_var, state="readonly", width=18)
        category_combo.pack(side="left")

        panes = ttk.Panedwindow(self.content, orient=tk.HORIZONTAL)
        panes.pack(fill="both", expand=True)
        list_frame = ttk.Frame(panes, style="Panel.TFrame")
        detail_frame = ttk.LabelFrame(panes, text="Bookmark Details", padding=10)
        panes.add(list_frame, weight=3)
        panes.add(detail_frame, weight=2)

        columns = ("id", "title", "category", "type", "evidence", "created")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")
        for column, label, width in [
            ("id", "ID", 50), ("title", "Title", 280), ("category", "Category", 120),
            ("type", "Object Type", 125), ("evidence", "Evidence", 190), ("created", "Created UTC", 190),
        ]:
            tree.heading(column, text=label)
            tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        details = tk.Text(detail_frame, wrap="word", state="disabled", background=COLORS["white"], relief="flat")
        details.pack(fill="both", expand=True)

        def load_rows(*_args) -> None:
            selected_category = category_var.get()
            term = search_var.get().strip()
            sql = """SELECT b.id,b.title,b.category,b.object_type,
                     COALESCE(e.evidence_number || ' - ', '') || COALESCE(e.name,''),b.created_utc
                     FROM bookmarks b LEFT JOIN evidence e ON e.id=b.evidence_id WHERE 1=1"""
            params = []
            if selected_category and selected_category != "All Categories":
                sql += " AND b.category=?"; params.append(selected_category)
            if term:
                sql += " AND (b.title LIKE ? OR b.reference LIKE ? OR b.notes LIKE ? OR b.object_type LIKE ?)"
                params.extend([f"%{term}%"] * 4)
            sql += " ORDER BY b.id DESC"
            tree.delete(*tree.get_children())
            with sqlite3.connect(self.case.database) as connection:
                for row in connection.execute(sql, params):
                    tree.insert("", "end", values=row)

        with sqlite3.connect(self.case.database) as connection:
            categories = [row[0] for row in connection.execute("SELECT DISTINCT category FROM bookmarks WHERE category<>'' ORDER BY category")]
        category_combo["values"] = ["All Categories", *categories]
        search_entry.bind("<KeyRelease>", load_rows)
        category_combo.bind("<<ComboboxSelected>>", load_rows)

        def show_detail(_event=None) -> None:
            selection = tree.selection()
            details.configure(state="normal"); details.delete("1.0", "end")
            if selection:
                bookmark_id = int(tree.item(selection[0], "values")[0])
                with sqlite3.connect(self.case.database) as connection:
                    row = connection.execute("""SELECT b.id,b.title,b.category,b.object_type,b.object_id,b.reference,b.notes,
                        b.examiner,b.created_utc,b.modified_utc,COALESCE(e.evidence_number || ' - ', '') || COALESCE(e.name,'')
                        FROM bookmarks b LEFT JOIN evidence e ON e.id=b.evidence_id WHERE b.id=?""", (bookmark_id,)).fetchone()
                if row:
                    labels = ("ID","Title","Category","Object Type","Object ID","Reference / Path","Notes","Examiner","Created UTC","Modified UTC","Evidence")
                    for label, value in zip(labels, row): details.insert("end", f"{label}: {value or ''}\n\n")
            details.configure(state="disabled")
        tree.bind("<<TreeviewSelect>>", show_detail)
        tree.bind("<Double-1>", lambda _event: self.edit_bookmark(tree))
        load_rows()

    def bookmark_dialog(self, bookmark_id: Optional[int] = None) -> None:
        assert self.case is not None
        existing = None
        if bookmark_id:
            with sqlite3.connect(self.case.database) as connection:
                existing = connection.execute("SELECT title,category,object_type,object_id,evidence_id,reference,notes FROM bookmarks WHERE id=?", (bookmark_id,)).fetchone()
        dialog = tk.Toplevel(self); dialog.title("Edit Bookmark" if bookmark_id else "Add Bookmark"); dialog.transient(self); dialog.grab_set(); dialog.geometry("650x610")
        frame = ttk.Frame(dialog, padding=18); frame.pack(fill="both", expand=True); frame.columnconfigure(1, weight=1)
        values = existing or ("", "General", "General", "", None, "", "")
        title_var, category_var, type_var, object_var, reference_var = (tk.StringVar(value=str(values[i] or "")) for i in (0,1,2,3,5))
        with sqlite3.connect(self.case.database) as connection:
            evidence_rows = connection.execute("SELECT id,COALESCE(evidence_number || ' - ', '') || name FROM evidence ORDER BY id").fetchall()
        evidence_labels = ["Unassigned", *[row[1] for row in evidence_rows]]
        evidence_map = {row[1]: row[0] for row in evidence_rows}
        current_evidence = next((label for label,eid in evidence_map.items() if eid == values[4]), "Unassigned")
        evidence_var = tk.StringVar(value=current_evidence)
        fields = [("Title", title_var), ("Category", category_var), ("Object Type", type_var), ("Object ID", object_var), ("Evidence", evidence_var), ("Reference / Path", reference_var)]
        for row,(label,var) in enumerate(fields):
            ttk.Label(frame,text=label).grid(row=row,column=0,sticky="nw",padx=(0,12),pady=6)
            if label == "Evidence": widget=ttk.Combobox(frame,textvariable=var,values=evidence_labels,state="readonly")
            elif label == "Object Type": widget=ttk.Combobox(frame,textvariable=var,values=("General","File","Registry","Email","Timeline","Browser","Event Log","Other"))
            else: widget=ttk.Entry(frame,textvariable=var)
            widget.grid(row=row,column=1,sticky="ew",pady=6)
        ttk.Label(frame,text="Notes").grid(row=6,column=0,sticky="nw",padx=(0,12),pady=6)
        notes=tk.Text(frame,height=12,wrap="word"); notes.grid(row=6,column=1,sticky="nsew",pady=6); notes.insert("1.0",str(values[6] or "")); frame.rowconfigure(6,weight=1)
        buttons=ttk.Frame(frame); buttons.grid(row=7,column=0,columnspan=2,sticky="e",pady=(14,0))
        def save():
            title=title_var.get().strip()
            if not title: messagebox.showwarning("Bookmark","Enter a bookmark title.",parent=dialog); return
            now=utc_now(); evidence_id=evidence_map.get(evidence_var.get())
            data=(title,category_var.get().strip() or "General",type_var.get().strip() or "General",object_var.get().strip(),evidence_id,reference_var.get().strip(),notes.get("1.0","end-1c").strip(),self.case.examiner,now)
            with sqlite3.connect(self.case.database) as connection:
                if bookmark_id:
                    connection.execute("UPDATE bookmarks SET title=?,category=?,object_type=?,object_id=?,evidence_id=?,reference=?,notes=?,examiner=?,modified_utc=? WHERE id=?", (*data,bookmark_id))
                else:
                    connection.execute("INSERT INTO bookmarks(title,category,object_type,object_id,evidence_id,reference,notes,examiner,created_utc,modified_utc) VALUES(?,?,?,?,?,?,?,?,?,?)", (*data,now))
            self.audit("BOOKMARK_UPDATED" if bookmark_id else "BOOKMARK_ADDED","bookmark",str(bookmark_id or ""),title); dialog.destroy(); self.select_case_page("bookmarks")
        ttk.Button(buttons,text="Cancel",style="Secondary.TButton",command=dialog.destroy).pack(side="right")
        ttk.Button(buttons,text="Save Bookmark",style="Primary.TButton",command=save).pack(side="right",padx=(0,8))

    def add_bookmark(self) -> None:
        self.bookmark_dialog()

    def edit_bookmark(self, tree: ttk.Treeview) -> None:
        selection=tree.selection()
        if not selection: messagebox.showinfo("Bookmarks","Select a bookmark first.",parent=self); return
        self.bookmark_dialog(int(tree.item(selection[0],"values")[0]))

    def delete_bookmark(self, tree: ttk.Treeview) -> None:
        assert self.case is not None
        selection=tree.selection()
        if not selection: messagebox.showinfo("Bookmarks","Select a bookmark first.",parent=self); return
        bookmark_id=int(tree.item(selection[0],"values")[0]); title=tree.item(selection[0],"values")[1]
        if not messagebox.askyesno("Delete Bookmark",f"Delete bookmark '{title}'?",parent=self): return
        with sqlite3.connect(self.case.database) as connection: connection.execute("DELETE FROM bookmarks WHERE id=?",(bookmark_id,))
        self.audit("BOOKMARK_DELETED","bookmark",str(bookmark_id),str(title)); self.select_case_page("bookmarks")

    def show_notes(self) -> None:
        """Display a complete notes manager with search, reading, and editing."""
        assert self.content is not None and self.case is not None
        self.heading("Case Notes", "Create, search, read, and edit investigation notes.")

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))

        ttk.Label(toolbar, text="Search:").pack(side="left")
        search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=search_var, width=38)
        search_entry.pack(side="left", padx=(8, 12))

        body = ttk.Panedwindow(self.content, orient="horizontal")
        body.pack(fill="both", expand=True)

        list_frame = ttk.Frame(body, style="White.TFrame", padding=8)
        editor_frame = ttk.Frame(body, style="White.TFrame", padding=12)
        body.add(list_frame, weight=2)
        body.add(editor_frame, weight=3)

        columns = ("id", "title", "modified")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")
        tree.heading("id", text="ID")
        tree.heading("title", text="Title")
        tree.heading("modified", text="Modified UTC")
        tree.column("id", width=55, stretch=False, anchor="w")
        tree.column("title", width=300, anchor="w")
        tree.column("modified", width=185, anchor="w")
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        current_id = tk.StringVar(value="")
        title_var = tk.StringVar()
        created_var = tk.StringVar(value="New note")
        modified_var = tk.StringVar(value="")

        ttk.Label(editor_frame, text="Title", style="CardTitle.TLabel").pack(anchor="w")
        title_entry = ttk.Entry(editor_frame, textvariable=title_var)
        title_entry.pack(fill="x", pady=(5, 10))

        meta = ttk.Frame(editor_frame, style="White.TFrame")
        meta.pack(fill="x", pady=(0, 8))
        ttk.Label(meta, textvariable=created_var, style="WhiteMuted.TLabel").pack(side="left")
        ttk.Label(meta, textvariable=modified_var, style="WhiteMuted.TLabel").pack(side="right")

        ttk.Label(editor_frame, text="Note", style="CardTitle.TLabel").pack(anchor="w")
        text_frame = ttk.Frame(editor_frame, style="White.TFrame")
        text_frame.pack(fill="both", expand=True, pady=(5, 10))
        note_text = tk.Text(text_frame, wrap="word", undo=True, font=("Segoe UI", 10))
        note_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=note_text.yview)
        note_text.configure(yscrollcommand=note_scroll.set)
        note_text.pack(side="left", fill="both", expand=True)
        note_scroll.pack(side="right", fill="y")

        button_bar = ttk.Frame(editor_frame, style="White.TFrame")
        button_bar.pack(fill="x")

        def clear_editor() -> None:
            current_id.set("")
            title_var.set("")
            note_text.delete("1.0", "end")
            created_var.set("New note")
            modified_var.set("")
            title_entry.focus_set()

        def load_notes(*_args) -> None:
            selected_id = current_id.get()
            query = search_var.get().strip()
            sql = "SELECT id,title,modified_utc FROM notes"
            params: list[str] = []
            if query:
                sql += " WHERE title LIKE ? OR body LIKE ?"
                token = f"%{query}%"
                params.extend([token, token])
            sql += " ORDER BY modified_utc DESC, id DESC"
            with sqlite3.connect(self.case.database) as connection:
                rows = connection.execute(sql, params).fetchall()
            tree.delete(*tree.get_children())
            restore_item = None
            for row in rows:
                item = tree.insert("", "end", values=row)
                if selected_id and str(row[0]) == selected_id:
                    restore_item = item
            if restore_item:
                tree.selection_set(restore_item)
                tree.see(restore_item)

        def load_selected(_event=None) -> None:
            selection = tree.selection()
            if not selection:
                return
            note_id = int(tree.item(selection[0], "values")[0])
            with sqlite3.connect(self.case.database) as connection:
                row = connection.execute(
                    "SELECT id,title,body,created_utc,modified_utc FROM notes WHERE id=?",
                    (note_id,),
                ).fetchone()
            if not row:
                return
            current_id.set(str(row[0]))
            title_var.set(str(row[1] or ""))
            note_text.delete("1.0", "end")
            note_text.insert("1.0", str(row[2] or ""))
            created_var.set(f"Created: {row[3]}")
            modified_var.set(f"Modified: {row[4]}")

        def save_note() -> None:
            title = title_var.get().strip()
            body_text = note_text.get("1.0", "end-1c")
            if not title:
                messagebox.showwarning("Case Notes", "Enter a note title.", parent=self)
                title_entry.focus_set()
                return
            now = utc_now()
            note_id_text = current_id.get()
            with sqlite3.connect(self.case.database) as connection:
                if note_id_text:
                    connection.execute(
                        "UPDATE notes SET title=?,body=?,modified_utc=? WHERE id=?",
                        (title, body_text, now, int(note_id_text)),
                    )
                    note_id = int(note_id_text)
                    action = "NOTE_UPDATED"
                else:
                    cursor = connection.execute(
                        "INSERT INTO notes(title,body,created_utc,modified_utc) VALUES(?,?,?,?)",
                        (title, body_text, now, now),
                    )
                    note_id = int(cursor.lastrowid)
                    current_id.set(str(note_id))
                    action = "NOTE_ADDED"
            self.audit(action, "note", str(note_id), title)
            load_notes()
            # Reload timestamps from the saved record.
            with sqlite3.connect(self.case.database) as connection:
                row = connection.execute(
                    "SELECT created_utc,modified_utc FROM notes WHERE id=?", (note_id,)
                ).fetchone()
            if row:
                created_var.set(f"Created: {row[0]}")
                modified_var.set(f"Modified: {row[1]}")

        def delete_note() -> None:
            note_id_text = current_id.get()
            if not note_id_text:
                messagebox.showinfo("Case Notes", "Select a note first.", parent=self)
                return
            title = title_var.get().strip() or f"Note {note_id_text}"
            if not messagebox.askyesno(
                "Delete Note", f"Permanently delete '{title}'?", parent=self
            ):
                return
            with sqlite3.connect(self.case.database) as connection:
                connection.execute("DELETE FROM notes WHERE id=?", (int(note_id_text),))
            self.audit("NOTE_DELETED", "note", note_id_text, title)
            clear_editor()
            load_notes()

        ttk.Button(toolbar, text="＋ New Note", style="Primary.TButton", command=clear_editor).pack(side="left")
        ttk.Button(toolbar, text="Refresh", style="Secondary.TButton", command=load_notes).pack(side="left", padx=8)
        ttk.Button(button_bar, text="Delete", style="Secondary.TButton", command=delete_note).pack(side="left")
        ttk.Button(button_bar, text="Save Note", style="Primary.TButton", command=save_note).pack(side="right")

        tree.bind("<<TreeviewSelect>>", load_selected)
        tree.bind("<Double-1>", load_selected)
        search_var.trace_add("write", load_notes)
        self.bind("<Control-s>", lambda _event: save_note())
        load_notes()

    def add_note(self) -> None:
        # Retained for compatibility with older callers; the Notes page now
        # provides an integrated New Note editor.
        self.select_case_page("notes")

    def sync_reports_folder(self) -> int:
        """Register every file found in the case Reports folder."""
        assert self.case is not None
        reports_dir = self.case.folder / "Reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        files = sorted(path for path in reports_dir.rglob("*") if path.is_file())
        added = 0
        with sqlite3.connect(self.case.database) as connection:
            existing_rows = connection.execute("SELECT id,file_path FROM reports").fetchall()
            existing = {
                os.path.normcase(os.path.abspath(str(path))): report_id
                for report_id, path in existing_rows if path
            }
            now = utc_now()
            for path in files:
                normalized = os.path.normcase(os.path.abspath(str(path)))
                if normalized in existing:
                    continue
                connection.execute(
                    """
                    INSERT INTO reports(title,report_type,file_path,created_utc,description)
                    VALUES(?,?,?,?,?)
                    """,
                    (
                        path.stem,
                        path.suffix.lstrip(".").upper() or "FILE",
                        str(path),
                        now,
                        "Automatically discovered in the Reports folder",
                    ),
                )
                added += 1
        if added:
            self.audit(
                "REPORTS_FOLDER_SYNCED", "reports", "", f"Registered {added} new report file(s)"
            )
        return added

    def open_path(self, path: Path) -> None:
        """Open a file or folder with the operating system's default application."""
        try:
            if not path.exists():
                raise FileNotFoundError(f"The file no longer exists:\n{path}")
            if sys.platform == "win32":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Unable to Open File", str(exc), parent=self)

    def show_reports(self) -> None:
        assert self.content is not None and self.case is not None
        self.sync_reports_folder()
        self.heading(
            "Reports",
            "Automatically displays every document found in the case Reports folder.",
        )

        toolbar = ttk.Frame(self.content, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(toolbar, text="Create Case Report", style="Primary.TButton", command=self.create_report).pack(side="left")
        ttk.Button(toolbar, text="Create Chain of Custody Report", style="Secondary.TButton", command=self.create_chain_report).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Open Reports Folder", style="Primary.TButton", command=lambda: self.open_folder(self.case.folder / "Reports")).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Register External File", style="Secondary.TButton", command=self.register_report).pack(side="left", padx=8)

        search_var = tk.StringVar()
        ttk.Label(toolbar, text="Search:").pack(side="left", padx=(20, 5))
        ttk.Entry(toolbar, textvariable=search_var, width=28).pack(side="left")

        columns = ("id", "title", "type", "size", "modified", "path")
        tree = ttk.Treeview(self.content, columns=columns, show="headings", selectmode="browse")
        specs = [
            ("id", "ID", 55),
            ("title", "File", 260),
            ("type", "Type", 80),
            ("size", "Size", 90),
            ("modified", "Modified", 165),
            ("path", "File Path", 510),
        ]
        for column, label, width in specs:
            tree.heading(column, text=label)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        status_var = tk.StringVar()
        ttk.Label(self.content, textvariable=status_var, style="Muted.TLabel").pack(anchor="w", pady=(7, 0))

        def refresh(*_args) -> None:
            self.sync_reports_folder()
            query = search_var.get().strip().lower()
            with sqlite3.connect(self.case.database) as connection:
                rows = connection.execute(
                    "SELECT id,title,report_type,file_path,created_utc FROM reports ORDER BY id DESC"
                ).fetchall()
            tree.delete(*tree.get_children())
            visible = 0
            for report_id, title, report_type, file_path, created in rows:
                path = Path(str(file_path or ""))
                haystack = f"{title} {report_type} {file_path}".lower()
                if query and query not in haystack:
                    continue
                try:
                    stat = path.stat()
                    size = human_size(stat.st_size)
                    modified = __import__("datetime").datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                except OSError:
                    size = "Missing"
                    modified = str(created or "")
                tree.insert("", "end", values=(report_id, title, report_type, size, modified, file_path))
                visible += 1
            status_var.set(f"{visible} document(s) shown. Double-click a document to open it.")

        def selected_path() -> Optional[Path]:
            selection = tree.selection()
            if not selection:
                messagebox.showinfo("Reports", "Select a document first.", parent=self)
                return None
            values = tree.item(selection[0], "values")
            return Path(str(values[5]))

        def open_selected(_event=None) -> None:
            path = selected_path()
            if path:
                self.open_path(path)

        ttk.Button(toolbar, text="↻ Reload", style="Secondary.TButton", command=refresh).pack(side="right")
        ttk.Button(toolbar, text="Open Selected", style="Primary.TButton", command=open_selected).pack(side="right", padx=8)
        tree.bind("<Double-1>", open_selected)
        tree.bind("<Return>", open_selected)
        search_var.trace_add("write", refresh)
        refresh()

    def create_report(self) -> None:
        assert self.case is not None
        reports_dir = self.case.folder / "Reports"; reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = utc_now().replace(":", "-").replace("+00:00", "Z")
        path = reports_dir / f"{safe_name(self.case.name)}_Case_Report_{stamp}.html"
        with sqlite3.connect(self.case.database) as con:
            evidence = con.execute("SELECT evidence_number,name,evidence_type,COALESCE(mounted_volume,root_path,source,''),status FROM evidence ORDER BY id").fetchall()
            notes = con.execute("SELECT title,body,created_utc FROM notes ORDER BY id").fetchall()
            registry_count = con.execute("SELECT COUNT(*) FROM registry_artifacts").fetchone()[0] if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='registry_artifacts'").fetchone() else 0
            custody = con.execute("SELECT c.transfer_utc,COALESCE(e.evidence_number||' - ','')||COALESCE(e.name,'Unassigned'),c.released_by,c.received_by,c.purpose,c.location,c.condition FROM chain_of_custody c LEFT JOIN evidence e ON e.id=c.evidence_id ORDER BY c.transfer_utc,c.id").fetchall()
        rows=''.join(f"<tr><td>{html.escape(str(a or ''))}</td><td>{html.escape(str(b or ''))}</td><td>{html.escape(str(c or ''))}</td><td>{html.escape(str(d or ''))}</td><td>{html.escape(str(e or ''))}</td></tr>" for a,b,c,d,e in evidence)
        custody_rows=''.join(f"<tr><td>{html.escape(str(a or ''))}</td><td>{html.escape(str(b or ''))}</td><td>{html.escape(str(c or ''))}</td><td>{html.escape(str(d or ''))}</td><td>{html.escape(str(e or ''))}</td><td>{html.escape(str(f or ''))}</td><td>{html.escape(str(g or ''))}</td></tr>" for a,b,c,d,e,f,g in custody)
        note_html=''.join(f"<section><h3>{html.escape(t)}</h3><small>{html.escape(c)}</small><p>{html.escape(b).replace(chr(10),'<br>')}</p></section>" for t,b,c in notes)
        document=f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(self.case.name)} Case Report</title><style>body{{font-family:Segoe UI,Arial;margin:40px;color:#172431}}header{{background:#061522;color:white;padding:24px}}h1{{margin:0}}table{{border-collapse:collapse;width:100%;margin-top:12px}}th,td{{border:1px solid #c8d5df;padding:8px;text-align:left}}th{{background:#587795;color:white}}small{{color:#607180}}</style></head><body><header><h1>Fraud Fighter Toolbox</h1><div>Digital Forensics. Real Answers. Stronger Outcomes.</div></header><h2>Case Report</h2><p><b>Case:</b> {html.escape(self.case.name)}<br><b>Case number:</b> {html.escape(self.case.number)}<br><b>Examiner:</b> {html.escape(self.case.examiner)}<br><b>Generated:</b> {html.escape(utc_now())}</p><h2>Evidence Inventory</h2><table><tr><th>No.</th><th>Name</th><th>Type</th><th>Mounted volume / source</th><th>Status</th></tr>{rows}</table><h2>Chain of Custody</h2><table><tr><th>Transfer UTC</th><th>Evidence</th><th>Released By</th><th>Received By</th><th>Purpose</th><th>Location</th><th>Condition</th></tr>{custody_rows or '<tr><td colspan=7>No chain-of-custody entries.</td></tr>'}</table><h2>Registry Artifact Summary</h2><p>{registry_count:,} registry artifact records are stored in the case database.</p><h2>Case Notes</h2>{note_html or '<p>No case notes.</p>'}</body></html>"""
        path.write_text(document,encoding="utf-8")
        with sqlite3.connect(self.case.database) as con:
            cur=con.execute("INSERT INTO reports(title,report_type,file_path,created_utc,description) VALUES(?,?,?,?,?)",(path.stem,"HTML",str(path),utc_now(),"Generated case report")); report_id=cur.lastrowid
        self.audit("REPORT_CREATED","report",str(report_id),str(path)); self.select_case_page("reports")
        messagebox.showinfo("Report Created", f"Report created:\n{path}", parent=self)

    def register_report(self) -> None:
        assert self.case is not None
        selected = filedialog.askopenfilename(parent=self, title="Select Report")
        if not selected:
            return
        path = Path(selected)
        with sqlite3.connect(self.case.database) as connection:
            cursor = connection.execute(
                """
                INSERT INTO reports
                (title, report_type, file_path, created_utc, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (path.stem, path.suffix.lstrip(".").upper(), str(path), utc_now(), ""),
            )
            report_id = cursor.lastrowid
        self.audit("REPORT_REGISTERED", "report", str(report_id), str(path))
        self.select_case_page("reports")

    def show_audit(self) -> None:
        assert self.content is not None and self.case is not None
        self.heading("Audit Log", "Review actions recorded by the suite launcher.")

        columns = ("id", "time", "examiner", "action", "object", "details")
        tree = ttk.Treeview(self.content, columns=columns, show="headings")
        for column, label, width in [
            ("id", "ID", 55),
            ("time", "Event UTC", 210),
            ("examiner", "Examiner", 150),
            ("action", "Action", 180),
            ("object", "Object", 150),
            ("details", "Details", 500),
        ]:
            tree.heading(column, text=label)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        with sqlite3.connect(self.case.database) as connection:
            rows = connection.execute(
                """
                SELECT id, event_utc, examiner, action,
                       CASE
                           WHEN object_type IS NULL OR object_type = '' THEN ''
                           ELSE object_type || ':' || COALESCE(object_id, '')
                       END,
                       details
                FROM audit_log ORDER BY id DESC
                """
            ).fetchall()
        for row in rows:
            tree.insert("", "end", values=row)

    def launch_plugin(self, plugin: PluginInfo, extra_environment: Optional[dict[str, str]] = None) -> None:
        assert self.case is not None
        existing = self.plugin_processes.get(plugin.plugin_id)
        if existing and existing.poll() is None:
            if messagebox.askyesno(
                "Plugin Already Running",
                f"{plugin.name} is already running.\n\nLaunch another instance?",
                parent=self,
            ) is False:
                return

        environment = os.environ.copy()
        environment.update(
            {
                "FFT_CASE_DB": str(self.case.database),
                "FFT_CASE_FOLDER": str(self.case.folder),
                "FFT_CASE_NAME": self.case.name,
                "FFT_CASE_NUMBER": self.case.number,
                "FFT_EXAMINER": self.case.examiner,
                "FFT_SUITE_VERSION": APP_VERSION,
            }
        )

        if extra_environment:
            environment.update(extra_environment)

        if plugin.executable.suffix.lower() == ".py":
            command = [sys.executable, str(plugin.executable)]
        else:
            command = [str(plugin.executable)]

        if plugin.pass_case_arguments:
            command.extend(
                [
                    "--case-db", str(self.case.database),
                    "--case-folder", str(self.case.folder),
                ]
            )

        try:
            process = subprocess.Popen(
                command,
                cwd=str(plugin.working_directory),
                env=environment,
            )
            self.plugin_processes[plugin.plugin_id] = process
            with sqlite3.connect(self.case.database) as connection:
                connection.execute(
                    """
                    INSERT INTO plugin_runs
                    (plugin_id, plugin_name, executable_path, process_id,
                     started_utc, status, message)
                    VALUES (?, ?, ?, ?, ?, 'Launched', ?)
                    """,
                    (
                        plugin.plugin_id,
                        plugin.name,
                        str(plugin.executable),
                        process.pid,
                        utc_now(),
                        "Launched in a separate process and window",
                    ),
                )
            self.audit(
                "PLUGIN_LAUNCHED",
                "plugin",
                plugin.plugin_id,
                f"{plugin.name}; PID {process.pid}; {plugin.executable}",
            )
        except Exception as exc:
            messagebox.showerror("Plugin Launch Failed", str(exc), parent=self)
            self.audit(
                "PLUGIN_LAUNCH_FAILED",
                "plugin",
                plugin.plugin_id,
                f"{plugin.name}: {exc}",
            )

    def open_folder(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Unable to Open Folder", str(exc), parent=self)

    def close_case(self) -> None:
        if self.case:
            self.audit("CASE_CLOSED", "case", "1", f"Closed case {self.case.name}")
        self.show_welcome()

    def close_application(self) -> None:
        if self.case:
            self.audit("APPLICATION_CLOSED", "application", "", "Suite launcher closed")
        self.destroy()

