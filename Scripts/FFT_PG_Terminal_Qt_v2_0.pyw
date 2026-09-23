#!/usr/bin/env python3
# FFT_TOOL
# TITLE: Terminal
# ID: terminal
# CATEGORY: Plugins
# VERSION: 2.0.0
# DESCRIPTION: Launch PowerShell, Command Prompt, Windows Terminal, Python, or SQLite with the active FFT case context.
# ICON: 🖥
# PASS_CASE_ARGUMENTS: true

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QColor, QFont, QKeySequence, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "FFT Terminal"
APP_VERSION = "2.0.0"

COLORS = {
    "navy": "#061522",
    "navy2": "#0c2235",
    "blue": "#188bd0",
    "panel": "#eef3f7",
    "white": "#ffffff",
    "text": "#172431",
    "muted": "#607180",
    "border": "#c8d5df",
    "green": "#367d4a",
    "red": "#a33b3b",
}

FFT_STYLE = """
QMainWindow { background: #eef3f7; }
QMenuBar { background: #061522; color: white; }
QMenuBar::item:selected { background: #0c2235; }
QMenu { background: white; color: #172431; }
QToolBar { background: #0c2235; border: none; padding: 4px; spacing: 5px; }
QToolButton, QPushButton {
    background: #188bd0; color: white; border: none;
    border-radius: 4px; padding: 7px 11px;
}
QToolButton:hover, QPushButton:hover { background: #0f6ea6; }
QLineEdit, QComboBox, QPlainTextEdit, QTableWidget {
    background: white; color: #172431; border: 1px solid #c8d5df;
    selection-background-color: #188bd0; selection-color: white;
}
QHeaderView::section {
    background: #dce7f0; color: #172431; padding: 5px;
    border: 0; border-right: 1px solid #c8d5df;
    border-bottom: 1px solid #c8d5df; font-weight: 600;
}
QTabWidget::pane { border: 1px solid #c8d5df; background: white; }
QTabBar::tab { background: #dce7f0; padding: 7px 12px; }
QTabBar::tab:selected { background: white; color: #061522; }
QStatusBar { background: #0c2235; color: #dce7f0; }
QCheckBox { color: #172431; spacing: 5px; }
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--case-db", default="")
    parser.add_argument("--case-folder", default="")
    args, _ = parser.parse_known_args()
    return args


class TerminalWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        args = parse_arguments()

        self.settings = QSettings("FraudFighterToolbox", "TerminalQt")
        self.case_db = Path(
            args.case_db or os.environ.get("FFT_CASE_DB", "")
        ) if (args.case_db or os.environ.get("FFT_CASE_DB")) else None
        self.case_folder = Path(
            args.case_folder or os.environ.get("FFT_CASE_FOLDER", "")
        ) if (args.case_folder or os.environ.get("FFT_CASE_FOLDER")) else None
        self.case_name = os.environ.get("FFT_CASE_NAME", "Standalone Analysis")
        self.case_number = os.environ.get("FFT_CASE_NUMBER", "")
        self.examiner = os.environ.get("FFT_EXAMINER", "")
        self.evidence_root = os.environ.get(
            "FFT_EVIDENCE_ROOT",
            os.environ.get("FFT_EVIDENCE", ""),
        )

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1160, 760)
        self.setMinimumSize(900, 620)
        self.setStyleSheet(FFT_STYLE)

        self._build_actions()
        self._build_menu()
        self._build_toolbar()
        self._build_ui()
        self._build_statusbar()
        self._restore_state()
        self.refresh_environment()

    def _build_actions(self) -> None:
        self.act_launch = QAction("Launch Terminal", self)
        self.act_launch.setShortcut(QKeySequence("Ctrl+Return"))
        self.act_launch.triggered.connect(self.launch_selected)

        self.act_case_folder = QAction("Open Case Folder", self)
        self.act_case_folder.triggered.connect(
            lambda: self.open_folder(self.case_folder)
        )

        self.act_db_folder = QAction("Open Database Folder", self)
        self.act_db_folder.triggered.connect(
            lambda: self.open_folder(self.case_db.parent if self.case_db else None)
        )

        self.act_evidence = QAction("Open Evidence Folder", self)
        self.act_evidence.triggered.connect(
            lambda: self.open_folder(Path(self.evidence_root) if self.evidence_root else None)
        )

        self.act_exit = QAction("Exit", self)
        self.act_exit.triggered.connect(self.close)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction(self.act_launch)
        file_menu.addSeparator()
        file_menu.addAction(self.act_exit)

        folders = self.menuBar().addMenu("&Folders")
        folders.addAction(self.act_case_folder)
        folders.addAction(self.act_db_folder)
        folders.addAction(self.act_evidence)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        toolbar.addAction(self.act_launch)
        toolbar.addSeparator()
        toolbar.addAction(self.act_case_folder)
        toolbar.addAction(self.act_db_folder)
        toolbar.addAction(self.act_evidence)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(12, 10, 12, 10)
        self.setCentralWidget(central)

        header = QLabel(
            f"<b>{self.case_name}</b>"
            f" &nbsp; Case: {self.case_number or 'Not specified'}"
            f" &nbsp; Examiner: {self.examiner or 'Not specified'}"
        )
        header.setStyleSheet("color:#061522; font-size:13px;")
        layout.addWidget(header)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)

        form = QFormLayout()
        self.shell_combo = QComboBox()
        self.shell_combo.addItems([
            "Windows Terminal",
            "PowerShell",
            "Command Prompt",
            "Python REPL",
            "SQLite CLI",
        ])
        self.shell_combo.currentTextChanged.connect(self.update_command_preview)
        form.addRow("Terminal:", self.shell_combo)

        self.working_dir = QLineEdit(self.default_working_directory())
        browse = QPushButton("Browse")
        browse.clicked.connect(self.choose_working_directory)
        directory_row = QWidget()
        directory_layout = QHBoxLayout(directory_row)
        directory_layout.setContentsMargins(0, 0, 0, 0)
        directory_layout.addWidget(self.working_dir, 1)
        directory_layout.addWidget(browse)
        form.addRow("Start in:", directory_row)

        self.keep_open = QCheckBox("Keep terminal open after command completes")
        self.keep_open.setChecked(True)
        form.addRow("", self.keep_open)

        self.load_environment = QCheckBox("Load FFT case environment variables")
        self.load_environment.setChecked(True)
        form.addRow("", self.load_environment)

        self.elevated = QCheckBox("Request elevated Administrator terminal")
        form.addRow("", self.elevated)

        left_layout.addLayout(form)

        left_layout.addWidget(QLabel("Optional startup command:"))
        self.command_edit = QPlainTextEdit()
        self.command_edit.setPlaceholderText(
            "Examples:\n"
            'Get-ChildItem -Force\n'
            'python --version\n'
            'sqlite3 "%FFT_CASE_DB%"'
        )
        self.command_edit.setFont(QFont("Consolas", 10))
        self.command_edit.textChanged.connect(self.update_command_preview)
        left_layout.addWidget(self.command_edit, 1)

        presets_label = QLabel("Command presets")
        presets_label.setStyleSheet("font-weight:700; color:#061522;")
        left_layout.addWidget(presets_label)

        preset_row = QHBoxLayout()
        for title, command in (
            ("List Files", "Get-ChildItem -Force"),
            ("Python Version", "python --version"),
            ("Case DB Tables", 'sqlite3 "%FFT_CASE_DB%" ".tables"'),
            ("Environment", "Get-ChildItem Env:FFT_*"),
        ):
            button = QPushButton(title)
            button.clicked.connect(
                lambda checked=False, value=command: self.command_edit.setPlainText(value)
            )
            preset_row.addWidget(button)
        left_layout.addLayout(preset_row)

        launch = QPushButton("Launch Selected Terminal")
        launch.setMinimumHeight(42)
        launch.clicked.connect(self.launch_selected)
        left_layout.addWidget(launch)

        splitter.addWidget(left)

        tabs = QTabWidget()

        preview_tab = QWidget()
        preview_layout = QVBoxLayout(preview_tab)
        preview_layout.addWidget(QLabel("Command preview"))
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(QFont("Consolas", 10))
        preview_layout.addWidget(self.preview, 1)
        tabs.addTab(preview_tab, "Launch Preview")

        env_tab = QWidget()
        env_layout = QVBoxLayout(env_tab)
        self.env_table = QTableWidget(0, 2)
        self.env_table.setHorizontalHeaderLabels(["Variable", "Value"])
        self.env_table.horizontalHeader().setStretchLastSection(True)
        self.env_table.setAlternatingRowColors(True)
        self.env_table.setSelectionBehavior(QTableWidget.SelectRows)
        env_layout.addWidget(self.env_table)
        tabs.addTab(env_tab, "FFT Environment")

        help_tab = QWidget()
        help_layout = QVBoxLayout(help_tab)
        help_text = QPlainTextEdit()
        help_text.setReadOnly(True)
        help_text.setPlainText(
            "FFT Terminal launches an external terminal process using the active "
            "case context.\n\n"
            "Available variables include:\n"
            "  FFT_CASE_DB\n"
            "  FFT_CASE_FOLDER\n"
            "  FFT_CASE_NAME\n"
            "  FFT_CASE_NUMBER\n"
            "  FFT_EXAMINER\n"
            "  FFT_EVIDENCE_ROOT\n\n"
            "The external terminal starts in the selected working directory. "
            "Commands are passed to the selected shell rather than executed "
            "inside this Qt window."
        )
        help_text.setFont(QFont("Segoe UI", 10))
        help_layout.addWidget(help_text)
        tabs.addTab(help_tab, "Help")

        splitter.addWidget(tabs)
        splitter.setSizes([610, 520])

        self.shell_combo.setCurrentText(
            self.settings.value("last_shell", "Windows Terminal")
        )
        self.update_command_preview()

    def _build_statusbar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)
        self.status_label = QLabel("Ready")
        self.context_label = QLabel(
            "Case context loaded" if self.case_db else "Standalone mode"
        )
        bar.addWidget(self.status_label, 1)
        bar.addPermanentWidget(self.context_label)

    def default_working_directory(self) -> str:
        if self.case_folder and self.case_folder.exists():
            return str(self.case_folder)
        if self.case_db and self.case_db.parent.exists():
            return str(self.case_db.parent)
        return str(Path.cwd())

    def refresh_environment(self) -> None:
        values = {
            "FFT_CASE_DB": str(self.case_db or ""),
            "FFT_CASE_FOLDER": str(self.case_folder or ""),
            "FFT_CASE_NAME": self.case_name,
            "FFT_CASE_NUMBER": self.case_number,
            "FFT_EXAMINER": self.examiner,
            "FFT_EVIDENCE_ROOT": self.evidence_root,
        }
        self.env_table.setRowCount(len(values))
        for row, (name, value) in enumerate(values.items()):
            self.env_table.setItem(row, 0, QTableWidgetItem(name))
            self.env_table.setItem(row, 1, QTableWidgetItem(value))
        self.env_table.resizeColumnsToContents()
        self.update_command_preview()

    def choose_working_directory(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Choose Terminal Working Directory",
            self.working_dir.text(),
        )
        if selected:
            self.working_dir.setText(selected)
            self.update_command_preview()

    def environment(self) -> dict[str, str]:
        env = os.environ.copy()
        if not self.load_environment.isChecked():
            return env
        env.update({
            "FFT_CASE_DB": str(self.case_db or ""),
            "FFT_CASE_FOLDER": str(self.case_folder or ""),
            "FFT_CASE_NAME": self.case_name,
            "FFT_CASE_NUMBER": self.case_number,
            "FFT_EXAMINER": self.examiner,
            "FFT_EVIDENCE_ROOT": self.evidence_root,
        })
        return env

    def expand_command(self, command: str) -> str:
        values = {
            "%FFT_CASE_DB%": str(self.case_db or ""),
            "%FFT_CASE_FOLDER%": str(self.case_folder or ""),
            "%FFT_CASE_NAME%": self.case_name,
            "%FFT_CASE_NUMBER%": self.case_number,
            "%FFT_EXAMINER%": self.examiner,
            "%FFT_EVIDENCE_ROOT%": self.evidence_root,
        }
        for token, value in values.items():
            command = command.replace(token, value)
        return command

    def executable(self, name: str) -> Optional[str]:
        candidates = {
            "Windows Terminal": ["wt.exe", "wt"],
            "PowerShell": ["pwsh.exe", "powershell.exe", "pwsh", "powershell"],
            "Command Prompt": ["cmd.exe", "cmd"],
            "Python REPL": [sys.executable, "python.exe", "python"],
            "SQLite CLI": ["sqlite3.exe", "sqlite3"],
        }[name]
        for candidate in candidates:
            if Path(candidate).exists():
                return candidate
            found = shutil.which(candidate)
            if found:
                return found
        return None

    def build_command(self) -> tuple[list[str], bool]:
        shell = self.shell_combo.currentText()
        exe = self.executable(shell)
        if not exe:
            raise FileNotFoundError(
                f"{shell} was not found on this computer."
            )

        command = self.expand_command(self.command_edit.toPlainText().strip())
        keep = self.keep_open.isChecked()

        if shell == "Windows Terminal":
            if command:
                ps = self.executable("PowerShell")
                if not ps:
                    raise FileNotFoundError("PowerShell was not found.")
                args = [exe, "-d", self.working_dir.text(), ps]
                args += ["-NoExit" if keep else "-Command"]
                if keep:
                    args += ["-Command", command]
                else:
                    args += [command]
            else:
                args = [exe, "-d", self.working_dir.text()]
        elif shell == "PowerShell":
            args = [exe]
            if command:
                if keep:
                    args += ["-NoExit", "-Command", command]
                else:
                    args += ["-Command", command]
            elif keep:
                args += ["-NoExit"]
        elif shell == "Command Prompt":
            args = [exe]
            if command:
                args += ["/K" if keep else "/C", command]
            elif keep:
                args += ["/K"]
        elif shell == "Python REPL":
            args = [exe]
            if command:
                args += ["-c", command]
                if keep:
                    args = [
                        self.executable("Command Prompt") or "cmd.exe",
                        "/K",
                        subprocess.list2cmdline(args),
                    ]
        else:
            args = [exe]
            if self.case_db:
                args.append(str(self.case_db))
            if command:
                args.append(command)

        return args, self.elevated.isChecked()

    def update_command_preview(self) -> None:
        try:
            command, elevated = self.build_command()
            prefix = "Administrator launch requested\n\n" if elevated else ""
            self.preview.setPlainText(
                prefix
                + "Working directory:\n"
                + self.working_dir.text()
                + "\n\nCommand:\n"
                + subprocess.list2cmdline(command)
            )
        except Exception as exc:
            self.preview.setPlainText(str(exc))

    def launch_selected(self) -> None:
        workdir = Path(self.working_dir.text().strip())
        if not workdir.exists() or not workdir.is_dir():
            QMessageBox.critical(
                self, APP_NAME, "Select a valid working directory."
            )
            return

        try:
            command, elevated = self.build_command()
            env = self.environment()

            if elevated and os.name == "nt":
                joined = subprocess.list2cmdline(command)
                escaped = joined.replace("'", "''")
                subprocess.Popen(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-Command",
                        f"Start-Process -FilePath 'cmd.exe' "
                        f"-ArgumentList '/c {escaped}' -Verb RunAs",
                    ],
                    cwd=str(workdir),
                    env=env,
                )
            else:
                subprocess.Popen(
                    command,
                    cwd=str(workdir),
                    env=env,
                    creationflags=(
                        subprocess.CREATE_NEW_CONSOLE
                        if os.name == "nt" else 0
                    ),
                )

            self.settings.setValue("last_shell", self.shell_combo.currentText())
            self.status_label.setText(
                f"Launched {self.shell_combo.currentText()} at {utc_now()}"
            )
            self.audit_launch(command, workdir)
        except Exception as exc:
            QMessageBox.critical(self, "Terminal Launch Failed", str(exc))
            self.status_label.setText("Launch failed")

    def audit_launch(self, command: list[str], workdir: Path) -> None:
        if not self.case_db or not self.case_db.exists():
            return
        try:
            with sqlite3.connect(self.case_db) as con:
                table = con.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='audit_log'"
                ).fetchone()
                if table:
                    columns = {
                        row[1].lower()
                        for row in con.execute("PRAGMA table_info(audit_log)")
                    }
                    if {"action", "details"}.issubset(columns):
                        if "created_utc" in columns:
                            con.execute(
                                "INSERT INTO audit_log "
                                "(action,details,created_utc) VALUES(?,?,?)",
                                (
                                    "TERMINAL_LAUNCHED",
                                    json.dumps({
                                        "shell": self.shell_combo.currentText(),
                                        "command": command,
                                        "working_directory": str(workdir),
                                    }),
                                    utc_now(),
                                ),
                            )
        except sqlite3.Error:
            pass

    def open_folder(self, path: Optional[Path]) -> None:
        if not path:
            QMessageBox.information(
                self, APP_NAME, "This folder is not available in the current context."
            )
            return
        try:
            path.mkdir(parents=True, exist_ok=True)
            if sys.platform == "win32":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            QMessageBox.critical(self, "Unable to Open Folder", str(exc))

    def _restore_state(self) -> None:
        geometry = self.settings.value("geometry")
        state = self.settings.value("state")
        if geometry:
            self.restoreGeometry(geometry)
        if state:
            self.restoreState(state)

    def closeEvent(self, event) -> None:
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("state", self.saveState())
        self.settings.setValue("working_directory", self.working_dir.text())
        event.accept()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("Fraud Fighter Toolbox")
    app.setStyle("Fusion")
    palette = app.palette()
    palette.setColor(QPalette.Highlight, QColor(COLORS["blue"]))
    palette.setColor(QPalette.HighlightedText, QColor("white"))
    app.setPalette(palette)

    window = TerminalWindow()
    saved_directory = window.settings.value("working_directory", "")
    if saved_directory and Path(str(saved_directory)).exists():
        window.working_dir.setText(str(saved_directory))
        window.update_command_preview()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
