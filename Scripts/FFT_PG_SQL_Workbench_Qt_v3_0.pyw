#!/usr/bin/env python3
# FFT_TOOL
# TITLE: SQL Workbench
# ID: sql_workbench
# CATEGORY: Plugins
# VERSION: 3.0.0
# DESCRIPTION: Qt-based SQLite workbench for the active Fraud Fighter Toolbox case database.
# ICON: 🗄
# PASS_CASE_ARGUMENTS: true

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QRunnable,
    QSettings,
    QSize,
    Qt,
    QThreadPool,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QIcon,
    QKeySequence,
    QPalette,
    QSyntaxHighlighter,
    QTextCharFormat,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTableView,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "FFT SQL Workbench"
APP_VERSION = "3.0.0"

FFT_STYLE = """
QMainWindow {
    background: #eef3f7;
}
QMenuBar {
    background: #071725;
    color: white;
}
QMenuBar::item:selected {
    background: #0d2b43;
}
QMenu {
    background: white;
    color: #172431;
}
QToolBar {
    background: #0b2235;
    spacing: 4px;
    border: none;
    padding: 4px;
}
QToolButton {
    color: white;
    background: #1686c7;
    border: none;
    border-radius: 4px;
    padding: 6px 9px;
}
QToolButton:hover {
    background: #0f6ea6;
}
QDockWidget {
    color: #172431;
    font-weight: 600;
}
QDockWidget::title {
    background: #dce7f0;
    padding: 6px;
}
QPlainTextEdit, QTextEdit, QLineEdit, QTreeWidget, QListWidget, QTableView, QComboBox {
    background: white;
    color: #172431;
    border: 1px solid #c7d4de;
    selection-background-color: #1686c7;
    selection-color: white;
}
QHeaderView::section {
    background: #dce7f0;
    color: #172431;
    padding: 5px;
    border: 0;
    border-right: 1px solid #c7d4de;
    border-bottom: 1px solid #c7d4de;
    font-weight: 600;
}
QPushButton {
    background: #1686c7;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 10px;
}
QPushButton:hover {
    background: #0f6ea6;
}
QStatusBar {
    background: #0b2235;
    color: #dce7f0;
}
QProgressBar {
    border: 1px solid #c7d4de;
    border-radius: 3px;
    text-align: center;
    background: white;
}
QProgressBar::chunk {
    background: #1686c7;
}
"""

WRITE_PATTERN = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|VACUUM|ATTACH|DETACH|REINDEX|ANALYZE|PRAGMA\s+(?!table_info|index_list|index_info|foreign_key_list|database_list))\b",
    re.IGNORECASE | re.DOTALL,
)


class SQLHighlighter(QSyntaxHighlighter):
    KEYWORDS = {
        "SELECT", "FROM", "WHERE", "ORDER", "BY", "GROUP", "HAVING", "LIMIT",
        "OFFSET", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "ON", "AS",
        "DISTINCT", "UNION", "ALL", "INSERT", "INTO", "VALUES", "UPDATE",
        "SET", "DELETE", "CREATE", "TABLE", "VIEW", "INDEX", "DROP", "ALTER",
        "AND", "OR", "NOT", "NULL", "IS", "IN", "LIKE", "BETWEEN", "CASE",
        "WHEN", "THEN", "ELSE", "END", "ASC", "DESC", "COUNT", "SUM", "AVG",
        "MIN", "MAX", "EXPLAIN", "QUERY", "PLAN", "PRAGMA",
    }

    def __init__(self, document):
        super().__init__(document)
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor("#005f9e"))
        self.keyword_format.setFontWeight(QFont.Bold)

        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor("#9c3d10"))

        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#6a7f8f"))
        self.comment_format.setFontItalic(True)

        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor("#6c3fa1"))

    def highlightBlock(self, text: str) -> None:
        for keyword in self.KEYWORDS:
            for match in re.finditer(rf"\b{re.escape(keyword)}\b", text, re.IGNORECASE):
                self.setFormat(match.start(), match.end() - match.start(), self.keyword_format)

        for match in re.finditer(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"", text):
            self.setFormat(match.start(), match.end() - match.start(), self.string_format)

        for match in re.finditer(r"\b\d+(?:\.\d+)?\b", text):
            self.setFormat(match.start(), match.end() - match.start(), self.number_format)

        comment_at = text.find("--")
        if comment_at >= 0:
            self.setFormat(comment_at, len(text) - comment_at, self.comment_format)


class QueryTableModel(QAbstractTableModel):
    def __init__(self, headers: Optional[list[str]] = None, rows: Optional[list[tuple[Any, ...]]] = None):
        super().__init__()
        self.headers = headers or []
        self.rows = rows or []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        value = self.rows[index.row()][index.column()]
        if role in (Qt.DisplayRole, Qt.EditRole):
            if value is None:
                return ""
            if isinstance(value, bytes):
                return f"<BLOB: {len(value)} bytes>"
            return str(value)
        if role == Qt.ToolTipRole:
            if isinstance(value, bytes):
                return value[:256].hex(" ")
            return "" if value is None else str(value)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.headers[section] if section < len(self.headers) else ""
        return str(section + 1)

    def sort(self, column: int, order: Qt.SortOrder) -> None:
        if not (0 <= column < len(self.headers)):
            return
        self.layoutAboutToBeChanged.emit()

        def key(row):
            value = row[column]
            return (value is None, str(value).lower() if value is not None else "")

        self.rows.sort(key=key, reverse=(order == Qt.DescendingOrder))
        self.layoutChanged.emit()


class WorkerSignals(QObject):
    finished = Signal(object)
    error = Signal(str)


class QueryWorker(QRunnable):
    def __init__(self, db_path: str, sql: str, read_only: bool, row_limit: int = 100000):
        super().__init__()
        self.db_path = db_path
        self.sql = sql
        self.read_only = read_only
        self.row_limit = row_limit
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            uri = f"file:{Path(self.db_path).as_posix()}?mode={'ro' if self.read_only else 'rw'}"
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = None
            cur = conn.cursor()
            cur.execute(self.sql)

            if cur.description:
                headers = [col[0] for col in cur.description]
                rows = cur.fetchmany(self.row_limit)
                truncated = cur.fetchone() is not None
                result = {
                    "headers": headers,
                    "rows": rows,
                    "rowcount": len(rows),
                    "truncated": truncated,
                    "changes": 0,
                }
            else:
                conn.commit()
                result = {
                    "headers": ["Result"],
                    "rows": [(f"Statement completed. Rows affected: {cur.rowcount}",)],
                    "rowcount": 1,
                    "truncated": False,
                    "changes": cur.rowcount,
                }

            conn.close()
            self.signals.finished.emit(result)
        except Exception:
            self.signals.error.emit(traceback.format_exc())


class SQLWorkbench(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("FraudFighterToolbox", "SQLWorkbench")
        self.db_path = ""
        self.model = QueryTableModel()
        self.thread_pool = QThreadPool.globalInstance()
        self.read_only = True
        self.query_counter = 1

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(1000, 700)
        self.resize(1400, 900)
        self.setStyleSheet(FFT_STYLE)

        self._build_actions()
        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_docks()
        self._build_statusbar()
        self._restore_state()

        current_db = os.environ.get("FFT_CASE_DB", "").strip()
        if current_db and Path(current_db).exists():
            self.open_database(current_db)
        else:
            self.status_message("No current case database detected. Use Open Database.")

    def _build_actions(self) -> None:
        self.act_open_current = QAction("Open Current Case DB", self)
        self.act_open_current.setShortcut(QKeySequence("Ctrl+Shift+O"))
        self.act_open_current.triggered.connect(self.open_current_case_db)

        self.act_open_db = QAction("Open Database…", self)
        self.act_open_db.setShortcut(QKeySequence.Open)
        self.act_open_db.triggered.connect(self.choose_database)

        self.act_refresh = QAction("Refresh Schema", self)
        self.act_refresh.setShortcut(QKeySequence.Refresh)
        self.act_refresh.triggered.connect(self.refresh_schema)

        self.act_execute = QAction("Execute", self)
        self.act_execute.setShortcut(QKeySequence("F5"))
        self.act_execute.triggered.connect(self.execute_current_sql)

        self.act_explain = QAction("Explain", self)
        self.act_explain.setShortcut(QKeySequence("Ctrl+E"))
        self.act_explain.triggered.connect(self.explain_current_sql)

        self.act_clear = QAction("Clear Editor", self)
        self.act_clear.setShortcut(QKeySequence("Ctrl+L"))
        self.act_clear.triggered.connect(lambda: self.current_editor().clear())

        self.act_new_tab = QAction("New Query Tab", self)
        self.act_new_tab.setShortcut(QKeySequence("Ctrl+T"))
        self.act_new_tab.triggered.connect(self.add_query_tab)

        self.act_close_tab = QAction("Close Query Tab", self)
        self.act_close_tab.setShortcut(QKeySequence("Ctrl+W"))
        self.act_close_tab.triggered.connect(self.close_current_tab)

        self.act_open_sql = QAction("Open SQL…", self)
        self.act_open_sql.triggered.connect(self.open_sql_file)

        self.act_save_sql = QAction("Save SQL…", self)
        self.act_save_sql.setShortcut(QKeySequence.Save)
        self.act_save_sql.triggered.connect(self.save_sql_file)

        self.act_export_csv = QAction("Export Results to CSV…", self)
        self.act_export_csv.triggered.connect(self.export_csv)

        self.act_export_json = QAction("Export Results to JSON…", self)
        self.act_export_json.triggered.connect(self.export_json)

        self.act_copy = QAction("Copy Selected Cells", self)
        self.act_copy.setShortcut(QKeySequence.Copy)
        self.act_copy.triggered.connect(self.copy_selected_cells)

        self.act_read_only = QAction("Read-only Mode", self)
        self.act_read_only.setCheckable(True)
        self.act_read_only.setChecked(True)
        self.act_read_only.triggered.connect(self.toggle_read_only)

        self.act_quit = QAction("Exit", self)
        self.act_quit.triggered.connect(self.close)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction(self.act_open_current)
        file_menu.addAction(self.act_open_db)
        file_menu.addSeparator()
        file_menu.addAction(self.act_open_sql)
        file_menu.addAction(self.act_save_sql)
        file_menu.addSeparator()
        file_menu.addAction(self.act_export_csv)
        file_menu.addAction(self.act_export_json)
        file_menu.addSeparator()
        file_menu.addAction(self.act_quit)

        query_menu = self.menuBar().addMenu("&Query")
        query_menu.addAction(self.act_execute)
        query_menu.addAction(self.act_explain)
        query_menu.addAction(self.act_clear)
        query_menu.addSeparator()
        query_menu.addAction(self.act_new_tab)
        query_menu.addAction(self.act_close_tab)
        query_menu.addSeparator()
        query_menu.addAction(self.act_read_only)

        view_menu = self.menuBar().addMenu("&View")
        view_menu.addAction(self.act_refresh)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setIconSize(QSize(18, 18))
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        for action in (
            self.act_open_current,
            self.act_open_db,
            self.act_refresh,
            self.act_execute,
            self.act_explain,
            self.act_clear,
            self.act_new_tab,
            self.act_export_csv,
        ):
            toolbar.addAction(action)

        toolbar.addSeparator()
        toolbar.addAction(self.act_read_only)

    def _build_central(self) -> None:
        self.query_tabs = QTabWidget()
        self.query_tabs.setTabsClosable(True)
        self.query_tabs.tabCloseRequested.connect(self.close_tab_at)
        self.query_tabs.currentChanged.connect(self.update_window_title)

        self.results_view = QTableView()
        self.results_view.setModel(self.model)
        self.results_view.setSortingEnabled(True)
        self.results_view.setAlternatingRowColors(True)
        self.results_view.setSelectionBehavior(QTableView.SelectItems)
        self.results_view.setSelectionMode(QTableView.ExtendedSelection)
        self.results_view.horizontalHeader().setSectionsMovable(True)
        self.results_view.horizontalHeader().setStretchLastSection(False)
        self.results_view.verticalHeader().setDefaultSectionSize(24)
        self.results_view.doubleClicked.connect(self.update_record_detail)
        self.results_view.clicked.connect(self.update_record_detail)
        self.results_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_view.customContextMenuRequested.connect(self.show_results_menu)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Find text in displayed results…")
        self.filter_edit.textChanged.connect(self.find_in_results)

        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.addWidget(self.filter_edit)
        results_layout.addWidget(self.results_view)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.query_tabs)
        splitter.addWidget(results_widget)
        splitter.setSizes([330, 500])
        self.setCentralWidget(splitter)

        self.add_query_tab(
            "SELECT name, type\n"
            "FROM sqlite_master\n"
            "WHERE type IN ('table', 'view')\n"
            "ORDER BY type, name;"
        )

    def _build_docks(self) -> None:
        self.schema_tree = QTreeWidget()
        self.schema_tree.setHeaderLabels(["Database Objects"])
        self.schema_tree.itemDoubleClicked.connect(self.schema_item_double_clicked)
        self.schema_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.schema_tree.customContextMenuRequested.connect(self.show_schema_menu)

        schema_dock = QDockWidget("Schema Browser", self)
        schema_dock.setObjectName("SchemaDock")
        schema_dock.setWidget(self.schema_tree)
        self.addDockWidget(Qt.LeftDockWidgetArea, schema_dock)

        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.load_history_item)
        history_dock = QDockWidget("Query History", self)
        history_dock.setObjectName("HistoryDock")
        history_dock.setWidget(self.history_list)
        self.addDockWidget(Qt.RightDockWidgetArea, history_dock)

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setFont(QFont("Consolas", 9))
        detail_dock = QDockWidget("Record Detail", self)
        detail_dock.setObjectName("DetailDock")
        detail_dock.setWidget(self.detail_view)
        self.addDockWidget(Qt.BottomDockWidgetArea, detail_dock)

    def _build_statusbar(self) -> None:
        status = QStatusBar()
        self.setStatusBar(status)

        self.connection_label = QLabel("Disconnected")
        self.sqlite_label = QLabel(f"SQLite {sqlite3.sqlite_version}")
        self.rows_label = QLabel("Rows: 0")
        self.mode_label = QLabel("READ ONLY")

        self.progress = QProgressBar()
        self.progress.setMaximumWidth(160)
        self.progress.setRange(0, 0)
        self.progress.hide()

        status.addWidget(self.connection_label, 1)
        status.addPermanentWidget(self.progress)
        status.addPermanentWidget(self.rows_label)
        status.addPermanentWidget(self.sqlite_label)
        status.addPermanentWidget(self.mode_label)

    def _restore_state(self) -> None:
        geometry = self.settings.value("geometry")
        state = self.settings.value("windowState")
        if geometry:
            self.restoreGeometry(geometry)
        if state:
            self.restoreState(state)

    def closeEvent(self, event) -> None:
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
        self.settings.setValue("lastDatabase", self.db_path)
        self.settings.setValue("lastSQL", self.current_editor().toPlainText())
        event.accept()

    def add_query_tab(self, sql: str = "") -> None:
        editor = QPlainTextEdit()
        editor.setFont(QFont("Consolas", 10))
        editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        editor.setPlainText(sql)
        SQLHighlighter(editor.document())

        index = self.query_tabs.addTab(editor, f"Query {self.query_counter}")
        self.query_counter += 1
        self.query_tabs.setCurrentIndex(index)

    def current_editor(self) -> QPlainTextEdit:
        editor = self.query_tabs.currentWidget()
        if not isinstance(editor, QPlainTextEdit):
            raise RuntimeError("No active SQL editor.")
        return editor

    def close_tab_at(self, index: int) -> None:
        if self.query_tabs.count() <= 1:
            self.query_tabs.widget(index).clear()
            return
        widget = self.query_tabs.widget(index)
        self.query_tabs.removeTab(index)
        widget.deleteLater()

    def close_current_tab(self) -> None:
        self.close_tab_at(self.query_tabs.currentIndex())

    def update_window_title(self) -> None:
        db_name = Path(self.db_path).name if self.db_path else "No Database"
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — {db_name}")

    def status_message(self, message: str, timeout: int = 5000) -> None:
        self.statusBar().showMessage(message, timeout)

    def open_current_case_db(self) -> None:
        current_db = os.environ.get("FFT_CASE_DB", "").strip()
        if not current_db:
            QMessageBox.information(self, "Current Case Database", "FFT_CASE_DB is not set.")
            return
        self.open_database(current_db)

    def choose_database(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open SQLite Database",
            self.db_path or str(Path.home()),
            "SQLite databases (*.db *.sqlite *.sqlite3);;All files (*.*)",
        )
        if path:
            self.open_database(path)

    def open_database(self, path: str) -> None:
        path_obj = Path(path)
        if not path_obj.exists():
            QMessageBox.warning(self, "Database Not Found", f"Database does not exist:\n{path}")
            return
        try:
            conn = sqlite3.connect(f"file:{path_obj.as_posix()}?mode=ro", uri=True)
            conn.execute("SELECT 1")
            conn.close()
        except Exception as exc:
            QMessageBox.critical(self, "Database Error", str(exc))
            return

        self.db_path = str(path_obj)
        self.connection_label.setText(f"Connected: {path_obj.name}")
        self.refresh_schema()
        self.update_window_title()
        self.status_message(f"Opened {path_obj}")

    def refresh_schema(self) -> None:
        self.schema_tree.clear()
        if not self.db_path:
            return

        try:
            conn = sqlite3.connect(f"file:{Path(self.db_path).as_posix()}?mode=ro", uri=True)
            rows = conn.execute(
                "SELECT name, type, sql FROM sqlite_master "
                "WHERE type IN ('table','view','index','trigger') "
                "AND name NOT LIKE 'sqlite_%' "
                "ORDER BY type, name"
            ).fetchall()

            categories = {}
            for category in ("table", "view", "index", "trigger"):
                item = QTreeWidgetItem([category.title() + "s"])
                item.setData(0, Qt.UserRole, {"type": "category", "name": category})
                self.schema_tree.addTopLevelItem(item)
                categories[category] = item

            for name, obj_type, sql in rows:
                item = QTreeWidgetItem([name])
                item.setData(0, Qt.UserRole, {"type": obj_type, "name": name, "sql": sql or ""})
                categories[obj_type].addChild(item)

                if obj_type in ("table", "view"):
                    try:
                        columns = conn.execute(f'PRAGMA table_info("{name.replace(chr(34), chr(34)*2)}")').fetchall()
                        for col in columns:
                            col_name = col[1]
                            col_type = col[2] or ""
                            col_item = QTreeWidgetItem([f"{col_name}  {col_type}".strip()])
                            col_item.setData(0, Qt.UserRole, {"type": "column", "name": col_name, "parent": name})
                            item.addChild(col_item)
                    except sqlite3.Error:
                        pass

            conn.close()
            self.schema_tree.expandToDepth(0)
            object_count = sum(parent.childCount() for parent in categories.values())
            self.status_message(f"Schema refreshed: {object_count} objects")
        except Exception as exc:
            QMessageBox.critical(self, "Schema Error", str(exc))

    def schema_item_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        data = item.data(0, Qt.UserRole) or {}
        obj_type = data.get("type")
        name = data.get("name", "")
        if obj_type in ("table", "view"):
            safe = name.replace('"', '""')
            self.current_editor().setPlainText(f'SELECT *\nFROM "{safe}"\nLIMIT 1000;')
            self.execute_current_sql()
        elif obj_type == "column":
            editor = self.current_editor()
            editor.insertPlainText(f'"{name.replace(chr(34), chr(34)*2)}"')

    def show_schema_menu(self, pos) -> None:
        item = self.schema_tree.itemAt(pos)
        if not item:
            return
        data = item.data(0, Qt.UserRole) or {}
        if data.get("type") not in ("table", "view"):
            return

        menu = QMenu(self)
        act_select = menu.addAction("SELECT first 1,000 rows")
        act_count = menu.addAction("Count rows")
        act_schema = menu.addAction("Show CREATE statement")
        chosen = menu.exec(self.schema_tree.viewport().mapToGlobal(pos))
        name = data["name"].replace('"', '""')

        if chosen == act_select:
            self.current_editor().setPlainText(f'SELECT * FROM "{name}" LIMIT 1000;')
            self.execute_current_sql()
        elif chosen == act_count:
            self.current_editor().setPlainText(f'SELECT COUNT(*) AS row_count FROM "{name}";')
            self.execute_current_sql()
        elif chosen == act_schema:
            self.current_editor().setPlainText(data.get("sql", ""))

    def toggle_read_only(self, checked: bool) -> None:
        if not checked:
            answer = QMessageBox.warning(
                self,
                "Enable Write Mode",
                "Write mode can modify the case database.\n\n"
                "For forensic work, use a verified working copy rather than original evidence.\n\n"
                "Enable write mode?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                self.act_read_only.setChecked(True)
                return

        self.read_only = self.act_read_only.isChecked()
        self.mode_label.setText("READ ONLY" if self.read_only else "WRITE ENABLED")
        self.mode_label.setStyleSheet("" if self.read_only else "color: #ffcc66; font-weight: bold;")

    def selected_sql(self) -> str:
        editor = self.current_editor()
        cursor = editor.textCursor()
        sql = cursor.selectedText().replace("\u2029", "\n").strip()
        return sql or editor.toPlainText().strip()

    def execute_current_sql(self) -> None:
        self.execute_sql(self.selected_sql())

    def explain_current_sql(self) -> None:
        sql = self.selected_sql()
        if not sql:
            return
        self.execute_sql("EXPLAIN QUERY PLAN " + sql.rstrip().rstrip(";"))

    def execute_sql(self, sql: str) -> None:
        if not self.db_path:
            QMessageBox.information(self, "No Database", "Open a SQLite database first.")
            return
        if not sql:
            QMessageBox.information(self, "No SQL", "Enter a SQL statement.")
            return
        if self.read_only and WRITE_PATTERN.search(sql):
            QMessageBox.warning(
                self,
                "Read-only Mode",
                "This statement appears to modify the database.\n\nDisable read-only mode before executing it."
            )
            return

        self.history_list.insertItem(0, " ".join(sql.split())[:500])
        self.progress.show()
        self.act_execute.setEnabled(False)
        self.status_message("Executing query…", 0)

        worker = QueryWorker(self.db_path, sql, self.read_only)
        worker.signals.finished.connect(self.query_finished)
        worker.signals.error.connect(self.query_failed)
        self.thread_pool.start(worker)

    @Slot(object)
    def query_finished(self, result: dict[str, Any]) -> None:
        self.progress.hide()
        self.act_execute.setEnabled(True)

        self.model = QueryTableModel(result["headers"], result["rows"])
        self.results_view.setModel(self.model)
        self.results_view.setSortingEnabled(True)
        self.results_view.resizeColumnsToContents()

        row_count = result["rowcount"]
        self.rows_label.setText(f"Rows: {row_count:,}")
        suffix = " (display limit reached)" if result.get("truncated") else ""
        self.status_message(f"Query completed: {row_count:,} rows{suffix}")
        self.detail_view.clear()

    @Slot(str)
    def query_failed(self, error: str) -> None:
        self.progress.hide()
        self.act_execute.setEnabled(True)
        self.status_message("Query failed")
        QMessageBox.critical(self, "SQL Error", error)

    def update_record_detail(self, index: QModelIndex) -> None:
        if not index.isValid() or not self.model.rows:
            return
        row = self.model.rows[index.row()]
        lines = []
        for header, value in zip(self.model.headers, row):
            if isinstance(value, bytes):
                display = value[:512].hex(" ")
                if len(value) > 512:
                    display += "\n…"
            else:
                display = "" if value is None else str(value)
            lines.append(f"{header}\n{'-' * len(header)}\n{display}\n")
        self.detail_view.setPlainText("\n".join(lines))

    def find_in_results(self, text: str) -> None:
        if not text:
            return
        text_lower = text.lower()
        start = self.results_view.currentIndex()
        start_row = start.row() + 1 if start.isValid() else 0

        for offset in range(len(self.model.rows)):
            row_index = (start_row + offset) % max(1, len(self.model.rows))
            row = self.model.rows[row_index]
            for col, value in enumerate(row):
                if text_lower in ("" if value is None else str(value).lower()):
                    idx = self.model.index(row_index, col)
                    self.results_view.setCurrentIndex(idx)
                    self.results_view.scrollTo(idx)
                    return

    def show_results_menu(self, pos) -> None:
        menu = QMenu(self)
        copy_action = menu.addAction("Copy Selected Cells")
        export_csv_action = menu.addAction("Export Results to CSV")
        export_json_action = menu.addAction("Export Results to JSON")
        menu.addSeparator()
        autosize_action = menu.addAction("Auto-size Columns")
        chosen = menu.exec(self.results_view.viewport().mapToGlobal(pos))

        if chosen == copy_action:
            self.copy_selected_cells()
        elif chosen == export_csv_action:
            self.export_csv()
        elif chosen == export_json_action:
            self.export_json()
        elif chosen == autosize_action:
            self.results_view.resizeColumnsToContents()

    def copy_selected_cells(self) -> None:
        indexes = sorted(self.results_view.selectedIndexes(), key=lambda x: (x.row(), x.column()))
        if not indexes:
            return

        rows: dict[int, dict[int, str]] = {}
        for idx in indexes:
            rows.setdefault(idx.row(), {})[idx.column()] = str(self.model.data(idx, Qt.DisplayRole))

        min_col = min(idx.column() for idx in indexes)
        max_col = max(idx.column() for idx in indexes)
        output = []
        for row_number in sorted(rows):
            output.append("\t".join(rows[row_number].get(col, "") for col in range(min_col, max_col + 1)))

        QApplication.clipboard().setText("\n".join(output))
        self.status_message("Selected cells copied")

    def export_csv(self) -> None:
        if not self.model.headers:
            QMessageBox.information(self, "No Results", "There are no results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "query_results.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.model.headers)
                for row in self.model.rows:
                    writer.writerow([
                        value.hex() if isinstance(value, bytes) else value
                        for value in row
                    ])
            self.status_message(f"Exported {len(self.model.rows):,} rows to CSV")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    def export_json(self) -> None:
        if not self.model.headers:
            QMessageBox.information(self, "No Results", "There are no results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "query_results.json", "JSON files (*.json)")
        if not path:
            return
        try:
            records = []
            for row in self.model.rows:
                record = {}
                for header, value in zip(self.model.headers, row):
                    record[header] = value.hex() if isinstance(value, bytes) else value
                records.append(record)
            Path(path).write_text(json.dumps(records, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            self.status_message(f"Exported {len(records):,} rows to JSON")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    def open_sql_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open SQL File", "", "SQL files (*.sql);;Text files (*.txt);;All files (*.*)")
        if path:
            try:
                self.current_editor().setPlainText(Path(path).read_text(encoding="utf-8-sig"))
            except Exception as exc:
                QMessageBox.critical(self, "Open SQL Error", str(exc))

    def save_sql_file(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save SQL File", "query.sql", "SQL files (*.sql);;Text files (*.txt)")
        if path:
            try:
                Path(path).write_text(self.current_editor().toPlainText(), encoding="utf-8")
                self.status_message(f"Saved SQL to {path}")
            except Exception as exc:
                QMessageBox.critical(self, "Save SQL Error", str(exc))

    def load_history_item(self, item) -> None:
        self.current_editor().setPlainText(item.text())


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("Fraud Fighter Toolbox")
    app.setStyle("Fusion")

    palette = app.palette()
    palette.setColor(QPalette.Highlight, QColor("#1686c7"))
    palette.setColor(QPalette.HighlightedText, QColor("white"))
    app.setPalette(palette)

    window = SQLWorkbench()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
