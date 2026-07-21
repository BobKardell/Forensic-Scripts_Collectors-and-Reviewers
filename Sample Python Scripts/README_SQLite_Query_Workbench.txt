SQLite Query Workbench
======================

Place SQLite_Query_Workbench.py in:

Forensics Collector Global Settings/Python Scripts

The script automatically loads .sql files from:

Forensics Collector Global Settings/SQL Queries

Features
--------
- Open SQLite .sqlite, .sqlite3, .db, and .db3 files.
- View tables, views, columns, data types, primary keys, and NOT NULL fields.
- Double-click a table to create a SELECT query.
- Double-click a field to insert its qualified name.
- Run saved or ad hoc SQL queries.
- Read-only operation by default.
- Optional write-query mode with a confirmation warning.
- Sort results by clicking column headers.
- Double-click a result row for a field-by-field viewer.
- Export displayed query results to CSV.

Run
---
python SQLite_Query_Workbench.py

Forensic caution
----------------
The database opens read-only by default. Only enable write queries when you
intend to modify a working copy or case database.
