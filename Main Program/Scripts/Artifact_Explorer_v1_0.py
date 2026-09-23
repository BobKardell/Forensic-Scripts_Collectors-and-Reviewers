#!/usr/bin/env python3
# FFT_TOOL
# TITLE: Artifact Explorer
# ID: artifact_explorer
# CATEGORY: Analysis Tools
# VERSION: 1.0.0
# DESCRIPTION: Parse Windows registry-derived artifacts, MRUs, USB and mounted devices, Jump Lists, LNK files, browser and search history, and Prefetch files.
# ICON: ✅
# PASS_CASE_ARGUMENTS: false

from __future__ import annotations

import csv
import json
import os
import queue
import re
import shutil
import sqlite3
import struct
import tempfile
import threading
import traceback
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Any, Iterable, Optional

APP_NAME = "Artifact Explorer"
APP_VERSION = "1.0.0"
CASE_DB = Path(os.environ["FFT_CASE_DB"]) if os.environ.get("FFT_CASE_DB") else None
CASE_NAME = os.environ.get("FFT_CASE_NAME", "Standalone Analysis")
CASE_NUMBER = os.environ.get("FFT_CASE_NUMBER", "")
EXAMINER = os.environ.get("FFT_EXAMINER", "")
ENV_EVIDENCE_ID = os.environ.get("FFT_EVIDENCE_ID", "")
ENV_EVIDENCE_ROOT = os.environ.get("FFT_EVIDENCE_ROOT", "")

COLORS = {"navy":"#061522","blue":"#188bd0","panel":"#f2f6f9","white":"#ffffff","text":"#172431","muted":"#607180","border":"#c8d5df","red":"#a33b3b","green":"#367d4a"}
BATCH_SIZE = 250


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iso_from_unix(value: float) -> str:
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return ""


def filetime_to_iso(value: int) -> str:
    if not value:
        return ""
    try:
        return (datetime(1601,1,1,tzinfo=timezone.utc) + timedelta(microseconds=value/10)).isoformat(timespec="seconds")
    except Exception:
        return ""


def chrome_time_to_iso(value: Any) -> str:
    try:
        micros = int(value)
        if micros <= 0:
            return ""
        return (datetime(1601,1,1,tzinfo=timezone.utc) + timedelta(microseconds=micros)).isoformat(timespec="seconds")
    except Exception:
        return ""


def firefox_time_to_iso(value: Any) -> str:
    try:
        micros = int(value)
        if micros <= 0:
            return ""
        return datetime.fromtimestamp(micros / 1_000_000, timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return ""


def strings_from_bytes(data: bytes, minimum: int = 6, limit: int = 200) -> list[str]:
    found: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        text = m.group().decode("utf-8", "replace").strip()
        if text and text not in found:
            found.append(text)
            if len(found) >= limit:
                break
    try:
        decoded = data.decode("utf-16le", "ignore")
        for m in re.finditer(r"[\x20-\x7e]{%d,}" % minimum, decoded):
            text = m.group().strip()
            if text and text not in found:
                found.append(text)
                if len(found) >= limit:
                    break
    except Exception:
        pass
    return found


def user_from_path(path: Path) -> str:
    parts = list(path.parts)
    lowered = [p.lower() for p in parts]
    if "users" in lowered:
        idx = lowered.index("users")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "System"


def search_term_from_url(url: str) -> str:
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        for key in ("q","query","p","text","search_query","wd"):
            if key in q and q[key]:
                return q[key][0]
    except Exception:
        pass
    return ""


class ArtifactExplorer(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1560x900")
        self.minsize(1120, 720)
        self.configure(bg=COLORS["panel"])

        self.case_db = CASE_DB
        self.evidence_id = int(ENV_EVIDENCE_ID) if ENV_EVIDENCE_ID.isdigit() else 0
        self.root_var = tk.StringVar(value=self.resolve_evidence_root())
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0)
        self.current_var = tk.StringVar(value="")
        self.total_var = tk.StringVar(value="0")
        self.errors_var = tk.StringVar(value="0")
        self.registry_var = tk.StringVar(value="0")
        self.mru_var = tk.StringVar(value="0")
        self.usb_var = tk.StringVar(value="0")
        self.mounted_var = tk.StringVar(value="0")
        self.jump_var = tk.StringVar(value="0")
        self.lnk_var = tk.StringVar(value="0")
        self.browser_var = tk.StringVar(value="0")
        self.search_var_count = tk.StringVar(value="0")
        self.prefetch_var = tk.StringVar(value="0")
        self.search_filter_var = tk.StringVar()
        self.category_filter_var = tk.StringVar(value="All")

        self.scan_registry = tk.BooleanVar(value=True)
        self.scan_mru = tk.BooleanVar(value=True)
        self.scan_usb = tk.BooleanVar(value=True)
        self.scan_mounted = tk.BooleanVar(value=True)
        self.scan_jump = tk.BooleanVar(value=True)
        self.scan_lnk = tk.BooleanVar(value=True)
        self.scan_browser = tk.BooleanVar(value=True)
        self.scan_search = tk.BooleanVar(value=True)
        self.scan_prefetch = tk.BooleanVar(value=True)

        self.ui_queue: queue.Queue[tuple] = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.run_id = 0
        self._configure_styles()
        self._build_ui()
        self.ensure_database()
        self.ensure_schema()
        self.refresh_all()
        self.after(100, self.process_queue)

    def resolve_evidence_root(self) -> str:
        candidates: list[str] = []
        if CASE_DB and CASE_DB.exists() and ENV_EVIDENCE_ID.isdigit():
            try:
                with sqlite3.connect(CASE_DB) as con:
                    table_row = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND lower(name)='evidence'").fetchone()
                    if table_row:
                        table = table_row[0]
                        cols = {r[1].lower(): r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
                        id_col = next((cols[k] for k in ("id","evidence_id","evidenceid") if k in cols), None)
                        paths = [cols[k] for k in ("mounted_volume","mount_path","mounted_path","volume_root","evidence_root","root_path") if k in cols]
                        if id_col and paths:
                            row = con.execute(f'SELECT {", ".join(chr(34)+c+chr(34) for c in paths)} FROM "{table}" WHERE "{id_col}"=?',(int(ENV_EVIDENCE_ID),)).fetchone()
                            if row:
                                candidates.extend(str(v).strip() for v in row if v)
            except Exception:
                pass
        if ENV_EVIDENCE_ROOT:
            candidates.append(ENV_EVIDENCE_ROOT)
        for c in candidates:
            if Path(c).exists():
                return c
        return candidates[0] if candidates else ""

    def ensure_database(self) -> None:
        if not self.case_db:
            self.case_db = Path.cwd() / "Artifact_Explorer_Standalone.sqlite"
        self.case_db.parent.mkdir(parents=True, exist_ok=True)

    def ensure_schema(self) -> None:
        with sqlite3.connect(self.case_db) as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS forensic_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL DEFAULT 0,
                run_id INTEGER,
                category TEXT NOT NULL,
                subtype TEXT,
                artifact_name TEXT,
                user_name TEXT,
                timestamp_utc TEXT,
                source_path TEXT,
                key_path TEXT,
                value_name TEXT,
                value_data TEXT,
                description TEXT,
                parser_name TEXT,
                raw_data TEXT,
                created_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_forensic_artifacts_evidence ON forensic_artifacts(evidence_id);
            CREATE INDEX IF NOT EXISTS idx_forensic_artifacts_category ON forensic_artifacts(category);
            CREATE INDEX IF NOT EXISTS idx_forensic_artifacts_time ON forensic_artifacts(timestamp_utc);
            CREATE TABLE IF NOT EXISTS artifact_scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                started_utc TEXT,
                completed_utc TEXT,
                root_path TEXT,
                status TEXT,
                artifact_count INTEGER DEFAULT 0,
                error_count INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS artifact_parse_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                run_id INTEGER,
                parser_name TEXT,
                source_path TEXT,
                error_message TEXT,
                traceback_text TEXT,
                created_utc TEXT
            );
            """)

    def _configure_styles(self) -> None:
        s = ttk.Style(self)
        try: s.theme_use("clam")
        except tk.TclError: pass
        s.configure("TFrame", background=COLORS["panel"])
        s.configure("White.TFrame", background=COLORS["white"])
        s.configure("Title.TLabel", background=COLORS["navy"], foreground="white", font=("Segoe UI",18,"bold"))
        s.configure("Header.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI",11,"bold"))
        s.configure("CardValue.TLabel", background=COLORS["white"], foreground=COLORS["blue"], font=("Segoe UI",18,"bold"))
        s.configure("CardTitle.TLabel", background=COLORS["white"], foreground=COLORS["muted"], font=("Segoe UI",9))
        s.configure("Treeview", rowheight=24, font=("Segoe UI",9))
        s.configure("Treeview.Heading", font=("Segoe UI",9,"bold"))

    def _build_ui(self) -> None:
        header = tk.Frame(self,bg=COLORS["navy"],height=66)
        header.pack(fill="x")
        tk.Label(header,text=APP_NAME,bg=COLORS["navy"],fg="white",font=("Segoe UI",18,"bold")).pack(side="left",padx=18,pady=14)
        tk.Label(header,text=f"v{APP_VERSION}",bg=COLORS["navy"],fg="#a9c9dd",font=("Segoe UI",10)).pack(side="left")

        toolbar = ttk.Frame(self,padding=(12,10)); toolbar.pack(fill="x")
        ttk.Label(toolbar,text="Evidence Root:").pack(side="left")
        ttk.Entry(toolbar,textvariable=self.root_var,width=62).pack(side="left",padx=6)
        ttk.Button(toolbar,text="Browse",command=self.browse_root).pack(side="left")
        ttk.Button(toolbar,text="Scan Selected",command=self.start_scan).pack(side="left",padx=(14,4))
        ttk.Button(toolbar,text="Stop",command=self.stop_scan).pack(side="left")
        ttk.Button(toolbar,text="Export CSV",command=self.export_csv).pack(side="right")
        ttk.Button(toolbar,text="Clear Results",command=self.clear_results).pack(side="right",padx=6)

        opts = ttk.LabelFrame(self,text="Artifact Types",padding=8); opts.pack(fill="x",padx=12,pady=(0,8))
        checks=[("Registry",self.scan_registry),("MRUs",self.scan_mru),("USB Devices",self.scan_usb),("Mounted Devices",self.scan_mounted),("Jump Lists",self.scan_jump),("LNK Files",self.scan_lnk),("Browser History",self.scan_browser),("Search History",self.scan_search),("Prefetch",self.scan_prefetch)]
        for text,var in checks: ttk.Checkbutton(opts,text=text,variable=var).pack(side="left",padx=7)

        progress = ttk.Frame(self,padding=(12,0)); progress.pack(fill="x")
        ttk.Progressbar(progress,variable=self.progress_var,maximum=100).pack(side="left",fill="x",expand=True)
        ttk.Label(progress,textvariable=self.status_var,width=22).pack(side="left",padx=8)
        ttk.Label(self,textvariable=self.current_var,foreground=COLORS["muted"]).pack(fill="x",padx=14)

        cards=ttk.Frame(self,padding=10); cards.pack(fill="x")
        metrics=[("Total",self.total_var),("Registry",self.registry_var),("MRUs",self.mru_var),("USB",self.usb_var),("Mounted",self.mounted_var),("Jump Lists",self.jump_var),("LNK",self.lnk_var),("Browser",self.browser_var),("Search",self.search_var_count),("Prefetch",self.prefetch_var),("Errors",self.errors_var)]
        for i,(title,var) in enumerate(metrics):
            f=ttk.Frame(cards,style="White.TFrame",padding=8); f.grid(row=0,column=i,sticky="nsew",padx=3)
            ttk.Label(f,text=title,style="CardTitle.TLabel").pack()
            ttk.Label(f,textvariable=var,style="CardValue.TLabel").pack()
            cards.columnconfigure(i,weight=1)

        notebook=ttk.Notebook(self); notebook.pack(fill="both",expand=True,padx=12,pady=(0,12))
        results=ttk.Frame(notebook,padding=8); errors=ttk.Frame(notebook,padding=8)
        notebook.add(results,text="Artifacts"); notebook.add(errors,text="Errors")

        filters=ttk.Frame(results); filters.pack(fill="x",pady=(0,6))
        ttk.Label(filters,text="Search:").pack(side="left")
        e=ttk.Entry(filters,textvariable=self.search_filter_var,width=44); e.pack(side="left",padx=5); e.bind("<Return>",lambda _e:self.refresh_results())
        ttk.Label(filters,text="Category:").pack(side="left",padx=(12,3))
        combo=ttk.Combobox(filters,textvariable=self.category_filter_var,state="readonly",width=18,values=["All","Registry","MRU","USB Device","Mounted Device","Jump List","LNK","Browser History","Search History","Prefetch"]); combo.pack(side="left"); combo.bind("<<ComboboxSelected>>",lambda _e:self.refresh_results())
        ttk.Button(filters,text="Apply",command=self.refresh_results).pack(side="left",padx=6)

        cols=("category","subtype","timestamp","user","name","value","source")
        self.tree=ttk.Treeview(results,columns=cols,show="headings")
        headings={"category":"Category","subtype":"Subtype","timestamp":"Timestamp (UTC)","user":"User","name":"Artifact","value":"Value / Target","source":"Source"}
        widths={"category":120,"subtype":150,"timestamp":180,"user":100,"name":220,"value":360,"source":390}
        for c in cols: self.tree.heading(c,text=headings[c]); self.tree.column(c,width=widths[c],anchor="w")
        y=ttk.Scrollbar(results,orient="vertical",command=self.tree.yview); x=ttk.Scrollbar(results,orient="horizontal",command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        self.tree.pack(side="left",fill="both",expand=True); y.pack(side="right",fill="y"); x.pack(side="bottom",fill="x")
        self.tree.bind("<Double-1>",self.show_detail)

        self.error_tree=ttk.Treeview(errors,columns=("parser","source","error","time"),show="headings")
        for c,t,w in (("parser","Parser",150),("source","Source",460),("error","Error",600),("time","Time",180)):
            self.error_tree.heading(c,text=t); self.error_tree.column(c,width=w,anchor="w")
        self.error_tree.pack(fill="both",expand=True)

    def browse_root(self) -> None:
        p=filedialog.askdirectory(title="Select mounted evidence root")
        if p: self.root_var.set(p)

    def start_scan(self) -> None:
        root=Path(self.root_var.get().strip())
        if not root.exists():
            messagebox.showerror(APP_NAME,"The evidence root does not exist."); return
        if self.worker and self.worker.is_alive(): return
        self.cancel_event.clear(); self.progress_var.set(0); self.status_var.set("Starting scan...")
        with sqlite3.connect(self.case_db) as con:
            cur=con.execute("INSERT INTO artifact_scan_runs(evidence_id,started_utc,root_path,status) VALUES(?,?,?,?)",(self.evidence_id,utc_now(),str(root),"Running")); self.run_id=cur.lastrowid
        selected=[
            ("Registry",self.scan_registry.get(),self.parse_registry_results),
            ("MRUs",self.scan_mru.get(),self.parse_mrus),
            ("USB Devices",self.scan_usb.get(),self.parse_usb),
            ("Mounted Devices",self.scan_mounted.get(),self.parse_mounted),
            ("Jump Lists",self.scan_jump.get(),lambda r:self.parse_jump_lists(root)),
            ("LNK Files",self.scan_lnk.get(),lambda r:self.parse_lnk_files(root)),
            ("Browser History",self.scan_browser.get(),lambda r:self.parse_browsers(root)),
            ("Search History",self.scan_search.get(),self.parse_search_history),
            ("Prefetch",self.scan_prefetch.get(),lambda r:self.parse_prefetch(root)),
        ]
        tasks=[x for x in selected if x[1]]
        self.worker=threading.Thread(target=self._scan_worker,args=(tasks,),daemon=True); self.worker.start()

    def stop_scan(self) -> None:
        self.cancel_event.set(); self.status_var.set("Stopping...")

    def _scan_worker(self,tasks) -> None:
        try:
            for idx,(name,_enabled,func) in enumerate(tasks,1):
                if self.cancel_event.is_set(): break
                self.ui_queue.put(("status",f"Parsing {name}...")); self.ui_queue.put(("progress",(idx-1)/max(len(tasks),1)*100))
                try: func(Path(self.root_var.get()))
                except Exception as exc: self.record_error(name,"",exc)
                self.ui_queue.put(("refresh",))
            status="Stopped" if self.cancel_event.is_set() else "Completed"
            with sqlite3.connect(self.case_db) as con:
                count=con.execute("SELECT COUNT(*) FROM forensic_artifacts WHERE evidence_id=? AND run_id=?",(self.evidence_id,self.run_id)).fetchone()[0]
                errs=con.execute("SELECT COUNT(*) FROM artifact_parse_errors WHERE evidence_id=? AND run_id=?",(self.evidence_id,self.run_id)).fetchone()[0]
                con.execute("UPDATE artifact_scan_runs SET completed_utc=?,status=?,artifact_count=?,error_count=? WHERE id=?",(utc_now(),status,count,errs,self.run_id))
            self.ui_queue.put(("progress",100)); self.ui_queue.put(("done",status))
        except Exception as exc:
            self.record_error("Artifact Explorer","",exc); self.ui_queue.put(("done","Failed"))

    def stop_requested(self) -> bool:
        return self.cancel_event.is_set()

    def insert_artifacts(self, rows: Iterable[tuple]) -> None:
        rows=list(rows)
        if not rows: return
        with sqlite3.connect(self.case_db) as con:
            con.executemany("""INSERT INTO forensic_artifacts
            (evidence_id,run_id,category,subtype,artifact_name,user_name,timestamp_utc,source_path,key_path,value_name,value_data,description,parser_name,raw_data,created_utc)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",rows)

    def artifact(self,category:str,subtype:str,name:str,user:str="",timestamp:str="",source:str="",key_path:str="",value_name:str="",value_data:str="",description:str="",parser:str="",raw:Any="") -> tuple:
        if not isinstance(raw,str):
            try: raw=json.dumps(raw,ensure_ascii=False,default=str)
            except Exception: raw=str(raw)
        return (self.evidence_id,self.run_id,category,subtype,name,user,timestamp,source,key_path,value_name,str(value_data or ""),description,parser,raw,utc_now())

    def table_exists(self, con:sqlite3.Connection, name:str) -> bool:
        return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name)=lower(?)",(name,)).fetchone() is not None

    def parse_registry_results(self,_root:Path) -> None:
        rows=[]
        with sqlite3.connect(self.case_db) as con:
            con.row_factory=sqlite3.Row
            candidates=["registry_artifacts","registry_results"]
            for table in candidates:
                if not self.table_exists(con,table): continue
                cols={r[1].lower():r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
                ev=cols.get("evidence_id") or cols.get("evidenceid")
                sql=f'SELECT * FROM "{table}"' + (f' WHERE "{ev}"=?' if ev else "")
                for r in con.execute(sql,(self.evidence_id,) if ev else ()):
                    d=dict(r)
                    key=str(d.get(cols.get("key_path",""),d.get("key_path","")) or d.get("registry_key","") or "")
                    valname=str(d.get("value_name","") or d.get("name","") or "")
                    data=str(d.get("value_data","") or d.get("data","") or d.get("value","") or "")
                    hive=str(d.get("hive_type","") or d.get("hive","") or "")
                    user=str(d.get("user_name","") or d.get("user","") or "")
                    ts=str(d.get("last_write_time","") or d.get("timestamp_utc","") or d.get("timestamp","") or "")
                    src=str(d.get("hive_path","") or d.get("source_path","") or "")
                    name=valname or key.rsplit("\\",1)[-1] or "Registry Entry"
                    rows.append(self.artifact("Registry",hive,name,user,ts,src,key,valname,data,"Imported from Registry Explorer",f"{table} importer",d))
                    if len(rows)>=BATCH_SIZE: self.insert_artifacts(rows); rows=[]
        self.insert_artifacts(rows)

    def registry_source_rows(self, patterns:list[str]) -> list[sqlite3.Row]:
        with sqlite3.connect(self.case_db) as con:
            con.row_factory=sqlite3.Row
            clauses=" OR ".join("lower(coalesce(key_path,'')) LIKE ? OR lower(coalesce(artifact_name,'')) LIKE ?" for _ in patterns)
            params=[]
            for p in patterns: params += [f"%{p.lower()}%",f"%{p.lower()}%"]
            return con.execute(f"SELECT * FROM forensic_artifacts WHERE evidence_id=? AND category='Registry' AND ({clauses})",[self.evidence_id,*params]).fetchall()

    def parse_mrus(self,_root:Path) -> None:
        patterns=["recentdocs","runmru","typedpaths","opensavemru","lastvisitedpidlmru","wordwheelquery","comdlg32","userassist"]
        rows=[]
        for r in self.registry_source_rows(patterns):
            rows.append(self.artifact("MRU","Registry MRU",r["artifact_name"],r["user_name"],r["timestamp_utc"],r["source_path"],r["key_path"],r["value_name"],r["value_data"],"MRU-derived registry artifact","MRU parser",dict(r)))
        self.insert_artifacts(rows)

    def parse_usb(self,_root:Path) -> None:
        patterns=["usbstor","enum\\usb","portable devices","deviceclasses","wpd"]
        rows=[]
        for r in self.registry_source_rows(patterns):
            rows.append(self.artifact("USB Device","Registry USB",r["artifact_name"],r["user_name"],r["timestamp_utc"],r["source_path"],r["key_path"],r["value_name"],r["value_data"],"USB-related registry artifact","USB parser",dict(r)))
        self.insert_artifacts(rows)

    def parse_mounted(self,_root:Path) -> None:
        patterns=["mounteddevices","mountpoints2","dosdevices","volume{"]
        rows=[]
        for r in self.registry_source_rows(patterns):
            rows.append(self.artifact("Mounted Device","Registry Mount",r["artifact_name"],r["user_name"],r["timestamp_utc"],r["source_path"],r["key_path"],r["value_name"],r["value_data"],"Mounted-volume registry artifact","Mounted-device parser",dict(r)))
        self.insert_artifacts(rows)

    def walk_matching(self,root:Path,names:tuple[str,...]=(),suffixes:tuple[str,...]=()) -> Iterable[Path]:
        skip={"$recycle.bin","system volume information"}
        for current,dirs,files in os.walk(root):
            if self.stop_requested(): return
            dirs[:]=[d for d in dirs if d.lower() not in skip]
            for f in files:
                lf=f.lower()
                if (names and lf in names) or (suffixes and any(lf.endswith(s) for s in suffixes)):
                    yield Path(current)/f

    def parse_lnk_files(self,root:Path) -> None:
        rows=[]
        for path in self.walk_matching(root,suffixes=(".lnk",)):
            if self.stop_requested(): break
            try:
                data=path.read_bytes()
                if len(data)<76 or data[:4]!=b"L\x00\x00\x00":
                    raise ValueError("Not a valid Shell Link header")
                created=filetime_to_iso(struct.unpack_from("<Q",data,28)[0]); accessed=filetime_to_iso(struct.unpack_from("<Q",data,36)[0]); modified=filetime_to_iso(struct.unpack_from("<Q",data,44)[0])
                strings=strings_from_bytes(data,6,80)
                likely=[s for s in strings if ("\\" in s or ":" in s or s.lower().endswith((".exe",".doc",".pdf",".jpg",".txt")))]
                target=max(likely,key=len) if likely else (strings[0] if strings else "")
                raw={"created":created,"modified":modified,"accessed":accessed,"strings":strings}
                ts=modified or created or iso_from_unix(path.stat().st_mtime)
                rows.append(self.artifact("LNK","Shell Link",path.name,user_from_path(path),ts,str(path),value_data=target,description="Windows shortcut file",parser="LNK parser",raw=raw))
                if len(rows)>=BATCH_SIZE: self.insert_artifacts(rows); rows=[]
            except Exception as exc: self.record_error("LNK parser",str(path),exc)
        self.insert_artifacts(rows)

    def parse_jump_lists(self,root:Path) -> None:
        rows=[]
        for path in self.walk_matching(root,suffixes=(".automaticdestinations-ms",".customdestinations-ms")):
            if self.stop_requested(): break
            try:
                data=path.read_bytes(); strings=strings_from_bytes(data,7,200)
                targets=[s for s in strings if "\\" in s or s.lower().startswith(("http://","https://"))]
                subtype="Automatic Destinations" if path.name.lower().endswith(".automaticdestinations-ms") else "Custom Destinations"
                value=" | ".join(targets[:20])
                rows.append(self.artifact("Jump List",subtype,path.name,user_from_path(path),iso_from_unix(path.stat().st_mtime),str(path),value_data=value,description=f"Embedded targets: {len(targets)}",parser="Jump List strings parser",raw={"strings":strings,"targets":targets}))
                if len(rows)>=BATCH_SIZE: self.insert_artifacts(rows); rows=[]
            except Exception as exc: self.record_error("Jump List parser",str(path),exc)
        self.insert_artifacts(rows)

    def copy_sqlite(self,path:Path) -> Path:
        tmp=Path(tempfile.mkdtemp(prefix="fft_artifact_"))/path.name
        shutil.copy2(path,tmp)
        for suffix in ("-wal","-shm"):
            side=Path(str(path)+suffix)
            if side.exists():
                try: shutil.copy2(side,Path(str(tmp)+suffix))
                except Exception: pass
        return tmp

    def browser_profiles(self,root:Path) -> Iterable[tuple[str,str,Path,str]]:
        for path in self.walk_matching(root,names=("history","places.sqlite")):
            lp=str(path).lower()
            browser=""
            if "google\\chrome" in lp or "google/chrome" in lp: browser="Chrome"
            elif "microsoft\\edge" in lp or "microsoft/edge" in lp: browser="Edge"
            elif "bravesoftware" in lp: browser="Brave"
            elif "opera software" in lp: browser="Opera"
            elif path.name.lower()=="places.sqlite" and "mozilla" in lp: browser="Firefox"
            if browser:
                yield browser,user_from_path(path),path,path.parent.name

    def parse_browsers(self,root:Path) -> None:
        rows=[]
        for browser,user,path,profile in self.browser_profiles(root):
            if self.stop_requested(): break
            tmp=None
            try:
                tmp=self.copy_sqlite(path)
                con=sqlite3.connect(f"file:{tmp}?mode=ro",uri=True); con.row_factory=sqlite3.Row
                if browser=="Firefox":
                    sql="""SELECT p.url,p.title,p.visit_count,v.visit_date FROM moz_places p JOIN moz_historyvisits v ON v.place_id=p.id ORDER BY v.visit_date"""
                    for r in con.execute(sql):
                        url=r["url"] or ""; title=r["title"] or ""; ts=firefox_time_to_iso(r["visit_date"])
                        rows.append(self.artifact("Browser History",browser,title or url,user,ts,str(path),value_data=url,description=f"Profile: {profile}; visits: {r['visit_count']}",parser="Firefox history parser",raw=dict(r)))
                        if len(rows)>=BATCH_SIZE: self.insert_artifacts(rows); rows=[]
                else:
                    sql="""SELECT u.url,u.title,u.visit_count,v.visit_time FROM urls u JOIN visits v ON v.url=u.id ORDER BY v.visit_time"""
                    for r in con.execute(sql):
                        url=r["url"] or ""; title=r["title"] or ""; ts=chrome_time_to_iso(r["visit_time"])
                        rows.append(self.artifact("Browser History",browser,title or url,user,ts,str(path),value_data=url,description=f"Profile: {profile}; visits: {r['visit_count']}",parser=f"{browser} history parser",raw=dict(r)))
                        if len(rows)>=BATCH_SIZE: self.insert_artifacts(rows); rows=[]
                con.close()
            except Exception as exc: self.record_error(f"{browser} history parser",str(path),exc)
            finally:
                if tmp:
                    try: shutil.rmtree(tmp.parent,ignore_errors=True)
                    except Exception: pass
        self.insert_artifacts(rows)

    def parse_search_history(self,_root:Path) -> None:
        rows=[]
        with sqlite3.connect(self.case_db) as con:
            con.row_factory=sqlite3.Row
            for r in con.execute("SELECT * FROM forensic_artifacts WHERE evidence_id=? AND category='Browser History'",(self.evidence_id,)):
                term=search_term_from_url(r["value_data"] or "")
                if term:
                    rows.append(self.artifact("Search History",r["subtype"],term,r["user_name"],r["timestamp_utc"],r["source_path"],value_data=r["value_data"],description="Search term extracted from browser URL",parser="Browser search parser",raw=dict(r)))
            for r in con.execute("SELECT * FROM forensic_artifacts WHERE evidence_id=? AND category='MRU' AND (lower(key_path) LIKE '%wordwheelquery%' OR lower(key_path) LIKE '%typedpaths%' OR lower(key_path) LIKE '%runmru%')",(self.evidence_id,)):
                rows.append(self.artifact("Search History","Windows Registry",r["artifact_name"],r["user_name"],r["timestamp_utc"],r["source_path"],r["key_path"],r["value_name"],r["value_data"],"Windows search or typed-path history", "Windows search history parser",dict(r)))
        self.insert_artifacts(rows)

    def parse_prefetch(self,root:Path) -> None:
        rows=[]
        pfdir=root/"Windows"/"Prefetch"
        paths=list(pfdir.glob("*.pf")) if pfdir.exists() else list(self.walk_matching(root,suffixes=(".pf",)))
        for path in paths:
            if self.stop_requested(): break
            try:
                data=path.read_bytes()
                if len(data)<100: raise ValueError("Prefetch file too small")
                version=struct.unpack_from("<I",data,0)[0]
                sig=data[4:8]
                if sig!=b"SCCA": raise ValueError("Unsupported or compressed Prefetch signature")
                exe=data[16:76].decode("utf-16le","ignore").rstrip("\x00")
                run_count=0; last_runs=[]
                if version==17:
                    last_runs=[filetime_to_iso(struct.unpack_from("<Q",data,120)[0])]; run_count=struct.unpack_from("<I",data,144)[0]
                elif version==23:
                    last_runs=[filetime_to_iso(struct.unpack_from("<Q",data,128)[0])]; run_count=struct.unpack_from("<I",data,152)[0]
                elif version in (26,30,31):
                    for off in range(128,128+64,8):
                        ts=filetime_to_iso(struct.unpack_from("<Q",data,off)[0]);
                        if ts: last_runs.append(ts)
                    run_count=struct.unpack_from("<I",data,208)[0] if len(data)>=212 else 0
                else:
                    last_runs=[iso_from_unix(path.stat().st_mtime)]
                strings=strings_from_bytes(data,8,300)
                refs=[s for s in strings if "\\" in s][:100]
                ts=last_runs[0] if last_runs else iso_from_unix(path.stat().st_mtime)
                rows.append(self.artifact("Prefetch",f"Version {version}",exe or path.stem,"System",ts,str(path),value_data=f"Run Count: {run_count}",description=f"Last runs: {', '.join(last_runs)}; referenced files: {len(refs)}",parser="Prefetch parser",raw={"version":version,"run_count":run_count,"last_runs":last_runs,"references":refs}))
                if len(rows)>=BATCH_SIZE: self.insert_artifacts(rows); rows=[]
            except Exception as exc: self.record_error("Prefetch parser",str(path),exc)
        self.insert_artifacts(rows)

    def record_error(self,parser:str,source:str,exc:Exception) -> None:
        tb=traceback.format_exc()
        with sqlite3.connect(self.case_db) as con:
            con.execute("INSERT INTO artifact_parse_errors(evidence_id,run_id,parser_name,source_path,error_message,traceback_text,created_utc) VALUES(?,?,?,?,?,?,?)",(self.evidence_id,self.run_id,parser,source,str(exc),tb,utc_now()))

    def refresh_all(self) -> None:
        self.refresh_counts(); self.refresh_results(); self.refresh_errors()

    def refresh_counts(self) -> None:
        with sqlite3.connect(self.case_db) as con:
            total=con.execute("SELECT COUNT(*) FROM forensic_artifacts WHERE evidence_id=?",(self.evidence_id,)).fetchone()[0]
            self.total_var.set(str(total))
            mapping={"Registry":self.registry_var,"MRU":self.mru_var,"USB Device":self.usb_var,"Mounted Device":self.mounted_var,"Jump List":self.jump_var,"LNK":self.lnk_var,"Browser History":self.browser_var,"Search History":self.search_var_count,"Prefetch":self.prefetch_var}
            for cat,var in mapping.items(): var.set(str(con.execute("SELECT COUNT(*) FROM forensic_artifacts WHERE evidence_id=? AND category=?",(self.evidence_id,cat)).fetchone()[0]))
            self.errors_var.set(str(con.execute("SELECT COUNT(*) FROM artifact_parse_errors WHERE evidence_id=?",(self.evidence_id,)).fetchone()[0]))

    def refresh_results(self) -> None:
        for i in self.tree.get_children(): self.tree.delete(i)
        sql="SELECT id,category,subtype,timestamp_utc,user_name,artifact_name,value_data,source_path FROM forensic_artifacts WHERE evidence_id=?"; params:[Any]=[self.evidence_id]
        if self.category_filter_var.get()!="All": sql+=" AND category=?"; params.append(self.category_filter_var.get())
        q=self.search_filter_var.get().strip()
        if q:
            sql+=" AND (artifact_name LIKE ? OR value_data LIKE ? OR source_path LIKE ? OR key_path LIKE ?)"; params += [f"%{q}%"]*4
        sql+=" ORDER BY COALESCE(timestamp_utc,'') DESC,id DESC LIMIT 10000"
        with sqlite3.connect(self.case_db) as con:
            for r in con.execute(sql,params):
                self.tree.insert("","end",iid=str(r[0]),values=(r[1],r[2],r[3],r[4],r[5],r[6],r[7]))

    def refresh_errors(self) -> None:
        for i in self.error_tree.get_children(): self.error_tree.delete(i)
        with sqlite3.connect(self.case_db) as con:
            for r in con.execute("SELECT parser_name,source_path,error_message,created_utc FROM artifact_parse_errors WHERE evidence_id=? ORDER BY id DESC LIMIT 5000",(self.evidence_id,)):
                self.error_tree.insert("","end",values=r)

    def process_queue(self) -> None:
        try:
            while True:
                item=self.ui_queue.get_nowait(); kind=item[0]
                if kind=="status": self.status_var.set(item[1])
                elif kind=="progress": self.progress_var.set(item[1])
                elif kind=="refresh": self.refresh_all(); self.update_idletasks()
                elif kind=="done": self.status_var.set(item[1]); self.refresh_all(); self.update_idletasks()
        except queue.Empty: pass
        self.after(100,self.process_queue)

    def show_detail(self,_event=None) -> None:
        sel=self.tree.selection()
        if not sel: return
        aid=int(sel[0])
        with sqlite3.connect(self.case_db) as con:
            con.row_factory=sqlite3.Row; r=con.execute("SELECT * FROM forensic_artifacts WHERE id=?",(aid,)).fetchone()
        if not r: return
        win=tk.Toplevel(self); win.title("Artifact Detail"); win.geometry("900x650")
        text=tk.Text(win,wrap="word",font=("Consolas",10)); text.pack(fill="both",expand=True)
        for k in r.keys(): text.insert("end",f"{k}:\n{r[k] or ''}\n\n")
        text.configure(state="disabled")

    def clear_results(self) -> None:
        if not messagebox.askyesno(APP_NAME,"Delete all Artifact Explorer results for the selected evidence?"): return
        with sqlite3.connect(self.case_db) as con:
            con.execute("DELETE FROM forensic_artifacts WHERE evidence_id=?",(self.evidence_id,)); con.execute("DELETE FROM artifact_parse_errors WHERE evidence_id=?",(self.evidence_id,)); con.execute("DELETE FROM artifact_scan_runs WHERE evidence_id=?",(self.evidence_id,))
        self.refresh_all()

    def export_csv(self) -> None:
        path=filedialog.asksaveasfilename(title="Export artifacts",defaultextension=".csv",filetypes=[("CSV files","*.csv")],initialfile="Artifact_Explorer_Results.csv")
        if not path: return
        with sqlite3.connect(self.case_db) as con:
            con.row_factory=sqlite3.Row; rows=con.execute("SELECT * FROM forensic_artifacts WHERE evidence_id=? ORDER BY timestamp_utc,id",(self.evidence_id,)).fetchall()
        if not rows: messagebox.showinfo(APP_NAME,"There are no artifacts to export."); return
        with open(path,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(rows[0].keys()); w.writerows([tuple(r) for r in rows])
        messagebox.showinfo(APP_NAME,f"Exported {len(rows):,} artifacts.")


def main() -> None:
    app=ArtifactExplorer(); app.mainloop()

if __name__=="__main__": main()
