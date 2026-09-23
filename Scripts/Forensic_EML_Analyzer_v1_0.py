#!/usr/bin/env python3
# FFT_TOOL
# TITLE: EML Analyzer
# ID: eml_analyzer
# CATEGORY: Plugins
# VERSION: 1.0
# DESCRIPTION: Analyze EML email files and message metadata.
# ICON: ✉
# PASS_CASE_ARGUMENTS: false

"""Portable forensic EML analyzer."""

SCRIPT_NAME = "Forensic EML Analyzer"
SCRIPT_CATEGORY = "Email Forensics"
SCRIPT_DESCRIPTION = (
    "Analyze EML files and extract Message-IDs, threading headers, recipients, "
    "attachments, domains, Received headers, and file hashes."
)
SCRIPT_AUTHOR = "Fraud Fighter Toolbox"
SCRIPT_VERSION = "1.0"

import csv
import hashlib
import html
import os
import queue
import re
import sqlite3
import sys
import threading
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

MESSAGE_ID_RE = re.compile(r"<[^<>\s]+@[^<>\s]+>")

MESSAGE_COLUMNS = [
    ("filename", "Filename", 180), ("path", "Path", 420),
    ("message_id", "Message-ID", 300), ("in_reply_to", "In-Reply-To", 260),
    ("references", "References", 400), ("subject", "Subject", 280),
    ("from_", "From", 240), ("to", "To", 280), ("cc", "CC", 220),
    ("bcc", "BCC", 180), ("date", "Date", 170),
    ("attachment_count", "Attachments", 90), ("size", "Size", 110),
    ("md5", "MD5", 260), ("sha256", "SHA-256", 470), ("status", "Status", 140),
]
INDEX_COLUMNS = [
    ("message_id", "Message-ID", 340), ("primary_count", "Primary Count", 100),
    ("reference_count", "Referenced Count", 120),
    ("total_appearances", "Total Appearances", 120), ("files", "Files", 520),
]
THREAD_COLUMNS = [
    ("thread_key", "Thread Key", 340), ("subject", "Subject", 320),
    ("message_count", "Messages", 90), ("first_date", "First Date", 170),
    ("last_date", "Last Date", 170), ("participants", "Participants", 500),
    ("files", "Files", 500),
]
ATTACH_COLUMNS = [
    ("message_file", "EML Filename", 180), ("message_id", "Message-ID", 280),
    ("attachment_name", "Attachment", 260), ("content_type", "Content Type", 180),
    ("size", "Size", 110), ("content_id", "Content-ID", 220),
    ("disposition", "Disposition", 120), ("sha256", "SHA-256", 470),
]
RECIPIENT_COLUMNS = [
    ("address", "Email Address", 300), ("display_name", "Display Name", 220),
    ("roles", "Roles", 120), ("message_count", "Messages", 100),
    ("files", "Files", 500),
]
DOMAIN_COLUMNS = [
    ("domain", "Domain", 280), ("message_count", "Messages", 100),
    ("addresses", "Addresses", 100), ("roles", "Roles", 150),
    ("files", "Files", 520),
]
RECEIVED_COLUMNS = [
    ("message_file", "EML Filename", 180), ("message_id", "Message-ID", 280),
    ("hop", "Hop", 60), ("received", "Received Header", 900),
]


def decode_mime(value):
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def normalize_ids(value):
    if not value:
        return []
    ids = MESSAGE_ID_RE.findall(str(value))
    return ids if ids else [str(value).strip()]


def parse_date(value):
    if not value:
        return "", None
    try:
        dt = parsedate_to_datetime(value)
        if dt is None:
            return decode_mime(value), None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %z"), dt.timestamp()
    except Exception:
        return decode_mime(value), None


def excel_col(n):
    name = ""
    while n:
        n, rem = divmod(n - 1, 26)
        name = chr(65 + rem) + name
    return name


def xml_escape(value):
    return html.escape(str(value), quote=False)


def write_multi_sheet_xlsx(path, sheets):
    shared, shared_map = [], {}

    def sidx(value):
        value = str(value)
        if value not in shared_map:
            shared_map[value] = len(shared)
            shared.append(value)
        return shared_map[value]

    sheet_xml, sheet_entries, rel_entries, overrides = [], [], [], []
    for num, (name, headers, rows) in enumerate(sheets, 1):
        safe_name = re.sub(r'[\[\]:*?/\\]', '_', name)[:31] or f"Sheet{num}"
        sheet_entries.append(f'<sheet name="{xml_escape(safe_name)}" sheetId="{num}" r:id="rId{num}"/>')
        rel_entries.append(
            f'<Relationship Id="rId{num}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{num}.xml"/>'
        )
        overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{num}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
        rows_xml = []
        header_cells = []
        for col_num, header in enumerate(headers, 1):
            ref = f"{excel_col(col_num)}1"
            header_cells.append(f'<c r="{ref}" t="s" s="1"><v>{sidx(header)}</v></c>')
        rows_xml.append(f'<row r="1">{"".join(header_cells)}</row>')
        for row_num, row in enumerate(rows, 2):
            cells = []
            for col_num, value in enumerate(row, 1):
                ref = f"{excel_col(col_num)}{row_num}"
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    cells.append(f'<c r="{ref}" s="2"><v>{value}</v></c>')
                else:
                    cells.append(f'<c r="{ref}" t="s" s="2"><v>{sidx(value)}</v></c>')
            rows_xml.append(f'<row r="{row_num}">{"".join(cells)}</row>')
        last_col = excel_col(max(1, len(headers)))
        last_row = max(1, len(rows) + 1)
        widths = ''.join(
            f'<col min="{i}" max="{i}" width="{min(max(len(str(h))+3, 12), 60)}" customWidth="1"/>'
            for i, h in enumerate(headers, 1)
        )
        sheet_xml.append(
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<dimension ref="A1:{last_col}{last_row}"/>'
            '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
            f'<cols>{widths}</cols><sheetData>{"".join(rows_xml)}</sheetData>'
            f'<autoFilter ref="A1:{last_col}{last_row}"/></worksheet>'
        )

    styles_id = len(sheets) + 1
    strings_id = len(sheets) + 2
    rel_entries.extend([
        f'<Relationship Id="rId{styles_id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>',
        f'<Relationship Id="rId{strings_id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>',
    ])
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        + ''.join(overrides) +
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
        '</Types>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets>{"".join(sheet_entries)}</sheets></workbook>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + ''.join(rel_entries) + '</Relationships>'
    )
    styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Calibri"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"/><right style="thin"/><top style="thin"/><bottom style="thin"/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0"/><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0"><alignment vertical="top" wrapText="1"/></xf></cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''
    shared_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{len(shared)}" uniqueCount="{len(shared)}">'
        + ''.join(f'<si><t xml:space="preserve">{xml_escape(v)}</t></si>' for v in shared)
        + '</sst>'
    )
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', content_types)
        z.writestr('_rels/.rels', root_rels)
        z.writestr('xl/workbook.xml', workbook)
        z.writestr('xl/_rels/workbook.xml.rels', workbook_rels)
        z.writestr('xl/styles.xml', styles)
        z.writestr('xl/sharedStrings.xml', shared_xml)
        for i, xml in enumerate(sheet_xml, 1):
            z.writestr(f'xl/worksheets/sheet{i}.xml', xml)


class EMLAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{SCRIPT_NAME} v{SCRIPT_VERSION}")
        self.geometry("1500x860")
        self.minsize(1050, 680)
        self.source_mode = tk.StringVar(value="folder")
        self.source_path = tk.StringVar()
        self.include_subdirs = tk.BooleanVar(value=True)
        self.hash_files = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Ready")
        self.current = tk.StringVar(value="")
        self.progress = tk.DoubleVar(value=0)
        self.messages, self.attachments, self.received_headers = [], [], []
        self.message_id_index, self.threads, self.recipients, self.domains = [], [], [], []
        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker = None
        self.sort_state = {}
        self.tables = {}
        self._build_ui()
        self.after(100, self._process_events)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self):
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", relief="sunken", anchor="w", padding=(6, 3))

        menu = tk.Menu(self)
        fm = tk.Menu(menu, tearoff=False)
        fm.add_command(label="Open EML File...", command=self._choose_file)
        fm.add_command(label="Open Folder...", command=self._choose_folder)
        fm.add_separator()
        fm.add_command(label="Export All to Excel...", command=self._export_excel)
        fm.add_command(label="Export All to SQLite...", command=self._export_sqlite)
        fm.add_command(label="Export Current Tab to CSV...", command=self._export_csv)
        fm.add_separator(); fm.add_command(label="Exit", command=self._close)
        menu.add_cascade(label="File", menu=fm)
        tm = tk.Menu(menu, tearoff=False)
        tm.add_command(label="Analyze", command=self._start, accelerator="F5")
        tm.add_command(label="Cancel", command=self._cancel, accelerator="Esc")
        tm.add_command(label="Clear Results", command=self._clear)
        menu.add_cascade(label="Tools", menu=tm)
        hm = tk.Menu(menu, tearoff=False)
        hm.add_command(label="About", command=lambda: messagebox.showinfo(
            "About", f"{SCRIPT_NAME}\nVersion {SCRIPT_VERSION}\n\nPortable EML indexing and analysis with no third-party packages.", parent=self))
        menu.add_cascade(label="Help", menu=hm)
        self.config(menu=menu)

        outer = ttk.Frame(self, padding=10); outer.pack(fill="both", expand=True)
        head = ttk.Frame(outer); head.pack(fill="x", pady=(0,8))
        ttk.Label(head, text=SCRIPT_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="Message IDs • Threads • Attachments • Domains").pack(side="right")

        src = ttk.LabelFrame(outer, text="Source", padding=8); src.pack(fill="x", pady=(0,8))
        r1 = ttk.Frame(src); r1.pack(fill="x", pady=(0,6))
        ttk.Radiobutton(r1, text="Single EML file", variable=self.source_mode, value="file", command=self._mode_changed).pack(side="left")
        ttk.Radiobutton(r1, text="Folder of EML files", variable=self.source_mode, value="folder", command=self._mode_changed).pack(side="left", padx=(15,0))
        self.sub_check = ttk.Checkbutton(r1, text="Include subdirectories", variable=self.include_subdirs); self.sub_check.pack(side="left", padx=(25,0))
        ttk.Checkbutton(r1, text="Calculate MD5 and SHA-256", variable=self.hash_files).pack(side="left", padx=(15,0))
        r2 = ttk.Frame(src); r2.pack(fill="x")
        ttk.Entry(r2, textvariable=self.source_path).pack(side="left", fill="x", expand=True)
        ttk.Button(r2, text="Browse...", command=self._browse).pack(side="left", padx=(6,0))

        controls = ttk.Frame(outer); controls.pack(fill="x", pady=(0,8))
        self.run_btn = ttk.Button(controls, text="Analyze EML Files", style="Primary.TButton", command=self._start); self.run_btn.pack(side="left")
        self.cancel_btn = ttk.Button(controls, text="Cancel", command=self._cancel, state="disabled"); self.cancel_btn.pack(side="left", padx=6)
        ttk.Button(controls, text="Clear Results", command=self._clear).pack(side="left")
        ttk.Button(controls, text="Export Current CSV", command=self._export_csv).pack(side="right")
        ttk.Button(controls, text="Export SQLite", command=self._export_sqlite).pack(side="right", padx=6)
        ttk.Button(controls, text="Export Excel", command=self._export_excel).pack(side="right")

        self.notebook = ttk.Notebook(outer); self.notebook.pack(fill="both", expand=True)
        for name, cols in [
            ("Messages", MESSAGE_COLUMNS), ("Message-ID Index", INDEX_COLUMNS),
            ("Threads", THREAD_COLUMNS), ("Attachments", ATTACH_COLUMNS),
            ("Recipients", RECIPIENT_COLUMNS), ("Domains", DOMAIN_COLUMNS),
            ("Received Headers", RECEIVED_COLUMNS),
        ]:
            self._add_tab(name, cols)
        bottom = ttk.Frame(outer); bottom.pack(fill="x", pady=(8,0))
        ttk.Progressbar(bottom, variable=self.progress, maximum=100).pack(fill="x")
        ttk.Label(bottom, textvariable=self.current).pack(fill="x", pady=(3,0))
        ttk.Label(outer, textvariable=self.status, style="Status.TLabel").pack(fill="x", pady=(4,0))
        self.bind("<F5>", lambda e: self._start()); self.bind("<Escape>", lambda e: self._cancel())
        self._mode_changed()

    def _add_tab(self, name, cols):
        frame = ttk.Frame(self.notebook); self.notebook.add(frame, text=name)
        keys = tuple(c[0] for c in cols)
        tree = ttk.Treeview(frame, columns=keys, show="headings", selectmode="extended")
        numeric = {"size","attachment_count","message_count","hop","primary_count","reference_count","total_appearances","addresses"}
        for key,label,width in cols:
            tree.heading(key, text=label, command=lambda n=name,c=key:self._sort(n,c))
            tree.column(key, width=width, minwidth=70, anchor="e" if key in numeric else "w")
        y=ttk.Scrollbar(frame,orient="vertical",command=tree.yview); x=ttk.Scrollbar(frame,orient="horizontal",command=tree.xview)
        tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        tree.grid(row=0,column=0,sticky="nsew"); y.grid(row=0,column=1,sticky="ns"); x.grid(row=1,column=0,sticky="ew")
        frame.rowconfigure(0,weight=1); frame.columnconfigure(0,weight=1)
        cm=tk.Menu(tree,tearoff=False); cm.add_command(label="Copy Selected Rows", command=lambda t=tree,c=cols:self._copy_rows(t,c))
        tree.bind("<Button-3>", lambda e,t=tree,m=cm:self._popup(e,t,m))
        self.tables[name]=(tree,cols)

    def _mode_changed(self): self.sub_check.configure(state="disabled" if self.source_mode.get()=="file" else "normal")
    def _browse(self): self._choose_file() if self.source_mode.get()=="file" else self._choose_folder()
    def _choose_file(self):
        p=filedialog.askopenfilename(parent=self,title="Select EML File",filetypes=[("EML files","*.eml"),("All files","*.*")])
        if p: self.source_mode.set("file"); self.source_path.set(p); self._mode_changed()
    def _choose_folder(self):
        p=filedialog.askdirectory(parent=self,title="Select Folder Containing EML Files")
        if p: self.source_mode.set("folder"); self.source_path.set(p); self._mode_changed()

    def _start(self):
        if self.worker and self.worker.is_alive(): return
        src=self.source_path.get().strip()
        if not src: messagebox.showinfo("Select Source","Select an EML file or folder first.",parent=self); return
        p=Path(src)
        if not p.exists(): messagebox.showerror("Source Not Found","The selected source does not exist.",parent=self); return
        settings={"source":src,"mode":self.source_mode.get(),"recursive":self.include_subdirs.get(),"hash":self.hash_files.get()}
        self.cancel_event.clear(); self.run_btn.configure(state="disabled"); self.cancel_btn.configure(state="normal")
        self.progress.set(0); self.status.set("Finding EML files..."); self.current.set("")
        self.worker=threading.Thread(target=self._worker,args=(settings,),daemon=True); self.worker.start()

    def _worker(self,s):
        try:
            source=Path(s["source"])
            if s["mode"]=="file": files=[source]
            elif s["recursive"]: files=sorted((p for p in source.rglob("*") if p.is_file() and p.suffix.lower()==".eml"),key=lambda p:str(p).lower())
            else: files=sorted((p for p in source.iterdir() if p.is_file() and p.suffix.lower()==".eml"),key=lambda p:str(p).lower())
            self.events.put(("total",len(files))); msgs=[]
            for i,p in enumerate(files,1):
                if self.cancel_event.is_set(): self.events.put(("cancelled",i-1,len(files))); return
                self.events.put(("current",str(p),i,len(files)))
                msg,atts,recv=self._parse_eml(p,s["hash"]); msgs.append(msg)
                self.events.put(("message",msg,atts,recv,i,len(files)))
            self.events.put(("derived",self._build_derived(msgs)))
            self.events.put(("complete",len(files)))
        except Exception as exc: self.events.put(("fatal",str(exc)))

    def _parse_eml(self,path,do_hash):
        r={k:"" for k,_,_ in MESSAGE_COLUMNS}
        r.update({"filename":path.name,"path":str(path.resolve()),"size":path.stat().st_size,"status":"OK","_date_ts":None,"_from":[],"_to":[],"_cc":[],"_bcc":[],"_refs":[]})
        atts=[]; recv=[]
        try:
            raw=path.read_bytes(); msg=BytesParser(policy=policy.default).parsebytes(raw)
            mids=normalize_ids(msg.get("Message-ID")); irt=normalize_ids(msg.get("In-Reply-To")); refs=normalize_ids(msg.get("References"))
            r["message_id"]=mids[0] if mids else ""; r["in_reply_to"]=" ".join(irt); r["references"]=" ".join(refs); r["_refs"]=list(dict.fromkeys(irt+refs))
            r["subject"]=decode_mime(msg.get("Subject")); r["from_"]=decode_mime(msg.get("From")); r["to"]=decode_mime(msg.get("To")); r["cc"]=decode_mime(msg.get("Cc")); r["bcc"]=decode_mime(msg.get("Bcc"))
            r["date"],r["_date_ts"]=parse_date(msg.get("Date"))
            r["_from"]=getaddresses(msg.get_all("From",[])); r["_to"]=getaddresses(msg.get_all("To",[])); r["_cc"]=getaddresses(msg.get_all("Cc",[])); r["_bcc"]=getaddresses(msg.get_all("Bcc",[]))
            for hop,h in enumerate(msg.get_all("Received",[]),1): recv.append({"message_file":path.name,"message_id":r["message_id"],"hop":hop,"received":decode_mime(h)})
            for part in msg.walk():
                if part.is_multipart(): continue
                fn=part.get_filename(); disp=part.get_content_disposition() or ""
                if fn or disp=="attachment":
                    fn=decode_mime(fn) or "unnamed_attachment.bin"
                    try: payload=part.get_payload(decode=True) or b""
                    except Exception: payload=b""
                    atts.append({"message_file":path.name,"message_id":r["message_id"],"attachment_name":fn,"content_type":part.get_content_type(),"size":len(payload),"content_id":decode_mime(part.get("Content-ID")),"disposition":disp,"sha256":hashlib.sha256(payload).hexdigest() if payload else ""})
            r["attachment_count"]=len(atts)
            if do_hash: r["md5"]=hashlib.md5(raw).hexdigest(); r["sha256"]=hashlib.sha256(raw).hexdigest()
        except Exception as exc: r["status"]=f"Error: {exc}"
        return r,atts,recv

    def _build_derived(self,msgs):
        primary=defaultdict(list); referenced=defaultdict(list); parent={}
        for m in msgs:
            mid=m.get("message_id","")
            if mid: primary[mid].append(m["filename"])
            if mid and m.get("_refs"): parent[mid]=m["_refs"][-1]
            for rid in m.get("_refs",[]): referenced[rid].append(m["filename"])
        idx=[]
        for mid in sorted(set(primary)|set(referenced),key=str.lower):
            files=sorted(set(primary[mid]+referenced[mid])); idx.append({"message_id":mid,"primary_count":len(primary[mid]),"reference_count":len(referenced[mid]),"total_appearances":len(primary[mid])+len(referenced[mid]),"files":"; ".join(files)})
        def root(m):
            mid=m.get("message_id")
            if mid:
                seen=set(); cur=mid
                while cur in parent and cur not in seen: seen.add(cur); cur=parent[cur]
                return cur
            subj=re.sub(r"^\s*((re|fw|fwd)\s*:\s*)+","",m.get("subject",""),flags=re.I).strip().lower()
            return f"subject:{subj}" if subj else f"file:{m['filename']}"
        groups=defaultdict(list)
        for m in msgs: groups[root(m)].append(m)
        threads=[]
        for key,g in groups.items():
            ordered=sorted(g,key=lambda m:(m.get("_date_ts") is None,m.get("_date_ts") or 0)); parts=set()
            for m in g:
                for field in ("_from","_to","_cc","_bcc"):
                    for _,addr in m.get(field,[]):
                        if addr: parts.add(addr.lower())
            threads.append({"thread_key":key,"subject":ordered[0].get("subject","") if ordered else "","message_count":len(g),"first_date":ordered[0].get("date","") if ordered else "","last_date":ordered[-1].get("date","") if ordered else "","participants":"; ".join(sorted(parts)),"files":"; ".join(m["filename"] for m in ordered)})
        threads.sort(key=lambda r:(-r["message_count"],r["thread_key"].lower()))
        rinfo={}; dinfo={}; rolemap={"_from":"From","_to":"To","_cc":"CC","_bcc":"BCC"}
        for m in msgs:
            for field,role in rolemap.items():
                for name,addr in m.get(field,[]):
                    addr=addr.strip().lower()
                    if not addr: continue
                    info=rinfo.setdefault(addr,{"names":set(),"roles":set(),"files":set()})
                    if name: info["names"].add(decode_mime(name))
                    info["roles"].add(role); info["files"].add(m["filename"])
                    if "@" in addr:
                        dom=addr.rsplit("@",1)[1]; di=dinfo.setdefault(dom,{"addresses":set(),"roles":set(),"files":set()})
                        di["addresses"].add(addr); di["roles"].add(role); di["files"].add(m["filename"])
        rec=[{"address":a,"display_name":"; ".join(sorted(i["names"])),"roles":", ".join(sorted(i["roles"])),"message_count":len(i["files"]),"files":"; ".join(sorted(i["files"]))} for a,i in rinfo.items()]
        rec.sort(key=lambda r:(-r["message_count"],r["address"]))
        dom=[{"domain":d,"message_count":len(i["files"]),"addresses":len(i["addresses"]),"roles":", ".join(sorted(i["roles"])),"files":"; ".join(sorted(i["files"]))} for d,i in dinfo.items()]
        dom.sort(key=lambda r:(-r["message_count"],r["domain"]))
        return idx,threads,rec,dom

    def _process_events(self):
        try:
            while True:
                e=self.events.get_nowait(); kind=e[0]
                if kind=="total":
                    self.status.set(f"Found {e[1]:,} EML file(s).")
                    if e[1]==0: self._finish("No EML files found.")
                elif kind=="current":
                    path,i,total=e[1:]; self.current.set(f"{i:,} of {total:,}: {path}"); self.progress.set((i-1)/total*100 if total else 0)
                elif kind=="message":
                    m,atts,recv,i,total=e[1:]; self.messages.append(m); self.attachments.extend(atts); self.received_headers.extend(recv)
                    self._insert("Messages",m)
                    for r in atts:self._insert("Attachments",r)
                    for r in recv:self._insert("Received Headers",r)
                    self.progress.set(i/total*100 if total else 0); self.status.set(f"Parsed {i:,} of {total:,} EML file(s).")
                elif kind=="derived":
                    self.message_id_index,self.threads,self.recipients,self.domains=e[1]
                    for tab,rows in [("Message-ID Index",self.message_id_index),("Threads",self.threads),("Recipients",self.recipients),("Domains",self.domains)]:
                        self._clear_table(tab)
                        for r in rows:self._insert(tab,r)
                elif kind=="complete": self.progress.set(100); self._finish(f"Complete. Parsed {e[1]:,} EML file(s); {len(self.message_id_index):,} Message-ID entries; {len(self.attachments):,} attachment(s).")
                elif kind=="cancelled": self._finish(f"Cancelled after {e[1]:,} of {e[2]:,} file(s).")
                elif kind=="fatal": self._finish(f"Error: {e[1]}"); messagebox.showerror("Analysis Error",e[1],parent=self)
        except queue.Empty: pass
        self.after(100,self._process_events)

    def _insert(self,tab,row):
        tree,cols=self.tables[tab]; tree.insert("","end",values=tuple(row.get(k,"") for k,_,_ in cols))
    def _clear_table(self,tab):
        tree,_=self.tables[tab]
        for item in tree.get_children(): tree.delete(item)
    def _finish(self,text): self.run_btn.configure(state="normal"); self.cancel_btn.configure(state="disabled"); self.current.set(""); self.status.set(text)
    def _cancel(self):
        if self.worker and self.worker.is_alive(): self.cancel_event.set(); self.status.set("Cancelling...")
    def _clear(self):
        if self.worker and self.worker.is_alive(): messagebox.showinfo("Analysis Running","Cancel the analysis before clearing.",parent=self); return
        self.messages.clear(); self.attachments.clear(); self.received_headers.clear(); self.message_id_index.clear(); self.threads.clear(); self.recipients.clear(); self.domains.clear()
        for tab in self.tables:self._clear_table(tab)
        self.progress.set(0); self.status.set("Results cleared.")
    def _sort(self,tab,col):
        tree,_=self.tables[tab]; rev=self.sort_state.get((tab,col),False); numeric={"size","attachment_count","message_count","hop","primary_count","reference_count","total_appearances","addresses"}
        def key(item):
            v=tree.set(item,col)
            if col in numeric:
                try:return int(v)
                except:return 0
            return v.lower()
        items=list(tree.get_children("")); items.sort(key=key,reverse=rev)
        for i,item in enumerate(items):tree.move(item,"",i)
        self.sort_state[(tab,col)]=not rev
    def _popup(self,e,tree,menu):
        row=tree.identify_row(e.y)
        if row and row not in tree.selection():tree.selection_set(row)
        menu.tk_popup(e.x_root,e.y_root)
    def _copy_rows(self,tree,cols):
        sel=tree.selection()
        if not sel:return
        lines=["\t".join(label for _,label,_ in cols)]+["\t".join(map(str,tree.item(i,"values"))) for i in sel]
        self.clipboard_clear(); self.clipboard_append("\n".join(lines)); self.status.set(f"Copied {len(sel):,} row(s).")
    def _current_data(self):
        tab=self.notebook.tab(self.notebook.select(),"text"); mapping={"Messages":self.messages,"Message-ID Index":self.message_id_index,"Threads":self.threads,"Attachments":self.attachments,"Recipients":self.recipients,"Domains":self.domains,"Received Headers":self.received_headers}
        return tab,self.tables[tab][1],mapping[tab]
    def _export_csv(self):
        tab,cols,rows=self._current_data()
        if not rows:messagebox.showinfo("Export CSV","The current tab has no data.",parent=self);return
        p=filedialog.asksaveasfilename(parent=self,title=f"Export {tab} to CSV",defaultextension=".csv",initialfile=tab.replace(" ","_").replace("-","_")+".csv",filetypes=[("CSV file","*.csv"),("All files","*.*")])
        if not p:return
        try:
            with open(p,"w",newline="",encoding="utf-8-sig") as f:
                w=csv.writer(f);w.writerow([label for _,label,_ in cols]);w.writerows([[r.get(k,"") for k,_,_ in cols] for r in rows])
            self.status.set(f"CSV exported to {p}")
        except Exception as exc:messagebox.showerror("CSV Export Error",str(exc),parent=self)
    def _datasets(self):
        return [("Messages",MESSAGE_COLUMNS,self.messages),("Message-ID Index",INDEX_COLUMNS,self.message_id_index),("Threads",THREAD_COLUMNS,self.threads),("Attachments",ATTACH_COLUMNS,self.attachments),("Recipients",RECIPIENT_COLUMNS,self.recipients),("Domains",DOMAIN_COLUMNS,self.domains),("Received Headers",RECEIVED_COLUMNS,self.received_headers)]
    def _export_excel(self):
        if not self.messages:messagebox.showinfo("Export Excel","There are no analysis results.",parent=self);return
        p=filedialog.asksaveasfilename(parent=self,title="Export Analysis to Excel",defaultextension=".xlsx",initialfile="Forensic_EML_Analysis.xlsx",filetypes=[("Excel workbook","*.xlsx"),("All files","*.*")])
        if not p:return
        try:
            sheets=[(n,[label for _,label,_ in c],[[r.get(k,"") for k,_,_ in c] for r in rows]) for n,c,rows in self._datasets()]
            write_multi_sheet_xlsx(p,sheets);self.status.set(f"Excel workbook exported to {p}")
        except Exception as exc:messagebox.showerror("Excel Export Error",str(exc),parent=self)
    def _export_sqlite(self):
        if not self.messages:messagebox.showinfo("Export SQLite","There are no analysis results.",parent=self);return
        p=filedialog.asksaveasfilename(parent=self,title="Export Analysis to SQLite",defaultextension=".sqlite",initialfile="Forensic_EML_Analysis.sqlite",filetypes=[("SQLite database","*.sqlite"),("All files","*.*")])
        if not p:return
        try:
            conn=sqlite3.connect(p);cur=conn.cursor(); numeric={"size","attachment_count","message_count","hop","primary_count","reference_count","total_appearances","addresses"}
            for name,cols,rows in self._datasets():
                table=name.lower().replace("-","_").replace(" ","_");cur.execute(f'DROP TABLE IF EXISTS "{table}"')
                definitions = []
                for k, _, _ in cols:
                    col_type = "INTEGER" if k in numeric else "TEXT"
                    definitions.append(f'"{k}" {col_type}')
                cur.execute(f'CREATE TABLE "{table}" ({", ".join(definitions)})')
                if rows:
                    keys=[k for k,_,_ in cols]
                    quoted_keys = ",".join(f'"{k}"' for k in keys)
                    placeholders = ",".join("?" for _ in keys)
                    cur.executemany(
                        f'INSERT INTO "{table}" ({quoted_keys}) VALUES ({placeholders})',
                        [[r.get(k,"") for k in keys] for r in rows]
                    )
            conn.commit();conn.close();self.status.set(f"SQLite database exported to {p}")
        except Exception as exc:messagebox.showerror("SQLite Export Error",str(exc),parent=self)
    def _close(self):
        if self.worker and self.worker.is_alive() and not messagebox.askyesno("Analysis Running","Cancel the analysis and exit?",parent=self):return
        self.cancel_event.set();self.destroy()


def main():
    EMLAnalyzer().mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
