#!/usr/bin/env python3
"""Portable forensic encoding and timestamp conversion GUI."""

# FFT_TOOL
# TITLE: Encoder / Decoder
# ID: Encoder / Decoder
# CATEGORY: Plugins
# VERSION: 1.0
# DESCRIPTION: Analyze EML email files and message metadata.
# ICON: 🔐
# PASS_CASE_ARGUMENTS: false

SCRIPT_NAME = "Forensic Encoding Converter"
SCRIPT_CATEGORY = "Utilities"
SCRIPT_DESCRIPTION = (
    "Convert text, ASCII, UTF, hexadecimal, decimal, binary, octal, Base64, "
    "URL encoding, HTML entities, ROT13, hashes, timestamps, GUIDs, and SIDs."
)
SCRIPT_AUTHOR = "Fraud Fighter Toolbox"
SCRIPT_VERSION = "1.3"

import base64, codecs, hashlib, html, json, os, re, struct, urllib.parse, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
    BaseTk = TkinterDnD.Tk
except ImportError:
    DND_FILES = None
    DND_AVAILABLE = False
    BaseTk = tk.Tk

TEXT_CODECS = {
    "ASCII": "ascii", "UTF-8": "utf-8", "UTF-16 LE": "utf-16-le",
    "UTF-16 BE": "utf-16-be", "UTF-32 LE": "utf-32-le",
    "UTF-32 BE": "utf-32-be",
}
TIMESTAMPS = [
    "Windows FILETIME", "Unix Epoch", "Unix Epoch Milliseconds",
    "Chrome/WebKit Timestamp", "Firefox Timestamp", "Cocoa Timestamp",
]
INPUTS = [
    "Auto Detect", "Plain Text", *TEXT_CODECS, "Hexadecimal",
    "Hexadecimal (0x prefixed)", "Decimal Bytes", "Binary Bytes",
    "Octal Bytes", "Base64", "Base64 URL Safe", "URL Encoding",
    "HTML Entities", "ROT13", *TIMESTAMPS, "GUID",
    "Windows SID (binary hex)", "Raw Hex Dump", "C Byte Array",
    "Python Bytes", "PowerShell Byte Array", "VB.NET Byte Array",
    "Java Byte Array",
]
OUTPUTS = [
    "Plain Text", *TEXT_CODECS, "Hexadecimal", "Hexadecimal (0x prefixed)",
    "Decimal Bytes", "Binary Bytes", "Octal Bytes", "Base64",
    "Base64 URL Safe", "URL Encoding", "HTML Entities", "ROT13",
    *TIMESTAMPS, "GUID", "Windows SID (binary hex)",
    "MD5", "SHA-1", "SHA-256", "SHA-512",
]

def clean_hex(s):
    s = re.sub(r"(?i)0x|\\x", "", s)
    s = re.sub(r"[^0-9a-fA-F]", "", s)
    return ("0" + s) if len(s) % 2 else s

def best_text(data):
    for enc in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
        try:
            text = data.decode(enc)
            good = sum(c.isprintable() or c in "\r\n\t" for c in text)
            if text and good / len(text) > .8:
                return text
        except UnicodeError:
            pass
    return data.decode("latin-1", errors="replace")

def parse_numbers(s, base):
    vals = [int(x, base) for x in re.findall(r"[0-9A-Fa-f]+", s)]
    if any(v > 255 for v in vals):
        raise ValueError("Each byte value must be between 0 and 255.")
    return bytes(vals)

def parse_dt(s):
    s = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S",
                    "%Y-%m-%d", "%m/%d/%Y"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            raise ValueError("Use ISO format or YYYY-MM-DD HH:MM:SS.")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def ts_to_dt(value, kind):
    n = int(str(value).strip(), 0)
    if kind == "Windows FILETIME":
        return datetime(1601,1,1,tzinfo=timezone.utc) + timedelta(microseconds=n/10)
    if kind == "Unix Epoch":
        return datetime.fromtimestamp(n, timezone.utc)
    if kind == "Unix Epoch Milliseconds":
        return datetime.fromtimestamp(n/1000, timezone.utc)
    if kind == "Chrome/WebKit Timestamp":
        return datetime(1601,1,1,tzinfo=timezone.utc) + timedelta(microseconds=n)
    if kind == "Firefox Timestamp":
        return datetime.fromtimestamp(n/1_000_000, timezone.utc)
    if kind == "Cocoa Timestamp":
        return datetime(2001,1,1,tzinfo=timezone.utc) + timedelta(seconds=n)

def dt_to_ts(dt, kind):
    if kind == "Windows FILETIME":
        return int((dt-datetime(1601,1,1,tzinfo=timezone.utc)).total_seconds()*10_000_000)
    if kind == "Unix Epoch":
        return int(dt.timestamp())
    if kind == "Unix Epoch Milliseconds":
        return int(dt.timestamp()*1000)
    if kind == "Chrome/WebKit Timestamp":
        return int((dt-datetime(1601,1,1,tzinfo=timezone.utc)).total_seconds()*1_000_000)
    if kind == "Firefox Timestamp":
        return int(dt.timestamp()*1_000_000)
    if kind == "Cocoa Timestamp":
        return int((dt-datetime(2001,1,1,tzinfo=timezone.utc)).total_seconds())

def sid_from_bytes(data):
    if len(data) < 8:
        raise ValueError("SID data is too short.")
    count = data[1]
    if len(data) < 8 + count*4:
        raise ValueError("SID data is incomplete.")
    authority = int.from_bytes(data[2:8], "big")
    subs = [struct.unpack("<I", data[8+i*4:12+i*4])[0] for i in range(count)]
    return "S-" + "-".join(map(str, [data[0], authority, *subs]))

def sid_to_bytes(s):
    p = s.strip().split("-")
    if len(p) < 3 or p[0].upper() != "S":
        raise ValueError("SID must use S-1-... format.")
    rev, auth = int(p[1]), int(p[2])
    subs = [int(x) for x in p[3:]]
    return bytes([rev, len(subs)]) + auth.to_bytes(6,"big") + b"".join(struct.pack("<I",x) for x in subs)

def decode_value(value, kind):
    if kind in ("Plain Text", "ASCII", "UTF-8"):
        return value.encode(TEXT_CODECS.get(kind, "utf-8")), None
    if kind in TEXT_CODECS:
        return value.encode(TEXT_CODECS[kind]), None
    if kind.startswith("Hexadecimal"):
        return bytes.fromhex(clean_hex(value)), None
    if kind == "Decimal Bytes":
        return parse_numbers(value, 10), None
    if kind == "Octal Bytes":
        return parse_numbers(value, 8), None
    if kind == "Binary Bytes":
        bits = re.sub(r"[^01]", "", value)
        if len(bits) % 8:
            bits = bits.zfill((len(bits)+7)//8*8)
        return bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)), None
    if kind == "Base64":
        s = re.sub(r"\s+","",value); s += "="*((4-len(s)%4)%4)
        return base64.b64decode(s), None
    if kind == "Base64 URL Safe":
        s = re.sub(r"\s+","",value); s += "="*((4-len(s)%4)%4)
        return base64.urlsafe_b64decode(s), None
    if kind == "URL Encoding":
        return urllib.parse.unquote_to_bytes(value), None
    if kind == "HTML Entities":
        return html.unescape(value).encode(), None
    if kind == "ROT13":
        return codecs.decode(value, "rot_13").encode(), None
    if kind in TIMESTAMPS:
        dt = ts_to_dt(value, kind)
        return dt.isoformat().encode(), dt
    if kind == "GUID":
        g = uuid.UUID(value.strip())
        return g.bytes_le, g
    if kind == "Windows SID (binary hex)":
        sid = sid_from_bytes(bytes.fromhex(clean_hex(value)))
        return sid.encode(), sid
    raise ValueError("Unsupported input encoding.")

def encode_value(data, kind, context=None):
    if kind == "Plain Text":
        return best_text(data)
    if kind in TEXT_CODECS:
        text = best_text(data)
        encoded = text.encode(TEXT_CODECS[kind])
        return encoded.decode(TEXT_CODECS[kind]) if kind in ("ASCII","UTF-8") else " ".join(f"{b:02X}" for b in encoded)
    if kind == "Hexadecimal":
        return " ".join(f"{b:02X}" for b in data)
    if kind == "Hexadecimal (0x prefixed)":
        return " ".join(f"0x{b:02X}" for b in data)
    if kind == "Decimal Bytes":
        return " ".join(map(str, data))
    if kind == "Binary Bytes":
        return " ".join(f"{b:08b}" for b in data)
    if kind == "Octal Bytes":
        return " ".join(f"{b:03o}" for b in data)
    if kind == "Base64":
        return base64.b64encode(data).decode()
    if kind == "Base64 URL Safe":
        return base64.urlsafe_b64encode(data).decode()
    if kind == "URL Encoding":
        return urllib.parse.quote_from_bytes(data)
    if kind == "HTML Entities":
        return html.escape(best_text(data))
    if kind == "ROT13":
        return codecs.encode(best_text(data), "rot_13")
    if kind in TIMESTAMPS:
        dt = context if isinstance(context, datetime) else parse_dt(best_text(data))
        return str(dt_to_ts(dt, kind))
    if kind == "GUID":
        return str(uuid.UUID(bytes_le=data)) if len(data)==16 else str(uuid.UUID(best_text(data).strip()))
    if kind == "Windows SID (binary hex)":
        return " ".join(f"{b:02X}" for b in sid_to_bytes(best_text(data).strip()))
    if kind == "Raw Hex Dump":
        return raw_hex_dump(data)
    if kind in ("C Byte Array", "Python Bytes", "PowerShell Byte Array", "VB.NET Byte Array", "Java Byte Array"):
        return byte_array_text(data, kind)
    alg = {"MD5":"md5","SHA-1":"sha1","SHA-256":"sha256","SHA-512":"sha512"}.get(kind)
    if alg:
        return hashlib.new(alg, data).hexdigest()
    raise ValueError("Unsupported output encoding.")

def raw_hex_dump(data, width=16):
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset+width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08X}  {hex_part:<{width*3-1}}  |{ascii_part}|")
    return "\n".join(lines)

def detect_file_type(data):
    signatures = [
        (b"MZ", "Windows PE executable (EXE/DLL/SYS)"),
        (b"PK\\x03\\x04", "ZIP archive / Office Open XML document"),
        (b"PK\\x05\\x06", "Empty ZIP archive"),
        (b"%PDF-", "PDF document"),
        (b"\\x89PNG\\r\\n\\x1a\\n", "PNG image"),
        (b"\\xff\\xd8\\xff", "JPEG image"),
        (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"),
        (b"SQLite format 3\\x00", "SQLite database"),
        (b"regf", "Windows Registry hive"),
        (b"ElfFile\\x00", "Windows Event Log EVTX"),
        (b"L\\x00\\x00\\x00", "Windows shortcut (LNK), probable"),
        (b"\\x7fELF", "ELF executable"),
        (b"\\x1f\\x8b", "GZIP archive"),
        (b"BZh", "BZIP2 archive"),
        (b"7z\\xbc\\xaf'\\x1c", "7-Zip archive"),
        (b"Rar!\\x1a\\x07", "RAR archive"),
        (b"MSCF", "Microsoft Cabinet archive"),
        (b"\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1", "OLE Compound File / legacy Office document"),
        (b"{\\rtf", "RTF document"),
        (b"ID3", "MP3 audio with ID3 tag"),
        (b"fLaC", "FLAC audio"),
        (b"OggS", "Ogg container"),
    ]
    for sig, name in signatures:
        if data.startswith(sig):
            return name
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "ISO Base Media (MP4/MOV/HEIC family)"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "TAR archive"
    return "Unknown / no recognized signature"

def byte_array_text(data, kind):
    if kind == "C Byte Array":
        vals = ", ".join(f"0x{b:02X}" for b in data)
        return f"unsigned char data[{len(data)}] = {{\n    {vals}\n}};"
    if kind == "Python Bytes":
        body = "".join(f"\\x{b:02x}" for b in data)
        return f"data = b\"{body}\""
    if kind == "PowerShell Byte Array":
        return "[byte[]]$data = " + ", ".join(f"0x{b:02X}" for b in data)
    if kind == "VB.NET Byte Array":
        return "Dim data As Byte() = {" + ", ".join(f"&H{b:02X}" for b in data) + "}"
    if kind == "Java Byte Array":
        vals = ", ".join(f"(byte)0x{b:02X}" for b in data)
        return f"byte[] data = new byte[] {{ {vals} }};"
    raise ValueError("Unsupported byte-array output.")

def detect(value):
    out = []
    def add(label, result, confidence="Possible"):
        key = (label, str(result))
        if key not in {(x[1],x[2]) for x in out}:
            out.append((confidence, label, str(result)[:5000]))
    text = value.strip()
    hx = clean_hex(text)
    if hx and re.fullmatch(r"(?i)[0-9a-fx\\\s,:-]+", text):
        try:
            data = bytes.fromhex(hx)
            add("Hexadecimal → Text", best_text(data), "Likely")
            add("Hexadecimal → Decimal Bytes", " ".join(map(str,data)))
            if len(data)==16: add("Hexadecimal → GUID", uuid.UUID(bytes_le=data))
            try: add("Hexadecimal → Windows SID", sid_from_bytes(data))
            except Exception: pass
        except Exception: pass
    compact = re.sub(r"\s+","",text)
    if len(compact)>=4 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        for label, fn in (("Base64 → Text",base64.b64decode),
                          ("Base64 URL Safe → Text",base64.urlsafe_b64decode)):
            try:
                s=compact+"="*((4-len(compact)%4)%4)
                add(label,best_text(fn(s)),"Likely")
            except Exception: pass
    bits=re.sub(r"[^01]","",text)
    if bits and len(bits)%8==0 and re.fullmatch(r"[01\s]+",text):
        try: add("Binary → Text",best_text(bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))),"Likely")
        except Exception: pass
    if "%" in text:
        u=urllib.parse.unquote(text)
        if u!=text: add("URL Encoding → Text",u,"Likely")
    if "&" in text and ";" in text:
        h=html.unescape(text)
        if h!=text: add("HTML Entities → Text",h,"Likely")
    if re.fullmatch(r"\d{9,20}",text):
        for kind in TIMESTAMPS:
            try:
                dt=ts_to_dt(text,kind)
                if 1970<=dt.year<=2200: add(f"{kind} → UTC",dt.isoformat(),"Likely")
            except Exception: pass
    try: add("GUID → Little-endian Hex"," ".join(f"{b:02X}" for b in uuid.UUID(text).bytes_le),"Likely")
    except Exception: pass
    if re.fullmatch(r"S-\d+(?:-\d+)+",text,re.I):
        try: add("SID → Binary Hex"," ".join(f"{b:02X}" for b in sid_to_bytes(text)),"Likely")
        except Exception: pass
    add("UTF-8 → Hexadecimal"," ".join(f"{b:02X}" for b in text.encode()))
    add("UTF-8 → Base64",base64.b64encode(text.encode()).decode())
    return sorted(out,key=lambda x:0 if x[0]=="Likely" else 1)

class App(BaseTk):
    def __init__(self):
        super().__init__()
        self.title(f"{SCRIPT_NAME} v{SCRIPT_VERSION}")
        self.geometry("1100x740"); self.minsize(850,600)
        self.live=tk.BooleanVar(value=False); self.status=tk.StringVar(value="Ready")
        self.word_wrap=tk.BooleanVar(value=True)
        self.show_auto_detect_tab=tk.BooleanVar(value=True)
        self.show_byte_inspector_tab=tk.BooleanVar(value=True)
        self.text_stats=tk.StringVar(value="Characters: 0   Bytes: 0   Lines: 1   Cursor: 1:0   Selected: 0")
        self.detect_map={}; self.history=[]
        self.last_data = b""
        self.file_type = tk.StringVar(value="File signature: No decoded data")
        self.context_widget = None
        self.create_menu()
        self.make_ui()
        self.bind("<F5>",lambda e:self.convert())
        self.bind("<F6>",lambda e:self.auto_detect())
        self.bind_all("<Shift-F10>", self.show_context_menu_keyboard, add="+")
        self.bind_all("<KeyPress-Menu>", self.show_context_menu_keyboard, add="+")
        self.setup_drag_and_drop()


    def create_menu(self):
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Open File...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save Output...", command=self.save, accelerator="Ctrl+S")
        file_menu.add_command(label="Save Raw Decoded Bytes...", command=self.save_raw, accelerator="Ctrl+Shift+S")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menu.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menu, tearoff=False)
        view_menu.add_checkbutton(label="Word Wrap", variable=self.word_wrap, command=self.apply_word_wrap)
        view_menu.add_separator()
        view_menu.add_checkbutton(label="Show Auto Detect Tab", variable=self.show_auto_detect_tab, command=self.update_optional_tabs)
        view_menu.add_checkbutton(label="Show Byte Inspector Tab", variable=self.show_byte_inspector_tab, command=self.update_optional_tabs)
        menu.add_cascade(label="View", menu=view_menu)

        tools_menu = tk.Menu(menu, tearoff=False)
        tools_menu.add_command(label="Convert", command=self.convert, accelerator="F5")
        tools_menu.add_command(label="Auto Detect", command=self.auto_detect, accelerator="F6")
        tools_menu.add_command(label="Swap Encodings", command=self.swap)
        tools_menu.add_separator()
        tools_menu.add_command(label="Show Raw Hex Dump", command=self.show_raw_dump)
        tools_menu.add_command(label="Save Raw Decoded Bytes...", command=self.save_raw)
        menu.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menu)

    def make_ui(self):
        root=ttk.Frame(self,padding=10); root.pack(fill="both",expand=True)
        top=ttk.Frame(root); top.pack(fill="x",pady=(0,8))
        ttk.Label(top,text=SCRIPT_NAME,font=("Segoe UI",15,"bold")).pack(side="left")
        ttk.Checkbutton(top,text="Byte Inspector",variable=self.show_byte_inspector_tab,command=self.update_optional_tabs).pack(side="right",padx=(8,0))
        ttk.Checkbutton(top,text="Auto Detect",variable=self.show_auto_detect_tab,command=self.update_optional_tabs).pack(side="right",padx=(8,0))
        ttk.Checkbutton(top,text="Word wrap",variable=self.word_wrap,command=self.apply_word_wrap).pack(side="right",padx=(8,0))
        ttk.Checkbutton(top,text="Live conversion",variable=self.live).pack(side="right")
        bar=ttk.LabelFrame(root,text="Conversion",padding=8); bar.pack(fill="x")
        self.in_kind=ttk.Combobox(bar,values=INPUTS,state="readonly"); self.in_kind.set("Plain Text")
        self.out_kind=ttk.Combobox(bar,values=OUTPUTS,state="readonly"); self.out_kind.set("Hexadecimal")
        ttk.Label(bar,text="Input encoding").grid(row=0,column=0,sticky="w")
        ttk.Label(bar,text="Output encoding").grid(row=0,column=2,sticky="w")
        self.in_kind.grid(row=1,column=0,sticky="ew",padx=(0,8))
        ttk.Button(bar,text="⇄ Swap",command=self.swap).grid(row=1,column=1,padx=4)
        self.out_kind.grid(row=1,column=2,sticky="ew",padx=(8,0))
        bar.columnconfigure(0,weight=1); bar.columnconfigure(2,weight=1)
        self.main_pane=ttk.Panedwindow(root,orient="horizontal"); self.main_pane.pack(fill="both",expand=True,pady=8)
        left=ttk.Frame(self.main_pane); right=ttk.Frame(self.main_pane); self.main_pane.add(left,weight=1); self.main_pane.add(right,weight=1)
        ttk.Label(left,text="Input",font=("Segoe UI",10,"bold")).pack(anchor="w")
        self.input=tk.Text(left,wrap="word",font=("Consolas",10),undo=True); self.input.pack(fill="both",expand=True,pady=4)
        self.input.bind("<<Modified>>",self.changed)
        self.add_text_context_menu(self.input, editable=True)
        row=ttk.Frame(left); row.pack(fill="x")
        ttk.Button(row,text="Convert",command=self.convert).pack(side="left")
        ttk.Button(row,text="Auto Detect",command=self.auto_detect).pack(side="left",padx=5)
        ttk.Button(row,text="Open File",command=self.open_file).pack(side="left")
        ttk.Button(row,text="Clear",command=self.clear).pack(side="left",padx=5)
        nb=ttk.Notebook(right); nb.pack(fill="both",expand=True)
        tab1=ttk.Frame(nb); tab2=ttk.Frame(nb); tab3=ttk.Frame(nb)
        nb.add(tab1,text="Converted"); nb.add(tab2,text="Auto Detect"); nb.add(tab3,text="Byte Inspector")
        self.nb=nb; self.converted_tab=tab1; self.auto_detect_tab=tab2; self.byte_inspector_tab=tab3
        self.output=tk.Text(tab1,wrap="word",font=("Consolas",10),undo=True); self.output.pack(fill="both",expand=True)
        self.add_text_context_menu(self.output, editable=True)
        orow=ttk.Frame(tab1); orow.pack(fill="x")
        ttk.Button(orow,text="Copy",command=self.copy).pack(side="left")
        ttk.Button(orow,text="Save Text",command=self.save).pack(side="left",padx=5)
        ttk.Button(orow,text="Save Raw Bytes",command=self.save_raw).pack(side="left")
        ttk.Button(orow,text="Raw Hex Dump",command=self.show_raw_dump).pack(side="left",padx=5)
        ttk.Label(tab1,textvariable=self.file_type,anchor="w",relief="groove",padding=(5,3)).pack(fill="x",pady=(4,0))
        self.detect_pane=ttk.Panedwindow(tab2,orient="vertical"); self.detect_pane.pack(fill="both",expand=True)
        detect_list_frame=ttk.Frame(self.detect_pane); detect_result_frame=ttk.Frame(self.detect_pane)
        self.detect_pane.add(detect_list_frame,weight=1); self.detect_pane.add(detect_result_frame,weight=2)
        self.tree=ttk.Treeview(detect_list_frame,columns=("confidence","type"),show="headings")
        self.tree.heading("confidence",text="Confidence"); self.tree.heading("type",text="Interpretation")
        self.tree.column("confidence",width=85,stretch=False); self.tree.pack(fill="both",expand=True)
        self.tree.bind("<<TreeviewSelect>>",self.show_detect)
        self.tree.bind("<Double-1>",self.use_detected_interpretation)
        self.detect_text=tk.Text(detect_result_frame,wrap="word",font=("Consolas",10),undo=True); self.detect_text.pack(fill="both",expand=True)
        self.add_text_context_menu(self.detect_text, editable=True)
        self.bytes=ttk.Treeview(tab3,columns=("off","hex","dec","bin","ascii"),show="headings")
        for k,t,w in (("off","Offset",90),("hex","Hex",60),("dec","Decimal",70),("bin","Binary",95),("ascii","ASCII",60)):
            self.bytes.heading(k,text=t); self.bytes.column(k,width=w,anchor="center")
        self.bytes.pack(fill="both",expand=True)
        status_frame=ttk.Frame(root)
        status_frame.pack(fill="x")
        ttk.Label(status_frame,textvariable=self.status,relief="sunken",anchor="w").pack(side="left",fill="x",expand=True)
        ttk.Label(status_frame,textvariable=self.text_stats,relief="sunken",anchor="e",padding=(6,0)).pack(side="right")
        for widget in (self.input,self.output,self.detect_text):
            widget.bind("<KeyRelease>",self.update_text_stats,add="+")
            widget.bind("<ButtonRelease-1>",self.update_text_stats,add="+")
            widget.bind("<<Selection>>",self.update_text_stats,add="+")
            widget.bind("<FocusIn>",self.update_text_stats,add="+")
        self.bind("<Control-o>",lambda e:self.open_file())
        self.bind("<Control-s>",lambda e:self.save())
        self.bind("<Control-Shift-S>",lambda e:self.save_raw())
        self.apply_word_wrap()
        self.update_text_stats()



    def apply_word_wrap(self):
        mode = "word" if self.word_wrap.get() else "none"
        for widget in (getattr(self,"input",None),getattr(self,"output",None),getattr(self,"detect_text",None)):
            if widget is not None:
                widget.configure(wrap=mode)
        self.status.set("Word wrap enabled." if mode == "word" else "Word wrap disabled.")

    def update_optional_tabs(self):
        tabs = set(self.nb.tabs())
        auto_id = str(self.auto_detect_tab)
        byte_id = str(self.byte_inspector_tab)
        if self.show_auto_detect_tab.get() and auto_id not in tabs:
            self.nb.add(self.auto_detect_tab, text="Auto Detect")
        elif not self.show_auto_detect_tab.get() and auto_id in tabs:
            if self.nb.select() == auto_id:
                self.nb.select(self.converted_tab)
            self.nb.hide(self.auto_detect_tab)
        tabs = set(self.nb.tabs())
        if self.show_byte_inspector_tab.get() and byte_id not in tabs:
            self.nb.add(self.byte_inspector_tab, text="Byte Inspector")
        elif not self.show_byte_inspector_tab.get() and byte_id in tabs:
            if self.nb.select() == byte_id:
                self.nb.select(self.converted_tab)
            self.nb.hide(self.byte_inspector_tab)

    def update_text_stats(self, event=None):
        widget = event.widget if event is not None and isinstance(event.widget, tk.Text) else self.focus_get()
        if not isinstance(widget, tk.Text):
            widget = getattr(self,"input",None)
        if widget is None:
            return
        text = widget.get("1.0","end-1c")
        try:
            byte_count = len(text.encode("utf-8"))
        except Exception:
            byte_count = 0
        lines = int(widget.index("end-1c").split(".")[0]) if text else 1
        cursor = widget.index("insert")
        try:
            selected = len(widget.get("sel.first","sel.last"))
        except tk.TclError:
            selected = 0
        self.text_stats.set(
            f"Characters: {len(text):,}   Bytes: {byte_count:,}   Lines: {lines:,}   Cursor: {cursor}   Selected: {selected:,}"
        )

    def add_text_context_menu(self, widget, editable=True):
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="Undo", command=lambda w=widget: self.text_event(w, "<<Undo>>"))
        menu.add_command(label="Redo", command=lambda w=widget: self.text_event(w, "<<Redo>>"))
        menu.add_separator()
        menu.add_command(label="Cut", command=lambda w=widget: self.text_event(w, "<<Cut>>"))
        menu.add_command(label="Copy", command=lambda w=widget: self.text_event(w, "<<Copy>>"))
        menu.add_command(label="Paste", command=lambda w=widget: self.text_event(w, "<<Paste>>"))
        menu.add_command(label="Delete", command=lambda w=widget: self.delete_selection(w))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda w=widget: self.select_all(w))
        widget._context_menu = menu
        widget._context_editable = editable
        widget.bind("<Button-3>", self.show_context_menu, add="+")
        widget.bind("<Button-2>", self.show_context_menu, add="+")
        widget.bind("<Control-a>", lambda e, w=widget: self.select_all(w), add="+")
        widget.bind("<Control-A>", lambda e, w=widget: self.select_all(w), add="+")

    def text_event(self, widget, virtual_event):
        try:
            widget.event_generate(virtual_event)
        except tk.TclError:
            pass

    def has_selection(self, widget):
        try:
            return bool(widget.tag_ranges("sel"))
        except tk.TclError:
            return False

    def show_context_menu(self, event):
        widget = event.widget
        self.context_widget = widget
        try:
            widget.focus_set()
            menu = widget._context_menu
            selected = self.has_selection(widget)
            editable = bool(widget._context_editable) and str(widget.cget("state")) != "disabled"
            menu.entryconfigure("Cut", state="normal" if selected and editable else "disabled")
            menu.entryconfigure("Copy", state="normal" if selected else "disabled")
            menu.entryconfigure("Delete", state="normal" if selected and editable else "disabled")
            menu.entryconfigure("Paste", state="normal" if editable else "disabled")
            menu.entryconfigure("Undo", state="normal" if editable else "disabled")
            menu.entryconfigure("Redo", state="normal" if editable else "disabled")
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            try:
                menu.grab_release()
            except Exception:
                pass
        return "break"

    def show_context_menu_keyboard(self, event=None):
        widget = self.focus_get()
        if widget is None or not hasattr(widget, "_context_menu"):
            return
        x = widget.winfo_rootx() + 20
        y = widget.winfo_rooty() + 20
        class E: pass
        e = E(); e.widget = widget; e.x_root = x; e.y_root = y
        return self.show_context_menu(e)

    def select_all(self, widget):
        widget.tag_add("sel", "1.0", "end-1c")
        widget.mark_set("insert", "1.0")
        widget.see("insert")
        return "break"

    def delete_selection(self, widget):
        try:
            widget.delete("sel.first", "sel.last")
        except tk.TclError:
            pass

    def setup_drag_and_drop(self):
        if not DND_AVAILABLE:
            self.status.set("Ready — install tkinterdnd2 for file drag-and-drop support.")
            return
        for widget in (self, self.input):
            try:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self.handle_drop)
            except Exception:
                pass
        self.status.set("Ready — files may be dragged onto the window.")

    def handle_drop(self, event):
        try:
            paths = self.tk.splitlist(event.data)
            if paths:
                self.load_path(Path(paths[0]))
        except Exception as exc:
            messagebox.showerror("Drop Error", str(exc), parent=self)
        return event.action if hasattr(event, "action") else None

    def load_path(self, path):
        data = Path(path).read_bytes()
        self.last_data = data
        self.file_type.set(f"File signature: {detect_file_type(data)}")
        printable = sum(b in (9,10,13) or 32<=b<=126 for b in data)/max(len(data),1)
        self.input.delete("1.0","end")
        if printable>.75:
            self.in_kind.set("Plain Text")
            self.input.insert("1.0",best_text(data))
        else:
            self.in_kind.set("Hexadecimal")
            self.input.insert("1.0"," ".join(f"{b:02X}" for b in data))
        self.populate_bytes(data)
        self.status.set(f"Loaded {len(data):,} bytes from {path} — {detect_file_type(data)}"); self.update_text_stats()

    def use_detected_interpretation(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        label = self.tree.item(selected[0], "values")[1]
        mapping = [
            ("Hexadecimal → GUID", "Hexadecimal", "GUID"),
            ("Hexadecimal → Windows SID", "Windows SID (binary hex)", "Plain Text"),
            ("Hexadecimal", "Hexadecimal", "Plain Text"),
            ("Base64 URL Safe", "Base64 URL Safe", "Plain Text"),
            ("Base64", "Base64", "Plain Text"),
            ("Binary", "Binary Bytes", "Plain Text"),
            ("URL Encoding", "URL Encoding", "Plain Text"),
            ("HTML Entities", "HTML Entities", "Plain Text"),
            ("Windows FILETIME", "Windows FILETIME", "Plain Text"),
            ("Unix Epoch Milliseconds", "Unix Epoch Milliseconds", "Plain Text"),
            ("Unix Epoch", "Unix Epoch", "Plain Text"),
            ("Chrome/WebKit Timestamp", "Chrome/WebKit Timestamp", "Plain Text"),
            ("Firefox Timestamp", "Firefox Timestamp", "Plain Text"),
            ("Cocoa Timestamp", "Cocoa Timestamp", "Plain Text"),
            ("GUID", "GUID", "Hexadecimal"),
            ("SID", "Plain Text", "Windows SID (binary hex)"),
            ("UTF-8 → Hexadecimal", "Plain Text", "Hexadecimal"),
            ("UTF-8 → Base64", "Plain Text", "Base64"),
        ]
        for prefix, input_kind, output_kind in mapping:
            if label.startswith(prefix):
                self.in_kind.set(input_kind)
                self.out_kind.set(output_kind)
                self.convert()
                return
        self.status.set(f"No automatic conversion mapping is defined for: {label}")

    def changed(self,e=None):
        if self.input.edit_modified():
            self.input.edit_modified(False)
            if self.live.get(): self.after(300,lambda:self.convert(False))

    def convert(self,show=True):
        try:
            raw=self.input.get("1.0","end-1c")
            if not raw:return
            if self.in_kind.get()=="Auto Detect": return self.auto_detect()
            data,ctx=decode_value(raw,self.in_kind.get())
            self.last_data = data
            self.file_type.set(f"File signature: {detect_file_type(data)}")
            result=encode_value(data,self.out_kind.get(),ctx)
            self.output.delete("1.0","end"); self.output.insert("1.0",result)
            self.populate_bytes(data); self.nb.select(0)
            self.status.set(f"Converted {len(data):,} byte(s) — {detect_file_type(data)}."); self.update_text_stats()
        except Exception as ex:
            self.status.set(f"Error: {ex}")
            if show: messagebox.showerror("Conversion Error",str(ex),parent=self)

    def auto_detect(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        self.detect_map={}
        results=detect(self.input.get("1.0","end-1c"))
        for conf,label,result in results:
            iid=self.tree.insert("","end",values=(conf,label)); self.detect_map[iid]=result
        if results:
            first=self.tree.get_children()[0]; self.tree.selection_set(first); self.show_detect()
        self.nb.select(1); self.status.set(f"{len(results)} interpretation(s) found.")

    def show_detect(self,e=None):
        s=self.tree.selection()
        if s:
            self.detect_text.delete("1.0","end"); self.detect_text.insert("1.0",self.detect_map.get(s[0],"")); self.update_text_stats()

    def populate_bytes(self,data):
        for i in self.bytes.get_children(): self.bytes.delete(i)
        for n,b in enumerate(data[:10000]):
            self.bytes.insert("","end",values=(f"0x{n:08X}",f"{b:02X}",b,f"{b:08b}",chr(b) if 32<=b<=126 else "."))

    def swap(self):
        if self.out_kind.get() not in INPUTS:
            return messagebox.showinfo("Cannot Swap","Hash values cannot be reversed.",parent=self)
        out=self.output.get("1.0","end-1c")
        a,b=self.in_kind.get(),self.out_kind.get()
        self.in_kind.set(b); self.out_kind.set("Plain Text" if a=="Auto Detect" else a)
        if out:self.input.delete("1.0","end");self.input.insert("1.0",out)

    def copy(self):
        v=self.output.get("1.0","end-1c") or self.detect_text.get("1.0","end-1c")
        if v:self.clipboard_clear();self.clipboard_append(v);self.status.set("Copied to clipboard.")

    def open_file(self):
        p=filedialog.askopenfilename(parent=self)
        if not p:return
        try:
            self.load_path(Path(p))
        except Exception as ex:
            messagebox.showerror("Open File Error",str(ex),parent=self)

    def show_raw_dump(self):
        if not self.last_data:
            try:
                raw = self.input.get("1.0", "end-1c")
                if not raw:
                    return
                if self.in_kind.get() == "Auto Detect":
                    raise ValueError("Choose a specific input encoding before producing raw bytes.")
                self.last_data, _ = decode_value(raw, self.in_kind.get())
            except Exception as exc:
                messagebox.showerror("Raw Decode Error", str(exc), parent=self)
                return
        self.output.delete("1.0", "end")
        self.output.insert("1.0", raw_hex_dump(self.last_data))
        self.out_kind.set("Raw Hex Dump")
        self.populate_bytes(self.last_data)
        self.file_type.set(f"File signature: {detect_file_type(self.last_data)}")
        self.nb.select(self.converted_tab)
        self.status.set(f"Displayed raw hex dump for {len(self.last_data):,} byte(s).")

    def save_raw(self):
        if not self.last_data:
            try:
                raw = self.input.get("1.0", "end-1c")
                if not raw:
                    messagebox.showinfo("Save Raw Bytes", "There is no decoded byte stream to save.", parent=self)
                    return
                if self.in_kind.get() == "Auto Detect":
                    raise ValueError("Choose a specific input encoding before saving raw bytes.")
                self.last_data, _ = decode_value(raw, self.in_kind.get())
            except Exception as exc:
                messagebox.showerror("Raw Decode Error", str(exc), parent=self)
                return
        p = filedialog.asksaveasfilename(
            parent=self,
            title="Save Raw Decoded Bytes",
            defaultextension=".bin",
            filetypes=[("Binary file", "*.bin"), ("All files", "*.*")],
        )
        if not p:
            return
        try:
            Path(p).write_bytes(self.last_data)
            self.status.set(f"Saved {len(self.last_data):,} raw byte(s) to {p}")
        except Exception as exc:
            messagebox.showerror("Save Raw Error", str(exc), parent=self)

    def save(self):
        v=self.output.get("1.0","end-1c") or self.detect_text.get("1.0","end-1c")
        if not v:return
        p=filedialog.asksaveasfilename(parent=self,defaultextension=".txt",filetypes=[("Text","*.txt"),("All","*.*")])
        if p:Path(p).write_text(v,encoding="utf-8");self.status.set(f"Saved to {p}")

    def clear(self):
        for w in (self.input,self.output,self.detect_text):w.delete("1.0","end")
        for tree in (self.tree,self.bytes):
            for i in tree.get_children():tree.delete(i)
        self.last_data = b""
        self.file_type.set("File signature: No decoded data")
        self.status.set("Cleared.")

    def show_about(self):
        messagebox.showinfo(
            "About",
            f"{SCRIPT_NAME}\nVersion {SCRIPT_VERSION}\n\n"
            "Converts forensic encodings and timestamps, preserves exact decoded bytes, "
            "identifies common file signatures, displays raw hex/ASCII data, and saves "
            "binary output without text conversion.",
            parent=self,
        )

def main():
    App().mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
