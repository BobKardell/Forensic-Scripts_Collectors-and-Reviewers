
#!/usr/bin/env python3
# FFT_TOOL
# TITLE: File Inventory
# ID: file_inventory
# CATEGORY: Analysis Tools
# VERSION: 1.0.0
# DESCRIPTION: Scan evidence and populate the file_inventory table.
# ICON: file_inventory
# PASS_CASE_ARGUMENTS: true

import os, sqlite3
from pathlib import Path
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox

CASE_DB=os.environ.get("FFT_CASE_DB","")
EVIDENCE_ID=int(os.environ.get("FFT_EVIDENCE_ID","0"))

def iso(ts):
    return datetime.fromtimestamp(ts,timezone.utc).isoformat(timespec="seconds")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FFT File Inventory")
        self.geometry("650x220")
        self.status=tk.StringVar(value="Ready")
        self.files=tk.StringVar(value="0")
        self.pb=ttk.Progressbar(self,mode="indeterminate")
        ttk.Label(self,text="Simple File Inventory",font=("Segoe UI",16,"bold")).pack(pady=10)
        ttk.Label(self,textvariable=self.files).pack()
        self.pb.pack(fill="x",padx=20,pady=10)
        ttk.Button(self,text="Start Inventory",command=self.scan).pack()
        ttk.Label(self,textvariable=self.status).pack(pady=10)

    def evidence_root(self):
        con=sqlite3.connect(CASE_DB)
        cur=con.cursor()
        tbl=cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        names={r[0].lower():r[0] for r in tbl}
        if "evidence" not in names:
            raise Exception("Evidence table not found")
        table=names["evidence"]
        cols=[r[1] for r in cur.execute(f'PRAGMA table_info("{table}")')]
        pathcol=None
        for c in cols:
            if c.lower() in ("mounted_volume","mount_path","mounted_path","evidence_root","root_path"):
                pathcol=c
                break
        idcol=None
        for c in cols:
            if c.lower() in ("id","evidence_id"):
                idcol=c
                break
        root=cur.execute(f'SELECT "{pathcol}" FROM "{table}" WHERE "{idcol}"=?',(EVIDENCE_ID,)).fetchone()
        con.close()
        if not root: raise Exception("Evidence not found")
        return Path(root[0])

    def ensure_schema(self,con):
        con.execute("""
        CREATE TABLE IF NOT EXISTS file_inventory(
            id INTEGER PRIMARY KEY,
            evidence_id INTEGER,
            full_path TEXT,
            directory TEXT,
            filename TEXT,
            extension TEXT,
            size_bytes INTEGER,
            created_utc TEXT,
            modified_utc TEXT,
            accessed_utc TEXT,
            scan_time_utc TEXT
        )
        """)
        con.commit()

    def scan(self):
        try:
            root=self.evidence_root()
        except Exception as e:
            messagebox.showerror("Error",str(e)); return
        self.pb.start()
        con=sqlite3.connect(CASE_DB)
        self.ensure_schema(con)
        con.execute("DELETE FROM file_inventory WHERE evidence_id=?",(EVIDENCE_ID,))
        count=0
        for dirpath,_,files in os.walk(root):
            for f in files:
                p=Path(dirpath)/f
                try:
                    st=p.stat()
                    con.execute("""INSERT INTO file_inventory
                    (evidence_id,full_path,directory,filename,extension,size_bytes,
                    created_utc,modified_utc,accessed_utc,scan_time_utc)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (EVIDENCE_ID,str(p),str(p.parent),p.name,p.suffix.lower(),
                     st.st_size,iso(st.st_ctime),iso(st.st_mtime),
                     iso(st.st_atime),datetime.now(timezone.utc).isoformat(timespec="seconds")))
                    count+=1
                    if count%500==0:
                        con.commit()
                        self.files.set(f"{count:,} files")
                        self.update()
                except:
                    pass
        con.commit()
        con.close()
        self.pb.stop()
        self.files.set(f"{count:,} files inventoried")
        self.status.set("Complete")
        messagebox.showinfo("Finished",f"Inventoried {count:,} files.")

if __name__=="__main__":
    App().mainloop()
