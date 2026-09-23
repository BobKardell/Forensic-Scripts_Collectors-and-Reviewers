#!/usr/bin/env python3
# FFT_TOOL
# TITLE: Benford Analyzer
# ID: benford_analyzer
# CATEGORY: Plugins
# VERSION: 1.0
# DESCRIPTION: Perform Benford Law analysis on numeric datasets.
# ICON: ▥
# PASS_CASE_ARGUMENTS: false

"""Fraud Analytics Workbench - Benford Analyzer v1.0"""
from __future__ import annotations

import csv, html, io, math, re, tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

APP_NAME = "Fraud Analytics Workbench"
APP_VERSION = "1.0"

try:
    import numpy as np
    import pandas as pd
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.figure import Figure
except Exception as exc:
    root = tk.Tk(); root.withdraw()
    messagebox.showerror(
        "Missing Dependencies",
        "Install required packages with:\n\n"
        "pip install pandas numpy matplotlib openpyxl\n\n"
        f"Details: {exc}"
    )
    raise SystemExit(1)


@dataclass
class BenfordResult:
    mode: str
    labels: list[int]
    expected: np.ndarray
    observed: np.ndarray
    counts: np.ndarray
    total: int
    numeric: int
    analyzed: int
    ignored: int
    mad: float
    chi_square: float
    ks: float
    correlation: float
    conformity: str
    indices: dict[int, list[int]]


def parse_number(value) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float, np.number)):
        try:
            v = float(value)
            return v if math.isfinite(v) else None
        except Exception:
            return None
    text = str(value).strip()
    if not text:
        return None
    negative = text.startswith("(") and text.endswith(")")
    if negative:
        text = text[1:-1]
    text = re.sub(r"[$€£,%\s]", "", text)
    try:
        v = float(text)
        return -v if negative else v
    except ValueError:
        return None


def significant_digits(value: float) -> str:
    value = abs(value)
    if value == 0:
        return ""
    mantissa = f"{value:.15e}".split("e", 1)[0]
    return "".join(ch for ch in mantissa if ch.isdigit()).lstrip("0")


def digit_value(value: float, mode: str) -> Optional[int]:
    digits = significant_digits(value)
    if not digits:
        return None
    if mode == "First Digit":
        return int(digits[0])
    if mode == "Second Digit":
        return int(digits[1]) if len(digits) > 1 else 0
    if mode == "First Two Digits":
        return int(digits[:2]) if len(digits) > 1 else int(digits[0]) * 10
    return None


def expected_distribution(mode: str):
    if mode == "First Digit":
        labels = list(range(1, 10))
        expected = np.array([math.log10(1 + 1/d) for d in labels])
    elif mode == "Second Digit":
        labels = list(range(10))
        expected = np.array([
            sum(math.log10(1 + 1/(10*k+d)) for k in range(1, 10))
            for d in labels
        ])
    else:
        labels = list(range(10, 100))
        expected = np.array([math.log10(1 + 1/d) for d in labels])
    return labels, expected


def conformity(mode: str, mad: float) -> str:
    limits = {
        "First Digit": (0.006, 0.012, 0.015),
        "Second Digit": (0.008, 0.010, 0.012),
        "First Two Digits": (0.0012, 0.0018, 0.0022),
    }[mode]
    if mad <= limits[0]: return "Close conformity"
    if mad <= limits[1]: return "Acceptable conformity"
    if mad <= limits[2]: return "Marginal conformity"
    return "Nonconformity"


def analyze(series: pd.Series, mode: str, ignore_zero=True, absolute=True,
            ignore_duplicates=False, minimum=None, maximum=None) -> BenfordResult:
    labels, expected = expected_distribution(mode)
    pos = {d:i for i,d in enumerate(labels)}
    counts = np.zeros(len(labels), dtype=int)
    indices = {d: [] for d in labels}
    seen = set(); numeric = 0; accepted = 0

    for idx, raw in series.items():
        value = parse_number(raw)
        if value is None:
            continue
        numeric += 1
        if absolute:
            value = abs(value)
        if ignore_zero and value == 0:
            continue
        if minimum is not None and value < minimum:
            continue
        if maximum is not None and value > maximum:
            continue
        if ignore_duplicates:
            key = round(value, 12)
            if key in seen:
                continue
            seen.add(key)
        digit = digit_value(value, mode)
        if digit not in pos:
            continue
        counts[pos[digit]] += 1
        indices[digit].append(int(idx))
        accepted += 1

    observed = counts / accepted if accepted else np.zeros_like(expected)
    if accepted:
        mad = float(np.mean(np.abs(observed - expected)))
        exp_counts = expected * accepted
        chi = float(np.sum((counts-exp_counts)**2 / exp_counts))
        ks = float(np.max(np.abs(np.cumsum(observed)-np.cumsum(expected))))
        corr = float(np.corrcoef(observed, expected)[0,1]) if np.std(observed) else 0.0
    else:
        mad = chi = ks = corr = 0.0

    return BenfordResult(mode, labels, expected, observed, counts, len(series), numeric,
                         accepted, len(series)-accepted, mad, chi, ks, corr,
                         conformity(mode, mad) if accepted else "No data", indices)


class DataGrid(ttk.Frame):
    def __init__(self, master, on_change):
        super().__init__(master)
        self.df = pd.DataFrame(); self.on_change = on_change; self.filter_indices = None
        self.tree = ttk.Treeview(self, show="headings", selectmode="extended")
        ys = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0,column=0,sticky="nsew"); ys.grid(row=0,column=1,sticky="ns"); xs.grid(row=1,column=0,sticky="ew")
        self.rowconfigure(0,weight=1); self.columnconfigure(0,weight=1)
        self.tree.bind("<Control-v>", self.paste)
        self.tree.bind("<Control-V>", self.paste)
        self.tree.bind("<Delete>", self.delete_rows)

    def parse_clipboard(self, text):
        text = text.replace("\r\n","\n").replace("\r","\n").strip("\n")
        if not text.strip(): return pd.DataFrame()
        try: delim = csv.Sniffer().sniff(text[:10000], delimiters="\t,;|").delimiter
        except Exception: delim = "\t" if "\t" in text else ","
        rows = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if any(str(x).strip() for x in r)]
        width = max(map(len, rows)); rows = [r+[""]*(width-len(r)) for r in rows]
        first = [str(x).strip() for x in rows[0]]
        numeric = sum(parse_number(x) is not None for x in first)
        header = numeric < max(1, len(first)/2) and len(set(first)) == len(first)
        cols = first if header else [f"Column {i+1}" for i in range(width)]
        data = rows[1:] if header else rows
        seen={}; final=[]
        for c in cols:
            c = c or "Column"
            n=seen.get(c,0)+1; seen[c]=n; final.append(c if n==1 else f"{c}_{n}")
        return pd.DataFrame(data, columns=final)

    def paste(self, event=None):
        try: text = self.clipboard_get()
        except tk.TclError: return "break"
        try: self.set_df(self.parse_clipboard(text))
        except Exception as exc: messagebox.showerror("Paste Error", str(exc))
        return "break"

    def set_df(self, df):
        self.df = df.reset_index(drop=True).copy(); self.filter_indices=None; self.refresh(); self.on_change(self.df)

    def refresh(self):
        self.tree.delete(*self.tree.get_children()); self.tree["columns"] = list(self.df.columns)
        for col in self.df.columns:
            self.tree.heading(col, text=str(col)); self.tree.column(col, width=max(90,min(240,len(str(col))*10+30)))
        indices = list(self.df.index) if self.filter_indices is None else [i for i in self.df.index if i in self.filter_indices]
        for i in indices[:10000]:
            self.tree.insert("","end",iid=f"r{i}",values=["" if pd.isna(self.df.at[i,c]) else str(self.df.at[i,c]) for c in self.df.columns])

    def show_indices(self, indices): self.filter_indices=set(indices); self.refresh()
    def show_all(self): self.filter_indices=None; self.refresh()
    def delete_rows(self, event=None):
        ids=[int(i[1:]) for i in self.tree.selection() if i.startswith("r")]
        if ids: self.set_df(self.df.drop(ids).reset_index(drop=True))
        return "break"


class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title(f"{APP_NAME} v{APP_VERSION}"); self.geometry("1280x850"); self.minsize(980,680)
        self.column=tk.StringVar(); self.mode=tk.StringVar(value="First Digit")
        self.ignore_zero=tk.BooleanVar(value=True); self.absolute=tk.BooleanVar(value=True); self.ignore_dupes=tk.BooleanVar()
        self.minv=tk.StringVar(); self.maxv=tk.StringVar(); self.status=tk.StringVar(value="Paste data or open a file.")
        self.result=None
        self.metrics={k:tk.StringVar(value="—") for k in ["Rows","Analyzed","Ignored","MAD","Chi-square","KS","Correlation","Assessment"]}
        self.make_menu(); self.make_ui(); self.draw_empty()

    def make_menu(self):
        m=tk.Menu(self); f=tk.Menu(m,tearoff=0)
        f.add_command(label="Open CSV / Excel…",command=self.open_file); f.add_command(label="Paste Data",command=lambda:self.grid.paste())
        f.add_separator(); f.add_command(label="Export Chart…",command=self.export_chart); f.add_command(label="Export Exceptions…",command=self.export_exceptions); f.add_command(label="Export HTML Report…",command=self.export_report)
        f.add_separator(); f.add_command(label="Exit",command=self.destroy); m.add_cascade(label="File",menu=f)
        a=tk.Menu(m,tearoff=0); a.add_command(label="Run Analysis",command=self.run); a.add_command(label="Show All Rows",command=self.show_all); a.add_command(label="Clear",command=lambda:self.grid.set_df(pd.DataFrame())); m.add_cascade(label="Analyze",menu=a)
        h=tk.Menu(m,tearoff=0); h.add_command(label="Benford Guidance",command=self.guidance); h.add_command(label="About",command=self.about); m.add_cascade(label="Help",menu=h)
        self.config(menu=m)

    def make_ui(self):
        outer=ttk.Frame(self,padding=8); outer.pack(fill="both",expand=True)
        bar=ttk.Frame(outer); bar.pack(fill="x",pady=(0,6))
        ttk.Button(bar,text="Open File",command=self.open_file).pack(side="left",padx=3)
        ttk.Button(bar,text="Paste Data",command=lambda:self.grid.paste()).pack(side="left",padx=3)
        ttk.Button(bar,text="Run Analysis",command=self.run).pack(side="left",padx=3)
        ttk.Button(bar,text="Show All",command=self.show_all).pack(side="left",padx=3)
        ttk.Label(bar,text="Column:").pack(side="left",padx=(15,3)); self.cc=ttk.Combobox(bar,textvariable=self.column,state="readonly",width=25); self.cc.pack(side="left"); self.cc.bind("<<ComboboxSelected>>",lambda e:self.run())
        ttk.Label(bar,text="Test:").pack(side="left",padx=(12,3)); mc=ttk.Combobox(bar,textvariable=self.mode,state="readonly",values=["First Digit","Second Digit","First Two Digits"],width=16); mc.pack(side="left"); mc.bind("<<ComboboxSelected>>",lambda e:self.run())

        panes=ttk.Panedwindow(outer,orient="vertical"); panes.pack(fill="both",expand=True)
        top=ttk.Frame(panes); bottom=ttk.Frame(panes); panes.add(top,weight=3); panes.add(bottom,weight=2)
        hp=ttk.Panedwindow(top,orient="horizontal"); hp.pack(fill="both",expand=True)
        chart=ttk.Frame(hp); side=ttk.Frame(hp,padding=10); hp.add(chart,weight=4); hp.add(side,weight=1)
        self.fig=Figure(figsize=(8,4.5),dpi=100,constrained_layout=True); self.ax=self.fig.add_subplot(111)
        self.canvas=FigureCanvasTkAgg(self.fig,master=chart); self.canvas.get_tk_widget().pack(fill="both",expand=True); NavigationToolbar2Tk(self.canvas,chart).update(); self.canvas.mpl_connect("pick_event",self.pick)
        ttk.Label(side,text="Analysis Summary",font=("TkDefaultFont",11,"bold")).pack(anchor="w",pady=(0,8))
        for key in self.metrics:
            row=ttk.Frame(side); row.pack(fill="x",pady=2); ttk.Label(row,text=key+":",width=12).pack(side="left"); ttk.Label(row,textvariable=self.metrics[key],font=("TkDefaultFont",10,"bold")).pack(side="left")
        ttk.Separator(side).pack(fill="x",pady=10); ttk.Label(side,text="Data Rules",font=("TkDefaultFont",10,"bold")).pack(anchor="w")
        ttk.Checkbutton(side,text="Ignore zeros",variable=self.ignore_zero,command=self.run).pack(anchor="w")
        ttk.Checkbutton(side,text="Use absolute values",variable=self.absolute,command=self.run).pack(anchor="w")
        ttk.Checkbutton(side,text="Ignore duplicates",variable=self.ignore_dupes,command=self.run).pack(anchor="w")
        b=ttk.Frame(side); b.pack(fill="x",pady=8); ttk.Label(b,text="Minimum").grid(row=0,column=0,sticky="w"); ttk.Label(b,text="Maximum").grid(row=0,column=1,sticky="w",padx=(6,0)); ttk.Entry(b,textvariable=self.minv,width=10).grid(row=1,column=0,sticky="ew"); ttk.Entry(b,textvariable=self.maxv,width=10).grid(row=1,column=1,sticky="ew",padx=(6,0)); b.columnconfigure((0,1),weight=1)
        ttk.Button(side,text="Apply Rules",command=self.run).pack(fill="x"); ttk.Label(side,text="Click a chart bar to filter the grid to matching records.",wraplength=220).pack(anchor="w",pady=10)
        self.count=tk.StringVar(value="0 rows"); head=ttk.Frame(bottom); head.pack(fill="x",pady=(0,4)); ttk.Label(head,text="Source Data",font=("TkDefaultFont",10,"bold")).pack(side="left"); ttk.Label(head,textvariable=self.count).pack(side="left",padx=10); ttk.Label(head,text="Ctrl+V pastes from Excel").pack(side="right")
        self.grid=DataGrid(bottom,self.data_changed); self.grid.pack(fill="both",expand=True)
        ttk.Separator(outer).pack(fill="x",pady=(5,3)); ttk.Label(outer,textvariable=self.status).pack(anchor="w")

    def data_changed(self, df):
        cols=list(df.columns); self.cc["values"]=cols; self.count.set(f"{len(df):,} rows × {len(cols)} columns")
        if not cols: self.column.set(""); self.result=None; self.draw_empty(); return
        scores=[(df[c].map(lambda x:parse_number(x) is not None).sum(),c) for c in cols]
        if self.column.get() not in cols: self.column.set(max(scores)[1])
        self.run()

    def optional(self,text):
        if not text.strip(): return None
        v=parse_number(text)
        if v is None: raise ValueError(f"Invalid numeric limit: {text}")
        return v

    def run(self):
        if self.grid.df.empty or not self.column.get(): self.draw_empty(); return
        try:
            mn=self.optional(self.minv.get()); mx=self.optional(self.maxv.get())
            if mn is not None and mx is not None and mn>mx: raise ValueError("Minimum cannot exceed maximum")
            r=analyze(self.grid.df[self.column.get()],self.mode.get(),self.ignore_zero.get(),self.absolute.get(),self.ignore_dupes.get(),mn,mx)
        except Exception as exc: messagebox.showerror("Analysis Error",str(exc)); return
        self.result=r
        vals={"Rows":f"{r.total:,}","Analyzed":f"{r.analyzed:,}","Ignored":f"{r.ignored:,}","MAD":f"{r.mad:.6f}","Chi-square":f"{r.chi_square:.3f}","KS":f"{r.ks:.4f}","Correlation":f"{r.correlation:.4f}","Assessment":r.conformity}
        for k,v in vals.items(): self.metrics[k].set(v)
        self.draw(r); self.status.set(f"Analyzed {r.analyzed:,} records in {self.column.get()}.")

    def draw_empty(self):
        self.ax.clear(); self.ax.set_title("Benford Analysis"); self.ax.text(.5,.5,"Paste data or open a CSV/Excel file",ha="center",va="center",transform=self.ax.transAxes); self.ax.set_xticks([]); self.ax.set_yticks([]); self.canvas.draw_idle()

    def draw(self,r):
        self.ax.clear(); x=np.arange(len(r.labels)); w=.42
        bars=self.ax.bar(x-w/2,r.observed*100,w,label="Observed",picker=True); self.ax.bar(x+w/2,r.expected*100,w,label="Expected")
        for bar,d in zip(bars,r.labels): bar._digit=d
        if r.mode=="First Two Digits":
            ticks=np.arange(0,len(r.labels),5); self.ax.set_xticks(ticks); self.ax.set_xticklabels([r.labels[i] for i in ticks],rotation=45)
        else: self.ax.set_xticks(x); self.ax.set_xticklabels(r.labels)
        self.ax.set_ylabel("Percent"); self.ax.set_xlabel(r.mode); self.ax.set_title(f"{r.mode} — {self.column.get()}\n{r.conformity} | MAD {r.mad:.6f}"); self.ax.grid(axis="y",alpha=.25); self.ax.legend(); self.canvas.draw_idle()

    def pick(self,event):
        d=getattr(event.artist,"_digit",None)
        if d is None or not self.result:return
        inds=self.result.indices[d]; self.grid.show_indices(inds); self.count.set(f"{len(inds):,} matching rows — {self.mode.get()} = {d}"); self.status.set(f"Filtered to digit {d}.")

    def show_all(self): self.grid.show_all(); self.count.set(f"{len(self.grid.df):,} rows × {len(self.grid.df.columns)} columns"); self.status.set("Showing all rows.")

    def open_file(self):
        p=filedialog.askopenfilename(filetypes=[("Supported","*.csv *.tsv *.txt *.xlsx *.xlsm"),("All files","*.*")])
        if not p:return
        try:
            path=Path(p)
            if path.suffix.lower() in {".xlsx",".xlsm"}: df=pd.read_excel(path,dtype=object)
            else: df=pd.read_csv(path,sep="\t" if path.suffix.lower()==".tsv" else None,engine="python",dtype=object,keep_default_na=False,encoding_errors="replace")
            self.grid.set_df(df); self.status.set(f"Loaded {len(df):,} rows from {path.name}")
        except Exception as exc: messagebox.showerror("Open Error",str(exc))

    def exceptions_df(self):
        if not self.result:return pd.DataFrame()
        r=self.result
        return pd.DataFrame({"Digit":r.labels,"Count":r.counts,"Observed Percent":r.observed*100,"Expected Percent":r.expected*100,"Difference Percent":(r.observed-r.expected)*100,"Absolute Difference":np.abs(r.observed-r.expected)}).sort_values("Absolute Difference",ascending=False)

    def export_chart(self):
        if not self.result:return messagebox.showinfo("Export","Run an analysis first.")
        p=filedialog.asksaveasfilename(defaultextension=".png",filetypes=[("PNG","*.png"),("PDF","*.pdf")]);
        if p:self.fig.savefig(p,dpi=200,bbox_inches="tight")

    def export_exceptions(self):
        df=self.exceptions_df()
        if df.empty:return messagebox.showinfo("Export","Run an analysis first.")
        p=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")]);
        if p:df.to_csv(p,index=False)

    def export_report(self):
        if not self.result:return messagebox.showinfo("Export","Run an analysis first.")
        p=filedialog.asksaveasfilename(defaultextension=".html",filetypes=[("HTML","*.html")])
        if not p:return
        target=Path(p); img=target.with_name(target.stem+"_chart.png"); self.fig.savefig(img,dpi=180,bbox_inches="tight"); r=self.result
        rows="".join(f"<tr><td>{row['Digit']}</td><td>{int(row['Count'])}</td><td>{row['Observed Percent']:.3f}%</td><td>{row['Expected Percent']:.3f}%</td><td>{row['Difference Percent']:+.3f}%</td></tr>" for _,row in self.exceptions_df().iterrows())
        target.write_text(f'''<!doctype html><meta charset="utf-8"><title>Benford Report</title><style>body{{font-family:Arial;margin:36px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.m{{border:1px solid #aaa;padding:10px;border-radius:6px}}img{{max-width:100%}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #aaa;padding:7px;text-align:right}}th:first-child,td:first-child{{text-align:left}}</style><h1>Benford Analysis Report</h1><p><b>Column:</b> {html.escape(self.column.get())}<br><b>Test:</b> {r.mode}</p><div class="grid"><div class="m">Rows<br><b>{r.total:,}</b></div><div class="m">Analyzed<br><b>{r.analyzed:,}</b></div><div class="m">MAD<br><b>{r.mad:.6f}</b></div><div class="m">Assessment<br><b>{r.conformity}</b></div><div class="m">Chi-square<br><b>{r.chi_square:.3f}</b></div><div class="m">KS<br><b>{r.ks:.4f}</b></div><div class="m">Correlation<br><b>{r.correlation:.4f}</b></div><div class="m">Ignored<br><b>{r.ignored:,}</b></div></div><img src="{img.name}"><h2>Digit deviations</h2><table><tr><th>Digit</th><th>Count</th><th>Observed</th><th>Expected</th><th>Difference</th></tr>{rows}</table><p><i>Benford analysis is an investigative screening procedure and does not by itself establish fraud.</i></p>''',encoding="utf-8")

    def guidance(self): messagebox.showinfo("Benford Guidance","Best suited to naturally occurring values spanning several orders of magnitude. Avoid assigned numbers, fixed-price datasets, and heavily constrained populations. Nonconformity is a screening indicator, not proof of fraud.")
    def about(self): messagebox.showinfo("About",f"{APP_NAME} v{APP_VERSION}\n\nFirst digit, second digit, and first-two-digit Benford analysis.")


if __name__ == "__main__":
    App().mainloop()
