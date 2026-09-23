"""Live Evidence Collector - copies selected Windows artifacts to a structured ZIP."""
import csv, hashlib, os, shutil, socket, subprocess, sys, tempfile, threading, zipfile
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

SCRIPT_NAME='Live Evidence Collector'
SCRIPT_CATEGORY='Evidence Collection'
SCRIPT_DESCRIPTION='Collect selected Windows evidence into a structured ZIP for later analysis, including live Registry exports.'
SCRIPT_AUTHOR='Bob Kardell / ChatGPT'
SCRIPT_VERSION='1.7'


def sha256_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()


PROFILE_HELP_TEXT = """LIVE EVIDENCE COLLECTION PROFILES

Quick Triage
- Event Logs, Registry hives, Prefetch, browser data, execution and user activity artifacts.

Timeline Analysis
- Event Logs, Registry hives/logs, Prefetch, execution/user activity, $MFT, $LogFile, $UsnJrnl, $Boot.

Malware Investigation
- Event Logs, Registry/TxR, Prefetch, browser, Amcache/SRUM/Tasks/WMI, user activity, $MFT, $LogFile, $UsnJrnl.

Insider Threat
- Event Logs, Registry/logs, browser, execution/user activity, $MFT, $LogFile, $UsnJrnl.

Full Live Collection
- Every available artifact category.

Custom
- Examiner-selected artifacts.

All Button
- Selects all artifact checkboxes.

NTFS metadata collection does not perform a directory walk. Live user hives and Amcache use reg save when available. Run as Administrator. Failures are preserved in collection_errors.csv.
"""


class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title(SCRIPT_NAME); self.geometry('1040x920'); self.minsize(900,720)
        self.drive=tk.StringVar(value='C:\\'); self.case=tk.StringVar(); self.status=tk.StringVar(value='Choose a source drive and case folder.')
        self.evtx=tk.BooleanVar(value=True)
        self.system_registry=tk.BooleanVar(value=True)
        self.user_registry=tk.BooleanVar(value=True)
        self.registry_logs=tk.BooleanVar(value=True)
        self.registry_txr=tk.BooleanVar(value=True)
        self.prefetch=tk.BooleanVar(value=True)
        self.browser=tk.BooleanVar(value=True)
        self.execution_artifacts=tk.BooleanVar(value=True)
        self.user_activity=tk.BooleanVar(value=True)
        self.ntfs_mft=tk.BooleanVar(value=True)
        self.ntfs_logfile=tk.BooleanVar(value=True)
        self.ntfs_usnjrnl=tk.BooleanVar(value=True)
        self.ntfs_bitmap=tk.BooleanVar(value=False)
        self.ntfs_boot=tk.BooleanVar(value=True)
        self.ntfs_mftmirr=tk.BooleanVar(value=False)
        self.profile_vars={
            'Quick Triage':tk.BooleanVar(value=False),
            'Timeline Analysis':tk.BooleanVar(value=False),
            'Malware Investigation':tk.BooleanVar(value=False),
            'Insider Threat':tk.BooleanVar(value=False),
            'Full Live Collection':tk.BooleanVar(value=False),
            'Custom':tk.BooleanVar(value=True),
        }
        self.running=False; self.build()

    def build(self):
        root=ttk.Frame(self,padding=14); root.pack(fill='both',expand=True)
        ttk.Label(root,text=SCRIPT_NAME,font=('Segoe UI',16,'bold')).pack(anchor='w')
        ttk.Label(root,text='Collect selected Windows artifacts into a ZIP for later analysis. Run as Administrator for protected files.',wraplength=900).pack(anchor='w',pady=(2,12))
        setup=ttk.LabelFrame(root,text='Collection Setup',padding=12); setup.pack(fill='x'); setup.columnconfigure(1,weight=1)
        ttk.Label(setup,text='Source drive:').grid(row=0,column=0,sticky='w',pady=5)
        ttk.Combobox(setup,textvariable=self.drive,values=self.drives(),state='readonly',width=12).grid(row=0,column=1,sticky='w',pady=5)
        ttk.Label(setup,text='Case folder:').grid(row=1,column=0,sticky='w',pady=5)
        ttk.Entry(setup,textvariable=self.case).grid(row=1,column=1,sticky='ew',padx=(0,8),pady=5)
        ttk.Button(setup,text='Choose Case Folder...',command=self.choose_case).grid(row=1,column=2,pady=5)

        profiles=ttk.LabelFrame(root,text='Collection Profiles',padding=12); profiles.pack(fill='x',pady=(12,6))
        for index,name in enumerate(self.profile_vars):
            ttk.Checkbutton(profiles,text=name,variable=self.profile_vars[name],command=lambda n=name:self.apply_profile(n)).grid(row=index//3,column=index%3,sticky='w',padx=8,pady=4)
        ttk.Button(profiles,text='All',command=self.select_all).grid(row=2,column=0,sticky='w',padx=8,pady=(8,2))
        ttk.Button(profiles,text='Clear All',command=self.clear_all).grid(row=2,column=1,sticky='w',padx=8,pady=(8,2))
        ttk.Button(profiles,text='Profile Help...',command=self.show_profile_help).grid(row=2,column=2,sticky='w',padx=8,pady=(8,2))

        opts=ttk.LabelFrame(root,text='Artifacts to Collect',padding=12); opts.pack(fill='x',pady=6)
        choices=[
            ('Windows Event Logs (.evtx)',self.evtx),
            ('System Registry hives',self.system_registry),
            ('User Registry hives (NTUSER.DAT / UsrClass.dat)',self.user_registry),
            ('Registry transaction logs (.LOG1/.LOG2/.regtrans-ms)',self.registry_logs),
            ('Registry TxR files',self.registry_txr),
            ('Prefetch files (.pf)',self.prefetch),
            ('Browser history databases',self.browser),
            ('Execution artifacts (Amcache, SRUM, Scheduled Tasks)',self.execution_artifacts),
            ('User activity files (LNK, Jump Lists, Recycle Bin)',self.user_activity),
            ('NTFS $MFT',self.ntfs_mft),
            ('NTFS $LogFile',self.ntfs_logfile),
            ('NTFS $UsnJrnl',self.ntfs_usnjrnl),
            ('NTFS $Bitmap',self.ntfs_bitmap),
            ('NTFS $Boot',self.ntfs_boot),
            ('NTFS $MFTMirr',self.ntfs_mftmirr),
        ]
        for i,(label,var) in enumerate(choices):
            ttk.Checkbutton(opts,text=label,variable=var).grid(row=i//2,column=i%2,sticky='w',padx=6,pady=5)

        row=ttk.Frame(root); row.pack(fill='x')
        self.run_btn=ttk.Button(row,text='Collect Evidence',command=self.start); self.run_btn.pack(side='left')
        ttk.Button(row,text='Open Evidence Folder',command=self.open_evidence).pack(side='left',padx=8)
        ttk.Button(row,text='Clear Log',command=lambda:self.log.delete('1.0','end')).pack(side='left')
        lf=ttk.LabelFrame(root,text='Collection Log',padding=8); lf.pack(fill='both',expand=True,pady=(12,0))
        self.log=ScrolledText(lf,wrap='word',font=('Consolas',9)); self.log.pack(fill='both',expand=True)
        ttk.Label(root,textvariable=self.status,relief='sunken',anchor='w',padding=5).pack(fill='x',pady=(10,0))

    @staticmethod
    def drives():
        if os.name!='nt': return ['/']
        found=[f'{c}:\\' for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if os.path.exists(f'{c}:\\')]
        return found or ['C:\\']

    def artifact_vars(self):
        return {'evtx':self.evtx,'system_registry':self.system_registry,'user_registry':self.user_registry,'registry_logs':self.registry_logs,'registry_txr':self.registry_txr,'prefetch':self.prefetch,'browser':self.browser,'execution_artifacts':self.execution_artifacts,'user_activity':self.user_activity,'ntfs_mft':self.ntfs_mft,'ntfs_logfile':self.ntfs_logfile,'ntfs_usnjrnl':self.ntfs_usnjrnl,'ntfs_bitmap':self.ntfs_bitmap,'ntfs_boot':self.ntfs_boot,'ntfs_mftmirr':self.ntfs_mftmirr}

    def set_artifacts(self,names):
        for name,var in self.artifact_vars().items(): var.set(name in names)

    def apply_profile(self,selected):
        if not self.profile_vars[selected].get():
            if not any(v.get() for v in self.profile_vars.values()): self.profile_vars['Custom'].set(True)
            return
        for name,var in self.profile_vars.items():
            if name!=selected: var.set(False)
        profiles={
            'Quick Triage':{'evtx','system_registry','user_registry','prefetch','browser','execution_artifacts','user_activity'},
            'Timeline Analysis':{'evtx','system_registry','user_registry','registry_logs','prefetch','execution_artifacts','user_activity','ntfs_mft','ntfs_logfile','ntfs_usnjrnl','ntfs_boot'},
            'Malware Investigation':{'evtx','system_registry','user_registry','registry_logs','registry_txr','prefetch','browser','execution_artifacts','user_activity','ntfs_mft','ntfs_logfile','ntfs_usnjrnl'},
            'Insider Threat':{'evtx','system_registry','user_registry','registry_logs','browser','execution_artifacts','user_activity','ntfs_mft','ntfs_logfile','ntfs_usnjrnl'},
            'Full Live Collection':set(self.artifact_vars()),
            'Custom':None,
        }
        chosen=profiles[selected]
        if chosen is not None: self.set_artifacts(chosen)

    def select_all(self):
        self.set_artifacts(set(self.artifact_vars()))
        for name,var in self.profile_vars.items(): var.set(name=='Full Live Collection')

    def clear_all(self):
        self.set_artifacts(set())
        for name,var in self.profile_vars.items(): var.set(name=='Custom')

    def selected_profile_name(self):
        for name,var in self.profile_vars.items():
            if var.get():
                return name
        return 'Custom'

    @staticmethod
    def safe_filename(value):
        invalid='<>:\"/\\|?*'
        cleaned=''.join('_' if ch in invalid else ch for ch in value)
        cleaned='_'.join(cleaned.split())
        return cleaned.strip().rstrip('.') or 'Collection'

    def show_profile_help(self):
        path=Path(__file__).with_name('Live_Evidence_Collection_Profiles.txt')
        content=path.read_text(encoding='utf-8',errors='replace') if path.exists() else PROFILE_HELP_TEXT
        win=tk.Toplevel(self); win.title('Collection Profile Help'); win.geometry('820x650')
        viewer=ScrolledText(win,wrap='word',font=('Segoe UI',10)); viewer.pack(fill='both',expand=True,padx=10,pady=10)
        viewer.insert('1.0',content); viewer.config(state='disabled')
        ttk.Button(win,text='Close',command=win.destroy).pack(pady=(0,10))

    def choose_case(self):
        p=filedialog.askdirectory(title='Choose Case Folder')
        if p:self.case.set(p)

    def open_evidence(self):
        if not self.case.get().strip(): return messagebox.showinfo('No Case Folder','Choose a case folder first.')
        p=Path(self.case.get())/'Evidence'; p.mkdir(parents=True,exist_ok=True)
        try:
            if os.name=='nt': os.startfile(str(p))
            elif sys.platform=='darwin': subprocess.Popen(['open',str(p)])
            else: subprocess.Popen(['xdg-open',str(p)])
        except Exception as e: messagebox.showerror('Open Folder Error',str(e))

    def say(self,text): self.after(0,lambda:(self.log.insert('end',text+'\n'),self.log.see('end')))

    def start(self):
        if self.running:return
        source=Path(self.drive.get()); case=Path(self.case.get().strip())
        if not source.exists(): return messagebox.showerror('Invalid Source','The selected source drive is unavailable.')
        if not self.case.get().strip(): return messagebox.showwarning('Case Folder Required','Choose a case folder.')
        flags=(self.evtx,self.system_registry,self.user_registry,self.registry_logs,self.registry_txr,self.prefetch,self.browser,self.execution_artifacts,self.user_activity,self.ntfs_mft,self.ntfs_logfile,self.ntfs_usnjrnl,self.ntfs_bitmap,self.ntfs_boot,self.ntfs_mftmirr)
        if not any(v.get() for v in flags): return messagebox.showwarning('Nothing Selected','Select at least one artifact category.')
        evidence=case/'Evidence'; evidence.mkdir(parents=True,exist_ok=True)
        self.running=True; self.run_btn.config(state='disabled'); self.status.set('Collection running...'); self.log.delete('1.0','end')
        threading.Thread(target=self.collect,args=(source,evidence),daemon=True).start()

    def stage(self,src,dst,errors):
        dst.parent.mkdir(parents=True,exist_ok=True)
        try: shutil.copy2(src,dst); return True,'File copy'
        except Exception as first:
            if os.name=='nt':
                try:
                    r=subprocess.run(['robocopy',str(src.parent),str(dst.parent),src.name,'/B','/R:1','/W:1','/COPY:DAT','/DCOPY:T','/NFL','/NDL','/NJH','/NJS','/NP'],capture_output=True,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                    copied=dst.parent/src.name
                    if r.returncode<8 and copied.exists():
                        if copied!=dst: copied.replace(dst)
                        return True,'robocopy /B'
                    second=r.stderr.strip() or r.stdout.strip() or f'robocopy exit {r.returncode}'
                except Exception as e: second=f'{type(e).__name__}: {e}'
            else: second='Backup-mode copy unavailable on this OS.'
            errors.append({'source_path':str(src),'stage':'Copy','error':f'Normal: {type(first).__name__}: {first}; Fallback: {second}'})
            self.say(f'ERROR: {src}'); return False,''

    @staticmethod
    def incremented_archive_path(archive_path,used_paths):
        """Return a collision-free archive path while preserving directories."""
        normalized=str(archive_path).replace('\\','/').lstrip('/')
        used={str(value).replace('\\','/').lower() for value in used_paths}
        if normalized.lower() not in used:
            return normalized
        path=Path(normalized)
        parent='' if str(path.parent)=='.' else str(path.parent).replace('\\','/')
        name=path.name
        suffix=''.join(path.suffixes)
        stem=name[:-len(suffix)] if suffix else name
        counter=2
        while True:
            candidate_name=f'{stem}_{counter}{suffix}'
            candidate=f'{parent}/{candidate_name}' if parent else candidate_name
            if candidate.lower() not in used:
                return candidate
            counter+=1

    def reserve_archive_path(self,archive_path,items):
        used=[entry[1] for entry in items]
        unique=self.incremented_archive_path(archive_path,used)
        if unique!=str(archive_path).replace('\\','/').lstrip('/'):
            self.say(f'Archive name collision: {archive_path} -> {unique}')
        return unique

    def add_file(self,src,source_root,temp,items,errors,method_hint=None):
        try: arc=str(src.relative_to(source_root)).replace('\\','/')
        except Exception: arc=f'Collected/{src.name}'
        arc=self.reserve_archive_path(arc,items)
        dst=temp/arc; ok,method=self.stage(src,dst,errors)
        if ok: items.append((dst,arc,str(src),method_hint or method))

    def add_pattern(self,src_dir,pattern,prefix,temp,items,errors,recursive=False):
        self.say(f'Scanning: {src_dir}')
        if not src_dir.exists(): errors.append({'source_path':str(src_dir),'stage':'Discovery','error':'Directory not found'}); return
        try: files=list(src_dir.rglob(pattern) if recursive else src_dir.glob(pattern))
        except Exception as e: errors.append({'source_path':str(src_dir),'stage':'Discovery','error':f'{type(e).__name__}: {e}'}); return
        for src in files:
            if not src.is_file(): continue
            rel=src.relative_to(src_dir)
            desired_arc=str(Path(prefix)/rel).replace('\\','/')
            arc=self.reserve_archive_path(desired_arc,items)
            dst=temp/arc; ok,method=self.stage(src,dst,errors)
            if ok: items.append((dst,arc,str(src),method))

    @staticmethod
    def is_live_system_drive(source):
        if os.name != 'nt': return False
        return str(source).rstrip('\\/').upper()==os.environ.get('SystemDrive','C:').rstrip('\\/').upper()

    @staticmethod
    def reg_executable():
        if os.name!='nt': return 'reg'
        p=Path(os.environ.get('SystemRoot',r'C:\\Windows'))/'System32'/'reg.exe'
        return str(p) if p.exists() else 'reg.exe'

    def reg_save(self,key,destination,archive_path,items,errors):
        destination.parent.mkdir(parents=True,exist_ok=True)
        cmd=[self.reg_executable(),'save',key,str(destination),'/y']; self.say(f"Registry export: {' '.join(cmd)}")
        try:
            result=subprocess.run(cmd,capture_output=True,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if result.returncode==0 and destination.exists() and destination.stat().st_size>0:
                items.append((destination,archive_path,key,'reg save')); self.say(f'Saved Registry hive: {key}'); return True
            msg=result.stderr.strip() or result.stdout.strip() or f'reg save exit {result.returncode}'
            errors.append({'source_path':key,'stage':'Registry reg save','error':msg}); self.say(f'ERROR: reg save failed for {key}: {msg}')
        except Exception as e:
            errors.append({'source_path':key,'stage':'Registry reg save','error':f'{type(e).__name__}: {e}'}); self.say(f'ERROR: reg save failed for {key}: {e}')
        return False

    def loaded_user_hives(self,temp,items,errors):
        """Save loaded user hives as standalone files using reg.exe save."""
        if os.name!='nt':
            return

        try:
            result=subprocess.run(
                [self.reg_executable(),'query',r'HKU'],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),
            )
            if result.returncode!=0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f'exit {result.returncode}')

            discovered=set()
            for line in result.stdout.splitlines():
                key=line.strip()
                if not key.upper().startswith('HKEY_USERS\\'):
                    continue
                sid=key.split('\\',1)[1]
                if sid=='.DEFAULT':
                    continue

                if sid.endswith('_Classes'):
                    base_sid=sid[:-8]
                    if not base_sid.startswith('S-1-'):
                        continue
                    name=f'{base_sid}_UsrClass.hiv'
                elif sid.startswith('S-1-'):
                    name=f'{sid}_NTUSER.hiv'
                else:
                    continue

                if key.upper() in discovered:
                    continue
                discovered.add(key.upper())
                self.reg_save(
                    key,
                    temp/'Registry/LiveSaved/Users'/name,
                    f'Registry/LiveSaved/Users/{name}',
                    items,
                    errors,
                )

            # HKCU is retained as a clearly labeled convenience copy for the
            # account running the collector, even when its SID hive was saved.
            self.reg_save(
                r'HKCU',
                temp/'Registry/LiveSaved/Users'/'Current_User_NTUSER.hiv',
                'Registry/LiveSaved/Users/Current_User_NTUSER.hiv',
                items,
                errors,
            )
        except Exception as e:
            errors.append({'source_path':'HKU','stage':'Registry user hive discovery','error':f'{type(e).__name__}: {e}'})

    def copy_user_registry_files(self,source,temp,items,errors,include_hives=True,include_logs=True):
        users=source/'Users'
        if not users.exists(): return
        try: profiles=[p for p in users.iterdir() if p.is_dir()]
        except Exception as e: errors.append({'source_path':str(users),'stage':'User Registry discovery','error':str(e)}); return
        base_files=[]
        if include_hives:
            base_files += [Path('NTUSER.DAT'),Path('AppData/Local/Microsoft/Windows/UsrClass.dat')]
        if include_logs:
            base_files += [Path('NTUSER.DAT.LOG1'),Path('NTUSER.DAT.LOG2'),Path('AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1'),Path('AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2')]
        for profile in profiles:
            for rel in base_files:
                src=profile/rel
                if src.exists(): self.add_file(src,source,temp,items,errors)

    def collect_registry(self,source,temp,items,errors):
        live=self.is_live_system_drive(source)
        if self.system_registry.get():
            self.say('Collecting system Registry hives...')
            if live:
                for name,key in {'SYSTEM':r'HKLM\SYSTEM','SOFTWARE':r'HKLM\SOFTWARE','SAM':r'HKLM\SAM','SECURITY':r'HKLM\SECURITY','DEFAULT':r'HKU\.DEFAULT'}.items():
                    self.reg_save(key,temp/'Registry/LiveSaved'/f'{name}.hiv',f'Registry/LiveSaved/{name}.hiv',items,errors)
            else:
                cfg=source/'Windows/System32/config'
                for name in ('SYSTEM','SOFTWARE','SAM','SECURITY','DEFAULT'):
                    src=cfg/name
                    if src.exists(): self.add_file(src,source,temp,items,errors)

        if self.user_registry.get():
            self.say('Collecting user Registry hives...')
            if live:
                self.loaded_user_hives(temp,items,errors)
            else:
                self.copy_user_registry_files(source,temp,items,errors,include_hives=True,include_logs=False)

        if self.registry_logs.get():
            self.say('Collecting Registry transaction logs...')
            cfg=source/'Windows/System32/config'
            if cfg.exists():
                for pattern in ('*.LOG1','*.LOG2','*.blf','*.regtrans-ms'):
                    self.add_pattern(cfg,pattern,'Windows/System32/config',temp,items,errors,recursive=True)
            self.copy_user_registry_files(source,temp,items,errors,include_hives=False,include_logs=True)

        if self.registry_txr.get():
            self.say('Collecting Registry TxR files...')
            for txr in (source/'Windows/System32/config/TxR',source/'Windows/System32/config/RegBack'):
                if txr.exists(): self.add_pattern(txr,'*',str(txr.relative_to(source)).replace('\\','/'),temp,items,errors,recursive=True)

    def ntfs_copy_with_esentutl(self,source_spec,destination,errors):
        destination.parent.mkdir(parents=True,exist_ok=True)
        if os.name!='nt':
            errors.append({'source_path':source_spec,'stage':'NTFS metadata','error':'NTFS metadata collection requires Windows.'}); return False,''
        esent=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32'/'esentutl.exe'
        cmd=[str(esent if esent.exists() else 'esentutl.exe'),'/y',source_spec,'/d',str(destination),'/o']
        self.say(f"NTFS metadata: {' '.join(cmd)}")
        try:
            r=subprocess.run(cmd,capture_output=True,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if r.returncode==0 and destination.exists() and destination.stat().st_size>0: return True,'esentutl /y'
            msg=r.stderr.strip() or r.stdout.strip() or f'esentutl exit {r.returncode}'
        except Exception as e: msg=f'{type(e).__name__}: {e}'
        errors.append({'source_path':source_spec,'stage':'NTFS metadata copy','error':msg}); self.say(f'ERROR: NTFS metadata copy failed for {source_spec}: {msg}'); return False,''

    def collect_usn_text_export(self,drive,temp,items,errors):
        if os.name!='nt': return
        out=temp/'NTFS_Metadata'/'UsnJrnl_ReadJournal.txt'; out.parent.mkdir(parents=True,exist_ok=True)
        try:
            with open(out,'w',encoding='utf-8',errors='replace') as f:
                r=subprocess.run(['fsutil','usn','readjournal',drive,'csv'],stdout=f,stderr=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if r.returncode==0 and out.exists() and out.stat().st_size>0: items.append((out,'NTFS_Metadata/UsnJrnl_ReadJournal.txt',f'{drive} $UsnJrnl','fsutil usn readjournal'))
            else: errors.append({'source_path':f'{drive} $UsnJrnl','stage':'USN journal export','error':r.stderr.strip() or f'fsutil exit {r.returncode}'})
        except Exception as e: errors.append({'source_path':f'{drive} $UsnJrnl','stage':'USN journal export','error':f'{type(e).__name__}: {e}'})
        q=temp/'NTFS_Metadata'/'UsnJrnl_Query.txt'
        try:
            r=subprocess.run(['fsutil','usn','queryjournal',drive],capture_output=True,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)); q.write_text(r.stdout+('\n'+r.stderr if r.stderr else ''),encoding='utf-8',errors='replace')
            if q.stat().st_size: items.append((q,'NTFS_Metadata/UsnJrnl_Query.txt',f'{drive} $UsnJrnl metadata','fsutil usn queryjournal'))
        except Exception as e: errors.append({'source_path':f'{drive} $UsnJrnl','stage':'USN journal query','error':f'{type(e).__name__}: {e}'})

    def collect_ntfs_metadata(self,source,temp,items,errors):
        if os.name!='nt': errors.append({'source_path':str(source),'stage':'NTFS metadata','error':'Supported only on Windows.'}); return
        drive=str(source).rstrip('\\/')
        if len(drive)==2 and drive[1]==':': drive+='\\'
        for name,var in [('$MFT',self.ntfs_mft),('$LogFile',self.ntfs_logfile),('$Bitmap',self.ntfs_bitmap),('$Boot',self.ntfs_boot),('$MFTMirr',self.ntfs_mftmirr)]:
            if not var.get(): continue
            source_spec=f'{drive}{name}'; dst=temp/'NTFS_Metadata'/name
            ok,method=self.ntfs_copy_with_esentutl(source_spec,dst,errors)
            if ok: items.append((dst,f'NTFS_Metadata/{name}',source_spec,method))
        if self.ntfs_usnjrnl.get():
            source_spec=f'{drive}$Extend\\$UsnJrnl:$J'; dst=temp/'NTFS_Metadata'/'$UsnJrnl_$J'
            ok,method=self.ntfs_copy_with_esentutl(source_spec,dst,errors)
            if ok: items.append((dst,'NTFS_Metadata/$UsnJrnl_$J',source_spec,method))
            self.collect_usn_text_export(drive,temp,items,errors)

    def collect_browser(self,source,temp,items,errors):
        users=source/'Users'
        if not users.exists(): errors.append({'source_path':str(users),'stage':'Browser discovery','error':'Users directory not found'}); return
        try: profiles=[p for p in users.iterdir() if p.is_dir()]
        except Exception as e: errors.append({'source_path':str(users),'stage':'Browser discovery','error':str(e)}); return
        for profile in profiles:
            for root in (profile/'AppData/Local/Google/Chrome/User Data',profile/'AppData/Local/Microsoft/Edge/User Data'):
                if root.exists():
                    for name in ('History','Cookies','Login Data','Web Data','Bookmarks'):
                        try:candidates=root.rglob(name)
                        except Exception:candidates=[]
                        for src in candidates:
                            if src.is_file(): self.add_file(src,source,temp,items,errors)
            ff=profile/'AppData/Roaming/Mozilla/Firefox/Profiles'
            if ff.exists():
                for name in ('places.sqlite','cookies.sqlite','logins.json','key4.db','formhistory.sqlite'):
                    for src in ff.rglob(name): self.add_file(src,source,temp,items,errors)

    def registry_key_exists(self,key):
        if os.name!='nt':
            return False
        try:
            result=subprocess.run(
                [self.reg_executable(),'query',key],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),
            )
            return result.returncode==0
        except Exception:
            return False

    def collect_amcache(self,source,temp,items,errors):
        """Acquire Amcache and report only final failures, not failed fallbacks."""
        self.say('Collecting Amcache...')
        live=self.is_live_system_drive(source)
        amcache_dir=source/'Windows/AppCompat/Programs'
        amcache_hive=amcache_dir/'Amcache.hve'
        archive_path='Windows/AppCompat/Programs/Amcache.hve'
        destination=temp/archive_path
        acquired=False
        attempts=[]

        if live and self.registry_key_exists(r'HKLM\Amcache'):
            before=len(errors)
            acquired=self.reg_save(r'HKLM\Amcache',destination,archive_path,items,errors)
            if len(errors)>before:
                attempts.extend(errors[before:])
                del errors[before:]

        if not acquired and amcache_hive.exists() and os.name=='nt':
            destination.parent.mkdir(parents=True,exist_ok=True)
            esent=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32'/'esentutl.exe'
            cmd=[str(esent if esent.exists() else 'esentutl.exe'),'/y',str(amcache_hive),'/d',str(destination),'/o']
            self.say(f"Amcache acquisition: {' '.join(cmd)}")
            try:
                result=subprocess.run(cmd,capture_output=True,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                if result.returncode==0 and destination.exists() and destination.stat().st_size>0:
                    items.append((destination,archive_path,str(amcache_hive),'esentutl /y'))
                    self.say('Saved Amcache hive with esentutl /y')
                    acquired=True
                else:
                    msg=result.stderr.strip() or result.stdout.strip() or f'esentutl exit {result.returncode}'
                    attempts.append({'source_path':str(amcache_hive),'stage':'Amcache esentutl attempt','error':msg})
                    self.say(f'NOTICE: esentutl did not copy Amcache; trying backup copy: {msg}')
            except Exception as exc:
                attempts.append({'source_path':str(amcache_hive),'stage':'Amcache esentutl attempt','error':f'{type(exc).__name__}: {exc}'})
                self.say(f'NOTICE: esentutl did not copy Amcache; trying backup copy: {exc}')

        if not acquired and amcache_hive.exists():
            before=len(errors)
            ok,method=self.stage(amcache_hive,destination,errors)
            if ok:
                items.append((destination,archive_path,str(amcache_hive),method))
                acquired=True
                self.say(f'Saved Amcache hive with {method}')
                if len(errors)>before:
                    del errors[before:]
            else:
                if len(errors)>before:
                    attempts.extend(errors[before:])
                    del errors[before:]

        if not amcache_hive.exists():
            errors.append({'source_path':str(amcache_hive),'stage':'Amcache discovery','error':'Amcache.hve was not found'})
            self.say(f'WARNING: Amcache hive not found at {amcache_hive}')
        elif not acquired:
            details=' | '.join(a.get('error','') for a in attempts) or 'All acquisition methods failed.'
            errors.append({'source_path':str(amcache_hive),'stage':'Amcache final acquisition','error':details})
            self.say('ERROR: Amcache acquisition failed. See collection_errors.csv.')

        # LOG1 and LOG2 are optional. Missing files are not errors. If present,
        # attempt esentutl first and backup-mode copy second. Record only a final failure.
        for name in ('Amcache.hve.LOG1','Amcache.hve.LOG2'):
            src=amcache_dir/name
            if not src.exists():
                self.say(f'NOTICE: Optional Amcache transaction log not present: {name}')
                continue
            arc=f'Windows/AppCompat/Programs/{name}'
            dst=temp/arc
            log_ok=False
            log_attempts=[]
            if os.name=='nt':
                dst.parent.mkdir(parents=True,exist_ok=True)
                esent=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32'/'esentutl.exe'
                cmd=[str(esent if esent.exists() else 'esentutl.exe'),'/y',str(src),'/d',str(dst),'/o']
                try:
                    result=subprocess.run(cmd,capture_output=True,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                    if result.returncode==0 and dst.exists() and dst.stat().st_size>0:
                        items.append((dst,arc,str(src),'esentutl /y'))
                        log_ok=True
                    else:
                        log_attempts.append(result.stderr.strip() or result.stdout.strip() or f'esentutl exit {result.returncode}')
                except Exception as exc:
                    log_attempts.append(f'{type(exc).__name__}: {exc}')
            if not log_ok:
                before=len(errors)
                ok,method=self.stage(src,dst,errors)
                if ok:
                    items.append((dst,arc,str(src),method))
                    log_ok=True
                    if len(errors)>before: del errors[before:]
                elif len(errors)>before:
                    log_attempts.extend(e.get('error','') for e in errors[before:])
                    del errors[before:]
            if not log_ok:
                errors.append({'source_path':str(src),'stage':'Amcache transaction log final acquisition','error':' | '.join(log_attempts) or 'All acquisition methods failed.'})
                self.say(f'WARNING: Could not collect optional {name}')

        return acquired

    def collect_execution(self,source,temp,items,errors):
        self.say('Collecting execution and system activity artifacts...')

        self.collect_amcache(source,temp,items,errors)

        srum=source/'Windows/System32/sru/SRUDB.dat'
        if srum.exists():
            self.add_file(srum,source,temp,items,errors)

        tasks=source/'Windows/System32/Tasks'
        if tasks.exists():
            self.add_pattern(tasks,'*','Windows/System32/Tasks',temp,items,errors,recursive=True)

        wbem=source/'Windows/System32/wbem/Repository'
        if wbem.exists():
            self.add_pattern(wbem,'*','Windows/System32/wbem/Repository',temp,items,errors,recursive=True)

    def collect_user_activity(self,source,temp,items,errors):
        self.say('Collecting user activity files...')
        users=source/'Users'
        if users.exists():
            try:profiles=[p for p in users.iterdir() if p.is_dir()]
            except Exception as e: errors.append({'source_path':str(users),'stage':'User activity discovery','error':str(e)}); profiles=[]
            for p in profiles:
                roots=[
                    # Recent is scanned recursively and already includes both
                    # AutomaticDestinations and CustomDestinations Jump Lists.
                    p/'AppData/Roaming/Microsoft/Windows/Recent',
                    p/'AppData/Local/ConnectedDevicesPlatform',
                    p/'AppData/Local/Microsoft/Windows/Notifications',
                ]
                for root in roots:
                    if root.exists(): self.add_pattern(root,'*',str(root.relative_to(source)).replace('\\','/'),temp,items,errors,recursive=True)
        recycle=source/'$Recycle.Bin'
        if recycle.exists(): self.add_pattern(recycle,'*','$Recycle.Bin',temp,items,errors,recursive=True)

    def collect(self,source,evidence):
        profile=self.safe_filename(self.selected_profile_name())
        stamp=datetime.now().strftime('%Y_%m_%d_%H-%M')
        zpath=evidence/f'{profile}_{stamp}.zip'; manifest=[]; errors=[]; items=[]
        self.say(f'Source: {source}'); self.say(f'Output: {zpath}'); self.say('Original files will not be deleted.\n')
        try:
            with tempfile.TemporaryDirectory(prefix='FraudFighter_LiveCollection_') as td:
                temp=Path(td)
                if self.evtx.get():self.add_pattern(source/'Windows/System32/winevt/Logs','*.evtx','Windows/System32/winevt/Logs',temp,items,errors)
                if self.prefetch.get():self.add_pattern(source/'Windows/Prefetch','*.pf','Windows/Prefetch',temp,items,errors)
                if any(v.get() for v in (self.system_registry,self.user_registry,self.registry_logs,self.registry_txr)):self.collect_registry(source,temp,items,errors)
                if self.browser.get():self.collect_browser(source,temp,items,errors)
                if self.execution_artifacts.get():self.collect_execution(source,temp,items,errors)
                if self.user_activity.get():self.collect_user_activity(source,temp,items,errors)
                if any(v.get() for v in (self.ntfs_mft,self.ntfs_logfile,self.ntfs_usnjrnl,self.ntfs_bitmap,self.ntfs_boot,self.ntfs_mftmirr)): self.collect_ntfs_metadata(source,temp,items,errors)
                with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED,allowZip64=True) as z:
                    written_archive_paths=[]
                    for staged,arc,src,method in items:
                        try:
                            final_arc=self.incremented_archive_path(arc,written_archive_paths)
                            if final_arc!=arc:
                                self.say(f'ZIP name collision: {arc} -> {final_arc}')
                            written_archive_paths.append(final_arc)
                            manifest.append({'archive_path':final_arc,'source_path':src,'size':staged.stat().st_size,'sha256':sha256_file(staged),'collection_method':method,'collected_at':datetime.now().isoformat(timespec='seconds')})
                            z.write(staged,final_arc); self.say(f'Added: {final_arc}')
                        except Exception as e:errors.append({'source_path':src,'stage':'ZIP/Hash','error':f'{type(e).__name__}: {e}'})
                    mp=temp/'collection_manifest.csv'
                    with open(mp,'w',encoding='utf-8-sig',newline='') as f:
                        w=csv.DictWriter(f,fieldnames=['archive_path','source_path','size','sha256','collection_method','collected_at']); w.writeheader(); w.writerows(manifest)
                    z.write(mp,'collection_manifest.csv')
                    ep=temp/'collection_errors.csv'
                    with open(ep,'w',encoding='utf-8-sig',newline='') as f:
                        w=csv.DictWriter(f,fieldnames=['source_path','stage','error']); w.writeheader(); w.writerows(errors)
                    z.write(ep,'collection_errors.csv')
                    ip=temp/'collection_info.txt'; selected_profiles=', '.join(name for name,var in self.profile_vars.items() if var.get()) or 'Custom'; ip.write_text(f'Application: {SCRIPT_NAME}\nVersion: {SCRIPT_VERSION}\nComputer: {socket.gethostname()}\nSource: {source}\nCollection Profile: {selected_profiles}\nFiles: {len(manifest)}\nErrors: {len(errors)}\nOriginal files were not deleted.\n',encoding='utf-8'); z.write(ip,'collection_info.txt')
            summary=f'Collection complete: {len(manifest):,} file(s), {len(errors):,} error(s).\n\n{zpath}'
            self.say('\n'+summary); self.after(0,lambda:self.finish(summary,True))
        except Exception as e:self.after(0,lambda:self.finish(f'Collection failed:\n{e}',False))

    def finish(self,msg,ok):
        self.running=False; self.run_btn.config(state='normal'); self.status.set(msg.replace('\n',' '))
        (messagebox.showinfo if ok else messagebox.showerror)('Collection Complete' if ok else 'Collection Error',msg)


if __name__=='__main__': App().mainloop()
