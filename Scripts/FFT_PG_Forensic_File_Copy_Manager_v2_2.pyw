#!/usr/bin/env python3
# FFT_TOOL
# TITLE: File Copy Manager
# ID: forensics_file_copy_manager
# CATEGORY: Plugins
# VERSION: 2.2
# DESCRIPTION: Forensically copy selected files while preserving metadata and calculating hashes.
# ICON: ⇩
# PASS_CASE_ARGUMENTS: false

"""
Forensic File Copy Manager v2.1
Standard-library-only Tkinter logical forensic copy utility.
Designed primarily for Windows 10/11 and NTFS; it remains importable on other platforms.

Windows/NTFS build highlights:
- Include/exclude extension filters
- Windows Archive-bit filter: Any / Set / Clear
- Date range filters for Created / Modified / Accessed
- Owner, group, mode, Windows attributes, and security descriptor capture
- Best-effort preservation of owner, group, DACL, timestamps, mode, and attributes
- Preview grid records included and excluded files with reasons
- Existing hash deduplication and destination renaming retained

Limitations:
- This is a logical file-copy tool, not a physical disk-imaging tool.
- Reading files can update source access time. The application records metadata
  first and attempts to restore source access/modified times after hashing.
- Restoring Windows owner/DACL can require elevated rights.
- SACL/auditing data is not copied by default because it generally requires
  SeSecurityPrivilege.
- POSIX birth/creation time usually cannot be assigned.
"""

from __future__ import annotations

import csv
import ctypes
import fnmatch
import hashlib
import os
import queue
import shutil
import stat
import sys
import threading
import tkinter as tk
from dataclasses import dataclass, asdict
from datetime import datetime, time as dt_time, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

APP_NAME = "Forensic File Copy Manager"
APP_VERSION = "2.2"
CHUNK = 4 * 1024 * 1024
TOLERANCE_NS = 2_000_000_000

# Windows file attribute flags
WIN_ATTRS = {
    0x00000001: "READONLY",
    0x00000002: "HIDDEN",
    0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY",
    0x00000020: "ARCHIVE",
    0x00000040: "DEVICE",
    0x00000080: "NORMAL",
    0x00000100: "TEMPORARY",
    0x00000200: "SPARSE_FILE",
    0x00000400: "REPARSE_POINT",
    0x00000800: "COMPRESSED",
    0x00001000: "OFFLINE",
    0x00002000: "NOT_CONTENT_INDEXED",
    0x00004000: "ENCRYPTED",
    0x00008000: "INTEGRITY_STREAM",
    0x00010000: "VIRTUAL",
    0x00020000: "NO_SCRUB_DATA",
    0x00040000: "EA",
    0x00080000: "PINNED",
    0x00100000: "UNPINNED",
    0x00400000: "RECALL_ON_DATA_ACCESS",
}

OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SECURITY_INFO_FLAGS = (
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
)


def is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@dataclass
class Meta:
    path: str
    name: str
    extension: str
    size: int
    created_ns: Optional[int]
    modified_ns: int
    accessed_ns: int
    mode: int
    uid: Optional[int]
    gid: Optional[int]
    owner: str
    group: str
    windows_attributes: Optional[int]
    attributes_text: str
    security_descriptor: bytes = b""
    md5: str = ""
    sha1: str = ""


@dataclass
class ScanItem:
    path: Path
    included: bool
    reason: str
    meta: Optional[Meta]


@dataclass
class Record:
    source_path: str
    original_filename: str
    extension: str
    destination_path: str
    destination_filename: str
    scan_disposition: str
    filter_reason: str
    action: str
    duplicate: str
    duplicate_of: str
    duplicate_hash: str
    source_owner: str
    destination_owner: str
    source_group: str
    destination_group: str
    source_attributes: str
    destination_attributes: str
    owner_verified: str
    group_verified: str
    attributes_verified: str
    security_verified: str
    size_source: int
    size_destination: int
    source_created_utc: str
    destination_created_utc: str
    source_modified_utc: str
    destination_modified_utc: str
    source_accessed_utc: str
    destination_accessed_utc: str
    source_md5: str
    destination_md5: str
    source_sha1: str
    destination_sha1: str
    size_verified: str
    md5_verified: str
    sha1_verified: str
    created_verified: str
    modified_verified: str
    accessed_verified: str
    overall_status: str
    notes: str


def fmt(ns: Optional[int]) -> str:
    if ns is None:
        return "Unsupported"
    try:
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat()
    except Exception:
        return str(ns)


def close_time(a: Optional[int], b: Optional[int]) -> bool:
    return a is not None and b is not None and abs(a - b) <= TOLERANCE_NS


def creation_time_ns(path: Path, st: os.stat_result) -> Optional[int]:
    if sys.platform == "win32":
        return int(st.st_ctime_ns)
    birth = getattr(st, "st_birthtime", None)
    return int(float(birth) * 1e9) if birth is not None else None


def windows_attributes(path: Path) -> Optional[int]:
    if sys.platform != "win32":
        return None
    value = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if value == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(value)


def attributes_to_text(value: Optional[int], mode: int) -> str:
    parts = []
    if value is not None:
        parts.extend(name for flag, name in WIN_ATTRS.items() if value & flag)
    else:
        if mode & stat.S_IRUSR:
            parts.append("OWNER_READ")
        if mode & stat.S_IWUSR:
            parts.append("OWNER_WRITE")
        if mode & stat.S_IXUSR:
            parts.append("OWNER_EXECUTE")
    return "|".join(parts) if parts else "None"


def lookup_windows_owner_group(path: Path) -> tuple[str, str]:
    if sys.platform != "win32":
        return "", ""

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    p_owner = ctypes.c_void_p()
    p_group = ctypes.c_void_p()
    p_sd = ctypes.c_void_p()

    result = advapi32.GetNamedSecurityInfoW(
        ctypes.c_wchar_p(str(path)),
        1,  # SE_FILE_OBJECT
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
        ctypes.byref(p_owner),
        ctypes.byref(p_group),
        None,
        None,
        ctypes.byref(p_sd),
    )
    if result != 0:
        return f"Unavailable ({result})", f"Unavailable ({result})"

    def sid_name(sid: ctypes.c_void_p) -> str:
        name_size = ctypes.c_uint32(0)
        domain_size = ctypes.c_uint32(0)
        sid_type = ctypes.c_uint32(0)
        advapi32.LookupAccountSidW(
            None, sid, None, ctypes.byref(name_size),
            None, ctypes.byref(domain_size), ctypes.byref(sid_type)
        )
        name = ctypes.create_unicode_buffer(max(1, name_size.value))
        domain = ctypes.create_unicode_buffer(max(1, domain_size.value))
        if advapi32.LookupAccountSidW(
            None, sid, name, ctypes.byref(name_size),
            domain, ctypes.byref(domain_size), ctypes.byref(sid_type)
        ):
            return f"{domain.value}\\{name.value}" if domain.value else name.value
        return "Unknown SID"

    try:
        return sid_name(p_owner), sid_name(p_group)
    finally:
        if p_sd:
            kernel32.LocalFree(p_sd)


def get_security_descriptor(path: Path) -> bytes:
    if sys.platform != "win32":
        return b""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    needed = ctypes.c_uint32(0)
    advapi32.GetFileSecurityW(
        str(path), SECURITY_INFO_FLAGS, None, 0, ctypes.byref(needed)
    )
    if needed.value == 0:
        return b""
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetFileSecurityW(
        str(path),
        SECURITY_INFO_FLAGS,
        buffer,
        needed.value,
        ctypes.byref(needed),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return bytes(buffer.raw[:needed.value])


def set_security_descriptor(path: Path, descriptor: bytes) -> None:
    if sys.platform != "win32" or not descriptor:
        return
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    buffer = ctypes.create_string_buffer(descriptor)
    if not advapi32.SetFileSecurityW(
        str(path), SECURITY_INFO_FLAGS, buffer
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def metadata(path: Path, capture_security: bool = True) -> Meta:
    st = path.stat(follow_symlinks=False)
    uid = getattr(st, "st_uid", None)
    gid = getattr(st, "st_gid", None)

    if sys.platform == "win32":
        owner, group_name = lookup_windows_owner_group(path)
    else:
        # Keep the script importable outside Windows without relying on the
        # Unix-only pwd/grp modules. Numeric identifiers are sufficient for
        # the portable fallback and are never used on Windows.
        owner = str(uid) if uid is not None else ""
        group_name = str(gid) if gid is not None else ""

    attrs = windows_attributes(path)
    mode = stat.S_IMODE(st.st_mode)

    try:
        sd = get_security_descriptor(path) if capture_security else b""
    except Exception:
        sd = b""

    return Meta(
        path=str(path),
        name=path.name,
        extension=path.suffix.lower(),
        size=int(st.st_size),
        created_ns=creation_time_ns(path, st),
        modified_ns=int(st.st_mtime_ns),
        accessed_ns=int(st.st_atime_ns),
        mode=mode,
        uid=uid,
        gid=gid,
        owner=owner,
        group=group_name,
        windows_attributes=attrs,
        attributes_text=attributes_to_text(attrs, mode),
        security_descriptor=sd,
    )


def hashes(path: Path) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with path.open("rb", buffering=0) as stream:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            md5.update(block)
            sha1.update(block)
    return md5.hexdigest(), sha1.hexdigest()


def restore_times(path: Path, meta: Meta) -> None:
    try:
        os.utime(path, ns=(meta.accessed_ns, meta.modified_ns), follow_symlinks=False)
    except Exception:
        pass


def win_set_times(path: Path, created: Optional[int], accessed: int, modified: int) -> None:
    if sys.platform != "win32":
        return

    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

    def convert(ns: Optional[int]) -> Optional[FILETIME]:
        if ns is None:
            return None
        value = ns // 100 + 116444736000000000
        return FILETIME(value & 0xFFFFFFFF, value >> 32)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0x0100 | 0x40000000,
        0x1 | 0x2 | 0x4,
        None,
        3,
        0x02000000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        c, a, m = convert(created), convert(accessed), convert(modified)
        if not kernel32.SetFileTime(
            handle,
            ctypes.byref(c) if c else None,
            ctypes.byref(a),
            ctypes.byref(m),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)


def apply_meta(path: Path, meta: Meta, preserve_security: bool) -> list[str]:
    notes: list[str] = []

    try:
        os.chmod(path, meta.mode)
    except Exception as exc:
        notes.append(f"Mode not preserved: {exc}")

    if sys.platform != "win32" and meta.uid is not None and meta.gid is not None:
        try:
            os.chown(path, meta.uid, meta.gid, follow_symlinks=False)
        except PermissionError:
            notes.append("Owner/group not restored: elevated rights required")
        except Exception as exc:
            notes.append(f"Owner/group not restored: {exc}")

    if preserve_security and meta.security_descriptor:
        try:
            set_security_descriptor(path, meta.security_descriptor)
        except Exception as exc:
            notes.append(f"Windows owner/group/DACL not restored: {exc}")

    try:
        os.utime(path, ns=(meta.accessed_ns, meta.modified_ns), follow_symlinks=False)
    except Exception as exc:
        notes.append(f"Access/modified timestamps not preserved: {exc}")

    if sys.platform == "win32":
        try:
            win_set_times(path, meta.created_ns, meta.accessed_ns, meta.modified_ns)
        except Exception as exc:
            notes.append(f"Creation time not preserved: {exc}")

        if meta.windows_attributes is not None:
            try:
                if not ctypes.windll.kernel32.SetFileAttributesW(
                    str(path), meta.windows_attributes
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
            except Exception as exc:
                notes.append(f"Windows attributes not preserved: {exc}")
    else:
        notes.append("Creation/birth time cannot ordinarily be assigned on this platform.")

    return notes


def safe_relative(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return Path(path.name)


def available_path(path: Path, overwrite: bool) -> Path:
    if overwrite or not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    counter = 2
    while True:
        candidate = path.with_name(f"{stem}_{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def sanitize_component(text: str) -> str:
    invalid = '<>:"/\\|?*' if sys.platform == "win32" else "/\0"
    return "".join("_" if ch in invalid else ch for ch in text).strip()


def build_destination_filename(
    source: Path,
    prefix: str,
    keep_original: bool,
    add_counter: bool,
    counter: int,
    counter_width: int,
) -> str:
    parts: list[str] = []
    prefix = sanitize_component(prefix)
    if prefix:
        parts.append(prefix)
    if keep_original:
        parts.append(sanitize_component(source.stem))
    if add_counter:
        parts.append(str(counter).zfill(counter_width))
    if not parts:
        parts.append(sanitize_component(source.stem) or "file")
    return "_".join(parts) + source.suffix


def parse_patterns(text: str) -> list[str]:
    result = []
    for item in text.replace(",", ";").split(";"):
        item = item.strip()
        if not item:
            continue
        if item.startswith("."):
            item = "*" + item
        elif "*" not in item and "?" not in item:
            item = "*." + item.lstrip(".")
        result.append(item.lower())
    return result


def parse_date(text: str, end_of_day: bool = False) -> Optional[int]:
    text = text.strip()
    if not text:
        return None
    parsed = datetime.strptime(text, "%Y-%m-%d")
    if end_of_day:
        parsed = datetime.combine(parsed.date(), dt_time.max)
    parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1e9)


def choose_date(meta: Meta, date_type: str) -> Optional[int]:
    if date_type == "Created":
        return meta.created_ns
    if date_type == "Accessed":
        return meta.accessed_ns
    return meta.modified_ns


def evaluate_filters(
    meta: Meta,
    include_patterns: list[str],
    exclude_patterns: list[str],
    archive_filter: str,
    date_type: str,
    date_from_ns: Optional[int],
    date_to_ns: Optional[int],
) -> tuple[bool, str]:
    filename = meta.name.lower()

    if include_patterns and not any(fnmatch.fnmatch(filename, p) for p in include_patterns):
        return False, "Extension/name does not match include filter"

    if exclude_patterns and any(fnmatch.fnmatch(filename, p) for p in exclude_patterns):
        return False, "Matches exclude filter"

    if archive_filter != "Any":
        if meta.windows_attributes is None:
            return False, "Archive-bit filtering is unavailable on this platform"
        archive_set = bool(meta.windows_attributes & 0x20)
        if archive_filter == "Set" and not archive_set:
            return False, "Archive bit is not set"
        if archive_filter == "Clear" and archive_set:
            return False, "Archive bit is set"

    selected_date = choose_date(meta, date_type)
    if (date_from_ns is not None or date_to_ns is not None) and selected_date is None:
        return False, f"{date_type} date is unavailable"
    if date_from_ns is not None and selected_date is not None and selected_date < date_from_ns:
        return False, f"{date_type} date is before range"
    if date_to_ns is not None and selected_date is not None and selected_date > date_to_ns:
        return False, f"{date_type} date is after range"

    return True, "Matches filters"


def dedupe_key(meta: Meta, algorithm: str) -> str:
    if algorithm == "MD5":
        return f"MD5:{meta.md5}"
    if algorithm == "SHA-1":
        return f"SHA1:{meta.sha1}"
    return f"MD5:{meta.md5}|SHA1:{meta.sha1}"


def verify_text(a: str, b: str) -> str:
    return "PASS" if a == b else "FAIL"


def skipped_record(item: ScanItem, action: str, duplicate_of: str = "", duplicate_hash: str = "") -> Record:
    meta = item.meta
    assert meta is not None
    return Record(
        source_path=str(item.path),
        original_filename=item.path.name,
        extension=item.path.suffix.lower(),
        destination_path="",
        destination_filename="",
        scan_disposition="Included" if item.included else "Excluded",
        filter_reason=item.reason,
        action=action,
        duplicate="Yes" if duplicate_of else "No",
        duplicate_of=duplicate_of,
        duplicate_hash=duplicate_hash,
        source_owner=meta.owner,
        destination_owner="",
        source_group=meta.group,
        destination_group="",
        source_attributes=meta.attributes_text,
        destination_attributes="",
        owner_verified="N/A",
        group_verified="N/A",
        attributes_verified="N/A",
        security_verified="N/A",
        size_source=meta.size,
        size_destination=0,
        source_created_utc=fmt(meta.created_ns),
        destination_created_utc="",
        source_modified_utc=fmt(meta.modified_ns),
        destination_modified_utc="",
        source_accessed_utc=fmt(meta.accessed_ns),
        destination_accessed_utc="",
        source_md5=meta.md5,
        destination_md5="",
        source_sha1=meta.sha1,
        destination_sha1="",
        size_verified="N/A",
        md5_verified="N/A",
        sha1_verified="N/A",
        created_verified="N/A",
        modified_verified="N/A",
        accessed_verified="N/A",
        overall_status="SKIPPED",
        notes=item.reason if not duplicate_of else f"Duplicate of {duplicate_of}",
    )


def copy_hashed_file(
    item: ScanItem,
    destination: Path,
    source_meta: Meta,
    overwrite: bool,
    preserve_security: bool,
) -> Record:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Destination exists: {destination}")

    shutil.copyfile(item.path, destination, follow_symlinks=False)
    notes = apply_meta(destination, source_meta, preserve_security)

    destination_meta = metadata(destination, capture_security=True)
    dmd5, dsha1 = hashes(destination)

    # Destination hashing can change access time. Restore metadata again.
    notes.extend(apply_meta(destination, source_meta, preserve_security))
    destination_meta = metadata(destination, capture_security=True)

    size_ok = source_meta.size == destination_meta.size
    md5_ok = source_meta.md5 == dmd5
    sha1_ok = source_meta.sha1 == dsha1
    modified_ok = close_time(source_meta.modified_ns, destination_meta.modified_ns)
    accessed_ok = close_time(source_meta.accessed_ns, destination_meta.accessed_ns)

    if source_meta.created_ns is None or destination_meta.created_ns is None:
        created_status, created_ok = "Unsupported", True
    else:
        created_ok = close_time(source_meta.created_ns, destination_meta.created_ns)
        created_status = "PASS" if created_ok else "FAIL"

    owner_status = verify_text(source_meta.owner, destination_meta.owner)
    group_status = verify_text(source_meta.group, destination_meta.group)
    attr_status = (
        "PASS"
        if source_meta.windows_attributes == destination_meta.windows_attributes
        and source_meta.mode == destination_meta.mode
        else "FAIL"
    )

    if sys.platform == "win32" and preserve_security:
        security_status = "PASS" if (
            source_meta.owner == destination_meta.owner
            and source_meta.group == destination_meta.group
        ) else "FAIL"
    elif sys.platform == "win32":
        security_status = "Not requested"
    else:
        security_status = "POSIX owner/mode checked"

    overall = all((
        size_ok, md5_ok, sha1_ok, modified_ok, accessed_ok, created_ok,
        attr_status == "PASS",
    ))

    return Record(
        source_path=str(item.path),
        original_filename=item.path.name,
        extension=item.path.suffix.lower(),
        destination_path=str(destination),
        destination_filename=destination.name,
        scan_disposition="Included",
        filter_reason=item.reason,
        action="Copied",
        duplicate="No",
        duplicate_of="",
        duplicate_hash="",
        source_owner=source_meta.owner,
        destination_owner=destination_meta.owner,
        source_group=source_meta.group,
        destination_group=destination_meta.group,
        source_attributes=source_meta.attributes_text,
        destination_attributes=destination_meta.attributes_text,
        owner_verified=owner_status,
        group_verified=group_status,
        attributes_verified=attr_status,
        security_verified=security_status,
        size_source=source_meta.size,
        size_destination=destination_meta.size,
        source_created_utc=fmt(source_meta.created_ns),
        destination_created_utc=fmt(destination_meta.created_ns),
        source_modified_utc=fmt(source_meta.modified_ns),
        destination_modified_utc=fmt(destination_meta.modified_ns),
        source_accessed_utc=fmt(source_meta.accessed_ns),
        destination_accessed_utc=fmt(destination_meta.accessed_ns),
        source_md5=source_meta.md5,
        destination_md5=dmd5,
        source_sha1=source_meta.sha1,
        destination_sha1=dsha1,
        size_verified="PASS" if size_ok else "FAIL",
        md5_verified="PASS" if md5_ok else "FAIL",
        sha1_verified="PASS" if sha1_ok else "FAIL",
        created_verified=created_status,
        modified_verified="PASS" if modified_ok else "FAIL",
        accessed_verified="PASS" if accessed_ok else "FAIL",
        overall_status="PASS" if overall else "FAIL",
        notes="; ".join(dict.fromkeys(notes)),
    )


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1600x930")
        self.minsize(1150, 760)

        self.q: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.scan_items: list[ScanItem] = []
        self.records: list[Record] = []
        self.worker: Optional[threading.Thread] = None

        self.source = tk.StringVar()
        self.dest = tk.StringVar()
        self.mode = tk.StringVar(value="folder")
        self.recursive = tk.BooleanVar(value=True)
        self.flatten = tk.BooleanVar(value=False)
        self.overwrite = tk.BooleanVar(value=False)
        self.preserve_security = tk.BooleanVar(value=True)

        self.include_extensions = tk.StringVar()
        self.exclude_extensions = tk.StringVar()
        self.archive_filter = tk.StringVar(value="Any")
        self.date_type = tk.StringVar(value="Modified")
        self.date_from = tk.StringVar()
        self.date_to = tk.StringVar()

        self.deduplicate = tk.BooleanVar(value=False)
        self.dedupe_algorithm = tk.StringVar(value="SHA-1")

        self.prefix = tk.StringVar()
        self.keep_original = tk.BooleanVar(value=True)
        self.add_counter = tk.BooleanVar(value=False)
        self.counter_start = tk.StringVar(value="1")
        self.counter_width = tk.StringVar(value="6")

        platform_note = "Windows Administrator" if is_windows_admin() else ("Windows standard user" if sys.platform == "win32" else "Portable fallback")
        self.status = tk.StringVar(value=f"Select a source file or folder. Running as: {platform_note}.")
        self.summary = tk.StringVar(value="Scanned: 0 | Included: 0 | Excluded: 0")
        self.progress_text = tk.StringVar(value="0 of 0")
        self.preview = tk.StringVar(value="Example: original_filename.ext")

        self.configure_style()
        self.create_ui()
        self.update_preview()
        self.after(100, self.poll)

    def configure_style(self) -> None:
        """Apply a restrained slate-blue ttk theme without external packages."""
        self.configure(background="#eef1f6")
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        slate = "#5b6f92"
        slate_dark = "#3f506f"
        slate_light = "#dfe6f1"
        panel = "#f7f9fc"
        text = "#243247"
        muted = "#5b6678"

        style.configure("TFrame", background="#eef1f6")
        style.configure("Panel.TFrame", background=panel)
        style.configure("TLabel", background="#eef1f6", foreground=text)
        style.configure("Panel.TLabel", background=panel, foreground=text)
        style.configure("Hint.TLabel", background=panel, foreground=muted)
        style.configure("Status.TLabel", background=slate_dark, foreground="white", padding=(8, 5))
        style.configure("Header.TLabel", background=slate, foreground="white", font=("Segoe UI", 10, "bold"), padding=(8, 5))

        style.configure(
            "TNotebook",
            background="#eef1f6",
            borderwidth=0,
            tabmargins=(4, 5, 4, 0),
        )
        style.configure(
            "TNotebook.Tab",
            background=slate_light,
            foreground=slate_dark,
            padding=(18, 9),
            font=("Segoe UI", 10, "bold"),
            borderwidth=1,
        )
        # Keep every tab at exactly the same dimensions in all states.
        # Selection and hover are indicated by color only—no padding,
        # border, font, or expansion changes are applied.
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", slate),
                ("active", "#c7d2e4"),
                ("!selected", slate_light),
            ],
            foreground=[
                ("selected", "white"),
                ("active", slate_dark),
                ("!selected", slate_dark),
            ],
            expand=[
                ("selected", (0, 0, 0, 0)),
                ("active", (0, 0, 0, 0)),
                ("!selected", (0, 0, 0, 0)),
            ],
        )

        style.configure("TLabelframe", background=panel, bordercolor="#aab7ca", relief="solid")
        style.configure("TLabelframe.Label", background=panel, foreground=slate_dark, font=("Segoe UI", 10, "bold"))
        style.configure("TCheckbutton", background=panel, foreground=text)
        style.configure("TRadiobutton", background=panel, foreground=text)
        style.map("TCheckbutton", background=[("active", panel)])
        style.map("TRadiobutton", background=[("active", panel)])

        style.configure("Accent.TButton", background=slate, foreground="white", padding=(12, 7), font=("Segoe UI", 9, "bold"))
        style.map("Accent.TButton", background=[("active", slate_dark), ("pressed", slate_dark)], foreground=[("disabled", "#d8dde6")])
        style.configure("Secondary.TButton", padding=(10, 7))

        style.configure("Treeview", rowheight=25, background="white", fieldbackground="white", foreground=text)
        style.configure("Treeview.Heading", background=slate, foreground="white", font=("Segoe UI", 9, "bold"), relief="flat", padding=(5, 6))
        style.map("Treeview.Heading", background=[("active", slate_dark)])
        style.configure("Slate.Horizontal.TProgressbar", troughcolor="#d8dfeb", background=slate, bordercolor="#d8dfeb", lightcolor=slate, darkcolor=slate)

    def create_ui(self) -> None:
        outer = ttk.Frame(self, padding=10)
        outer.pack(fill="both", expand=True)

        title_bar = ttk.Frame(outer, style="Panel.TFrame", padding=(12, 8))
        title_bar.pack(fill="x", pady=(0, 8))
        ttk.Label(title_bar, text=f"{APP_NAME}  v{APP_VERSION}", style="Panel.TLabel", font=("Segoe UI", 14, "bold")).pack(side="left")
        privilege = "Administrator" if is_windows_admin() else ("Standard user" if sys.platform == "win32" else "Portable mode")
        ttk.Label(title_bar, text=f"Privilege: {privilege}", style="Hint.TLabel").pack(side="right")

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="x")

        source_tab = ttk.Frame(notebook, padding=12, style="Panel.TFrame")
        filters_tab = ttk.Frame(notebook, padding=12, style="Panel.TFrame")
        naming_tab = ttk.Frame(notebook, padding=12, style="Panel.TFrame")
        preservation_tab = ttk.Frame(notebook, padding=12, style="Panel.TFrame")

        notebook.add(source_tab, text="  Source  ")
        notebook.add(filters_tab, text="  Filters  ")
        notebook.add(naming_tab, text="  Naming & Deduplication  ")
        notebook.add(preservation_tab, text="  Preservation  ")

        source_box = ttk.LabelFrame(source_tab, text="Source and Destination", padding=12)
        source_box.pack(fill="x")
        ttk.Radiobutton(source_box, text="Single file", variable=self.mode, value="file", command=self.mode_change).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(source_box, text="Folder", variable=self.mode, value="folder", command=self.mode_change).grid(row=0, column=1, sticky="w")
        ttk.Label(source_box, text="Source", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(10, 2))
        ttk.Entry(source_box, textvariable=self.source).grid(row=2, column=0, columnspan=4, sticky="ew")
        self.source_button = ttk.Button(source_box, text="Browse Folder…", command=self.pick_folder, style="Secondary.TButton")
        self.source_button.grid(row=2, column=4, padx=(8, 0))
        ttk.Label(source_box, text="Destination", style="Panel.TLabel").grid(row=3, column=0, sticky="w", pady=(10, 2))
        ttk.Entry(source_box, textvariable=self.dest).grid(row=4, column=0, columnspan=4, sticky="ew")
        ttk.Button(source_box, text="Browse…", command=self.pick_dest, style="Secondary.TButton").grid(row=4, column=4, padx=(8, 0))
        self.recursive_check = ttk.Checkbutton(source_box, text="Include all subfolders", variable=self.recursive)
        self.recursive_check.grid(row=5, column=0, sticky="w", pady=(10, 0))
        ttk.Checkbutton(source_box, text="Flatten into one destination directory", variable=self.flatten).grid(row=5, column=1, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Checkbutton(source_box, text="Overwrite existing destination files", variable=self.overwrite).grid(row=5, column=3, columnspan=2, sticky="w", pady=(10, 0))
        for col in range(4):
            source_box.columnconfigure(col, weight=1)

        # Filters are grouped into visually distinct panels.
        filter_grid = ttk.Frame(filters_tab, style="Panel.TFrame")
        filter_grid.pack(fill="x")
        filter_grid.columnconfigure(0, weight=3)
        filter_grid.columnconfigure(1, weight=2)

        file_types = ttk.LabelFrame(filter_grid, text="File Type Filters", padding=12)
        file_types.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        ttk.Label(file_types, text="Include extensions or wildcards", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(file_types, textvariable=self.include_extensions).grid(row=1, column=0, sticky="ew", pady=(3, 0))
        ttk.Label(file_types, text="Examples: pdf; docx; *.xlsx; *.msg. Leave blank to include all.", style="Hint.TLabel").grid(row=2, column=0, sticky="w", pady=(2, 8))
        ttk.Label(file_types, text="Exclude extensions or wildcards", style="Panel.TLabel").grid(row=3, column=0, sticky="w")
        ttk.Entry(file_types, textvariable=self.exclude_extensions).grid(row=4, column=0, sticky="ew", pady=(3, 0))
        ttk.Label(file_types, text="Examples: tmp; bak; ~$*; desktop.ini", style="Hint.TLabel").grid(row=5, column=0, sticky="w", pady=(2, 0))
        file_types.columnconfigure(0, weight=1)

        archive_box = ttk.LabelFrame(filter_grid, text="Archive Attribute", padding=12)
        archive_box.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ttk.Label(archive_box, text="Select which Windows archive-bit state is eligible:", style="Panel.TLabel", wraplength=330).pack(anchor="w", pady=(0, 8))
        for value, label in (("Any", "Ignore archive bit"), ("Set", "Archive bit set"), ("Clear", "Archive bit clear")):
            ttk.Radiobutton(archive_box, text=label, variable=self.archive_filter, value=value).pack(anchor="w", pady=2)

        date_box = ttk.LabelFrame(filters_tab, text="Date Range Filters", padding=12)
        date_box.pack(fill="x", pady=(12, 0))
        timestamp_box = ttk.Frame(date_box, style="Panel.TFrame")
        timestamp_box.grid(row=0, column=0, rowspan=2, sticky="nw", padx=(0, 24))
        ttk.Label(timestamp_box, text="Timestamp to evaluate", style="Panel.TLabel", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 5))
        for value in ("Created", "Modified", "Accessed"):
            ttk.Radiobutton(timestamp_box, text=value, variable=self.date_type, value=value).pack(anchor="w", pady=2)

        ttk.Label(date_box, text="Beginning date", style="Panel.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Entry(date_box, textvariable=self.date_from, width=18).grid(row=1, column=1, sticky="w", padx=(0, 22), pady=(3, 0))
        ttk.Label(date_box, text="Through date", style="Panel.TLabel").grid(row=0, column=2, sticky="w")
        ttk.Entry(date_box, textvariable=self.date_to, width=18).grid(row=1, column=2, sticky="w", padx=(0, 22), pady=(3, 0))
        ttk.Label(date_box, text="Use YYYY-MM-DD. Dates are interpreted in UTC. Leave either field blank for an open-ended range.", style="Hint.TLabel", wraplength=430).grid(row=0, column=3, rowspan=2, sticky="w")
        date_box.columnconfigure(3, weight=1)

        dedupe = ttk.LabelFrame(naming_tab, text="Hash Deduplication", padding=12)
        dedupe.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ttk.Checkbutton(dedupe, text="Skip duplicate files based on hash", variable=self.deduplicate).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(dedupe, text="Comparison hash", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Combobox(dedupe, textvariable=self.dedupe_algorithm, values=("MD5", "SHA-1", "MD5 + SHA-1"), state="readonly", width=16).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(10, 0))
        ttk.Label(dedupe, text="The first occurrence is copied; subsequent matching files are reported as skipped.", style="Hint.TLabel", wraplength=440).grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))

        naming = ttk.LabelFrame(naming_tab, text="Destination Naming", padding=12)
        naming.pack(side="left", fill="both", expand=True, padx=(6, 0))
        ttk.Label(naming, text="Common prefix", style="Panel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(naming, textvariable=self.prefix).grid(row=0, column=1, columnspan=3, sticky="ew", padx=(8, 0))
        ttk.Checkbutton(naming, text="Keep original filename", variable=self.keep_original, command=self.update_preview).grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Checkbutton(naming, text="Append counter", variable=self.add_counter, command=self.update_preview).grid(row=1, column=2, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Label(naming, text="Counter start", style="Panel.TLabel").grid(row=2, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(naming, textvariable=self.counter_start, width=8).grid(row=2, column=1, sticky="w", padx=(8, 0), pady=(10, 0))
        ttk.Label(naming, text="Digits", style="Panel.TLabel").grid(row=2, column=2, sticky="w", padx=(14, 0), pady=(10, 0))
        ttk.Combobox(naming, textvariable=self.counter_width, values=tuple(str(i) for i in range(1, 11)), state="readonly", width=5).grid(row=2, column=3, sticky="w", padx=(8, 0), pady=(10, 0))
        ttk.Label(naming, textvariable=self.preview, style="Hint.TLabel").grid(row=3, column=0, columnspan=4, sticky="w", pady=(12, 0))
        naming.columnconfigure(1, weight=1)
        for variable in (self.prefix, self.counter_start, self.counter_width):
            variable.trace_add("write", lambda *_: self.update_preview())

        preserve_box = ttk.LabelFrame(preservation_tab, text="Metadata and NTFS Security Preservation", padding=12)
        preserve_box.pack(fill="x")
        ttk.Checkbutton(preserve_box, text="Preserve owner, group, and Windows DACL when permissions allow", variable=self.preserve_security).pack(anchor="w")
        ttk.Label(
            preserve_box,
            text=(
                "The application always attempts to preserve created, modified, and accessed timestamps, "
                "plus Windows file attributes. NTFS owner, group, and DACL restoration may require "
                "Administrator or backup/restore privileges. Results are recorded per file. "
                f"Current privilege level: {'Administrator' if is_windows_admin() else 'standard user'}."
            ),
            style="Hint.TLabel", wraplength=1000, justify="left",
        ).pack(anchor="w", pady=(10, 0))

        actions = ttk.Frame(outer, style="Panel.TFrame", padding=(10, 8))
        actions.pack(fill="x", pady=8)
        self.scan_button = ttk.Button(actions, text="Scan and Preview", command=self.scan, style="Accent.TButton")
        self.scan_button.pack(side="left")
        self.copy_button = ttk.Button(actions, text="Copy Included Files and Verify", command=self.start, state="disabled", style="Accent.TButton")
        self.copy_button.pack(side="left", padx=8)
        self.cancel_button = ttk.Button(actions, text="Cancel", command=self.do_cancel, state="disabled", style="Secondary.TButton")
        self.cancel_button.pack(side="left")
        ttk.Button(actions, text="Export CSV Report", command=self.export, style="Secondary.TButton").pack(side="left", padx=(18, 0))
        ttk.Label(actions, textvariable=self.summary, style="Panel.TLabel", font=("Segoe UI", 9, "bold")).pack(side="right")

        progress_frame = ttk.Frame(outer, style="Panel.TFrame", padding=(10, 7))
        progress_frame.pack(fill="x", pady=(0, 8))
        ttk.Label(progress_frame, text="Progress", style="Panel.TLabel", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8))
        self.progress = ttk.Progressbar(progress_frame, mode="determinate", style="Slate.Horizontal.TProgressbar")
        self.progress.pack(side="left", fill="x", expand=True)
        ttk.Label(progress_frame, textvariable=self.progress_text, width=16, style="Panel.TLabel").pack(side="left", padx=(8, 0))

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill="both", expand=True)
        columns = (
            "status", "reason", "original", "new", "source", "destination",
            "owner", "group", "attributes", "size", "created", "modified",
            "accessed", "md5", "sha1", "notes"
        )
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        labels = {
            "status": "Status", "reason": "Filter / Result", "original": "Original Name",
            "new": "Destination Name", "source": "Source Path", "destination": "Destination Path",
            "owner": "Owner", "group": "Group", "attributes": "Attributes",
            "size": "Size", "created": "Created UTC", "modified": "Modified UTC",
            "accessed": "Accessed UTC", "md5": "MD5", "sha1": "SHA-1", "notes": "Notes"
        }
        widths = {
            "status": 85, "reason": 220, "original": 180, "new": 180,
            "source": 300, "destination": 300, "owner": 170, "group": 150,
            "attributes": 240, "size": 90, "created": 180, "modified": 180,
            "accessed": 180, "md5": 240, "sha1": 300, "notes": 300,
        }
        for col in columns:
            self.tree.heading(col, text=labels[col])
            self.tree.column(col, width=widths[col], minwidth=60, anchor="w")
        self.tree.tag_configure("included", background="#e9f2ff")
        self.tree.tag_configure("excluded", background="#f3f4f6", foreground="#687386")
        self.tree.tag_configure("passed", background="#e6f4ea")
        self.tree.tag_configure("duplicate", background="#fff4d6")
        self.tree.tag_configure("failed", background="#fde8e8")
        self.tree.tag_configure("error", background="#f9d7dc")
        vbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        ttk.Label(outer, textvariable=self.status, style="Status.TLabel").pack(fill="x", pady=(6, 0))

    def mode_change(self) -> None:
        if self.mode.get() == "file":
            self.source_button.configure(text="Browse File…", command=self.pick_file)
            self.recursive_check.configure(state="disabled")
        else:
            self.source_button.configure(text="Browse Folder…", command=self.pick_folder)
            self.recursive_check.configure(state="normal")

    def pick_file(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.mode.set("file")
            self.mode_change()
            self.source.set(path)

    def pick_folder(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.mode.set("folder")
            self.mode_change()
            self.source.set(path)

    def pick_dest(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.dest.set(path)

    def update_preview(self) -> None:
        try:
            counter = int(self.counter_start.get() or "1")
            width = int(self.counter_width.get() or "6")
            name = build_destination_filename(
                Path("original_filename.ext"),
                self.prefix.get(),
                self.keep_original.get(),
                self.add_counter.get(),
                counter,
                width,
            )
            self.preview.set(f"Example: {name}")
        except Exception:
            self.preview.set("Example unavailable until counter settings are valid.")

    def validate_naming(self) -> tuple[int, int]:
        try:
            start = int(self.counter_start.get())
            width = int(self.counter_width.get())
        except ValueError as exc:
            raise ValueError("Counter start and digit width must be whole numbers.") from exc
        if start < 0:
            raise ValueError("Counter start cannot be negative.")
        if not 1 <= width <= 20:
            raise ValueError("Counter digit width must be between 1 and 20.")
        if not self.keep_original.get() and not self.add_counter.get() and not self.prefix.get().strip():
            raise ValueError("Naming settings would produce an empty filename.")
        return start, width

    def filter_settings(self) -> dict:
        try:
            date_from_ns = parse_date(self.date_from.get(), False)
            date_to_ns = parse_date(self.date_to.get(), True)
        except ValueError as exc:
            raise ValueError("Dates must use YYYY-MM-DD format.") from exc
        if date_from_ns is not None and date_to_ns is not None and date_from_ns > date_to_ns:
            raise ValueError("The beginning date cannot be after the ending date.")
        return {
            "include": parse_patterns(self.include_extensions.get()),
            "exclude": parse_patterns(self.exclude_extensions.get()),
            "archive": self.archive_filter.get(),
            "date_type": self.date_type.get(),
            "date_from": date_from_ns,
            "date_to": date_to_ns,
        }

    def scan(self) -> None:
        source = Path(self.source.get().strip())
        if not source.exists():
            messagebox.showerror("Invalid Source", "Source does not exist.")
            return
        try:
            filters = self.filter_settings()
        except Exception as exc:
            messagebox.showerror("Filter Error", str(exc))
            return

        if self.mode.get() == "file":
            paths = [source] if source.is_file() else []
        else:
            iterator = source.rglob("*") if self.recursive.get() else source.glob("*")
            paths = sorted(path for path in iterator if path.is_file() and not path.is_symlink())

        self.scan_items.clear()
        self.records.clear()
        self.tree.delete(*self.tree.get_children())

        included = excluded = errors = 0
        for index, path in enumerate(paths):
            try:
                meta = metadata(path, capture_security=True)
                is_included, reason = evaluate_filters(
                    meta,
                    filters["include"],
                    filters["exclude"],
                    filters["archive"],
                    filters["date_type"],
                    filters["date_from"],
                    filters["date_to"],
                )
                item = ScanItem(path, is_included, reason, meta)
                self.scan_items.append(item)
                if is_included:
                    included += 1
                    status = "INCLUDED"
                else:
                    excluded += 1
                    status = "EXCLUDED"

                values = (
                    status, reason, path.name, "", str(path), "",
                    meta.owner, meta.group, meta.attributes_text, f"{meta.size:,}",
                    fmt(meta.created_ns), fmt(meta.modified_ns), fmt(meta.accessed_ns),
                    "", "", ""
                )
            except Exception as exc:
                errors += 1
                item = ScanItem(path, False, f"Metadata error: {exc}", None)
                self.scan_items.append(item)
                values = (
                    "ERROR", str(exc), path.name, "", str(path), "",
                    "", "", "", "", "", "", "", "", "", ""
                )
            row_tag = "included" if values[0] == "INCLUDED" else ("excluded" if values[0] == "EXCLUDED" else "error")
            self.tree.insert("", "end", iid=f"f{index}", values=values, tags=(row_tag,))

        self.progress.configure(maximum=max(1, included), value=0)
        self.progress_text.set(f"0 of {included:,}")
        self.copy_button.configure(state="normal" if included else "disabled")
        self.summary.set(
            f"Scanned: {len(paths):,} | Included: {included:,} | Excluded: {excluded:,} | Errors: {errors:,}"
        )
        self.status.set("Preview complete. Review included and excluded rows before copying.")

    def start(self) -> None:
        included_items = [item for item in self.scan_items if item.included and item.meta is not None]
        if not included_items:
            messagebox.showinfo("No Included Files", "No files currently match the filters.")
            return

        destination = Path(self.dest.get().strip())
        if not self.dest.get().strip():
            messagebox.showwarning("Destination Required", "Select a destination.")
            return

        try:
            counter_start, counter_width = self.validate_naming()
            destination.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("Configuration Error", str(exc))
            return

        root = Path(self.source.get()).parent if self.mode.get() == "file" else Path(self.source.get())
        settings = {
            "counter_start": counter_start,
            "counter_width": counter_width,
            "prefix": self.prefix.get(),
            "keep_original": self.keep_original.get(),
            "add_counter": self.add_counter.get(),
            "deduplicate": self.deduplicate.get(),
            "dedupe_algorithm": self.dedupe_algorithm.get(),
            "flatten": self.flatten.get(),
            "overwrite": self.overwrite.get(),
            "preserve_security": self.preserve_security.get(),
        }

        # Add filtered-out rows to the report immediately.
        self.records = [
            skipped_record(item, "Excluded by filter")
            for item in self.scan_items if not item.included and item.meta is not None
        ]

        self.cancel.clear()
        self.scan_button.configure(state="disabled")
        self.copy_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.progress.configure(maximum=len(included_items), value=0)
        self.worker = threading.Thread(
            target=self.work,
            args=(included_items, root, destination, settings),
            daemon=True,
        )
        self.worker.start()

    def work(self, items: list[ScanItem], root: Path, destination: Path, settings: dict) -> None:
        passed = skipped = failed = 0
        seen_hashes: dict[str, str] = {}
        counter = settings["counter_start"]

        for position, item in enumerate(items):
            if self.cancel.is_set():
                self.q.put(("done", passed, skipped, failed, True))
                return

            index = self.scan_items.index(item)
            try:
                meta = item.meta
                assert meta is not None

                try:
                    meta.md5, meta.sha1 = hashes(item.path)
                finally:
                    restore_times(item.path, meta)

                key = dedupe_key(meta, settings["dedupe_algorithm"])
                if settings["deduplicate"] and key in seen_hashes:
                    record = skipped_record(item, "Skipped duplicate", seen_hashes[key], key)
                    self.records.append(record)
                    skipped += 1
                    self.q.put(("rec", index, record, passed, skipped, failed))
                    self.q.put(("prog", position + 1, len(items)))
                    continue

                destination_name = build_destination_filename(
                    item.path,
                    settings["prefix"],
                    settings["keep_original"],
                    settings["add_counter"],
                    counter,
                    settings["counter_width"],
                )
                if settings["add_counter"]:
                    counter += 1

                if settings["flatten"]:
                    dst = destination / destination_name
                else:
                    relative_parent = safe_relative(item.path.parent, root)
                    dst = destination / relative_parent / destination_name
                dst = available_path(dst, settings["overwrite"])

                record = copy_hashed_file(
                    item, dst, meta, settings["overwrite"], settings["preserve_security"]
                )
                self.records.append(record)
                seen_hashes.setdefault(key, record.destination_path)

                if record.overall_status == "PASS":
                    passed += 1
                else:
                    failed += 1
                self.q.put(("rec", index, record, passed, skipped, failed))
            except Exception as exc:
                failed += 1
                self.q.put(("err", index, str(exc), passed, skipped, failed))

            self.q.put(("prog", position + 1, len(items)))

        self.q.put(("done", passed, skipped, failed, False))

    def poll(self) -> None:
        try:
            while True:
                message = self.q.get_nowait()
                kind = message[0]

                if kind == "rec":
                    _, index, record, passed, skipped, failed = message
                    result_tag = "duplicate" if record.overall_status == "SKIPPED" else ("passed" if record.overall_status == "PASS" else "failed")
                    self.tree.item(
                        f"f{index}",
                        tags=(result_tag,),
                        values=(
                            record.overall_status,
                            record.action,
                            record.original_filename,
                            record.destination_filename,
                            record.source_path,
                            record.destination_path,
                            record.destination_owner or record.source_owner,
                            record.destination_group or record.source_group,
                            record.destination_attributes or record.source_attributes,
                            f"{record.size_source:,}",
                            record.destination_created_utc or record.source_created_utc,
                            record.destination_modified_utc or record.source_modified_utc,
                            record.destination_accessed_utc or record.source_accessed_utc,
                            record.source_md5,
                            record.source_sha1,
                            record.notes,
                        ),
                    )
                    self.summary.set(
                        f"Included processed: {passed + skipped + failed:,} | Passed: {passed:,} | "
                        f"Duplicates skipped: {skipped:,} | Failed: {failed:,}"
                    )

                elif kind == "err":
                    _, index, error, passed, skipped, failed = message
                    values = list(self.tree.item(f"f{index}", "values"))
                    values[0] = "ERROR"
                    values[1] = error
                    values[-1] = error
                    self.tree.item(f"f{index}", values=values, tags=("error",))
                    self.summary.set(
                        f"Included processed: {passed + skipped + failed:,} | Passed: {passed:,} | "
                        f"Duplicates skipped: {skipped:,} | Failed: {failed:,}"
                    )

                elif kind == "prog":
                    _, current, total = message
                    self.progress.configure(value=current)
                    self.progress_text.set(f"{current:,} of {total:,}")

                elif kind == "done":
                    _, passed, skipped, failed, cancelled = message
                    self.scan_button.configure(state="normal")
                    self.copy_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    prefix = "Cancelled. " if cancelled else "Complete. "
                    self.status.set(
                        prefix + f"{passed:,} passed; {skipped:,} duplicate files skipped; "
                        f"{failed:,} failed."
                    )
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def do_cancel(self) -> None:
        self.cancel.set()
        self.status.set("Cancellation requested; finishing the current file.")

    def export(self) -> None:
        if not self.records:
            messagebox.showinfo("No Report", "No completed or excluded records are available.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV report", "*.csv")]
        )
        if not path:
            return

        fields = list(asdict(self.records[0]).keys())
        with open(path, "w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for record in self.records:
                writer.writerow(asdict(record))

        self.status.set(f"Report exported to {Path(path).name}")


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
