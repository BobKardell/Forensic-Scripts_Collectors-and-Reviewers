#!/usr/bin/env python3
# FFT_TOOL
# TITLE: PST Explorer
# ID: pst_explorer
# CATEGORY: Plugins
# VERSION: 1.3
# DESCRIPTION: Review and export messages and metadata from Outlook PST files.
# ICON: ✉
# PASS_CASE_ARGUMENTS: false

"""
Forensic PST Explorer v1.3

Portable Windows-oriented PST/OST explorer for the Fraud Fighter Toolbox.

PST/OST parsing:
    Requires the optional pypff Python module from libpff.

EML export:
    Available directly from parsed PST/OST message properties.

MSG export:
    Available only when Microsoft Outlook and pywin32 are installed. The
    exported EML is opened by Outlook and saved as Unicode MSG.

Bookmark storage:
    Bookmarks are written to a sidecar SQLite database. The evidence file is
    opened read-only and is never modified.
"""

SCRIPT_NAME = "Forensic PST Explorer"
SCRIPT_VERSION = "1.3"
SCRIPT_CATEGORY = "Email Forensics"
SCRIPT_DESCRIPTION = (
    "Explore PST and OST mail stores, render formatted message bodies, preview "
    "and open attachments, bookmark evidence, and export messages as EML or MSG."
)

import csv
import hashlib
import html
import json
import mimetypes
import os
import queue
import quopri
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import traceback
from datetime import datetime
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import format_datetime, formataddr, getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    import pypff
except Exception:
    pypff = None

try:
    import win32com.client
except Exception:
    win32com = None


def safe_text(value):
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return repr(value)


def safe_filename(value, fallback="message"):
    value = safe_text(value).strip() or fallback
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value)
    value = re.sub(r"\s+", " ", value).strip(" .")
    return value[:150] or fallback


def hash_file(path):
    """Calculate MD5 and SHA-256 in a single read-only pass."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(block)
            sha256.update(block)
    return md5.hexdigest(), sha256.hexdigest()


def sha256_file(path):
    """Backward-compatible SHA-256 helper."""
    return hash_file(path)[1]


def format_dt(value):
    if not value:
        return ""
    if isinstance(value, datetime):
        try:
            return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        except Exception:
            return value.strftime("%Y-%m-%d %H:%M:%S")
    return safe_text(value)


def first_attr(obj, names, default=""):
    for name in names:
        try:
            value = getattr(obj, name)
            if callable(value):
                value = value()
            if value not in (None, ""):
                return value
        except Exception:
            pass
    return default


def collect_recipients(message):
    result = {"to": [], "cc": [], "bcc": []}
    try:
        count = message.number_of_recipients
    except Exception:
        count = 0
    for i in range(count):
        try:
            r = message.get_recipient(i)
            name = safe_text(first_attr(r, ["display_name", "name"], ""))
            addr = safe_text(first_attr(r, ["email_address", "smtp_address"], ""))
            rtype = first_attr(r, ["type", "recipient_type"], 1)
            try:
                rtype = int(rtype)
            except Exception:
                rtype = 1
            target = "to" if rtype == 1 else "cc" if rtype == 2 else "bcc"
            formatted = formataddr((name, addr)) if addr else name
            if formatted:
                result[target].append(formatted)
        except Exception:
            continue
    return result


def get_transport_headers(message):
    return safe_text(first_attr(message, [
        "transport_headers",
        "internet_headers",
        "headers"
    ], ""))


def message_identity(folder_path, message, index):
    entry = first_attr(message, ["entry_identifier", "identifier"], "")
    if isinstance(entry, bytes):
        return entry.hex()
    if entry:
        return safe_text(entry)
    message_id = safe_text(first_attr(message, [
        "internet_message_identifier",
        "message_identifier"
    ], ""))
    if message_id:
        return message_id
    seed = f"{folder_path}|{index}|{safe_text(first_attr(message,['subject'],''))}|{format_dt(first_attr(message,['delivery_time','client_submit_time'],''))}"
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()


def clean_attachment_name(value):
    """Normalize an attachment filename while preserving its extension."""
    value = safe_text(value).strip().strip('"').strip("'")
    if not value:
        return ""
    # Content-Disposition values sometimes include filename=.
    match = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';]+)', value, re.I)
    if match:
        value = match.group(1).strip()
    value = value.replace("\\", "/").split("/")[-1]
    return safe_filename(value, "")


def attachment_property_value(attachment, names):
    """Read a value from pypff attributes or property-record style APIs."""
    value = first_attr(attachment, names, "")
    if value not in (None, ""):
        return value

    # Some pypff builds expose MAPI properties through record sets.
    property_ids = {
        # PR_ATTACH_LONG_FILENAME / PR_ATTACH_LONG_FILENAME_W
        0x3707,
        # PR_ATTACH_FILENAME / PR_ATTACH_FILENAME_W
        0x3704,
        # PR_DISPLAY_NAME / PR_DISPLAY_NAME_W
        0x3001,
        # PR_ATTACH_CONTENT_LOCATION / PR_ATTACH_CONTENT_LOCATION_W
        0x3713,
        # PR_ATTACH_MIME_TAG / PR_ATTACH_MIME_TAG_W
        0x370E,
    }
    try:
        count = int(first_attr(attachment, ["number_of_record_sets"], 0) or 0)
        for i in range(count):
            record_set = attachment.get_record_set(i)
            entries = int(first_attr(record_set, ["number_of_entries"], 0) or 0)
            for j in range(entries):
                entry = record_set.get_entry(j)
                identifier = first_attr(entry, ["entry_type", "identifier", "type"], None)
                try:
                    identifier = int(identifier)
                except Exception:
                    continue
                if identifier not in property_ids:
                    continue
                for attr in ("data_as_string", "value", "data"):
                    try:
                        result = getattr(entry, attr)
                        if callable(result):
                            result = result()
                        if result not in (None, "", b""):
                            if isinstance(result, bytes):
                                for enc in ("utf-16-le", "utf-8", "windows-1252"):
                                    try:
                                        return result.decode(enc).rstrip("\x00")
                                    except Exception:
                                        continue
                            return result
                    except Exception:
                        pass
    except Exception:
        pass
    return ""


def detect_file_extension(data):
    """Return a likely extension using common file signatures."""
    if not data:
        return ""
    signatures = [
        (b"%PDF-", ".pdf"),
        (b"\x89PNG\r\n\x1a\n", ".png"),
        (b"\xff\xd8\xff", ".jpg"),
        (b"GIF87a", ".gif"),
        (b"GIF89a", ".gif"),
        (b"PK\x03\x04", ".zip"),
        (b"PK\x05\x06", ".zip"),
        (b"PK\x07\x08", ".zip"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".ole"),
        (b"{\\rtf", ".rtf"),
        (b"SQLite format 3\x00", ".sqlite"),
        (b"MZ", ".exe"),
        (b"\x7fELF", ".elf"),
        (b"\x1f\x8b", ".gz"),
        (b"Rar!\x1a\x07", ".rar"),
        (b"7z\xbc\xaf\x27\x1c", ".7z"),
        (b"OggS", ".ogg"),
        (b"fLaC", ".flac"),
        (b"ID3", ".mp3"),
        (b"BM", ".bmp"),
        (b"II*\x00", ".tif"),
        (b"MM\x00*", ".tif"),
    ]
    for signature, extension in signatures:
        if data.startswith(signature):
            # ZIP containers may be Office Open XML files.
            if extension == ".zip":
                sample = data[:1024 * 1024]
                if b"word/" in sample:
                    return ".docx"
                if b"xl/" in sample:
                    return ".xlsx"
                if b"ppt/" in sample:
                    return ".pptx"
            if extension == ".ole":
                return ".doc"
            return extension

    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"hevc", b"mif1"):
            return ".heic"
        return ".mp4"
    return ""


def determine_attachment_name(attachment, index, data=None):
    """
    Find the best original attachment name from Outlook/MAPI metadata.
    Falls back to MIME type and finally file-signature analysis.
    """
    candidates = [
        attachment_property_value(attachment, [
            "long_filename",
            "long_file_name",
            "attachment_long_filename",
            "attach_long_filename",
        ]),
        attachment_property_value(attachment, [
            "filename",
            "file_name",
            "attachment_filename",
            "attach_filename",
            "short_filename",
        ]),
        attachment_property_value(attachment, [
            "display_name",
            "attachment_display_name",
            "name",
            "title",
        ]),
        attachment_property_value(attachment, [
            "content_location",
            "attachment_content_location",
        ]),
    ]

    for candidate in candidates:
        name = clean_attachment_name(candidate)
        if name and name.lower() not in {
            "attachment", "attachment.bin", "file", "unknown"
        }:
            return name

    mime = safe_text(attachment_property_value(
        attachment, ["mime_type", "mime_tag", "content_type"]
    )).split(";", 1)[0].strip().lower()

    extension = ""
    if mime:
        extension = mimetypes.guess_extension(mime) or ""
        # Prefer common Windows extensions over less familiar aliases.
        extension = {
            ".jpe": ".jpg",
            ".jpeg": ".jpg",
            ".htm": ".html",
            ".tiff": ".tif",
        }.get(extension, extension)

    if not extension and data is not None:
        extension = detect_file_extension(data)

    return f"attachment_{index + 1}{extension or '.bin'}"


def get_attachment_metadata(attachment, index, read_data=False):
    """Return the best filename, MIME type, size, and optionally payload."""
    mime = safe_text(attachment_property_value(
        attachment, ["mime_type", "mime_tag", "content_type"]
    )).split(";", 1)[0].strip()
    try:
        size = int(first_attr(attachment, ["size", "data_size"], 0) or 0)
    except Exception:
        size = 0

    data = attachment_bytes(attachment) if read_data else None
    name = determine_attachment_name(attachment, index, data)

    # If no useful extension was present, inspect the payload before settling on .bin.
    if Path(name).suffix.lower() == ".bin" and data is None:
        data = attachment_bytes(attachment)
        detected = detect_file_extension(data)
        if detected:
            name = str(Path(name).with_suffix(detected))

    return {
        "name": name,
        "mime": mime,
        "size": size or (len(data) if data is not None else 0),
        "data": data,
    }


def attachment_bytes(attachment):
    size = first_attr(attachment, ["size"], 0)
    try:
        size = int(size)
    except Exception:
        size = 0

    for name in ("read_buffer", "read"):
        try:
            method = getattr(attachment, name)
            if size > 0:
                data = method(size)
            else:
                chunks = []
                while True:
                    chunk = method(1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                data = b"".join(chunks)
            if data is not None:
                return bytes(data)
        except Exception:
            pass
    return b""


def message_to_eml(message):
    eml = EmailMessage(policy=default_policy)
    subject = safe_text(first_attr(message, ["subject", "conversation_topic"], ""))
    sender_name = safe_text(first_attr(message, ["sender_name"], ""))
    sender_addr = safe_text(first_attr(message, [
        "sender_email_address", "sent_representing_email_address"
    ], ""))
    recipients = collect_recipients(message)

    eml["Subject"] = subject
    if sender_name or sender_addr:
        eml["From"] = formataddr((sender_name, sender_addr)) if sender_addr else sender_name
    if recipients["to"]:
        eml["To"] = ", ".join(recipients["to"])
    if recipients["cc"]:
        eml["Cc"] = ", ".join(recipients["cc"])
    if recipients["bcc"]:
        eml["Bcc"] = ", ".join(recipients["bcc"])

    msgid = safe_text(first_attr(message, [
        "internet_message_identifier", "message_identifier"
    ], ""))
    if msgid:
        eml["Message-ID"] = msgid

    submit_time = first_attr(message, ["client_submit_time", "delivery_time"], None)
    if isinstance(submit_time, datetime):
        try:
            eml["Date"] = format_datetime(submit_time)
        except Exception:
            pass

    headers = get_transport_headers(message)
    if headers:
        for line in headers.replace("\r\n", "\n").split("\n"):
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value or key.lower() in {
                "subject", "from", "to", "cc", "bcc", "date", "message-id",
                "content-type", "mime-version", "content-transfer-encoding"
            }:
                continue
            try:
                eml[key] = value
            except Exception:
                pass

    plain = safe_text(first_attr(message, ["plain_text_body", "body"], ""))
    html_body = safe_text(first_attr(message, ["html_body"], ""))
    if html_body and plain:
        eml.set_content(plain)
        eml.add_alternative(html_body, subtype="html")
    elif html_body:
        eml.set_content("This message contains an HTML body.")
        eml.add_alternative(html_body, subtype="html")
    else:
        eml.set_content(plain)

    try:
        count = int(message.number_of_attachments)
    except Exception:
        count = 0
    for i in range(count):
        try:
            a = message.get_attachment(i)
            metadata = get_attachment_metadata(a, i, read_data=True)
            name = metadata["name"]
            data = metadata["data"] or b""
            maintype, subtype = "application", "octet-stream"
            mime = metadata["mime"]
            if "/" in mime:
                maintype, subtype = mime.split("/", 1)
            eml.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
        except Exception:
            continue
    return eml.as_bytes()


def normalize_body_text(value, decode_quoted_printable=True):
    """
    Create a readable display copy of a message body without modifying evidence.

    Handles:
      - actual CR/LF combinations
      - literal escaped sequences such as \\r\\n, \\n and \\t
      - common quoted-printable artifacts
      - non-breaking/zero-width characters
      - excessive blank lines
    """
    text = safe_text(value)
    if not text:
        return ""

    # Some PST bindings expose bytes through their repr-like string form.
    if (text.startswith("b'") and text.endswith("'")) or (
            text.startswith('b"') and text.endswith('"')):
        text = text[2:-1]

    # Convert literal escape sequences only when they are visibly present.
    # This avoids the corruption that a general unicode_escape decode can cause.
    replacements = (
        ("\\\\r\\\\n", "\n"),
        ("\\\\n\\\\r", "\n"),
        ("\\\\r", "\n"),
        ("\\\\n", "\n"),
        ("\\\\t", "\t"),
        ("\\r\\n", "\n"),
        ("\\n\\r", "\n"),
        ("\\r", "\n"),
    )
    for old, new in replacements:
        text = text.replace(old, new)

    # Decode quoted-printable only when the body strongly resembles it.
    if decode_quoted_printable and re.search(
        r"(?:=[0-9A-Fa-f]{2})|(?:=\n)|(?:=\r\n)", text
    ):
        try:
            raw = quopri.decodestring(text.encode("utf-8", "replace"))
            for encoding in ("utf-8", "windows-1252", "latin-1"):
                try:
                    decoded = raw.decode(encoding)
                    if decoded:
                        text = decoded
                        break
                except UnicodeDecodeError:
                    continue
        except Exception:
            pass

    text = html.unescape(text)
    text = text.replace("\u00a0", " ")
    text = text.replace("\u200b", "")
    text = text.replace("\ufeff", "")
    text = text.replace("\x00", "")
    text = text.replace("\x0b", "\n")
    text = text.replace("\x0c", "\n")

    # Normalize remaining physical line endings.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Remove trailing spaces but retain indentation and intentional line breaks.
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)

    # Keep paragraphs readable without allowing hundreds of empty lines.
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def normalize_html_source(value):
    """Clean escaped transport characters while retaining HTML markup."""
    text = safe_text(value)
    if not text:
        return ""
    for old, new in (
        ("\\\\r\\\\n", "\n"),
        ("\\\\n\\\\r", "\n"),
        ("\\\\r", "\n"),
        ("\\\\n", "\n"),
        ("\\\\t", "\t"),
    ):
        text = text.replace(old, new)
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")


def extract_rtf_display(message):
    """
    Return the best RTF/raw representation exposed by the installed pypff build.
    pypff versions differ in which RTF property names they expose.
    """
    value = first_attr(message, [
        "rtf_body",
        "rich_text_body",
        "rtf_compressed",
        "compressed_rtf_body",
        "rtf"
    ], "")
    if isinstance(value, bytes):
        # Compressed RTF may be binary. Preserve a readable forensic indication.
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return value.decode("windows-1252")
            except UnicodeDecodeError:
                return (
                    "[Binary or compressed RTF data]\n\n"
                    + value[:4096].hex(" ")
                )
    return normalize_body_text(value, decode_quoted_printable=False)


class RichTextHTMLParser(HTMLParser):
    """Render common HTML email formatting into a Tk Text widget."""

    BLOCK_TAGS = {
        "p", "div", "section", "article", "header", "footer", "blockquote",
        "table", "tr", "ul", "ol", "pre", "h1", "h2", "h3", "h4", "h5", "h6"
    }

    def __init__(self, widget):
        super().__init__(convert_charrefs=True)
        self.widget = widget
        self.tag_stack = []
        self.list_stack = []
        self.href_stack = []
        self.in_style_or_script = 0

    def _active_tags(self):
        tags = []
        for item in self.tag_stack:
            if item not in tags:
                tags.append(item)
        return tuple(tags)

    def _ensure_newline(self, count=1):
        current = self.widget.get("end-3c", "end-1c") if self.widget.index("end-1c") != "1.0" else ""
        needed = "\n" * count
        if count == 2:
            if current.endswith("\n\n"):
                return
            if current.endswith("\n"):
                self.widget.insert("end", "\n")
            else:
                self.widget.insert("end", "\n\n")
        elif not current.endswith("\n"):
            self.widget.insert("end", needed)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)
        if tag in ("style", "script", "head"):
            self.in_style_or_script += 1
            return
        if self.in_style_or_script:
            return

        if tag in self.BLOCK_TAGS:
            self._ensure_newline(2 if tag in ("p", "div", "blockquote") else 1)
        if tag == "br":
            self.widget.insert("end", "\n")
            return
        if tag in ("b", "strong"):
            self.tag_stack.append("bold")
        elif tag in ("i", "em"):
            self.tag_stack.append("italic")
        elif tag == "u":
            self.tag_stack.append("underline")
        elif tag in ("s", "strike", "del"):
            self.tag_stack.append("strike")
        elif tag in ("code", "tt", "pre"):
            self.tag_stack.append("mono")
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self.tag_stack.append(tag)
        elif tag == "blockquote":
            self.tag_stack.append("blockquote")
        elif tag == "a":
            href = attrs.get("href", "")
            self.href_stack.append(href)
            self.tag_stack.append("link")
        elif tag == "ul":
            self.list_stack.append(("ul", 0))
        elif tag == "ol":
            self.list_stack.append(("ol", 0))
        elif tag == "li":
            self._ensure_newline()
            if self.list_stack:
                kind, count = self.list_stack[-1]
                count += 1
                self.list_stack[-1] = (kind, count)
                bullet = "• " if kind == "ul" else f"{count}. "
            else:
                bullet = "• "
            self.widget.insert("end", "    " * max(len(self.list_stack) - 1, 0) + bullet,
                               self._active_tags())
        elif tag == "img":
            alt = attrs.get("alt") or attrs.get("title") or "embedded image"
            self.widget.insert("end", f"[Image: {alt}]", self._active_tags())

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ("style", "script", "head"):
            self.in_style_or_script = max(0, self.in_style_or_script - 1)
            return
        if self.in_style_or_script:
            return

        mapping = {
            "b": "bold", "strong": "bold",
            "i": "italic", "em": "italic",
            "u": "underline",
            "s": "strike", "strike": "strike", "del": "strike",
            "code": "mono", "tt": "mono", "pre": "mono",
            "blockquote": "blockquote",
            "h1": "h1", "h2": "h2", "h3": "h3",
            "h4": "h4", "h5": "h5", "h6": "h6",
            "a": "link",
        }
        style_tag = mapping.get(tag)
        if style_tag:
            for index in range(len(self.tag_stack) - 1, -1, -1):
                if self.tag_stack[index] == style_tag:
                    del self.tag_stack[index]
                    break
        if tag == "a" and self.href_stack:
            href = self.href_stack.pop()
            if href:
                self.widget.insert("end", f" <{href}>", ("link_url",))
        if tag in ("ul", "ol") and self.list_stack:
            self.list_stack.pop()
            self._ensure_newline()
        elif tag in self.BLOCK_TAGS or tag == "li":
            self._ensure_newline()

    def handle_data(self, data):
        if self.in_style_or_script or not data:
            return
        if "mono" not in self.tag_stack:
            data = re.sub(r"[ \t\r\f\v]+", " ", data)
        self.widget.insert("end", data, self._active_tags())


class BookmarkStore:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_sha256 TEXT NOT NULL,
                evidence_path TEXT NOT NULL,
                message_key TEXT NOT NULL,
                folder_path TEXT,
                subject TEXT,
                sender TEXT,
                recipients TEXT,
                message_date TEXT,
                category TEXT,
                note TEXT,
                created_utc TEXT NOT NULL,
                UNIQUE(evidence_sha256, message_key)
            )
        """)
        self.conn.commit()

    def add(self, record, category, note):
        self.conn.execute("""
            INSERT INTO bookmarks (
                evidence_sha256, evidence_path, message_key, folder_path,
                subject, sender, recipients, message_date, category, note,
                created_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(evidence_sha256, message_key) DO UPDATE SET
                category=excluded.category,
                note=excluded.note,
                subject=excluded.subject,
                sender=excluded.sender,
                recipients=excluded.recipients,
                message_date=excluded.message_date
        """, (
            record["evidence_sha256"], record["evidence_path"],
            record["message_key"], record["folder_path"], record["subject"],
            record["sender"], record["recipients"], record["date"],
            category, note
        ))
        self.conn.commit()

    def remove(self, evidence_sha256, message_key):
        self.conn.execute(
            "DELETE FROM bookmarks WHERE evidence_sha256=? AND message_key=?",
            (evidence_sha256, message_key)
        )
        self.conn.commit()

    def contains(self, evidence_sha256, message_key):
        row = self.conn.execute(
            "SELECT 1 FROM bookmarks WHERE evidence_sha256=? AND message_key=?",
            (evidence_sha256, message_key)
        ).fetchone()
        return bool(row)

    def rows(self, evidence_sha256=None):
        sql = """SELECT folder_path, subject, sender, recipients, message_date,
                        category, note, message_key, evidence_path, evidence_sha256,
                        created_utc
                 FROM bookmarks"""
        args = ()
        if evidence_sha256:
            sql += " WHERE evidence_sha256=?"
            args = (evidence_sha256,)
        sql += " ORDER BY created_utc DESC"
        return self.conn.execute(sql, args).fetchall()

    def close(self):
        self.conn.close()


class PSTExplorer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{SCRIPT_NAME} v{SCRIPT_VERSION}")
        self.geometry("1600x920")
        self.minsize(1100, 700)

        self.store = None
        self.pst = None
        self.pst_path = ""
        self.pst_sha256 = ""
        self.pst_md5 = ""
        self.folder_objects = {}
        self.message_records = []
        self.record_by_iid = {}
        self.current_record = None
        self.queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker = None
        self.bookmarks = None
        self.attachment_by_iid = {}
        self.attachment_tempdir = tempfile.TemporaryDirectory(prefix="FFTX_PST_Attachments_")

        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.folder_status = tk.StringVar(value="No PST/OST open")
        self.bookmark_only = tk.BooleanVar(value=False)

        self.build_style()
        self.build_menu()
        self.build_ui()
        self.after(100, self.poll_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Status.TLabel", relief="sunken", anchor="w", padding=(6, 3))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))

    def build_menu(self):
        m = tk.Menu(self)
        filem = tk.Menu(m, tearoff=False)
        filem.add_command(label="Open PST/OST...", command=self.open_dialog)
        filem.add_separator()
        filem.add_command(label="Export Selected as EML...", command=self.export_selected_eml)
        filem.add_command(label="Export Selected as MSG...", command=self.export_selected_msg)
        filem.add_command(label="Export Current Folder as EML...", command=self.export_folder_eml)
        filem.add_command(label="Export Entire Store as EML...", command=self.export_store_eml)
        filem.add_separator()
        filem.add_command(label="Export Bookmarks CSV...", command=self.export_bookmarks_csv)
        filem.add_command(label="Export Bookmarks JSON...", command=self.export_bookmarks_json)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.on_close)
        m.add_cascade(label="File", menu=filem)

        bm = tk.Menu(m, tearoff=False)
        bm.add_command(label="Bookmark Selected...", command=self.bookmark_selected)
        bm.add_command(label="Remove Bookmark", command=self.remove_bookmark)
        bm.add_command(label="Show Bookmark Manager", command=self.show_bookmarks)
        m.add_cascade(label="Bookmarks", menu=bm)

        helpm = tk.Menu(m, tearoff=False)
        helpm.add_command(label="Dependency Status", command=self.dependency_status)
        helpm.add_command(label="Evidence File Hashes...", command=self.show_evidence_hashes)
        helpm.add_separator()
        helpm.add_command(label="About", command=self.about)
        m.add_cascade(label="Help", menu=helpm)
        self.config(menu=m)

    def build_ui(self):
        outer = ttk.Frame(self, padding=8)
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer)
        head.pack(fill="x", pady=(0, 7))
        ttk.Label(head, text=SCRIPT_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(head, textvariable=self.folder_status).pack(side="right")

        toolbar = ttk.Frame(outer)
        toolbar.pack(fill="x", pady=(0, 7))
        ttk.Button(toolbar, text="Open PST/OST", style="Primary.TButton",
                   command=self.open_dialog).pack(side="left")
        ttk.Button(toolbar, text="Bookmark", command=self.bookmark_selected).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Export EML", command=self.export_selected_eml).pack(side="left")
        ttk.Button(toolbar, text="Export MSG", command=self.export_selected_msg).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Bookmarks", command=self.show_bookmarks).pack(side="left")
        ttk.Label(toolbar, text="Search:").pack(side="left", padx=(25, 4))
        search = ttk.Entry(toolbar, textvariable=self.search_var)
        search.pack(side="left", fill="x", expand=True)
        search.bind("<Return>", lambda e: self.apply_filter())
        ttk.Button(toolbar, text="Search", command=self.apply_filter).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Clear", command=self.clear_filter).pack(side="left")
        ttk.Checkbutton(toolbar, text="Bookmarks only", variable=self.bookmark_only,
                        command=self.apply_filter).pack(side="left", padx=(10, 0))

        main = ttk.Panedwindow(outer, orient="horizontal")
        main.pack(fill="both", expand=True)

        left = ttk.Frame(main)
        center = ttk.Frame(main)
        main.add(left, weight=1)
        main.add(center, weight=4)

        ttk.Label(left, text="Mail Store Folders").pack(anchor="w")
        self.folder_tree = ttk.Treeview(left, show="tree")
        fy = ttk.Scrollbar(left, orient="vertical", command=self.folder_tree.yview)
        self.folder_tree.configure(yscrollcommand=fy.set)
        self.folder_tree.pack(side="left", fill="both", expand=True)
        fy.pack(side="right", fill="y")
        self.folder_tree.bind("<<TreeviewSelect>>", self.folder_selected)

        vertical = ttk.Panedwindow(center, orient="vertical")
        vertical.pack(fill="both", expand=True)

        gridframe = ttk.Frame(vertical)
        previewframe = ttk.Frame(vertical)
        vertical.add(gridframe, weight=3)
        vertical.add(previewframe, weight=2)

        columns = ("bookmark", "date", "from", "to", "subject", "attachments", "message_id")
        self.message_tree = ttk.Treeview(gridframe, columns=columns, show="headings",
                                         selectmode="extended")
        settings = [
            ("bookmark", "★", 40),
            ("date", "Date", 170),
            ("from", "From", 220),
            ("to", "To", 220),
            ("subject", "Subject", 360),
            ("attachments", "Attachments", 90),
            ("message_id", "Message-ID", 300),
        ]
        for key, title, width in settings:
            self.message_tree.heading(key, text=title)
            self.message_tree.column(key, width=width, minwidth=40)
        gy = ttk.Scrollbar(gridframe, orient="vertical", command=self.message_tree.yview)
        gx = ttk.Scrollbar(gridframe, orient="horizontal", command=self.message_tree.xview)
        self.message_tree.configure(yscrollcommand=gy.set, xscrollcommand=gx.set)
        self.message_tree.grid(row=0, column=0, sticky="nsew")
        gy.grid(row=0, column=1, sticky="ns")
        gx.grid(row=1, column=0, sticky="ew")
        gridframe.rowconfigure(0, weight=1)
        gridframe.columnconfigure(0, weight=1)
        self.message_tree.bind("<<TreeviewSelect>>", self.message_selected)
        self.message_tree.bind("<Double-1>", lambda e: self.bookmark_selected())

        self.preview_notebook = ttk.Notebook(previewframe)
        self.preview_notebook.pack(fill="both", expand=True)
        self.preview_text = self.add_rich_text_tab("Formatted")
        self.plain_text_view = self.add_text_tab("Plain Text")
        self.html_source_view = self.add_text_tab("HTML Source")
        self.rtf_raw_view = self.add_text_tab("RTF / Raw")
        self.headers_text = self.add_text_tab("Headers")
        self.attach_tree = self.add_attachment_tab()
        self.properties_text = self.add_text_tab("Properties")

        self.progress = ttk.Progressbar(outer, mode="determinate")
        self.progress.pack(fill="x", pady=(7, 0))
        ttk.Label(outer, textvariable=self.status_var,
                  style="Status.TLabel").pack(fill="x", pady=(3, 0))

        context = tk.Menu(self.message_tree, tearoff=False)
        context.add_command(label="Bookmark Selected...", command=self.bookmark_selected)
        context.add_command(label="Remove Bookmark", command=self.remove_bookmark)
        context.add_separator()
        context.add_command(label="Export Selected as EML...", command=self.export_selected_eml)
        context.add_command(label="Export Selected as MSG...", command=self.export_selected_msg)
        self.message_tree.bind("<Button-3>", lambda e: self.popup_menu(e, context))

    def add_rich_text_tab(self, title):
        frame = ttk.Frame(self.preview_notebook)
        self.preview_notebook.add(frame, text=title)
        text = tk.Text(frame, wrap="word", font=("Segoe UI", 10), padx=10, pady=8)
        y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=y.set)
        text.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")

        text.tag_configure("header_label", font=("Segoe UI", 9, "bold"))
        text.tag_configure("header_value", font=("Segoe UI", 9))
        text.tag_configure("separator", foreground="#777777")
        text.tag_configure("bold", font=("Segoe UI", 10, "bold"))
        text.tag_configure("italic", font=("Segoe UI", 10, "italic"))
        text.tag_configure("underline", underline=True)
        text.tag_configure("strike", overstrike=True)
        text.tag_configure("mono", font=("Consolas", 10))
        text.tag_configure("h1", font=("Segoe UI", 18, "bold"), spacing1=8, spacing3=5)
        text.tag_configure("h2", font=("Segoe UI", 16, "bold"), spacing1=7, spacing3=4)
        text.tag_configure("h3", font=("Segoe UI", 14, "bold"), spacing1=6, spacing3=3)
        text.tag_configure("h4", font=("Segoe UI", 12, "bold"))
        text.tag_configure("h5", font=("Segoe UI", 11, "bold"))
        text.tag_configure("h6", font=("Segoe UI", 10, "bold"))
        text.tag_configure("blockquote", lmargin1=25, lmargin2=25, foreground="#555555")
        text.tag_configure("link", foreground="#0645AD", underline=True)
        text.tag_configure("link_url", foreground="#666666", font=("Segoe UI", 8))
        return text

    def add_text_tab(self, title):
        frame = ttk.Frame(self.preview_notebook)
        self.preview_notebook.add(frame, text=title)
        text = tk.Text(frame, wrap="word", font=("Consolas", 10))
        y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=y.set)
        text.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")
        return text

    def add_attachment_tab(self):
        frame = ttk.Frame(self.preview_notebook)
        self.preview_notebook.add(frame, text="Attachments")

        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 4))
        ttk.Label(bar, text="Double-click an attachment to extract and open it.").pack(side="left")
        ttk.Button(bar, text="Open Selected", command=self.open_selected_attachment).pack(side="right")
        ttk.Button(bar, text="Save Selected As...", command=self.save_selected_attachment).pack(
            side="right", padx=5)

        tree = ttk.Treeview(
            frame, columns=("name", "extension", "size", "mime"), show="headings",
            selectmode="browse"
        )
        tree.heading("name", text="Attachment Name")
        tree.heading("extension", text="Type")
        tree.heading("size", text="Size (bytes)")
        tree.heading("mime", text="MIME Type")
        tree.column("name", width=500)
        tree.column("extension", width=90)
        tree.column("size", width=120, anchor="e")
        tree.column("mime", width=240)
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=y.set)
        tree.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")
        tree.bind("<Double-1>", self.open_selected_attachment)

        menu = tk.Menu(tree, tearoff=False)
        menu.add_command(label="Open Attachment", command=self.open_selected_attachment)
        menu.add_command(label="Save Attachment As...", command=self.save_selected_attachment)
        tree.bind("<Button-3>", lambda e: self.popup_attachment_menu(e, menu))
        return tree

    def popup_menu(self, event, menu):
        row = self.message_tree.identify_row(event.y)
        if row and row not in self.message_tree.selection():
            self.message_tree.selection_set(row)
        menu.tk_popup(event.x_root, event.y_root)

    def popup_attachment_menu(self, event, menu):
        row = self.attach_tree.identify_row(event.y)
        if row:
            self.attach_tree.selection_set(row)
            self.attach_tree.focus(row)
            menu.tk_popup(event.x_root, event.y_root)

    def selected_attachment(self):
        selection = self.attach_tree.selection()
        if not selection:
            return None
        return self.attachment_by_iid.get(selection[0])

    def attachment_payload(self, item):
        if not item:
            return b""
        data = item.get("data")
        if data is None:
            data = attachment_bytes(item["attachment"])
            item["data"] = data
            if Path(item["name"]).suffix.lower() == ".bin":
                detected = detect_file_extension(data)
                if detected:
                    item["name"] = str(Path(item["name"]).with_suffix(detected))
        return data

    def unique_attachment_path(self, folder, name):
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        candidate = folder / safe_filename(name, "attachment.bin")
        stem, suffix = candidate.stem, candidate.suffix
        counter = 2
        while candidate.exists():
            candidate = folder / f"{stem}_{counter}{suffix}"
            counter += 1
        return candidate

    def open_selected_attachment(self, event=None):
        item = self.selected_attachment()
        if not item:
            messagebox.showinfo("Attachment", "Select an attachment first.", parent=self)
            return
        try:
            payload = self.attachment_payload(item)
            path = self.unique_attachment_path(
                self.attachment_tempdir.name, item["name"]
            )
            path.write_bytes(payload)
            if os.name == "nt":
                os.startfile(str(path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
            self.status_var.set(f"Opened attachment: {item['name']}")
        except Exception as exc:
            messagebox.showerror(
                "Attachment Open Error",
                f"Unable to open the attachment with its associated application.\n\n{exc}",
                parent=self
            )

    def save_selected_attachment(self):
        item = self.selected_attachment()
        if not item:
            messagebox.showinfo("Attachment", "Select an attachment first.", parent=self)
            return
        self.attachment_payload(item)
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save Attachment As",
            initialfile=safe_filename(item["name"], "attachment.bin"),
            defaultextension=Path(item["name"]).suffix
        )
        if not path:
            return
        try:
            Path(path).write_bytes(self.attachment_payload(item))
            self.status_var.set(f"Saved attachment: {path}")
        except Exception as exc:
            messagebox.showerror("Attachment Save Error", str(exc), parent=self)

    def show_evidence_hashes(self):
        if not self.pst_path:
            messagebox.showinfo(
                "Evidence File Hashes",
                "Open a PST or OST file first.",
                parent=self
            )
            return

        win = tk.Toplevel(self)
        win.title("Evidence File Hashes")
        win.geometry("850x360")
        win.transient(self)

        body = ttk.Frame(win, padding=12)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Evidence file", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        path_box = tk.Text(body, height=2, wrap="word", font=("Consolas", 10))
        path_box.pack(fill="x", pady=(3, 10))
        path_box.insert("1.0", self.pst_path)
        path_box.configure(state="disabled")

        ttk.Label(body, text="MD5", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        md5_entry = ttk.Entry(body, font=("Consolas", 10))
        md5_entry.pack(fill="x", pady=(3, 10))
        md5_entry.insert(0, self.pst_md5)
        md5_entry.configure(state="readonly")

        ttk.Label(body, text="SHA-256", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        sha_entry = ttk.Entry(body, font=("Consolas", 10))
        sha_entry.pack(fill="x", pady=(3, 10))
        sha_entry.insert(0, self.pst_sha256)
        sha_entry.configure(state="readonly")

        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(
            buttons, text="Copy MD5",
            command=lambda: self.copy_to_clipboard(self.pst_md5)
        ).pack(side="left")
        ttk.Button(
            buttons, text="Copy SHA-256",
            command=lambda: self.copy_to_clipboard(self.pst_sha256)
        ).pack(side="left", padx=5)
        ttk.Button(
            buttons, text="Copy Both",
            command=lambda: self.copy_to_clipboard(
                f"MD5: {self.pst_md5}\nSHA-256: {self.pst_sha256}"
            )
        ).pack(side="left")
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")

    def copy_to_clipboard(self, value):
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()
        self.status_var.set("Hash copied to clipboard.")

    def dependency_status(self):
        msg = [
            f"pypff/libpff: {'Available' if pypff else 'NOT AVAILABLE'}",
            f"Microsoft Outlook COM export: {'Available' if win32com else 'NOT AVAILABLE'}",
            "",
            "PST/OST reading requires pypff.",
            "MSG export requires Windows, Microsoft Outlook, and pywin32."
        ]
        messagebox.showinfo("Dependency Status", "\n".join(msg), parent=self)

    def about(self):
        messagebox.showinfo(
            "About",
            f"{SCRIPT_NAME} v{SCRIPT_VERSION}\n\n"
            "Read-only PST/OST exploration with selectable Formatted, Plain Text, "
            "HTML Source, and RTF/Raw views; original MAPI attachment filename "
            "recovery, attachment viewing, bookmarks, evidence hashes, and EML/MSG export.\n\n"
            "The original evidence store is never modified.",
            parent=self
        )

    def open_dialog(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Open Outlook PST or OST",
            filetypes=[("Outlook stores", "*.pst *.ost"), ("PST", "*.pst"),
                       ("OST", "*.ost"), ("All files", "*.*")]
        )
        if path:
            self.open_store(path)

    def open_store(self, path):
        if pypff is None:
            messagebox.showerror(
                "pypff Required",
                "This utility requires the pypff Python module from libpff to "
                "read PST or OST files.\n\nThe graphical interface and export "
                "workflow are installed, but the mail store cannot be opened "
                "until pypff is available.",
                parent=self
            )
            return

        self.close_store()
        self.status_var.set("Calculating evidence SHA-256...")
        self.update_idletasks()
        try:
            evidence_md5, evidence_hash = hash_file(path)
            from pathlib import Path as _P
            open_path = str(_P(path).expanduser().resolve(strict=False))
            if open_path.startswith('\\\\?\\'):
                open_path = open_path[4:]
            if not os.path.exists(open_path):
                raise FileNotFoundError(f'PST/OST file not found: {open_path}')
            pst = pypff.file()
            try:
                pst.open(open_path)
            except Exception:
                pst.open(os.path.normpath(open_path))
            self.pst = pst
            self.pst_path = open_path
            self.pst_sha256 = evidence_hash
            self.pst_md5 = evidence_md5
            sidecar = Path(path).with_suffix(Path(path).suffix + ".fftx_bookmarks.sqlite")
            self.bookmarks = BookmarkStore(sidecar)
            self.folder_status.set(f"{Path(path).name} | SHA-256: {evidence_hash[:16]}…")
            self.populate_folders()
            self.status_var.set(f"Opened read-only: {path}")
        except Exception as exc:
            self.close_store()
            messagebox.showerror("Open Error", str(exc), parent=self)
            self.status_var.set("Open failed.")

    def close_store(self):
        self.cancel_event.set()
        if self.bookmarks:
            try:
                self.bookmarks.close()
            except Exception:
                pass
        self.bookmarks = None
        if self.pst:
            try:
                self.pst.close()
            except Exception:
                pass
        self.pst = None
        self.pst_path = ""
        self.pst_sha256 = ""
        self.pst_md5 = ""
        self.folder_objects.clear()
        self.message_records.clear()
        self.record_by_iid.clear()
        for tree in (getattr(self, "folder_tree", None), getattr(self, "message_tree", None)):
            if tree:
                for item in tree.get_children():
                    tree.delete(item)

    def populate_folders(self):
        for item in self.folder_tree.get_children():
            self.folder_tree.delete(item)
        self.folder_objects.clear()
        root = self.pst.get_root_folder()

        def add_folder(folder, parent_iid="", path_parts=None):
            path_parts = path_parts or []
            name = safe_text(first_attr(folder, ["name"], "(Unnamed Folder)"))
            parts = path_parts + [name]
            folder_path = "\\".join(parts)
            iid = self.folder_tree.insert(parent_iid, "end", text=name, open=(parent_iid == ""))
            self.folder_objects[iid] = (folder, folder_path)
            try:
                count = int(folder.number_of_sub_folders)
            except Exception:
                count = 0
            for i in range(count):
                try:
                    add_folder(folder.get_sub_folder(i), iid, parts)
                except Exception:
                    continue

        add_folder(root)
        roots = self.folder_tree.get_children()
        if roots:
            self.folder_tree.selection_set(roots[0])
            self.folder_tree.focus(roots[0])
            self.folder_selected()

    def folder_selected(self, event=None):
        selection = self.folder_tree.selection()
        if not selection:
            return
        folder, folder_path = self.folder_objects[selection[0]]
        self.load_folder(folder, folder_path)

    def load_folder(self, folder, folder_path):
        self.message_records.clear()
        self.record_by_iid.clear()
        for item in self.message_tree.get_children():
            self.message_tree.delete(item)
        try:
            total = int(folder.number_of_sub_messages)
        except Exception:
            total = 0
        self.progress.configure(maximum=max(total, 1), value=0)
        self.status_var.set(f"Loading {total:,} messages from {folder_path}...")
        self.update_idletasks()

        for i in range(total):
            try:
                msg = folder.get_sub_message(i)
                recipients = collect_recipients(msg)
                sender_name = safe_text(first_attr(msg, ["sender_name"], ""))
                sender_addr = safe_text(first_attr(msg, [
                    "sender_email_address", "sent_representing_email_address"
                ], ""))
                sender = formataddr((sender_name, sender_addr)) if sender_addr else sender_name
                date = format_dt(first_attr(msg, [
                    "delivery_time", "client_submit_time", "creation_time"
                ], ""))
                key = message_identity(folder_path, msg, i)
                try:
                    acount = int(msg.number_of_attachments)
                except Exception:
                    acount = 0
                record = {
                    "message": msg,
                    "message_key": key,
                    "folder_path": folder_path,
                    "subject": safe_text(first_attr(msg, ["subject", "conversation_topic"], "")),
                    "sender": sender,
                    "recipients": ", ".join(recipients["to"]),
                    "cc": ", ".join(recipients["cc"]),
                    "bcc": ", ".join(recipients["bcc"]),
                    "date": date,
                    "message_id": safe_text(first_attr(msg, [
                        "internet_message_identifier", "message_identifier"
                    ], "")),
                    "attachments": acount,
                    "evidence_sha256": self.pst_sha256,
                    "evidence_path": self.pst_path,
                }
                self.message_records.append(record)
            except Exception as exc:
                continue
            self.progress["value"] = i + 1
            if i % 50 == 0:
                self.update_idletasks()
        self.apply_filter()
        self.status_var.set(f"Loaded {len(self.message_records):,} messages from {folder_path}.")

    def apply_filter(self):
        query = self.search_var.get().strip().lower()
        for item in self.message_tree.get_children():
            self.message_tree.delete(item)
        self.record_by_iid.clear()

        for record in self.message_records:
            if self.bookmark_only.get() and self.bookmarks and not self.bookmarks.contains(
                    self.pst_sha256, record["message_key"]):
                continue
            hay = " ".join([
                record["subject"], record["sender"], record["recipients"],
                record["cc"], record["bcc"], record["message_id"], record["date"]
            ]).lower()
            if query and query not in hay:
                continue
            starred = "★" if self.bookmarks and self.bookmarks.contains(
                self.pst_sha256, record["message_key"]) else ""
            iid = self.message_tree.insert("", "end", values=(
                starred, record["date"], record["sender"], record["recipients"],
                record["subject"], record["attachments"], record["message_id"]
            ))
            self.record_by_iid[iid] = record
        self.status_var.set(f"Showing {len(self.record_by_iid):,} message(s).")

    def clear_filter(self):
        self.search_var.set("")
        self.bookmark_only.set(False)
        self.apply_filter()

    def selected_records(self):
        return [self.record_by_iid[i] for i in self.message_tree.selection()
                if i in self.record_by_iid]

    def message_selected(self, event=None):
        records = self.selected_records()
        if not records:
            return
        record = records[0]
        self.current_record = record
        msg = record["message"]
        plain_raw = safe_text(first_attr(msg, ["plain_text_body", "body"], ""))
        html_raw = safe_text(first_attr(msg, ["html_body"], ""))
        rtf_raw = extract_rtf_display(msg)

        plain = normalize_body_text(plain_raw)
        html_body = normalize_html_source(html_raw)

        self.render_formatted_preview(record, plain, html_body)
        self.set_text(
            self.plain_text_view,
            plain or self.html_to_readable_text(html_body) or "[No plain-text body available]"
        )
        self.set_text(
            self.html_source_view,
            html_body or "[No HTML body available]"
        )
        self.set_text(
            self.rtf_raw_view,
            rtf_raw or "[No RTF/raw body property exposed by this pypff build]"
        )
        self.set_text(self.headers_text, normalize_body_text(
            get_transport_headers(msg), decode_quoted_printable=False
        ))
        props = {
            "Message Key": record["message_key"],
            "Evidence Path": self.pst_path,
            "Evidence MD5": self.pst_md5,
            "Evidence SHA-256": self.pst_sha256,
            "Folder": record["folder_path"],
            "Subject": record["subject"],
            "Sender": record["sender"],
            "Recipients": record["recipients"],
            "CC": record["cc"],
            "BCC": record["bcc"],
            "Date": record["date"],
            "Message-ID": record["message_id"],
            "Attachment Count": record["attachments"],
            "Body Format": (
                "HTML/Rich Text" if html_body
                else "Plain Text" if plain
                else "RTF/Raw" if rtf_raw
                else "Unavailable"
            ),
            "Available Views": ", ".join(
                name for name, available in (
                    ("Formatted", bool(html_body or plain)),
                    ("Plain Text", bool(plain or html_body)),
                    ("HTML Source", bool(html_body)),
                    ("RTF / Raw", bool(rtf_raw)),
                ) if available
            ),
        }
        self.set_text(
            self.properties_text,
            "\n".join(f"{k}: {v}" for k, v in props.items())
        )

        self.attachment_by_iid.clear()
        for item in self.attach_tree.get_children():
            self.attach_tree.delete(item)
        try:
            count = int(msg.number_of_attachments)
        except Exception:
            count = 0
        for i in range(count):
            try:
                attachment = msg.get_attachment(i)
                metadata = get_attachment_metadata(attachment, i, read_data=False)
                name = metadata["name"]
                size = metadata["size"]
                mime = metadata["mime"]
                extension = Path(name).suffix.lower().lstrip(".").upper() or "FILE"
                iid = self.attach_tree.insert(
                    "", "end", values=(name, extension, size, mime)
                )
                self.attachment_by_iid[iid] = {
                    "attachment": attachment,
                    "name": name,
                    "size": size,
                    "mime": mime,
                    "data": metadata["data"],
                    "index": i,
                }
            except Exception:
                pass

    def html_to_readable_text(self, html_body):
        """Produce a readable plain-text fallback from HTML."""
        if not html_body:
            return ""
        value = re.sub(r"(?is)<(script|style|head).*?>.*?</\1>", "", html_body)
        value = re.sub(r"(?i)<br\s*/?>", "\n", value)
        value = re.sub(r"(?i)</(?:p|div|li|tr|h[1-6]|blockquote)>", "\n", value)
        value = re.sub(r"(?is)<[^>]+>", "", value)
        return normalize_body_text(value)

    def render_formatted_preview(self, record, plain, html_body):
        widget = self.preview_text
        widget.configure(state="normal")
        widget.delete("1.0", "end")

        header_rows = [
            ("Subject", record["subject"]),
            ("From", record["sender"]),
            ("To", record["recipients"]),
            ("CC", record["cc"]),
            ("Date", record["date"]),
            ("Message-ID", record["message_id"]),
            ("Folder", record["folder_path"]),
            (
                "Bookmarked",
                "Yes" if self.bookmarks and self.bookmarks.contains(
                    self.pst_sha256, record["message_key"]
                ) else "No"
            ),
        ]
        for label, value in header_rows:
            if value:
                widget.insert("end", f"{label}: ", ("header_label",))
                widget.insert("end", f"{value}\n", ("header_value",))
        widget.insert("end", "\n" + "─" * 100 + "\n\n", ("separator",))

        if html_body:
            try:
                parser = RichTextHTMLParser(widget)
                parser.feed(html_body)
                parser.close()
            except Exception:
                widget.insert(
                    "end",
                    plain or self.html_to_readable_text(html_body)
                )
        else:
            widget.insert(
                "end",
                plain or "[No readable HTML or plain-text body available]"
            )
        widget.configure(state="disabled")
        widget.see("1.0")

    def set_text(self, widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", safe_text(value))
        widget.configure(state="disabled")

    def bookmark_selected(self):
        records = self.selected_records()
        if not records or not self.bookmarks:
            messagebox.showinfo("Bookmark", "Select one or more messages.", parent=self)
            return
        category = simpledialog.askstring(
            "Bookmark Category",
            "Category:", initialvalue="Pertinent", parent=self
        )
        if category is None:
            return
        note = simpledialog.askstring(
            "Bookmark Note",
            "Optional note:", initialvalue="", parent=self
        )
        if note is None:
            note = ""
        for record in records:
            self.bookmarks.add(record, category.strip() or "Pertinent", note)
        self.apply_filter()
        self.status_var.set(f"Bookmarked {len(records):,} message(s).")

    def remove_bookmark(self):
        records = self.selected_records()
        if not records or not self.bookmarks:
            return
        for record in records:
            self.bookmarks.remove(self.pst_sha256, record["message_key"])
        self.apply_filter()
        self.status_var.set(f"Removed {len(records):,} bookmark(s).")

    def show_bookmarks(self):
        if not self.bookmarks:
            messagebox.showinfo("Bookmarks", "Open a PST or OST first.", parent=self)
            return
        win = tk.Toplevel(self)
        win.title("Bookmark Manager")
        win.geometry("1200x550")
        cols = ("folder", "subject", "sender", "date", "category", "note", "created")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        widths = [240, 300, 220, 160, 130, 300, 160]
        for c, w in zip(cols, widths):
            tree.heading(c, text=c.replace("_", " ").title())
            tree.column(c, width=w)
        y = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        x = ttk.Scrollbar(win, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)
        for row in self.bookmarks.rows(self.pst_sha256):
            folder, subject, sender, recipients, date, category, note, key, ep, eh, created = row
            tree.insert("", "end", values=(
                folder, subject, sender, date, category, note, created
            ))

    def unique_export_path(self, folder, record, ext, index):
        datepart = re.sub(r"[^0-9]", "", record["date"])[:14] or "undated"
        base = f"{datepart}_{safe_filename(record['subject'], 'No Subject')}_{index:06d}"
        return Path(folder) / f"{base}.{ext}"

    def export_records_eml(self, records, destination, preserve_folder=False):
        if not records:
            return 0
        exported = 0
        for index, record in enumerate(records, 1):
            outdir = Path(destination)
            if preserve_folder:
                parts = [safe_filename(p, "folder") for p in record["folder_path"].split("\\") if p]
                outdir = outdir.joinpath(*parts)
            outdir.mkdir(parents=True, exist_ok=True)
            path = self.unique_export_path(outdir, record, "eml", index)
            path.write_bytes(message_to_eml(record["message"]))
            exported += 1
        return exported

    def export_selected_eml(self):
        records = self.selected_records()
        if not records:
            messagebox.showinfo("Export EML", "Select one or more messages.", parent=self)
            return
        dest = filedialog.askdirectory(parent=self, title="Export Selected Messages as EML")
        if not dest:
            return
        try:
            count = self.export_records_eml(records, dest)
            self.status_var.set(f"Exported {count:,} EML file(s) to {dest}")
        except Exception as exc:
            messagebox.showerror("EML Export Error", str(exc), parent=self)

    def export_selected_msg(self):
        records = self.selected_records()
        if not records:
            messagebox.showinfo("Export MSG", "Select one or more messages.", parent=self)
            return
        if win32com is None:
            messagebox.showerror(
                "MSG Export Unavailable",
                "MSG export requires Windows, Microsoft Outlook, and pywin32.\n\n"
                "EML export remains available without Outlook.",
                parent=self
            )
            return
        dest = filedialog.askdirectory(parent=self, title="Export Selected Messages as MSG")
        if not dest:
            return
        try:
            outlook = win32com.client.Dispatch("Outlook.Application")
            exported = 0
            with tempfile.TemporaryDirectory() as temp:
                for index, record in enumerate(records, 1):
                    eml_path = self.unique_export_path(temp, record, "eml", index)
                    eml_path.write_bytes(message_to_eml(record["message"]))
                    item = outlook.Session.OpenSharedItem(str(eml_path))
                    msg_path = self.unique_export_path(dest, record, "msg", index)
                    item.SaveAs(str(msg_path), 9)  # olMSGUnicode
                    item.Close(0)
                    exported += 1
            self.status_var.set(f"Exported {exported:,} MSG file(s) to {dest}")
        except Exception as exc:
            messagebox.showerror("MSG Export Error", str(exc), parent=self)

    def export_folder_eml(self):
        if not self.message_records:
            messagebox.showinfo("Export Folder", "Select a folder containing messages.", parent=self)
            return
        dest = filedialog.askdirectory(parent=self, title="Export Current Folder as EML")
        if not dest:
            return
        try:
            count = self.export_records_eml(self.message_records, dest)
            self.status_var.set(f"Exported {count:,} EML file(s).")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc), parent=self)

    def all_records(self):
        records = []
        for iid, (folder, folder_path) in self.folder_objects.items():
            try:
                count = int(folder.number_of_sub_messages)
            except Exception:
                count = 0
            for i in range(count):
                try:
                    msg = folder.get_sub_message(i)
                    recipients = collect_recipients(msg)
                    sender_name = safe_text(first_attr(msg, ["sender_name"], ""))
                    sender_addr = safe_text(first_attr(msg, ["sender_email_address"], ""))
                    sender = formataddr((sender_name, sender_addr)) if sender_addr else sender_name
                    records.append({
                        "message": msg,
                        "message_key": message_identity(folder_path, msg, i),
                        "folder_path": folder_path,
                        "subject": safe_text(first_attr(msg, ["subject"], "")),
                        "sender": sender,
                        "recipients": ", ".join(recipients["to"]),
                        "cc": ", ".join(recipients["cc"]),
                        "bcc": ", ".join(recipients["bcc"]),
                        "date": format_dt(first_attr(msg, ["delivery_time", "client_submit_time"], "")),
                        "message_id": safe_text(first_attr(msg, ["internet_message_identifier"], "")),
                        "attachments": int(first_attr(msg, ["number_of_attachments"], 0) or 0),
                        "evidence_sha256": self.pst_sha256,
                        "evidence_path": self.pst_path,
                    })
                except Exception:
                    pass
        return records

    def export_store_eml(self):
        if not self.pst:
            return
        dest = filedialog.askdirectory(parent=self, title="Export Entire Store as EML")
        if not dest:
            return
        try:
            self.status_var.set("Enumerating entire store...")
            self.update_idletasks()
            records = self.all_records()
            count = self.export_records_eml(records, dest, preserve_folder=True)
            self.status_var.set(f"Exported {count:,} EML file(s), preserving folder structure.")
        except Exception as exc:
            messagebox.showerror("Store Export Error", str(exc), parent=self)

    def export_bookmarks_csv(self):
        if not self.bookmarks:
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".csv",
            initialfile="PST_Bookmarks.csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return
        rows = self.bookmarks.rows(self.pst_sha256)
        headers = [
            "Folder", "Subject", "Sender", "Recipients", "Message Date",
            "Category", "Note", "Message Key", "Evidence Path",
            "Evidence SHA-256", "Created UTC"
        ]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(headers)
            w.writerows(rows)
        self.status_var.set(f"Bookmarks exported to {path}")

    def export_bookmarks_json(self):
        if not self.bookmarks:
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".json",
            initialfile="PST_Bookmarks.json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        headers = [
            "folder", "subject", "sender", "recipients", "message_date",
            "category", "note", "message_key", "evidence_path",
            "evidence_sha256", "created_utc"
        ]
        data = [dict(zip(headers, row)) for row in self.bookmarks.rows(self.pst_sha256)]
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        self.status_var.set(f"Bookmarks exported to {path}")

    def poll_queue(self):
        self.after(100, self.poll_queue)

    def on_close(self):
        self.close_store()
        try:
            self.attachment_tempdir.cleanup()
        except Exception:
            pass
        self.destroy()


def main():
    app = PSTExplorer()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
