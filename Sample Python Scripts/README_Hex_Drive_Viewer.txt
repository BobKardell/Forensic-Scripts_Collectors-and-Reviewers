Hex Drive Viewer

Place in:
Forensics Collector Global Settings\Python Scripts

Run:
python Hex_Drive_Viewer.py

Features:
- Read-only file viewing
- Raw volume or physical drive viewing
- Hexadecimal and ASCII display
- Decimal or hexadecimal offset navigation
- Hex, ASCII, and UTF-16LE search
- Adjustable page size and bytes per row
- Export a selected range to a new binary file

Windows raw paths:
\\.\C:
\\.\PhysicalDrive0

Linux raw paths:
/dev/sda
/dev/nvme0n1

Administrator/root permissions may be required for raw devices.
The selected source is opened read-only.
