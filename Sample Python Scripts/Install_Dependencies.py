"""
Install_Dependencies.py

Installs packages listed in a requirements.txt file.
Designed to be launched from the Fraud Fighter Toolbox Tools/Python Scripts tab.
"""

import subprocess
import sys
from pathlib import Path
from tkinter import Tk, filedialog, messagebox

SCRIPT_NAME = "Install Dependencies"
SCRIPT_VERSION = "1.0"
SCRIPT_AUTHOR = "Bob Kardell / ChatGPT"
SCRIPT_CATEGORY = "Utilities"
SCRIPT_DESCRIPTION = "Install Python dependencies from a requirements.txt file."


def main():
    root = Tk()
    root.withdraw()

    default = Path(__file__).resolve().parents[1] / "requirements.txt"

    if default.exists():
        req_file = default
    else:
        messagebox.showinfo(
            "Select Requirements File",
            "Select the requirements.txt file to install."
        )
        filename = filedialog.askopenfilename(
            title="Choose requirements.txt",
            filetypes=[("Requirements", "requirements*.txt"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not filename:
            return
        req_file = Path(filename)

    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "-r",
        str(req_file),
    ]

    answer = messagebox.askyesno(
        "Install Dependencies",
        f"This will run:\n\n{' '.join(cmd)}\n\nContinue?"
    )
    if not answer:
        return

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        messagebox.showinfo(
            "Success",
            "Dependencies installed successfully."
        )
    else:
        messagebox.showerror(
            "Installation Failed",
            result.stderr or result.stdout
        )


if __name__ == "__main__":
    main()
