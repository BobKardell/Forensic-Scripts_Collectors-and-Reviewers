from pathlib import Path

APP_NAME = "Fraud Fighter Toolbox"
APP_VERSION = "6.4.0"
ROOT_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = ROOT_DIR / "assets"
PLUGINS_DIR = ROOT_DIR / "plugins"
SCRIPTS_DIR = ROOT_DIR / "Scripts"
CASES_DIR = ROOT_DIR / "cases"
SETTINGS_PATH = ROOT_DIR / "settings.json"
LOGO_PATH = ASSETS_DIR / "fraud_fighter_toolbox.png"

COLORS = {
    "navy": "#061522", "navy2": "#0c2235", "slate": "#587795",
    "slate_dark": "#3e5c78", "slate_light": "#dce7f0", "blue": "#188bd0",
    "panel": "#f2f6f9", "white": "#ffffff", "text": "#172431",
    "muted": "#607180", "border": "#c8d5df", "green": "#367d4a",
    "amber": "#a96f17", "red": "#a33b3b",
}
