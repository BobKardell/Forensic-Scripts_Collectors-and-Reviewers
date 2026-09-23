#!/usr/bin/env python3
from fraud_fighter.app import SuiteApp
from fraud_fighter.config import ASSETS_DIR, PLUGINS_DIR, SCRIPTS_DIR, CASES_DIR

def main() -> None:
    for folder in (ASSETS_DIR, PLUGINS_DIR, SCRIPTS_DIR, CASES_DIR):
        folder.mkdir(exist_ok=True)
    SuiteApp().mainloop()

if __name__ == "__main__":
    main()
