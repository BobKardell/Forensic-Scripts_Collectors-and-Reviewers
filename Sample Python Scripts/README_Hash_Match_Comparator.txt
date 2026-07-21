Hash Match Comparator

Run:
    python Hash_Match_Comparator.py

Supported inputs:
    CSV, TSV, TXT, XLSX, XLSM

Excel support:
    python -m pip install openpyxl

Workflow:
1. Choose MD5 or SHA1.
2. Load the first file and select its hash field.
3. Load the second file and select its hash field.
4. Run the comparison.
5. Review or export matching rows.

Hashes are normalized to lowercase and spaces, colons, and hyphens are removed.
Invalid hashes are excluded and counted.
