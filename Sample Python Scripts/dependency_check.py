import importlib
packages=[('PySide6','PySide6'),('openpyxl','openpyxl'),('python-evtx','Evtx'),('LnkParse3','LnkParse3'),('olefile','olefile'),('windowsprefetch','windowsprefetch'),('PyYAML','yaml'),('Pillow','PIL')]
missing=[]
for d,m in packages:
    try:
        importlib.import_module(m); print('[OK]',d)
    except Exception:
        print('[MISSING]',d); missing.append(d)
print('\nRun: python -m pip install -r requirements.txt' if missing else '\nAll dependencies installed.')
