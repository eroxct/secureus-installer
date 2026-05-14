# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['secureus_app/monitor.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtWidgets',
        'PyQt5.QtGui',
        'numpy',
        'pandas',
        'socket',
        'subprocess',
        'platform',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['flask', 'werkzeug', 'shap', 'lime', 'sklearn', 'xgboost'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zlib, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SecureUS Monitor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # no black console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,              # add icon.ico path here if you have one
)
