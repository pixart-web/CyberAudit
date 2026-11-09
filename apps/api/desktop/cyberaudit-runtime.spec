from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


api_root = Path(SPEC).resolve().parent.parent
common_data = [
    (str(api_root / "alembic.ini"), "."),
    (str(api_root / "alembic"), "alembic"),
]
common_hidden_imports = collect_submodules("cyberaudit")
common_hidden_imports += collect_submodules("uvicorn")
common_hidden_imports += collect_submodules("dramatiq")
common_hidden_imports += collect_submodules("passlib.handlers")
common_data += collect_data_files("reportlab")


def executable(entrypoint: str, name: str):
    analysis = Analysis(
        [str(api_root / "desktop" / entrypoint)],
        pathex=[str(api_root)],
        binaries=[],
        datas=common_data,
        hiddenimports=common_hidden_imports,
        hookspath=[],
        hooksconfig={},
        runtime_hooks=[],
        excludes=["tkinter", "matplotlib", "IPython"],
        noarchive=False,
        optimize=1,
    )
    archive = PYZ(analysis.pure)
    return EXE(
        archive,
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        name=name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )


api = executable("api_entry.py", "cyberaudit-api")
worker = executable("worker_entry.py", "cyberaudit-worker")
