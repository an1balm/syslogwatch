#!/usr/bin/env python3
"""Ensambla el add-on en `dist/syslogwatch/`: código + metadatos + Dockerfile.

El contexto de construcción de un add-on es **su propia carpeta**, así que el
paquete Python tiene que viajar dentro. En vez de duplicar `src/` a mano, esta
herramienta lo copia: una sola fuente de verdad.

    python3 scripts/build_addon.py [--out dist] [--zip]
"""

from __future__ import annotations

import argparse
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADDON_DIR = ROOT / "addon"
PACKAGE_DIR = ROOT / "src" / "syslogwatch"
SKIP_SUFFIXES = (".pyc", ".pyo")
SKIP_DIRS = {"__pycache__", ".mypy_cache", ".pytest_cache"}


def _copy_package(destination: Path) -> int:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        PACKAGE_DIR,
        destination,
        ignore=shutil.ignore_patterns(*SKIP_DIRS, *SKIP_SUFFIXES),
    )
    return len(list(destination.rglob("*.py")))


def build(out_dir: Path = ROOT / "dist", make_zip: bool = False) -> Path:
    target = out_dir / "syslogwatch"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)

    for name in ("config.yaml", "Dockerfile", "DOCS.md"):
        source = ADDON_DIR / name
        if not source.exists():
            raise FileNotFoundError(f"falta {source}")
        shutil.copy2(source, target / name)

    translations = ADDON_DIR / "translations"
    if translations.is_dir():
        shutil.copytree(translations, target / "translations")

    modules = _copy_package(target / "app" / "syslogwatch")
    (target / "app" / "syslogwatch" / "__init__.py").touch(exist_ok=True)
    print(f"add-on ensamblado en {target} ({modules} módulos)")

    if make_zip:
        archive = out_dir / "syslogwatch-addon.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in target.rglob("*"):
                if path.is_file():
                    bundle.write(path, path.relative_to(target.parent))
        print(f"zip listo: {archive} ({archive.stat().st_size // 1024} KB)")
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Ensambla el add-on de Home Assistant")
    parser.add_argument("--out", default=str(ROOT / "dist"))
    parser.add_argument("--zip", action="store_true", help="además genera un zip para copiar")
    args = parser.parse_args(argv)
    try:
        build(Path(args.out), make_zip=args.zip)
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
