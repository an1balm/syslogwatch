#!/usr/bin/env python3
"""Valida el add-on y lo empaqueta para copiarlo a `/addons` o subirlo a un repo.

El add-on se construye **desde su propia carpeta** (`addon/`), así que el paquete
Python vive dentro (`addon/app/syslogwatch`): una sola copia del código, la misma
que usan la CLI y los tests. Este script no duplica nada; comprueba que el árbol
está completo y, si quieres, genera un zip listo para copiar.

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
PACKAGE_DIR = ADDON_DIR / "app" / "syslogwatch"
REQUIRED = ("config.yaml", "Dockerfile", "DOCS.md", "app/syslogwatch/__init__.py")
SKIP_DIRS = {"__pycache__", ".mypy_cache", ".pytest_cache"}


def _check_files() -> list:
    problems = []
    for name in REQUIRED:
        if not (ADDON_DIR / name).exists():
            problems.append(f"falta addon/{name}")
    if not PACKAGE_DIR.exists():
        problems.append("falta addon/app/syslogwatch")
    return problems


def _check_config() -> list:
    config = ADDON_DIR / "config.yaml"
    if not config.exists():
        return []
    text = config.read_text(encoding="utf-8")
    problems = [f"config.yaml sin '{key}'" for key in ("name:", "version:", "slug:", "arch:", "description:")
                if key not in text]
    options = text.split("options:", 1)[-1].split("schema:", 1)[0]
    schema = text.split("schema:", 1)[-1]
    for option in ("since_hours", "top", "min_score", "min_severity", "web", "refresh_minutes"):
        if option not in options or option not in schema:
            problems.append(f"opción '{option}' sin declarar en options/schema")
    return problems


def check() -> list:
    """Devuelve la lista de problemas; vacía significa que el add-on es válido."""
    return _check_files() + _check_config()


def build(out_dir: Path = ROOT / "dist", make_zip: bool = False) -> Path:
    problems = check()
    if problems:
        raise ValueError("; ".join(problems))

    target = out_dir / "syslogwatch"
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        ADDON_DIR,
        target,
        ignore=shutil.ignore_patterns(*SKIP_DIRS, "*.pyc", "*.pyo"),
    )
    modules = len(list((target / "app" / "syslogwatch").glob("*.py")))
    print(f"add-on listo en {target} ({modules} módulos)")

    if make_zip:
        archive = out_dir / "syslogwatch-addon.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in target.rglob("*"):
                if path.is_file():
                    bundle.write(path, path.relative_to(target.parent))
        print(f"zip listo: {archive} ({archive.stat().st_size // 1024} KB)")
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Valida y empaqueta el add-on")
    parser.add_argument("--out", default=str(ROOT / "dist"))
    parser.add_argument("--zip", action="store_true", help="además genera un zip para copiar")
    parser.add_argument("--check", action="store_true", help="sólo validar")
    args = parser.parse_args(argv)

    if args.check:
        problems = check()
        for problem in problems:
            print(f"✗ {problem}", file=sys.stderr)
        if not problems:
            print("add-on válido")
        return 1 if problems else 0

    try:
        build(Path(args.out), make_zip=args.zip)
    except ValueError as error:
        print(f"add-on inválido: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
