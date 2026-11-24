"""El add-on tiene que estar completo en `addon/` o HA no lo construye."""

import json
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_addon  # noqa: E402


def test_the_addon_tree_is_valid():
    assert build_addon.check() == []


def test_the_package_lives_inside_the_addon():
    assert (ROOT / "addon" / "app" / "syslogwatch" / "addon_main.py").exists()
    assert not (ROOT / "src").exists(), "no debe haber una segunda copia del paquete"


def test_build_copies_the_whole_addon(tmp_path):
    target = build_addon.build(tmp_path)
    for name in ("config.yaml", "Dockerfile", "DOCS.md", "translations/es.yaml",
                 "app/syslogwatch/addon_main.py", "app/syslogwatch/ws.py"):
        assert (target / name).exists(), name


def test_build_skips_caches_and_bytecode(tmp_path):
    target = build_addon.build(tmp_path)
    names = [path.name for path in target.rglob("*") if path.is_file()]
    assert not any(name.endswith(".pyc") for name in names)
    assert "__pycache__" not in str(target)


def test_config_has_the_keys_home_assistant_requires():
    text = (ROOT / "addon" / "config.yaml").read_text(encoding="utf-8")
    for key in ("name:", "version:", "slug:", "arch:", "description:", "ingress:", "homeassistant_api: true"):
        assert key in text, key
    options = text.split("options:", 1)[1].split("schema:", 1)[0]
    schema = text.split("schema:", 1)[1]
    for option in ("since_hours", "top", "min_score", "min_severity", "web", "refresh_minutes"):
        assert option in options, option
        assert option in schema, option


def test_check_mode_reports_a_broken_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(build_addon, "ADDON_DIR", tmp_path)
    problems = build_addon.check()
    assert any("config.yaml" in problem for problem in problems)
    assert build_addon.main(["--check"]) == 1


def test_build_rejects_an_incomplete_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(build_addon, "ADDON_DIR", tmp_path)
    with pytest.raises(ValueError):
        build_addon.build(tmp_path / "out")


def test_the_built_addon_serves_its_panel(tmp_path):
    """Arranca el árbol empaquetado de verdad y pide /healthz."""
    target = build_addon.build(tmp_path)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    options = data_dir / "options.json"
    options.write_text(
        json.dumps({"web": False, "refresh_minutes": 60, "ingress_port": 8793, "data_dir": str(data_dir)}),
        encoding="utf-8",
    )
    environment = {
        "PYTHONPATH": str(target / "app"),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "SYSLOGWATCH_OPTIONS": str(options),
    }
    code = (
        "from pathlib import Path;"
        "import os, syslogwatch.addon_main as m;"
        "m.OPTIONS_PATH = Path(os.environ['SYSLOGWATCH_OPTIONS']);"
        "raise SystemExit(m.main())"
    )
    process = subprocess.Popen([sys.executable, "-c", code], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 15
        payload = None
        while time.time() < deadline and payload is None:
            time.sleep(0.3)
            try:
                with urllib.request.urlopen("http://127.0.0.1:8793/healthz", timeout=2) as response:
                    payload = json.loads(response.read())
            except OSError:
                continue
        assert payload is not None, "el panel no respondió"
        assert payload["eventos"] == 0
        with urllib.request.urlopen("http://127.0.0.1:8793/", timeout=2) as response:
            assert "Syslogwatch" in response.read().decode()
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_zip_bundle_contains_the_addon_folder(tmp_path):
    build_addon.build(tmp_path, make_zip=True)
    archive = tmp_path / "syslogwatch-addon.zip"
    assert archive.exists()
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
    assert "syslogwatch/config.yaml" in names
    assert any(name.endswith("syslogwatch/app/syslogwatch/addon_main.py") for name in names)
