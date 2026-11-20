# 在线更新清单生成脚本：版本/URL/签名/校验和字段
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "build_update_manifest", ROOT / "scripts" / "build_update_manifest.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_generates_version_and_latest_manifest(tmp_path):
    cli = tmp_path / "ruoyi-scan.exe"
    setup = tmp_path / "Ruoyi-Scan_v2.1.0_x64-setup.exe"
    sig = tmp_path / "Ruoyi-Scan_v2.1.0_x64-setup.exe.sig"
    cli.write_bytes(b"cli")
    setup.write_bytes(b"setup")
    sig.write_text("SIGNATURE", encoding="utf-8")
    out = tmp_path / "out"
    module = _load_script()
    rc = module.main(
        [
            "--version",
            "2.1.0",
            "--tag",
            "v2.1.0",
            "--repo",
            "xiabai2008/RuoYi-Scan",
            "--assets-dir",
            str(tmp_path),
            "--cli-exe",
            str(cli),
            "--desktop-setup",
            str(setup),
            "--desktop-sig",
            str(sig),
            "--notes-file",
            str(tmp_path / "notes.md"),
            "--out-dir",
            str(out),
            "--pub-date",
            "2026-11-20T00:00:00Z",
        ]
    )
    assert rc == 0
    version = json.loads((out / "version.json").read_text(encoding="utf-8"))
    latest = json.loads((out / "latest.json").read_text(encoding="utf-8"))
    assert version["schema"] == 1
    assert version["version"] == "2.1.0"
    assert version["assets"]["cli"]["windows-x86_64"]["url"].endswith("/releases/download/v2.1.0/ruoyi-scan.exe")
    assert version["assets"]["desktop"]["windows-x86_64"]["signature"] == "SIGNATURE"
    assert latest["version"] == "2.1.0"
    assert latest["platforms"]["windows-x86_64"]["url"].endswith("Ruoyi-Scan_v2.1.0_x64-setup.exe")
    assert latest["platforms"]["windows-x86_64"]["signature"] == "SIGNATURE"


def test_missing_signature_fails(tmp_path):
    cli = tmp_path / "ruoyi-scan.exe"
    setup = tmp_path / "Ruoyi-Scan_v2.1.0_x64-setup.exe"
    cli.write_bytes(b"cli")
    setup.write_bytes(b"setup")
    module = _load_script()
    rc = module.main(
        [
            "--version",
            "2.1.0",
            "--tag",
            "v2.1.0",
            "--assets-dir",
            str(tmp_path),
            "--cli-exe",
            str(cli),
            "--desktop-setup",
            str(setup),
            "--desktop-sig",
            str(tmp_path / "missing.sig"),
            "--out-dir",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 2
