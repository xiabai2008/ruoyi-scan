#!/usr/bin/env python3
"""生成 v2 在线更新清单。

产物（写入 --out-dir，通常为 desktop/artifacts，随 GitHub Release 上传）：
- version.json：CLI / 通用清单（版本、CLI exe 与桌面安装包的 URL/sha256/size）；
- latest.json：Tauri updater 清单（桌面安装包 + minisign 签名）。

用法：
  python scripts/build_update_manifest.py \
    --version 2.0.1 --tag v2.0.1 \
    --assets-dir desktop/artifacts \
    --cli-exe desktop/artifacts/ruoyi-scan.exe \
    --desktop-setup desktop/artifacts/Ruoyi-Scan_v2.0.1_x64-setup.exe \
    --desktop-sig desktop/artifacts/Ruoyi-Scan_v2.0.1_x64-setup.exe.sig \
    --notes-file release-notes/v2.0.1.md \
    --out-dir desktop/artifacts
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _asset(path: Path, url: str) -> dict:
    return {"url": url, "sha256": _sha256(path), "size": path.stat().st_size}


def _release_url(repo: str, tag: str, name: str) -> str:
    return "https://github.com/%s/releases/download/%s/%s" % (repo, tag, name)


def _read_notes(path: str) -> str:
    if not path:
        return ""
    file = Path(path)
    if not file.is_file():
        return ""
    return file.read_text(encoding="utf-8", errors="replace")[:16000]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="生成 version.json / Tauri latest.json")
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", default="xiabai2008/RuoYi-Scan")
    parser.add_argument("--assets-dir", default="desktop/artifacts")
    parser.add_argument("--cli-exe", default="")
    parser.add_argument("--desktop-setup", default="")
    parser.add_argument("--desktop-sig", default="")
    parser.add_argument("--notes-file", default="")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--pub-date", default="")
    args = parser.parse_args(argv)

    version = args.version.lstrip("vV")
    tag = args.tag if args.tag.startswith("v") else "v" + args.tag
    out_dir = Path(args.out_dir or args.assets_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    pub_date = args.pub_date or _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    notes = _read_notes(args.notes_file)

    cli_path = Path(args.cli_exe) if args.cli_exe else Path(args.assets_dir) / "ruoyi-scan.exe"
    setup_path = (
        Path(args.desktop_setup)
        if args.desktop_setup
        else Path(args.assets_dir) / ("Ruoyi-Scan_%s_x64-setup.exe" % tag)
    )
    sig_path = Path(args.desktop_sig) if args.desktop_sig else setup_path.with_name(setup_path.name + ".sig")

    if not cli_path.is_file():
        print("[!] CLI exe 不存在: %s" % cli_path, file=sys.stderr)
        return 2
    if not setup_path.is_file():
        print("[!] 桌面安装包不存在: %s" % setup_path, file=sys.stderr)
        return 2
    if not sig_path.is_file() or not sig_path.read_text(encoding="utf-8", errors="replace").strip():
        print("[!] 桌面更新签名不存在或为空: %s" % sig_path, file=sys.stderr)
        print("    CI 需设置 TAURI_SIGNING_PRIVATE_KEY（以及可选 password）后重新构建。", file=sys.stderr)
        return 2

    cli_url = _release_url(args.repo, tag, cli_path.name)
    setup_url = _release_url(args.repo, tag, setup_path.name)
    manifest = {
        "schema": 1,
        "version": version,
        "tag": tag,
        "pub_date": pub_date,
        "notes": notes,
        "pip": {"package": "ruoyi-scan", "version": version},
        "assets": {
            "cli": {"windows-x86_64": _asset(cli_path, cli_url)},
            "desktop": {
                "windows-x86_64": dict(
                    _asset(setup_path, setup_url),
                    signature=str(sig_path.read_text(encoding="utf-8", errors="replace")).strip(),
                )
            },
        },
    }
    version_file = out_dir / "version.json"
    version_file.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    latest = {
        "version": version,
        "notes": notes,
        "pub_date": pub_date,
        "platforms": {
            "windows-x86_64": {
                "signature": manifest["assets"]["desktop"]["windows-x86_64"]["signature"],
                "url": setup_url,
            }
        },
    }
    latest_file = out_dir / "latest.json"
    latest_file.write_text(json.dumps(latest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("[+] 已生成 %s" % version_file)
    print("[+] 已生成 %s" % latest_file)
    print("    version: %s  tag: %s" % (version, tag))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
