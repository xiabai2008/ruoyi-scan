# lib/updater.py — CLI 在线检查更新 / 自升级
"""CLI 在线更新服务。

设计边界
========
- 只负责「版本清单 → 比较 → 下载校验 → 升级动作」，不直接打印 UI；
  CLI 呈现统一在 cli/tool_runner.run_update_mode。
- 版本清单来自 GitHub Release 的 version.json（HTTPS）；单文件 exe 下载后
  必须校验 sha256，Pip 安装交给当前解释器的 pip。
- 运行中的 Windows exe 无法直接覆盖：下载到同目录 .new，再用延迟批处理
  在进程退出后原子替换并重启；批处理只包含本模块生成的固定命令。
- 网络失败/清单缺字段一律显式报错，不静默当作「已是最新」。
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

from common.logger import get_logger
from config.settings import GITHUB, VERSION

logger = get_logger(__name__)

DEFAULT_MANIFEST_URL = GITHUB.rstrip("/") + "/releases/latest/download/version.json"
_ENV_MANIFEST_URL = "RUOYI_SCAN_UPDATE_URL"
_MANIFEST_MAX_BYTES = 1024 * 1024
_ASSET_MAX_BYTES = 300 * 1024 * 1024
_USER_AGENT = "ruoyi-scan/%s" % VERSION


class UpdateError(RuntimeError):
    """在线更新不可用或清单/资产不可信。"""


@dataclass
class UpdateInfo:
    """一次检查的结果（不包含网络对象，便于序列化/测试）。"""

    current: str
    latest: str
    available: bool
    notes: str = ""
    pub_date: str = ""
    manifest: Dict[str, Any] = field(default_factory=dict)
    manifest_url: str = ""


def _parse_version(value: str) -> Optional[Tuple[Tuple[int, int, int], Optional[Tuple[Any, ...]]]]:
    """解析 SemVer；允许 v 前缀，预发布段按 . 分段。"""
    text = str(value or "").strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", text)
    if not match:
        return None
    core = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    pre_text = match.group(4)
    if pre_text is None:
        return core, None
    pre: list[Any] = []
    for part in pre_text.split("."):
        pre.append(int(part) if part.isdigit() else part.lower())
    return core, tuple(pre)


def compare_versions(left: str, right: str) -> int:
    """比较两个版本：left > right 返回 1，相等 0，小于 -1。

    非 SemVer 字符串按字面量比较（升级动作会因无法解析而拒绝执行）。
    """
    a = _parse_version(left)
    b = _parse_version(right)
    if a is None or b is None:
        return (left > right) - (left < right)
    core_a, pre_a = a
    core_b, pre_b = b
    if core_a != core_b:
        return 1 if core_a > core_b else -1
    if pre_a is None and pre_b is None:
        return 0
    if pre_a is None:
        return 1
    if pre_b is None:
        return -1
    for x, y in zip(pre_a, pre_b):
        if x == y:
            continue
        # 数字标识符低于字母标识符（SemVer 2.0.0 §11）
        if isinstance(x, int) and isinstance(y, str):
            return -1
        if isinstance(x, str) and isinstance(y, int):
            return 1
        return 1 if x > y else -1
    if len(pre_a) == len(pre_b):
        return 0
    return 1 if len(pre_a) > len(pre_b) else -1


def is_newer(latest: str, current: str) -> bool:
    return compare_versions(latest, current) > 0


def manifest_url(explicit: str = "") -> str:
    if explicit:
        return explicit.strip()
    return os.environ.get(_ENV_MANIFEST_URL, "").strip() or DEFAULT_MANIFEST_URL


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    # 本地端到端测试/内网镜像允许 localhost，绝不允许任意明文公网地址。
    if parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1"):
        return
    raise UpdateError("更新地址必须使用 HTTPS（仅 localhost 可用 HTTP）")


def fetch_manifest(url: str = "", timeout: int = 10) -> Dict[str, Any]:
    """拉取并校验 version.json。"""
    target = manifest_url(url)
    _validate_url(target)
    try:
        resp = requests.get(
            target,
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        raise UpdateError("检查更新失败（网络异常）：%s" % exc) from exc
    if resp.status_code != 200:
        raise UpdateError("检查更新失败：清单 HTTP %s" % resp.status_code)
    if len(resp.content or b"") > _MANIFEST_MAX_BYTES:
        raise UpdateError("更新清单异常：超过 %d 字节" % _MANIFEST_MAX_BYTES)
    try:
        data = resp.json()
    except ValueError as exc:
        raise UpdateError("更新清单不是合法 JSON") from exc
    if not isinstance(data, dict):
        raise UpdateError("更新清单格式错误：根节点必须是对象")
    if data.get("schema") != 1:
        raise UpdateError("更新清单 schema 不受支持：%r" % data.get("schema"))
    version = str(data.get("version") or "").strip()
    if _parse_version(version) is None:
        raise UpdateError("更新清单 version 非法：%r" % version)
    return data


def check_for_update(current: Optional[str] = None, url: str = "", timeout: int = 10) -> UpdateInfo:
    current_version = current or VERSION
    target = manifest_url(url)
    data = fetch_manifest(target, timeout=timeout)
    latest = str(data.get("version") or "")
    return UpdateInfo(
        current=current_version,
        latest=latest,
        available=is_newer(latest, current_version),
        notes=str(data.get("notes") or ""),
        pub_date=str(data.get("pub_date") or ""),
        manifest=data,
        manifest_url=target,
    )


def _asset_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows-x86_64"
    if sys.platform == "darwin":
        return "darwin-x86_64"
    return "linux-x86_64"


def get_cli_asset(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """取当前运行形态对应的 CLI 资产。

    PyInstaller 冻结版按平台取 exe；pip 安装版由 pip 负责，返回空 dict。
    """
    if not getattr(sys, "frozen", False):
        return {}
    assets = manifest.get("assets") or {}
    cli = assets.get("cli") or {}
    asset = cli.get(_asset_platform()) or {}
    if not isinstance(asset, dict) or not asset.get("url"):
        raise UpdateError("更新清单缺少当前平台的 CLI 资产（%s）" % _asset_platform())
    return asset


def _download_asset(asset: Dict[str, Any], dest: Path, timeout: int = 30) -> Path:
    url = str(asset.get("url") or "")
    _validate_url(url)
    expected = str(asset.get("sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpdateError("更新资产缺少合法 sha256，拒绝下载")
    expected_size = asset.get("size")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    total = 0
    try:
        with requests.get(url, stream=True, timeout=timeout, headers={"User-Agent": _USER_AGENT}) as resp:
            if resp.status_code != 200:
                raise UpdateError("下载更新资产失败：HTTP %s" % resp.status_code)
            with open(tmp, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=1024 * 256):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > _ASSET_MAX_BYTES:
                        raise UpdateError("更新资产超过 %d 字节上限" % _ASSET_MAX_BYTES)
                    digest.update(chunk)
                    fh.write(chunk)
        if expected_size is not None and int(expected_size) != total:
            raise UpdateError("更新资产大小不匹配：期望 %s，实际 %d" % (expected_size, total))
        actual = digest.hexdigest()
        if actual != expected:
            raise UpdateError("更新资产 sha256 不匹配：期望 %s，实际 %s" % (expected, actual))
        os.replace(str(tmp), str(dest))
        return dest
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                logger.debug("清理临时更新文件失败", exc_info=True)


def _pip_install(latest: str) -> int:
    """用当前解释器的 pip 升级 ruoyi-scan。"""
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check"]
    if "-" in latest:
        # 预发布版本必须显式 --pre，否则 pip 会认为「已是最新正式版」。
        cmd.append("--pre")
    cmd.append("ruoyi-scan==%s" % latest)
    logger.info("执行 pip 升级: %s", cmd)
    try:
        return int(subprocess.call(cmd))
    except OSError as exc:
        raise UpdateError("无法启动 pip：%s" % exc) from exc


def _replace_frozen_exe(asset: Dict[str, Any]) -> None:
    """Windows 单文件 exe 自替换：下载 → 延迟批处理替换 → 重启。"""
    if not sys.platform.startswith("win"):
        raise UpdateError("单文件版自升级当前仅支持 Windows；请重新下载对应平台安装包")
    target = Path(sys.executable).resolve()
    if target.suffix.lower() != ".exe":
        raise UpdateError("当前可执行文件不是 .exe，无法执行单文件自升级")
    staged = target.with_name(target.name + ".new")
    downloaded = Path(tempfile.gettempdir()) / ("ruoyi-scan-%s-download%s" % (VERSION, target.suffix))
    _download_asset(asset, downloaded)
    try:
        shutil.copy2(str(downloaded), str(staged))
    except OSError as exc:
        raise UpdateError("更新文件写入失败（目录不可写？）：%s" % exc) from exc

    batch = Path(tempfile.gettempdir()) / ("ruoyi-scan-self-update-%d.bat" % os.getpid())
    script = (
        "@echo off\r\n"
        "chcp 65001 >nul\r\n"
        'set "TARGET=%s"\r\n'
        'set "STAGED=%s"\r\n'
        # 固定等待 5 秒再替换：依赖 tasklist 等待 PID 在部分环境会被
        # find/findstr 的 PATH 劫持或 PID 复用卡住；当前进程已在正常退出，
        # 固定延迟后重试 move 足以覆盖 Windows 文件句柄释放。
        "C:\\Windows\\System32\\timeout.exe /t 5 /nobreak >nul\r\n"
        ":replace\r\n"
        'move /Y "%%STAGED%%" "%%TARGET%%" >nul 2>&1\r\n'
        "if errorlevel 1 (\r\n"
        "  timeout /t 2 /nobreak >nul\r\n"
        "  goto replace\r\n"
        ")\r\n"
        'start "" "%%TARGET%%"\r\n'
        'del "%%~f0"\r\n'
    ) % (target, staged)
    try:
        batch.write_text(script, encoding="utf-8")
    except OSError as exc:
        raise UpdateError("无法创建更新脚本：%s" % exc) from exc
    flags = 0
    if hasattr(subprocess, "DETACHED_PROCESS"):
        flags |= subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        flags |= subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    subprocess.Popen(
        ["cmd.exe", "/c", str(batch)],
        creationflags=flags,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def perform_update(info: UpdateInfo) -> int:
    """执行升级。返回 0 表示已触发/完成；非 0 为错误码。"""
    if not info.available:
        return 0
    if getattr(sys, "frozen", False):
        asset = get_cli_asset(info.manifest)
        _replace_frozen_exe(asset)
        return 0
    return _pip_install(info.latest)
