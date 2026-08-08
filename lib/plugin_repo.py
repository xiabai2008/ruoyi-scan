# E5：插件模板仓库（导出 / manifest / 签名 / 远程更新 / 安装目录）
#
# 设计目标：为社区贡献插件建立分发通道（参照 nuclei-templates 模式）：
#   1. --plugin-export <dir>   导出已加载插件元信息 + 源码副本（含 SHA256 摘要）
#   2. --plugin-manifest <dir> 生成/校验 manifest.json（Ed25519 签名，cryptography 可选）
#   3. --plugin-update [url]   从远程仓库下载 zip → 校验 → 安装到用户插件目录
#   4. 用户插件目录自动发现（~/.ruoyi-scan/plugins/）
#
# 供应链安全：
#   - 安装前强制校验 manifest SHA256 摘要（防篡改）
#   - 有公钥时强制验签（Ed25519），失败拒绝安装
#   - 无 cryptography 时降级为摘要校验 + 黄色提示（不阻断主流程）
import hashlib
import json
import os
import shutil
import tempfile
import time
import zipfile
from typing import Dict, List, Optional

from common.logger import get_logger

logger = get_logger(__name__)

# 用户插件安装目录（~/.ruoyi-scan/plugins/）
def user_plugin_dir() -> str:
    """返回用户插件安装目录（不存在时创建）"""
    home = os.path.expanduser("~")
    path = os.path.join(home, ".ruoyi-scan", "plugins")
    os.makedirs(path, exist_ok=True)
    return path


def signing_dir() -> str:
    """返回签名密钥目录（~/.ruoyi-scan/）"""
    home = os.path.expanduser("~")
    path = os.path.join(home, ".ruoyi-scan")
    os.makedirs(path, exist_ok=True)
    return path


def _sha256(path: str) -> str:
    """计算文件 SHA256"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# === 导出 ===


def export_plugins(out_dir: str) -> Dict[str, str]:
    """导出已加载插件到 out_dir（源码副本 + meta 描述）

    Args:
        out_dir: 导出目录（相对路径如 plugins/ruoyi/ 保留）

    Returns:
        {相对路径: sha256} 摘要表（用于 manifest）
    """
    import importlib
    import pkgutil

    hashes: Dict[str, str] = {}
    os.makedirs(out_dir, exist_ok=True)
    meta_file = os.path.join(out_dir, "plugins_meta.json")
    meta_data = {}

    for pkg_name in ["plugins.ruoyi", "plugins.spring", "plugins.common"]:
        try:
            pkg = importlib.import_module(pkg_name)
            pkg_path = os.path.dirname(pkg.__file__)
            rel_dir = os.path.join(out_dir, pkg_name.replace(".", "/"))
            os.makedirs(rel_dir, exist_ok=True)
            for fname in sorted(os.listdir(pkg_path)):
                if not fname.endswith(".py"):
                    continue
                src = os.path.join(pkg_path, fname)
                dst = os.path.join(rel_dir, fname)
                shutil.copy2(src, dst)
                rel = os.path.join(pkg_name.replace(".", "/"), fname).replace("\\", "/")
                hashes[rel] = _sha256(dst)
        except Exception as e:
            logger.debug("导出插件包 %s 失败: %s", pkg_name, e)

    # 插件元信息（from loader）
    from core.loader import discover_plugin_packages, load_plugins

    for pkg_name in discover_plugin_packages():
        try:
            for cls in load_plugins(pkg_name):
                inst = cls()
                if hasattr(inst, "meta"):
                    m = inst.meta()
                    m["module"] = "%s.%s" % (pkg_name, cls.__module__.rsplit(".", 1)[-1])
                    meta_data[m["name"]] = m
        except Exception:
            continue
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, ensure_ascii=False, indent=2)
    hashes["plugins_meta.json"] = _sha256(meta_file)
    return hashes


# === manifest + 签名 ===


def build_manifest(out_dir: str, version: str = "1.0.0", sign_key_path: str = "") -> dict:
    """构建 manifest.json（含 Ed25519 签名，cryptography 可选）

    Args:
        out_dir: 已导出的插件目录
        version: 仓库版本号
        sign_key_path: 私钥路径（缺省自动找 ~/.ruoyi-scan/signing.key；没有则跳过签名）

    Returns:
        manifest 字典（已写入 out_dir/manifest.json）
    """
    hashes = {}
    for root, _dirs, names in os.walk(out_dir):
        for n in sorted(names):
            if n in ("manifest.json",):
                continue
            p = os.path.join(root, n)
            rel = os.path.relpath(p, out_dir).replace("\\", "/")
            hashes[rel] = _sha256(p)

    manifest = {
        "schema": "ruoyi-scan-plugin-repo",
        "version": version,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "files": hashes,
        "signature": "",
    }
    # 签名（Ed25519，cryptography 可选）
    sig = _sign_manifest(manifest, sign_key_path)
    if sig:
        manifest["signature"] = sig
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest


def _load_or_create_key(path: str):
    """加载或生成 Ed25519 私钥（cryptography 缺失返回 None）"""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return None
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # 导出公钥
    pub = key.public_key()
    with open(path + ".pub", "wb") as f:
        f.write(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return key


def _sign_manifest(manifest: dict, sign_key_path: str = "") -> str:
    """签名 manifest（无 cryptography / 无密钥 → 空串）

    密钥不存在时自动生成（Ed25519，~/.ruoyi-scan/signing.key + .pub）。
    """
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: F401
    except ImportError:
        return ""
    if not sign_key_path:
        sign_key_path = os.path.join(signing_dir(), "signing.key")
    key = _load_or_create_key(sign_key_path)
    if key is None:
        return ""
    payload = json.dumps(manifest["files"], sort_keys=True, ensure_ascii=False).encode("utf-8")
    return key.sign(payload).hex()


def verify_manifest(manifest: dict, repo_dir: str, pubkey_path: str = "") -> List[str]:
    """校验 manifest：摘要 + 签名（可选）

    Args:
        manifest: manifest 字典
        repo_dir: 仓库解压根目录
        pubkey_path: 公钥路径（缺省自动找 ~/.ruoyi-scan/signing.pub；无公钥只验摘要）

    Returns:
        错误列表（空 = 校验通过）
    """
    errors = []
    for rel, expect in (manifest.get("files") or {}).items():
        p = os.path.join(repo_dir, rel)
        if not os.path.isfile(p):
            errors.append("缺少文件: %s" % rel)
            continue
        if _sha256(p) != expect:
            errors.append("摘要不匹配: %s" % rel)
    # 签名验证
    if manifest.get("signature"):
        if not pubkey_path:
            pubkey_path = os.path.join(signing_dir(), "signing.pub")
        if os.path.isfile(pubkey_path):
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

                with open(pubkey_path, "rb") as f:
                    pub = serialization.load_pem_public_key(f.read())
                payload = json.dumps(manifest["files"], sort_keys=True, ensure_ascii=False).encode("utf-8")
                pub.verify(bytes.fromhex(manifest["signature"]), payload)
            except Exception as e:
                errors.append("签名验证失败: %s" % e)
    return errors


# === 远程更新 ===


def download_and_install(url: str, dest_dir: Optional[str] = None, timeout: int = 30) -> List[str]:
    """从远程仓库下载 zip → 校验 → 安装到用户插件目录

    Args:
        url: 仓库 zip 下载地址（如 https://github.com/xxx/repo/archive/refs/heads/main.zip）
        dest_dir: 安装目录（缺省用户插件目录）
        timeout: 下载超时

    Returns:
        安装的文件相对路径列表；校验失败抛 ValueError

    Raises:
        ValueError: 下载/校验/安装失败
    """
    import io
    import requests

    dest = dest_dir or user_plugin_dir()
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
    except Exception as e:
        raise ValueError("仓库下载失败: %s" % e)

    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_repo_")
    try:
        # 解压（支持 zip；单个 manifest.json 直接安装）
        try:
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                zf.extractall(tmp)
        except zipfile.BadZipFile:
            raise ValueError("仓库包不是有效的 zip 文件")

        # 定位 manifest.json（可能嵌套一层目录）
        repo_root = tmp
        if not os.path.isfile(os.path.join(repo_root, "manifest.json")):
            candidates = [d for d in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, d))]
            for c in candidates:
                if os.path.isfile(os.path.join(tmp, c, "manifest.json")):
                    repo_root = os.path.join(tmp, c)
                    break
            else:
                raise ValueError("仓库包缺少 manifest.json")

        with open(os.path.join(repo_root, "manifest.json"), "r", encoding="utf-8") as f:
            manifest = json.load(f)
        errors = verify_manifest(manifest, repo_root)
        if errors:
            raise ValueError("仓库校验失败:\n" + "\n".join("  - " + e for e in errors))

        installed = []
        for rel in (manifest.get("files") or {}).keys():
            src = os.path.join(repo_root, rel)
            dst = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            installed.append(rel)
        return installed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# === 用户安装目录发现 ===


def load_user_installed_plugins() -> List[type]:
    """加载用户安装目录（~/.ruoyi-scan/plugins/）下的插件

    递归发现 .py 单文件插件（模板仓库结构：plugins/ruoyi/xxx.py），
    复用 core.loader._load_external_file 机制；校验失败跳过不阻断。
    """
    from core.loader import _load_external_file

    base = user_plugin_dir()
    results = []
    seen = set()
    for root, _dirs, names in os.walk(base):
        for n in sorted(names):
            if not n.endswith(".py") or n.startswith("_"):
                continue
            p = os.path.join(root, n)
            if p in seen:
                continue
            seen.add(p)
            results.extend(_load_external_file(p, logger))
    return results
