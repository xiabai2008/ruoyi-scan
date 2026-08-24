# E5：插件模板仓库（导出 / manifest / 签名 / 远程更新 / 安装目录）
#
# 设计目标：为社区贡献插件建立分发通道（参照 nuclei-templates 模式）：
#   1. --plugin-export <dir>   导出已加载插件元信息 + 源码副本（含 SHA256 摘要）
#   2. --plugin-manifest <dir> 生成/校验 manifest.json（Ed25519 签名，cryptography 可选）
#   3. --plugin-update [url]   从远程仓库下载 zip → 校验 → 安装到用户插件目录
#   4. 用户插件目录自动发现（~/.ruoyi-scan/plugins/）
#
# 供应链安全（fail-closed，禁止降级放行）：
#   - 安装前强制校验 manifest SHA256 摘要（防篡改）
#   - 远程安装强制 Ed25519 验签（公钥来自本地可信存储 ~/.ruoyi-scan/signing.pub，
#     而非 manifest 自证）；无签名 / 无公钥 / 验签失败一律拒绝安装
#   - 无 cryptography 时远程安装直接拒绝（不降级为纯摘要校验），并提示安装指引
#   - 所有 manifest 相对路径与 zip 成员名做路径穿越（zip-slip）防护
import hashlib
import json
import os
import re
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


def _is_safe_rel(rel: str) -> bool:
    """判断 manifest 相对路径 / zip 成员名是否安全（防路径穿越与 zip-slip）

    规则：非空时拒绝绝对路径（/ 或 \\ 开头）、拒绝含 \\ 的路径（Windows 盘符/
    反斜杠穿越）、拒绝任一路径段为 .. 或 .。
    """
    if not rel:
        return True
    if rel.startswith("/") or rel.startswith("\\") or os.path.isabs(rel):
        return False
    if "\\" in rel:
        return False
    for part in rel.split("/"):
        if part in ("..", "."):
            return False
    return True


def _safe_join(base: str, rel: str):
    """安全拼接 base 与 manifest 相对路径，返回 (path, None) 或 (None, 错误串)

    在 _is_safe_rel 基础上用 normpath/abspath 二次确认，防止拼接后越出 base。
    """
    if not _is_safe_rel(rel):
        return None, "非法路径（绝对路径或 .. 穿越）: %s" % rel
    p = os.path.normpath(os.path.join(base, rel))
    base_abs = os.path.abspath(base)
    p_abs = os.path.abspath(p)
    if p_abs != base_abs and not p_abs.startswith(base_abs + os.sep):
        return None, "非法路径（越出仓库目录）: %s" % rel
    return p, None


# === 导出 ===


def export_plugins(out_dir: str) -> Dict[str, str]:
    """导出已加载插件到 out_dir（源码副本 + meta 描述）

    Args:
        out_dir: 导出目录（相对路径如 plugins/ruoyi/ 保留）

    Returns:
        {相对路径: sha256} 摘要表（用于 manifest）
    """
    import importlib

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
    for root, dirs, names in os.walk(out_dir):
        # 排除 .git 等元目录（manifest 只描述分发内容）
        dirs[:] = [d for d in dirs if d != ".git"]
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
    """加载或生成 Ed25519 私钥（cryptography 缺失返回 None）

    私钥写入 path，公钥写入 path + ".pub"；当 path 是默认密钥
    （~/.ruoyi-scan/signing.key）时，公钥同步到 signing_dir()/signing.pub，
    与 verify_manifest / download_and_install 的默认公钥路径保持一致。
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return None
    if os.path.isfile(path):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        _sync_default_pub(path, key)
        return key
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
    _sync_default_pub(path, key)
    return key


def _sync_default_pub(key_path: str, key) -> None:
    """默认密钥场景下，把公钥同步到 signing_dir()/signing.pub

    保证自动生成的公钥与 verify_manifest 默认查找路径一致，
    避免消费者因缺少 signing.pub 而拒绝验签。
    """
    default_key = os.path.join(signing_dir(), "signing.key")
    if os.path.abspath(key_path) == os.path.abspath(default_key):
        try:
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            return
        pub = key.public_key()
        pub_path = os.path.join(signing_dir(), "signing.pub")
        with open(pub_path, "wb") as f:
            f.write(
                pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )


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


def verify_manifest(
    manifest: dict,
    repo_dir: str,
    pubkey_path: str = "",
    require_signature: bool = False,
) -> List[str]:
    """校验 manifest：摘要 + 签名

    Args:
        manifest: manifest 字典
        repo_dir: 仓库解压根目录
        pubkey_path: 公钥路径（缺省自动找 ~/.ruoyi-scan/signing.pub）
        require_signature: 强制要求签名且验签通过（fail-closed）。
            远程安装必须为 True；本地仓库自校验可保持 False 向后兼容。

    Returns:
        错误列表（空 = 校验通过）
    """
    errors = []
    # 1. 摘要校验（防篡改；路径经 _safe_join 防穿越）
    for rel, expect in (manifest.get("files") or {}).items():
        p, err = _safe_join(repo_dir, rel)
        if err:
            errors.append("文件路径不合法: %s (%s)" % (rel, err))
            continue
        if not os.path.isfile(p):
            errors.append("缺少文件: %s" % rel)
            continue
        if _sha256(p) != expect:
            errors.append("摘要不匹配: %s" % rel)

    # 2. 签名验证
    has_sig = bool(manifest.get("signature"))
    if not pubkey_path:
        pubkey_path = os.path.join(signing_dir(), "signing.pub")
    pubkey_exists = os.path.isfile(pubkey_path)
    if require_signature:
        if not has_sig:
            errors.append("manifest 未签名：远程安装要求 Ed25519 签名，拒绝安装")
        if has_sig and not pubkey_exists:
            errors.append("缺少可信公钥（%s），无法验签，拒绝安装" % pubkey_path)
    if has_sig and pubkey_exists:
        try:
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            errors.append("无法验签：未安装 cryptography 库（pip install cryptography）")
            return errors
        try:
            with open(pubkey_path, "rb") as f:
                pub = serialization.load_pem_public_key(f.read())
            payload = json.dumps(manifest["files"], sort_keys=True, ensure_ascii=False).encode("utf-8")
            pub.verify(bytes.fromhex(manifest["signature"]), payload)
        except Exception as e:
            errors.append("签名验证失败: %s" % e)
    return errors


# === 远程更新 ===


def _github_api_fallback(url: str) -> str:
    """GitHub codeload 受限时的 API 回退地址

    示例：https://github.com/o/r/archive/refs/heads/main.zip
          → https://api.github.com/repos/o/r/zipball/main
    """
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/archive/refs/heads/([^/]+)\.zip", url)
    if m:
        return "https://api.github.com/repos/%s/%s/zipball/%s" % (m.group(1), m.group(2), m.group(3))
    return ""


def download_and_install(
    url: str,
    dest_dir: Optional[str] = None,
    timeout: int = 30,
    trusted_pubkey_path: str = "",
    require_signature: bool = True,
) -> List[str]:
    """从远程仓库下载 zip → 强制验签 → 安装到用户插件目录

    Args:
        url: 仓库 zip 下载地址（如 https://github.com/xxx/repo/archive/refs/heads/main.zip）
        dest_dir: 安装目录（缺省用户插件目录）
        timeout: 下载超时
        trusted_pubkey_path: 可信公钥路径（缺省 ~/.ruoyi-scan/signing.pub）
        require_signature: 强制 Ed25519 验签（默认 True，fail-closed）。
            无签名 / 无公钥 / 验签失败 / 未装 cryptography 一律拒绝安装。

    Returns:
        安装的文件相对路径列表；校验失败抛 ValueError

    Raises:
        ValueError: 下载/校验/安装失败
    """
    import io

    import requests

    dest = dest_dir or user_plugin_dir()
    candidates = [url]
    fb = _github_api_fallback(url)
    if fb:
        candidates.append(fb)
    resp = None
    last_err = ""
    for candidate in candidates:
        try:
            # GitHub codeload/api 要求合法 User-Agent（python-requests 默认 UA 会 403）
            resp = requests.get(
                candidate,
                timeout=timeout,
                headers={"User-Agent": "ruoyi-scan/1.1.0"},
            )
            resp.raise_for_status()
            break
        except Exception as e:
            last_err = str(e)
            resp = None
            continue
    if resp is None:
        raise ValueError("仓库下载失败: %s" % last_err)

    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_repo_")
    try:
        # 解压（zip-slip 防护：先校验所有成员名，拒绝绝对路径 / .. 穿越）
        try:
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                for name in zf.namelist():
                    if not _is_safe_rel(name):
                        raise ValueError("仓库包包含非法路径成员: %s" % name)
                zf.extractall(tmp)
        except zipfile.BadZipFile:
            raise ValueError("仓库包不是有效的 zip 文件")

        # 定位 manifest.json（可能嵌套一层目录）
        repo_root = tmp
        if not os.path.isfile(os.path.join(repo_root, "manifest.json")):
            for c in os.listdir(tmp):
                if os.path.isfile(os.path.join(tmp, c, "manifest.json")):
                    repo_root = os.path.join(tmp, c)
                    break
            else:
                raise ValueError("仓库包缺少 manifest.json")

        with open(os.path.join(repo_root, "manifest.json"), "r", encoding="utf-8") as f:
            manifest = json.load(f)
        errors = verify_manifest(
            manifest,
            repo_root,
            pubkey_path=trusted_pubkey_path,
            require_signature=require_signature,
        )
        if errors:
            raise ValueError("仓库校验失败（已拒绝安装）:\n" + "\n".join("  - " + e for e in errors))

        installed = []
        for rel in (manifest.get("files") or {}).keys():
            src, err = _safe_join(repo_root, rel)
            if err:
                raise ValueError("安装路径不合法，拒绝安装: %s (%s)" % (rel, err))
            dst, err = _safe_join(dest, rel)
            if err:
                raise ValueError("安装路径不合法，拒绝安装: %s (%s)" % (rel, err))
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

    去重策略：与内置插件包（plugins.ruoyi/spring/common/jeecgboot）同名的
    插件类跳过——内置优先，用户副本不重复执行（模板仓库会安装内置包的副本，
    避免同一插件跑两遍 / 版本漂移）。
    """
    from core.loader import _load_external_file, discover_plugin_packages, load_plugins

    # 内置插件类名集合（去重基准）
    builtin_names = set()
    try:
        for pkg in discover_plugin_packages():
            for cls in load_plugins(pkg):
                builtin_names.add(getattr(cls, "name", cls.__name__))
    except Exception:
        pass

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
            for cls in _load_external_file(p, logger):
                cls_name = getattr(cls, "name", cls.__name__)
                if cls_name in builtin_names:
                    logger.debug("跳过与内置重名的用户插件: %s", cls_name)
                    continue
                results.append(cls)
    return results
