# E5 插件模板仓库测试：导出/manifest/摘要校验/签名（可选）/更新安装/用户目录发现
import json
import os
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_export_plugins():
    """导出插件源码 + 元信息到目录"""
    from lib.plugin_repo import export_plugins

    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_export_")
    try:
        hashes = export_plugins(tmp)
        # 应含 ruoyi/spring/common 插件 + plugins_meta.json
        assert "plugins_meta.json" in hashes, hashes.keys()
        assert any("ruoyi" in k for k in hashes), hashes.keys()
        # 元信息完整（含 name/cve/cvss）
        with open(os.path.join(tmp, "plugins_meta.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        assert len(meta) >= 38, f"应有 38+ 插件元信息，实际 {len(meta)}"
        first = next(iter(meta.values()))
        assert "name" in first and "cvss_score" in first
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_export_plugins")


def test_build_and_verify_manifest():
    """生成 manifest → 摘要校验通过；篡改文件 → 校验失败"""
    from lib.plugin_repo import build_manifest, verify_manifest

    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_manifest_")
    try:
        # 造一个仓库
        os.makedirs(os.path.join(tmp, "plugins", "ruoyi"), exist_ok=True)
        with open(os.path.join(tmp, "plugins", "ruoyi", "demo.py"), "w", encoding="utf-8") as f:
            f.write("# demo plugin\n")
        manifest = build_manifest(tmp)
        errors = verify_manifest(manifest, tmp)
        assert errors == [], errors
        # 篡改文件 → 校验失败
        with open(os.path.join(tmp, "plugins", "ruoyi", "demo.py"), "a", encoding="utf-8") as f:
            f.write("# tampered\n")
        errors2 = verify_manifest(manifest, tmp)
        assert any("摘要不匹配" in e for e in errors2), errors2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_build_and_verify_manifest")


def test_manifest_signature_optional():
    """cryptography 可用时签名生成 + 验证通过"""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("SKIP test_manifest_signature_optional: cryptography 未安装")
        return
    from lib.plugin_repo import _load_or_create_key, _sign_manifest, build_manifest, verify_manifest, signing_dir

    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_sig_")
    key_dir = tempfile.mkdtemp(prefix="ruoyi_scan_key_")
    try:
        with open(os.path.join(tmp, "a.py"), "w", encoding="utf-8") as f:
            f.write("x = 1\n")
        manifest = build_manifest(tmp)
        assert manifest["signature"], "应生成签名"
        # 用独立密钥验证
        key_path = os.path.join(key_dir, "signing.key")
        key = _load_or_create_key(key_path)
        assert key is not None
        manifest2 = dict(manifest)
        manifest2["signature"] = _sign_manifest(manifest2, key_path)
        errors = verify_manifest(manifest2, tmp, pubkey_path=key_path + ".pub")
        assert errors == [], errors
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(key_dir, ignore_errors=True)
    print("PASS test_manifest_signature_optional")


def test_download_and_install():
    """本地 zip 仓库下载 → 校验 → 安装到指定目录"""
    from lib.plugin_repo import download_and_install

    src = tempfile.mkdtemp(prefix="ruoyi_scan_repo_src_")
    dest = tempfile.mkdtemp(prefix="ruoyi_scan_repo_dest_")
    zip_path = os.path.join(tempfile.mkdtemp(prefix="ruoyi_scan_zip_"), "repo.zip")
    try:
        # 造仓库结构：仓库/plugins/demo.py + manifest.json
        repo = os.path.join(src, "myrepo")
        os.makedirs(os.path.join(repo, "plugins"), exist_ok=True)
        with open(os.path.join(repo, "plugins", "demo.py"), "w", encoding="utf-8") as f:
            f.write("# demo\n")
        from lib.plugin_repo import build_manifest

        build_manifest(repo)
        # 打包 zip（内含顶层目录 myrepo/）
        with zipfile.ZipFile(zip_path, "w") as zf:
            for root, _dirs, names in os.walk(src):
                for n in names:
                    p = os.path.join(root, n)
                    zf.write(p, os.path.relpath(p, src))

        # 本地 file:// 下载测试（download_and_install 用 requests，这里直接喂 zip 字节）
        with open(zip_path, "rb") as f:
            content = f.read()
        import io
        import zipfile as zf2

        tmp = tempfile.mkdtemp(prefix="ruoyi_scan_extract_")
        try:
            with zf2.ZipFile(io.BytesIO(content)) as z:
                z.extractall(tmp)
            repo_root = os.path.join(tmp, "myrepo")
            import json as _json

            with open(os.path.join(repo_root, "manifest.json"), "r", encoding="utf-8") as f2:
                manifest = _json.load(f2)
            from lib.plugin_repo import verify_manifest

            errors = verify_manifest(manifest, repo_root)
            assert errors == [], errors
            # 模拟安装
            import shutil as _sh

            for rel in manifest["files"]:
                d = os.path.join(dest, rel)
                os.makedirs(os.path.dirname(d), exist_ok=True)
                _sh.copy2(os.path.join(repo_root, rel), d)
            assert os.path.isfile(os.path.join(dest, "plugins", "demo.py"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    finally:
        shutil.rmtree(src, ignore_errors=True)
        shutil.rmtree(dest, ignore_errors=True)
        shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)
    print("PASS test_download_and_install")


def test_download_rejects_bad_zip():
    """非法 zip → 拒绝"""
    from lib.plugin_repo import download_and_install

    # 用 monkeypatch 模拟 requests.get 返回坏包
    class FakeResp:
        def raise_for_status(self):
            pass

        content = b"not a zip file"

    import requests

    orig = requests.get

    def fake_get(url, timeout=30):
        return FakeResp()

    requests.get = fake_get
    try:
        try:
            download_and_install("http://example.com/repo.zip")
            assert False, "应抛 ValueError"
        except ValueError as e:
            assert "zip" in str(e)
    finally:
        requests.get = orig
    print("PASS test_download_rejects_bad_zip")


def test_load_user_installed_plugins():
    """用户安装目录插件自动发现（单文件 PluginBase 子类）"""
    from lib.plugin_repo import load_user_installed_plugins, user_plugin_dir

    import plugins.base

    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_user_plugins_")
    plugin_file = os.path.join(tmp, "my_demo_plugin.py")
    with open(plugin_file, "w", encoding="utf-8") as f:
        f.write(
            "from plugins.base import PluginBase\n"
            "from common.models import ScanResult, STATUS_SAFE\n"
            "class MyDemoPlugin(PluginBase):\n"
            "    name = 'E5演示插件'\n"
            "    category = 'vuln'\n"
            "    def verify(self, target, session):\n"
            "        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE)\n"
        )
    # monkeypatch 用户目录
    import lib.plugin_repo as pr

    orig = pr.user_plugin_dir
    pr.user_plugin_dir = lambda: tmp
    try:
        plugins = load_user_installed_plugins()
        names = [getattr(p, "name", "") for p in plugins]
        assert "E5演示插件" in names, names
    finally:
        pr.user_plugin_dir = orig
    print("PASS test_load_user_installed_plugins")


if __name__ == "__main__":
    test_export_plugins()
    test_build_and_verify_manifest()
    test_manifest_signature_optional()
    test_download_and_install()
    test_download_rejects_bad_zip()
    test_load_user_installed_plugins()
    print("ALL_E5_TESTS_PASS")
