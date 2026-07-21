# D25：插件 SDK（自定义插件开发框架）
#
# 提供插件模板生成、验证、文档生成工具，方便用户开发自定义插件
#
# 使用方式：
#   # 生成插件模板
#   python main.py --plugin-init my_plugin --category ruoyi
#   # → 生成 plugins/ruoyi/my_plugin.py
#
#   # 验证插件
#   python main.py --plugin-check plugins/ruoyi/my_plugin.py
#   # → 检查字段完整性、verify() 方法、合规映射等
#
#   # 列出所有插件元数据
#   python main.py --plugin-list
#
# 插件开发规范：
#   1. 必须继承 PluginBase
#   2. 必须实现 verify(target, session) 方法
#   3. 必须填写 name/severity/category/description/fix 字段
#   4. 建议填写 cve/cvss_vector/compliance/fix_detail/reproduce
#   5. verify() 必须返回 ScanResult
import importlib
import os
import pkgutil
import re
from typing import Any, Dict, List, Tuple

from core.loader import discover_plugin_packages

# ============================================================
# 插件模板
# ============================================================

PLUGIN_TEMPLATE = '''# {description}
# CVSS: {cvss_vector}
# 合规: {compliance}
from plugins.base import PluginBase
from common.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from core.http import join_url


class {class_name}(PluginBase):
    """{name} 检测插件"""
    name = '{name}'
    cve = '{cve}'
    severity = '{severity}'
    category = '{category}'
    description = '{description}'
    fix = '{fix}'
    fix_detail = (
        '【升级方案】TODO: 升级至 X.X.X+\\n'
        '【代码修复】TODO: 修改 XXX 方法\\n'
        '【配置加固】TODO: application.yml 配置\\n'
        '【WAF 规则】TODO: 拦截规则\\n'
        '【合规】{compliance}'
    )
    reproduce = (
        '# 1. 探测端点\\n'
        'curl -i "{probe_url}"\\n'
        '\\n'
        '# 预期响应：TODO: 响应特征\\n'
    )
    # D2: 影响版本
    affected_versions = ''
    # D12: CVSS v3.1 + 合规映射
    cvss_vector = '{cvss_vector}'
    compliance = '{compliance}'
    # D7: WAF 绕过支持
    vuln_type = 'rce'  # rce/sqli/xss/lfi/ssl/ssrf/info/auth/other
    supports_waf_bypass = False

    def verify(self, target, session):
        """检测 {name}

        Args:
            target: 目标 URL
            session: SessionManager 实例
        Returns:
            ScanResult
        """
        url = join_url(target, '{probe_path}')
        try:
            resp = session.get(url)
        except Exception as e:
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        # TODO: 实现检测逻辑
        if 'TODO_INDICATOR' in text:
            print(ok(f'存在 {{self.name}}'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 TODO_INDICATOR 特征',
                fix=self.fix,
            )
        print(no(f'不存在 {{self.name}}'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=url, evidence='响应不含特征')
'''


def generate_plugin(
    name: str,
    category: str = "common",
    severity: str = "high",
    cve: str = "N/A",
    description: str = "",
    fix: str = "",
    probe_path: str = "/",
    probe_url: str = "http://target/",
    cvss_vector: str = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    compliance: str = "OWASP:A03:2021;等保2.0:8.1.3",
) -> str:
    """生成插件源代码

    Args:
        name: 插件名称（如 'SQL注入'）
        category: 插件类别（ruoyi/spring/common）
        severity: 严重度（high/medium/low）
        cve: CVE 编号
        description: 漏洞描述
        fix: 修复建议
        probe_path: 探测路径
        probe_url: 探测 URL（模板展示用）
        cvss_vector: CVSS v3.1 向量
        compliance: 合规映射
    Returns:
        插件源代码字符串
    """
    # 生成类名：将插件名转为 PascalCase
    class_name = _to_pascal_case(name)

    if not description:
        description = f"{name} 检测"
    if not fix:
        fix = f"修复 {name} 漏洞"

    return PLUGIN_TEMPLATE.format(
        name=name,
        class_name=class_name,
        category=category,
        severity=severity,
        cve=cve,
        description=description,
        fix=fix,
        probe_path=probe_path,
        probe_url=probe_url,
        cvss_vector=cvss_vector,
        compliance=compliance,
    )


def _to_pascal_case(name: str) -> str:
    """将插件名转为 PascalCase 类名

    如 'SQL注入' → 'SQL注入Plugin'
    如 'file_read' → 'FileReadPlugin'
    如 'my-plugin' → 'MyPluginPlugin'（始终追加 Plugin 后缀）
    """
    # 去除特殊字符
    cleaned = re.sub(r"[^\w\u4e00-\u9fff]", "_", name)
    # 按下划线分割并首字母大写
    parts = cleaned.split("_")
    result = "".join(p[:1].upper() + p[1:] for p in parts if p)
    # 始终追加 Plugin 后缀（保证类名一致性）
    return result + "Plugin"


def init_plugin_file(name: str, category: str = "common", output_dir: str = None, **kwargs) -> str:
    """生成插件文件并写入磁盘

    Args:
        name: 插件名称
        category: 插件类别
        output_dir: 输出目录（默认 plugins/<category>/）
        **kwargs: 传递给 generate_plugin 的参数
    Returns:
        生成的文件路径
    """
    if output_dir is None:
        # 找到项目根目录
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(project_root, "plugins", category)

    os.makedirs(output_dir, exist_ok=True)

    # 生成文件名：插件名转为下划线
    filename = _to_filename(name)
    filepath = os.path.join(output_dir, f"{filename}.py")

    # 检查文件是否已存在
    if os.path.exists(filepath):
        raise FileExistsError(f"插件文件已存在: {filepath}")

    # 生成源代码
    source = generate_plugin(name, category=category, **kwargs)

    # 写入文件
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(source)

    return filepath


def _to_filename(name: str) -> str:
    """将插件名转为文件名（下划线小写）"""
    # 中文保留，英文转下划线
    result = re.sub(r"([A-Z])", r"_\1", name).lower().lstrip("_")
    result = re.sub(r"\s+", "_", result)
    return result


# ============================================================
# 插件验证
# ============================================================


def check_plugin(filepath: str) -> Tuple[bool, List[str], List[str]]:
    """验证插件文件完整性

    Args:
        filepath: 插件文件路径
    Returns:
        (是否通过, 错误列表, 警告列表)
    """
    errors = []
    warnings = []

    if not os.path.isfile(filepath):
        errors.append(f"文件不存在: {filepath}")
        return False, errors, warnings

    # 读取源代码
    with open(filepath, encoding="utf-8") as f:
        source = f.read()

    # 检查必需的类属性
    required_attrs = ["name", "severity", "category", "description", "fix"]
    for attr in required_attrs:
        pattern = rf'^\s*{attr}\s*=\s*[\'"].+[\'"]'
        if not re.search(pattern, source, re.MULTILINE):
            errors.append(f"缺少必需属性: {attr}")

    # 检查 verify 方法
    if "def verify(self, target, session):" not in source and "def verify(self,target,session):" not in source:
        errors.append("缺少 verify(self, target, session) 方法")

    # 检查 ScanResult 导入
    if "ScanResult" not in source:
        errors.append("未导入 ScanResult")

    # 检查 PluginBase 继承
    if "PluginBase" not in source:
        errors.append("未继承 PluginBase")

    # 建议的属性（警告）
    recommended_attrs = ["cve", "cvss_vector", "compliance", "fix_detail", "reproduce"]
    for attr in recommended_attrs:
        pattern = rf'^\s*{attr}\s*=\s*[\'"].*[\'"]'
        if not re.search(pattern, source, re.MULTILINE):
            warnings.append(f"建议填写属性: {attr}")

    # 检查 TODO 标记
    if "TODO" in source:
        todo_count = source.count("TODO")
        warnings.append(f"含 {todo_count} 个 TODO 标记，请完善检测逻辑")

    return len(errors) == 0, errors, warnings


def check_plugin_by_import(filepath: str) -> Tuple[bool, List[str], List[str]]:
    """通过导入方式验证插件（更严格）

    Args:
        filepath: 插件文件路径
    Returns:
        (是否通过, 错误列表, 警告列表)
    """
    errors = []
    warnings = []

    try:
        # 动态导入
        import importlib.util

        spec = importlib.util.spec_from_file_location("plugin_module", filepath)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # 查找 PluginBase 子类
        from plugins.base import PluginBase

        plugin_classes = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, PluginBase)
                and attr is not PluginBase
                and attr.__module__ == module.__name__
            ):
                plugin_classes.append(attr)

        if not plugin_classes:
            errors.append("未找到 PluginBase 子类")
            return False, errors, warnings

        if len(plugin_classes) > 1:
            warnings.append(f"发现 {len(plugin_classes)} 个插件类，建议每文件只含一个")

        # 验证每个插件类
        for cls in plugin_classes:
            instance = cls()
            # 检查必需属性
            for attr in ["name", "severity", "category", "description", "fix"]:
                val = getattr(instance, attr, "")
                if not val:
                    errors.append(f"{cls.__name__}.{attr} 为空")

            # 检查 verify 方法
            if not hasattr(instance, "verify"):
                errors.append(f"{cls.__name__} 缺少 verify 方法")

            # 建议属性
            for attr in ["cve", "cvss_vector", "compliance", "fix_detail", "reproduce"]:
                val = getattr(instance, attr, "")
                if not val:
                    warnings.append(f"{cls.__name__}.{attr} 为空（建议填写）")

    except Exception as e:
        errors.append(f"导入失败: {e}")

    return len(errors) == 0, errors, warnings


# ============================================================
# 插件列表
# ============================================================


def list_all_plugins() -> List[Dict[str, Any]]:
    """列出所有插件的元数据

    Returns:
        插件元数据列表，每项含 name/category/severity/cve/cvss/compliance
    """
    from plugins.base import PluginBase

    plugins = []

    for pkg_name in discover_plugin_packages():
        try:
            pkg = importlib.import_module(pkg_name)
            for _, name, is_pkg in pkgutil.iter_modules(pkg.__path__):
                if is_pkg or name.startswith("_"):
                    continue
                mn = f"{pkg_name}.{name}"
                try:
                    m = importlib.import_module(mn)
                    for an in dir(m):
                        a = getattr(m, an)
                        if (
                            isinstance(a, type)
                            and issubclass(a, PluginBase)
                            and a is not PluginBase
                            and a.__module__ == mn
                        ):
                            try:
                                instance = a()
                                plugins.append(
                                    {
                                        "module": mn,
                                        "class": an,
                                        "name": getattr(instance, "name", ""),
                                        "category": getattr(instance, "category", ""),
                                        "severity": getattr(instance, "severity", ""),
                                        "cve": getattr(instance, "cve", ""),
                                        "cvss_vector": getattr(instance, "cvss_vector", ""),
                                        "compliance": getattr(instance, "compliance", ""),
                                        "has_fix_detail": bool(getattr(instance, "fix_detail", "")),
                                        "has_reproduce": bool(getattr(instance, "reproduce", "")),
                                    }
                                )
                            except Exception:
                                continue
                except Exception:
                    continue
        except Exception:
            continue

    return plugins


def generate_plugin_docs(output_path: str) -> str:
    """生成插件文档（Markdown 格式）

    Args:
        output_path: 输出文件路径
    Returns:
        生成的文件路径
    """
    plugins = list_all_plugins()

    lines = [
        "# Ruoyi-Scan 插件列表",
        "",
        f"共 {len(plugins)} 个插件",
        "",
        "| 模块 | 类名 | 漏洞名称 | 类别 | 严重度 | CVE | CVSS | 合规 | 修复详情 | 复现命令 |",
        "|------|------|----------|------|--------|-----|------|------|----------|----------|",
    ]

    for p in plugins:
        has_fix = "✓" if p["has_fix_detail"] else "✗"
        has_reproduce = "✓" if p["has_reproduce"] else "✗"
        lines.append(
            f"| {p['module']} | {p['class']} | {p['name']} | {p['category']} | "
            f"{p['severity']} | {p['cve']} | {p['cvss_vector']} | {p['compliance']} | "
            f"{has_fix} | {has_reproduce} |"
        )

    lines.append("")
    lines.append("## 统计")
    lines.append("")

    # 按类别统计
    categories = {}
    for p in plugins:
        cat = p["category"]
        categories[cat] = categories.get(cat, 0) + 1
    lines.append("### 按类别")
    for cat, count in sorted(categories.items()):
        lines.append(f"- {cat}: {count} 个")

    # 按严重度统计
    severities = {}
    for p in plugins:
        sev = p["severity"]
        severities[sev] = severities.get(sev, 0) + 1
    lines.append("")
    lines.append("### 按严重度")
    for sev, count in sorted(severities.items()):
        lines.append(f"- {sev}: {count} 个")

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path
