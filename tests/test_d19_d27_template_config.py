# D19/D27 扫描模板 + YAML 配置文件 测试
#
# D19 覆盖：
#   1. ScanTemplate 数据类字段
#   2. TEMPLATES 字典含 4 个模板（quick/deep/compliance/dengbao）
#   3. get_template() / list_templates()
#   4. apply_template() 填充默认参数（不覆盖 CLI 显式指定）
#   5. filter_plugins() 按严重度/类别/合规过滤
#
# D27 覆盖：
#   1. load_yaml_config() 加载 YAML 文件
#   2. _simple_yaml_parse() 简易解析器
#   3. _infer_type() 类型推断
#   4. normalize_config_keys() key 别名映射
#   5. merge_config_with_args() 合并优先级
#   6. apply_config_to_args() 完整流程
#   7. create_example_config() 生成示例文件
import os
import sys
import tempfile
import types
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.scan_templates import (
    ScanTemplate, TEMPLATES, get_template, list_templates,
    apply_template, filter_plugins, set_parser_defaults,
)
from lib.config_loader import (
    load_yaml_config, _simple_yaml_parse, _infer_type,
    normalize_config_keys, merge_config_with_args, apply_config_to_args,
    create_example_config, set_parser_defaults as cl_set_defaults,
)


# ============================================================
# D19：扫描模板
# ============================================================

class TestScanTemplateDataclass:
    """ScanTemplate 数据类测试"""

    def test_scan_template_fields(self):
        """ScanTemplate 含所有必要字段"""
        t = ScanTemplate(
            name='test', display_name='测试', description='desc',
            severity_filter={'high'}, category_filter={'vuln'},
            compliance_filter={'OWASP'},
        )
        assert t.name == 'test'
        assert t.display_name == '测试'
        assert t.severity_filter == {'high'}
        assert t.category_filter == {'vuln'}
        assert t.compliance_filter == {'OWASP'}

    def test_scan_template_defaults(self):
        """ScanTemplate 默认值为空集合"""
        t = ScanTemplate(name='t', display_name='T', description='d')
        assert t.severity_filter == set()
        assert t.category_filter == set()
        assert t.compliance_filter == set()
        assert t.default_args == {}
        assert t.estimated_time == ''


class TestTemplatesRegistry:
    """模板注册表测试"""

    def test_templates_has_four(self):
        """TEMPLATES 含 4 个模板"""
        assert len(TEMPLATES) >= 4

    def test_templates_keys(self):
        """TEMPLATES 含 quick/deep/compliance/dengbao"""
        assert 'quick' in TEMPLATES
        assert 'deep' in TEMPLATES
        assert 'compliance' in TEMPLATES
        assert 'dengbao' in TEMPLATES

    def test_get_template_quick(self):
        """get_template('quick') 返回快速扫描模板"""
        t = get_template('quick')
        assert t is not None
        assert t.name == 'quick'
        assert 'high' in t.severity_filter

    def test_get_template_deep(self):
        """get_template('deep') 返回深度扫描模板"""
        t = get_template('deep')
        assert t is not None
        assert t.name == 'deep'
        assert t.default_args.get('crawl') is True
        assert t.default_args.get('subdomain') is True
        assert t.default_args.get('js_extract') is True

    def test_get_template_compliance(self):
        """get_template('compliance') 返回 OWASP 合规扫描模板"""
        t = get_template('compliance')
        assert t is not None
        assert 'OWASP' in t.compliance_filter
        assert 'vuln' in t.category_filter

    def test_get_template_dengbao(self):
        """get_template('dengbao') 返回等保合规扫描模板"""
        t = get_template('dengbao')
        assert t is not None
        assert '等保' in t.compliance_filter
        assert 'vuln' in t.category_filter

    def test_get_template_not_found(self):
        """get_template('unknown') 返回 None"""
        assert get_template('nonexistent') is None

    def test_list_templates_returns_all(self):
        """list_templates() 返回所有模板"""
        templates = list_templates()
        assert len(templates) >= 4
        names = {t.name for t in templates}
        assert {'quick', 'deep', 'compliance', 'dengbao'} <= names


class TestApplyTemplate:
    """apply_template() 测试"""

    def setup_method(self):
        """注入测试用默认值"""
        set_parser_defaults({
            'threads': 1, 'timeout': 10, 'crawl': False,
            'crawl_depth': 2, 'crawl_max_pages': 50,
            'subdomain': False, 'js_extract': False,
        })

    def test_apply_template_fills_defaults(self):
        """模板填充未指定的默认参数"""
        args = types.SimpleNamespace(
            threads=1, timeout=10, crawl=False,
            crawl_depth=2, crawl_max_pages=50,
            subdomain=False, js_extract=False,
        )
        tmpl = apply_template(args, 'deep', verbose=False)
        assert tmpl is not None
        # deep 模板应填充 crawl=True, subdomain=True, js_extract=True
        assert args.crawl is True
        assert args.subdomain is True
        assert args.js_extract is True
        assert args.crawl_depth == 3
        assert args.crawl_max_pages == 100

    def test_apply_template_preserves_cli_args(self):
        """模板不覆盖 CLI 显式指定的参数"""
        # threads=10 与默认值 1 不同 → 视为 CLI 显式指定 → 不覆盖
        args = types.SimpleNamespace(
            threads=10, timeout=10, crawl=False,
            crawl_depth=2, crawl_max_pages=50,
            subdomain=False, js_extract=False,
        )
        apply_template(args, 'deep', verbose=False)
        # threads 应保持 10（CLI 显式指定）
        assert args.threads == 10

    def test_apply_template_quick(self):
        """quick 模板填充 threads=5"""
        args = types.SimpleNamespace(
            threads=1, timeout=10, crawl=False,
            crawl_depth=2, crawl_max_pages=50,
            subdomain=False, js_extract=False,
        )
        apply_template(args, 'quick', verbose=False)
        assert args.threads == 5
        assert args.timeout == 8
        assert args.crawl is False  # quick 不启用爬虫

    def test_apply_template_not_found(self):
        """模板不存在时返回 None"""
        args = types.SimpleNamespace()
        result = apply_template(args, 'nonexistent', verbose=False)
        assert result is None


class TestFilterPlugins:
    """filter_plugins() 测试"""

    def _make_plugin_cls(self, name='test', severity='high', category='vuln', compliance=''):
        """创建模拟插件类"""
        class FakePlugin:
            pass
        FakePlugin.severity = severity
        FakePlugin.category = category
        FakePlugin.compliance = compliance
        FakePlugin.__name__ = name
        return FakePlugin

    def test_filter_by_severity(self):
        """按严重度过滤"""
        plugins = [
            self._make_plugin_cls('high1', severity='high'),
            self._make_plugin_cls('low1', severity='low'),
            self._make_plugin_cls('medium1', severity='medium'),
        ]
        tmpl = ScanTemplate(name='t', display_name='T', description='d',
                            severity_filter={'high'})
        filtered = filter_plugins(plugins, tmpl)
        assert len(filtered) == 1
        assert filtered[0].__name__ == 'high1'

    def test_filter_by_category(self):
        """按类别过滤"""
        plugins = [
            self._make_plugin_cls('vuln1', category='vuln'),
            self._make_plugin_cls('recon1', category='recon'),
        ]
        tmpl = ScanTemplate(name='t', display_name='T', description='d',
                            category_filter={'vuln'})
        filtered = filter_plugins(plugins, tmpl)
        assert len(filtered) == 1
        assert filtered[0].__name__ == 'vuln1'

    def test_filter_by_compliance_owasp(self):
        """按 OWASP 合规映射过滤"""
        plugins = [
            self._make_plugin_cls('has_owasp', compliance='等保2.0:8.1.4;OWASP:A01:2021'),
            self._make_plugin_cls('no_owasp', compliance='等保2.0:8.1.4'),
            self._make_plugin_cls('empty', compliance=''),
        ]
        tmpl = ScanTemplate(name='t', display_name='T', description='d',
                            compliance_filter={'OWASP'})
        filtered = filter_plugins(plugins, tmpl)
        assert len(filtered) == 1
        assert filtered[0].__name__ == 'has_owasp'

    def test_filter_by_compliance_dengbao(self):
        """按等保合规映射过滤"""
        plugins = [
            self._make_plugin_cls('has_dengbao', compliance='等保2.0:8.1.4;OWASP:A01:2021'),
            self._make_plugin_cls('only_owasp', compliance='OWASP:A03:2021'),
        ]
        tmpl = ScanTemplate(name='t', display_name='T', description='d',
                            compliance_filter={'等保'})
        filtered = filter_plugins(plugins, tmpl)
        assert len(filtered) == 1
        assert filtered[0].__name__ == 'has_dengbao'

    def test_filter_no_rules(self):
        """无过滤规则时返回全部"""
        plugins = [
            self._make_plugin_cls('p1'),
            self._make_plugin_cls('p2'),
        ]
        tmpl = ScanTemplate(name='t', display_name='T', description='d')
        filtered = filter_plugins(plugins, tmpl)
        assert len(filtered) == 2

    def test_filter_no_template(self):
        """模板为 None 时返回全部"""
        plugins = [self._make_plugin_cls('p1')]
        filtered = filter_plugins(plugins, None)
        assert len(filtered) == 1

    def test_filter_real_plugins_compliance(self):
        """使用真实插件验证 compliance 模板过滤"""
        import importlib
        import pkgutil
        from plugins.base import PluginBase

        all_plugins = []
        for pkg_name in ['plugins.ruoyi', 'plugins.spring', 'plugins.common']:
            try:
                pkg = importlib.import_module(pkg_name)
                for _, name, is_pkg in pkgutil.iter_modules(pkg.__path__):
                    if is_pkg or name.startswith('_'):
                        continue
                    mn = f'{pkg_name}.{name}'
                    try:
                        m = importlib.import_module(mn)
                        for an in dir(m):
                            a = getattr(m, an)
                            if (isinstance(a, type) and issubclass(a, PluginBase)
                                    and a is not PluginBase and a.__module__ == mn):
                                all_plugins.append(a)
                    except Exception:
                        continue
            except Exception:
                continue

        # compliance 模板应过滤出含 OWASP 映射的插件
        tmpl = get_template('compliance')
        filtered = filter_plugins(all_plugins, tmpl)
        # 应有至少 1 个插件通过过滤
        assert len(filtered) >= 1, 'compliance 模板应过滤出至少 1 个插件'
        # 所有过滤后的插件都应含 OWASP 映射
        for cls in filtered:
            assert 'OWASP' in (getattr(cls, 'compliance', '') or ''), \
                f'{cls.__name__} 应含 OWASP 映射'


# ============================================================
# D27：YAML 配置文件
# ============================================================

class TestInferType:
    """_infer_type() 类型推断测试"""

    def test_infer_bool_true(self):
        assert _infer_type('true') is True
        assert _infer_type('True') is True
        assert _infer_type('yes') is True
        assert _infer_type('on') is True

    def test_infer_bool_false(self):
        assert _infer_type('false') is False
        assert _infer_type('False') is False
        assert _infer_type('no') is False
        assert _infer_type('off') is False

    def test_infer_int(self):
        assert _infer_type('42') == 42
        assert _infer_type('0') == 0
        assert _infer_type('-5') == -5

    def test_infer_float(self):
        assert _infer_type('3.14') == 3.14
        assert _infer_type('0.5') == 0.5

    def test_infer_str(self):
        assert _infer_type('hello') == 'hello'
        assert _infer_type('http://example.com') == 'http://example.com'

    def test_infer_empty(self):
        assert _infer_type('') == ''


class TestSimpleYamlParse:
    """_simple_yaml_parse() 简易解析器测试"""

    def test_parse_basic(self):
        """基本 key: value 解析"""
        content = 'target: http://example.com/\nthreads: 5\ndebug: true'
        result = _simple_yaml_parse(content)
        assert result['target'] == 'http://example.com/'
        assert result['threads'] == 5
        assert result['debug'] is True

    def test_parse_comments(self):
        """注释行被忽略"""
        content = '# 这是注释\ntarget: http://x/\n# 另一个注释\nthreads: 3'
        result = _simple_yaml_parse(content)
        assert len(result) == 2
        assert result['target'] == 'http://x/'
        assert result['threads'] == 3

    def test_parse_quoted_string(self):
        """引号字符串去引号"""
        content = 'proxy: "http://127.0.0.1:8080"\nreport: \'./reports\''
        result = _simple_yaml_parse(content)
        assert result['proxy'] == 'http://127.0.0.1:8080'
        assert result['report'] == './reports'

    def test_parse_empty_lines(self):
        """空行被忽略"""
        content = 'target: http://x/\n\n\ndebug: false'
        result = _simple_yaml_parse(content)
        assert len(result) == 2

    def test_parse_error_no_colon(self):
        """无冒号行报错"""
        with pytest.raises(ValueError):
            _simple_yaml_parse('invalid line without colon')


class TestNormalizeConfigKeys:
    """normalize_config_keys() key 别名映射测试"""

    def test_normalize_hyphen_to_underscore(self):
        """横线 key 映射为下划线"""
        config = {'proxy-file': '/path', 'crawl-depth': 3}
        result = normalize_config_keys(config)
        assert 'proxy_file' in result
        assert 'crawl_depth' in result
        assert result['proxy_file'] == '/path'
        assert result['crawl_depth'] == 3

    def test_normalize_underscore_kept(self):
        """下划线 key 保持不变"""
        config = {'proxy_file': '/path', 'crawl_depth': 3}
        result = normalize_config_keys(config)
        assert 'proxy_file' in result
        assert 'crawl_depth' in result

    def test_normalize_known_keys(self):
        """已知 key 映射到 argparse dest"""
        config = {
            'target': 'http://x/',
            'threads': 5,
            'report-format': 'html',
            'bypass-waf': 'auto',
        }
        result = normalize_config_keys(config)
        assert 'u' in result  # target → u
        assert 'threads' in result
        assert 'report_format' in result
        assert 'bypass_waf' in result

    def test_normalize_unknown_key_kept(self):
        """未知 key 保留"""
        config = {'custom_key': 'value'}
        result = normalize_config_keys(config)
        assert 'custom_key' in result

    def test_normalize_mode_is_none(self):
        """mode 映射为 None（由 main() 单独处理）"""
        config = {'mode': 'u'}
        result = normalize_config_keys(config)
        assert 'mode' not in result  # mode → None，被过滤掉


class TestLoadYamlConfig:
    """load_yaml_config() 文件加载测试"""

    def test_load_yaml_file(self):
        """加载 YAML 文件"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml',
                                         delete=False, encoding='utf-8') as f:
            f.write('target: http://example.com/\nthreads: 5\ndebug: true\n')
            filepath = f.name
        try:
            config = load_yaml_config(filepath)
            assert config['target'] == 'http://example.com/'
            assert config['threads'] == 5
            assert config['debug'] is True
        finally:
            os.unlink(filepath)

    def test_load_yaml_file_not_found(self):
        """文件不存在抛 FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            load_yaml_config('/nonexistent/path/config.yml')

    def test_load_empty_yaml(self):
        """空 YAML 文件返回空字典"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml',
                                         delete=False, encoding='utf-8') as f:
            f.write('')
            filepath = f.name
        try:
            config = load_yaml_config(filepath)
            assert config == {}
        finally:
            os.unlink(filepath)


class TestMergeConfigWithArgs:
    """merge_config_with_args() 合并优先级测试"""

    def test_merge_overrides_defaults(self):
        """配置文件覆盖默认值"""
        args = types.SimpleNamespace(
            threads=1, timeout=10, crawl=False, subdomain=False, proxy=None,
        )
        config = {'threads': 5, 'crawl': True}
        cl_set_defaults({
            'threads': 1, 'timeout': 10, 'crawl': False,
            'subdomain': False, 'proxy': None,
        })
        merged, overridden = merge_config_with_args(args, config)
        assert merged.threads == 5
        assert merged.crawl is True
        assert 'threads' in overridden
        assert 'crawl' in overridden

    def test_merge_preserves_cli_args(self):
        """配置文件不覆盖 CLI 显式指定的参数"""
        # threads=10 与默认 1 不同 → CLI 显式指定 → 不覆盖
        args = types.SimpleNamespace(
            threads=10, timeout=10, crawl=False, subdomain=False, proxy=None,
        )
        config = {'threads': 5}
        cl_set_defaults({
            'threads': 1, 'timeout': 10, 'crawl': False,
            'subdomain': False, 'proxy': None,
        })
        merged, overridden = merge_config_with_args(args, config)
        # threads 应保持 10（CLI 显式指定）
        assert merged.threads == 10
        assert 'threads' not in overridden


class TestCreateExampleConfig:
    """create_example_config() 示例文件生成测试"""

    def test_create_example_config(self):
        """生成示例配置文件"""
        with tempfile.TemporaryDirectory() as d:
            filepath = os.path.join(d, 'example.yml')
            create_example_config(filepath)
            assert os.path.exists(filepath)
            # 验证内容含关键字段
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            assert 'target:' in content
            assert 'template:' in content
            assert 'threads:' in content
            assert 'proxy:' in content
            assert 'crawl:' in content


class TestConfigTemplateIntegration:
    """配置文件 + 模板集成测试"""

    def test_config_then_template(self):
        """配置文件先加载，模板后应用（模板优先级 > 配置文件）"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml',
                                         delete=False, encoding='utf-8') as f:
            f.write('threads: 3\ncrawl: false\ntimeout: 12\n')
            filepath = f.name
        try:
            # 模拟 main() 中的流程
            args = types.SimpleNamespace(
                config=filepath,
                template='deep',
                threads=1, timeout=10, crawl=False,
                crawl_depth=2, crawl_max_pages=50,
                subdomain=False, js_extract=False,
            )

            # Step 1: 加载配置文件
            config_data = load_yaml_config(filepath)
            config_data = normalize_config_keys(config_data)

            # 注入测试用默认值
            cl_set_defaults({
                'threads': 1, 'timeout': 10, 'crawl': False,
                'crawl_depth': 2, 'crawl_max_pages': 50,
                'subdomain': False, 'js_extract': False,
            })
            set_parser_defaults({
                'threads': 1, 'timeout': 10, 'crawl': False,
                'crawl_depth': 2, 'crawl_max_pages': 50,
                'subdomain': False, 'js_extract': False,
            })

            args, _overridden = merge_config_with_args(args, config_data)
            # 配置文件应覆盖默认值
            assert args.threads == 3
            assert args.timeout == 12

            # Step 2: 应用模板
            # 模板默认值与配置文件后的值比较：threads=3 ≠ 默认 1 → 视为"已指定" → 不覆盖
            apply_template(args, 'deep', verbose=False)
            # threads 应保持 3（配置文件已设置，模板不覆盖）
            assert args.threads == 3
            # crawl: 配置文件设为 False（与默认相同），模板应覆盖为 True
            assert args.crawl is True
            assert args.subdomain is True
            assert args.js_extract is True
        finally:
            os.unlink(filepath)


if __name__ == '__main__':
    import pytest
    sys.exit(pytest.main([__file__, '-v']))
