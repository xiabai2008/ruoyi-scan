# ThinkPHP APP_DEBUG 信息泄露：调试模式开启时，错误页返回完整异常栈与框架路径
# 探测任意触发异常的请求，响应含 think\exception 等调试特征即判存在（信息泄露，属中危）
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 调试模式特征（与 lab/thinkphp_server.py vuln 模式一致；python 字面量 '\\' 即响应中的反斜杠）
DEBUG_MARKER = 'think\\exception'


class ThinkphpDebugInfoPlugin(PluginBase):
    name = 'ThinkPHP APP_DEBUG 调试信息泄露'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = 'APP_DEBUG=true 时错误页暴露异常栈、绝对路径与 SQL，便于攻击者收集环境信息'
    fix = '生产环境设置 app_debug=false；自定义错误页；禁止向客户端输出异常详情'

    def verify(self, target, session):
        # 触发一个可被框架捕获的异常（探测参数，不造成破坏）
        url = join_url(target, '/index.php') + '?debug_probe=1'
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('ThinkPHP APP_DEBUG 信息泄露（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if DEBUG_MARKER in text:
            print(ok('存在 ThinkPHP APP_DEBUG 调试信息泄露'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含调试异常特征：{DEBUG_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP APP_DEBUG 调试信息泄露'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含调试异常特征（APP_DEBUG 已关闭或未触发异常）')
