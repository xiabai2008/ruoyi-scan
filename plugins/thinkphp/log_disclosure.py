# ThinkPHP runtime 日志文件暴露（信息泄露）
# 漏洞原因：runtime/log/ 目录未限制 web 访问，攻击者可读取应用日志（含请求参数、绝对路径与 SQL）。
# 本插件仅做存在性验证：访问默认日志路径，检测响应是否返回日志内容特征。
import datetime

from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
LOG_MARKER = 'thinkphp-log-disclosure'


class ThinkphpLogDisclosurePlugin(PluginBase):
    name = 'ThinkPHP runtime 日志文件暴露'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = 'runtime/log/ 目录可未授权访问，日志含请求参数、绝对路径与 SQL，造成信息泄露'
    fix = '禁止 web 访问 runtime 目录（web 服务器 deny 规则）；日志仅服务端可读'

    def verify(self, target, session):
        # 默认日志路径 runtime/log/YYYYMMDD.log（探测当天日志）
        today = datetime.datetime.now().strftime('%Y%m%d')
        url = target.rstrip('/') + '/runtime/log/' + today + '.log'
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('ThinkPHP runtime 日志暴露（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        # 判定：签名靶场 marker 命中 OR 真实漏洞响应（日志内容特征）
        if resp.status_code == 200 and LOG_MARKER in text:
            print(ok('存在 ThinkPHP runtime 日志文件暴露'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含日志特征：{LOG_MARKER}',
                fix=self.fix,
            )
        # 真实日志格式：[ 2024-01-01T00:00:00 ] INFO: [ app ] ...
        # 关键特征：ISO 时间戳 + 日志级别 + 模块名
        if resp.status_code == 200 and len(text) > 50:
            log_features = ['INFO:', 'ERROR:', 'DEBUG:', 'WARNING:', 'NOTICE:']
            has_log_level = any(f in text for f in log_features)
            # 时间戳特征：[ YYYY-MM-DDTHH:MM:SS ] 或 [ YYYY-MM-DD HH:MM:SS ]
            has_timestamp = ('[ 20' in text and 'T' in text) or ('[ 20' in text and ':' in text)
            if has_log_level and has_timestamp:
                print(ok('存在 ThinkPHP runtime 日志文件暴露（真实漏洞响应）'))
                return ScanResult(
                    kind='vuln', name=self.name, severity=self.severity,
                    status=STATUS_CONFIRMED, url=url,
                    evidence='响应含日志格式特征（ISO 时间戳 + 日志级别），证实日志文件可访问',
                    fix=self.fix,
                )
        print(no('不存在 ThinkPHP runtime 日志文件暴露'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='日志路径未暴露（404 或非日志内容）')
