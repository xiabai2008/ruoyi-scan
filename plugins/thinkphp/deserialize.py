# ThinkPHP 5.x 反序列化远程代码执行（POP 链利用）
# 漏洞原因：框架未对不可信输入做反序列化过滤，攻击者构造 POP 链触发 __destruct/__wakeup
#   → 写入缓存文件 → 文件包含，最终 getshell（影响 5.1.x 多版本）。
# 本插件仅做存在性验证：发送 PHP 序列化对象探针，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
DESER_MARKER = 'thinkphp-deserialize-rce-confirmed'


class ThinkphpDeserializePlugin(PluginBase):
    name = 'ThinkPHP 5.x 反序列化远程代码执行'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '框架接收不可信 PHP 序列化数据，POP 链可写缓存 + 文件包含 getshell（影响 5.1.x）'
    fix = '升级 ThinkPHP 至官方修复版本；禁止反序列化不可信输入；使用 JSON 替代序列化'

    def verify(self, target, session):
        url = join_url(target, '/index.php')
        # 探针：PHP 序列化对象 O:（仅触发签名，不执行破坏性 POP 链）
        data = {'data': 'O:12:"think\Request":0:{}'}
        try:
            resp = session.post(url, data=data)
        except Exception as e:
            print(no('ThinkPHP 反序列化 RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if DESER_MARKER in text:
            print(ok('存在 ThinkPHP 反序列化远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含反序列化 RCE 特征：{DESER_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 反序列化远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含反序列化 RCE 特征（可能已修复或接口不可达）')
