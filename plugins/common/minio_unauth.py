# MinIO 未授权访问检测（F7 中间件包）
# 非破坏性：GET /minio/health/live 确认服务存在；GET /minio/ 无鉴权枚举 bucket 特征
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from plugins.base import PluginBase


class MinioUnauthPlugin(PluginBase):
    name = "MinIO 未授权访问"
    cve = "CVE-2023-28432"
    severity = "medium"
    category = "vuln"
    description = "MinIO 对象存储未授权访问（默认配置匿名可列举/读取 bucket）"
    fix = "配置 MinIO 访问凭证（AccessKey/SecretKey）；关闭匿名策略"
    fix_detail = (
        "【配置加固】设置 MINIO_ROOT_USER/MINIO_ROOT_PASSWORD 强凭证\n"
        "【策略修复】bucket 策略移除匿名访问（s3:GetObject 不授权 *）\n"
        "【网络加固】云安全组限制 9000/9001 端口访问来源\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/minio/health/live"   # 服务健康检查\n'
        'curl "http://target/minio/"              # 无凭证列举 bucket\n'
        "# 预期响应：health/live 返回 200；/minio/ 返回 bucket 列表 JSON"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False

    def verify(self, target, session):
        # 1. 确认 MinIO 服务存在
        health_url = join_url(target, "/minio/health/live")
        try:
            resp = session.get(health_url)
        except Exception as e:
            print(no("MinIO 未授权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=health_url, evidence=str(e))
        if resp.status_code not in (200, 301, 302, 400):
            print(no("未检测到 MinIO 服务"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=health_url)
        # 2. 无凭证列举 bucket（匿名桶列表）
        root_url = join_url(target, "/minio/")
        try:
            resp2 = session.get(root_url)
            text2 = resp2.text or ""
        except Exception as e:
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=root_url, evidence=str(e))
        if match_positive(text2, ["bucket", "storage-class", "minio"]):
            print(ok("存在 MinIO 未授权访问"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=root_url,
                evidence="无凭证返回 bucket 列表",
                fix=self.fix,
                extra={"vuln_type": "unauth", "plugin_name": "minio_unauth"},
            )
        print(no("不存在 MinIO 未授权访问"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=root_url)
