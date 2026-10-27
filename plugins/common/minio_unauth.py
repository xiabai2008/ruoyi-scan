# MinIO 未授权访问检测（F7 中间件包）
# 非破坏性：GET /minio/health/live 确认服务存在；GET /minio/ 无鉴权枚举 bucket 特征
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from lib.reporter import emit
from plugins.base import PluginBase


class MinioUnauthPlugin(PluginBase):
    """检测 MinIO 未授权访问（F7 中间件）：非破坏性确认服务存在并无凭证枚举 bucket"""

    name = "MinIO 未授权访问"
    # 本插件检测匿名 bucket 枚举/未授权访问，与 CVE-2023-28432（bootstrap 接口环境变量泄露）不是同一问题
    cve = "N/A"
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
        """检测 MinIO 是否未授权访问（非破坏性）

        @param target: 目标站点 URL
        @param session: 已配置的 HTTP 会话（复用其超时/代理设置）
        @return: ScanResult（CONFIRMED 表示无凭证即可列举 bucket）
        """
        # 1. 确认 MinIO 服务存在
        health_url = join_url(target, "/minio/health/live")
        try:
            resp = session.get(health_url)
        except Exception as e:
            emit(no("MinIO 未授权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=health_url, evidence=str(e))
        # 200 为健康检查正常响应；301/302/400 只有在响应头/正文含 MinIO 专有信号
        # （Server: MinIO / X-Amz-* / 正文 minio 字样）时才视为服务存在——
        # 否则任何返回这些状态码的无关服务器或 WAF 错误页都会进入 bucket 枚举阶段
        code = getattr(resp, "status_code", 0)
        headers_text = str(getattr(resp, "headers", "") or "").lower()
        body_text = (resp.text or "").lower()
        minio_signal = "minio" in headers_text or "x-amz" in headers_text or "minio" in body_text
        if code != 200 and not minio_signal:
            emit(no("未检测到 MinIO 服务"))
            # 三态纪律：SAFE 必须带可复核证据（否则统一降级 UNKNOWN）
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_SAFE,
                url=health_url,
                evidence=f"健康检查返回 HTTP {code} 且无 MinIO 专有特征（Server/X-Amz/正文），未发现 MinIO 服务",
            )
        # 2. 无凭证列举 bucket（匿名桶列表）
        root_url = join_url(target, "/minio/")
        try:
            resp2 = session.get(root_url)
            text2 = resp2.text or ""
        except Exception as e:
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=root_url, evidence=str(e))
        # 匿名列举成功时 /minio/ 必须返回 2xx 且正文含 bucket 列表结构；
        # 403/404 错误页（AccessDenied/<Error>、控制台登录页）即使含 "minio"/"bucket" 字样也不算未授权
        if resp2.status_code == 200 and match_positive(
            text2,
            ["bucket", "storage-class", "<ListAllMyBucketsResult"],
            negatives=["AccessDenied", "<Error>"],
        ):
            emit(ok("存在 MinIO 未授权访问"))
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
        emit(no("不存在 MinIO 未授权访问"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=root_url,
            evidence=f"/minio/ 返回 HTTP {resp2.status_code}，未出现匿名 bucket 列表特征",
        )
