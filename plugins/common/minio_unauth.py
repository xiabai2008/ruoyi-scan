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
    # v1.6：被测命题是「**不登录**就能访问」。共享会话可能已被默认口令/爆破插件
    # 登录污染，带着 admin 的 cookie 探到这里拿到的 200 只证明「登录后能访问」，
    # 不构成未授权漏洞（客户现场：Swagger 开了但配了认证 → 误报「未授权访问」）。
    # 声明后引擎会在会话被污染时注入干净的 SessionManager。
    anonymous_probe = True
    supports_waf_bypass = False

    def verify(self, target, session):
        """未授权判定必须用**匿名会话**：高权会话下的 200 是「登录后可读」，不是未授权。

        与 unauth_batch / ruoyi_swagger_unauth 同一口径（core.session.SessionManager.anonymous）。
        复用共享会话时，若调用方注入了 cookie/token（--auth / --auth-login），
        本插件会把「已鉴权的正常响应」误读成「未授权暴露」——客户现场最常见的形态是
        「接口开了但配了认证」，此时报告会写「未授权访问」，复核时被当场打回。
        """
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            return self._verify_anonymous(target, probe)
        finally:
            if probe is not session:
                probe.close()

    def _verify_anonymous(self, target, session):
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
        #
        # ⚠ 探测路径的选择（2026-11-01 C4-2 实测纠正）
        #
        # 旧实现只探 /minio/ —— 那是 **MinIO 控制台入口**，永远返回登录页 HTML，
        # 不含 bucket 列表。真实 MinIO 的匿名列举走 **S3 协议根路径 GET /**，
        # 返回 <ListAllMyBucketsResult> XML。两个路径语义完全不同。
        #
        # 实测（用真实 S3 协议响应复刻的靶场）：
        #   GET /            → 200 + <ListAllMyBucketsResult><Bucket>hospital-reports...（漏洞点）
        #   GET /minio/      → 200 + 控制台 SPA HTML（登录页，无 bucket）
        #   → 旧实现探 /minio/ 判 SAFE，**漏报**
        #
        # 与 rocketmq_unauth 是同一类缺陷：照着自己想象的路径写，没按真实产品形态验证。
        #
        # 现按顺序探两个路径，任一命中即 CONFIRMED：
        #   1. "/"       S3 ListBuckets（真实漏洞点）
        #   2. "/minio/" 兼容少数把控制台挂在该前缀下、且配置了匿名桶列表的部署
        candidates = [join_url(target, "/"), join_url(target, "/minio/")]
        last_err = None
        last_url = candidates[0]
        last_status = 0
        for cand in candidates:
            last_url = cand
            try:
                resp2 = session.get(cand)
            except Exception as e:
                last_err = e
                continue
            last_status = resp2.status_code
            text2 = resp2.text or ""
            # 匿名列举成功：2xx + 正文含 bucket 列表结构。
            # 403/404 错误页（AccessDenied/<Error>）与控制台登录页即使含
            # "minio"/"bucket" 字样也不算未授权 —— 靠 negatives 排除。
            # 正向特征只认 **S3 XML 结构**，不认裸关键字 "bucket"。
            # 实测踩过：控制台登录页里出现 "bucket manager" 这类字样就会被早先的
            # 泛用 positive "bucket" 命中 → 把安全站点误判成未授权。
            # 真实的匿名列举响应一定带 <ListAllMyBucketsResult> 或 <ListBucketResult>
            # 这类 S3 专有元素名，控制台 HTML 不会有。
            if resp2.status_code == 200 and match_positive(
                text2,
                ["<ListAllMyBucketsResult", "<ListBucketResult", "<Bucket><Name>"],
                negatives=["AccessDenied", "<Error>"],
            ):
                emit(ok("存在 MinIO 未授权访问"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=cand,
                    evidence=f"无凭证从 {cand} 返回 bucket 列表（S3 ListBuckets 匿名可读）",
                    fix=self.fix,
                    extra={"vuln_type": "unauth", "plugin_name": "minio_unauth"},
                )
        if last_err is not None and last_status == 0:
            # 两个路径都请求失败：测不到 ≠ 安全
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=last_url, evidence=str(last_err))
        emit(no("不存在 MinIO 未授权访问"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=last_url,
            evidence=f"探测了 S3 根路径与 /minio/（最后 {last_url} 返回 HTTP {last_status}），未出现匿名 bucket 列表特征",
        )
