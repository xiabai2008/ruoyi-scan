# 链 2 专用插件：默认口令 → 登录链 → 任意文件上传 → webshell
#
# 两个原子步骤：
#   1. DefaultPasswordLoginPlugin: 默认口令登录验证（extra: login_token, username）
#   2. FileUploadVerifyPlugin: 任意文件上传验证（上传 JSP 探针，非真实 webshell）
#
# 注意：本链仅验证可利用性，不实际上传真实 webshell。
import hashlib
import json

import requests

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase

logger = get_logger(__name__)

# Ruoyi 常见默认口令（仅用于授权测试）
_DEFAULT_CREDS = [
    ("admin", "admin123"),
    ("ry", "admin123"),
    ("admin", "admin"),
]


def _parse_json(resp):
    """稳健解析响应 JSON：优先 resp.json()，失败/空对象时回退解析 resp.text

    Returns:
        解析出的 dict/list；无法解析时返回 None
    """
    try:
        body = resp.json()
    except Exception:
        body = None
    if isinstance(body, (dict, list)) and body:
        return body
    try:
        return json.loads(getattr(resp, "text", "") or "")
    except Exception:
        return None


def _upload_fields(body):
    """从上传响应 JSON 中提取 (url, fileName) 字段

    仅接受 JSON 对象（部分版本把字段包在 data 子对象内）；
    非对象或字段缺失时返回空串，避免 "url" 子串在任意 HTML/错误页中出现即误判接口可达。
    """
    if not isinstance(body, dict):
        return "", ""
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    return str(data.get("url") or ""), str(data.get("fileName") or "")


class DefaultPasswordLoginPlugin(PluginBase):
    """默认口令登录验证（链 2 步骤 1）

    尝试常见默认口令登录 Ruoyi 系统，成功时 extra.login_token 存储登录凭证。
    """

    name = "默认口令登录"
    severity = "high"
    category = "vuln"
    description = "尝试 Ruoyi 常见默认口令登录"
    fix = "强制修改默认口令，启用密码复杂度策略，限制登录失败次数"

    def verify(self, target, session):
        """尝试常见默认口令登录，成功时提取 token 存入 extra.login_token

        先探测验证码接口判断是否开启（开启则链路不可行），关闭后逐条
        尝试 _DEFAULT_CREDS；响应须为 HTTP 200 的业务 JSON 且含非空 token
        （或明确 code==200）才判定登录成功，避免用子串匹配把错误页误判为成功。

        @param target: 扫描目标 URL
        @param session: HTTP 会话（含登录态与 cookie 处理）
        @return: ScanResult；CONFIRMED=默认口令可用，SAFE=不可用或验证码开启，UNKNOWN=网络异常
        """
        login_url = join_url(target, "/login")
        captcha_url = join_url(target, "/captchaImage")

        # 探测验证码接口：请求失败判 UNKNOWN——无法确认验证码关闭时不得继续口令爆破
        try:
            captcha_resp = session.get(captcha_url)
        except requests.exceptions.RequestException as e:
            logger.debug("验证码接口请求失败: %s", e, exc_info=True)
            return ScanResult(
                kind="chain",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=captcha_url,
                evidence=f"验证码接口请求失败，无法判定验证码状态: {e}",
            )

        # 验证码状态判定：优先读若依显式返回的 captchaEnabled 字段；
        # 老版本无该字段时回退 uuid 特征（captchaImage 开启时响应必带 uuid）
        captcha_body = _parse_json(captcha_resp)
        if isinstance(captcha_body, dict) and "captchaEnabled" in captcha_body:
            captcha_enabled = bool(captcha_body.get("captchaEnabled"))
        else:
            captcha_enabled = "uuid" in (captcha_resp.text or "")

        if captcha_enabled:
            # 验证码开启，默认口令链路不可行（需配合 D3 验证码绕过）
            return ScanResult(
                kind="chain",
                name=self.name,
                status=STATUS_SAFE,
                url=login_url,
                evidence="验证码已开启，默认口令链路不可行",
            )

        # 尝试默认口令
        for username, password in _DEFAULT_CREDS:
            try:
                resp = session.post(
                    login_url,
                    json={
                        "username": username,
                        "password": password,
                    },
                )
            except requests.exceptions.RequestException as e:
                # 仅吞掉网络传输异常（并留痕）：编程错误不再被静默掩盖
                logger.debug("默认口令尝试请求失败（%s/%s）: %s", username, password, e, exc_info=True)
                continue

            # 结构化判定：解析业务 JSON 并检查 token/code 字段，
            # 不能再用 "token" in text 之类的子串匹配（HTML 错误页含 token/code 字样即误报成功）
            body = _parse_json(resp)
            token = ""
            code = None
            if isinstance(body, dict):
                token = str(body.get("token") or "")
                code = body.get("code")
            # 登录成功特征：HTTP 200 且返回非空 token（旧版仅返回 code==200）
            if resp.status_code == 200 and (token or code in (200, "200")):
                return ScanResult(
                    kind="chain",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=login_url,
                    evidence=f"默认口令登录成功: {username}/{password}",
                    fix=self.fix,
                    extra={"login_token": token, "username": username, "vuln_type": "default_password"},
                )

        return ScanResult(kind="chain", name=self.name, status=STATUS_SAFE, url=login_url, evidence="默认口令登录失败")


class FileUploadVerifyPlugin(PluginBase):
    """任意文件上传验证（链 2 步骤 2）

    验证 /common/upload 接口是否可上传 JSP 文件（仅验证接口可达性和权限，
    不实际上传恶意文件，仅发送一个无害的探针请求）。
    """

    name = "任意文件上传验证"
    severity = "high"
    category = "vuln"
    description = "验证文件上传接口可上传 JSP 文件（仅探针，非真实 webshell）"
    fix = "限制上传文件类型白名单，禁止 JSP/JSPX，上传目录禁止执行权限"

    def verify(self, target, session):
        """验证 /common/upload 上传接口：先测 txt 可达性，再测 JSP 是否被拦截

        仅发送无害探针（txt 文本 + JSP 注释），不实际上传可执行文件；
        判定基于响应 JSON 的 fileName/url 字段（结构化校验，避免任意含 "url"
        字样的页面被判为可达）；上传接口不可达或需鉴权时判定为 SAFE。

        @param target: 扫描目标 URL
        @param session: HTTP 会话（含登录态与 cookie 处理）
        @return: ScanResult；CONFIRMED=接口可达（jsp_allowed 区分风险等级），SAFE=需鉴权或不可达，UNKNOWN=网络异常
        """
        upload_url = join_url(target, "/common/upload")
        # 构造一个无害的探针文件（仅验证接口响应，不实际上传可执行文件）
        # 探针内容绑定目标 sha256 摘要：上传成功后可在回显 URL 中回溯校验，
        # 且跨进程稳定（hash() 受 PYTHONHASHSEED 加盐影响，不能作稳定标记）
        probe_content = "probe_" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
        try:
            # 发送一个合法后缀文件验证接口可达性
            files = {"file": ("test.txt", probe_content, "text/plain")}
            resp = session.post(upload_url, files=files)
            text = resp.text
        except Exception as e:
            return ScanResult(
                kind="chain", name=self.name, status=STATUS_UNKNOWN, url=upload_url, evidence=f"网络异常: {e}"
            )

        # 上传成功特征：HTTP 200/201 且响应 JSON 对象含非空 fileName/url 字段
        # （历史缺陷：`"fileName" in text or "url" in text` 会把错误页/任意 HTML 判为接口可达）
        up_url, up_name = _upload_fields(_parse_json(resp))
        if resp.status_code in (200, 201) and (up_url or up_name):
            # 进一步检查是否允许 JSP（通过上传 JSP 注释探针判断后缀是否被拦截）
            try:
                # JSP 注释探针：无任何执行副作用，仅用于判断 JSP 后缀是否被拦截
                jsp_files = {"file": ("probe.jsp", "<%-- probe --%>", "application/octet-stream")}
                jsp_resp = session.post(upload_url, files=jsp_files)
                jsp_url, jsp_name = _upload_fields(_parse_json(jsp_resp))
                if jsp_resp.status_code in (200, 201) and (jsp_url or jsp_name):
                    return ScanResult(
                        kind="chain",
                        name=self.name,
                        severity=self.severity,
                        status=STATUS_CONFIRMED,
                        url=upload_url,
                        evidence="文件上传接口允许 JSP 文件（webshell 风险）",
                        fix=self.fix,
                        extra={
                            "upload_endpoint": "/common/upload",
                            "jsp_allowed": True,
                            "vuln_type": "file_upload_jsp",
                        },
                    )
                # JSP 被拦截
                return ScanResult(
                    kind="chain",
                    name=self.name,
                    severity="medium",
                    status=STATUS_CONFIRMED,
                    url=upload_url,
                    evidence="文件上传接口可达但 JSP 被拦截",
                    fix=self.fix,
                    extra={
                        "upload_endpoint": "/common/upload",
                        "jsp_allowed": False,
                        "vuln_type": "file_upload_txt_only",
                    },
                )
            except Exception:
                logger.debug("JSP 上传验证失败", exc_info=True)

            # 仅 txt 上传成功
            return ScanResult(
                kind="chain",
                name=self.name,
                severity="medium",
                status=STATUS_CONFIRMED,
                url=upload_url,
                evidence="文件上传接口可达（仅验证 txt 上传）",
                fix=self.fix,
                extra={"upload_endpoint": "/common/upload", "vuln_type": "file_upload_reachable"},
            )

        # 需鉴权或不可达
        if "login" in text.lower() or resp.status_code in (302, 401, 403):
            return ScanResult(
                kind="chain", name=self.name, status=STATUS_SAFE, url=upload_url, evidence="上传接口需鉴权"
            )

        return ScanResult(
            kind="chain", name=self.name, status=STATUS_SAFE, url=upload_url, evidence="上传接口不可达或无特征"
        )
