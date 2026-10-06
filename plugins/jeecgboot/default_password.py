# JeecgBoot 默认口令：admin/123456 登录探测（brute 类，存在性验证）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import parse_json_body
from lib.reporter import emit
from plugins.base import PluginBase


def _is_login_success(resp):
    """判定响应是否为登录成功（严格解析 JSON，非子串匹配）

    正向证据要求：
    - 能解析为 JSON 对象
    - token 为非空字符串（兼容顶层 token 与 JeecgBoot result.token 两种结构）
    - 业务码成立：code 为 200/0 或缺失，或 success 为真
    - msg 不含登录失败词（错误/失败/error）
    """
    # 统一走 parse_json_body：优先 .json()，失败回退解析 text（兼容测试桩/老版本客户端）
    body = parse_json_body(resp)
    if not isinstance(body, dict):
        return False

    # 顶层 token 优先；缺失时回退取 result.token（JeecgBoot 常见嵌套结构）
    token = body.get("token")
    if not token and isinstance(body.get("result"), dict):
        token = body["result"].get("token")
    if not isinstance(token, str) or not token.strip():
        return False

    code = body.get("code")
    code_ok = code in (200, 0, None)
    success_ok = body.get("success") is True
    if not (code_ok or success_ok):
        return False

    msg = str(body.get("msg", ""))
    failure_kw = ["错误", "失败", "error"]
    if any(kw in msg for kw in failure_kw):
        return False
    return True


class JeecgDefaultPasswordPlugin(PluginBase):
    name = "JeecgBoot 默认口令"
    cve = "N/A"
    severity = "medium"
    category = "brute"
    description = "JeecgBoot 后台默认口令 admin/123456（未修改则可直接登录）"
    fix = "修改默认口令 admin/123456；启用强密码策略"
    fix_detail = (
        "【配置加固】首次登录强制修改默认口令 admin/123456\n"
        "【代码修复】开启密码强度校验（8 位以上含数字字母）\n"
        "【合规】OWASP A07:2021 身份认证失败；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl -X POST "http://target/jeecg-boot/sys/login" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"username":"admin","password":"123456","code":"","checkKey":""}\'\n'
        "# 预期响应：JSON 含 token 字段（登录成功）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.4;OWASP:A07:2021"
    vuln_type = "auth"
    supports_waf_bypass = False

    def verify(self, target, session):
        """探测 JeecgBoot 后台默认口令 admin/123456 能否直接登录。

        @param target: 目标站点根 URL，用于拼接登录接口路径
        @param session: 复用的 HTTP 会话（带连接池与超时配置）
        @return: ScanResult —— 登录成功 CONFIRMED；口令无效 SAFE；网络异常 UNKNOWN
        """
        url = join_url(target, "/jeecg-boot/sys/login")
        try:
            resp = session.post(
                url,
                # 验证码字段 code/checkKey 留空：多数版本登录接口不强制校验验证码，可空值直达
                data='{"username":"admin","password":"123456","code":"","checkKey":""}',
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            # 网络异常无法证明口令状态：归 UNKNOWN 而非 SAFE，避免把"测不到"误报成"安全"
            emit(no("JeecgBoot 默认口令（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 旧实现判定为 200 且 "token" in text：任何含 "token" 字样的 200 页面（前端模板、
        # 文档页、错误提示）都会误报。现改为解析 JSON，要求 token 为非空字符串，
        # 且（code 为 200/0/缺失 或 success 为真），并排除 msg 含失败词的响应。
        if resp.status_code == 200 and _is_login_success(resp):
            emit(ok("存在 JeecgBoot 默认口令"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="admin/123456 登录成功（JSON 返回非空 token 且业务码成立）",
                fix=self.fix,
                extra={"vuln_type": "default_password", "plugin_name": "jeecg_default_pw"},
            )
        emit(no("不存在 JeecgBoot 默认口令"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
