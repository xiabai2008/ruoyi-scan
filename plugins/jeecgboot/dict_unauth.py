# JeecgBoot 字典越权：/sys/dict/list 未授权返回字典配置（信息泄露）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import parse_json_body
from lib.reporter import emit
from plugins.base import PluginBase


def _is_dict_list_json(resp):
    """判定响应是否为 JeecgBoot 字典/分页列表业务 JSON（结构成立，而非仅含通用键）

    正向证据要求（全部满足）：
    - 能解析为 JSON 对象（解析失败 → 未命中）
    - code == 200（若 code 是 int；缺省或非 int 时跳过此约束）
    - records 或 rows 为 list（真实分页数据的载体）
    - 存在 total 或 success 之一（分页/业务成功标志）
    """
    body = parse_json_body(resp)
    if not isinstance(body, dict):
        # 非 JSON 响应（HTML 拦截页/网关错误页）一律不命中
        return False
    code = body.get("code")
    if isinstance(code, int) and code != 200:
        return False
    records = body.get("records")
    rows = body.get("rows")
    if not (isinstance(records, list) or isinstance(rows, list)):
        return False
    return ("total" in body) or ("success" in body)


class JeecgDictUnauthPlugin(PluginBase):
    name = "JeecgBoot 字典越权"
    cve = "CVE-2023-1454"
    severity = "medium"
    category = "vuln"
    description = "JeecgBoot /sys/dict/list 未授权访问，泄露系统字典配置"
    fix = "升级 JeecgBoot；sys 接口强制鉴权"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.5.2+\n"
        "【配置加固】sa-token 拦截器移除 /sys/** 免鉴权白名单\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/jeecg-boot/sys/dict/list?current=1&size=10"\n'
        "# 预期响应：JSON 含 records 字段与字典数据（未授权可访问）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False

    def verify(self, target, session):
        """检测 /sys/dict/list 是否未授权返回字典配置（结构化 JSON 校验）。

        @param target: 目标站点根 URL
        @param session: 复用的 HTTP 会话
        @return: ScanResult —— 命中 CONFIRMED；未命中 SAFE；网络异常 UNKNOWN
        """
        # 上下文路径候选：JeecgBoot 默认 /jeecg-boot 前缀；target 已自带该前缀时避免重复拼接
        # （join_url 只去重斜杠、不会去掉重复的路径段），同时兜底探测网关剥离前缀的部署
        if target.rstrip("/").endswith("/jeecg-boot"):
            prefixes = [""]
        else:
            prefixes = ["/jeecg-boot", ""]

        got_response = False
        last_url = join_url(target, "/sys/dict/list")
        last_error = ""
        for prefix in prefixes:
            # 携带分页参数确保命中列表查询分支：放行鉴权时才可能返回 records 结构
            url = join_url(target, f"{prefix}/sys/dict/list?current=1&size=10")
            last_url = url
            try:
                resp = session.get(url)
            except Exception as e:
                last_error = str(e)
                continue
            got_response = True
            # 结构化判定：解析 JSON 并校验分页结构（records 数组 + total），
            # 不再用 "records"/"code" 子串——任意含这两个词的 HTML/JSON 页面都会误报 CONFIRMED
            if self._is_dict_page(resp):
                emit(ok("存在 JeecgBoot 字典越权"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    # 附带响应片段：报告需能自证命中形态，便于人工区分真实字典 JSON 与误报
                    evidence=f"未授权返回字典分页 JSON（records + total）：{(resp.text or '')[:200]}",
                    fix=self.fix,
                    extra={"vuln_type": "unauth", "plugin_name": "jeecg_dict_unauth"},
                )
        if not got_response:
            # 所有候选路径网络异常 → UNKNOWN（测不到 ≠ 安全，避免漏报）
            emit(no("JeecgBoot 字典越权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=last_url, evidence=last_error)
        emit(no("不存在 JeecgBoot 字典越权"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=last_url)

    @staticmethod
    def _is_dict_page(resp) -> bool:
        """响应是否为 JeecgBoot 字典分页业务 JSON

        接受两种形态：Result 包装（result.records + result.total + 顶层 code）
        或直接分页对象，均要求 records 为数组且含 total 字段。
        """
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
        except Exception:
            return False
        if not isinstance(body, dict):
            return False
        page = body.get("result") if isinstance(body.get("result"), dict) else body
        return isinstance(page.get("records"), list) and "total" in page and "code" in body
