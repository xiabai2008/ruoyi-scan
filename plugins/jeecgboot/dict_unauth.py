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
        """检测 /sys/dict/list 是否未授权返回字典配置。

        @param target: 目标站点根 URL
        @param session: 复用的 HTTP 会话
        @return: ScanResult —— 命中 CONFIRMED；未命中 SAFE；网络异常 UNKNOWN
        """
        # 携带分页参数确保命中列表查询分支：放行鉴权时才可能返回 records 结构
        url = join_url(target, "/jeecg-boot/sys/dict/list?current=1&size=10")
        try:
            resp = session.get(url)
        except Exception as e:
            # 网络异常归 UNKNOWN：测不到 ≠ 安全，避免漏报
            emit(no("JeecgBoot 字典越权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 旧实现判定为 match_all(text, ["records", "code"])：records/code 是最通用的分页 JSON 键，
        # 任意分页接口都会误报。现改为解析 JSON 并校验结构成立：
        #   code == 200（若是 int）且 records/rows 为 list 且存在 total/success 之一。
        if resp.status_code == 200 and _is_dict_list_json(resp):
            emit(ok("存在 JeecgBoot 字典越权"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="未授权返回字典列表 JSON（records/rows 数组 + 分页结构成立）",
                fix=self.fix,
                extra={"vuln_type": "unauth", "plugin_name": "jeecg_dict_unauth"},
            )
        emit(no("不存在 JeecgBoot 字典越权"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
