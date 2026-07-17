# Thymeleaf/SpEL 模板注入：路径注入 __${7*7}__::.x 探针，按响应是否含 49 判定（保守判定）
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from urllib.parse import quote


class ThymeleafSstiPlugin(PluginBase):
    name = 'Thymeleaf/SpEL 模板注入'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = (
        'Thymeleaf 视图名注入：当 URL 路径被作为视图名传给 Thymeleaf 解析时，'
        '__${7*7}__::.x 会被求值为 49。本插件仅用算术表达式探针验证，不执行命令'
    )
    fix = (
        '禁止将用户可控路径直接作为视图名；使用 @Controller + @ResponseBody 显式标注；'
        '升级 Spring/Thymeleaf 修复 CVE-2023-38286 等已知漏洞；URL 白名单路由'
    )

    # 探针：__${7*7}__::.x 求值后 Thymeleaf 视图名变为 49（路径未配置时报错页含 49）
    # 不使用 Runtime.exec 类破坏性 payload（agents.md §7）
    PROBE = '__${7*7}__::.x'
    # 求值结果（用于判定命中）
    EVAL_RESULT = '49'
    # 原始表达式片段（用于排除「原文反射」误报）
    RAW_REFLECTION = '7*7'

    # 候选探测路径：RuoYi 不同版本的可疑端点（保守起见探测多个，任一命中即判存在）
    CANDIDATE_PATHS = [
        '__${7*7}__::.x',                    # 根路径注入
        'getInfo/__${7*7}__::.x',            # 用户信息接口路径片段注入
        'system/user/__${7*7}__::.x',        # 用户管理路径
        'demo/table/__${7*7}__::.x',         # 示例页面
    ]

    def verify(self, target, session):
        # 候选路径任一命中即判存在；全部无响应判 UNKNOWN；命中特征但无 49 判 SAFE
        got_response = False
        for path in self.CANDIDATE_PATHS:
            # Tomcat/Spring 默认会剥离 URL 路径中的裸花括号 {}，导致 __${7*7}__ 退化成
            # __$7*7__ 而失去求值能力。对探针中的特殊字符做百分号编码，使其在路径中存活，
            # 服务端解码后得到原始 __${7*7}__ 再被 SpEL 求值（与真实 SSTI 探测一致）。
            enc = path.replace('$', '%24').replace('{', '%7B').replace('}', '%7D')
            url = join_url(target, enc)
            try:
                resp = session.get(url)
            except Exception as e:
                # 网络异常不阻断，继续尝试下一个候选路径
                continue
            got_response = True
            text = resp.text or ''
            # 判定 1：响应含求值结果 49 且不含原始表达式 7*7（区分求值与原文反射）
            if self.EVAL_RESULT in text and self.RAW_REFLECTION not in text:
                # 进一步控误报：49 不能是状态码本身（如 490、49ms 等），需在响应体而非状态码
                # 这里要求 49 出现在响应体内容中（text），且不应是端口/版本号常见场景
                # 为保守起见，再校验：响应中含错误堆栈或 Thymeleaf/SpEL 关键字
                evidence_keywords = ['thymeleaf', 'TemplateEngine', 'SpEL', 'EL104', 'expression',
                                     'viewName', 'template', 'org.thymeleaf', 'Cannot resolve']
                lower_text = text.lower()
                has_engine_evidence = any(kw.lower() in lower_text for kw in evidence_keywords)
                # 严格判定：49 + 引擎关键字同时出现才算命中
                # 退化宽松：仅 49 且无 7*7 反射（可能为业务数值巧合，标 UNKNOWN 待复核）
                if has_engine_evidence:
                    print(ok('存在 Thymeleaf/SpEL 模板注入漏洞'))
                    return ScanResult(
                        kind='vuln', name=self.name, severity=self.severity,
                        status=STATUS_CONFIRMED, url=url,
                        evidence=f'响应含求值结果 {self.EVAL_RESULT} 且含模板引擎关键字，'
                                 f'前 200 字节：{text[:200]}',
                        extra={'probe': path, 'eval_result': self.EVAL_RESULT},
                        fix=self.fix,
                    )
                # 49 但无引擎关键字：保留 UNKNOWN，避免漏报也避免误报
                # 不直接判 SAFE（可能仅是错误页未暴露堆栈），亦不判 CONFIRMED
                print(no(f'Thymeleaf SSTI：候选 {path} 响应含 49 但无引擎关键字，待复核'))
                return ScanResult(
                    kind='vuln', name=self.name, status=STATUS_UNKNOWN, url=url,
                    evidence=f'响应含 {self.EVAL_RESULT} 但无模板引擎关键字，需人工复核',
                    extra={'probe': path},
                )

        # 所有候选路径均无 49 出现 → 判 SAFE（无求值迹象）
        if got_response:
            print(no('不存在 Thymeleaf/SpEL 模板注入漏洞'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=join_url(target, self.CANDIDATE_PATHS[0]),
                              evidence=f'所有候选路径均无求值结果 {self.EVAL_RESULT}')
        print(no('Thymeleaf SSTI：所有候选路径网络异常，无法判定'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                          url=join_url(target, self.CANDIDATE_PATHS[0]),
                          evidence='所有候选路径均网络异常')
