# 定时任务 RCE：未授权访问 /monitor/job/edit 接口存在性判定（不执行实际 RCE）
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_positive


class JobRcePlugin(PluginBase):
    name = '定时任务 RCE（未授权访问）'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = (
        '若依 /monitor/job/edit 接口未授权可访问：攻击者可编辑 invokeTarget 触发 RCE。'
        '本插件仅验证编辑接口未鉴权，不实际修改任务或触发执行（agents.md §7 安全合规）'
    )
    fix = (
        '强制 /monitor/job/** 鉴权；白名单校验 invokeTarget 调用目标，禁止 ruoYiConfig 等敏感方法；'
        '后台路径接入统一鉴权框架'
    )

    # 鉴权拦截关键字（命中即视为接口受保护，判 SAFE）
    AUTH_BLOCK_KEYWORDS = ['登录', '请先登录', 'unauthorized', '认证失败', '无法访问系统资源', 'signin', 'login']

    def verify(self, target, session):
        url = join_url(target, 'monitor/job/edit')
        # 用不存在的 jobId 探测：若未鉴权，服务端会进入业务校验返回「任务不存在」类响应
        # 若已鉴权，服务端在拦截器层即返回登录重定向/401（不会进入业务逻辑）
        # 该探测不会修改任何真实任务（jobId=99999 通常不存在）
        data = {
            'jobId': '99999',
            'jobName': 'ruoyi_scan_probe',
            'jobGroup': 'DEFAULT',
            'invokeTarget': 'ryTask.ryParams(\'ry\'',
            'cronExpression': '0/10 * * * * ?',
            'misfirePolicy': '1',
            'concurrent': '1',
            'status': '1',
        }
        try:
            resp = session.post(url, data=data)
        except Exception as e:
            print(no('定时任务 RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        code = getattr(resp, 'status_code', 0)

        # 解析 JSON 响应（RuoYi AjaxResult 通常含 code/msg）
        is_json = False
        body = {}
        try:
            body = resp.json()
            is_json = True
        except Exception:
            pass

        # 1) 若响应含鉴权拦截关键字 → 接口已保护，判 SAFE（使用 match_positive 统一降误报）
        if match_positive(text, self.AUTH_BLOCK_KEYWORDS):
            print(no('不存在定时任务 RCE 漏洞（编辑接口已鉴权）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                              evidence=f'响应含鉴权拦截关键字：{text[:200]}')

        # 2) HTTP 状态码 401/403 → 鉴权拦截（无论响应是否为 JSON）
        if code in (401, 403):
            print(no(f'不存在定时任务 RCE 漏洞（HTTP {code} 鉴权拦截）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                              evidence=f'HTTP {code} 鉴权拦截')

        # 3) JSON 响应且 code 表示进入了业务层
        #    - code == 200：通常表示操作成功（极端情况：未鉴权且 jobId 真的存在并修改成功，严重）
        #    - code == 500：业务校验失败（如「定时任务不存在」），证明已绕过鉴权进入业务层
        #    - code == 401/403：鉴权失败（已在第 2 步兜底）
        if is_json:
            r_code = body.get('code')
            msg = str(body.get('msg', ''))
            # 鉴权失败码（JSON body 内的 code）
            if r_code in (401, 403):
                print(no(f'不存在定时任务 RCE 漏洞（接口已鉴权，JSON code={r_code}）'))
                return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                                  evidence=f'code={r_code} msg={msg}')
            # 业务层响应（200 成功 / 500 任务不存在）→ 绕过鉴权，存在未授权访问
            # 注意：仅 code==200/500 判 CONFIRMED；其他业务码（400 参数错误等）不判，
            # 避免「r_code is not None」导致任意 JSON 响应均误报（P0 修复）
            if r_code in (200, 500):
                print(ok('存在定时任务 RCE 漏洞（未授权访问编辑接口）'))
                return ScanResult(
                    kind='vuln', name=self.name, severity=self.severity,
                    status=STATUS_CONFIRMED, url=url,
                    evidence=f'未鉴权进入业务层：code={r_code} msg={msg}',
                    extra={'code': r_code, 'msg': msg},
                    fix=self.fix,
                )
            # 其他业务码（如 400 参数错误、404 等）：无法明确判定是否绕过鉴权，标 UNKNOWN
            # （不判 SAFE 避免漏报已修复但返回奇怪码的系统；也不判 CONFIRMED 避免误报）
            print(no(f'定时任务 RCE：JSON code={r_code} 不在已知范围，判 UNKNOWN'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, url=url,
                              evidence=f'JSON 业务码 {r_code} 不在 (200,500) 范围：{msg}')

        # 4) 非 JSON 响应但 HTTP 200 + 非鉴权关键字 → 可能是 HTML 编辑页（未授权渲染）
        if code == 200 and not match_positive(text, ['login', 'signin', '登录']):
            print(ok('存在定时任务 RCE 漏洞（未授权访问编辑页面）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'HTTP 200 且无鉴权关键字，响应前 200 字节：{text[:200]}',
                fix=self.fix,
            )

        # 5) 其他情形：无法明确判定（如非 200 的非 JSON 响应，且无关键字）
        print(no('定时任务 RCE：响应特征不明确，判 UNKNOWN'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, url=url,
                          evidence=f'HTTP {code} 响应前 200 字节：{text[:200]}')
