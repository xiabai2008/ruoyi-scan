# 任意文件上传：POST /common/upload 上传无害 .txt 探针，按 JSON 响应判定接口可写
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no


class FileUploadPlugin(PluginBase):
    name = '任意文件上传'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '若依后台 /common/upload 未授权可写：上传无害 .txt 探针，响应 JSON 含 url/fileName 字段即存在'
    fix = '强制 /common/upload 鉴权；服务端白名单校验扩展名；上传目录不可执行；按用户隔离存储路径'

    # 探针文件名与内容（agents.md §7：仅做存在性验证，不上传可执行文件）
    PROBE_NAME = 'ruoyi_scan_probe.txt'
    PROBE_CONTENT = 'ruoyi-scan-probe-benign-content'

    def verify(self, target, session):
        url = target + 'common/upload'
        # multipart/form-data：RuoYi 默认字段名为 file
        files = {'file': (self.PROBE_NAME, self.PROBE_CONTENT, 'text/plain')}
        try:
            resp = session.post(url, files=files)
        except Exception as e:
            print(no('任意文件上传（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        # 响应体文本（错误页可能非 JSON，需容错）
        text = resp.text or ''
        ctype = resp.headers.get('Content-Type', '') if hasattr(resp, 'headers') else ''

        # 控误报：必须是 JSON 响应 + 解析成功 + 含 url 或 fileName 字段
        # 不直接判定 200：RuoYi 部分版本上传成功 code=200 但 HTTP 状态可能仍是 200，统一以 JSON 内容为准
        is_json = 'json' in ctype.lower() or text.lstrip().startswith('{')
        if not is_json:
            print(no('不存在任意文件上传漏洞'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                              evidence='响应非 JSON（疑似已鉴权拦截）')

        try:
            data = resp.json()
        except Exception:
            print(no('不存在任意文件上传漏洞'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                              evidence='响应非合法 JSON')

        # RuoYi 上传响应：{"code":200,"fileName":"...","url":"/profile/upload/...","newFileName":"..."}
        # 部分版本无 code，但必有 url 或 fileName
        up_url = data.get('url') or ''
        file_name = data.get('fileName') or ''
        code = data.get('code')

        # 控误报：url/fileName 非空且 url 以 http 或 / 开头（排除任意字符串响应）
        url_valid = bool(up_url) and (up_url.startswith('http') or up_url.startswith('/'))
        name_valid = bool(file_name)

        # 上传成功判定：code==200 或 (url_valid 或 name_valid)
        # 仅含 code != 200 的 msg 不算命中（如 "请先登录"）
        if code == 200 or url_valid or name_valid:
            # 进一步排除鉴权拦截：若 msg 含登录关键字，判 SAFE
            msg = str(data.get('msg', ''))
            if any(kw in msg for kw in ['登录', '请先登录', 'unauthorized', '未授权']):
                print(no('不存在任意文件上传漏洞（接口已鉴权）'))
                return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                                  evidence=f'响应 msg={msg}（疑似拦截）')
            print(ok('存在任意文件上传漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'上传响应 JSON：code={code} url={up_url} fileName={file_name}',
                extra={'uploaded_url': up_url, 'file_name': file_name, 'code': code},
                fix=self.fix,
            )

        print(no('不存在任意文件上传漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence=f'响应未含上传字段：{text[:200]}')
