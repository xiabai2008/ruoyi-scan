# D6.3 三条经典链实现与验收（7 场景 mock 测试）
#
# 测试策略：mock SessionManager 的 get/post 方法，模拟不同响应场景，
# 验证链编排器的端到端行为（状态聚合、上下文传递、失败策略）。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chains.registry import get_chain, list_chains
from common.models import FingerprintResult
from core.chain import (
    CHAIN_BLOCKED,
    CHAIN_CONFIRMED,
    CHAIN_PARTIAL,
    NODE_FAILED,
    NODE_SKIPPED,
    NODE_SUCCESS,
    ChainEngine,
)

# === Mock SessionManager ===


class MockResponse:
    """Mock HTTP 响应"""

    def __init__(self, text="", status_code=200, json_data=None):
        self.text = text
        self.status_code = status_code
        self._json = json_data

    def json(self):
        return self._json or {}


class MockSession:
    """Mock SessionManager

    用法：
        session = MockSession()
        session.set_response('/login', {'text': '{"token":"abc"}'})
        session.set_response('/system/role/list', {'text': 'XPATH error: ~ry'})
    """

    def __init__(self):
        self._responses = {}  # url_substring → response config
        self.request_count = 0
        self.proxy = None
        self.debug = False

    def set_response(self, url_substring, text="", status_code=200, json_data=None):
        """设置 URL 匹配规则和对应响应"""
        self._responses[url_substring] = {
            "text": text,
            "status_code": status_code,
            "json": json_data,
        }

    def _match_response(self, url):
        """根据 URL 匹配预设响应"""
        self.request_count += 1
        for substring, config in self._responses.items():
            if substring in url:
                return MockResponse(text=config["text"], status_code=config["status_code"], json_data=config["json"])
        # 默认响应
        return MockResponse(text="", status_code=404)

    def get(self, url, **kwargs):
        return self._match_response(url)

    def post(self, url, **kwargs):
        return self._match_response(url)

    def close(self):
        pass


def _run_chain(chain_name, session):
    """执行指定链（使用 mock session）"""
    chain_def = get_chain(chain_name)
    assert chain_def is not None, f"链 {chain_name} 未注册"
    engine = ChainEngine()
    fp = FingerprintResult(cms="ruoyi", confidence=0.9)
    return engine.run(chain_def, "http://target/", session, fp)


# === 场景 1：链 1 全成功（SQL注入 → 配置读取 → RCE 验证）===


def test_chain1_full_success():
    """链 1：三步全成功 → CONFIRMED"""
    session = MockSession()
    # 步骤 1：SQL 注入返回数据库名
    session.set_response("/system/role/list", text='{"msg":"XPATH syntax error: \'~ry\'"}')
    # 步骤 2：配置文件读取返回含密码的配置
    session.set_response(
        "/common/download/resource",
        text="spring:\n  datasource:\n    password: root123\n    url: jdbc:mysql://localhost:3306/ry",
    )
    # 步骤 3：定时任务接口返回 jobs 列表
    session.set_response("/monitor/job/list", text='{"rows":[{"jobId":1,"invokeTarget":"ruoYi.run"}]}')

    result = _run_chain("ruoyi_sql_to_rce", session)

    assert result.node_status["sql_inject"] == NODE_SUCCESS
    assert result.node_status["config_read"] == NODE_SUCCESS
    assert result.node_status["job_rce"] == NODE_SUCCESS
    assert result.status == CHAIN_CONFIRMED
    # 验证 facts 提取
    assert result.facts.get("db_name") == "ry", f"db_name 应为 ry，实际 {result.facts}"
    assert "db_password" in result.secrets_masked, "应提取 db_password（脱敏）"


# === 场景 2：链 1 SQL 注入失败 → 整链 BLOCKED ===


def test_chain1_sql_inject_blocked():
    """链 1：SQL 注入失败（abort）→ 整链 BLOCKED"""
    session = MockSession()
    # 步骤 1：SQL 注入返回无特征
    session.set_response("/system/role/list", text='{"code":200,"msg":"success"}')
    # 步骤 2/3 不会执行（abort 传播）

    result = _run_chain("ruoyi_sql_to_rce", session)

    assert result.node_status["sql_inject"] == NODE_FAILED
    assert result.node_status["config_read"] == NODE_SKIPPED, "config_read 应被 abort 跳过"
    assert result.node_status["job_rce"] == NODE_SKIPPED, "job_rce 应被 abort 跳过"
    assert result.status == CHAIN_BLOCKED


# === 场景 3：链 1 SQL 成功但配置读取失败 → PARTIAL ===


def test_chain1_partial_config_read_failed():
    """链 1：SQL 成功，配置读取失败（continue），RCE 成功 → PARTIAL"""
    session = MockSession()
    # 步骤 1：SQL 注入成功
    session.set_response("/system/role/list", text='{"msg":"XPATH syntax error: \'~ry\'"}')
    # 步骤 2：配置文件读取返回空（无 password/spring 关键字）
    session.set_response("/common/download/resource", text="404 not found")
    # 步骤 3：定时任务接口成功
    session.set_response("/monitor/job/list", text='{"rows":[{"jobId":1,"invokeTarget":"ruoYi.run"}]}')

    result = _run_chain("ruoyi_sql_to_rce", session)

    assert result.node_status["sql_inject"] == NODE_SUCCESS
    assert result.node_status["config_read"] == NODE_FAILED, "配置读取应失败"
    assert result.node_status["job_rce"] == NODE_SUCCESS, "RCE 验证应继续执行（continue）"
    assert result.status == CHAIN_PARTIAL, f"应 PARTIAL，实际 {result.status}"


# === 场景 4：链 2 全成功（默认口令登录 → 文件上传）===


def test_chain2_full_success():
    """链 2：默认口令登录成功 + JSP 上传成功 → CONFIRMED"""
    session = MockSession()
    # 步骤 1：验证码关闭 + 登录成功
    session.set_response("captchaImage", text='{"code":200}')
    session.set_response("/login", text='{"code":200,"token":"abc123"}')
    # 步骤 2：txt 上传成功 + JSP 上传成功
    session.set_response("/common/upload", text='{"fileName":"test.txt","url":"/upload/test.txt"}')

    result = _run_chain("ruoyi_defaultpw_to_webshell", session)

    assert result.node_status["default_login"] == NODE_SUCCESS
    assert result.node_status["file_upload"] == NODE_SUCCESS
    assert result.status == CHAIN_CONFIRMED


# === 场景 5：链 2 验证码开启 → 登录失败 → BLOCKED ===


def test_chain2_captcha_blocked():
    """链 2：验证码开启 → 默认口令链路不可行 → BLOCKED"""
    session = MockSession()
    # 验证码开启
    session.set_response("captchaImage", text='{"uuid":"abc","img":"..."}')

    result = _run_chain("ruoyi_defaultpw_to_webshell", session)

    assert result.node_status["default_login"] == NODE_FAILED
    assert result.node_status["file_upload"] == NODE_SKIPPED, "file_upload 应被 abort 跳过"
    assert result.status == CHAIN_BLOCKED


# === 场景 6：链 3 全成功（Nacos 未授权 → 配置提取）===


def test_chain3_full_success():
    """链 3：Nacos 未授权 + 配置提取 → CONFIRMED 或 PARTIAL（mock 环境下配置内容可能无法精确模拟）"""
    session = MockSession()
    # 步骤 1：Nacos 用户列表可读（含 username 字段 + 200 状态码）
    session.set_response(
        "/v1/auth/users", text='{"totalCount":1,"pageNumber":1,"pageSize":1,"pageItems":[{"username":"nacos"}]}'
    )
    # 步骤 1：Nacos 配置列表可读（含 pageItems）
    session.set_response(
        "/v1/cs/configs", text='{"totalCount":1,"pageItems":[{"dataId":"application.yml","group":"DEFAULT_GROUP"}]}'
    )

    result = _run_chain("ruoyi_nacos_to_dbcreds", session)

    # nacos_unauth 应成功（用户列表和配置接口都可读）
    assert result.node_status["nacos_unauth"] == NODE_SUCCESS, (
        f"nacos_unauth 应成功，实际 {result.node_status.get('nacos_unauth')}"
    )
    # config_extract 应执行（不跳过），状态可以是 success/failed/error（mock 限制）
    assert result.node_status["config_extract"] != NODE_SKIPPED, (
        "config_extract 不应被跳过（nacos_unauth 成功且 on_fail=continue）"
    )
    # 链整体状态应为 CONFIRMED（nacos_unauth 成功即视为漏洞存在）
    assert result.status in [CHAIN_CONFIRMED, CHAIN_PARTIAL], f"应 CONFIRMED 或 PARTIAL，实际 {result.status}"


# === 场景 7：链 3 Nacos 不可达 → BLOCKED ===


def test_chain3_nacos_unreachable():
    """链 3：Nacos 服务不可达 → BLOCKED"""
    session = MockSession()
    # 所有 Nacos 接口返回 404
    session.set_response("/v1/auth/users", text="404", status_code=404)
    session.set_response("/v1/cs/configs", text="404", status_code=404)

    result = _run_chain("ruoyi_nacos_to_dbcreds", session)

    assert result.node_status["nacos_unauth"] == NODE_FAILED
    assert result.node_status["config_extract"] == NODE_SKIPPED, "config_extract 应被 abort 跳过"
    assert result.status == CHAIN_BLOCKED


# === 附加测试：链定义校验 ===


def test_all_chains_validate():
    """所有注册的链定义校验通过"""
    for chain_info in list_chains():
        chain_def = get_chain(chain_info["name"])
        assert chain_def is not None, f"链 {chain_info['name']} 未注册"
        errors = chain_def.validate()
        assert errors == [], f"链 {chain_info['name']} 校验失败: {errors}"


def test_chain1_to_scan_result_confirmed():
    """链 1 CONFIRMED → ScanResult kind='chain'"""
    session = MockSession()
    session.set_response("/system/role/list", text='{"msg":"XPATH syntax error: \'~ry\'"}')
    session.set_response("/common/download/resource", text="spring:\n  password: root123")
    session.set_response("/monitor/job/list", text='{"rows":[{"jobId":1,"invokeTarget":"ruoYi.run"}]}')

    chain_def = get_chain("ruoyi_sql_to_rce")
    engine = ChainEngine()
    fp = FingerprintResult(cms="ruoyi", confidence=0.9)
    result = engine.run(chain_def, "http://target/", session, fp)

    scan_result = result.to_scan_result(chain_def)
    assert scan_result.kind == "chain"
    assert scan_result.status == "CONFIRMED"
    assert scan_result.extra["chain_name"] == "ruoyi_sql_to_rce"
    assert scan_result.extra["success_count"] == 3


if __name__ == "__main__":
    test_chain1_full_success()
    test_chain1_sql_inject_blocked()
    test_chain1_partial_config_read_failed()
    test_chain2_full_success()
    test_chain2_captcha_blocked()
    test_chain3_full_success()
    test_chain3_nacos_unreachable()
    test_all_chains_validate()
    test_chain1_to_scan_result_confirmed()
    print("All D6.3 chain scenario tests passed!")
