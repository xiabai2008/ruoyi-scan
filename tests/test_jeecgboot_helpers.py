# JeecgBoot 结构化判定 helper 单元测试
# 背景：合并后新增的 JSON 结构校验 helper 此前无直接用例，异常/边界分支未覆盖。
# 这些 helper 是「判定过宽」修复的核心（防通用子串误报），值得独立守护。
from plugins.jeecgboot.dict_unauth import _is_dict_list_json
from plugins.jeecgboot.file_upload_jmreport import _is_upload_success_json
from plugins.jeecgboot.sql_inject_jmreport import _has_sql_result_echo


class _Resp:
    """最小响应替身：payload=None 时 json() 抛异常（模拟非 JSON 响应）"""

    status_code = 200

    def __init__(self, payload=None, text="", headers=None):
        self._payload = payload
        self.text = text
        self.headers = headers or {}

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def test_is_dict_list_json_cases():
    # 正向：records/rows 为 list + total/success 之一
    assert _is_dict_list_json(_Resp({"records": [{"id": 1}], "total": 1})) is True
    assert _is_dict_list_json(_Resp({"rows": [], "success": True})) is True
    # 负向：code 非 200 → 拒绝
    assert _is_dict_list_json(_Resp({"code": 500, "records": [1], "total": 1})) is False
    # 负向：records 不是 list → 拒绝
    assert _is_dict_list_json(_Resp({"code": 200, "records": "not-a-list", "total": 1})) is False
    # 负向：非 JSON → 拒绝
    assert _is_dict_list_json(_Resp(None, text="<html></html>")) is False
    # 负向：非对象 JSON（字符串）→ 拒绝
    assert _is_dict_list_json(_Resp("plain-string")) is False


def test_is_upload_success_json_cases():
    # 正向：fileName 非空 + url 非空
    assert _is_upload_success_json(_Resp({"fileName": "a.jsp", "url": "/upload/a.jsp"})) is True
    # 正向：fileName 非空 + code==200
    assert _is_upload_success_json(_Resp({"fileName": "a.jsp", "code": 200})) is True
    # 负向：fileName 为空 → 拒绝
    assert _is_upload_success_json(_Resp({"fileName": "  ", "url": "/x"})) is False
    # 负向：无 fileName → 拒绝
    assert _is_upload_success_json(_Resp({"url": "/x", "code": 200})) is False
    # 负向：非 JSON → 拒绝
    assert _is_upload_success_json(_Resp(None, text="<html>upload</html>")) is False


def test_has_sql_result_echo_cases():
    # user() 回显：user@host
    assert _has_sql_result_echo(_Resp({"result": "root@localhost"})) is True
    # @@version 回显：x.y.z
    assert _has_sql_result_echo(_Resp({"result": "5.7.34"})) is True
    # database() 回显：短裸标识符（合法库名）
    assert _has_sql_result_echo(_Resp({"result": "ruoyi_db"})) is True
    # list 结果（多条记录）同样按文本匹配（host 段需以字母开头，符合 helper 正则设计）
    assert _has_sql_result_echo(_Resp({"result": ["root@localhost"]})) is True
    # 没有 result 键 → 无证据
    assert _has_sql_result_echo(_Resp({"code": 200, "message": "ok"})) is False
    # result 是普通业务文案（无 SQL 形态）→ 无证据
    assert _has_sql_result_echo(_Resp({"result": "操作成功"})) is False
    # 非 JSON → 无证据
    assert _has_sql_result_echo(_Resp(None, text="<html></html>")) is False
