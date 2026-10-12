# 覆盖率补盲：公共构件的小分支
#  - common/logger.py：首次挂载 handler（无同名 StreamHandler 时）分支
#  - common/models.py：ComponentVersionResult.to_dict() 序列化分支
import logging

import common.logger as logger_mod
from common.models import ComponentVersionResult


def test_setup_logging_adds_handler_when_missing():
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_configured = logger_mod._configured
    try:
        root.handlers.clear()
        logger_mod._configured = False
        logger_mod.setup_logging(level=logging.INFO)
        assert any(isinstance(h, logging.StreamHandler) for h in root.handlers), "首次调用应挂载 stderr handler"
    finally:
        root.handlers[:] = saved_handlers
        logger_mod._configured = saved_configured


def test_component_version_result_to_dict():
    result = ComponentVersionResult()
    result.component = "fastjson"
    result.detected_version = "1.2.3"
    result.status = "confirmed"
    result.cve = "CVE-2022-0001"
    result.fix_version = "1.2.4"
    result.evidence = "版本区间命中"
    result.url = "http://x/"

    data = result.to_dict()
    assert data["component"] == "fastjson"
    assert data["detected_version"] == "1.2.3"
    assert data["cve"] == "CVE-2022-0001"
    assert data["fix_version"] == "1.2.4"
    assert data["evidence"] == "版本区间命中"
    assert data["url"] == "http://x/"
