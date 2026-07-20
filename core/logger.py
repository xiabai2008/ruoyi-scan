# 项目级日志工具：统一 logger 配置，避免 except: pass 静默吞错
#
# 用法：
#   from core.logger import get_logger
#   logger = get_logger(__name__)
#   except Exception as e:
#       logger.debug("操作失败", exc_info=True)
#
# 默认行为：
#   - 无配置时使用 WARNING 级别（生产安静，仅警告以上输出）
#   - 通过 setup_logging(debug=True) 或环境变量 RUOYI_SCAN_DEBUG=1 切换 DEBUG 级别
#   - 日志格式：[时间] [级别] [模块] 消息
import logging
import os
import sys

_DEFAULT_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
_DEFAULT_DATEFMT = "%H:%M:%S"

_configured = False


def setup_logging(debug: bool = False, level: int | None = None) -> None:
    """初始化全局日志配置（幂等，重复调用安全）

    Args:
        debug: True 则使用 DEBUG 级别，False 使用 WARNING
        level: 直接指定级别（优先于 debug）
    """
    global _configured
    if level is None:
        env_level = os.environ.get("RUOYI_SCAN_DEBUG", "")
        level = logging.DEBUG if (debug or env_level in ("1", "true", "yes")) else logging.WARNING
    if not _configured:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT))
        root = logging.getLogger()
        # 避免重复添加 handler
        if not any(isinstance(h, logging.StreamHandler) and h.formatter and "levelname" in (h.formatter._fmt or "") for h in root.handlers):
            root.addHandler(handler)
        root.setLevel(level)
        _configured = True
    else:
        logging.getLogger().setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """获取模块 logger（自动确保全局配置已初始化）

    Args:
        name: 通常传 __name__

    Returns:
        logging.Logger 实例
    """
    if not _configured:
        setup_logging()
    return logging.getLogger(name)
