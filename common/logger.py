# common/logger.py — 项目级日志工具（共享基础层，供 core/lib/api/cli/plugins 共同依赖）
#
# 用法：
#   from common.logger import get_logger
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

# 第三方库降噪名单：目标不可达时 urllib3 对每个失败请求输出 2 行 "Retrying" 警告，
# 数十个插件叠加会刷出数百行并淹没工具自身的进度输出（实测不可达目标时完全看不到
# 工具结论）。DEBUG 档位不降噪——排查连通性问题时需要底层重试详情。
_NOISY_LOGGERS = ("urllib3", "requests", "charset_normalizer")

_configured = False


def setup_logging(debug: bool = False, level: int | None = None) -> None:
    """初始化全局日志配置（幂等，重复调用安全）

    Args:
        debug: True 则使用 DEBUG 级别，False 使用 WARNING
        level: 直接指定级别（优先于 debug）
    """
    global _configured
    if level is None:
        # 容器/CI 部署可用环境变量 RUOYI_SCAN_DEBUG=1 全局强制 DEBUG，与 --debug 等效
        env_level = os.environ.get("RUOYI_SCAN_DEBUG", "")
        level = logging.DEBUG if (debug or env_level in ("1", "true", "yes")) else logging.WARNING
    if not _configured:
        # 日志走 stderr：避免污染 stdout（banner/报告等用户主输出）
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT))
        root = logging.getLogger()
        # 避免重复添加 handler
        if not any(
            isinstance(h, logging.StreamHandler) and h.formatter and "levelname" in (h.formatter._fmt or "")
            for h in root.handlers
        ):
            root.addHandler(handler)
        _configured = True
    # 重复设置级别是幂等的，故不区分首次/后续调用
    logging.getLogger().setLevel(level)
    # NOTSET 表示继承父 logger（root），用于 DEBUG 档位恢复第三方库原始输出
    third_party_level = logging.NOTSET if level <= logging.DEBUG else logging.ERROR
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(third_party_level)


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
