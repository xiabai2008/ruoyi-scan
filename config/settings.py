# 全局配置：线程 / 限速 / 代理 / 超时 / 字典路径
import os

# 项目根目录（config/ 的上一级）
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dict_path(name):
    """字典路径：优先 data/，回退根目录（兼容 legacy Ruoyi-Scan.py 共用）

    字典内容原样保留（ruoyi.txt 保留 %20 前缀；password.txt 保留空行口令，勿 strip）。
    """
    data_path = os.path.join(BASE_DIR, 'data', name)
    root_path = os.path.join(BASE_DIR, name)
    return data_path if os.path.exists(data_path) else root_path


# 默认 User-Agent（沿用原脚本）
DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0'

# 请求超时（秒）
TIMEOUT = 10

# 并发线程数（Step 5 启用）
THREADS = 5

# 限速（每秒请求数，0 表示不限速）
RATE = 0

# 代理（如 http://127.0.0.1:8080，None 表示不使用）
PROXY = None

# 字典路径
RUOYI_DICT = _dict_path('ruoyi.txt')
PASSWORD_DICT = _dict_path('password.txt')

# 报告输出目录
REPORT_DIR = os.path.join(BASE_DIR, 'reports')

# Druid 爆破用户名清单（沿用原 web_login，6 个）
DRUID_USERS = ['ruoyi', 'druid', 'admin', 'admin123', 'auth', '123456']

# 定时任务任意文件读取：固定 JSESSIONID（沿用原脚本）
JOB_JSESSIONID = '6db3d8ea-2d5c-490e-9863-6ef864b99828'

# 工具版本与作者（同步 banner）
VERSION = '1.0.0'
AUTHOR = 'XiaBai'
GITHUB = 'https://www.github.com/xueshanchengke/Ruoyi-Scan'
CONTACT = '暂无QAQ'
