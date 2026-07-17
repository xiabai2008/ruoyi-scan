# 指纹特征库（数据驱动，阶段二核心基建）
# 设计目标：新增 CMS 只需在此追加一条特征数据，引擎/路由/报告零改动即支持识别与定向检测。
#
# 特征类型说明：
#   favicon_hashes : favicon.ico 原始字节的 md5 集合（标准库 hashlib.md5(content).hexdigest()）
#   strong_paths   : 强特征路径列表，每项 {path, expect}
#                    expect='json'  -> 响应 Content-Type 含 json 且 body 含 code/msg
#                    expect='image' -> 响应 Content-Type 含 image
#                    expect='any'   -> 仅需 status_code==200
#   login_keywords : 登录页/标题强关键字（命中任一 +weight_strong）
#   weak_keywords  : 弱关键字（标题/响应体含其一 +weight_weak）
# 置信度：强特征 weight_strong/个，弱特征 weight_weak/个，上限 1.0。
#         至少命中一个强特征 → 高置信；仅弱特征 → 低置信（供人工复核）；无特征 → 未识别。

# 真实采集的 RuoYi 4.7.8 favicon md5（2026-07-17 从运行实例 127.0.0.1:8080/favicon.ico 采集，size=16958）
RUOYI_FAVICON_MD5 = 'e49fd30ea870c7a820464ca56a113e6e'

# CMS 特征库：cms 标识 -> 特征 dict
CMS_FEATURES = {
    'ruoyi': {
        'display': 'RuoYi',
        'favicon_hashes': {RUOYI_FAVICON_MD5},
        'strong_paths': [
            {'path': '/prod-api/', 'expect': 'json'},      # 若依前后端分离版 API 前缀
            {'path': '/captcha/image', 'expect': 'image'},  # 若依验证码图片接口
            {'path': '/getInfo', 'expect': 'json'},         # 若依登录后用户信息接口
        ],
        'login_keywords': ['RuoYi', '若依管理系统', '若依管理'],
        'weak_keywords': ['若依', 'ruoyi', 'RuoYi'],
        'weight_strong': 0.5,
        'weight_weak': 0.2,
    },
    # ThinkPHP（阶段二第二个 CMS 插件包）：默认入口 /index.php + 主页 ThinkPHP Framework 标题
    'thinkphp': {
        'display': 'ThinkPHP',
        'favicon_hashes': set(),  # ThinkPHP 默认无稳定 favicon，靠入口路径 + 主页关键字识别
        'strong_paths': [
            {'path': '/index.php', 'expect': 'any'},   # ThinkPHP 默认入口脚本
        ],
        'login_keywords': ['ThinkPHP Framework'],       # 默认欢迎页标题强特征
        'weak_keywords': ['ThinkPHP', 'thinkphp'],       # 响应体/调试页关键字
        'weight_strong': 0.5,
        'weight_weak': 0.2,
    },
    # Spring Boot（阶段二第三个 CMS 插件包）：Actuator 端点 JSON 响应为强特征 + 默认错误页弱特征
    'spring': {
        'display': 'Spring Boot',
        'favicon_hashes': set(),  # Spring Boot 默认绿叶 favicon 随版本变化，不设固定 hash
        'strong_paths': [
            {'path': '/actuator', 'expect': 'any'},          # Actuator 根端点 200 即强 Spring Boot 信号
        ],
        'login_keywords': [],                               # Spring Boot 无统一登录页
        'weak_keywords': ['Whitelabel Error Page', 'Spring Boot', 'spring-boot'],
        'weight_strong': 0.5,
        'weight_weak': 0.2,
    },
    # 泛微 e-cology OA（阶段四第四个 CMS 插件包）：/login/Login.jsp 登录页 + 主页泛微关键字
    'weaver': {
        'display': 'Weaver e-cology',
        'favicon_hashes': set(),
        'strong_paths': [
            {'path': '/login/Login.jsp', 'expect': 'any'},  # OA 登录页
        ],
        'login_keywords': ['泛微', 'e-cology', 'weaver'],
        'weak_keywords': ['ecology', 'weaver', 'OA'],
        'weight_strong': 0.5,
        'weight_weak': 0.2,
    },
}


def get_feature(cms):
    """返回某 CMS 的特征 dict，未注册返回 None"""
    return CMS_FEATURES.get(cms)


def list_cms():
    """返回所有已注册 CMS 标识列表"""
    return list(CMS_FEATURES.keys())
