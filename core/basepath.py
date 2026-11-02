# API 前缀（base path）探测：前后端分离版只反代 /prod-api/ 时的探测基准修正
#
# 背景（2026-10-29 R7 靶场实测）：
#   RuoYi-Vue / RuoYi-Cloud 等分离版的标准 nginx 形态是**只反代 /prod-api/**：
#       location /          { root .../dist; try_files $uri $uri/ /index.html; }
#       location /prod-api/ { proxy_pass http://127.0.0.1:8080/; }
#   此时根路径下的 /druid/index.html、/swagger-ui.html、/actuator/env、
#   /system/user/list 全部命中 SPA 的 index.html（HTTP 200 HTML）。
#   所有「按根路径拼 URL」的插件都拿不到后端真实响应：
#     - 该命中的（Druid 控制台暴露、默认口令、定时任务…）全部落空 → 系统性漏报
#     - 目录扫描把同一个 index.html 当成海量「存在的路径」→ 噪声
#   实测 R7（严格只反代 /prod-api/）无会话扫描：除宿主级 Redis 外全部「不存在/无法判定」。
#
# 本模块探测若依后端**匿名可达**的特征接口来判断前缀，供编排器把插件探测基准
# 从 http://host/ 提升为 http://host/prod-api/。根路径本身已直连后端（单机版）
# 时返回空串，行为不变。
import json
import re
from typing import Any, List
from urllib.parse import urlsplit

from common.logger import get_logger

logger = get_logger(__name__)

# 候选前缀：RuoYi-Vue 官方脚手架为 /prod-api/，其余为常见改法
CANDIDATES = ("/prod-api", "/dev-api", "/api", "/jeecg-boot", "/jeecg")

# 验证码接口（用来确认「这个前缀确实通到若依后端」）
#   RuoYi-Vue（3.8.x/3.9.x）: /captchaImage  -> {"code":200,"captchaEnabled":...}
#   RuoYi-Cloud（3.6.x）    : /code           -> 网关 RouterFunction 返回同样结构
#   RuoYi-Vue-Plus（5.x）   : /auth/code      -> {"code":200,"data":{"captchaEnabled":...}}
# 实测（2026-10-29 R8 RuoYi-Cloud v3.6.8）：只探测 /captchaImage 时，
# /prod-api/captchaImage 在网关上是 404（Cloud 没有该端点），前缀探测失败 →
# 插件全部退回根路径 → 命中的只有 SPA 的 index.html → 整站系统性漏报（含
# /prod-api/actuator/env、/prod-api/v3/api-docs 这类真实暴露项）。
# 实测（2026-10-29 R9 RuoYi-Vue-Plus v5.6.2）：同理，Plus 的验证码端点是
# /auth/code，缺这一条时 base-path 探测失败 → R9 首扫只出 1 条 CONFIRMED，
# 而 /prod-api/v3/api-docs 实际返回 312KB 的 OpenAPI 文档。
#
# 2026-11-02 补第 4 条（v1.5.6 WP1）：RuoYi 4.x **单机版/Thymeleaf 版**的验证码是
# `/captcha/captchaImage`，返回的是 **image/jpeg 图片而非 JSON**。
# 实测 D1（4.6.2 二开，context-path=/portal）：
#   GET /portal/captcha/captchaImage?type=char -> 200 image/jpeg 3092 字节
#   GET /portal/captchaImage                   -> 302（路径根本不存在）
# 缺这一条时，自定义 context-path 的 4.x 站点一个判据都对不上 → 前缀识别不出来。
# 注意必须带 `type=char`：实测 R1 无参返回 **200 + 0 字节**（BufferedImage 为 null、
# 异常被吞），只有带 type 才是 3102 字节真实图片（详见 topics/quality.md 铁律 11）。
CAPTCHA_PATHS = ("/captchaImage", "/code", "/auth/code", "/captcha/captchaImage?type=char")

# 图片型验证码判据的最小字节数：真实 JPEG 验证码 2.8–3.2KB（R1/D1 实测）。
# 阈值设在 512 是为了容忍不同尺寸/质量的验证码，同时排除 0 字节（缺 type 参数的
# 经典失败形态）和几十字节的错误页。只判 Content-Type 不够——很多 WAF/兜底页
# 也会返回 image/* 或错误地声明成图片。
_MIN_CAPTCHA_IMAGE_BYTES = 512

# JeecgBoot 的真实验证码接口：GET {base}/sys/randomImage/{key}
# 返回 {"success":true,"result":{"img":"data:image/png;base64,..."}}
# 固定 key 便于复现；真实 Jeecg 接受任意 key。
JEECG_CAPTCHA_PATH = "/sys/randomImage/ruoyi_scan_probe"


def _looks_like_ruoyi_api(resp: Any) -> bool:
    """判断响应是否是若依验证码接口的 JSON（证明「这个前缀通到后端」）

    RuoYi-Vue: GET {base}/captchaImage ->
        {"msg":"操作成功","code":200,"captchaEnabled":true,"uuid":"...","img":"/9j/..."}
    验证码关闭时只有 {"msg":"操作成功","code":200,"captchaEnabled":false}，
    因此不能要求 img/uuid，认 captchaEnabled 即可；同时兼容仍带 img/uuid 的版本。
    """
    try:
        if getattr(resp, "status_code", 0) != 200:
            return False
        ctype = (resp.headers.get("Content-Type") or "").lower()
        text = resp.text or ""
        if "json" not in ctype and not text.lstrip().startswith("{"):
            return False
        data = json.loads(text)
        if not isinstance(data, dict):
            return False
        if "captchaEnabled" in data or ("code" in data and ("img" in data or "uuid" in data)):
            return True
        # RuoYi-Vue-Plus 5.x 把业务字段包在 data 里：
        #   {"code":200,"msg":"操作成功","data":{"captchaEnabled":false,"uuid":null,"img":null}}
        inner = data.get("data")
        if isinstance(inner, dict) and "captchaEnabled" in inner:
            return True
        return False
    except Exception:
        return False


def _looks_like_jeecg_api(resp: Any) -> bool:
    """判断响应是否是 JeecgBoot 的真实验证码接口。

    真实响应（JeecgBoot 3.6.3 实测 2026-10-31）：
        GET /jeecg-boot/sys/randomImage/1234
        {"success":true,"message":"","code":0,
         "result":"data:image/jpg;base64,/9j/4AAQ..."}

    注意两点，都跟"想当然"的实现不同：
      1. `result` 是**字符串**（data URI），不是 {"img": "..."} 字典；
      2. `code` 是 0（Jeecg 的成功码），不是 200。

    因此两种形态都要认：result 为 dict 时取 img，为 str 时直接判前缀。
    只认 success=True 不够，必须拿到真实的图片数据，否则任意 success 响应都会命中。
    """
    try:
        if getattr(resp, "status_code", 0) != 200:
            return False
        ctype = (resp.headers.get("Content-Type") or "").lower()
        text = resp.text or ""
        if "json" not in ctype and not text.lstrip().startswith("{"):
            return False
        data = json.loads(text)
        if not isinstance(data, dict) or data.get("success") is not True:
            return False
        result = data.get("result")
        if isinstance(result, str):
            return result.startswith("data:image")
        if isinstance(result, dict):
            img = result.get("img")
            return isinstance(img, str) and bool(img) and img.startswith("data:image")
        return False
    except Exception:
        return False


def _looks_like_image_captcha(resp: Any) -> bool:
    """判断响应是否是真实的图片验证码（RuoYi 4.x 单机版形态）。

    真实响应（2026-11-02 R1 4.5.1 / D1 4.6.2 实测）：
        GET /captcha/captchaImage?type=char
        200  image/jpeg   3102 字节（R1）/ 3092 字节（D1）

    为什么要同时校验字节数：
      - **0 字节**是这个端点最典型的失败形态——缺 `type` 参数时 BufferedImage
        为 null、异常被框架吞掉，仍返回 200 + image/jpeg，但正文是空的。
        只看 Content-Type 会把这种「探测本身失败」当成「接口存在」。
      - 太小的响应（几十字节）多半是 WAF/兜底页错误地声明成图片。
    """
    try:
        if getattr(resp, "status_code", 0) != 200:
            return False
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if not ctype.startswith("image/"):
            return False
        content = getattr(resp, "content", None)
        if content is None:
            # 兼容没有 .content 的轻量响应替身：按 text 长度粗略估计
            return len(resp.text or "") >= _MIN_CAPTCHA_IMAGE_BYTES
        return len(content) >= _MIN_CAPTCHA_IMAGE_BYTES
    except Exception:
        return False


def _probe_api_base(base: str, session: Any) -> bool:
    """在给定前缀下尝试对应验证码接口，任一命中即说明该前缀通到后端。

    Jeecg 前缀只用 Jeecg 专用探针：/captchaImage 是 RuoYi 的路径，
    在 Jeecg 里并不存在，不能拿它当判据。
    """
    is_jeecg = base.endswith("/jeecg-boot") or base.endswith("/jeecg")
    if not is_jeecg:
        for path in CAPTCHA_PATHS:
            try:
                resp = session.get(base + path)
                # 两种形态都认：分离版/Cloud/Plus 是 JSON，4.x 单机版是图片
                if _looks_like_ruoyi_api(resp) or _looks_like_image_captcha(resp):
                    return True
            except Exception:
                logger.debug("验证码接口探测失败: %s%s", base, path, exc_info=True)
        return False
    try:
        return _looks_like_jeecg_api(session.get(base + JEECG_CAPTCHA_PATH))
    except Exception:
        logger.debug("Jeecg 验证码接口探测失败: %s%s", base, JEECG_CAPTCHA_PATH, exc_info=True)
        return False


# JeecgBoot 的 context-path（插件内部路径已自带）
_JEECG_BASES = ("/jeecg-boot", "/jeecg")


# 插件路径里可能**自带**的 API 前缀。这类插件不能再被追加同名前缀，
# 否则会拼成 /prod-api/prod-api/... 或 /portal/prod-api/... 的双前缀。
# 与 _JEECG_BASES 的区别：Jeecg 是「整包插件都自带」，这里是「个别插件自带」，
# 由插件在 verify 里写死（如 plus_job_unauth 探 /prod-api/monitor/job/list）。
_SELF_PREFIXED = ("/prod-api", "/dev-api", "/api")


def plugin_target_for(target: str, api_base: str, plugin_prefixes: Any = None) -> str:
    """把探测到的 API 前缀提升为插件探测基准（引擎用）。

    JeecgBoot 例外：其插件路径内部已经写死 context-path（/jeecg-boot/...），
    若再把 api_base 追加到 target 会拼成 /jeecg-boot/jeecg-boot/... 的双前缀，
    真实 Jeecg 目标会整包漏报（2026-11-02 R10 实测，5 个插件 URL 翻倍）。
    因此 Jeecg 上下文保持站点根，由插件自己拼 context-path。

    Args:
        target: 站点根
        api_base: 探测到的 API 前缀
        plugin_prefixes: 该插件路径里自带的前缀（可选）。若与 api_base 相同，
            说明插件自己会拼这一段，不能再追加。
    """
    if not api_base:
        return target
    if api_base in _JEECG_BASES:
        return target
    if plugin_prefixes and api_base in plugin_prefixes:
        return target
    return target.rstrip("/") + api_base + "/"


# ── 被动前缀提取（v1.5.6 WP1）─────────────────────────────────────────
# 候选表写死时，自定义 context-path（如 D1 二开的 /portal）永远落不进候选，
# 路径类插件整类探错基准。这里从**已经在拿的响应**里读前缀线索，不额外发请求。
#
# 线索来源（按可靠性排序）：
#   1. Set-Cookie 的 Path=      —— 后端自己声明的 cookie 作用域，最可靠
#   2. 302 的 Location          —— 重定向目标常带真实前缀（/portal/login）
#   3. HTML/JS 里的 baseURL     —— 前端构建时写死的 API 前缀
#   4. api-docs 的 servers[].url —— OpenAPI 文档自述的服务地址
#
# 全部都只是**候选扩充**：抽出来的前缀仍要过 _probe_api_base（真图片/真 JSON）
# 才被采纳，不放松任何判定。
_PATH_LIKE_RE = re.compile(r"^/[A-Za-z0-9_.\-]{1,32}$")

# JS/HTML 里常见的 API 前缀赋值形态：
#   baseURL: '/portal'   baseURL="/portal/api"   VUE_APP_BASE_API:'/portal'
#   注意只认同级路径，不认 http(s) 绝对地址（那是跨域 CDN/网关，不是 context-path）
_JS_BASE_RE = re.compile(
    r"""(?:baseURL|baseUrl|BASE_API|VUE_APP_BASE_API|VITE_APP_BASE_API)\s*[:=]\s*['"](/[A-Za-z0-9_.\-]{1,32})['"]"""
)


def _accept_candidate(path: Any) -> str:
    """把抽取到的路径收敛成可探测的前缀；不合格返回空串。

    过滤器必须严——错误候选会让每次扫描多打一轮请求，还可能把
    业务模块路径（/system、/monitor）误当前缀探出假结论。
    """
    if not isinstance(path, str):
        return ""
    cand = path.strip().rstrip("/")
    if not cand or cand == "/" or not cand.startswith("/"):
        return ""
    if not _PATH_LIKE_RE.match(cand):
        return ""
    # 已知的业务模块路径不是 context-path：探它们会把「业务接口可达」
    # 误当成「前缀存在」，进而把整站插件基准推到错误位置
    if cand.lower() in _NOT_A_CONTEXT_PATH:
        return ""
    return cand


# 这些是若依/Spring 的业务端点段，不可能是 context-path
_NOT_A_CONTEXT_PATH = frozenset(
    {
        "/login",
        "/logout",
        "/index",
        "/home",
        "/system",
        "/monitor",
        "/tool",
        "/common",
        "/error",
        "/actuator",
        "/swagger-ui",
        "/v2",
        "/v3",
        "/druid",
        "/nacos",
        "/favicon.ico",
    }
)


def extract_base_hints(target: str, session: Any, html: str = "") -> List[str]:
    """从站点根/登录页的响应里被动提取可能的 API 前缀（不发新请求时用 html 参数）。

    Args:
        target: 站点根 URL
        session: 会话；html 为空时会用它取一次根路径
        html: 已有的页面正文（编排器可能已经拿过登录页，避免重复请求）

    Returns:
        去重后的候选前缀列表（如 ['/portal']），可能为空
    """
    hints: List[str] = []

    def _add(value: Any) -> None:
        cand = _accept_candidate(value)
        if cand and cand not in hints:
            hints.append(cand)

    body = html or ""
    resp = None
    if not body:
        try:
            # allow_redirects=False 是**必须**的：跟随重定向会拿到最终页，
            # 把真正带信息的 302 与 Set-Cookie: Path=/portal 全部丢掉。
            # 实测 D1：GET / -> 302 Location: .../portal/ -> 再 302 到 /portal/auth/signin
            # 并下发 Path=/portal 的 JSESSIONID；跟随到底只剩登录页 HTML，线索全无。
            resp = session.get(target.rstrip("/") + "/", allow_redirects=False)
        except TypeError:
            # 轻量响应替身可能不接受该参数：退化为普通请求（被动提取会少几条线索，
            # 但不影响主流程——线索只是候选扩充，最终仍由验证码判据决定）
            try:
                resp = session.get(target.rstrip("/") + "/")
            except Exception:
                logger.debug("根路径请求失败，跳被动前缀提取", exc_info=True)
                resp = None
        except Exception:
            logger.debug("根路径请求失败，跳被动前缀提取", exc_info=True)
            resp = None
        if resp is not None:
            body = getattr(resp, "text", "") or ""

    # 1) Set-Cookie 的 Path=
    #    注意 headers.get() 只取首个值；真实站点常有多个 Set-Cookie，必须扫完整头串
    if resp is not None:
        try:
            headers_text = str(resp.headers)
            for m in re.finditer(r"[Pp]ath=(/[A-Za-z0-9_.\-/]{1,40})", headers_text):
                _add(m.group(1))
        except Exception:
            logger.debug("Set-Cookie 前缀提取失败", exc_info=True)
        # 2) 3xx 的 Location。两种形态都要认：
        #    - 相对：Location: /portal/
        #    - 绝对：Location: http://host/portal/（nginx return 302 http://$host/portal/ 就是这种）
        #    实测 D1：GET / -> 302 http://127.0.0.1:19321/portal/ —— 只认相对形态会漏掉。
        try:
            location = str(resp.headers.get("Location", "") or "")
            if location:
                loc_path = urlsplit(location).path if "://" in location else location
                if loc_path.startswith("/"):
                    _add("/" + loc_path.strip("/").split("/")[0])
        except Exception:
            logger.debug("Location 前缀提取失败", exc_info=True)

    # 3) HTML/JS 里的 baseURL 赋值
    if body:
        for m in _JS_BASE_RE.finditer(body):
            _add(m.group(1))

    return hints


def detect_api_base(target: str, session: Any, html: str = "", extra_hints: Any = None) -> str:
    """探测需要在 target 后追加的 API 前缀

    Args:
        target: 目标 URL
        session: HTTP 会话
        html: 可选，已拿到的页面正文（供被动提取线索，避免重复请求）
        extra_hints: 可选，额外候选前缀（如命令行 --base-path 指定的），优先级最高

    Returns:
        ''（根路径已直连后端，或未识别出前缀）或 '/prod-api' 这类前缀（不带尾斜杠）
    """
    base = target.rstrip("/")
    if not base:
        return ""
    # 0) 显式指定优先：运维知道真实前缀时不该再赌自动探测
    for hint in extra_hints or ():
        cand = _accept_candidate(hint)
        if cand and _probe_api_base(base + cand, session):
            return cand
    # 1) 根路径就能拿到后端验证码 → 不需要前缀（单机版 / 根路径反代）
    if _probe_api_base(base, session):
        return ""
    # 2) 被动提取的前缀优先于写死候选表：它们是这个站点自己声明的，命中率高得多
    for cand in extract_base_hints(target, session, html=html):
        if cand not in CANDIDATES and _probe_api_base(base + cand, session):
            return str(cand)
    # 3) 逐候选前缀探测（兜底）
    for cand in CANDIDATES:
        if _probe_api_base(base + cand, session):
            return cand
    return ""
