# 指纹识别接口 + 通用特征判定（数据驱动，支持多 CMS 自动识别与路由）
import hashlib
import re

from lib.fingerprint_features import get_feature, list_cms
from core.models import FingerprintResult


class Fingerprint:
    """指纹识别抽象接口（新增 CMS 实现此接口即可，引擎零改动）"""

    def detect(self, target, session) -> FingerprintResult:
        """识别目标 CMS，返回 FingerprintResult（cms 空串表示未识别）"""
        raise NotImplementedError


class FeatureBasedFingerprint(Fingerprint):
    """基于特征库的通用多特征交叉判定

    适用于任一在 lib.fingerprint_features.CMS_FEATURES 中注册的 CMS。
    强特征 +weight_strong/个，弱特征 +weight_weak/个，置信度上限 1.0。
    至少命中一个强特征 → 高置信；仅弱特征 → 低置信（供人工复核）；无特征 → 未识别。
    """

    def __init__(self, cms):
        self.cms = cms
        self.feature = get_feature(cms)

    def detect(self, target, session) -> FingerprintResult:
        if not self.feature:
            return FingerprintResult(cms='', version='', confidence=0.0, matched=[])

        f = self.feature
        matched = []
        strong_hits = 0
        weak_hits = 0
        w_strong = f.get('weight_strong', 0.5)
        w_weak = f.get('weight_weak', 0.2)

        # 1. 主页特征：GET 根路径，检查标题与响应体关键字
        try:
            resp = session.get(target)
            text = resp.text or ''
            title_m = re.findall(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
            title = title_m[0] if title_m else ''
            for kw in f.get('login_keywords', []):
                if kw in text or kw in title:
                    strong_hits += 1
                    matched.append('login:%s' % kw)
                    break
            for kw in f.get('weak_keywords', []):
                if kw in text or kw in title:
                    weak_hits += 1
                    matched.append('keyword:%s' % kw)
                    break
        except Exception:
            pass

        # 2. 强特征路径探测
        for item in f.get('strong_paths', []):
            path = item['path']
            expect = item.get('expect', 'any')
            url = target + path.lstrip('/')
            try:
                r = session.get(url)
                if r.status_code != 200:
                    continue
                ct = (r.headers.get('Content-Type') or '').lower()
                body = r.text or ''
                if expect == 'json':
                    ok = ('json' in ct) and ('code' in body or 'msg' in body)
                elif expect == 'image':
                    ok = 'image' in ct
                else:
                    ok = True
                if ok:
                    strong_hits += 1
                    matched.append('path:%s(%s,%d)' % (path, expect, r.status_code))
            except Exception:
                continue

        # 3. favicon hash 比对（标准库 hashlib.md5(content).hexdigest()）
        try:
            fav = session.get(target + 'favicon.ico')
            if fav.status_code == 200 and len(fav.content) > 0:
                h = hashlib.md5(fav.content).hexdigest()
                if h in f.get('favicon_hashes', set()):
                    strong_hits += 1
                    matched.append('favicon:%s' % h)
                else:
                    weak_hits += 1
                    matched.append('favicon:unknown:%s' % h[:8])
        except Exception:
            pass

        confidence = min(1.0, strong_hits * w_strong + weak_hits * w_weak)
        if strong_hits > 0 or weak_hits > 0:
            return FingerprintResult(
                cms=self.cms, version='', confidence=confidence, matched=matched)
        return FingerprintResult(cms='', version='', confidence=0.0, matched=matched)


class RuoyiFingerprint(FeatureBasedFingerprint):
    """若依指纹识别（薄封装，向后兼容 main.py / 旧测试）"""

    def __init__(self):
        super().__init__('ruoyi')


def detect_cms(target, session) -> FingerprintResult:
    """多 CMS 指纹识别：遍历所有注册 CMS，返回置信度最高的结果

    用于阶段二自动路由：未知目标自动识别为对应 CMS 并加载插件包。
    多个 CMS 均弱命中时，选弱特征置信度最高者；均强命中时，选先注册者。
    """
    best = FingerprintResult(cms='', version='', confidence=0.0, matched=[])
    for cms in list_cms():
        res = FeatureBasedFingerprint(cms).detect(target, session)
        if res.cms and res.confidence > best.confidence:
            best = res
    return best
