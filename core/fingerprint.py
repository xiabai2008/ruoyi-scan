# 指纹识别接口 + RuoyiFingerprint（阶段一 stub，阶段二实装多特征交叉判定）
from core.models import FingerprintResult


class Fingerprint:
    """指纹识别抽象接口"""

    def detect(self, target, session) -> FingerprintResult:
        """识别目标 CMS，返回 FingerprintResult"""
        raise NotImplementedError


class RuoyiFingerprint(Fingerprint):
    """若依指纹识别

    阶段一 stub：直接判定为 ruoyi，置信度 1.0（保证主流程走通，引擎零改动即可演进）。
    阶段二将实装多特征交叉判定：favicon hash + 特征路径 /prod-api/ +
    验证码接口 + 登录页特征 + 响应头/标题。
    """

    # 若依特征路径（阶段二实装时使用）
    FEATURE_PATHS = ['/prod-api/', '/druid/login.html', '/swagger-ui.html']
    # 若依响应特征关键字
    FEATURE_KEYWORDS = ['若依', 'RuoYi', 'ruoyi']

    def detect(self, target, session) -> FingerprintResult:
        # 阶段一：硬编码返回 ruoyi
        return FingerprintResult(
            cms='ruoyi',
            version='',
            confidence=1.0,
            matched=['stub:阶段一硬编码']
        )
