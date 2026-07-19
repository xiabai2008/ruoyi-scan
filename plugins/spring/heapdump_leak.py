# Spring Boot Actuator heapdump 敏感信息泄露
# 漏洞原因：/actuator/heapdump 端点可匿名访问，下载 JVM 堆转储文件，内含
#   数据库口令、JWT 密钥、Session Token、API Key 等明文/编码敏感信息。
# 本插件仅做存在性验证：GET /actuator/heapdump 检测返回体含 heapdump 特征。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_heapdump_binary

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
HEAP_MARKER = 'spring-heapdump-leak-confirmed'


class SpringHeapdumpLeakPlugin(PluginBase):
    name = 'Spring Boot Actuator heapdump 敏感信息泄露'
    cve = 'N/A'
    severity = 'medium'
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
    compliance = '等保2.0:8.1.4;OWASP:A01:2021'
    category = 'vuln'
    description = '/actuator/heapdump 可匿名下载堆转储，内含口令/密钥/Token 等敏感信息'
    fix = '为 /actuator/heapdump 端点配置认证；或设置 management.endpoints.web.exposure.exclude=heapdump'
    fix_detail = (
        '【引入依赖】pom.xml 添加 Spring Security：\n'
        '  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>\n'
        '【配置加固】application.yml 禁用 heapdump 端点：\n'
        '  management.endpoints.web.exposure.include: health,info\n'
        '  management.endpoints.web.exposure.exclude: heapdump\n'
        '  management.endpoint.heapdump.enabled: false  # 直接禁用\n'
        '【SecurityConfig】为 heapdump 端点配置角色：\n'
        '  .antMatchers("/actuator/heapdump").hasRole("ADMIN")\n'
        '【端口隔离】management.server.port: 9090  # 管理端口与业务端口分离，仅内网访问\n'
        '【WAF 规则】拦截外网对 /actuator/heapdump 的访问，限制大文件下载\n'
        '【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制'
    )
    reproduce = (
        '# 1. 探测 heapdump 端点可达性：\n'
        'curl -I "http://target/actuator/heapdump"\n'
        '  # 返回 200 + Content-Type: application/octet-stream 即 heapdump 暴露\n'
        '\n'
        '# 2. 下载 JVM 堆转储文件：\n'
        'curl "http://target/actuator/heapdump" -o heapdump.bin\n'
        '  # 文件大小通常为 100MB ~ 数 GB\n'
        '\n'
        '# 3. 解压 gzip 堆转储（Spring Boot 2.x 默认 gzip 压缩）：\n'
        'mv heapdump.bin heapdump.gz && gunzip heapdump.gz\n'
        '\n'
        '# 4. 使用 Eclipse MAT / jhat / JDumpSpider 提取敏感信息：\n'
        'java -jar JDumpSpider.jar heapdump\n'
        '  # 提取 password / jwt / token / apiKey 等明文凭证\n'
        '\n'
        '# 预期响应：200 + Content-Type: application/octet-stream 即漏洞存在'
    )

    def verify(self, target, session):
        url = join_url(target, '/actuator/heapdump')
        try:
            resp = session.get(url, stream=True)
            # 仅读取前 64 KB 检测特征，避免完整下载大文件
            raw = resp.raw.read(65536)
            text = raw.decode('utf-8', errors='ignore')
        except Exception as e:
            print(no('Spring Boot Actuator heapdump 泄露（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        content_type = resp.headers.get('Content-Type', '') or ''
        is_octet = 'octet-stream' in content_type or 'application/x-gzip' in content_type

        if resp.status_code == 200 and is_octet and HEAP_MARKER in text:
            print(ok('存在 Spring Boot Actuator heapdump 敏感信息泄露'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 heapdump 特征：{HEAP_MARKER}（Content-Type={content_type}）',
                fix=self.fix,
            )
        # 真实漏洞响应：200 + octet-stream + heapdump 二进制特征（JAVA PROFILE / 敏感字符串）
        if resp.status_code == 200 and is_octet and match_heapdump_binary(text):
            print(ok('存在 Spring Boot Actuator heapdump 敏感信息泄露（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 heapdump 二进制特征（JAVA PROFILE / 敏感字符串），Content-Type={content_type}',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator heapdump 敏感信息泄露'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='heapdump 端点不可达或需认证（404/401）')
