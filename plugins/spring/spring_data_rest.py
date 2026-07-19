# Spring Data REST 信息泄露
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, SEVERITY_LOW
from lib.http import join_url


class SpringDataRestPlugin(PluginBase):
    name = 'Spring Data REST 信息泄露'
    cve = 'N/A'
    severity = SEVERITY_LOW
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
    compliance = '等保2.0:8.1.4;OWASP:A01:2021'
    category = 'vuln'
    description = 'Spring Data REST 默认暴露所有 Repository 端点，未设置访问控制时可能泄露数据库实体结构和数据'
    fix = '为 Repository 接口添加 @RepositoryRestResource(exported=false) 或设置方法级安全'
    fix_detail = (
        '【代码修复】为 Repository 接口关闭自动导出：\n'
        '  @RepositoryRestResource(exported = false)\n'
        '  public interface UserRepository extends JpaRepository<User, Long> {}\n'
        '【方法级安全】为敏感方法添加 @PreAuthorize：\n'
        '  @PreAuthorize("hasRole(\'ADMIN\')")\n'
        '  @Override\n'
        '  void delete(User user);\n'
        '【配置加固】application.yml 收敛 Data REST 暴露：\n'
        '  spring.data.rest.basePath: /internal/api  # 修改默认路径\n'
        '  spring.data.rest.defaultPageSize: 20  # 限制分页\n'
        '【SecurityConfig】为 /api/** 配置认证与角色：\n'
        '  .antMatchers("/api/**").authenticated()\n'
        '【WAF 规则】拦截 /api 与 /api/** 的匿名访问\n'
        '【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制'
    )
    reproduce = (
        '# 1. 探测 Spring Data REST 根端点：\n'
        'curl -i "http://target/api"\n'
        '  # 返回 200 + JSON 含 _links 字段即 Data REST 暴露\n'
        '\n'
        '# 2. 列出全部 Repository 实体端点：\n'
        'curl "http://target/api" | python -m json.tool\n'
        '  # _links 中含 users / orders 等实体名\n'
        '\n'
        '# 3. 访问具体实体数据（无认证即可读取）：\n'
        'curl "http://target/api/users" | python -m json.tool\n'
        'curl "http://target/api/users/1" | python -m json.tool\n'
        '\n'
        '# 预期响应：200 + JSON 含 _links（profile/self）即漏洞存在'
    )

    def verify(self, target, session) -> ScanResult:
        url = join_url(target, '/api')
        try:
            resp = session.get(url)
            text = (resp.text or '')[:500]
            if resp.status_code == 200 and '_links' in text and ('profile' in text or 'self' in text):
                return ScanResult(kind=self.category, name=self.name, severity=self.severity,
                                  status=STATUS_CONFIRMED, url=url, evidence='Spring Data REST HAL 端点可访问', fix=self.fix)
            return ScanResult(kind=self.category, name=self.name, severity=self.severity,
                              status=STATUS_SAFE, url=url, evidence=f'未发现 Data REST 端点')
        except Exception as e:
            return ScanResult(kind='error', name=self.name, status=STATUS_UNKNOWN, evidence=f'异常: {e}')
