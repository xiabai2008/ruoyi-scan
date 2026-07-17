# Spring Boot 插件包：plugin_list 声明本包插件类（按危险度排序）
from plugins.spring.spring4shell import Spring4shellPlugin
from plugins.spring.gateway_rce import SpringGatewayRcePlugin
from plugins.spring.actuator_env_rce import SpringActuatorEnvRcePlugin
from plugins.spring.jolokia_rce import SpringJolokiaRcePlugin
from plugins.spring.cloud_function_rce import SpringCloudFunctionRcePlugin
from plugins.spring.h2_console_rce import SpringH2ConsoleRcePlugin
from plugins.spring.actuator_unauth import SpringActuatorUnauthPlugin
from plugins.spring.heapdump_leak import SpringHeapdumpLeakPlugin
from plugins.spring.mappings_leak import SpringMappingsLeakPlugin

plugin_list = [
    # vuln：RCE 类（high）
    Spring4shellPlugin,              # CVE-2022-22965 Spring4Shell
    SpringGatewayRcePlugin,          # CVE-2022-22947 Spring Cloud Gateway RCE
    SpringActuatorEnvRcePlugin,      # Actuator env 配置覆盖 RCE
    SpringJolokiaRcePlugin,          # Jolokia reloadByURL JNDI RCE
    SpringCloudFunctionRcePlugin,    # CVE-2022-22963 Cloud Function SpEL RCE
    SpringH2ConsoleRcePlugin,        # H2 Console 未授权 JNDI RCE
    # vuln：信息泄露类（medium）
    SpringActuatorUnauthPlugin,       # Actuator 未授权访问
    SpringHeapdumpLeakPlugin,         # heapdump 敏感信息泄露
    SpringMappingsLeakPlugin,         # /mappings 路由映射泄露
]
