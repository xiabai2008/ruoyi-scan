# 目录扫描：读 ruoyi.txt 字典，逐条 GET 并打印 响应码/标题/长度/最终 URL
import re

from plugins.base import PluginBase
from core.models import ScanResult, STATUS_UNKNOWN
from lib.colors import GREEN, RED, YELLOW, RESET
from config import settings


class DirectoryScanPlugin(PluginBase):
    name = '目录扫描'
    cve = ''
    severity = 'low'
    category = 'recon'
    description = '基于 ruoyi.txt 字典的端点探测，输出状态码/标题/长度/URL（沿用原 path_scan 格式）'
    fix = '关闭未授权端点，敏感路径强制鉴权，下线调试与监控面板'

    def verify(self, target, session):
        # 原 path_scan 输出格式严格保留：
        #   [*]\033[33m响应:[{code}\033[33m] -> 标题:[{title}\033[33m] -> 长度:[\033[32m{len}\033[33m] -> {respnse.request.url}\033[0m
        # 状态码 '20' in code 为绿，否则红；标题为空显示红色 NULL，否则绿色
        hits = []
        try:
            with open(settings.RUOYI_DICT, 'r', encoding='utf-8') as f:
                path_list = f.read().splitlines()
        except Exception as e:
            print(f'{RED}[/]目录字典读取失败：{e}{RESET}')
            return ScanResult(kind='dir', name=self.name, status=STATUS_UNKNOWN,
                              url=settings.RUOYI_DICT, evidence=str(e))

        for path in path_list:
            # 双斜杠归一化：if self.url[-1] == '/' and path[0] == '/': path = path[1:]
            if target.endswith('/') and path.startswith('/'):
                path = path[1:]
            url = target + path
            try:
                respnse = session.get(url)
            except Exception:
                # 网络异常：打印红色提示，保留 UNKNOWN 语义（不阻断后续条目）
                print(f'{RED}[/]请求异常：{url}{RESET}')
                continue
            text = respnse.text
            # 标题正则严格保留：<title>(\w+)</title>
            title = re.findall('<title>(\\w+)</title>', text)
            if len(title) < 1:
                title = f'{RED}NULL{RESET}'
            else:
                title = f'{GREEN}{title[0]}{RESET}'
            code = str(respnse.status_code)
            # 状态码判定严格保留：'20' in code（200/201/204 均为绿）
            if '20' in code:
                code = f'{GREEN}{code}{RESET}'
            else:
                code = f'{RED}{code}{RESET}'
            # 行格式严格保留（[*] 前缀 + 黄色字段标签）
            print(f'[*]{YELLOW}响应:[{code}{YELLOW}] -> 标题:[{title}{YELLOW}] -> 长度:[{GREEN}{len(text)}{YELLOW}] -> {respnse.request.url}{RESET}')
            # 收集 2xx / 3xx / 有标题的条目供报告
            if '20' in str(respnse.status_code) or 'NULL' not in title:
                hits.append({
                    'url': respnse.request.url,
                    'code': str(respnse.status_code),
                    'length': len(text),
                })
        return ScanResult(kind='dir', name=self.name, status=STATUS_UNKNOWN,
                          url=target, evidence=f'扫描 {len(path_list)} 条，命中 {len(hits)} 条',
                          extra={'hits': hits})
