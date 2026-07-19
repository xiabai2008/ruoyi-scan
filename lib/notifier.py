# D21：告警通知（Webhook / 邮件 / 钉钉 / 企业微信 / 飞书）
#
# 扫描完成后自动推送结果到指定渠道
#
# 使用方式：
#   # Webhook 通知（通用）
#   python main.py -u http://target/ --notify webhook=https://hooks.example.com/scan
#
#   # 钉钉机器人
#   python main.py -u http://target/ --notify dingtalk=https://oapi.dingtalk.com/robot/send?access_token=xxx
#
#   # 企业微信机器人
#   python main.py -u http://target/ --notify wechat=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx
#
#   # 飞书机器人
#   python main.py -u http://target/ --notify feishu=https://open.feishu.cn/open-apis/bot/v2/hook/xxx
#
#   # 邮件通知
#   python main.py -u http://target/ --notify email=security@example.com
#
#   # 多渠道通知
#   python main.py -u http://target/ --notify webhook=https://x --notify email=y@z.com
#
# 环境变量配置（邮件）：
#   SMTP_HOST=smtp.example.com
#   SMTP_PORT=465
#   SMTP_USER=sender@example.com
#   SMTP_PASS=password
#   SMTP_FROM=sender@example.com
import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


def parse_notify_arg(notify_args: List[str]) -> List[Dict[str, str]]:
    """解析 --notify 参数列表

    Args:
        notify_args: --notify 参数值列表，如 ['webhook=https://x', 'email=y@z.com']
    Returns:
        解析后的通知配置列表
        [{'type': 'webhook', 'target': 'https://x'}, {'type': 'email', 'target': 'y@z.com'}]
    """
    notifications = []
    for arg in notify_args:
        arg = arg.strip()
        if not arg:
            continue
        # 支持 type=target 格式
        if '=' in arg:
            channel, _, target = arg.partition('=')
            channel = channel.strip().lower()
            target = target.strip()
            if not target:
                continue
            if channel in ('webhook', 'dingtalk', 'wechat', 'feishu', 'email'):
                notifications.append({'type': channel, 'target': target})
                continue
            # channel 不在已知类型中，尝试从 target 识别
            if target.startswith('http'):
                notifications.append({'type': 'webhook', 'target': target})
            elif '@' in target:
                notifications.append({'type': 'email', 'target': target})
        else:
            # 无 = 格式，自动识别 URL 或邮箱
            if arg.startswith('http'):
                notifications.append({'type': 'webhook', 'target': arg})
            elif '@' in arg:
                notifications.append({'type': 'email', 'target': arg})
    return notifications


def build_notification_message(report_builder) -> Dict[str, Any]:
    """从 ReportBuilder 构建通知消息内容

    Args:
        report_builder: ReportBuilder 实例
    Returns:
        消息内容字典，含 target/summary/vulns
    """
    dist = report_builder.risk_distribution()
    summary = report_builder.summary or {}
    confirmed = report_builder.confirmed_results()

    # 漏洞列表（最多 20 条，避免消息过长）
    vuln_list = []
    for r in confirmed[:20]:
        vuln_list.append({
            'name': r.name,
            'severity': r.severity,
            'url': r.url,
            'cve': getattr(r, 'cve', '') or '',
        })

    return {
        'target': report_builder.target,
        'scan_time': summary.get('started_at', ''),
        'duration': round(summary.get('duration', 0), 2),
        'request_count': summary.get('request_count', 0),
        'mode': summary.get('mode', ''),
        'risk_distribution': dist,
        'vuln_count': dist['total'],
        'high_count': dist['high'],
        'medium_count': dist['medium'],
        'low_count': dist['low'],
        'vulns': vuln_list,
        'truncated': len(confirmed) > 20,
        'total_vulns': len(confirmed),
    }


def _build_text_message(msg: Dict[str, Any]) -> str:
    """构建纯文本通知消息"""
    lines = [
        f'🔍 Ruoyi-Scan 扫描完成通知',
        f'━━━━━━━━━━━━━━━━━━━━━━━━',
        f'目标：{msg["target"]}',
        f'扫描时间：{msg["scan_time"]}',
        f'耗时：{msg["duration"]} 秒',
        f'请求数：{msg["request_count"]}',
        f'扫描模式：{msg["mode"]}',
        f'',
        f'📊 风险分布：',
        f'  确认漏洞：{msg["vuln_count"]} 个',
        f'  高危：{msg["high_count"]} 个',
        f'  中危：{msg["medium_count"]} 个',
        f'  低危：{msg["low_count"]} 个',
    ]
    if msg['vulns']:
        lines.append('')
        lines.append('🚨 漏洞列表（前 20 条）：')
        for i, v in enumerate(msg['vulns'], 1):
            cve_str = f' [{v["cve"]}]' if v['cve'] else ''
            lines.append(f'  {i}. [{v["severity"].upper()}] {v["name"]}{cve_str}')
            lines.append(f'     URL: {v["url"]}')
    if msg['truncated']:
        lines.append(f'  ... 共 {msg["total_vulns"]} 条，已截断显示')
    lines.append('━━━━━━━━━━━━━━━━━━━━━━━━')
    return '\n'.join(lines)


def _build_markdown_message(msg: Dict[str, Any]) -> str:
    """构建 Markdown 通知消息（钉钉/企业微信/飞书用）"""
    lines = [
        f'## 🔍 Ruoyi-Scan 扫描完成通知',
        f'',
        f'**目标**：{msg["target"]}',
        f'',
        f'**扫描时间**：{msg["scan_time"]}',
        f'',
        f'**耗时**：{msg["duration"]} 秒 | **请求数**：{msg["request_count"]} | **模式**：{msg["mode"]}',
        f'',
        f'### 📊 风险分布',
        f'',
        f'| 等级 | 数量 |',
        f'|------|------|',
        f'| 🔴 高危 | {msg["high_count"]} |',
        f'| 🟡 中危 | {msg["medium_count"]} |',
        f'| 🟢 低危 | {msg["low_count"]} |',
        f'| **总计** | **{msg["vuln_count"]}** |',
    ]
    if msg['vulns']:
        lines.append('')
        lines.append('### 🚨 漏洞列表（前 20 条）')
        lines.append('')
        lines.append('| # | 等级 | 漏洞名称 | CVE |')
        lines.append('|---|------|----------|-----|')
        for i, v in enumerate(msg['vulns'], 1):
            cve_str = v['cve'] or '—'
            lines.append(f'| {i} | {v["severity"].upper()} | {v["name"]} | {cve_str} |')
    if msg['truncated']:
        lines.append(f'\n*共 {msg["total_vulns"]} 条漏洞，已截断显示*')
    return '\n'.join(lines)


def send_webhook(url: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送通用 Webhook 通知

    Args:
        url: Webhook URL
        msg: 消息内容
        verbose: 是否打印日志
    Returns:
        是否成功
    """
    try:
        import requests
        payload = {
            'text': _build_text_message(msg),
            'markdown': _build_markdown_message(msg),
            'data': msg,
        }
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code < 400:
            if verbose:
                print(f'  [+]Webhook 通知已发送: {url[:50]}...')
            return True
        else:
            if verbose:
                print(f'  [!]Webhook 通知失败: HTTP {resp.status_code}')
            return False
    except Exception as e:
        if verbose:
            print(f'  [!]Webhook 通知异常: {e}')
        return False


def send_dingtalk(url: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送钉钉机器人通知

    Args:
        url: 钉钉 Webhook URL
        msg: 消息内容
    Returns:
        是否成功
    """
    try:
        import requests
        payload = {
            'msgtype': 'markdown',
            'markdown': {
                'title': '🔍 Ruoyi-Scan 扫描完成通知',
                'text': _build_markdown_message(msg),
            },
        }
        resp = requests.post(url, json=payload, timeout=10)
        result = resp.json()
        if result.get('errcode') == 0:
            if verbose:
                print(f'  [+]钉钉通知已发送')
            return True
        else:
            if verbose:
                print(f'  [!]钉钉通知失败: {result.get("errmsg", "未知错误")}')
            return False
    except Exception as e:
        if verbose:
            print(f'  [!]钉钉通知异常: {e}')
        return False


def send_wechat(url: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送企业微信机器人通知"""
    try:
        import requests
        payload = {
            'msgtype': 'markdown',
            'markdown': {
                'content': _build_markdown_message(msg),
            },
        }
        resp = requests.post(url, json=payload, timeout=10)
        result = resp.json()
        if result.get('errcode') == 0:
            if verbose:
                print(f'  [+]企业微信通知已发送')
            return True
        else:
            if verbose:
                print(f'  [!]企业微信通知失败: {result.get("errmsg", "未知错误")}')
            return False
    except Exception as e:
        if verbose:
            print(f'  [!]企业微信通知异常: {e}')
        return False


def send_feishu(url: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送飞书机器人通知"""
    try:
        import requests
        payload = {
            'msg_type': 'text',
            'content': {
                'text': _build_text_message(msg),
            },
        }
        resp = requests.post(url, json=payload, timeout=10)
        result = resp.json()
        if result.get('StatusCode') == 0 or result.get('code') == 0:
            if verbose:
                print(f'  [+]飞书通知已发送')
            return True
        else:
            if verbose:
                print(f'  [!]飞书通知失败: {result.get("msg", "未知错误")}')
            return False
    except Exception as e:
        if verbose:
            print(f'  [!]飞书通知异常: {e}')
        return False


def send_email(to_addr: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送邮件通知

    环境变量配置：
        SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS / SMTP_FROM
    """
    smtp_host = os.environ.get('SMTP_HOST', '')
    smtp_port = int(os.environ.get('SMTP_PORT', '465'))
    smtp_user = os.environ.get('SMTP_USER', '')
    smtp_pass = os.environ.get('SMTP_PASS', '')
    smtp_from = os.environ.get('SMTP_FROM', smtp_user)

    if not smtp_host or not smtp_user:
        if verbose:
            print(f'  [!]邮件通知跳过: 未配置 SMTP 环境变量（SMTP_HOST/SMTP_USER/SMTP_PASS）')
        return False

    try:
        # 构建邮件
        mime = MIMEMultipart('alternative')
        mime['Subject'] = f'🔍 Ruoyi-Scan 扫描完成 - {msg["target"]} ({msg["vuln_count"]} 个漏洞)'
        mime['From'] = smtp_from
        mime['To'] = to_addr

        # 纯文本版本
        text_content = _build_text_message(msg)
        mime.attach(MIMEText(text_content, 'plain', 'utf-8'))

        # HTML 版本
        html_content = _build_email_html(msg)
        mime.attach(MIMEText(html_content, 'html', 'utf-8'))

        # 发送
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, [to_addr], mime.as_string())
        server.quit()

        if verbose:
            print(f'  [+]邮件通知已发送: {to_addr}')
        return True
    except Exception as e:
        if verbose:
            print(f'  [!]邮件通知异常: {e}')
        return False


def _build_email_html(msg: Dict[str, Any]) -> str:
    """构建邮件 HTML 内容"""
    import html as html_module
    vuln_rows = ''
    for i, v in enumerate(msg['vulns'], 1):
        sev_color = {'high': '#d9534f', 'medium': '#f0ad4e', 'low': '#5cb85c'}.get(v['severity'], '#999')
        vuln_rows += (
            f'<tr>'
            f'<td>{i}</td>'
            f'<td><span style="color:{sev_color};font-weight:bold">{v["severity"].upper()}</span></td>'
            f'<td>{html_module.escape(v["name"])}</td>'
            f'<td style="word-break:break-all;color:#2980b9">{html_module.escape(v["url"])}</td>'
            f'<td>{html_module.escape(v["cve"] or "—")}</td>'
            f'</tr>'
        )

    return f'''<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Microsoft YaHei,Arial,sans-serif;background:#f7f7f9;padding:20px">
<div style="max-width:800px;margin:0 auto;background:#fff;padding:20px;border-radius:4px;border:1px solid #e0e0e0">
<h1 style="color:#2c3e50;border-bottom:2px solid #2c3e50;padding-bottom:8px">🔍 Ruoyi-Scan 扫描完成通知</h1>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px">
<tr><td style="padding:4px 10px"><strong>目标</strong></td><td>{html_module.escape(msg["target"])}</td></tr>
<tr><td style="padding:4px 10px"><strong>扫描时间</strong></td><td>{html_module.escape(msg["scan_time"])}</td></tr>
<tr><td style="padding:4px 10px"><strong>耗时</strong></td><td>{msg["duration"]} 秒</td></tr>
<tr><td style="padding:4px 10px"><strong>请求数</strong></td><td>{msg["request_count"]}</td></tr>
</table>
<h2 style="color:#34495e">📊 风险分布</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px">
<tr style="background:#2c3e50;color:#fff"><th style="padding:8px">等级</th><th style="padding:8px">数量</th></tr>
<tr><td style="padding:8px;color:#d9534f">🔴 高危</td><td style="padding:8px">{msg["high_count"]}</td></tr>
<tr><td style="padding:8px;color:#f0ad4e">🟡 中危</td><td style="padding:8px">{msg["medium_count"]}</td></tr>
<tr><td style="padding:8px;color:#5cb85c">🟢 低危</td><td style="padding:8px">{msg["low_count"]}</td></tr>
<tr><td style="padding:8px"><strong>总计</strong></td><td style="padding:8px"><strong>{msg["vuln_count"]}</strong></td></tr>
</table>
<h2 style="color:#34495e">🚨 漏洞列表</h2>
<table style="width:100%;border-collapse:collapse">
<tr style="background:#2c3e50;color:#fff">
<th style="padding:8px">#</th><th style="padding:8px">等级</th><th style="padding:8px">漏洞名称</th>
<th style="padding:8px">URL</th><th style="padding:8px">CVE</th>
</tr>
{vuln_rows or '<tr><td colspan="5" style="padding:20px;text-align:center;color:#999">无确认漏洞</td></tr>'}
</table>
</div>
</body>
</html>'''


def send_notifications(notifications: List[Dict[str, str]], report_builder, verbose: bool = True):
    """发送所有通知

    Args:
        notifications: 通知配置列表（parse_notify_arg 返回值）
        report_builder: ReportBuilder 实例
        verbose: 是否打印日志
    """
    if not notifications:
        return

    msg = build_notification_message(report_builder)
    if verbose:
        print(f'\n{("=" * 60)}')
        print(f'[*]发送扫描结果通知（{len(notifications)} 个渠道）')

    senders = {
        'webhook': send_webhook,
        'dingtalk': send_dingtalk,
        'wechat': send_wechat,
        'feishu': send_feishu,
        'email': send_email,
    }

    success_count = 0
    for n in notifications:
        sender = senders.get(n['type'])
        if sender:
            # email 类型的 target 是邮箱地址，其他类型的 target 是 URL
            if n['type'] == 'email':
                if sender(n['target'], msg, verbose):
                    success_count += 1
            else:
                if sender(n['target'], msg, verbose):
                    success_count += 1

    if verbose:
        print(f'[*]通知发送完成: {success_count}/{len(notifications)} 成功')
        print(f'{("=" * 60)}\n')
