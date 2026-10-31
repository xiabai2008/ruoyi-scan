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
#
# 内网 Webhook（127.0.0.1 / 10.x / 192.168.x 等）默认被拒绝；确需使用时显式设置：
#   RUOYI_SCAN_ALLOW_PRIVATE_WEBHOOKS=1
import ipaddress
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit

from lib.reporter import emit


def parse_notify_arg(notify_args: List[str]) -> List[Dict[str, str]]:
    """解析 --notify 参数列表

    Args:
        notify_args: --notify 参数值列表，如 ['webhook=https://x', 'email=y@z.com']
    Returns:
        解析后的通知配置列表
        [{'type': 'webhook', 'target': 'https://x'}, {'type': 'email', 'target': 'y@z.com'}]
    """
    notifications = []
    known_channels = ("webhook", "dingtalk", "wechat", "feishu", "email")
    for arg in notify_args:
        arg = arg.strip()
        if not arg:
            continue
        # 仅当前缀是已知渠道名时才按 type=target 拆分：
        # 否则带查询串的裸 URL（如 https://x/hook?token=abc）会被误拆成 channel/target 而丢弃
        if "=" in arg:
            prefix, _, rest = arg.partition("=")
            prefix = prefix.strip().lower()
            if prefix in known_channels:
                target = rest.strip()
                if target:
                    notifications.append({"type": prefix, "target": target})
                continue
        # 整串 URL / 邮箱自动识别（优先于 = 拆分，兼容裸 webhook URL）
        if arg.startswith("http"):
            notifications.append({"type": "webhook", "target": arg})
            continue
        if "@" in arg and "=" not in arg:
            notifications.append({"type": "email", "target": arg})
            continue
        if "=" in arg:
            # 前缀不是已知渠道：兼容旧行为，尝试从 target 段识别
            _, _, rest = arg.partition("=")
            rest = rest.strip()
            if rest.startswith("http"):
                notifications.append({"type": "webhook", "target": rest})
            elif "@" in rest:
                notifications.append({"type": "email", "target": rest})
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
        vuln_list.append(
            {
                "name": r.name,
                "severity": r.severity,
                "url": r.url,
                "cve": getattr(r, "cve", "") or "",
            }
        )

    return {
        "target": report_builder.target,
        "scan_time": summary.get("started_at", ""),
        "duration": round(summary.get("duration", 0), 2),
        "request_count": summary.get("request_count", 0),
        "mode": summary.get("mode", ""),
        "risk_distribution": dist,
        "vuln_count": dist["total"],
        "high_count": dist["high"],
        "medium_count": dist["medium"],
        "low_count": dist["low"],
        "vulns": vuln_list,
        "truncated": len(confirmed) > 20,
        "total_vulns": len(confirmed),
    }


def _build_text_message(msg: Dict[str, Any]) -> str:
    """构建纯文本通知消息"""
    lines = [
        "🔍 Ruoyi-Scan 扫描完成通知",
        "━━━━━━━━━━━━━━━━━━━━━━━━",
        f"目标：{msg['target']}",
        f"扫描时间：{msg['scan_time']}",
        f"耗时：{msg['duration']} 秒",
        f"请求数：{msg['request_count']}",
        f"扫描模式：{msg['mode']}",
        "",
        "📊 风险分布：",
        f"  确认漏洞：{msg['vuln_count']} 个",
        f"  高危：{msg['high_count']} 个",
        f"  中危：{msg['medium_count']} 个",
        f"  低危：{msg['low_count']} 个",
    ]
    if msg["vulns"]:
        lines.append("")
        lines.append("🚨 漏洞列表（前 20 条）：")
        for i, v in enumerate(msg["vulns"], 1):
            cve_str = f" [{v['cve']}]" if v["cve"] else ""
            lines.append(f"  {i}. [{v['severity'].upper()}] {v['name']}{cve_str}")
            lines.append(f"     URL: {v['url']}")
    if msg["truncated"]:
        lines.append(f"  ... 共 {msg['total_vulns']} 条，已截断显示")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


def _build_markdown_message(msg: Dict[str, Any]) -> str:
    """构建 Markdown 通知消息（钉钉/企业微信/飞书用）"""
    lines = [
        "## 🔍 Ruoyi-Scan 扫描完成通知",
        "",
        f"**目标**：{msg['target']}",
        "",
        f"**扫描时间**：{msg['scan_time']}",
        "",
        f"**耗时**：{msg['duration']} 秒 | **请求数**：{msg['request_count']} | **模式**：{msg['mode']}",
        "",
        "### 📊 风险分布",
        "",
        "| 等级 | 数量 |",
        "|------|------|",
        f"| 🔴 高危 | {msg['high_count']} |",
        f"| 🟡 中危 | {msg['medium_count']} |",
        f"| 🟢 低危 | {msg['low_count']} |",
        f"| **总计** | **{msg['vuln_count']}** |",
    ]
    if msg["vulns"]:
        lines.append("")
        lines.append("### 🚨 漏洞列表（前 20 条）")
        lines.append("")
        lines.append("| # | 等级 | 漏洞名称 | CVE |")
        lines.append("|---|------|----------|-----|")
        for i, v in enumerate(msg["vulns"], 1):
            cve_str = v["cve"] or "—"
            lines.append(f"| {i} | {v['severity'].upper()} | {v['name']} | {cve_str} |")
    if msg["truncated"]:
        lines.append(f"\n*共 {msg['total_vulns']} 条漏洞，已截断显示*")
    return "\n".join(lines)


def _redact_url_for_log(url: str) -> str:
    """日志脱敏：Webhook 端点常把访问凭证放在查询串（access_token/key）或路径末段（hook token），输出前抹除"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    if parts.query:
        parts = parts._replace(query="***")
    if parts.path:
        # 长路径段（如飞书 hook 路径 token）按凭证处理
        parts = parts._replace(path="/".join("***" if len(seg) > 12 else seg for seg in parts.path.split("/")))
    return urlunsplit(parts)


def _allow_private_webhooks() -> bool:
    return os.environ.get("RUOYI_SCAN_ALLOW_PRIVATE_WEBHOOKS", "").strip().lower() in ("1", "true", "yes", "on")


def _validate_webhook_url(url: str) -> str:
    """限制 Webhook 为 http/https，并默认拒绝本机/内网字面量地址。

    说明：这里只校验字面量 IP 与 localhost，不做 DNS 解析，避免在离线环境
    为每次通知引入解析超时；如需访问内网 Webhook，设置
    RUOYI_SCAN_ALLOW_PRIVATE_WEBHOOKS=1 显式放开。
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Webhook URL 为空")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise ValueError("Webhook 仅支持 http/https")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("Webhook URL 缺少主机名")
    if parts.username or parts.password:
        raise ValueError("Webhook URL 不允许内嵌用户名/密码")
    if _allow_private_webhooks():
        return url.strip()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Webhook 默认拒绝 localhost")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return url.strip()
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        raise ValueError("Webhook 默认拒绝内网/保留地址")
    return url.strip()


def _post_json(url: str, payload: Dict[str, Any], timeout: int = 10):
    """统一发送 JSON 通知：所有 Webhook 类型共用同一套 URL 校验。"""
    import requests

    return requests.post(_validate_webhook_url(url), json=payload, timeout=timeout)


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
        payload = {
            "text": _build_text_message(msg),
            "markdown": _build_markdown_message(msg),
            "data": msg,
        }
        resp = _post_json(url, payload)
        if resp.status_code < 400:
            if verbose:
                emit(f"  [+]Webhook 通知已发送: {_redact_url_for_log(url)[:50]}...")
            return True
        else:
            if verbose:
                emit(f"  [!]Webhook 通知失败: HTTP {resp.status_code}")
            return False
    except Exception as e:
        if verbose:
            emit(f"  [!]Webhook 通知异常: {e}")
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
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": "🔍 Ruoyi-Scan 扫描完成通知",
                "text": _build_markdown_message(msg),
            },
        }
        resp = _post_json(url, payload)
        result = resp.json()
        if result.get("errcode") == 0:
            if verbose:
                emit("  [+]钉钉通知已发送")
            return True
        else:
            if verbose:
                emit(f"  [!]钉钉通知失败: {result.get('errmsg', '未知错误')}")
            return False
    except Exception as e:
        if verbose:
            emit(f"  [!]钉钉通知异常: {e}")
        return False


def send_wechat(url: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送企业微信机器人通知"""
    try:
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": _build_markdown_message(msg),
            },
        }
        resp = _post_json(url, payload)
        result = resp.json()
        if result.get("errcode") == 0:
            if verbose:
                emit("  [+]企业微信通知已发送")
            return True
        else:
            if verbose:
                emit(f"  [!]企业微信通知失败: {result.get('errmsg', '未知错误')}")
            return False
    except Exception as e:
        if verbose:
            emit(f"  [!]企业微信通知异常: {e}")
        return False


def send_feishu(url: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送飞书机器人通知"""
    try:
        payload = {
            "msg_type": "text",
            "content": {
                "text": _build_text_message(msg),
            },
        }
        resp = _post_json(url, payload)
        result = resp.json()
        if result.get("StatusCode") == 0 or result.get("code") == 0:
            if verbose:
                emit("  [+]飞书通知已发送")
            return True
        else:
            if verbose:
                emit(f"  [!]飞书通知失败: {result.get('msg', '未知错误')}")
            return False
    except Exception as e:
        if verbose:
            emit(f"  [!]飞书通知异常: {e}")
        return False


def send_email(to_addr: str, msg: Dict[str, Any], verbose: bool = True) -> bool:
    """发送邮件通知

    环境变量配置：
        SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS / SMTP_FROM
    """
    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port_raw = os.environ.get("SMTP_PORT", "465")
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    smtp_from = os.environ.get("SMTP_FROM", smtp_user)

    if not smtp_host or not smtp_user:
        if verbose:
            emit("  [!]邮件通知跳过: 未配置 SMTP 环境变量（SMTP_HOST/SMTP_USER/SMTP_PASS）")
        return False

    # 端口解析放在异常保护内：SMTP_PORT 非数字时跳过本渠道而非中断整个通知流程
    try:
        smtp_port = int(smtp_port_raw)
    except ValueError:
        if verbose:
            emit(f"  [!]邮件通知跳过: SMTP_PORT 配置非法（{smtp_port_raw!r}），应为数字端口")
        return False

    try:
        # 构建邮件
        mime = MIMEMultipart("alternative")
        mime["Subject"] = f"🔍 Ruoyi-Scan 扫描完成 - {msg['target']} ({msg['vuln_count']} 个漏洞)"
        mime["From"] = smtp_from
        mime["To"] = to_addr

        # 纯文本版本
        text_content = _build_text_message(msg)
        mime.attach(MIMEText(text_content, "plain", "utf-8"))

        # HTML 版本
        html_content = _build_email_html(msg)
        mime.attach(MIMEText(html_content, "html", "utf-8"))

        # 发送（try/finally 保证 starttls/login/sendmail 异常路径也关闭连接，避免 socket 泄漏）
        server = None
        try:
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to_addr], mime.as_string())
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass

        if verbose:
            emit(f"  [+]邮件通知已发送: {to_addr}")
        return True
    except Exception as e:
        if verbose:
            emit(f"  [!]邮件通知异常: {e}")
        return False


def _build_email_html(msg: Dict[str, Any]) -> str:
    """构建邮件 HTML 内容"""
    import html as html_module

    vuln_rows = ""
    for i, v in enumerate(msg["vulns"], 1):
        sev_color = {"high": "#d9534f", "medium": "#f0ad4e", "low": "#5cb85c"}.get(v["severity"], "#999")
        vuln_rows += (
            f"<tr>"
            f"<td>{i}</td>"
            f'<td><span style="color:{sev_color};font-weight:bold">{v["severity"].upper()}</span></td>'
            f"<td>{html_module.escape(v['name'])}</td>"
            f'<td style="word-break:break-all;color:#2980b9">{html_module.escape(v["url"])}</td>'
            f"<td>{html_module.escape(v['cve'] or '—')}</td>"
            f"</tr>"
        )

    return f"""<!DOCTYPE html>
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
</html>"""


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
        emit(f"\n{('=' * 60)}")
        emit(f"[*]发送扫描结果通知（{len(notifications)} 个渠道）")

    senders = {
        "webhook": send_webhook,
        "dingtalk": send_dingtalk,
        "wechat": send_wechat,
        "feishu": send_feishu,
        "email": send_email,
    }

    success_count = 0
    for n in notifications:
        sender = senders.get(n["type"])
        if sender:
            if sender(n["target"], msg, verbose):
                success_count += 1

    if verbose:
        emit(f"[*]通知发送完成: {success_count}/{len(notifications)} 成功")
        emit(f"{('=' * 60)}\n")
