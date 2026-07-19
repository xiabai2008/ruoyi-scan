# D35：Web UI 控制台
#
# 生成单页 HTML Web 控制台，连接现有 FastAPI WebSocket（D9/D11 已就绪），
# 提供扫描任务管理、实时进度、报告查看、插件管理的可视化界面。
#
# 设计原则：
#   1. 单 HTML 文件（内联 CSS/JS），无需构建工具，零依赖
#   2. 连接现有 FastAPI WebSocket API（/ws/scan）
#   3. 响应式布局，支持桌面/平板/手机
#   4. 原生 JS，不依赖 React/Vue 等框架
#
# 使用方式：
#   # 生成 Web UI HTML 文件
#   python main.py --web-ui --web-ui-output webui/index.html
#
#   # 启动 API 服务后访问 Web UI
#   python main.py --serve --port 8000
#   # 浏览器打开 http://localhost:8000/
import datetime
import html as html_module
import os
from typing import Any, Dict, List, Optional


# ============================================================
# Web UI HTML 模板
# ============================================================

WEB_UI_TEMPLATE = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ruoyi-Scan 控制台</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {{
    font-family: "Microsoft YaHei", "Segoe UI", system-ui, sans-serif;
    background: #f5f6fa; color: #2c3e50; min-height: 100vh;
  }}
  .header {{
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: #fff; padding: 16px 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    display: flex; justify-content: space-between; align-items: center;
  }}
  .header h1 {{ font-size: 20px; font-weight: 600; }}
  .header .status {{ font-size: 13px; opacity: 0.9; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  .grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;
  }}
  @media (max-width: 768px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  .card {{
    background: #fff; border-radius: 8px; padding: 20px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  }}
  .card h2 {{
    font-size: 16px; margin-bottom: 16px; padding-bottom: 12px;
    border-bottom: 2px solid #f0f0f0; color: #34495e;
  }}
  .form-group {{ margin-bottom: 12px; }}
  .form-group label {{
    display: block; font-size: 13px; color: #7f8c8d; margin-bottom: 4px;
  }}
  .form-group input, .form-group select, .form-group textarea {{
    width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px;
    font-size: 14px; transition: border-color 0.2s;
  }}
  .form-group input:focus, .form-group select:focus {{
    outline: none; border-color: #667eea;
  }}
  .btn {{
    padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer;
    font-size: 14px; font-weight: 500; transition: all 0.2s;
  }}
  .btn-primary {{
    background: #667eea; color: #fff;
  }}
  .btn-primary:hover {{ background: #5568d3; }}
  .btn-danger {{ background: #e74c3c; color: #fff; }}
  .btn-danger:hover {{ background: #c0392b; }}
  .btn-success {{ background: #27ae60; color: #fff; }}
  .btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
  .progress-bar {{
    width: 100%; height: 24px; background: #ecf0f1; border-radius: 12px;
    overflow: hidden; margin: 8px 0;
  }}
  .progress-fill {{
    height: 100%; background: linear-gradient(90deg, #27ae60, #2ecc71);
    transition: width 0.3s; display: flex; align-items: center;
    justify-content: center; color: #fff; font-size: 12px; font-weight: 600;
  }}
  .stats-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px;
  }}
  .stat-box {{
    background: #f8f9fa; border-radius: 6px; padding: 12px; text-align: center;
  }}
  .stat-box .num {{ font-size: 24px; font-weight: 700; color: #2c3e50; }}
  .stat-box .label {{ font-size: 12px; color: #7f8c8d; margin-top: 4px; }}
  .stat-box.high .num {{ color: #e74c3c; }}
  .stat-box.medium .num {{ color: #f39c12; }}
  .stat-box.low .num {{ color: #27ae60; }}
  .log-area {{
    background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 4px;
    font-family: Consolas, "Courier New", monospace; font-size: 12px;
    height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;
  }}
  .log-line {{ margin-bottom: 2px; }}
  .log-info {{ color: #569cd6; }}
  .log-success {{ color: #4ec9b0; }}
  .log-warning {{ color: #dcdcaa; }}
  .log-error {{ color: #f44747; }}
  .vuln-table {{
    width: 100%; border-collapse: collapse; font-size: 13px;
  }}
  .vuln-table th {{
    background: #34495e; color: #fff; padding: 8px 10px; text-align: left;
  }}
  .vuln-table td {{
    padding: 8px 10px; border-bottom: 1px solid #eee;
  }}
  .vuln-table tr:hover {{ background: #f8f9fa; }}
  .badge {{
    padding: 2px 8px; border-radius: 3px; font-size: 11px; color: #fff;
  }}
  .badge-high {{ background: #e74c3c; }}
  .badge-medium {{ background: #f39c12; }}
  .badge-low {{ background: #27ae60; }}
  .badge-confirmed {{ background: #e74c3c; }}
  .badge-safe {{ background: #27ae60; }}
  .badge-unknown {{ background: #95a5a6; }}
  .connection-status {{
    display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px;
  }}
  .connection-status.connected {{ background: #27ae60; }}
  .connection-status.disconnected {{ background: #e74c3c; }}
  .tabs {{
    display: flex; border-bottom: 2px solid #f0f0f0; margin-bottom: 16px;
  }}
  .tab {{
    padding: 10px 20px; cursor: pointer; border-bottom: 2px solid transparent;
    font-size: 14px; color: #7f8c8d; transition: all 0.2s;
  }}
  .tab.active {{ color: #667eea; border-bottom-color: #667eea; }}
  .tab-content {{ display: none; }}
  .tab-content.active {{ display: block; }}
</style>
</head>
<body>
<div class="header">
  <h1>Ruoyi-Scan 控制台</h1>
  <div class="status">
    <span class="connection-status disconnected" id="connStatus"></span>
    <span id="connText">未连接</span>
  </div>
</div>

<div class="container">
  <!-- 扫描配置 -->
  <div class="card" style="margin-bottom: 20px;">
    <h2>扫描配置</h2>
    <div class="grid">
      <div>
        <div class="form-group">
          <label>目标 URL</label>
          <input type="text" id="targetUrl" placeholder="http://example.com" value="">
        </div>
        <div class="form-group">
          <label>扫描模式</label>
          <select id="scanMode">
            <option value="full">综合扫描（-u）</option>
            <option value="vuln">漏洞检测（-p）</option>
            <option value="dir">目录扫描（-m）</option>
            <option value="brute">登录爆破（-l）</option>
          </select>
        </div>
      </div>
      <div>
        <div class="form-group">
          <label>扫描模板</label>
          <select id="scanTemplate">
            <option value="">默认</option>
            <option value="quick">快速扫描</option>
            <option value="deep">深度扫描</option>
            <option value="compliance">OWASP 合规</option>
            <option value="dengbao">等保合规</option>
          </select>
        </div>
        <div class="form-group">
          <label>认证（可选，格式：cookie=值）</label>
          <input type="text" id="authInfo" placeholder="cookie=JSESSIONID=xxx">
        </div>
      </div>
    </div>
    <div style="display: flex; gap: 12px;">
      <button class="btn btn-primary" id="startScanBtn" onclick="startScan()">开始扫描</button>
      <button class="btn btn-danger" id="stopScanBtn" onclick="stopScan()" disabled>停止扫描</button>
    </div>
  </div>

  <!-- 进度与统计 -->
  <div class="card" style="margin-bottom: 20px;" id="progressCard" style="display:none;">
    <h2>扫描进度</h2>
    <div class="progress-bar">
      <div class="progress-fill" id="progressFill" style="width: 0%;">0%</div>
    </div>
    <div class="stats-grid">
      <div class="stat-box"><div class="num" id="statTotal">0</div><div class="label">总请求数</div></div>
      <div class="stat-box high"><div class="num" id="statHigh">0</div><div class="label">高危漏洞</div></div>
      <div class="stat-box medium"><div class="num" id="statMedium">0</div><div class="label">中危漏洞</div></div>
      <div class="stat-box low"><div class="num" id="statLow">0</div><div class="label">低危漏洞</div></div>
    </div>
  </div>

  <!-- 标签页 -->
  <div class="card">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('vulns')">漏洞列表</div>
      <div class="tab" onclick="switchTab('logs')">实时日志</div>
      <div class="tab" onclick="switchTab('plugins')">插件管理</div>
    </div>

    <!-- 漏洞列表 -->
    <div class="tab-content active" id="tab-vulns">
      <table class="vuln-table">
        <thead>
          <tr>
            <th>严重度</th><th>漏洞名称</th><th>URL</th><th>状态</th><th>修复建议</th>
          </tr>
        </thead>
        <tbody id="vulnTableBody">
          <tr><td colspan="5" style="text-align:center;color:#999;padding:20px;">暂无扫描结果</td></tr>
        </tbody>
      </table>
    </div>

    <!-- 实时日志 -->
    <div class="tab-content" id="tab-logs">
      <div class="log-area" id="logArea">等待扫描开始...</div>
    </div>

    <!-- 插件管理 -->
    <div class="tab-content" id="tab-plugins">
      <p style="color:#7f8c8d; padding: 20px;">插件管理功能需连接 API 服务。使用 <code>--serve</code> 启动 API 后访问。</p>
    </div>
  </div>
</div>

<script>
let ws = null;
let scanTaskId = null;

// WebSocket 连接
function connectWebSocket() {{
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${{protocol}}//${{location.host}}/ws/scan`;

  try {{
    ws = new WebSocket(wsUrl);
  }} catch (e) {{
    updateConnectionStatus(false);
    return;
  }}

  ws.onopen = () => {{
    updateConnectionStatus(true);
    appendLog('WebSocket 已连接', 'success');
  }};

  ws.onmessage = (event) => {{
    try {{
      const data = JSON.parse(event.data);
      handleWebSocketMessage(data);
    }} catch (e) {{
      appendLog(event.data, 'info');
    }}
  }};

  ws.onclose = () => {{
    updateConnectionStatus(false);
    appendLog('WebSocket 已断开', 'warning');
    // 5 秒后重连
    setTimeout(connectWebSocket, 5000);
  }};

  ws.onerror = (error) => {{
    appendLog('WebSocket 错误', 'error');
  }};
}}

function updateConnectionStatus(connected) {{
  const dot = document.getElementById('connStatus');
  const text = document.getElementById('connText');
  if (connected) {{
    dot.className = 'connection-status connected';
    text.textContent = '已连接';
  }} else {{
    dot.className = 'connection-status disconnected';
    text.textContent = '未连接';
  }}
}}

function handleWebSocketMessage(data) {{
  if (data.type === 'progress') {{
    updateProgress(data);
  }} else if (data.type === 'vuln') {{
    addVulnRow(data);
    updateStats(data.stats || {{}});
  }} else if (data.type === 'log') {{
    appendLog(data.message, data.level || 'info');
  }} else if (data.type === 'complete') {{
    onScanComplete(data);
  }} else if (data.type === 'error') {{
    appendLog(`错误: ${{data.message}}`, 'error');
  }}
}}

function startScan() {{
  const target = document.getElementById('targetUrl').value.trim();
  if (!target) {{
    alert('请输入目标 URL');
    return;
  }}

  const mode = document.getElementById('scanMode').value;
  const template = document.getElementById('scanTemplate').value;
  const auth = document.getElementById('authInfo').value.trim();

  // 通过 API 启动扫描
  fetch('/api/scan', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      target: target,
      mode: mode,
      template: template,
      auth: auth || null,
    }}),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.task_id) {{
      scanTaskId = data.task_id;
      document.getElementById('startScanBtn').disabled = true;
      document.getElementById('stopScanBtn').disabled = false;
      document.getElementById('progressCard').style.display = 'block';
      appendLog(`扫描已启动：任务 ID ${{scanTaskId}}`, 'success');
    }} else {{
      appendLog(`启动失败：${{data.detail || '未知错误'}}`, 'error');
    }}
  }})
  .catch(err => {{
    appendLog(`请求失败：${{err}}`, 'error');
  }});
}}

function stopScan() {{
  if (scanTaskId) {{
    fetch(`/api/scan/${{scanTaskId}}/stop`, {{ method: 'POST' }})
    .then(() => {{
      appendLog('扫描已停止', 'warning');
      onScanComplete({{}});
    }})
    .catch(err => appendLog(`停止失败：${{err}}`, 'error'));
  }}
}}

function updateProgress(data) {{
  const pct = data.progress || 0;
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressFill').textContent = Math.round(pct) + '%';

  if (data.request_count) {{
    document.getElementById('statTotal').textContent = data.request_count;
  }}
}}

function updateStats(stats) {{
  if (stats.high !== undefined) document.getElementById('statHigh').textContent = stats.high;
  if (stats.medium !== undefined) document.getElementById('statMedium').textContent = stats.medium;
  if (stats.low !== undefined) document.getElementById('statLow').textContent = stats.low;
}}

function addVulnRow(vuln) {{
  const tbody = document.getElementById('vulnTableBody');
  // 清除"暂无"占位行
  if (tbody.children.length === 1 && tbody.children[0].cells.length === 1) {{
    tbody.innerHTML = '';
  }}

  const severityClass = vuln.severity === 'high' ? 'badge-high' :
                        vuln.severity === 'medium' ? 'badge-medium' : 'badge-low';
  const severityText = vuln.severity === 'high' ? '高危' :
                       vuln.severity === 'medium' ? '中危' : '低危';
  const statusClass = vuln.status === 'CONFIRMED' ? 'badge-confirmed' :
                      vuln.status === 'SAFE' ? 'badge-safe' : 'badge-unknown';
  const statusText = vuln.status === 'CONFIRMED' ? '确认' :
                     vuln.status === 'SAFE' ? '安全' : '未知';

  const row = document.createElement('tr');
  row.innerHTML = `
    <td><span class="badge ${{severityClass}}">${{severityText}}</span></td>
    <td>${{escapeHtml(vuln.name || '')}}</td>
    <td style="word-break:break-all;color:#2980b9;font-family:Consolas,monospace;font-size:12px;">${{escapeHtml(vuln.url || '')}}</td>
    <td><span class="badge ${{statusClass}}">${{statusText}}</span></td>
    <td style="color:#27ae60;font-size:12px;">${{escapeHtml(vuln.fix || '')}}</td>
  `;
  tbody.appendChild(row);
}}

function onScanComplete(data) {{
  document.getElementById('startScanBtn').disabled = false;
  document.getElementById('stopScanBtn').disabled = true;
  document.getElementById('progressFill').style.width = '100%';
  document.getElementById('progressFill').textContent = '100%';
  appendLog('扫描完成', 'success');

  if (data.report_url) {{
    appendLog(`报告地址: ${{data.report_url}}`, 'info');
  }}
}}

function appendLog(message, level) {{
  const logArea = document.getElementById('logArea');
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = `log-line log-${{level || 'info'}}`;
  line.textContent = `[${{time}}] ${{message}}`;
  logArea.appendChild(line);
  logArea.scrollTop = logArea.scrollHeight;

  // 限制日志条数
  while (logArea.children.length > 500) {{
    logArea.removeChild(logArea.firstChild);
  }}
}}

function switchTab(tabName) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(`tab-${{tabName}}`).classList.add('active');
}}

function escapeHtml(text) {{
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}}

// 页面加载后连接 WebSocket
window.addEventListener('load', () => {{
  connectWebSocket();
  appendLog('Web UI 控制台已加载', 'info');
  appendLog('请确保 API 服务已启动（--serve）', 'info');
}});
</script>
</body>
</html>'''


# ============================================================
# Web UI 生成
# ============================================================

def generate_web_ui(output_path: str = None,
                    api_base_url: str = '',
                    title: str = 'Ruoyi-Scan 控制台') -> str:
    """生成 Web UI HTML 文件

    Args:
        output_path: 输出文件路径（默认 webui/index.html）
        api_base_url: API 服务地址（留空则使用相对路径）
        title: 页面标题

    Returns:
        生成的文件路径
    """
    if not output_path:
        output_path = os.path.join('webui', 'index.html')

    # 确保目录存在
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # 替换标题
    content = WEB_UI_TEMPLATE.replace('Ruoyi-Scan 控制台', html_module.escape(title))

    # 如果指定了 API 地址，修改 WebSocket 和 fetch 的基础 URL
    if api_base_url:
        api_base_url = api_base_url.rstrip('/')
        content = content.replace(
            "`${protocol}//${location.host}/ws/scan`",
            f'`{api_base_url}/ws/scan`'.replace('{api_base_url}', api_base_url)
        )
        content = content.replace("'/api/scan'", f"'{api_base_url}/api/scan'")
        content = content.replace(
            "`/api/scan/${scanTaskId}/stop`",
            f'`{api_base_url}/api/scan/${{scanTaskId}}/stop`'.replace('{api_base_url}', api_base_url)
        )

    # 添加生成时间元信息
    gen_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    content = content.replace(
        '</body>',
        f'<!-- Generated by Ruoyi-Scan at {gen_time} -->\n</body>'
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return output_path


def get_web_ui_info(output_path: str = None) -> Dict[str, Any]:
    """获取 Web UI 信息

    Args:
        output_path: 输出路径

    Returns:
        {'path': str, 'size': int, 'features': list}
    """
    path = output_path or os.path.join('webui', 'index.html')
    features = [
        '扫描任务管理（启动/停止）',
        '实时进度可视化（进度条 + 统计卡片）',
        '漏洞列表（严重度/状态徽标）',
        '实时日志（WebSocket 推送）',
        '插件管理标签页',
        'WebSocket 自动重连',
        '响应式布局（桌面/平板/手机）',
    ]
    return {
        'path': path,
        'features': features,
        'dependencies': 'FastAPI WebSocket（D9/D11）',
    }


# ============================================================
# 模式入口
# ============================================================

def run_web_ui_mode(args) -> int:
    """Web UI 生成模式入口

    Args:
        args: CLI 参数

    Returns:
        0 表示成功
    """
    output = getattr(args, 'web_ui_output', None) or 'webui/index.html'
    api_base = getattr(args, 'web_ui_api', None) or ''

    print(f'[*]生成 Web UI 控制台...')
    path = generate_web_ui(output_path=output, api_base_url=api_base)

    size = os.path.getsize(path)
    print(f'[+]Web UI 已生成: {path}（{size:,} 字节）')
    print(f'[+]功能列表:')
    info = get_web_ui_info(path)
    for feat in info['features']:
        print(f'    - {feat}')
    print(f'\n[*]使用方式:')
    print(f'    1. 启动 API 服务: python main.py --serve --port 8000')
    print(f'    2. 浏览器打开: http://localhost:8000/webui/index.html')
    print(f'       或直接打开文件: {path}')

    return 0
