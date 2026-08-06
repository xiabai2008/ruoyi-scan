# D5 误报率测试靶场：10 个非若依站点模拟
#
# 通过 FP_TARGET 环境变量切换返回不同页面（每个靶场一个端口，由 run_fp_test.py 启动多个实例）
# 所有靶场都"确定不是若依"，扫描后断言：
#   1. 指纹识别不应判为 ruoyi（假阳）
#   2. 即使误判，POC 不应 CONFIRMED
import os

from flask import Flask, Response

app = Flask(__name__)

# 10 个靶场定义：(target_id, description)
# 每个 target_id 对应一个非若依站点的特征页面
TARGETS = {
    'blank': '纯空白页面',
    'generic_html': '通用 HTML 首页（无 CMS 特征）',
    'wordpress': 'WordPress 特征页面',
    'joomla': 'Joomla 特征页面',
    'spring_whitelabel': 'Spring Boot Whitelabel 错误页',
    'django': 'Django 默认首页',
    'nginx_welcome': 'Nginx 默认欢迎页',
    'apache_welcome': 'Apache 默认欢迎页',
    'tomcat_default': 'Tomcat 默认首页',
    'weak_ruoyi_keyword': '含"若依"二字的非若依页面（边界测试，弱特征命中但无强特征）',
}


def render(target_id):
    """返回指定靶场的响应内容"""
    if target_id == 'blank':
        return '', 'text/html'

    if target_id == 'generic_html':
        return ('<html><head><title>Home</title></head>'
                '<body><h1>Welcome to Our Website</h1>'
                '<p>This is a generic website with no CMS features.</p>'
                '</body></html>'), 'text/html'

    if target_id == 'wordpress':
        return ('<html><head><title>My Blog</title>'
                '<link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css">'
                '<meta name="generator" content="WordPress 6.2"></head>'
                '<body class="wp-content"><h1>WordPress Site</h1>'
                '<p>Powered by WordPress</p></body></html>'), 'text/html'

    if target_id == 'joomla':
        return ('<html><head><title>Joomla Site</title>'
                '<meta name="generator" content="Joomla! 4.0"></head>'
                '<body><div id="joomla-container"><h1>Welcome to Joomla</h1>'
                '<p>Open Source Matters</p></div></body></html>'), 'text/html'

    if target_id == 'spring_whitelabel':
        return ('<html><head><title>Application Error</title></head>'
                '<body><div>Whitelabel Error Page</div>'
                '<div>This application has no explicit mapping for /error,'
                'so you are seeing this as a fallback.</div>'
                '<div id="timestamp">Sat Jul 18 10:00:00 CST 2026</div>'
                '<div>There was an unexpected error (type=Not Found, status=404).</div>'
                '</body></html>'), 'text/html'

    if target_id == 'django':
        return ('<html><head><title>The install worked successfully!</title></head>'
                '<body><h1>It worked!</h1>'
                '<p>Congratulations on your first Django-powered page.</p>'
                '<p>Of course, you have not actually done any work yet.</p>'
                '<p>Next, start your first app by running '
                '<code>python manage.py startapp [app_label]</code>.</p>'
                '</body></html>'), 'text/html'

    if target_id == 'nginx_welcome':
        return ('<html><head><title>Welcome to nginx!</title></head>'
                '<body><h1>Welcome to nginx!</h1>'
                '<p>If you see this page, the nginx web server is successfully installed.</p>'
                '<p>For online documentation and support please refer to '
                '<a href="http://nginx.org/">nginx.org</a>.</p>'
                '<p><em>Thank you for using nginx.</em></p></body></html>'), 'text/html'

    if target_id == 'apache_welcome':
        return ('<html><head><title>Apache HTTP Server Test Page</title></head>'
                '<body><h1>It works!</h1>'
                '<p>This is the default web page for this server.</p>'
                '<p>The web server software is running but no content has been added, yet.</p>'
                '</body></html>'), 'text/html'

    if target_id == 'tomcat_default':
        return ('<html><head><title>Apache Tomcat</title></head>'
                '<body><h1>Apache Tomcat/9.0.50</h1>'
                '<p>If you are seeing this page, you are using a standalone Tomcat server.</p>'
                '<h3>Tomcat Setup</h3>'
                '<p>For more information, please refer to the Tomcat documentation.</p>'
                '</body></html>'), 'text/html'

    if target_id == 'weak_ruoyi_keyword':
        # 边界测试：含"若依"二字（弱特征命中），但无若依强特征（login_keywords/favicon/strong_paths）
        # 预期：弱特征命中 → 低置信度（0.2），不应判为 ruoyi
        return ('<html><head><title>某企业管理系统</title></head>'
                '<body><h1>企业管理系统</h1>'
                '<p>本系统参考了若依的设计理念，但并非若依产品。</p>'
                '<p>Powered by Custom Framework v1.0</p>'
                '</body></html>'), 'text/html'

    return '<html>404</html>', 'text/html'


@app.route('/')
@app.route('/<path:subpath>')
def index(subpath=''):
    """所有路径返回同一靶场内容（模拟静态站点）"""
    target_id = os.environ.get('FP_TARGET', 'generic_html')
    content, ct = render(target_id)
    return Response(content, mimetype=ct + '; charset=utf-8')


if __name__ == '__main__':
    port = int(os.environ.get('FP_PORT', '8500'))
    target_id = os.environ.get('FP_TARGET', 'generic_html')
    print(f'[*] FP lab: target_id={target_id} on port {port}', flush=True)
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
