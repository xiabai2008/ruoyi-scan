<?php
/**
 * ThinkPHP 5.0.23 真实漏洞最小复现靶场（仅用于合法授权测试 / 教学验证）
 *
 * 复现漏洞链：
 *   1. _method=__construct 覆盖 Request 对象属性（5.0.23 RCE）
 *   2. invokefunction 路由调度（5.1.x RCE）
 *   3. think\Request/input filter 注入（5.1.x RCE）
 *
 * 参考：vulhub/thinkphp/5.0.23-rce/README.zh-cn.md
 *
 * 与 lab/thinkphp_server.py 的差异：
 *   - thinkphp_server.py 是签名靶场，返回 marker 字符串
 *   - 本脚本是真实漏洞复现，返回 phpinfo()/phpversion()/命令输出等真实响应
 *   - 用于阶段九真实交叉验证：检查插件是否能识别真实漏洞响应（非签名 marker）
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// 模拟 ThinkPHP Request 类漏洞触发链
class FakeRequest {
    public $filter = null;
    public $server = [];
    public $method = null;
    public $get = [];

    public function __construct() {
        $this->server = $_SERVER;
    }

    public function __set($name, $value) {
        $this->$name = $value;
    }

    // 模拟 Request::method(true) 返回 server[REQUEST_METHOD]
    public function getMethod() {
        return $this->server['REQUEST_METHOD'] ?? 'GET';
    }

    // 模拟 Request::input($data) 触发 call_user_func(filter, data)
    public function input($data) {
        if (is_array($this->filter)) {
            foreach ($this->filter as $f) {
                if (is_callable($f)) {
                    $data = call_user_func($f, $data);
                }
            }
        } elseif (is_string($this->filter) && is_callable($this->filter)) {
            $data = call_user_func($this->filter, $data);
        }
        return $data;
    }
}

$s = $_REQUEST['s'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

// 默认页：模拟 ThinkPHP Framework 欢迎页（指纹识别）
function thinkphp_home() {
    echo '<html><head><title>ThinkPHP Framework</title></head>';
    echo '<body><h1>ThinkPHP</h1><p>V5.0.23</p></body></html>';
}

// ============================================================
// 漏洞 1: _method=__construct 覆盖 Request 类（5.0.23 RCE）
// 触发：POST /index.php?s=captcha + _method=__construct&filter[]=phpinfo&...
// ============================================================
if (isset($_REQUEST['_method']) && $_REQUEST['_method'] === '__construct') {
    $request = new FakeRequest();
    // 把 POST/GET 参数当作 Request 对象属性覆盖
    foreach (['filter', 'server', 'method', 'get', 'route'] as $prop) {
        if (isset($_REQUEST[$prop])) {
            $request->$prop = $_REQUEST[$prop];
        }
    }
    // 触发漏洞链：filter[]=phpinfo + server[REQUEST_METHOD]=xxx
    // filter 是数组 → 遍历 call_user_func(filter_func, data)
    // data = server[REQUEST_METHOD]
    // 真实 ThinkPHP：当 filter[]=phpinfo 时，phpinfo(data) 会输出完整 phpinfo HTML
    $data = $request->input($request->getMethod());
    // 如果 data 是字符串输出（如 phpversion 返回的版本号），打印
    // 如果 filter 是 phpinfo，phpinfo() 已经直接输出 HTML
    if (is_string($data) && $data !== '' && stripos($data, '<!DOCTYPE') === false) {
        echo $data;
    }
    exit;
}

// ============================================================
// 漏洞 2: 5.1.x 路由调度 invokefunction RCE
// 触发：GET /?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
// ============================================================
if ($s && stripos($s, 'think\\app/invokefunction') !== false) {
    $function = $_REQUEST['function'] ?? '';
    $vars = $_REQUEST['vars'] ?? [];
    if (is_callable($function)) {
        // call_user_func_array('call_user_func_array', ['phpinfo', [1]])
        // 等价于 call_user_func_array('phpinfo', [1])
        $result = call_user_func_array($function, [$vars[0] ?? '', $vars[1] ?? []]);
        if (is_string($result)) {
            echo $result;
        }
        exit;
    }
}

// ============================================================
// 漏洞 3: 5.1.x think\Request/input filter 注入 RCE
// 触发：GET /index.php?s=think\Request/input&filter=phpinfo
// ============================================================
if ($s && stripos($s, 'think\\request/input') !== false) {
    $filter = $_REQUEST['filter'] ?? '';
    if (is_callable($filter)) {
        $result = call_user_func($filter, 'phpversion');
        if (is_string($result)) {
            echo $result;
        }
        exit;
    }
}

// ============================================================
// 漏洞 4: 多语言 RCE（lang 参数文件包含）
// 触发：GET /index.php?lang=php://filter/...
// 简化：检测 lang 参数含特殊字符即模拟文件包含
// ============================================================
if (isset($_REQUEST['lang'])) {
    $lang = $_REQUEST['lang'];
    if (stripos($lang, 'php://') !== false || strpos($lang, '..') !== false) {
        // 模拟文件包含执行 PHP 代码
        echo 'PHP Version ' . PHP_VERSION . "\n";
        echo 'PHP Logo: ' . (isset($_SERVER['PHPPHP_LOGO']) ? 'yes' : 'no') . "\n";
        exit;
    }
}

// ============================================================
// 漏洞 5: 模板驱动文件读取
// 触发：GET /?s=think\template&file=/etc/passwd
// 简化：返回模拟文件内容
// ============================================================
if ($s && stripos($s, 'think\\template') !== false && isset($_REQUEST['file'])) {
    $file = $_REQUEST['file'];
    // 模拟文件读取
    if (strpos($file, '..') !== false || strpos($file, '/') === 0 || strpos($file, '/etc/') === 0) {
        echo "root:x:0:0:root:/root:/bin/bash\n";
        echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
        exit;
    }
}

// ============================================================
// 漏洞 6: where 子句 SQL 注入
// 触发：GET /?order[updatexml(1,concat(0x7e,user()),1)]
// 简化：返回 SQL 错误
// ============================================================
$qs = $_SERVER['QUERY_STRING'] ?? '';
if (stripos($qs, 'extractvalue') !== false || stripos($qs, 'updatexml') !== false) {
    http_response_code(500);
    echo 'SQLSTATE[HY000]: General error: 1105 XPATH syntax error: \'~root@localhost~\'';
    exit;
}

// ============================================================
// 漏洞 7: runtime 日志暴露
// 触发：GET /runtime/log/2024-01/01.log
// ============================================================
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (strpos($path, '/runtime/log/') === 0) {
    echo '[ 2024-01-01T00:00:00 ] INFO: [ app ] default request param: id=1; SQL: SELECT * FROM user WHERE id=1' . "\n";
    exit;
}

// ============================================================
// 漏洞 8: APP_DEBUG 调试信息泄露
// 触发：GET /?debug_probe=1
// ============================================================
if (isset($_REQUEST['debug_probe'])) {
    http_response_code(500);
    echo '<html><body><h1>ThinkPHP Framework</h1><pre>';
    echo "[ error ] think\\exception\\ErrorException: Undefined variable: x\n";
    echo "#0 /var/www/html/thinkphp/library/think/Exception.php(123): ...\n";
    echo 'Stack trace:</pre></body></html>';
    exit;
}

// 默认：ThinkPHP 欢迎页
thinkphp_home();
