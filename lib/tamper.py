# payload 变形器纯函数（D7 阶段）
#
# 设计原则：
#   - 纯函数：输入 payload 字符串，输出变形后字符串，无副作用
#   - 零依赖：仅用标准库（re/random/urllib.parse）
#   - 可组合：多个变形函数可链式调用
#   - 对齐 SQLMap tamper 脚本命名
#
# 11 个变形函数：
#   space2comment / mysql_version_comment / randomcase / between_replace
#   url_encode / double_urlencode / hex_encode / base64_encode
#   split_for_chunked / hpp_duplicate / append_nullbyte
import base64
import random
import re
import urllib.parse


def space2comment(payload):
    """空格 → /**/（对齐 SQLMap space2comment）

    例: 'SELECT * FROM' → 'SELECT/**/*/**/FROM'
    """
    if not payload:
        return payload
    return payload.replace(' ', '/**/')


def mysql_version_comment(payload, version=50000):
    """MySQL 关键字 → /*!50000关键字*/（版本注释，MySQL ≥5.00 才执行）

    例: 'SELECT' → '/*!50000SELECT*/'
    对齐 SQLMap 无直接对应，但属常见 MySQL 绕过技术。
    """
    if not payload:
        return payload
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                'ORDER', 'BY', 'GROUP', 'HAVING', 'INSERT', 'UPDATE',
                'DELETE', 'DROP', 'CREATE', 'ALTER']
    result = payload
    for kw in keywords:
        result = re.sub(r'\b' + kw + r'\b', f'/*!{version}{kw}*/', result,
                        flags=re.IGNORECASE)
    return result


def randomcase(payload, keywords=None):
    """关键字大小写随机（对齐 SQLMap randomcase）

    Args:
        payload: 原始 payload
        keywords: 需要大小写混淆的关键字列表，默认为常见 SQL 关键字
    """
    if not payload:
        return payload
    if keywords is None:
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                    'ORDER', 'BY', 'GROUP', 'HAVING', 'INSERT', 'UPDATE',
                    'DELETE', 'DROP', 'CREATE', 'ALTER', 'CONCAT',
                    'DATABASE', 'USER', 'VERSION', 'SLEEP', 'BENCHMARK']
    result = payload
    for kw in keywords:
        # 查找所有匹配（忽略大小写），逐个替换为随机大小写
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        def _randomize(match):
            word = match.group(0)
            return ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in word
            )
        result = pattern.sub(_randomize, result)
    return result


def between_replace(payload):
    """= → BETWEEN x AND x（对齐 SQLMap between）

    例: 'id=1' → 'id BETWEEN 1 AND 1'
    仅替换比较运算符 =，不替换赋值。
    """
    if not payload:
        return payload
    # 匹配 field=value 模式（不替换 == 和 <= >=）
    def _replace(match):
        field = match.group(1)
        value = match.group(2)
        return f'{field} BETWEEN {value} AND {value}'
    # 匹配 标识符=值（数字或字符串）
    return re.sub(r'(\w+)=([^\s&|<>]+)', _replace, payload)


def url_encode(payload):
    """单层 URL 编码（对齐 SQLMap charencode）

    例: 'SELECT * FROM' → 'SELECT%20%2A%20FROM'
    保留字母数字，编码其他字符。
    """
    if not payload:
        return payload
    return urllib.parse.quote(payload, safe='')


def double_urlencode(payload):
    """双重 URL 编码（对齐 SQLMap charunicodeencode）

    例: ' ' → '%20' → '%2520'
    """
    if not payload:
        return payload
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')


def hex_encode(payload):
    """字符串 → Hex 编码（对齐 SQLMap apothostropheencode 思路）

    例: 'admin' → '0x61646d696e'
    """
    if not payload:
        return payload
    return '0x' + payload.encode('utf-8').hex()


def base64_encode(payload):
    """Base64 编码（对齐 SQLMap base64encode）

    例: 'SELECT' → 'U0VMRUNU'
    """
    if not payload:
        return payload
    return base64.b64encode(payload.encode('utf-8')).decode('ascii')


def split_for_chunked(payload, keywords=None):
    """关键字前插入分块拆分点（为分块传输准备）

    在指定关键字前插入 \r\n 分隔符，配合 Transfer-Encoding: chunked 使用。
    例: 'UNION SELECT' → 'UNION\r\nSELECT'
    """
    if not payload:
        return payload
    if keywords is None:
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR']
    result = payload
    for kw in keywords:
        result = re.sub(r'\b' + kw + r'\b', f'\\r\\n{kw}', result,
                        flags=re.IGNORECASE)
    return result


def hpp_duplicate(payload, param_name='id'):
    """HPP 参数污染（HTTP Parameter Pollution）

    在 payload 中追加重复参数，利用后端参数解析差异绕过 WAF。
    例: 'id=1 UNION SELECT' → 'id=1&id=UNION SELECT'
    """
    if not payload:
        return payload
    # 如果 payload 含 =，拆分为参数名和值
    if '=' in payload:
        parts = payload.split('=', 1)
        name = parts[0]
        value = parts[1] if len(parts) > 1 else ''
        return f'{name}={value}&{param_name}={value}'
    # 否则在末尾追加重复参数
    return f'{payload}&{param_name}={payload}'


def append_nullbyte(payload):
    """末尾加 %00（对齐 SQLMap appendnullbyte）

    某些 WAF 在 %00 后停止解析，可绕过规则匹配。
    例: 'payload' → 'payload%00'
    """
    if not payload:
        return payload
    return payload + '%00'


def apply_chain(payload, *tampers):
    """链式应用多个变形函数

    Args:
        payload: 原始 payload
        tampers: 变形函数列表，按顺序应用

    Returns:
        变形后的 payload
    Example:
        apply_chain('SELECT * FROM', space2comment, randomcase)
    """
    result = payload
    for tamper in tampers:
        if result:
            result = tamper(result)
    return result
