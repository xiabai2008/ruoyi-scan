# D7.1 payload 变形器纯函数单元测试
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.tamper import (
    append_nullbyte,
    apply_chain,
    base64_encode,
    between_replace,
    double_urlencode,
    hex_encode,
    hpp_duplicate,
    mysql_version_comment,
    randomcase,
    space2comment,
    split_for_chunked,
    url_encode,
)

# === space2comment ===

def test_space2comment_basic():
    """空格 → /**/"""
    assert space2comment('SELECT * FROM') == 'SELECT/**/*/**/FROM'

def test_space2comment_no_space():
    """无空格不变"""
    assert space2comment('SELECT') == 'SELECT'

def test_space2comment_empty():
    """空字符串不变"""
    assert space2comment('') == ''

def test_space2comment_none():
    """None 不变"""
    assert space2comment(None) is None


# === mysql_version_comment ===

def test_mysql_version_comment_basic():
    """关键字 → /*!50000关键字*/"""
    result = mysql_version_comment('SELECT * FROM users')
    assert '/*!50000SELECT*/' in result
    assert '/*!50000FROM*/' in result

def test_mysql_version_comment_custom_version():
    """自定义版本号"""
    result = mysql_version_comment('SELECT', version=40000)
    assert result == '/*!40000SELECT*/'


# === randomcase ===

def test_randomcase_changes_case():
    """大小写混淆后仍能匹配原词（忽略大小写）"""
    original = 'SELECT UNION FROM WHERE'
    result = randomcase(original)
    # 长度不变
    assert len(result) == len(original)
    # 忽略大小写后应与原词相同
    assert result.lower() == original.lower()

def test_randomcase_preserves_non_keywords():
    """非关键字不变"""
    result = randomcase('admin123')
    assert result == 'admin123'


# === between_replace ===

def test_between_replace_basic():
    """= → BETWEEN x AND x"""
    result = between_replace('id=1')
    assert 'BETWEEN' in result
    assert '1 AND 1' in result

def test_between_replace_no_equal():
    """无 = 不变"""
    assert between_replace('SELECT') == 'SELECT'


# === url_encode ===

def test_url_encode_basic():
    """URL 编码空格为 %20"""
    assert url_encode('SELECT *') == 'SELECT%20%2A'

def test_url_encode_alphanumeric():
    """字母数字不编码"""
    assert url_encode('admin123') == 'admin123'


# === double_urlencode ===

def test_double_urlencode_basic():
    """双重 URL 编码"""
    # 空格: ' ' → %20 → %2520
    result = double_urlencode(' ')
    assert result == '%2520'


# === hex_encode ===

def test_hex_encode_basic():
    """字符串 → 0x hex"""
    assert hex_encode('admin') == '0x' + 'admin'.encode('utf-8').hex()

def test_hex_encode_empty():
    """空字符串不变"""
    assert hex_encode('') == ''


# === base64_encode ===

def test_base64_encode_basic():
    """Base64 编码"""
    assert base64_encode('SELECT') == 'U0VMRUNU'

def test_base64_encode_empty():
    """空字符串不变"""
    assert base64_encode('') == ''


# === split_for_chunked ===

def test_split_for_chunked_inserts_separator():
    """关键字前插入分隔符"""
    result = split_for_chunked('UNION SELECT')
    # split_for_chunked 插入 \r\n（转义序列），结果应含回车换行
    assert '\r' in result or '\n' in result or '\\r' in result

def test_split_for_chunked_no_keywords():
    """无关键字不变"""
    assert split_for_chunked('admin') == 'admin'


# === hpp_duplicate ===

def test_hpp_duplicate_with_param():
    """含 = 的 payload 重复参数"""
    result = hpp_duplicate('id=1 UNION SELECT')
    assert '&id=' in result or '&' in result

def test_hpp_duplicate_without_param():
    """不含 = 的 payload 追加参数"""
    result = hpp_duplicate('payload', param_name='id')
    assert 'id=' in result


# === append_nullbyte ===

def test_append_nullbyte_basic():
    """末尾加 %00"""
    assert append_nullbyte('payload') == 'payload%00'

def test_append_nullbyte_empty():
    """空字符串不变"""
    assert append_nullbyte('') == ''


# === apply_chain ===

def test_apply_chain_multiple_tampers():
    """链式应用多个变形函数"""
    result = apply_chain('SELECT * FROM', space2comment, randomcase)
    # 应含 /**/（space2comment）
    assert '/**/' in result
    # 长度应 ≥ 原始（因插入了 /**/）

def test_apply_chain_empty():
    """空 payload 链式应用不变"""
    assert apply_chain('', space2comment, randomcase) == ''


if __name__ == '__main__':
    test_space2comment_basic()
    test_space2comment_no_space()
    test_space2comment_empty()
    test_space2comment_none()
    test_mysql_version_comment_basic()
    test_mysql_version_comment_custom_version()
    test_randomcase_changes_case()
    test_randomcase_preserves_non_keywords()
    test_between_replace_basic()
    test_between_replace_no_equal()
    test_url_encode_basic()
    test_url_encode_alphanumeric()
    test_double_urlencode_basic()
    test_hex_encode_basic()
    test_hex_encode_empty()
    test_base64_encode_basic()
    test_base64_encode_empty()
    test_split_for_chunked_inserts_separator()
    test_split_for_chunked_no_keywords()
    test_hpp_duplicate_with_param()
    test_hpp_duplicate_without_param()
    test_append_nullbyte_basic()
    test_append_nullbyte_empty()
    test_apply_chain_multiple_tampers()
    test_apply_chain_empty()
    print('All D7.1 tamper tests passed!')
