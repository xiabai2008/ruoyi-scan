#!/usr/bin/env python
"""导出 FastAPI OpenAPI 规范到 docs/openapi.json

用法：
    python scripts/export_openapi.py [--output docs/openapi.json]

生成的 openapi.json 可导入 Swagger UI / Postman / Insomnia 等工具，
也可通过 `redoc-cli bundle docs/openapi.json` 生成静态 HTML 文档。
"""

import argparse
import json
import os
import sys

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.app import create_app  # noqa: E402


def export_openapi(output_path: str, indent: int = 2) -> str:
    """导出 OpenAPI 规范到文件

    Args:
        output_path: 输出文件路径
        indent: JSON 缩进空格数

    Returns:
        输出文件路径
    """
    app = create_app()
    spec = app.openapi()

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=indent)

    path_count = sum(len(paths) for paths in spec.get("paths", {}).values())
    print(f"OpenAPI 规范已导出: {output_path}")
    print(f"  标题: {spec.get('info', {}).get('title', 'N/A')}")
    print(f"  版本: {spec.get('info', {}).get('version', 'N/A')}")
    print(f"  端点数: {path_count}")
    print(f"  文件大小: {os.path.getsize(output_path)} bytes")
    return output_path


def main():
    parser = argparse.ArgumentParser(description="导出 FastAPI OpenAPI 规范")
    parser.add_argument(
        "--output",
        "-o",
        default="docs/openapi.json",
        help="输出文件路径（默认: docs/openapi.json）",
    )
    parser.add_argument(
        "--indent",
        "-i",
        type=int,
        default=2,
        help="JSON 缩进空格数（默认: 2）",
    )
    args = parser.parse_args()
    export_openapi(args.output, args.indent)


if __name__ == "__main__":
    main()
