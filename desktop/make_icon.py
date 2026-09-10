"""生成 Tauri 应用图标 app-icon.png（1024x1024，纯 stdlib）

图形 = 画布 Logo 盾标放大版：深空圆角底 + 青色姬发式盾描边 + 盾内品红扫描线 + 青色圆点
"""
import math
import struct
import zlib

S = 1024

# 主盾多边形（22 格坐标系，画布 path 采样）
SHIELD = [
    (4, 6), (11, 3), (18, 6), (18, 12), (17.4, 14.6), (15.6, 16.8),
    (13.3, 18.6), (11, 21), (8.7, 18.6), (6.4, 16.8), (4.6, 14.6), (4, 12),
]
EAR_L = [(4, 6), (6, 1.5), (9, 4.2)]
EAR_R = [(13, 4.2), (16, 1.5), (18, 6)]


def poly_dist(px, py, poly):
    dmin = 1e9
    n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]
        x2, y2 = poly[(i + 1) % n]
        dx, dy = x2 - x1, y2 - y1
        L2 = dx * dx + dy * dy
        t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / L2))
        dmin = min(dmin, math.hypot(x1 + t * dx - px, y1 + t * dy - py))
    return dmin


def inside(px, py, poly):
    """射线法：点是否在多边形内"""
    n = len(poly)
    ok = False
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > py) != (yj > py) and px < (xj - xi) * (py - yi) / (yj - yi) + xi:
            ok = not ok
        j = i
    return ok


def render() -> bytes:
    ZOOM = 0.88  # 内容占画布 88%，居中
    rows = []
    bg = (10, 10, 20, 255)
    cyan = (46, 230, 230, 255)
    cyan_soft = (46, 230, 230, 90)
    pink = (255, 62, 200, 255)

    for py in range(S):
        row = bytearray((0,))
        fy = 11 + (py / S - 0.5) * 22.0 / ZOOM
        for px in range(S):
            fx = 11 + (px / S - 0.5) * 22.0 / ZOOM
            # 圆角方形底板（半径 10.6，圆角 2.4）
            corner = 2.4
            dx = max(abs(fx - 11) - (10.6 - corner), 0)
            dy = max(abs(fy - 11) - (10.6 - corner), 0)
            if math.hypot(dx, dy) > corner:
                row += bytes((0, 0, 0, 0))
                continue

            d = min(poly_dist(fx, fy, SHIELD), poly_dist(fx, fy, EAR_L), poly_dist(fx, fy, EAR_R))
            within = inside(fx, fy, SHIELD)

            r, g, b, a = bg
            if d < 0.75:
                r, g, b, a = cyan
            elif d < 1.7:
                r, g, b, a = cyan_soft

            # 盾内扫描线 y=11.5（描边内侧，避开描边本体）
            if within and abs(fy - 11.5) < 0.55 and d > 0.9:
                r, g, b, a = pink

            # 盾内圆点
            if within and math.hypot(fx - 11, fy - 15.8) < 1.25:
                r, g, b, a = cyan

            row += bytes((r, g, b, a))
        rows.append(bytes(row))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", S, S, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"".join(rows), 9))
        + chunk(b"IEND", b"")
    )


import os
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app-icon.png")
with open(out, "wb") as f:
    f.write(render())
print("written:", out)
