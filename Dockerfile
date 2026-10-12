# Ruoyi-Scan 扫描器镜像（生产就绪）
#
# 多阶段构建：builder 安装依赖 → runtime 仅含必要文件
# 用法：
#   docker build -t ruoyi-scan .
#   docker run --rm ruoyi-scan -p http://target/
#   docker run --rm -v $(pwd)/reports:/app/reports ruoyi-scan -p http://target/ --report /app/reports
#   docker run --rm -p 8000:8000 ruoyi-scan --serve --host 0.0.0.0 --port 8000
#
# 说明：
#   - 非 root 用户 scanner 固定 UID/GID=1000，与宿主 bind-mount 报告目录的常见属主（1000）对齐
#   - 镜像默认 CMD 为 -h（CLI 工具优先）；常驻 API 用上面 --serve 用法（compose 中已显式指定）

# ── 阶段 1: builder（安装依赖到虚拟环境）──
FROM python:3.11-slim AS builder

WORKDIR /build

# 安装构建依赖（编译 C 扩展用）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 创建虚拟环境
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 先复制依赖清单，利用 Docker 层缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 阶段 2: runtime（精简运行时镜像）──
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Ruoyi-Scan"
LABEL org.opencontainers.image.description="若依（RuoYi）专项漏洞扫描器"
LABEL org.opencontainers.image.source="https://github.com/xiabai2008/Ruoyi-Scan"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# 从 builder 复制虚拟环境
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# 创建非 root 用户（固定 UID/GID=1000：bind-mount 到 /app/reports 的宿主目录通常属主为 1000，保证可写）
RUN groupadd -g 1000 scanner && useradd -u 1000 -g scanner -d /app -s /sbin/nologin scanner

# 复制项目源码（本地产物/机密目录由 .dockerignore 排除）
COPY --chown=scanner:scanner . .

# 创建报告目录
RUN mkdir -p /app/reports /app/data && chown -R scanner:scanner /app/reports /app/data

# 运行时冒烟验证：slim 镜像无编译器，源码编译的依赖若缺 .so 会在此暴露而非运行时；
# 同时覆盖 --ai-validate 所需的进程内 lab 模块（.dockerignore 保留了 lab/server.py）
RUN python -c "import werkzeug, flask, requests, fastapi, uvicorn, reportlab, openpyxl, docx, lab.server; print('RUNTIME_IMPORT_OK')"

USER scanner

# Web API 端口（--serve 模式；供 docker run -P / 编排自动映射）
EXPOSE 8000

# 入口点固定为 main.py，CMD 后追加参数
ENTRYPOINT ["python", "main.py"]
CMD ["-h"]

# 健康检查：针对 --serve 模式探测 API 健康端点（默认 -h 模式容器立即退出，不受影响）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/system/health').read()"
