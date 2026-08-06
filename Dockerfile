# Ruoyi-Scan 扫描器镜像（生产就绪）
#
# 多阶段构建：builder 安装依赖 → runtime 仅含必要文件
# 用法：
#   docker build -t ruoyi-scan .
#   docker run --rm ruoyi-scan -p http://target/
#   docker run --rm -v $(pwd)/reports:/app/reports ruoyi-scan -p http://target/ --report /app/reports
#   docker run --rm -p 8000:8000 ruoyi-scan --serve --host 0.0.0.0 --port 8000

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

# 创建非 root 用户
RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /sbin/nologin scanner

# 复制项目源码
COPY --chown=scanner:scanner . .

# 创建报告目录
RUN mkdir -p /app/reports /app/data && chown -R scanner:scanner /app/reports /app/data

USER scanner

# 入口点固定为 main.py，CMD 后追加参数
ENTRYPOINT ["python", "main.py"]
CMD ["-h"]
