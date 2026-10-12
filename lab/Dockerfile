# 通用签名靶场镜像（阶段七）
# 通过 SERVER_FILE 环境变量决定运行哪个靶场：
#   server.py（RuoYi）/ spring_server.py（Spring Boot）
# 通过 LAB_MODE=vuln|safe 切换漏洞/安全模式，LAB_PORT 指定端口
# 用法：
#   docker build -t ruoyi-scan-lab ./lab
#   docker run -e SERVER_FILE=spring_server.py -e LAB_MODE=vuln -e LAB_PORT=8091 -p 8091:8091 ruoyi-scan-lab
FROM python:3.11-slim

WORKDIR /app

# 靶场仅依赖 Flask（与 lab/requirements.txt 的 Flask>=3.0 对齐，固定版本保证可复现）
RUN pip install --no-cache-dir "flask==3.1.3"

# 复制靶场脚本（.dockerignore 为白名单，仅放行 *.py）
COPY . /app

# 非 root 运行：vuln 模式含故意漏洞签名，降权以限制被利用后的影响面
RUN useradd -u 1000 -m -s /sbin/nologin lab && chown -R lab:lab /app

# 默认运行 ruoyi 靶场，safe 模式，端口 8080
ENV SERVER_FILE=server.py
ENV LAB_MODE=safe
ENV LAB_PORT=8080
# 容器内必须监听 0.0.0.0 才能被宿主端口映射访问（脚本默认 127.0.0.1）；
# 宿主侧暴露面由 -p 127.0.0.1:port:port 收口（见 lab/run_acceptance.sh 与 docker-compose.yml）
ENV LAB_HOST=0.0.0.0

EXPOSE 8080 8090 8091

USER lab

# sh -c 用于展开 $SERVER_FILE；exec 让 python 成为 PID 1，docker stop 的 SIGTERM 才能优雅送达；
# 变量加引号，避免 SERVER_FILE 含空格时被拆成多个参数
CMD ["sh", "-c", "exec python \"$SERVER_FILE\""]
