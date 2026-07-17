# 通用签名靶场镜像（阶段七）
# 通过 SERVER_FILE 环境变量决定运行哪个靶场：
#   server.py / thinkphp_server.py / spring_server.py / weaver_server.py
# 通过 LAB_MODE=vuln|safe 切换漏洞/安全模式，LAB_PORT 指定端口
# 用法：
#   docker build -t ruoyi-scan-lab ./lab
#   docker run -e SERVER_FILE=weaver_server.py -e LAB_MODE=vuln -e LAB_PORT=8090 -p 8090:8090 ruoyi-scan-lab
FROM python:3.11-slim

WORKDIR /app

# 靶场仅依赖 Flask
RUN pip install --no-cache-dir "flask>=2.3"

# 复制所有靶场脚本（server.py / thinkphp_server.py / spring_server.py / weaver_server.py）
COPY . /app

# 默认运行 ruoyi 靶场，safe 模式，端口 8080
ENV SERVER_FILE=server.py
ENV LAB_MODE=safe
ENV LAB_PORT=8080

EXPOSE 8080 8090 8091

# sh -c 使环境变量展开生效
CMD sh -c "python $SERVER_FILE"
