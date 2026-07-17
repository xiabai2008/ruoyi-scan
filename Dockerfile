# Ruoyi-Scan 扫描器镜像（阶段七）
# 用法：docker build -t ruoyi-scan .
#       docker run --rm ruoyi-scan -p http://target/
#       docker run --rm -v $(pwd)/reports:/app/reports ruoyi-scan -p http://target/ --report /app/reports
FROM python:3.11-slim

WORKDIR /app

# 先复制依赖清单，利用 Docker 层缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目源码
COPY . .

# 入口点固定为 main.py，CMD 后追加参数
ENTRYPOINT ["python", "main.py"]
CMD ["-h"]
