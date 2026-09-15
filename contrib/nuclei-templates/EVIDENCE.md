# 验证证据（v0.1.0）

## 环境

- nuclei: v3.11.1（windows_amd64，官方 release 二进制）
- 靶场: ruoyi-scan 签名靶场 `lab/server.py`（本仓库同项目，vuln / safe 双模式）
- 验证时间: 2026-09-15

## 方法

签名靶场以两种模式分别启动（同为随机高端口）：

```bash
LAB_MODE=vuln LAB_PORT=19100 python lab/server.py   # 带洞签名模式
LAB_MODE=safe LAB_PORT=19101 python lab/server.py   # 已修复签名模式

nuclei -duc -silent -nc -u http://127.0.0.1:<port> -t nuclei/
```

判定标准（与 ruoyi-scan 的三态纪律一致）：

- vuln 模式：每个模板必须命中（否则模板无效）
- safe 模式：必须**零命中**（误报红线）

## 结果

| 模式 | 命中数 | 结果 |
|------|--------|------|
| vuln | 4（3 模板，default-password 因 v4/v5 双请求各命中一次） | ✅ |
| safe | 0 | ✅ 零误报 |

### vuln 模式原始输出

```
[ruoyi-job-unauth] [http] [medium] http://127.0.0.1:19102/monitor/job/edit
[ruoyi-unauth-api] [http] [medium] http://127.0.0.1:19102/system/user/list
[ruoyi-default-password] [http] [high] http://127.0.0.1:19102/login
```

### safe 模式原始输出

```


```
（stdout 空 —— 零命中）

### 说明

- `ruoyi-default-password` 对 v4（表单）与 v5（JSON）两种登录协议各发一次请求；
  靶场两种协议均返回 token，故同一模板命中两次（不同 request）。
- 靶场为响应签名模拟器：验证的是 **matcher 与真实若依响应特征的匹配正确性**，
  不代表对特定实网版本的流行度证明。实网批量验证欢迎社区反馈。
