#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RuoYi 多版本靶场矩阵编排器。

目的
====
把「同一套若依插件在不同 RuoYi 版本上的三态判定表现」变成可复现的实验数据：
拉取官方源码 → 按版本要求选 JDK → 编译 → 建库导数据 → 起服务 → 扫描 → 汇总矩阵。

这是 `lab/REAL-RUOYI.md` 里遗留的 `real-ruoyi 自动化` 落地实现。此前只对 4.7.8
做过单版本交叉验证；而 4.8.0（CVE-2025-46174）与 4.8.2（CVE-2025-70986）各有独立
CVE，单版本结论不足以支撑「多版本适配」的论断。

版本与工具链要求（实测本机）
============================
| 版本    | JDK  | Spring Boot | 说明                          |
|---------|------|-------------|-------------------------------|
| v4.7.8  | 8    | 2.5.x       | 基线（已完成单版本验证）      |
| v4.8.0  | 8    | 2.5.x       | CVE-2025-46174 resetPwd 越权  |
| v4.8.2  | 8    | 2.5.x       | CVE-2025-70986 selectDept 越权 |
| v4.8.3  | 17   | 4.0.3       | 框架大版本跃迁，需独立 JDK    |

注意：RuoYi 4.x 是 Thymeleaf + Shiro 单体，**不依赖 Redis**（已核实无 RedisTemplate 用法）。

用法
====
    # 1. 拉源码（幂等，已存在则跳过）
    python run_matrix.py prepare

    # 2. 核对配置结构（确保运行时可被命令行覆盖）
    python run_matrix.py check

    # 3. 编译全部版本（首次约 10-20 分钟；需网络拉 Maven 依赖）
    #    此步不需要数据库，可先跑
    python run_matrix.py build

    # 4. 建库导数据（需要 MySQL 凭据）
    python run_matrix.py db  --db-user root --db-password *** --db-port 3306

    # 5. 起服务 + 扫描 + 出矩阵
    python run_matrix.py run --db-user root --db-password *** --db-port 3306

    # 单独执行某阶段 / 单版本
    python run_matrix.py build --only v4.8.0
    python run_matrix.py start --only v4.8.2
    python run_matrix.py scan  --only v4.8.3

    # 收尾（结束所有已启动实例）
    python run_matrix.py stop

设计要点
========
端口与数据库凭据**不写进 jar**，而在启动时以 Spring Boot 命令行参数覆盖
（`--server.port` / `--spring.datasource.druid.master.*`）。命令行优先级高于
application.yml，因此凭据变化无需重新编译——编译是全流程最慢的一步。

依赖：仅标准库 + 本机 JDK(8/17)、Maven、MySQL 客户端 + 本仓库的 main.py（扫描器）。
"""

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── 路径常量 ────────────────────────────────────────────────────
HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent  # 仓库根
SRC_DIR = HERE / "src"
OUT_DIR = HERE / "out"
LOG_DIR = OUT_DIR / "logs"
REPORT_DIR = OUT_DIR / "reports"
PID_DIR = OUT_DIR / "pids"

JDK_ROOT = Path("D:/develop")
MAVEN_CMD = Path("D:/tools/apache-maven-3.9.12/bin/mvn.cmd")
MAVEN_SETTINGS = HERE / "maven-settings.xml"

GITEE_REPO = "https://gitee.com/y_project/RuoYi.git"

# 扫描器在 API 模式下的静默不与本脚本相关：本脚本以 CLI 方式调用 main.py
SCANNER_ENTRY = PROJECT_ROOT / "main.py"

# ── 版本矩阵定义 ────────────────────────────────────────────────
# jdk_dir 指向本机已有的 JDK 安装目录（相对 JDK_ROOT）
VERSIONS = [
    {
        "tag": "v4.6.2",
        "jdk": "java-se-8u44-ri",
        "port": 18105,
        "db": "ry_matrix_462",
        "note": "白名单生效前（定时任务类漏洞应 CONFIRMED，第三条差异曲线）",
    },
    {
        "tag": "v4.7.8",
        "jdk": "java-se-8u44-ri",
        "port": 18101,
        "db": "ry_matrix_478",
        "note": "基线版本（此前已做单版本交叉验证）",
    },
    {
        "tag": "v4.8.0",
        "jdk": "java-se-8u44-ri",
        "port": 18102,
        "db": "ry_matrix_480",
        "note": "CVE-2025-46174：resetPwd 缺 checkUserDataScope 权限校验（CVSS 7.5）",
    },
    {
        "tag": "v4.8.2",
        "jdk": "java-se-8u44-ri",
        "port": 18103,
        "db": "ry_matrix_482",
        "note": "CVE-2025-70986：selectDept 越权访问部门数据（CVSS 7.5）",
    },
    {
        "tag": "v4.8.3",
        "jdk": "jdk-17.0.0.1",
        "port": 18104,
        "db": "ry_matrix_483",
        "note": "Spring Boot 4.0.3 大版本跃迁，需 JDK 17",
    },
]


def log(msg: str) -> None:
    print(f"[matrix] {msg}", flush=True)


def version_by_tag(tag: str) -> dict:
    for v in VERSIONS:
        if v["tag"] == tag:
            return v
    raise SystemExit(f"未知版本: {tag}（可选：{[v['tag'] for v in VERSIONS]}）")


def select_versions(args) -> list:
    return [version_by_tag(args.only)] if args.only else list(VERSIONS)


def run(cmd: list, cwd=None, env=None, logfile: Path = None, check: bool = True, timeout: int = None):
    """执行命令并落盘日志；失败时抛出带日志尾部的异常"""
    log(f"  $ {' '.join(str(c) for c in cmd[:4])}{' ...' if len(cmd) > 4 else ''}")
    merged = dict(os.environ)
    if env:
        merged.update(env)
    with open(logfile, "a", encoding="utf-8", errors="replace") as fh:
        fh.write(f"\n$ {' '.join(str(c) for c in cmd)}\n")
        fh.flush()
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, env=merged, stdout=fh, stderr=subprocess.STDOUT, timeout=timeout
        )
    if check and proc.returncode != 0:
        tail = ""
        if logfile and logfile.exists():
            tail = "".join(logfile.read_text(encoding="utf-8", errors="replace").splitlines(True)[-25:])
        raise SystemExit(f"命令失败 (exit={proc.returncode}): {' '.join(str(c) for c in cmd[:3])}\n--- 日志尾部 ---\n{tail}")
    return proc.returncode


# ── 阶段 1：拉源码 ──────────────────────────────────────────────
def stage_prepare(args) -> None:
    SRC_DIR.mkdir(parents=True, exist_ok=True)
    for v in select_versions(args):
        dest = SRC_DIR / v["tag"]
        if (dest / "pom.xml").exists():
            log(f"{v['tag']}: 源码已存在，跳过")
            continue
        log(f"{v['tag']}: 克隆 {GITEE_REPO}")
        run(
            ["git", "clone", "--quiet", "--depth", "1", "--branch", v["tag"], GITEE_REPO, str(dest)],
            cwd=SRC_DIR,
            logfile=LOG_DIR / f"{v['tag']}.prepare.log",
        )
    log("prepare 完成")


# ── 阶段：低权限探测账号（越权类 POC 的前置条件）───────────────
# 为什么必须用普通账号：RuoYi 的 checkUserDataScope 对超管**直接跳过**
#   if (!SysUser.isAdmin(ShiroUtils.getUserId())) { ...校验数据范围... }
# 拿 admin 探测时，无论目标版本有没有该校验行为都一致 ⇒ 区分不出来。
#
# 为什么必须造**专用最小权限角色**，而不是复用官方种子里的「普通角色」(role_id=2)：
# 实测 role_2 自带 85 个菜单权限，**包含 system:dept:list/view/add/edit/remove 全套**——
# 若用它探测「部门树越权」（CVE-2025-70986，探测账号需无 system:dept:list），
# 账号本来就合法持有该权限，根本构不成越权场景。因此本阶段造一个只授
# system:user:resetPwd 的专用角色，数据范围仅含部门 105（测试部门），
# 使超管（部门 103）天然在范围外。
LOWPRIV_LOGIN = "scanner_low"
LOWPRIV_PASSWORD = "LowPriv_2026"
LOWPRIV_SALT = "mtrx01"  # 固定盐，保证 seed 幂等可复现（仅实验室使用）
LOWPRIV_ROLE_ID = 99  # 专用探测角色（避开官方种子的 role_id 1/2）
LOWPRIV_DEPT_ID = 105  # 测试部门：在探测角色可见范围内
RESETPWD_MENU_ID = 1006  # sys_menu.perms = system:user:resetPwd
USERLIST_MENU_ID = 1000  # sys_menu.perms = system:user:list（供插件做「可见用户」对照基线）
JOBLIST_MENU_ID = 1050  # sys_menu.perms = monitor:job:list（读任务列表/日志）
JOBEDIT_MENU_ID = 1052  # sys_menu.perms = monitor:job:edit（定时任务白名单缺陷的触发权限）
JOBSTATUS_MENU_ID = 1054  # sys_menu.perms = monitor:job:changeStatus（/monitor/job/run 触发权限）
LOWPRIV_TARGET_DEPT = 103  # 超管所在部门（探测角色可见范围之外）


def ruoyi_password_hash(login_name: str, password: str, salt: str) -> str:
    """RuoYi 口令哈希：md5(loginName + password + salt)

    对应 `SysPasswordService.encryptPassword`：
        return new Md5Hash(loginName + password + salt).toHex();
    （2026-09-17 已用 admin/admin123 的实际存储值反推验证）
    """
    return hashlib.md5((login_name + password + salt).encode()).hexdigest()


def stage_seed(args) -> None:
    """在各版本库中创建低权限探测账号（越权类 POC 的前置条件）

    为每个版本库执行：
      1. 建专用最小权限角色（role_id=99）：**仅**授 `system:user:resetPwd`，
         数据范围=自定义、仅部门 105——刻意**不含**任何 system:dept:* 权限
         （复用官方「普通角色」会带上 dept 全套权限，使部门树越权探测失效）；
      2. 建 scanner_low 账号并绑定该角色（所在部门 105 在可见范围内，
         超管所在部门 103 与其数据范围都在外）。

    幂等：相关行先删后建。
    """
    pwd_hash = ruoyi_password_hash(LOWPRIV_LOGIN, LOWPRIV_PASSWORD, LOWPRIV_SALT)
    role_id = LOWPRIV_ROLE_ID
    for v in select_versions(args):
        db = v["db"]
        sql = f"""
DELETE FROM sys_user_role WHERE user_id IN (SELECT user_id FROM sys_user WHERE login_name='{LOWPRIV_LOGIN}');
DELETE FROM sys_role_menu WHERE role_id={role_id};
DELETE FROM sys_role_dept WHERE role_id={role_id};
DELETE FROM sys_role WHERE role_id={role_id};
DELETE FROM sys_user WHERE login_name='{LOWPRIV_LOGIN}';
INSERT INTO sys_role
    (role_id, role_name, role_key, role_sort, data_scope, status, del_flag, create_by, create_time, remark)
VALUES
    ({role_id}, '扫描探测专用', 'scanner_probe', 99, '2', '0', '0', 'admin', NOW(),
     '多版本矩阵低权探测角色（勿删）：仅 system:user:resetPwd，数据范围=部门{LOWPRIV_DEPT_ID}');
INSERT INTO sys_role_dept (role_id, dept_id) VALUES ({role_id}, {LOWPRIV_DEPT_ID});
INSERT INTO sys_role_menu (role_id, menu_id) VALUES ({role_id}, {RESETPWD_MENU_ID});
INSERT INTO sys_role_menu (role_id, menu_id) VALUES ({role_id}, {USERLIST_MENU_ID});
INSERT INTO sys_role_menu (role_id, menu_id) VALUES ({role_id}, {JOBLIST_MENU_ID});
INSERT INTO sys_role_menu (role_id, menu_id) VALUES ({role_id}, {JOBEDIT_MENU_ID});
INSERT INTO sys_role_menu (role_id, menu_id) VALUES ({role_id}, {JOBSTATUS_MENU_ID});
INSERT INTO sys_user
    (dept_id, login_name, user_name, user_type, email, phonenumber, sex, avatar,
     password, salt, status, del_flag, create_by, create_time, remark)
VALUES
    ({LOWPRIV_DEPT_ID}, '{LOWPRIV_LOGIN}', '低权探测账号', '00', '', '', '0', '',
     '{pwd_hash}', '{LOWPRIV_SALT}', '0', '0', 'admin', NOW(), '多版本矩阵低权探测账号');
INSERT INTO sys_user_role (user_id, role_id)
    SELECT user_id, {role_id} FROM sys_user WHERE login_name='{LOWPRIV_LOGIN}';
"""
        mysql_exec(args, sql, database=db)
        n = mysql_query(
            args, f"SELECT COUNT(*) FROM {db}.sys_user WHERE login_name='{LOWPRIV_LOGIN}' AND status='0';"
        )
        perms = mysql_query(
            args,
            f"SELECT COUNT(*) FROM {db}.sys_role_menu rm JOIN {db}.sys_menu m ON rm.menu_id=m.menu_id "
            f"WHERE rm.role_id={role_id};",
        )
        dept_perms = mysql_query(
            args,
            f"SELECT COUNT(*) FROM {db}.sys_role_menu rm JOIN {db}.sys_menu m ON rm.menu_id=m.menu_id "
            f"WHERE rm.role_id={role_id} AND m.perms LIKE 'system:dept%';",
        )
        log(
            f"{v['tag']}: 低权账号就绪（用户 {n} 个，权限 {perms} 项=[resetPwd,user:list,job:list,job:edit,job:status]，"
            f"其中 dept 类 {dept_perms} 项——必须为 0）"
        )
    log(f"seed 完成（账号 {LOWPRIV_LOGIN} / {LOWPRIV_PASSWORD}）")


# ── 数据源 URL 构造 ─────────────────────────────────────────────
def jdbc_url(args, v: dict) -> str:
    return (
        f"jdbc:mysql://{args.db_host}:{args.db_port}/{v['db']}"
        "?useUnicode=true&characterEncoding=utf8&zeroDateTimeBehavior=convertToNull"
        "&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=GMT%2B8"
    )


# ── 阶段 2：检查配置可覆盖性（不再改写 jar 内配置）──────────────
def stage_check(args) -> None:
    """确认各版本配置结构一致、且运行时可被命令行覆盖。

    设计决策：**不把端口与数据库凭据改写进 jar**，改为启动时用 Spring Boot 命令行
    参数覆盖（命令行优先级高于 application.yml）。好处：
      - 凭据变化无需重新编译（编译是全流程最慢的一步）；
      - 各版本源码保持原样，便于对照与复现；
      - 4 个版本共用同一份编译产物形态。
    本阶段只做结构核对，防止上游改结构后静默失效。
    """
    for v in select_versions(args):
        root = SRC_DIR / v["tag"]
        app_yml = root / "ruoyi-admin/src/main/resources/application.yml"
        druid_yml = root / "ruoyi-admin/src/main/resources/application-druid.yml"
        for p, pat, label in (
            (app_yml, r"(?m)^\s*port:\s*\d+", "server.port"),
            (druid_yml, r"(?m)^\s*url:\s*jdbc:mysql://[^\s]*", "datasource.master.url"),
            (druid_yml, r"(?m)^\s*username:\s*\S+", "datasource.master.username"),
            (druid_yml, r"(?m)^\s*password:\s*\S+", "datasource.master.password"),
        ):
            if not re.search(pat, p.read_text(encoding="utf-8")):
                raise SystemExit(f"{v['tag']}: 配置结构变化，未找到 {label}（{p.name}）——请更新 run_matrix.py")
        log(f"{v['tag']}: 配置结构核对通过（运行时覆盖路径可用）")
    log("check 完成")


# ── 阶段 3：Maven 编译 ──────────────────────────────────────────
def find_jar(tag: str) -> Path:
    root = SRC_DIR / tag
    jars = sorted((root / "ruoyi-admin/target").glob("ruoyi-admin*.jar"))
    jars = [j for j in jars if not j.name.endswith(".original")]
    return jars[0] if jars else None


def stage_build(args) -> None:
    for v in select_versions(args):
        root = SRC_DIR / v["tag"]
        jar = find_jar(v["tag"])
        if jar and not args.force:
            log(f"{v['tag']}: 产物已存在，跳过编译 → {jar.name}")
            continue
        jdk_home = JDK_ROOT / v["jdk"]
        if not (jdk_home / "bin/java.exe").exists():
            raise SystemExit(f"{v['tag']} 需要 JDK {v['jdk']}，未找到 {jdk_home}")
        log(f"{v['tag']}: 编译中（JAVA_HOME={jdk_home}；首次需下载依赖）")
        run(
            [str(MAVEN_CMD), "-s", str(MAVEN_SETTINGS), "-B", "-DskipTests", "clean", "package"],
            cwd=root,
            env={"JAVA_HOME": str(jdk_home)},
            logfile=LOG_DIR / f"{v['tag']}.build.log",
            timeout=1800,
        )
        jar = find_jar(v["tag"])
        if not jar:
            raise SystemExit(f"{v['tag']} 编译完成但未找到 ruoyi-admin jar，请查看日志")
        log(f"{v['tag']}: 编译成功 → {jar}")
    log("build 完成")


# ── 阶段 4：建库导数据 ──────────────────────────────────────────
def mysql_exec(args, sql_text: str, database: str = None) -> None:
    cmd = [
        args.mysql,
        f"--host={args.db_host}",
        f"--port={args.db_port}",
        f"--user={args.db_user}",
        "--default-character-set=utf8mb4",
    ]
    if database:
        cmd.append(database)
    env = {"MYSQL_PWD": args.db_password}
    proc = subprocess.run(
        cmd, input=sql_text, env={**os.environ, **env}, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        raise SystemExit(f"MySQL 执行失败: {proc.stderr.strip()[:500]}")


def mysql_query(args, sql_text: str) -> str:
    cmd = [
        args.mysql,
        f"--host={args.db_host}",
        f"--port={args.db_port}",
        f"--user={args.db_user}",
        "--batch",
        "--skip-column-names",
    ]
    proc = subprocess.run(
        cmd,
        input=sql_text,
        env={**os.environ, "MYSQL_PWD": args.db_password},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise SystemExit(f"MySQL 查询失败: {proc.stderr.strip()[:500]}")
    return proc.stdout.strip()


def stage_db(args) -> None:
    # 连通性预检：给出明确报错，而不是让后续步骤莫名失败
    ver = mysql_query(args, "SELECT VERSION();")
    log(f"MySQL 连通正常，服务端版本 {ver}")

    for v in select_versions(args):
        root = SRC_DIR / v["tag"]
        sql_files = sorted((root / "sql").glob("ry_*.sql")) + sorted((root / "sql").glob("quartz.sql"))
        if not sql_files:
            raise SystemExit(f"{v['tag']} 未找到 SQL 文件")

        mysql_exec(args, f"DROP DATABASE IF EXISTS `{v['db']}`; CREATE DATABASE `{v['db']}` DEFAULT CHARSET utf8mb4;")
        for f in sql_files:
            log(f"{v['tag']}: 导入 {f.name}")
            mysql_exec(args, f.read_text(encoding="utf-8", errors="replace"), database=v["db"])
        tables = mysql_query(args, f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{v['db']}';")
        log(f"{v['tag']}: 库 {v['db']} 就绪，共 {tables} 张表")
    log("db 完成")


# ── 阶段：项目自带的独立 MySQL 实例（避免依赖宿主 MySQL 凭据）──
MYSQLD_BIN = Path("C:/Program Files/MySQL/MySQL Server 8.0/bin/mysqld.exe")
MYSQL_DATA_DIR = HERE / "mysql_data"
LOCAL_DB_PORT = "13306"


def _pid_listening_on(port: str) -> str:
    """返回监听指定端口的进程 PID；无则空串

    只认 LISTENING 状态：会话结束后残留的 TIME_WAIT 连接会干扰匹配。
    """
    proc = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, errors="replace")
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
            if parts[1].endswith(":" + port):
                return parts[4]
    return ""


def stage_dbstart(args) -> None:
    """启动项目自带的独立 MySQL 实例（datadir=mysql_data，端口 13306，root 无密码）

    动机：宿主 MySQL 的 root 凭据往往不可得，而矩阵只需要一个可丢弃的库。
    独立实例让矩阵「开箱即跑」，且完全不触碰宿主数据。

    安全约定：本阶段与 dbstop **只操作监听在 LOCAL_DB_PORT 的进程**，
    绝不按镜像名（mysqld.exe）结束进程——宿主可能同时运行着自己的 MySQL 服务，
    按镜像名结束会连带杀掉它。
    """
    existing = _pid_listening_on(LOCAL_DB_PORT)
    if existing:
        log(f"独立 MySQL 已在运行（端口 {LOCAL_DB_PORT}，PID {existing}），跳过")
        return
    if not MYSQLD_BIN.exists():
        raise SystemExit(f"未找到 mysqld：{MYSQLD_BIN}")

    MYSQL_DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not (MYSQL_DATA_DIR / "mysql").exists():
        log("初始化独立数据目录（root 无密码，仅监听 127.0.0.1）...")
        run(
            [
                str(MYSQLD_BIN),
                "--initialize-insecure",
                f"--datadir={MYSQL_DATA_DIR}",
                f"--basedir={MYSQLD_BIN.parent.parent}",
            ],
            logfile=LOG_DIR / "mysql.init.log",
            timeout=300,
        )
    log(f"启动独立 MySQL（端口 {LOCAL_DB_PORT}）...")
    logf = open(LOG_DIR / "mysql.console.log", "a", encoding="utf-8", errors="replace")
    subprocess.Popen(
        [
            str(MYSQLD_BIN),
            f"--datadir={MYSQL_DATA_DIR}",
            f"--basedir={MYSQLD_BIN.parent.parent}",
            f"--port={LOCAL_DB_PORT}",
            "--bind-address=127.0.0.1",
            "--console",
        ],
        stdout=logf,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 120
    while time.time() < deadline:
        if _pid_listening_on(LOCAL_DB_PORT):
            log(f"独立 MySQL 已就绪（端口 {LOCAL_DB_PORT}）")
            return
        time.sleep(2)
    raise SystemExit("独立 MySQL 启动超时，请查看 out/logs/mysql.console.log")


def stage_dbstop(args) -> None:
    """结束项目自带的独立 MySQL 实例（按端口定位 PID，只结束该进程）"""
    pid = _pid_listening_on(LOCAL_DB_PORT)
    if not pid:
        log(f"端口 {LOCAL_DB_PORT} 无监听进程，无需清理")
        return
    log(f"结束独立 MySQL（PID {pid}）")
    subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
    time.sleep(2)
    if _pid_listening_on(LOCAL_DB_PORT):
        raise SystemExit(f"PID {pid} 未能结束，请手动检查端口 {LOCAL_DB_PORT}")
    log("dbstop 完成")


# ── 阶段 5：起服务 ──────────────────────────────────────────────
def pid_file(tag: str) -> Path:
    return PID_DIR / f"{tag}.pid"


def is_up(port: int, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=timeout) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        return e.code in (200, 302, 403)
    except Exception:
        return False


def stage_start(args) -> None:
    PID_DIR.mkdir(parents=True, exist_ok=True)
    for v in select_versions(args):
        if is_up(v["port"]):
            log(f"{v['tag']}: 端口 {v['port']} 已在服务，跳过启动")
            continue
        jar = find_jar(v["tag"])
        if not jar:
            raise SystemExit(f"{v['tag']} 无编译产物，请先执行 build")
        jdk_home = JDK_ROOT / v["jdk"]
        log(f"{v['tag']}: 启动（port={v['port']}, db={v['db']}）")
        # 端口与数据源均在命令行覆盖：优先级高于 application.yml，无需重新编译 jar
        overrides = [
            f"--server.port={v['port']}",
            f"--spring.datasource.druid.master.url={jdbc_url(args, v)}",
            f"--spring.datasource.druid.master.username={args.db_user}",
            f"--spring.datasource.druid.master.password={args.db_password}",
        ]
        logf = open(LOG_DIR / f"{v['tag']}.app.log", "a", encoding="utf-8", errors="replace")
        proc = subprocess.Popen(
            [str(jdk_home / "bin/java.exe"), "-jar", str(jar), *overrides],
            cwd=str(SRC_DIR / v["tag"]),
            env={**os.environ, "JAVA_HOME": str(jdk_home)},
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
        pid_file(v["tag"]).write_text(str(proc.pid), encoding="utf-8")

        deadline = time.time() + args.start_timeout
        while time.time() < deadline:
            if is_up(v["port"]):
                log(f"{v['tag']}: 已就绪（{v['port']}）")
                break
            if proc.poll() is not None:
                app_log = LOG_DIR / (v["tag"] + ".app.log")
                raise SystemExit(f"{v['tag']}: 进程提前退出，请查看 {app_log}")
            time.sleep(2)
        else:
            raise SystemExit(f"{v['tag']}: 启动超时（{args.start_timeout}s），请查看应用日志")
    log("start 完成")


def stage_stop(args) -> None:
    for v in select_versions(args):
        pf = pid_file(v["tag"])
        if not pf.exists():
            continue
        pid = pf.read_text(encoding="utf-8").strip()
        log(f"{v['tag']}: 结束进程 {pid}")
        subprocess.run(["taskkill", "/F", "/T", "/PID", pid], capture_output=True)
        pf.unlink(missing_ok=True)
    log("stop 完成")


# ── 阶段 6：扫描 ────────────────────────────────────────────────
def stage_scan(args) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    for v in select_versions(args):
        out_dir = REPORT_DIR / v["tag"]
        out_dir.mkdir(parents=True, exist_ok=True)
        if not is_up(v["port"]):
            raise SystemExit(f"{v['tag']}: 服务未就绪（port={v['port']}），请先执行 start")
        log(f"{v['tag']}: 扫描 http://127.0.0.1:{v['port']}/")
        run(
            [
                args.python,
                str(SCANNER_ENTRY),
                "-p",
                f"http://127.0.0.1:{v['port']}/",
                # 注意：不传 --cms——让扫描器走真实指纹（识别 cms + 版权年份版本号），
                # 否则 D3 的 affected_versions 过滤永远休眠（人工模式 version 为空）。
                "--timeout",
                str(args.scan_timeout),
                "--report",
                str(out_dir),
                "--report-format",
                "json",
            ],
            cwd=PROJECT_ROOT,
            logfile=LOG_DIR / f"{v['tag']}.scan.log",
            timeout=args.scan_timeout * 40,
        )
    log("scan 完成")


# ── 阶段 7：汇总矩阵 ────────────────────────────────────────────
def load_report(tag: str):
    p = REPORT_DIR / tag / "report.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def stage_matrix(args) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    per_version = {}

    for v in VERSIONS:
        rep = load_report(v["tag"])
        if rep is None:
            log(f"{v['tag']}: 无扫描报告，跳过")
            continue
        results = rep.get("results", [])
        counts = {"CONFIRMED": 0, "SAFE": 0, "UNKNOWN": 0}
        for r in results:
            st = r.get("status", "UNKNOWN")
            counts[st] = counts.get(st, 0) + 1
        per_version[v["tag"]] = {r.get("name", ""): r.get("status") for r in results}
        rows.append({"version": v["tag"], "port": v["port"], **counts, "total": len(results), "note": v["note"]})

    if not rows:
        raise SystemExit("没有任何扫描报告，无法生成矩阵。请先执行 run/scan。")

    # CSV
    csv_path = OUT_DIR / "matrix.csv"
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # Markdown：逐插件 × 逐版本的三态表（核心交付物）
    all_names = []
    for tag in per_version:
        for name in per_version[tag]:
            if name not in all_names:
                all_names.append(name)
    all_names.sort()

    tags = list(per_version.keys())
    md = ["# RuoYi 多版本靶场矩阵", ""]
    md.append("由 `lab/version_matrix/run_matrix.py` 自动生成。三态定义见 `common/models.py`。")
    md.append("")
    md.append("## 版本概览")
    md.append("")
    md.append("| 版本 | 端口 | CONFIRMED | SAFE | UNKNOWN | 合计 | 说明 |")
    md.append("|---|---|---|---|---|---|---|")
    for r in rows:
        md.append(
            f"| {r['version']} | {r['port']} | {r['CONFIRMED']} | {r['SAFE']} | {r['UNKNOWN']} | {r['total']} | {r['note']} |"
        )
    md.append("")
    md.append("## 逐插件三态分布")
    md.append("")
    md.append("| 插件 | " + " | ".join(tags) + " |")
    md.append("|---" * (len(tags) + 1) + "|")
    for name in all_names:
        cells = []
        for t in tags:
            st = per_version[t].get(name)
            cells.append("—" if st is None else {"CONFIRMED": "**C**", "SAFE": "S", "UNKNOWN": "U"}.get(st, st))
        md.append(f"| {name} | " + " | ".join(cells) + " |")
    md.append("")
    md.append("图例：**C** = CONFIRMED（确认存在）／S = SAFE（确认不存在）／U = UNKNOWN（无法判定）／— = 该版本未覆盖此插件")
    md.append("")

    md_path = OUT_DIR / "MATRIX.md"
    md_path.write_text("\n".join(md), encoding="utf-8")

    log(f"矩阵已生成：{md_path}")
    log(f"CSV：{csv_path}")
    for r in rows:
        log(f"  {r['version']}: C={r['CONFIRMED']} S={r['SAFE']} U={r['UNKNOWN']} (共 {r['total']})")
    log("matrix 完成")


# ── 命令行 ──────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="RuoYi 多版本靶场矩阵编排器")
    ap.add_argument(
        "stage",
        choices=[
            "prepare",
            "check",
            "build",
            "dbstart",
            "db",
            "seed",
            "dbstop",
            "start",
            "stop",
            "scan",
            "matrix",
            "run",
            "all",
        ],
        help="run/all = check → build → db → seed → start → scan → matrix（需先 dbstart 或自备 MySQL）",
    )
    ap.add_argument("--only", help="只处理指定版本（如 v4.8.0）")
    ap.add_argument("--force", action="store_true", help="build 阶段忽略已有产物强制重编译")
    ap.add_argument("--db-host", default="127.0.0.1")
    ap.add_argument("--db-port", default="3306")
    ap.add_argument("--db-user", default="root")
    ap.add_argument("--db-password", default=os.environ.get("MATRIX_DB_PASSWORD", ""))
    ap.add_argument("--mysql", default="mysql", help="mysql 客户端可执行文件路径")
    ap.add_argument("--python", default=sys.executable, help="扫描器使用的 Python 解释器")
    ap.add_argument("--start-timeout", type=int, default=180, help="单版本启动就绪等待上限（秒）")
    ap.add_argument("--scan-timeout", type=int, default=5, help="扫描器单请求超时（秒）")
    args = ap.parse_args()

    for d in (LOG_DIR, REPORT_DIR, PID_DIR):
        d.mkdir(parents=True, exist_ok=True)

    if args.stage == "prepare":
        stage_prepare(args)
        return

    if args.stage in ("db", "start", "scan") and not args.db_password:
        log("提示：未提供 --db-password 且环境变量 MATRIX_DB_PASSWORD 为空，MySQL 认证可能失败")

    dispatch = {
        "check": stage_check,
        "build": stage_build,
        "dbstart": stage_dbstart,
        "db": stage_db,
        "seed": stage_seed,
        "dbstop": stage_dbstop,
        "start": stage_start,
        "stop": stage_stop,
        "scan": stage_scan,
        "matrix": stage_matrix,
    }
    if args.stage in dispatch:
        dispatch[args.stage](args)
        return

    # run / all
    for name in ("check", "build", "db", "seed", "start", "scan", "matrix"):
        log(f"==== {name} ====")
        dispatch[name](args)


if __name__ == "__main__":
    main()
