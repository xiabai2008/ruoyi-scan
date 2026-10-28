# D36 分布式 CLI 接线回归测试
#
# 背景：`--distributed` 曾在 main.py 里被计入"可执行模式"，但 dispatcher 没有分支，
# 命令静默退出 0 什么都不做（2026-10-28 实测）。本文件锁住三件事：
#   1. 分发器真的把 --distributed 交给接线层；
#   2. 目标收集会剔除裸开关占位符 "__flag__"、按 -f 读文件、自动补协议；
#   3. ScanTask.mode(full/vuln/dir/brute) 与 ScanRequest.mode(u/m/p/l) 双向映射一致。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli import distributed_runner
from cli.dispatcher import dispatch
from main import build_parser


def _parse(argv):
    return build_parser().parse_args(argv)


# === 参数解析 ===


def test_parser_accepts_distributed():
    """--distributed 三个取值都能解析"""
    for kind in ("master", "worker", "standalone"):
        args = _parse(["--distributed", kind])
        assert args.distributed == kind


def test_parser_rejects_unknown_distributed():
    """非法模式由 argparse 拦截，不会走到接线层"""
    with pytest.raises(SystemExit):
        _parse(["--distributed", "cluster"])


def test_mode_flag_is_placeholder_with_file():
    """-f 配合 -p 时，-p 的值是占位符 __flag__（接线层必须按"已指定"处理）"""
    args = _parse(["--distributed", "standalone", "-f", "targets.txt", "-p"])
    assert args.p == "__flag__"
    assert args.file == "targets.txt"


# === 目标收集 ===


def test_collect_targets_from_file(tmp_path):
    """-f 文件：跳过空行与注释、补协议、去重"""
    f = tmp_path / "targets.txt"
    f.write_text(
        "http://10.0.0.1:8080/\n\n# 注释行\n10.0.0.2:8080\nhttp://10.0.0.1:8080/\n",
        encoding="utf-8",
    )
    args = _parse(["--distributed", "standalone", "-f", str(f), "-p"])
    targets = distributed_runner._collect_targets(args)
    assert targets == ["http://10.0.0.1:8080/", "http://10.0.0.2:8080"]


def test_collect_targets_missing_file():
    """文件不存在时报错并返回空列表，不能拿路径本身当目标"""
    args = _parse(["--distributed", "standalone", "-f", "no_such_file.txt", "-p"])
    assert distributed_runner._collect_targets(args) == []


def test_collect_targets_single_target_without_scheme():
    """单目标没写协议时自动补 http://"""
    args = _parse(["--distributed", "master", "-p", "127.0.0.1:18080"])
    assert distributed_runner._collect_targets(args) == ["http://127.0.0.1:18080"]


def test_collect_targets_ignores_bare_flag():
    """裸 -p（无 URL、无 -f）不应把 __flag__ 当目标"""
    args = _parse(["--distributed", "master", "-p"])
    assert distributed_runner._collect_targets(args) == []


# === 模式映射 ===


def test_mode_mapping_is_bijective():
    """u/p/m/l 与 full/vuln/dir/brute 必须一一对应，错一个就会静默跑错插件类别"""
    for cli_mode, task_mode in distributed_runner.MODE_TO_TASK.items():
        assert distributed_runner.TASK_TO_MODE[task_mode] == cli_mode


# === 分发器接线 ===


def test_dispatch_routes_to_distributed(monkeypatch):
    """dispatch 必须把 --distributed 交给接线层（回归：曾经完全没分支）"""
    called = {}

    def fake_runner(args):
        called["kind"] = args.distributed
        return 0

    monkeypatch.setattr(distributed_runner, "run_distributed_mode", fake_runner)
    dispatch(_parse(["--distributed", "standalone", "-f", "targets.txt", "-p"]))
    assert called["kind"] == "standalone"


def test_dispatch_exits_nonzero_on_failure(monkeypatch):
    """接线层返回非 0 时进程必须以该码退出，CI 才能发现失败"""
    monkeypatch.setattr(distributed_runner, "run_distributed_mode", lambda args: 2)
    with pytest.raises(SystemExit) as exc:
        dispatch(_parse(["--distributed", "standalone", "-f", "targets.txt", "-p"]))
    assert exc.value.code == 2


def test_master_without_targets_returns_bad_args(monkeypatch):
    """master 没有目标时应返回参数错误码，而不是连 Redis 空等"""
    args = _parse(["--distributed", "master"])
    assert distributed_runner.run_distributed_mode(args) == distributed_runner.EXIT_BAD_ARGS


def test_blocking_timeout_treated_as_empty():
    """redis 阻塞命令的读超时按「没取到任务」处理（否则 Worker 空闲一轮就崩）"""
    from lib.distributed import _is_blocking_timeout

    # redis.exceptions.TimeoutError 与内建 TimeoutError 不是同一个类，判断按类名走
    redis_timeout = type("TimeoutError", (Exception,), {})()
    assert _is_blocking_timeout(redis_timeout) is True
    assert _is_blocking_timeout(TimeoutError("socket")) is True
    assert _is_blocking_timeout(ValueError("bad url")) is False
