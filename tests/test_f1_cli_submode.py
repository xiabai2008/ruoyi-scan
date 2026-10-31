# F1-6：-m/-p/-l 裸开关不能被子模式前的 -u 目标吞掉。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cli.dispatcher as dispatcher
from cli.runner import MODE_LABELS
from main import build_parser


@pytest.mark.parametrize(
    "flag,expected_mode,expected_label",
    [
        ("-m", "m", "目录扫描"),
        ("-p", "p", "漏洞扫描"),
        ("-l", "l", "登录爆破"),
    ],
)
def test_submode_flag_before_u_target(monkeypatch, flag, expected_mode, expected_label):
    captured = {}

    monkeypatch.setattr(dispatcher, "preflight_target", lambda target, args: True)

    def fake_run_mode(mode, target, args, show_cta=True):
        captured["mode"] = mode
        captured["target"] = target
        # 报告 summary.mode 取的就是 MODE_LABELS[mode][0]
        captured["report_mode"] = MODE_LABELS[mode][0]

    monkeypatch.setattr(dispatcher, "run_mode", fake_run_mode)

    args = build_parser().parse_args([flag, "-u", "http://127.0.0.1:19302/"])
    dispatcher.dispatch(args)

    assert captured["mode"] == expected_mode
    assert captured["target"] == "http://127.0.0.1:19302/"
    assert captured["report_mode"] == expected_label
