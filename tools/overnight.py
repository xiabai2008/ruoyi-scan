"""夜间驱动器入口（放在 worktree 内，便于定时任务的 cwd 访问）。

真正的实现与 queue/state/logs 都在 D:\\HZR_PROJECTS\\_overnight，本文件只做转发，
避免把状态文件写进 git worktree。
"""
import runpy
import sys

TARGET = r"D:\HZR_PROJECTS\_overnight\driver.py"

if __name__ == "__main__":
    runpy.run_path(TARGET, run_name="__main__")
