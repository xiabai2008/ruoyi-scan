; Ruoyi-Scan NSIS 安装钩子（Tauri 2 installerHooks）
; 背景：引擎 exe（ruoyi-scan-engine.exe，~30MB）是壳首次运行时自解压到
;   %LOCALAPPDATA%\Ruoyi-Scan\engine\ 的运行时产物，NSIS 卸载器只删安装清单内的
;   文件，不认识运行时生成的子目录 → 卸载后残留 30MB 缓存。
; 此钩子在卸载完成后清掉引擎缓存与空目录；%USERPROFILE%\Ruoyi-Scan\（任务库/
;   报告 = 用户扫描历史）刻意保留，不做静默清除。

!macro NSIS_HOOK_POSTUNINSTALL
  DetailPrint "清理运行时引擎缓存..."
  RMDir /r "$LOCALAPPDATA\Ruoyi-Scan\engine"
  RMDir "$LOCALAPPDATA\Ruoyi-Scan"
!macroend
