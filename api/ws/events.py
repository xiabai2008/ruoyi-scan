# D9 WebSocket 事件类型常量
#
# 事件类型定义（与 orchestrator _emit 调用对齐）

# 任务状态事件
EVENT_STATUS = 'status'           # 任务状态变更：pending/running/done/failed/cancelled
EVENT_COMPLETE = 'complete'       # 任务完成（含 duration/result_count）

# 扫描过程事件
EVENT_FINGERPRINT = 'fingerprint' # 指纹识别完成
EVENT_WAF = 'waf'                 # WAF 识别完成
EVENT_PORTSCAN = 'portscan'       # 端口扫描完成
EVENT_CATEGORY_START = 'category_start'  # 插件分组开始
EVENT_RESULT = 'result'           # 单个插件产生结果
EVENT_PROGRESS = 'progress'       # 进度更新
EVENT_REPORT = 'report'           # 报告生成完成

# 错误事件
EVENT_ERROR = 'error'             # 任务异常

# 所有合法事件类型
ALL_EVENTS = {
    EVENT_STATUS, EVENT_COMPLETE, EVENT_FINGERPRINT, EVENT_WAF,
    EVENT_PORTSCAN, EVENT_CATEGORY_START, EVENT_RESULT, EVENT_PROGRESS,
    EVENT_REPORT, EVENT_ERROR,
}
