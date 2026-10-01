# 桥梁结构监测与限行决策

融合传感、巡检、交通荷载和天气数据，生成限载限行或恢复建议。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8318
```

默认端口为`8318`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`

限行链（告警、现场核查、交通通告按现场单号 `order_no` 串联）：

- `POST /api/chain/alerts`：按现场单号登记告警
- `POST /api/chain/verifications`：按现场单号登记现场核查
- `POST /api/chain/notices`：按现场单号登记交通通告（可带 `valid_until` 有效期）
- `POST /api/chain/monitoring`：监测值变化后重算限行建议
- `GET /api/chain/recommendation?order_no=...`：查询当前限行建议及历史

断网处置（本地存草稿，回网与中心合并）：

- `POST /api/drafts`：断网时按 `request_no` 存本地草稿
- `GET /api/drafts`：列出草稿（可按 `status` 过滤）
- `POST /api/drafts/merge`：回网合并草稿；同单号两边都改过则置为 `pending_confirmation`，不覆盖中心通告
- `POST /api/drafts/resolve`：处理待确认草稿（`keep=center` 或 `keep=local`，通告禁止覆盖中心版本）
- `POST /api/notices/expire`：通告失效检测，失效后限行建议立即失效重算

幂等与审计：所有写入均携带 `request_no`，失败后按原编号重试即返回首次结果，不重复落库；状态变更与审计事件在同一事务内提交，审计链可通过 `GET /api/audit` 查询。

允许角色：sensor_operator, bridge_engineer, traffic_authority, viewer。监测偏差与预警阈值之比和多条异常记录决定告警等级；限行与封闭决策必须绑定交通通告记录。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
