# 桥梁结构监测与限行决策

融合传感、巡检、交通荷载和天气数据，生成限载限行或恢复建议。系统按**现场单号**串联桥梁告警、现场核查和交通通告，支持断网草稿、回网合并、冲突留档和审计追溯。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限、关闭不变量和限行建议重算规则。
- `src/repository.py`：SQLite建表、事务、版本控制、建议、冲突和审计链。
- `src/local_draft.py`：断网本地草稿文件，原子写入并保留失败请求。
- `src/service.py`：权限检查、用例编排、幂等重试、离线合并和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则、失败和限行链测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --draft-file ./local_drafts.json --port 8318
```

默认端口为`8318`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

角色：`sensor_operator`、`bridge_engineer`、`traffic_authority`、`duty_officer`、`viewer`。

## 限行链接口

- `POST /api/cases`：值班员按现场单号登记告警、核查和通告。三类事实分开保存，默认编号为：
  - `{ticket_no}-ALARM`
  - `{ticket_no}-INSPECTION`
  - `{ticket_no}-TRAFFIC_NOTICE`
- `GET /api/items/{id}/recommendation`：读取当前限行建议；读取时会自动处理已到期通告。
- `POST /api/items/{id}/measurement`：提交监测值，必须带`expected_version`。
- `POST /api/records/{id}/reopen`：现场核查重开。
- `POST /api/records/{id}/expire`：交通通告失效。
- `GET /api/recommendations`：查看建议历史。
- `GET /api/conflicts`：查看合并冲突；`POST /api/conflicts/{id}/resolve`确认。
- `POST /api/drafts`：断网保存本地草稿。
- `GET /api/drafts`：查看未完成草稿。
- `POST /api/drafts/{request_id}/retry`：按原请求编号重试。
- `POST /api/drafts/sync`：回网后依次合并所有草稿。
- `GET /api/audit`：查看哈希链审计。

原有接口仍保留：`GET /health`、`GET /api/items`、`POST /api/items`、
`GET /api/items/{id}`、`POST /api/items/{id}/records`、
`POST /api/items/{id}/transition`。

## 请求编号和断网合并

所有写请求都应提交`request_id`。中心用请求编号保存操作指纹和结果：

- 同一编号、同一请求重放：返回原结果，不重复改变状态。
- 同一编号、不同请求：返回`409 Conflict`，不能覆盖原请求。
- 断网时：只写`local_drafts.json`，不改变中心数据。
- 写入失败：事务整体回滚，草稿保持`pending/retrying`，错误落记录，后续按原编号重试。
- 同单号两边都改过：中心通告不覆盖；中心副本和本地草稿各留一份，状态为冲突待确认。
- 交通通告任何回网更新都不会覆盖中心通告，需人工确认后另行处置。

## 建议失效和重算

以下事件会立即让旧建议失效并生成新建议，审计同时记录失效与重算：

1. 交通通告失效或到达`valid_until`；
2. 现场核查关闭后重开；
3. 监测严重度、监测值或阈值变化；
4. 告警、核查、通告事实发生合并。

当前建议以`basis_hash`标识输入事实；读取建议时返回`valid=false`表示中心事实已变化但尚未刷新。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
