# API 参考

AnyTLS Panel 提供三类接口，鉴权方式不同。接入前先确认使用的是正确类别。

## 鉴权方式

| 类别 | 接口 | 鉴权 | 稳定性 |
| --- | --- | --- | --- |
| 流量写入 API | `/api/traffic/*` | Bearer Token | 面向外部采集器，保持向后兼容 |
| 管理 JSON 接口 | 其他 `/api/*` | 管理员登录 Session；写操作还需要 CSRF | 主要供 Web 界面使用，可能随界面演进 |
| 公开订阅 | `/sub/<token>` | URL 中的用户服务 Token；旧账号 Token 继续兼容 | 面向订阅客户端 |

本文中的面板地址统一写作 `https://panel.example.com`，请替换为真实域名。

## 检查面板更新

`POST /api/updates/check` 需要管理员 Session 和 `X-CSRFToken`，无请求正文。返回 `current_version`、`status`、中文 `message`；查询成功还包含 `latest_version` 和官方 `release_url`。状态为 `available`、`current`、`ahead`、`unknown` 或 `error`，上游查询失败时返回 HTTP `503`，不会把失败当作“已是最新”。此接口仅检查版本；安装更新由服务器部署脚本执行。成功结果缓存 5 分钟，失败缓存 1 分钟。

## Bearer Token

部署会在面板服务器生成主 Token：

```text
/opt/anytls-panel/data/.traffic_api_token
```

主 Token 能写入所有账号，不能复制到节点。节点应使用账号级 Token：

```bash
sudo -u anytls-panel /opt/anytls-panel/venv/bin/python \
  /opt/anytls-panel/traffic_token.py 1
```

将末尾 `1` 换成真实账号 ID。账号级 Token 必须与请求中的同一个 `account_id` 配合使用。

所有流量接口使用：

```http
Authorization: Bearer <token>
Content-Type: application/json
```

每类流量接口默认限速为每分钟 60 次。超过限制时返回 HTTP `429`。

## 增量上报流量

`POST /api/traffic/report`

把本次新增字节数加到已有累计量。可提交一个对象或对象数组。

```bash
curl --fail-with-body \
  -X POST https://panel.example.com/api/traffic/report \
  -H "Authorization: Bearer $TRAFFIC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id":1,"bytes_used":1073741824}'
```

成功响应：

```json
{
  "results": [
    {
      "account_id": 1,
      "status": "ok",
      "total_bytes": 3221225472
    }
  ]
}
```

重复发送同一个增量会重复累计。需要自动重试时应使用幂等累计计数接口。

## 幂等累计计数

`POST /api/traffic/counter`

上报某个采集器从启动计数以来的原始累计值。服务端保存上次值并只增加差额，网络重试不会重复记账；计数器重置后也会从新值继续累计。

```bash
curl --fail-with-body \
  -X POST https://panel.example.com/api/traffic/counter \
  -H "Authorization: Bearer $ACCOUNT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "collector_id":"node-hk-01-port-443",
    "account_id":1,
    "counter_bytes":1073741824
  }'
```

成功响应：

```json
{
  "account_id": 1,
  "delta_bytes": 1048576,
  "status": "ok",
  "total_bytes": 3221225472
}
```

`collector_id` 必须包含 8–128 个字母、数字、点、下划线、冒号或连字符，并且长期绑定同一个账号。首次上报只建立基线，`delta_bytes` 为 `0`。

## 周期内单调设置绝对值

`POST /api/traffic/set`

把账号在当前流量周期内的累计量提高到给定值，但不会降低同一周期已有总量。账号设置了到期日时，必须同时提交 `cycle_started_on`；它等于系统根据真实到期日日号推导出的本周期开始日。旧周期样本返回 HTTP `409`，不会覆盖新周期数据。

```bash
curl --fail-with-body \
  -X POST https://panel.example.com/api/traffic/set \
  -H "Authorization: Bearer $ACCOUNT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id":1,"total_bytes":5368709120,"cycle_started_on":"2026-08-24"}'
```

成功响应：

```json
{"status":"ok","total_bytes":5368709120}
```

没有设置账号到期日时无法推导月度周期，接口保持原有的单调绝对值行为。新采集器优先使用幂等累计计数接口 `/api/traffic/counter`。

## 兼容的密码定位

主 Token 可以用节点密码替代 `account_id`：

```json
{"password":"节点密码","bytes_used":1024}
```

这只是兼容模式。如果相同密码出现在多个账号中，服务端返回 HTTP `409`。新接入应始终使用账号 ID 和账号级 Token。

## 常见错误

| 状态码 | 含义 | 建议处理 |
| --- | --- | --- |
| `400` | JSON、字段、整数或采集器 ID 无效 | 修正请求，不要原样重试 |
| `401` | Token 缺失或错误 | 检查 Token 来源和 Authorization 头 |
| `404` | 账号不存在或分享 Token 已失效 | 刷新账号 ID或重新生成分享链接 |
| `409` | 密码对应多个账号、采集器 ID 已绑定其他账号，或绝对流量样本属于旧周期 | 改用明确账号 ID、新采集器 ID，或刷新当前流量周期 |
| `413` | 请求体或批量项目超过上限 | 拆分请求 |
| `429` | 请求过于频繁 | 按退避策略稍后重试 |

客户端应记录 HTTP 状态码和响应中的 `error`，但不得把 Token、密码或完整订阅 URL 写入日志。

## 管理 JSON 接口

以下接口要求先通过 `/login` 建立管理员 Session：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| `GET` | `/api/accounts` | 获取账号列表 |
| `GET` | `/api/accounts/<id>/nodes` | 获取账号节点 |
| `POST` | `/api/check-by-host` | 检测给定主机和端口 |
| `POST` | `/api/nodes/<id>/check` | 检测一个已保存节点 |
| `POST` | `/api/accounts/<id>/check-all` | 批量检测账号节点 |
| `POST` | `/api/sync-all` | 同步全部活跃账号 |
| `GET` | `/api/subscribe` | 获取全部活跃账号的原始节点链接 |
| `POST` | `/api/accounts/<id>/generate-token` | 轮换账号分享 Token |

这些接口会返回订阅或节点敏感信息，不能通过未受信任的反向代理公开给第三方应用。写操作还要求页面生成的 CSRF Token；不建议把管理员 Session 当作长期自动化凭据。

## 公开订阅

`GET /sub/<token>` 不需要管理员 Session。普通客户端得到 Base64 内容；User-Agent 包含 `Clash` 时得到 Clash YAML。客户端中的订阅名称统一显示为 `SSRVPN.VIP`，不会暴露面板账号名。账号被停用、删除或 Token 轮换后，旧链接返回 `404`。

分享响应不再输出 `Subscription-Userinfo`，不会附带上传量、下载量、总配额或到期日期。该规则同时适用于账号分享和用户独立订阅、Base64 与 Clash YAML。后台仍保存这些数据，用户服务的开始日、到期日与暂停/停用检查继续生效。

公开订阅 URL 本身就是凭据：

- 只通过 HTTPS 传输；
- 不放在公开 Issue、日志、截图或分析平台中；
- 怀疑泄露时在账号详情中重新生成；
- 上游同步失败时，接口继续读取最后一次成功保存的节点，不会在公开请求中即时访问上游。
