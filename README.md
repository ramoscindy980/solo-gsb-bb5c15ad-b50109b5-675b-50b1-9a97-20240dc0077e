# JSON Redaction API

基于 FastAPI 的 JSON 结构脱敏服务。`POST /redact` 接收任意 JSON 文档与一组规则，
返回脱敏后的文档以及完整的审计轨迹。

## 快速启动

```bash
docker compose up --build
```

服务监听 **8080** 端口。也可以本地运行：

```bash
pip install -r requirements.txt
REDACT_SALT=my-secret uvicorn app.main:app --port 8080
```

## 接口

### `POST /redact`

请求体：

```json
{
  "data": { "任意": "JSON 文档" },
  "rules": [
    { "path": "/users/*/password", "action": "mask" },
    { "path": "/users/**/ssn", "action": "sha256" },
    { "path": "/debug", "action": "remove" }
  ]
}
```

响应体：

```json
{
  "redacted": { "脱敏后的": "文档" },
  "audit": [
    {
      "pointer": "/users/0/password",
      "rule": "/users/*/password",
      "rule_index": 0,
      "action": "mask",
      "applied": true
    }
  ]
}
```

审计轨迹按原始文档的遍历顺序排列；`pointer` 为命中节点在**原始结构**中的
JSON Pointer。当某节点的祖先已被其他规则消费（remove/mask/sha256）时，该条目的
`applied` 为 `false`。

### `GET /health`

健康检查，返回 `{"status": "ok"}`。

## 规则路径语法

规则路径是 [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901) JSON Pointer
（`~0` 转义 `~`，`~1` 转义 `/`，空字符串 `""` 指向文档根），并扩展两个通配符：

| 段     | 含义                                   |
| ------ | -------------------------------------- |
| `*`    | 匹配恰好一层（对象键或数组下标）       |
| `**`   | 匹配零层或任意多层                     |

数组下标用字面数字匹配（如 `/items/0`）。`*` 与 `**` 为保留段，无法匹配字面就叫
`*` 的键。

## 动作

| 动作     | 行为                                                                 |
| -------- | -------------------------------------------------------------------- |
| `mask`   | 将节点整体替换为 `"***"`                                             |
| `remove` | 从父对象/数组中删除该节点                                            |
| `sha256` | 替换为 `sha256(salt + value)` 的十六进制摘要；非字符串值先按规范 JSON（键排序、紧凑分隔符）序列化 |

## 多规则命中同一节点时的裁决

依次比较，选出唯一获胜规则：

1. **字面段更多**的规则优先；
2. **通配段更少**的规则优先；
3. **声明顺序更后**（在 `rules` 数组中下标更大）的规则优先。

## 匹配语义

- 所有匹配均针对**原始文档**计算，先收集全部命中，再统一应用。
- 删除数组元素不会使后续指针错位：审计中的指针始终指向原始下标。
- 若某节点被 remove/mask/sha256，其子树中命中的其他规则不再生效
  （审计中标记 `applied: false`）。

## 配置

| 环境变量      | 说明                                       | 默认值            |
| ------------- | ------------------------------------------ | ----------------- |
| `REDACT_SALT` | sha256 动作的哈希盐                        | 空字符串（Compose 中为 `dev-only-salt`，可用同名环境变量或 `.env` 文件覆盖） |

生产环境务必设置强随机盐：`REDACT_SALT=$(openssl rand -hex 32) docker compose up --build`

## 示例

```bash
curl -s http://localhost:8080/redact -H 'Content-Type: application/json' -d '{
  "data": {
    "users": [
      {"name": "amy", "password": "pw1", "ssn": "111-22-3333"},
      {"name": "bob", "password": "pw2", "ssn": "444-55-6666"}
    ],
    "debug": {"trace": true}
  },
  "rules": [
    {"path": "/users/*/password", "action": "mask"},
    {"path": "/users/**/ssn", "action": "sha256"},
    {"path": "/debug", "action": "remove"}
  ]
}' | jq
```

## 测试

```bash
pip install -r requirements-dev.txt
pytest
```

## 项目结构

```
app/
  main.py       # FastAPI 入口与请求/响应模型
  redactor.py   # 脱敏引擎：指针解析、通配匹配、优先级裁决、审计
tests/          # pytest 单元测试与 API 测试
Dockerfile
docker-compose.yml
requirements.txt / requirements-dev.txt
```
