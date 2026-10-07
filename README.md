# 委托能力链验证 API（Delegation Capability Chain）

客户端提交一条**根授权**和若干以 `parent_id` 相连的**委托令牌（capability token）**。
服务端完成：

1. **HMAC-SHA256 验签** —— 对规范化 JSON 报文验签（每主体独立密钥，按代次管理）；
2. **签发者检查** —— 根授权必须由配置的根主体签发；委托令牌的 `issuer` 必须等于父令牌的 `subject`；
3. **结构检查** —— 断链、重复 id、多根、分叉、环、与根不可达；
4. **逐级收窄** —— 子令牌的路径模式、HTTP 方法集合、时间窗、`allow_ip` CIDR 只能比父令牌更窄；
5. **请求级判定** —— 给定请求路径、方法、时间、来源 IP 与请求主体，返回 `allow` / `deny`、首个失败节点和完整验证轨迹；
6. **按时间生效的撤销审计** —— 运维方可对链上任一令牌追加**不可变撤销事件**（含生效时间、原因、幂等键），
   求值按请求时间解释事件：生效后该节点及其后代一律拒绝，生效前的历史请求仍按原链判定；
7. **一次性访问核销** —— 对已提交链的**末端令牌**执行一次性核销：以服务端接收时刻重算全部判定，
   仅在末端且允许时记录核销；同一令牌只能成功核销一次（并发仅一笔成功），
   `request_key` 成功重放返回首次结果（即使令牌随后过期 / 被撤销），换内容冲突；
   判定拒绝与目标不符均不核销、不占用 `request_key`；
8. **双主体会签核销** —— 一次访问需**主授权链**与**复核链**两条不同链的末端（subject 也必须不同）
   在**同一 SQLite 写事务**、**同一服务器时间**下分别按各自提交时锁定的密钥归属验签，
   并检查撤销 / 权限 / 已核销状态：两侧都允许且未核销才同时记入核销（共同核销时间，
   返回两份判定轨迹）；任一侧拒绝或已核销时另一侧不被消耗；同键同内容重放返回首次会签结果；
9. **HMAC 密钥轮换** —— 签发主体的密钥按**代次**管理：注册为第 1 代，每次轮换原子地追加一代并切换当前代。
   轮换后新提交的链只按新密钥验签；每条链在提交时锁定各签发主体的密钥代次，
   轮换前保存的链在链查询、只读求值与首次核销中继续按锁定代次的密钥重验，结论不变；
10. **提交时未注册签发者的结论冻结** —— 提交时签发者未注册（`unknown_issuer`）的链，
   把“缺失密钥”这一事实随链持久化：事后注册该主体、甚至轮换到匹配旧签名的密钥，
   链查询 / 重放 / 求值 / 首次核销都保持提交时的拒绝结论，永不翻转；
11. **撤销影响清单** —— 撤销追溯到已完成访问之前时，列出受影响的访问：事件写入时在
   **同一 SQLite 事务**内找出核销时间不早于 `effective_at`、早于事件写入时间，且末端
   令牌为撤销目标或其后代的成功核销（单链核销与双链会签均纳入；一笔会签只列一次，
   注明受影响的链与主授权 / 复核侧），随事件一并保存、之后不可变；可按撤销
   `request_key` 查询清单，原核销记录不做任何改写；
12. **疑似失陷密钥停用** —— 运维方可按**主体名 + 密钥代次**停用疑似失陷的签发密钥
    （记录原因，立即生效、不可撤销，后续轮换只追加新一代、**不解除**旧代次停用）。
    已提交且绑定该代次的链，在后续只读求值、首次单链核销与双链会签中一律从
    **对应签发节点**拒绝（轨迹 `key_active` 标出 `key_deactivated` 及原因）；
    只读求值把 `at` 指定到停用之前的过去时刻也不能绕过；会签一侧拒绝时另一侧不被消耗。
    停用当前代次时，新提交链仍保存原代次归属与拒绝结论，同内容重放返回原完整性结论；
    轮换后用新代次签发的链可正常验签 / 核销，历史链的原提交报告与已完成核销记录
    不改写，已成功核销的同键同内容重放仍返回首次结果。停用与链提交 / 核销并发时，
    归属与判定对应同一份已提交状态。
13. **链末端 subject 的跨链核销额度** —— 运维方可为**链末端 subject** 设置 / 调整
    成功核销**总额度**（未设置 = 不限额），并查询额度、已用量与剩余量。已用量 =
    该主体在全部链上的**成功单链核销**数 + **会签中该主体参与的一侧**的次数
    （每次算一次，含额度设置之前的历史成功核销）。余额检查在既有授权判定 / 撤销 /
    密钥停用检查**全部通过之后**才进行：单链余额不足明确拒绝且不占用 `request_key`；
    会签任一主体余额不足则**两侧均不核销、不占键**。额度可随时调高，调低不得低于
    已用量；并发核销与额度调整以 `BEGIN IMMEDIATE` 串行化、不会超发；失败不计数；
    追溯撤销 / 停用密钥不退还历史用量；成功请求同键重放保留首次结果且不重复计数。
    额度行与只追加的核销记录共同持久化，重启后口径不变。
14. **短时额度预留** —— 为一次单链访问预先**占一份额度**（有效秒数 1～300，
    到期自动释放）：提交 `chain_id`、末端 `token_id`、路径、方法、来源 IP、请求体、
    预留键与有效秒数，仅在**主体已设额度、授权允许、令牌未核销且可用量充足**时
    占一份并返回到期时间。同键同内容重放原预留，换内容冲突，失败不占键；
    **同一令牌只能有一笔有效预留**。额度查询区分**历史已用 / 有效预留 / 可用量**
    （`available = limit - used - reserved`）；普通单链核销与会签**不得占用**
    预留份额与被预留的令牌，调低额度不得侵占预留，过期自动释放。
    单链核销可携带预留键：链、令牌与访问内容匹配且未过期时才使用该份额，
    并重新检查验签 / 撤销 / 密钥停用 / 权限，成功则在同一事务内把预留转为已用。

相同 `chain_id` 的重放**幂等**（返回 200 + `replayed=true`）；相同 `chain_id` 内容变化返回 **409 Conflict**。
撤销与核销同样按 `request_key` 幂等：同键同内容重放原结果，同键换目标/内容返回 **409 Conflict**。

技术栈：Python · FastAPI · Pydantic v2 · SQLite（标准库 `sqlite3`）· Uvicorn。

---

## 一条命令启动

```bash
docker compose up --build
```

- API：<http://localhost:8000>
- 交互式文档（Swagger UI）：<http://localhost:8000/docs>
- 健康检查：<http://localhost:8000/health>
- SQLite 数据持久化在命名卷 `chain-data`（容器内 `/data/capabilities.db`）。

停止：`Ctrl+C`；清空数据重来：`docker compose down -v`。

本地裸跑（无需 Docker）：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 快速演示

容器启动后会自动播种演示主体（可通过 `SEED_DEMO_PRINCIPALS=false` 关闭）：

| 主体        | HMAC 密钥（仅演示，生产请覆盖）         |
| ----------- | --------------------------------------- |
| `root`      | 环境变量 `ROOT_HMAC_SECRET`（见 compose）|
| `service-a` | `demo-secret-service-a`                 |
| `service-b` | `demo-secret-service-b`                 |
| `alice`     | `demo-secret-alice`                     |

用随仓库附带的脚本生成一条已签名的合法链（`root → service-a → service-b`）、
提交、幂等重放、求值，对链末端执行一次性核销（含重放与重复核销冲突），
再追加一条撤销并演示“生效后拒绝 / 生效前仍按原链判定”（需要本地 Python 3.10+）：

```bash
# 只打印已签名的提交报文
PYTHONPATH=. python scripts/demo_chain.py print

# 提交 + 重放 + 求值（默认 http://127.0.0.1:8000，可用 BASE_URL 覆盖）
PYTHONPATH=. python scripts/demo_chain.py submit
```

---

## 数据模型

### 令牌 `CapabilityToken`

| 字段          | 类型                | 说明                                                                 |
| ------------- | ------------------- | -------------------------------------------------------------------- |
| `token_id`    | string              | 令牌唯一标识                                                         |
| `parent_id`   | string \| null      | 父令牌 id；根授权为 `null`                                           |
| `chain_id`    | string              | 所属能力链 id（提交体内所有令牌必须一致）                            |
| `issuer`      | string              | 签发主体；需事先注册其 HMAC 密钥                                     |
| `subject`     | string              | 被授权主体                                                           |
| `path_pattern`| string              | 资源路径 glob，以 `/` 开头；`*` 匹配单段，`**` 只能作末段（含 0 段）  |
| `methods`     | string[]            | 允许的 HTTP 方法（自动去重并转大写，至少 1 个）                      |
| `not_before`  | date-time           | 生效时间，**必须携带时区**（如 `...Z`）                              |
| `not_after`   | date-time           | 失效时间（严格晚于 `not_before`）                                    |
| `allow_ip`    | string \| null      | 可选 CIDR，如 `10.0.0.0/8`；必须是规范网络地址                       |
| `signature`   | string              | 64 位十六进制 HMAC-SHA256                                            |

### 提交体 `ChainSubmission`

```json
{ "chain_id": "demo-chain-0001", "tokens": [ { ...根令牌... }, { ...委托令牌... } ] }
```

### 求值请求 `EvaluateRequest`

| 字段           | 必填 | 说明                                         |
| -------------- | ---- | -------------------------------------------- |
| `request_path` | 是   | 实际请求路径                                 |
| `method`       | 是   | 实际 HTTP 方法（大小写不敏感）               |
| `at`           | 是   | 请求时间，必须携带时区                       |
| `source_ip`    | 否   | 链上任一令牌含 `allow_ip` 时需要提供         |
| `body`         | 否   | 任意 JSON；服务不据其授权，只记录 SHA-256 指纹到轨迹 |

### 撤销请求 `RevocationRequest`

`POST /api/v1/chains/{chain_id}/revocations`（`chain_id` 取自 URL 路径）：

| 字段           | 必填 | 说明                                              |
| -------------- | ---- | ------------------------------------------------- |
| `token_id`     | 是   | 被撤销的令牌；必须已存在于该链                    |
| `effective_at` | 是   | 撤销生效时间，必须携带时区；可指向未来（到期才解释） |
| `reason`       | 是   | 撤销原因（审计说明，非空）                        |
| `request_key`  | 是   | 客户端幂等键；同键内容必须一致，且**全局唯一**    |

### 核销请求 `RedeemRequest`

`POST /api/v1/chains/{chain_id}/redeem`（`chain_id` 取自 URL 路径）：

| 字段              | 必填 | 说明                                              |
| ----------------- | ---- | ------------------------------------------------- |
| `token_id`        | 是   | 被核销令牌；**必须为链末端**（唯一根→唯一子链的最后一个令牌） |
| `request_key`     | 是   | 客户端幂等键；同键内容必须一致，且**全局唯一**（仅成功核销占用） |
| `request_path`    | 是   | 实际请求路径                                      |
| `method`          | 是   | 实际 HTTP 方法（大小写不敏感）                    |
| `source_ip`       | 否   | 链上任一令牌含 `allow_ip` 时需要提供              |
| `body`            | 否   | 任意 JSON；服务只记录 SHA-256 指纹到轨迹，正文随核销记录留档 |
| `reservation_key` | 否   | 事先预留额度的预留键；提供后即成为核销内容的一部分（参与内容指纹） |

> 核销请求**不提供时间**：判定时间固定为服务端接收该请求的时刻（UTC）。

### 预留请求 `ReserveRequest`

`POST /api/v1/chains/{chain_id}/reservations`（`chain_id` 取自 URL 路径）：

| 字段              | 必填 | 说明                                              |
| ----------------- | ---- | ------------------------------------------------- |
| `token_id`        | 是   | 预留针对的令牌；**必须为链末端**                  |
| `reservation_key` | 是   | 客户端幂等键；同键内容必须一致（仅有效预留占用）  |
| `ttl_seconds`     | 是   | 预留有效秒数，**1～300**；到期自动释放            |
| `request_path`    | 是   | 计划访问的资源路径（核销时须一致）                |
| `method`          | 是   | 计划使用的 HTTP 方法（大小写不敏感）              |
| `source_ip`       | 否   | 计划访问的来源 IP（核销时须一致）                 |
| `body`            | 否   | 计划提交的请求体（核销时须一致）                  |

> 预留请求同样**不提供时间**：判定时间与到期起算点均为服务端接收时刻（UTC），
> 到期时间 `expires_at = 接收时刻 + ttl_seconds`。

### 会签请求 `CoRedeemRequest`

`POST /api/v1/co-redemptions`（两条链都放在请求体内，共享同一份请求上下文）：

| 字段              | 必填 | 说明                                                        |
| ----------------- | ---- | ----------------------------------------------------------- |
| `primary`         | 是   | `{"chain_id", "token_id"}`：主授权链及其**末端**令牌        |
| `review`          | 是   | `{"chain_id", "token_id"}`：复核链及其**末端**令牌          |
| `request_key`     | 是   | 客户端幂等键；同键内容必须一致，与单链核销**同一键空间**（仅成功会签占用） |
| `request_path`    | 是   | 实际请求路径（两侧共用）                                    |
| `method`          | 是   | 实际 HTTP 方法（大小写不敏感，两侧共用）                    |
| `source_ip`       | 否   | 任一链上任一令牌含 `allow_ip` 时需要提供                    |
| `body`            | 否   | 任意 JSON；服务只记录 SHA-256 指纹到轨迹，正文随核销记录留档 |

> 两条链的 `chain_id` 必须不同（422），两条链末端令牌的 `subject` 也必须不同（409）——
> 会签要求主授权与复核为**不同主体**。判定时间同样固定为服务端接收时刻（UTC），两侧共用。

---

## HTTP 接口

### `POST /api/v1/principals`

注册签发主体及其 HMAC 密钥（演示 / 引导用；生产建议关闭播种后自行注册）。

```json
{ "name": "service-a", "hmac_secret": "s3cr3t" }
```

- `201` 注册成功（密钥安装为第 1 代）；`409` 主体已存在。

### `POST /api/v1/principals/{name}/rotate-key`

轮换已注册主体的 HMAC 密钥（`name` 取自 URL 路径）：

```bash
curl -sS -X POST http://localhost:8000/api/v1/principals/service-a/rotate-key \
  -H 'Content-Type: application/json' \
  -d '{"hmac_secret": "s3cr3t-v2"}'
```

```json
{ "name": "service-a", "generation": 2, "rotated_at": "2026-10-04T09:00:00+00:00" }
```

- `200 OK`：新一代密钥已**原子**安装并切换为当前代，响应含新代次与轮换时间（**不回显密钥**）；
- `404 Not Found`：主体未注册；
- `409 Conflict`：新密钥与当前密钥相同（未执行任何切换）；
- `422`：请求体校验失败（如空密钥）。

**轮换语义（代次模型）**：

- 密钥按代次管理：注册为第 1 代，每次轮换 `+1`；全部代次**只追加、永不修改或删除**；
- 轮换后**新提交**的链只按当前（新）密钥验签——用旧密钥签出的新链得到 `bad_signature`；
- 每条链在**提交时**锁定各签发主体的密钥代次并随链持久化；轮换前保存的链在
  **链查询、只读求值、首次核销**中继续按锁定代次的密钥重验，验签结论与轮换前一致，
  撤销事件照常按请求时间解释；既有**无效**链不会因为新密钥恰好匹配而翻转为有效；
- 轮换与链提交并发交错时，链记录的密钥代次严格等于提交时实际验签所用的代次；
- 轮换在单个 `BEGIN IMMEDIATE` 事务内完成：失败（404 / 409 / 写冲突）不会留下部分切换；
- 已核销请求的同键同内容重放仍返回首次结果（与轮换无关）；任何响应都不携带密钥材料。

轮换前后的完整可执行示例（签名 → 提交 → 求值 → 核销）见下文
[密钥轮换演练](#密钥轮换演练轮换前后签名求值与核销)。

### `POST /api/v1/principals/{name}/generations/{generation}/deactivate-key`

疑似签发密钥失陷时，按**主体名 + 密钥代次**停用该代密钥（`name` / `generation`
均取自 URL 路径；注册为第 1 代，每次轮换 +1）：

```bash
curl -sS -X POST \
  http://localhost:8000/api/v1/principals/service-a/generations/1/deactivate-key \
  -H 'Content-Type: application/json' \
  -d '{"reason": "运维安全事件：疑似密钥失陷，立即停用第 1 代"}'
```

```json
{
  "replayed": false,
  "event": {
    "principal": "service-a",
    "generation": 1,
    "reason": "运维安全事件：疑似密钥失陷，立即停用第 1 代",
    "deactivated_at": "2026-10-06T09:00:00+00:00"
  }
}
```

请求体只有一个字段：

| 字段     | 必填 | 说明                                   |
| -------- | ---- | -------------------------------------- |
| `reason` | 是   | 停用原因（审计说明，非空），随事件冻结 |

- `201 Created`：新停用事件已落库，**立即生效、不可撤销**；
- `200 OK`：同一（主体, 代次）以**相同原因**重复调用，`replayed=true`，返回原事件；
- `409 Conflict`：该代次已停用但本次原因不同（停用原因不可改写）；
- `404 Not Found`：主体未注册，或主体不存在该代次密钥；
- `422`：代次非正整数、原因为空等输入校验失败。

**停用语义（与轮换 / 撤销的区别）**：

- 停用是**只追加、不可撤销**的审计动作：不删除任何密钥材料，也没有解除接口；
  后续轮换只是原子地追加新一代密钥并切换当前代，**绝不解除**旧代次的停用；
- 已提交链在提交时锁定了各签发主体的密钥代次。停用命中链上某个（主体, 代次）后，
  该链在后续**只读求值、首次单链核销、双链会签**中一律从**对应签发节点**拒绝
  （轨迹中该节点的 `key_active` 检查失败，reason 为 `key_deactivated`，
  detail 注明代次与停用原因；同一节点的 HMAC `signature` 检查仍可能通过）；
- 停用**与请求时间无关**（不同于按 `at` 解释的撤销）：只读求值即使把 `at`
  指定到停用之前的过去时刻，命中停用的节点仍拒绝，`first_failed_reason`
  为 `key_deactivated`；
- 双链会签中任一侧命中停用：该侧拒绝、另一侧照常判定但**不被消耗**
  （两侧都不核销、不占用 `request_key`）；
- 停用的若是**当前代次**：此后用该代密钥签出的新链**仍提交、仍持久化**，
  并保存原代次归属（归属表记录的仍是提交时的当前代次），提交报告即以
  `key_deactivated` 拒绝；同内容重放返回原完整性结论；
- 轮换后用**新代次**密钥签发的链可正常验签、求值与核销；被停用旧代次绑定的
  历史链继续拒绝；历史链的**原提交报告**（链查询中的 `integrity`）与
  **已完成的核销 / 会签记录不改写**，已成功核销的同键同内容重放仍返回首次结果；
- 停用在单个 `BEGIN IMMEDIATE` 事务内完成，与链提交、核销、会签串行化：
  并发交错时，链的代次归属与停用判定严格对应同一份已提交状态
  （提交早于停用：提交报告仍 allow、停用后实时求值拒绝；提交晚于停用：提交报告即拒绝）；
- 任何响应都不携带密钥材料。

停用前后、轮换之后的完整可执行示例（签名 → 提交 → 停用 → 求值 / 核销 / 会签 →
轮换 → 新代次链）见下文
[密钥停用演练](#密钥停用演练停用前后轮换后的求值核销与会签)。

### `POST /api/v1/chains`

提交一条能力链。

- `201 Created`：新 `chain_id`，已持久化（**完整性失败也会持久化**，含失败轨迹，便于审计）；
- `200 OK`：相同 `chain_id` 且内容逐字节等价（规范化后 SHA-256 相同），`replayed=true`；
- `409 Conflict`：相同 `chain_id` 但内容不同，响应体给出双方哈希：

```json
{
  "detail": {
    "detail": "chain_id='x' 已存在但内容不同；相同 chain_id 不允许提交不同内容",
    "chain_id": "x",
    "existing_sha256": "…",
    "received_sha256": "…"
  }
}
```

响应中的 `integrity` 字段：

```json
{
  "allow": true,
  "first_failed_node": null,
  "first_failed_reason": null,
  "ordered_token_ids": ["token-root", "token-a", "token-b"],
  "trace": [
    {
      "token_id": "token-a",
      "issuer": "service-a",
      "subject": "service-b",
      "parent_id": "token-root",
      "is_root": false,
      "checks": [
        { "name": "signature", "passed": true, "detail": "HMAC-SHA256 验签通过", "reason": null },
        { "name": "issuer_chain", "passed": true, "detail": "…", "reason": null },
        { "name": "path_narrows", "passed": true, "detail": "…", "reason": null },
        { "name": "methods_narrow", "passed": true, "detail": "…", "reason": null },
        { "name": "time_window_narrows", "passed": true, "detail": "…", "reason": null },
        { "name": "ip_range_narrows", "passed": true, "detail": "…", "reason": null }
      ]
    }
  ]
}
```

### `GET /api/v1/chains/{chain_id}`

返回存储的链：令牌列表、内容哈希、创建时间、提交时的完整性报告，以及按追加顺序排列的
**撤销事件列表** `revocations` 与**成功核销记录列表** `redemptions`（从未发生时均为 `[]`）；
不存在返回 `404`。

```json
{
  "chain_id": "demo-chain-0001",
  "content_sha256": "…",
  "created_at": "2026-10-01T00:00:00+00:00",
  "integrity": { /* 与提交时一致的完整性报告 */ },
  "tokens": [ /* …令牌… */ ],
  "revocations": [
    {
      "chain_id": "demo-chain-0001",
      "token_id": "token-a",
      "effective_at": "2026-10-01T12:00:00+00:00",
      "reason": "运维安全事件：疑似密钥泄露",
      "request_key": "ops-revoke-2026-0001",
      "content_sha256": "…",
      "created_at": "2026-10-01T09:30:00+00:00"
    }
  ],
  "redemptions": [
    {
      "chain_id": "demo-chain-0001",
      "token_id": "token-b",
      "request_key": "access-redeem-2026-0001",
      "request_path": "/files/reports/2026/q1.pdf",
      "method": "GET",
      "source_ip": "10.1.2.3",
      "request_body": { "q": "demo" },
      "content_sha256": "…",
      "evaluated_at": "2026-10-01T09:00:00+00:00",
      "redeemed_at": "2026-10-01T09:00:00+00:00",
      "created_at": "2026-10-01T09:00:00+00:00"
    }
  ]
}
```

### `POST /api/v1/chains/{chain_id}/revocations`

在**同一 SQLite 事务**（`BEGIN IMMEDIATE`）内确认 `token_id` 存在于该链、追加一条
不可变撤销事件，并**同事务算出该事件的影响清单**（见
`GET /api/v1/revocations/{request_key}/impacts`）随事件一并保存。

```bash
curl -sS -X POST http://localhost:8000/api/v1/chains/demo-chain-0001/revocations \
  -H 'Content-Type: application/json' \
  -d '{
    "token_id": "token-a",
    "effective_at": "2026-10-01T12:00:00Z",
    "reason": "运维安全事件：疑似密钥泄露",
    "request_key": "ops-revoke-2026-0001"
  }'
```

- `201 Created`：新事件已落库；
- `200 OK`：相同 `request_key` 且内容逐字节等价（规范化 SHA-256 相同），`replayed=true`，返回**原事件与原结果**；
- `409 Conflict`：
  - 相同 `request_key` 但更换了目标令牌 / 生效时间 / 原因（即使指向另一条链）；
  - 目标令牌此前已被撤销（`已撤销令牌不得重复生效`，即便换 `request_key`）；
- `404 Not Found`：链不存在，或令牌不属于该链；
- `422`：`effective_at` 未携带时区等输入校验失败。

`201` / `200` 响应体：

```json
{
  "replayed": false,
  "event": {
    "chain_id": "demo-chain-0001",
    "token_id": "token-a",
    "effective_at": "2026-10-01T12:00:00+00:00",
    "reason": "运维安全事件：疑似密钥泄露",
    "request_key": "ops-revoke-2026-0001",
    "content_sha256": "…",
    "created_at": "2026-10-01T09:30:00+00:00"
  },
  "affected_token_ids": ["token-a", "token-b"]
}
```

`affected_token_ids` 为被撤销节点**自身及其全部后代**，按原链根→叶顺序列出
（上例中 `token-b` 是 `token-a` 的下游委托，故一并失效）。

撤销事件**只追加、不可变**：服务不提供修改或删除接口；数据库层以
`request_key UNIQUE` 与 `(chain_id, token_id) UNIQUE` 双重约束兜底并发。

### `GET /api/v1/revocations/{request_key}/impacts`

按撤销 `request_key` 查询该事件写入时保存的**影响清单**——撤销追溯到已完成访问
之前时，哪些成功核销被命中。清单在事件写入的**同一 SQLite 事务**内计算并随事件
保存，之后不可变，命中条件：

- 核销时间 `redeemed_at` 不早于撤销 `effective_at`，且早于事件写入时间
  （`created_at`）——即访问完成时撤销尚未登记，但生效时间已覆盖该访问；
- 被核销的**末端令牌**是撤销目标或其后代（与响应中的 `affected_token_ids` 同集合）；
- **单链核销与双链会签均纳入**：一笔会签只列一次，以 `kind="co"` 与
  `side`（`primary` 主授权 / `review` 复核）注明受影响的链与侧；单链核销为
  `kind="single"`、`side=null`；
- 清单只是原核销记录的投影：**不改写** `redemptions` / 会签记录，链查询、求值与
  成功核销的同键重放结论保持原样。

```bash
curl -sS http://localhost:8000/api/v1/revocations/ops-revoke-2026-0001/impacts
```

```json
{
  "request_key": "ops-revoke-2026-0001",
  "chain_id": "demo-chain-0001",
  "token_id": "token-a",
  "effective_at": "2026-10-01T12:00:00+00:00",
  "impacts": [
    {
      "request_key": "access-redeem-2026-0001",
      "chain_id": "demo-chain-0001",
      "token_id": "token-b",
      "kind": "single",
      "side": null,
      "redeemed_at": "2026-10-01T12:30:00+00:00"
    }
  ]
}
```

- `200 OK`：`impacts` 按（核销时间, 访问 `request_key`）升序；无命中返回空清单 `[]`；
- `404 Not Found`：该 `request_key` 的撤销事件不存在（含撤销失败未落库的情形——
  撤销失败不会留下清单）；
- 同键同内容的撤销重放（`200`、`replayed=true`）不重复写入清单。

下面是一套**可直接复制执行**的演练（前提：服务运行在 `http://localhost:8000`，
仓库根目录，本地 Python 3.10+；签名复用 `app.security`）：

```bash
# 签名助手：生成 root -> service-a -> service-b 的三级链（时间窗覆盖当前时刻）
PYTHONPATH=. python3 - <<'PY' > /tmp/impact-chain.json
import json
from datetime import datetime, timedelta, timezone
from app.security import compute_signature

chain_id = "impact-demo-0001"
root_secret = "dev-root-secret-change-me"   # 对应 compose 中 ROOT_HMAC_SECRET
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")

def token(tid, parent, iss, sub, path, methods, secret):
    t = {
        "token_id": tid, "parent_id": parent, "chain_id": chain_id,
        "issuer": iss, "subject": sub, "path_pattern": path,
        "methods": methods, "not_before": nb, "not_after": na,
        "allow_ip": None, "signature": "",
    }
    t["signature"] = compute_signature(t, secret)
    return t

print(json.dumps({
    "chain_id": chain_id,
    "tokens": [
        token("imp-root", None, "root", "service-a",
              "/files/**", ["GET", "POST"], root_secret),
        token("imp-a", "imp-root", "service-a", "service-b",
              "/files/reports/*", ["GET"], "demo-secret-service-a"),
        token("imp-b", "imp-a", "service-b", "service-b",
              "/files/reports/q1.pdf", ["GET"], "demo-secret-service-b"),
    ],
}, ensure_ascii=False))
PY

# 1) 提交链
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/impact-chain.json
# → 201，"integrity": {"allow": true, ...}

# 2) 对链末端做一次性访问核销（判定时间 = 服务端接收时刻）
curl -sS -X POST http://localhost:8000/api/v1/chains/impact-demo-0001/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "imp-b", "request_key": "impact-access-0001",
       "request_path": "/files/reports/q1.pdf", "method": "GET"}'
# → 201，"redeemed": true

# 3) 追加一条生效时间早于该次访问的撤销（追溯到已完成访问之前）
curl -sS -X POST http://localhost:8000/api/v1/chains/impact-demo-0001/revocations \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "imp-a", "effective_at": "2026-01-01T00:00:00Z",
       "reason": "运维安全事件：疑似密钥泄露", "request_key": "impact-revoke-0001"}'
# → 201，"affected_token_ids": ["imp-a", "imp-b"]

# 4) 查询该撤销事件的影响清单：第 2 步的访问被列出
curl -sS http://localhost:8000/api/v1/revocations/impact-revoke-0001/impacts
# → 200，"impacts": [{"request_key": "impact-access-0001",
#      "chain_id": "impact-demo-0001", "token_id": "imp-b",
#      "kind": "single", "side": null, "redeemed_at": "..."}]

# 5) 不存在的撤销 request_key → 404
curl -sS -o /dev/null -w '%{http_code}\n' \
  http://localhost:8000/api/v1/revocations/no-such-key/impacts
# → 404
```

> 若第 3 步的 `effective_at` 改为晚于核销时间的未来时刻，第 4 步将返回空清单
> `"impacts": []`——生效前的访问不被追溯。会签被命中时条目为
> `"kind": "co"` 且 `"side": "primary"` 或 `"review"`（一笔会签只列一次）。
> 对应回归测试见 `tests/test_revocation_impacts.py`。

### `POST /api/v1/chains/{chain_id}/evaluate`

对已存链执行请求级判定（完整性检查每次实时重算）。返回：

```json
{
  "chain_id": "demo-chain-0001",
  "decision": "allow",
  "first_failed_node": null,
  "first_failed_reason": null,
  "body_sha256": "…",
  "first_revoked_node": null,
  "trace": [ /* 每个节点：完整性检查 + 请求级检查 */ ]
}
```

请求级检查项（按链上每个节点追加）：

| 检查名             | 失败原因                | 含义                          |
| ---------------- | -------------------------- | ----------------------------- |
| `revocation_active`| `revoked`                  | 请求时间点该节点自身（或其祖先）已被生效撤销 |
| `time_valid`     | `before_not_before` / `after_not_after` | 请求时间超出令牌有效期（边界含端点） |
| `method_allowed` | `method_not_allowed`       | 方法不在令牌方法集合          |
| `path_covered`   | `path_not_covered`         | 路径不匹配令牌 glob           |
| `ip_allowed`     | `ip_not_allowed`           | 来源 IP 不在 `allow_ip` 网段 |

#### 撤销如何参与求值

撤销按**请求时间 `at`** 解释，而非按事件提交时间：

- 仅当 `at >= effective_at` 时事件生效；生效事件使**目标节点及其全部后代**拒绝
  （后代节点的轨迹写明“祖先令牌 X 已被撤销，本节点作为其后代同步失效”）；
- 当 `at < effective_at` 时事件**完全不解释**：历史请求仍按原链判定，可正常 `allow`；
  因此允许提前登记一条未来生效的撤销；
- 响应顶层 `first_revoked_node` 标出按链顺序**最先受撤销影响的节点**（即最靠近根的
  被撤销节点本身，而非其后代）；它同时通常也是 `first_failed_node`（reason 为 `revoked`）。

求值必须**整条链所有节点**全部通过才为 `allow`；`first_failed_node` /
`first_failed_reason` 指向按链顺序（根→叶，先完整性后请求级）遇到的第一个失败。

---

## 短时额度预留 `POST /api/v1/chains/{chain_id}/reservations`

为一次单链访问**预先占一份额度**（有效秒数 1～300）。整个流程在
**同一 SQLite 事务**（`BEGIN IMMEDIATE`）内完成：

1. 以**服务端接收时刻**（UTC）重算现有验签、逐级收窄、按时间解释的撤销、
   密钥停用与请求级权限（与核销同一引擎）；
2. 仅在**目标确为链末端、判定允许、主体已设额度且可用量
   （`limit - used - reserved`）充足**时占一份，返回 `201` 与到期时间
   `expires_at`（= 接收时刻 + `ttl_seconds`）；
3. **同一令牌只能有一笔有效预留**：该令牌已持有未过期预留时返回 `409`
   （响应给出已有预留的 `existing_reservation_key` 与 `expires_at`）；
4. 同 `reservation_key` 同内容重放返回**首次预留结果**（`200`、
   `replayed=true`、到期时间与首次一致，不重复占份）；同键换内容
   （含换 `ttl_seconds`）返回 `409`；
5. **失败不占键**：判定拒绝（`decision="deny"`）、主体未设额度
   （`deny_reason="quota_unset"`）或可用量不足
   （`deny_reason="quota_exhausted"`）均返回 `200` + `reserved=false`，
   `reservation_key` 未被占用，条件满足后同键重试即可成功；
6. **过期自动释放**：到期后预留不再占额度、不再占用令牌与预留键——
   同一令牌可重新预留，同键重试按一笔全新预留处理（新的到期时间）。

```bash
curl -sS -X POST http://localhost:8000/api/v1/chains/quota-demo-2/reservations \
  -H 'Content-Type: application/json' \
  -d '{
    "token_id": "quota-demo-2-leaf",
    "reservation_key": "reserve-2026-0001",
    "ttl_seconds": 120,
    "request_path": "/files/reports/b",
    "method": "GET"
  }'
```

成功预留（`201 Created`）响应：

```json
{
  "chain_id": "quota-demo-2",
  "token_id": "quota-demo-2-leaf",
  "reservation_key": "reserve-2026-0001",
  "reserved": true,
  "replayed": false,
  "evaluated_at": "2026-10-06T09:00:00.000000Z",
  "expires_at": "2026-10-06T09:02:00.000000Z",
  "decision": "allow",
  "first_failed_node": null,
  "first_failed_reason": null,
  "body_sha256": "…",
  "first_revoked_node": null,
  "deny_reason": null,
  "quota": {
    "subject": "alice",
    "limit": 2,
    "used": 1,
    "reserved": 1,
    "remaining": 1,
    "available": 0,
    "updated_at": "2026-10-06T08:00:00+00:00"
  },
  "trace": [ /* 与 /evaluate 同构的完整判定轨迹 */ ]
}
```

状态码与重放语义：

| 情况 | 状态码 | 响应要点 |
| ---- | ------ | -------- |
| 首次且末端 + 允许 + 已设额度 + 可用量充足 | `201` | `reserved=true`、`expires_at`；`quota` 为占用一份后的口径 |
| 同 `reservation_key` 同内容重试（未过期） | `200` | `replayed=true`，回放首次结果（到期时间一致，不重复占份） |
| 末端且授权允许，但未设额度 | `200` | `reserved=false`、`deny_reason="quota_unset"`；不占键 |
| 末端且授权允许，但可用量不足 | `200` | `reserved=false`、`deny_reason="quota_exhausted"`；不占键 |
| 末端但授权 / 撤销 / 停用判定拒绝 | `200` | `reserved=false`、`decision="deny"`、完整轨迹；不占键 |
| 同 `reservation_key` 换内容（未过期） | `409` | 给出双方 `existing_sha256` / `received_sha256` |
| 目标非链末端 | `409` | 附 `chain_tip_token_id` |
| 令牌已核销 | `409` | 附 `existing_request_key` |
| 令牌已持有另一键的有效预留 | `409` | 附 `existing_reservation_key` 与 `expires_at` |
| 链 / 令牌不存在 | `404` | 令牌不属于该链按不存在处理 |
| `ttl_seconds` 超出 1～300 等 | `422` | Pydantic 校验错误 |

> 预留与核销 / 会签 / 额度调整同以 `BEGIN IMMEDIATE` 串行化：并发预留不会
> 超发可用量。预留的份额只能由**携带同一预留键、同访问内容的单链核销**转为
> 已用（见下节）；普通核销与会签既不得占用被预留的令牌，也不得使用预留的
> 份额（它们的可用量均不含 `reserved` 部分）。过期预留自动释放全部占用。
> 对应回归测试见 `tests/test_reservation.py`。

---

## 一次性访问核销 `POST /api/v1/chains/{chain_id}/redeem`

对已提交链的**末端令牌**做一次性（exactly-once）访问核销。整个流程在
**同一 SQLite 事务**（`BEGIN IMMEDIATE`，写锁串行化）内完成：

1. 以**服务端接收时刻**（UTC，响应中的 `evaluated_at`）重算现有验签、逐级收窄、
   按时间解释的撤销状态，以及路径 / 方法 / 时间窗 / 来源 IP 的请求级判定（复用只读求值的同一引擎）；
2. 仅当目标确为**链末端**且判定为 `allow` 时才追加一条不可变核销记录（`redeemed_at`）；
3. 同一令牌**只能成功核销一次**：并发请求仅一笔 `201`，其余均得到明确的
   `409`（含赢家的 `existing_request_key` 与 `redeemed_at`）；
4. 成功核销后，同一 `request_key` 带**相同内容**重试，返回**首次结果**
   （`200`、`replayed=true`、首次的轨迹与 `redeemed_at`），即使令牌随后过期或被撤销；
   同键换内容（换目标令牌 / 路径 / 方法 / IP / 请求体）返回 `409`；
5. 目标不是链末端，或判定为 `deny` 时，**既不核销，也不占用 `request_key`**——
   后续有效请求仍可尝试，同一 `request_key` 也还能用于一次成功核销；
6. **短时额度预留**：请求体可携带 `reservation_key` 使用事先预留的份额——
   仅当该令牌持有**同键、同访问内容**（路径 / 方法 / 来源 IP / 请求体）**且未过期**
   的有效预留时才核销，成功后在**同一事务**内把预留转为已用（预留行删除、
   已用量 +1，可用量不变；此时不再重复检查余额，但**仍重新检查**验签 / 撤销 /
   密钥停用 / 权限）。预留键不存在 / 已过期 / 内容不符
   （`deny_reason="reservation_mismatch"`）或授权重新判定拒绝时，**不核销、
   不占用 `request_key`、不计已用**（未过期的预留仍保留）。不带预留键的普通
   核销**不得占用被预留的令牌**（`deny_reason="token_reserved"`），其余额检查
   使用可用量 `available = limit - used - reserved`，同样不含他人预留的份额。

```bash
curl -sS -X POST http://localhost:8000/api/v1/chains/demo-chain-0001/redeem \
  -H 'Content-Type: application/json' \
  -d '{
    "token_id": "token-b",
    "request_key": "access-redeem-2026-0001",
    "request_path": "/files/reports/2026/q1.pdf",
    "method": "GET",
    "source_ip": "10.1.2.3",
    "body": {"q": "demo"}
  }'
```

成功核销（`201 Created`）响应：

```json
{
  "chain_id": "demo-chain-0001",
  "token_id": "token-b",
  "request_key": "access-redeem-2026-0001",
  "redeemed": true,
  "replayed": false,
  "evaluated_at": "2026-10-04T09:00:00.000000Z",
  "redeemed_at": "2026-10-04T09:00:00.000000Z",
  "decision": "allow",
  "first_failed_node": null,
  "first_failed_reason": null,
  "body_sha256": "…",
  "first_revoked_node": null,
  "deny_reason": null,
  "quota": {
    "subject": "service-b",
    "limit": 10,
    "used": 4,
    "remaining": 6,
    "updated_at": "2026-10-04T08:00:00+00:00"
  },
  "trace": [ /* 与 /evaluate 同构的完整判定轨迹：完整性 + 请求级 */ ]
}
```

> `deny_reason` 与 `quota` 仅在**既有授权 / 撤销 / 停用检查全部通过**（`decision="allow"`）
> 后才可能出现：未设置额度（不限额）时核销响应不带 `quota` 字段（`quota=null`）、
> `deny_reason=null`；额度用尽时 `200` + `redeemed=false` +
> `deny_reason="quota_exhausted"`，并给出拒绝瞬间的额度 / 已用量 / 剩余量。
> 既有检查拒绝时 `decision="deny"`，按约定**不检查余额**，故 `quota=null`。

状态码与重放语义：

| 情况 | 状态码 | 响应要点 |
| ---- | ------ | -------- |
| 首次且末端 + 允许 + 可用量充足（或预留匹配） | `201` | `redeemed=true`、`replayed=false`，记录核销；设置了额度时 `quota` 为扣减后口径 |
| 同 `request_key` 同内容重试 | `200` | `replayed=true`，回放首次结果（含首次额度口径；令牌事后过期 / 撤销也不变，不重复计数） |
| 末端且授权允许，但可用量用尽 | `200` | `redeemed=false`、`decision="allow"`、`deny_reason="quota_exhausted"`；不核销、不占键 |
| 末端但授权 / 撤销 / 停用判定拒绝 | `200` | `redeemed=false`、`decision="deny"`、完整轨迹；不查余额、不核销、不占键 |
| 令牌被他人预留，普通核销不带预留键 | `200` | `redeemed=false`、`deny_reason="token_reserved"`；不占键、不计已用 |
| 预留键不存在 / 已过期 / 访问内容不符 | `200` | `redeemed=false`、`deny_reason="reservation_mismatch"`；不占键、不计已用 |
| 同 `request_key` 换内容 | `409` | 给出双方 `existing_sha256` / `received_sha256` |
| 目标非链末端 | `409` | 附 `chain_tip_token_id`（结构异常无法确定时为 `null`） |
| 令牌此前已核销（含并发输家） | `409` | 附 `existing_request_key` 与赢家 `redeemed_at` |
| 链 / 令牌不存在 | `404` | 令牌不属于该链按不存在处理 |
| 输入非法（方法 / IP） | `422` | Pydantic 校验错误 |

> 核销是**只追加**的成功记录：数据库以 `request_key UNIQUE` 与
> `(chain_id, token_id) UNIQUE` 双重约束兜底并发；被拒绝 / 目标不符的尝试不落任何记录。
> 核销不影响原有只读 `/evaluate`：后者仍每次实时重算，令牌被核销后照常可按时间判定为 allow/deny。

---

## 双主体会签 `POST /api/v1/co-redemptions`

一次访问需要**两个不同主体**各自持有的能力链末端同时授权：主授权链（`primary`）与
复核链（`review`）的末端令牌在**同一 SQLite 写事务**（`BEGIN IMMEDIATE`）内、以
**同一服务端接收时刻**（UTC）分别判定——各链按**各自提交时锁定的密钥代次**验签，
并检查撤销、请求级权限与已核销状态：

1. 两条链的 `chain_id` 必须不同（否则 `422`），两链末端令牌的 `subject` 也必须不同
   （否则 `409`）——主授权与复核必须是不同主体；
2. **两侧都判定 `allow`、两侧 subject 额度都有余量且都未核销**时，才在同一事务内
   同时记入两侧核销，返回 `201`、两份判定轨迹、**共同核销时间**（`redeemed_at`，
   与 `evaluated_at` 一致）与各自扣减后的额度口径；
3. **任一侧拒绝或已核销，另一侧不被消耗**：授权 / 撤销 / 停用判定拒绝，或两侧都
   通过后的余额检查不足，均返回 `200` + `redeemed=false`
   （两侧都不核销、不占用 `request_key`）；任一侧此前已核销（无论单链核销还是会签）
   返回 `409`，另一侧照常可用；
4. 成功会签后，同一 `request_key` 带**相同内容**重试返回**首次会签结果**
   （`200`、`replayed=true`），即使令牌随后过期或被撤销；同键换内容
   （含主 / 复核互换）返回 `409`；
5. 会签与单链核销**共用同一“已核销”判定与 `request_key` 键空间**：会签的任一侧
   此后不能被单链接口当作独立请求再次核销（`409` 已核销），反之亦然；
   链查询 `GET /api/v1/chains/{chain_id}` 的 `redemptions` 中可见各自一侧的核销记录。

```bash
curl -sS -X POST http://localhost:8000/api/v1/co-redemptions \
  -H 'Content-Type: application/json' \
  -d '{
    "primary": {"chain_id": "cosign-primary-0001", "token_id": "cosign-leaf-p"},
    "review":  {"chain_id": "cosign-review-0001",  "token_id": "cosign-leaf-r"},
    "request_key": "access-cosign-2026-0001",
    "request_path": "/files/reports/q1.pdf",
    "method": "GET",
    "source_ip": "10.1.2.3",
    "body": {"q": "demo"}
  }'
```

成功会签（`201 Created`）响应：

```json
{
  "request_key": "access-cosign-2026-0001",
  "redeemed": true,
  "replayed": false,
  "evaluated_at": "2026-10-04T09:00:00.000000Z",
  "redeemed_at": "2026-10-04T09:00:00.000000Z",
  "body_sha256": "…",
  "primary": {
    "chain_id": "cosign-primary-0001",
    "token_id": "cosign-leaf-p",
    "subject": "alice",
    "decision": "allow",
    "first_failed_node": null,
    "first_failed_reason": null,
    "first_revoked_node": null,
    "deny_reason": null,
    "quota": {
      "subject": "alice",
      "limit": 10,
      "used": 7,
      "remaining": 3,
      "updated_at": "2026-10-04T08:00:00+00:00"
    },
    "trace": [ /* 主授权链的完整判定轨迹 */ ]
  },
  "review": {
    "chain_id": "cosign-review-0001",
    "token_id": "cosign-leaf-r",
    "subject": "service-b",
    "decision": "allow",
    "first_failed_node": null,
    "first_failed_reason": null,
    "first_revoked_node": null,
    "deny_reason": null,
    "quota": null,
    "trace": [ /* 复核链的完整判定轨迹 */ ]
  }
}
```

> 余额检查在**两侧既有判定都为 allow** 时才进行：设置了额度的一侧返回扣减后口径
> （未设置额度的一侧 `quota=null`）。任一主体余额不足时该侧
> `decision="deny"`、`deny_reason="quota_exhausted"`，**两侧均不核销、不占键**；
> 某一侧授权 / 撤销 / 停用拒绝时根本不进入余额检查，两侧 `quota` 均为 `null`。

状态码与重放语义：

| 情况 | 状态码 | 响应要点 |
| ---- | ------ | -------- |
| 首次且两侧末端都允许、可用量均充足、均无有效预留 | `201` | `redeemed=true`，两侧同时记入核销（共同 `redeemed_at`），各侧返回扣减后口径 |
| 同 `request_key` 同内容重试 | `200` | `replayed=true`，回放首次会签结果（含首次额度口径；事后过期 / 撤销也不变，不重复计数） |
| 两侧授权均允许，但任一主体可用量用尽 | `200` | 不足侧 `deny_reason="quota_exhausted"`；两侧都不核销、不占键 |
| 两侧授权均允许，但任一侧令牌持有有效预留 | `200` | 该侧 `deny_reason="token_reserved"`；两侧都不核销、不占键 |
| 任一侧授权 / 撤销 / 停用判定拒绝 | `200` | `redeemed=false`、两份轨迹；两侧都不核销、不占键（不查余额） |
| 同 `request_key` 换内容（含两侧互换） | `409` | 给出双方 `existing_sha256` / `received_sha256` |
| 两链末端 `subject` 相同 | `409` | 会签要求主授权与复核为不同主体 |
| 任一侧此前已核销（单链或会签） | `409` | 附 `side` 与 `existing_request_key`；另一侧不被消耗 |
| 目标非链末端 | `409` | 附 `side` 与 `chain_tip_token_id` |
| 任一链 / 令牌不存在 | `404` | 令牌不属于对应链按不存在处理 |
| 两链 `chain_id` 相同 / 输入非法 | `422` | Pydantic 校验错误 |

> 数据库以 `request_key UNIQUE`、`(primary_chain_id, primary_token_id) UNIQUE` 与
> `(review_chain_id, review_token_id) UNIQUE` 约束兜底并发：同一对末端并发会签仅一笔 `201`。

### 会签演练（可直接复制执行）

下面是一套完整的 bash 演练：构造两条链（主授权 `root → service-a`，末端主体 `alice`；
复核 `root → service-b`，末端主体 `service-b`）→ 提交 → 会签 → 重放 / 冲突 /
“单链接口不能重放会签的一半”→ 链查询各自核销记录。假设服务已通过
`docker compose up --build` 启动在 `http://localhost:8000`，命令在仓库根目录执行
（签名复用 `app.security`，需本地 Python 3.10+ 与 `pip install -r requirements.txt`）：

```bash
# 签名助手：生成 root -> $2(签发者) 的两级链，末端主体为 $3、末端令牌 id 为 $5，用 $4 签名
build_leg() {
  PYTHONPATH=. CHAIN_ID="$1" ISSUER="$2" TIP_SUBJECT="$3" ISSUER_SECRET="$4" \
  LEAF_ID="$5" python3 - <<'PY'
import json, os
from datetime import datetime, timedelta, timezone
from app.security import compute_signature

chain_id      = os.environ["CHAIN_ID"]
issuer        = os.environ["ISSUER"]
tip_subject   = os.environ["TIP_SUBJECT"]
issuer_secret = os.environ["ISSUER_SECRET"]
leaf_id       = os.environ["LEAF_ID"]
root_secret   = os.environ.get("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")

def token(tid, parent, iss, sub, path, methods, secret, allow_ip=None):
    t = {
        "token_id": tid, "parent_id": parent, "chain_id": chain_id,
        "issuer": iss, "subject": sub, "path_pattern": path,
        "methods": methods, "not_before": nb, "not_after": na,
        "allow_ip": allow_ip, "signature": "",
    }
    t["signature"] = compute_signature(t, secret)
    return t

print(json.dumps({
    "chain_id": chain_id,
    "tokens": [
        token("cosign-root", None, "root", issuer,
              "/files/**", ["GET", "POST"], root_secret),
        token(leaf_id, "cosign-root", issuer, tip_subject,
              "/files/reports/*", ["GET"], issuer_secret,
              allow_ip="10.1.0.0/16"),
    ],
}, ensure_ascii=False))
PY
}

# 1) 提交主授权链（末端主体 alice）与复核链（末端主体 service-b）
build_leg cosign-primary-0001 service-a alice     demo-secret-service-a cosign-leaf-p > /tmp/co-primary.json
build_leg cosign-review-0001  service-b service-b demo-secret-service-b cosign-leaf-r > /tmp/co-review.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/co-primary.json
# → 201，"integrity": {"allow": true, ...}
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/co-review.json
# → 201，"integrity": {"allow": true, ...}

# 2) 双主体会签：两侧末端都允许 -> 201，两份轨迹 + 共同核销时间
curl -sS -X POST http://localhost:8000/api/v1/co-redemptions \
  -H 'Content-Type: application/json' \
  -d '{
    "primary": {"chain_id": "cosign-primary-0001", "token_id": "cosign-leaf-p"},
    "review":  {"chain_id": "cosign-review-0001",  "token_id": "cosign-leaf-r"},
    "request_key": "access-cosign-2026-0001",
    "request_path": "/files/reports/q1.pdf",
    "method": "GET",
    "source_ip": "10.1.2.3"
  }'
# → 201，"redeemed": true，"redeemed_at" == "evaluated_at"（两侧共同时间）

# 3) 同 request_key 同内容重试：回放首次会签结果（事后撤销 / 到期也不变）
curl -sS -X POST http://localhost:8000/api/v1/co-redemptions \
  -H 'Content-Type: application/json' \
  -d '{
    "primary": {"chain_id": "cosign-primary-0001", "token_id": "cosign-leaf-p"},
    "review":  {"chain_id": "cosign-review-0001",  "token_id": "cosign-leaf-r"},
    "request_key": "access-cosign-2026-0001",
    "request_path": "/files/reports/q1.pdf",
    "method": "GET",
    "source_ip": "10.1.2.3"
  }'
# → 200，"replayed": true，轨迹与 redeemed_at 与首次完全一致

# 4) 会签的一半不能被单链接口当作独立请求重放：409 已核销
curl -sS -X POST http://localhost:8000/api/v1/chains/cosign-primary-0001/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "cosign-leaf-p", "request_key": "access-redeem-2026-0002",
       "request_path": "/files/reports/q1.pdf", "method": "GET",
       "source_ip": "10.1.2.3"}'
# → 409，"existing_request_key": "access-cosign-2026-0001"

# 5) 链查询：两条链各自的 redemptions 都能看到自己一侧的核销记录
curl -sS http://localhost:8000/api/v1/chains/cosign-primary-0001 | python3 -m json.tool | grep -A4 redemptions
curl -sS http://localhost:8000/api/v1/chains/cosign-review-0001  | python3 -m json.tool | grep -A4 redemptions
```

> 一方拒绝时另一方不被消耗：把第 2 步的 `source_ip` 改成 `192.168.0.1`
> （不在末端 `10.1.0.0/16` 内）会得到 `200` + `"redeemed": false` 与两份轨迹，
> 两侧都未核销、`request_key` 未占用——改回合法 IP 后用同一把键重试即可成功。
> 对应回归测试见 `tests/test_co_redemption.py`。

---

## 密钥轮换演练（轮换前后签名、求值与核销）

下面是一套**可直接复制执行**的 bash 演练：注册主体 → 轮换前签名/提交/求值 → 轮换密钥 →
验证既有链结论不变（查询 / 求值 / 首次核销 / 重放）→ 轮换后新旧密钥签名对比。
假设服务已通过 `docker compose up --build` 启动在 `http://localhost:8000`，
命令在仓库根目录执行（签名复用 `app.security`，需本地 Python 3.10+ 与 `pip install -r requirements.txt`）。

```bash
# 0) 注册演练主体 svc-demo（第 1 代密钥；已注册过会返回 409，可忽略或换个名字）
curl -sS -X POST http://localhost:8000/api/v1/principals \
  -H 'Content-Type: application/json' \
  -d '{"name": "svc-demo", "hmac_secret": "svc-demo-secret-v1"}'

# 签名助手：生成 root -> svc-demo 的两级链，child 用 $2 指定的 svc-demo 密钥签名
build_chain() {
  PYTHONPATH=. CHAIN_ID="$1" SVC_SECRET="$2" python3 - <<'PY'
import json, os
from datetime import datetime, timedelta, timezone
from app.security import compute_signature

chain_id   = os.environ["CHAIN_ID"]
svc_secret = os.environ["SVC_SECRET"]
root_secret = os.environ.get("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")

def token(tid, parent, issuer, subject, path, methods, secret):
    t = {
        "token_id": tid, "parent_id": parent, "chain_id": chain_id,
        "issuer": issuer, "subject": subject, "path_pattern": path,
        "methods": methods, "not_before": nb, "not_after": na,
        "allow_ip": None, "signature": "",
    }
    t["signature"] = compute_signature(t, secret)   # 规范化 JSON + HMAC-SHA256
    return t

print(json.dumps({
    "chain_id": chain_id,
    "tokens": [
        token("rot-root",  None,       "root",     "svc-demo",
              "/files/**", ["GET", "POST"], root_secret),
        token("rot-child", "rot-root", "svc-demo", "svc-demo-worker",
              "/files/reports/*", ["GET"], svc_secret),
    ],
}, ensure_ascii=False))
PY
}
```

### 轮换前：用第 1 代密钥签名、提交、求值

```bash
# 1) 用当前（第 1 代）密钥签名并提交
build_chain rot-chain-before svc-demo-secret-v1 > /tmp/rot-before.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/rot-before.json
# → 201，"integrity": {"allow": true, ...}

# 2) 轮换前只读求值
curl -sS -X POST http://localhost:8000/api/v1/chains/rot-chain-before/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/reports/q1.pdf\", \"method\": \"GET\", \
      \"at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
# → "decision": "allow"
```

### 轮换：原子切换到第 2 代密钥

```bash
# 3) 轮换 svc-demo 的 HMAC 密钥（响应不含密钥）
curl -sS -X POST http://localhost:8000/api/v1/principals/svc-demo/rotate-key \
  -H 'Content-Type: application/json' \
  -d '{"hmac_secret": "svc-demo-secret-v2"}'
# → 200 {"name": "svc-demo", "generation": 2, "rotated_at": "..."}
```

### 轮换后：既有链按提交时锁定的第 1 代密钥重验，结论不变

```bash
# 4a) 链查询：完整性报告仍是轮换前的验签结论
curl -sS http://localhost:8000/api/v1/chains/rot-chain-before
# → "integrity": {"allow": true, ...}

# 4b) 只读求值：继续用第 1 代密钥重验，仍 allow
curl -sS -X POST http://localhost:8000/api/v1/chains/rot-chain-before/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/reports/q1.pdf\", \"method\": \"GET\", \
      \"at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
# → "decision": "allow"

# 4c) 首次核销：同样按第 1 代密钥重验，正常核销
curl -sS -X POST http://localhost:8000/api/v1/chains/rot-chain-before/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "rot-child", "request_key": "rot-redeem-0001",
       "request_path": "/files/reports/q1.pdf", "method": "GET"}'
# → 201，"redeemed": true

# 4d) 同 request_key 同内容重放：仍返回首次结果（与轮换无关）
curl -sS -X POST http://localhost:8000/api/v1/chains/rot-chain-before/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "rot-child", "request_key": "rot-redeem-0001",
       "request_path": "/files/reports/q1.pdf", "method": "GET"}'
# → 200，"replayed": true，redeemed_at / 轨迹与首次完全一致
```

### 轮换后：新提交的链只按新密钥验签

```bash
# 5a) 旧密钥签出的新链：验签失败（bad_signature），失败结果同样持久化
build_chain rot-chain-old-key svc-demo-secret-v1 > /tmp/rot-old-key.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/rot-old-key.json
# → 201，"integrity": {"allow": false, "first_failed_reason": "bad_signature", ...}

# 5b) 新密钥签出的新链：正常通过，求值 / 核销照常
build_chain rot-chain-after svc-demo-secret-v2 > /tmp/rot-after.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/rot-after.json
# → 201，"integrity": {"allow": true, ...}

curl -sS -X POST http://localhost:8000/api/v1/chains/rot-chain-after/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/reports/q1.pdf\", \"method\": \"GET\", \
      \"at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
# → "decision": "allow"

curl -sS -X POST http://localhost:8000/api/v1/chains/rot-chain-after/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "rot-child", "request_key": "rot-redeem-0002",
       "request_path": "/files/reports/q1.pdf", "method": "GET"}'
# → 201，"redeemed": true
```

> 既有**无效**链也不会因新密钥恰好匹配而翻转：若某链提交时签名对当时的密钥无效，
> 即使该签名恰好等于新密钥的 HMAC，链查询 / 求值 / 核销仍按提交时锁定的代次重验，
> 结论保持 `bad_signature`（测试 `test_invalid_chain_does_not_turn_valid_when_new_key_happens_to_match`
> 覆盖了这一场景）。撤销事件与轮换正交：轮换后追加的撤销照常按请求时间生效。

---

## 密钥停用演练（停用前后、轮换后的求值、核销与会签）

下面是一套**可直接复制执行**的 bash 演练：注册主体 → 用第 1 代密钥签名 / 提交 /
求值 / 核销 → 停用第 1 代密钥 → 验证已提交链在求值（含指定过去时刻）、首次核销、
双链会签中从对应签发节点拒绝、会签另一侧不被消耗 → 轮换到第 2 代 → 验证旧代次链
仍拒绝、新代次链正常、历史报告与已完成核销不改写。
前提同[密钥轮换演练](#密钥轮换演练轮换前后签名求值与核销)：服务已通过
`docker compose up --build` 启动在 `http://localhost:8000`，命令在仓库根目录执行
（签名复用 `app.security`，需本地 Python 3.10+ 与 `pip install -r requirements.txt`）。

### 准备：注册主体并签名提交一条链

```bash
# 0) 注册演练主体 kill-demo（第 1 代密钥；已注册过会返回 409，可忽略或换名）
curl -sS -X POST http://localhost:8000/api/v1/principals \
  -H 'Content-Type: application/json' \
  -d '{"name": "kill-demo", "hmac_secret": "kill-demo-secret-v1"}'

# 签名助手：生成 root -> kill-demo 的两级链，child 用 $2 指定的密钥签名
build_kill_chain() {
  PYTHONPATH=. CHAIN_ID="$1" SVC_SECRET="$2" python3 - <<'PY'
import json, os
from datetime import datetime, timedelta, timezone
from app.security import compute_signature

chain_id   = os.environ["CHAIN_ID"]
svc_secret = os.environ["SVC_SECRET"]
root_secret = os.environ.get("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")

def token(tid, parent, issuer, subject, path, methods, secret):
    t = {
        "token_id": tid, "parent_id": parent, "chain_id": chain_id,
        "issuer": issuer, "subject": subject, "path_pattern": path,
        "methods": methods, "not_before": nb, "not_after": na,
        "allow_ip": None, "signature": "",
    }
    t["signature"] = compute_signature(t, secret)
    return t

print(json.dumps({
    "chain_id": chain_id,
    "tokens": [
        token("kill-root",  None,        "root",      "kill-demo",
              "/files/**", ["GET", "POST"], root_secret),
        token("kill-child", "kill-root", "kill-demo", "kill-demo-worker",
              "/files/x", ["GET"], svc_secret),
    ],
}, ensure_ascii=False))
PY
}

# 1) 用第 1 代密钥签名并提交：完整性通过
build_kill_chain kill-chain-1 kill-demo-secret-v1 > /tmp/kill-chain.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/kill-chain.json
# → 201，"integrity": {"allow": true, ...}

# 2) 停用前只读求值：allow
curl -sS -X POST http://localhost:8000/api/v1/chains/kill-chain-1/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/x\", \"method\": \"GET\", \
      \"at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
# → "decision": "allow"
```

### 停用：不可撤销地停用第 1 代密钥

```bash
# 3) 按主体名 + 代次停用（立即生效，记录原因）
curl -sS -X POST \
  http://localhost:8000/api/v1/principals/kill-demo/generations/1/deactivate-key \
  -H 'Content-Type: application/json' \
  -d '{"reason": "运维安全事件：怀疑第 1 代密钥泄露"}'
# → 201 {"replayed": false, "event": {"principal": "kill-demo",
#      "generation": 1, "reason": "...", "deactivated_at": "..."}}

# 3b) 同一（主体, 代次）同原因重放：幂等 200，返回原事件
curl -sS -X POST \
  http://localhost:8000/api/v1/principals/kill-demo/generations/1/deactivate-key \
  -H 'Content-Type: application/json' \
  -d '{"reason": "运维安全事件：怀疑第 1 代密钥泄露"}'
# → 200，"replayed": true，deactivated_at 与首次完全一致

# 3c) 换原因：409（停用不可改写）；不存在的主体 / 代次：404
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  http://localhost:8000/api/v1/principals/kill-demo/generations/1/deactivate-key \
  -H 'Content-Type: application/json' -d '{"reason": "另一个原因"}'
# → 409
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  http://localhost:8000/api/v1/principals/kill-demo/generations/9/deactivate-key \
  -H 'Content-Type: application/json' -d '{"reason": "x"}'
# → 404
```

### 停用后：已提交链在求值 / 核销中拒绝，过去时刻也绕不过

```bash
# 4a) 只读求值：从对应签发节点 kill-child 拒绝，轨迹标明密钥停用
curl -sS -X POST http://localhost:8000/api/v1/chains/kill-chain-1/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/x\", \"method\": \"GET\", \
      \"at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
# → "decision": "deny",
#   "first_failed_node": "kill-child",
#   "first_failed_reason": "key_deactivated"
#   kill-child 节点："signature" 仍 passed=true，
#   但 "key_active": {"passed": false, "reason": "key_deactivated",
#                     "detail": "签发者 kill-demo 第 1 代密钥已因疑似失陷被停用…"}

# 4b) 指定过去时刻（仍在链有效期内、停用之前）也不能绕过
curl -sS -X POST http://localhost:8000/api/v1/chains/kill-chain-1/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/x\", \"method\": \"GET\", \
      \"at\": \"$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ)\"}"
# → "decision": "deny", "first_failed_reason": "key_deactivated"
#   （停用与请求时间无关；区别于按 at 解释的撤销事件）

# 4c) 首次单链核销：判定拒绝，不核销、不占用 request_key
curl -sS -X POST http://localhost:8000/api/v1/chains/kill-chain-1/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "kill-child", "request_key": "kill-access-0001",
       "request_path": "/files/x", "method": "GET"}'
# → 200，"redeemed": false, "decision": "deny",
#   "first_failed_reason": "key_deactivated"

# 4d) 链查询：没有任何核销记录；提交时完整性报告仍是停用前的结论（不改写）
curl -sS http://localhost:8000/api/v1/chains/kill-chain-1 | python3 -m json.tool \
  | grep -E '"allow"|redemptions'
# → "allow": true（提交时报告原样），"redemptions": []

# 4e) 停用的就是当前代（此刻尚未轮换，当前代仍为第 1 代）：用该代密钥签出的
#     新链照样提交、照样持久化，归属仍记第 1 代，但提交报告即以停用拒绝
build_kill_chain kill-chain-current kill-demo-secret-v1 > /tmp/kill-current.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/kill-current.json
# → 201，"integrity": {"allow": false, "first_failed_node": "kill-child",
#      "first_failed_reason": "key_deactivated"}
# 同内容重放返回原完整性结论（不翻转）
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/kill-current.json
# → 200，"replayed": true，"integrity" 与首次完全一致
```

### 会签：一侧密钥停用 → 拒绝且另一侧不被消耗

```bash
# 5) 注册独立复核主体并造一条复核链（root -> kill-review，末端主体 kill-review-worker）
curl -sS -X POST http://localhost:8000/api/v1/principals \
  -H 'Content-Type: application/json' \
  -d '{"name": "kill-review", "hmac_secret": "kill-review-secret-v1"}'
PYTHONPATH=. CHAIN_ID="kill-review-1" python3 - <<'PY' > /tmp/kill-review.json
import json, os
from datetime import datetime, timedelta, timezone
from app.security import compute_signature
root_secret = os.environ.get("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")
def token(tid, parent, issuer, subject, secret):
    t = {"token_id": tid, "parent_id": parent, "chain_id": "kill-review-1",
         "issuer": issuer, "subject": subject, "path_pattern": "/files/**",
         "methods": ["GET"], "not_before": nb, "not_after": na,
         "allow_ip": None, "signature": ""}
    t["signature"] = compute_signature(t, secret)
    return t
print(json.dumps({"chain_id": "kill-review-1", "tokens": [
    token("kr-root", None, "root", "kill-review", root_secret),
    token("kr-leaf", "kr-root", "kill-review", "kill-review-worker",
          "kill-review-secret-v1"),
]}))
PY
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/kill-review.json
# → 201 allow

# 5b) 会签：主授权侧 kill-chain-1 绑定的第 1 代已停用 -> 200 redeemed=false，
#     primary 拒绝、review 仍 allow；两侧都不核销，request_key 未占用
curl -sS -X POST http://localhost:8000/api/v1/co-redemptions \
  -H 'Content-Type: application/json' \
  -d '{
    "primary": {"chain_id": "kill-chain-1",  "token_id": "kill-child"},
    "review":  {"chain_id": "kill-review-1", "token_id": "kr-leaf"},
    "request_key": "kill-cosign-0001",
    "request_path": "/files/x", "method": "GET"
  }'
# → 200，"redeemed": false,
#   "primary": {"decision": "deny", "first_failed_reason": "key_deactivated"},
#   "review":  {"decision": "allow"}

# 5c) 复核链没有被消耗：它仍可与一条正常链成功会签（同一把 request_key 也未占用）
curl -sS http://localhost:8000/api/v1/chains/kill-review-1 \
  | python3 -m json.tool | grep -A2 redemptions
# → "redemptions": []
```

### 轮换后：旧代次停用不解除，新代次链正常，历史记录不改写

```bash
# 6) 轮换到第 2 代密钥（不解除第 1 代停用）
curl -sS -X POST http://localhost:8000/api/v1/principals/kill-demo/rotate-key \
  -H 'Content-Type: application/json' \
  -d '{"hmac_secret": "kill-demo-secret-v2"}'
# → 200 {"name": "kill-demo", "generation": 2, ...}

# 6a) 历史链仍按锁定的第 1 代重验：停用继续生效，轮换没有解除
curl -sS -X POST http://localhost:8000/api/v1/chains/kill-chain-1/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/x\", \"method\": \"GET\", \
      \"at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
# → "decision": "deny", "first_failed_reason": "key_deactivated"

# 6b) 轮换后再用旧（第 1 代）密钥签出新链：当前代已是第 2 代，签名对新代次
#     无效 -> bad_signature；而上面第 4e 步在轮换前停用后提交的链，归属第 1 代，
#     结论是 key_deactivated——两种情况下代次归属与拒绝结论都随链冻结
build_kill_chain kill-chain-oldkey kill-demo-secret-v1 > /tmp/kill-oldkey.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/kill-oldkey.json
# → 201，"integrity": {"allow": false,
#      "first_failed_node": "kill-child", "first_failed_reason": "bad_signature"}

# 6c) 用第 2 代密钥签出的新链：正常验签、求值、核销
build_kill_chain kill-chain-2 kill-demo-secret-v2 > /tmp/kill-chain2.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/kill-chain2.json
# → 201 allow
curl -sS -X POST http://localhost:8000/api/v1/chains/kill-chain-2/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "kill-child", "request_key": "kill-access-0002",
       "request_path": "/files/x", "method": "GET"}'
# → 201，"redeemed": true

# 6d) 同内容提交重放 kill-chain-1：仍返回停用前的原完整性结论
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/kill-chain.json
# → 200，"replayed": true，"integrity": {"allow": true, ...}（首次提交结论）
```

> 停用与撤销是两条**正交**的安全动作：撤销按请求时间 `at` 解释（可登记未来生效，
> 生效前的历史请求仍按原链判定），并沿链传播到后代；密钥停用与请求时间无关、
> 只作用于“签发主体 = 被停用主体且链锁定代次 = 被停用代次”的签发节点，
> 不沿链传播（root 由 `root` 签发，停用 `kill-demo` 不影响 root 节点本身）。
> 对应回归测试见 `tests/test_key_deactivation.py`。

---

## 提交时未注册签发者的链：结论永不翻转

**问题**（修复前可重现）：一条链提交时签发者尚未注册，验签以 `unknown_issuer`
失败并随链持久化。但旧版本只为“提交时已注册”的主体记录密钥代次，未注册主体
在重验时回退到**当前密钥**——于是事后注册该主体、并轮换到恰好匹配旧签名的
密钥后，同内容重放与只读求值会翻转为放行，首次核销甚至返回 `201` 核销成功；
重启时的回填还会把这类旧链误绑到后来注册的密钥代次，重启后同样翻转。

**修复**：提交时“签发者未注册、缺失密钥”这一事实随链持久化
（`chain_missing_issuers` 表，与代次归属表互补）。链查询、同内容重放、只读求值
与首次核销对该类链一律保持提交时的 `unknown_issuer` 拒绝；旧库回填以随链保存的
提交时完整性报告为准——报告含 `unknown_issuer` 的签发者只记入缺失表（并清除
早期版本误写入的代次归属），绝不归到后来注册的密钥代次；提交时已注册主体的
旧链仍归到其历史第 1 代密钥，继续按原密钥验签。

下面是一套**可直接复制执行**的 bash 复现 / 验证流程（前提同
[密钥轮换演练](#密钥轮换演练轮换前后签名求值与核销)：服务运行在
`http://localhost:8000`，仓库根目录，本地 Python 3.10+）：

```bash
# 签名助手：生成 root -> $2(签发者) 的两级链，child 用 $3 指定的密钥签名
build_chain_for() {
  PYTHONPATH=. CHAIN_ID="$1" ISSUER="$2" ISSUER_SECRET="$3" python3 - <<'PY'
import json, os
from datetime import datetime, timedelta, timezone
from app.security import compute_signature

chain_id      = os.environ["CHAIN_ID"]
issuer        = os.environ["ISSUER"]
issuer_secret = os.environ["ISSUER_SECRET"]
root_secret   = os.environ.get("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")

def token(tid, parent, iss, sub, path, methods, secret):
    t = {
        "token_id": tid, "parent_id": parent, "chain_id": chain_id,
        "issuer": iss, "subject": sub, "path_pattern": path,
        "methods": methods, "not_before": nb, "not_after": na,
        "allow_ip": None, "signature": "",
    }
    t["signature"] = compute_signature(t, secret)
    return t

print(json.dumps({
    "chain_id": chain_id,
    "tokens": [
        token("ghost-root",  None,        "root", issuer,
              "/files/**", ["GET", "POST"], root_secret),
        token("ghost-child", "ghost-root", issuer, "ghost-worker",
              "/files/reports/*", ["GET"], issuer_secret),
    ],
}, ensure_ascii=False))
PY
}

# 1) ghost 尚未注册：用“未来的第 2 代密钥”ghost-secret-v2 签名并提交
build_chain_for ghost-chain ghost ghost-secret-v2 > /tmp/ghost-chain.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/ghost-chain.json
# → 201，"integrity": {"allow": false, "first_failed_reason": "unknown_issuer", ...}
#   （完整性失败同样持久化，此后链查询始终返回这份提交时报告）

# 2) 事后注册 ghost（第 1 代密钥与旧签名不符）
curl -sS -X POST http://localhost:8000/api/v1/principals \
  -H 'Content-Type: application/json' \
  -d '{"name": "ghost", "hmac_secret": "ghost-secret-v1"}'
# → 201 {"name": "ghost"}

# 3) 再轮换到恰好匹配旧签名的第 2 代密钥
curl -sS -X POST http://localhost:8000/api/v1/principals/ghost/rotate-key \
  -H 'Content-Type: application/json' \
  -d '{"hmac_secret": "ghost-secret-v2"}'
# → 200 {"name": "ghost", "generation": 2, "rotated_at": "..."}
#   此刻当前密钥已能匹配旧链签名——修复前，第 5/6/7 步会全部翻转为放行

# 4) 链查询：仍是提交时落库的拒绝报告
curl -sS http://localhost:8000/api/v1/chains/ghost-chain
# → 200，"integrity": {"allow": false, "first_failed_reason": "unknown_issuer", ...}

# 5) 同内容重放：结论与首次提交一致（修复前会翻转为 "allow": true）
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/ghost-chain.json
# → 200，"replayed": true，
#   "integrity": {"allow": false, "first_failed_reason": "unknown_issuer", ...}

# 6) 只读求值：仍按 unknown_issuer 拒绝（修复前会 "decision": "allow"）
curl -sS -X POST http://localhost:8000/api/v1/chains/ghost-chain/evaluate \
  -H 'Content-Type: application/json' \
  -d "{\"request_path\": \"/files/reports/q1.pdf\", \"method\": \"GET\", \
      \"at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
# → 200，"decision": "deny", "first_failed_reason": "unknown_issuer"

# 7) 首次核销：仍判定拒绝，不核销、不占 request_key（修复前会 201 核销成功）
curl -sS -X POST http://localhost:8000/api/v1/chains/ghost-chain/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id": "ghost-child", "request_key": "ghost-redeem-0001",
       "request_path": "/files/reports/q1.pdf", "method": "GET"}'
# → 200，"redeemed": false, "decision": "deny",
#   "first_failed_reason": "unknown_issuer"
```

> 重启服务（`docker compose restart`，触发旧库回填）后重复第 4–7 步，结论不变：
> 回填不会把提交时未注册的 `ghost` 归到后来注册的密钥代次。
> 而提交时签发者已注册的链不受影响——它们仍按提交时锁定的代次验签
> （见上节轮换演练）；撤销事件与已核销请求的同键重放也与轮换 / 注册无关，照常工作。
> 对应回归测试见 `tests/test_unknown_issuer.py`。

---

## 链末端 subject 的核销额度

运维方可为**链末端令牌的 `subject`（被授权主体）**设置一个可调整的**跨链成功核销
总额度**，并随时查询**额度 / 历史已用 / 有效预留 / 可用量**。

口径（额度行、只追加的核销记录与预留行都持久化在 SQLite 中，重启后不变）：

- **未设置额度 = 不限额**：查询时 `limit=null`、`remaining=null`、`available=null`，
  核销不受任何额外限制（此时也不能预留——预留要求主体已设额度）；
- **历史已用 `used`** = 该主体在**全部链**上的成功**单链核销**数，加上**会签中该主体
  参与的一侧**的次数——每笔会签对每个参与主体各计一次（两侧本就必须是不同主体）；
  **包含额度设置之前**已经发生的成功核销；
- **有效预留 `reserved`** = 该主体当前**未过期、未转为核销**的短时预留数
  （每笔预留占一份额度；过期自动释放，核销成功后转为已用）；
- **毛剩余 `remaining` = `limit - used`**（含被预留的份额）；
- **可用量 `available` = `limit - used - reserved`**：普通单链核销、会签与新预留
  实际可用的份额；
- 额度可随时调高；**调低（含首次设为有限值）不得低于 `used + reserved`**
  （不得侵占尚未过期 / 未核销的预留份额），否则 `409` 且原额度不变；
  `{"limit": null}` 显式清除额度、恢复不限额；
- 余额检查在**既有授权判定 / 撤销 / 密钥停用检查全部通过之后**才进行：
  - 单链核销可用量不足 → `200` + `redeemed=false` + `deny_reason="quota_exhausted"`，
    **不核销、不占用 `request_key`**（调高额度后同一把键即可成功）；
  - 会签任一主体可用量不足 → 该侧 `deny_reason="quota_exhausted"`，
    **两侧均不核销、不占键**；
  - 授权 / 撤销 / 停用先拒绝时**不检查余额**（响应不带额度口径）；
- 并发核销 / 预留与额度调整都在 `BEGIN IMMEDIATE` 写事务内串行化，**不会超发**；
  失败不计数；
- **追溯撤销 / 停用密钥不退还历史用量**：核销记录只追加、不改写不删除；
  成功请求**同键重放保留首次结果**（含首次额度口径快照），**不重复计数**。

### `GET /api/v1/subjects/{subject}/redemption-quota`

查询额度口径（主体从未配置过也可查询，表示不限额）：

```bash
curl -sS http://localhost:8000/api/v1/subjects/alice/redemption-quota
```

```json
{
  "subject": "alice",
  "limit": 2,
  "used": 1,
  "reserved": 1,
  "remaining": 1,
  "available": 0,
  "updated_at": "2026-10-06T09:00:00+00:00",
  "previous_limit": null
}
```

未设置额度时：

```json
{ "subject": "alice", "limit": null, "used": 0, "reserved": 0,
  "remaining": null, "available": null,
  "updated_at": null, "previous_limit": null }
```

> `previous_limit` 只在设置 / 调整响应中有意义（本次调整前的额度）；查询接口恒为 `null`。

### `PUT /api/v1/subjects/{subject}/redemption-quota`

设置 / 调整 / 清除额度（请求体只有一个字段 `limit`）：

| 请求体 | 含义 |
| ------ | ---- |
| `{"limit": 2}` | 把成功核销总额度设为非负整数 2（首次设置 / 调高 / 调低都走此接口） |
| `{"limit": null}` | 清除额度，恢复**不限额**（保留 `updated_at` 设置时间） |

- `200 OK`：设置成功，响应返回新口径与 `previous_limit`；
- `409 Conflict`：新额度低于 `used + reserved`（已用量与有效预留之和，响应给出
  `requested_limit`、当前 `limit`、`used`、`reserved`、`remaining`、`available`），
  本次不做任何改动；
- `422`：`limit` 为负数等输入校验失败。

### 额度演练（可直接复制执行，含单链与会签）

下面演练：给主体 `alice` 设置总额度 1 → 单链核销一次成功、第二次因余额不足被拒且
不占键 → 调高到 2 后同一把键成功 → 会签一侧 `alice` 额度不足时两侧均不核销、不占键。
前提同 [密钥轮换演练](#密钥轮换演练轮换前后签名求值与核销)：服务运行在
`http://localhost:8000`，仓库根目录，本地 Python 3.10+，演示主体已播种。

```bash
# 签名助手：生成 root -> service-a 的两级链，末端 subject 为 alice，链 id 取 $1
build_alice_chain() {
  PYTHONPATH=. CHAIN_ID="$1" python3 - <<'PY'
import json, os
from datetime import datetime, timedelta, timezone
from app.security import compute_signature
chain_id = os.environ["CHAIN_ID"]
root_secret = os.environ.get("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")
def token(tid, parent, iss, sub, path, methods, secret):
    t = {"token_id": tid, "parent_id": parent, "chain_id": chain_id,
         "issuer": iss, "subject": sub, "path_pattern": path, "methods": methods,
         "not_before": nb, "not_after": na, "allow_ip": None, "signature": ""}
    t["signature"] = compute_signature(t, secret)
    return t
root_id, leaf_id = chain_id + "-root", chain_id + "-leaf"
print(json.dumps({"chain_id": chain_id, "tokens": [
    token(root_id, None, "root", "service-a", "/files/**", ["GET", "POST"], root_secret),
    token(leaf_id, root_id, "service-a", "alice", "/files/reports/*", ["GET"],
          "demo-secret-service-a"),
]}))
PY
}

# 1) 提交两条末端 subject 都是 alice 的不同链
build_alice_chain quota-demo-1 > /tmp/quota-1.json
build_alice_chain quota-demo-2 > /tmp/quota-2.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/quota-1.json
# → 201，"integrity": {"allow": true, ...}
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/quota-2.json
# → 201，"integrity": {"allow": true, ...}

# 2) 未设置额度：不限额（limit / remaining 均为 null）
curl -sS http://localhost:8000/api/v1/subjects/alice/redemption-quota
# → {"subject":"alice","limit":null,"used":0,"remaining":null,"updated_at":null,...}

# 3) 给 alice 设置成功核销总额度 1
curl -sS -X PUT http://localhost:8000/api/v1/subjects/alice/redemption-quota \
  -H 'Content-Type: application/json' -d '{"limit": 1}'
# → {"subject":"alice","limit":1,"used":0,"remaining":1,"updated_at":"...","previous_limit":null}

# 4) 第一次单链核销：201 成功，quota 返回扣减后口径（used=1, remaining=0）
curl -sS -X POST http://localhost:8000/api/v1/chains/quota-demo-1/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"quota-demo-1-leaf","request_key":"quota-rk-1",
       "request_path":"/files/reports/a","method":"GET"}'
# → 201，"redeemed": true,
#   "quota": {"subject":"alice","limit":1,"used":1,"remaining":0,...}

# 5) 第二次单链核销（另一条链、另一把键）：授权允许但余额不足 →
#    200 明确拒绝，不核销、不占用 request_key
curl -sS -X POST http://localhost:8000/api/v1/chains/quota-demo-2/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"quota-demo-2-leaf","request_key":"quota-rk-2",
       "request_path":"/files/reports/b","method":"GET"}'
# → 200，"redeemed": false, "decision": "allow",
#   "deny_reason": "quota_exhausted",
#   "quota": {"subject":"alice","limit":1,"used":1,"remaining":0,...}

# 6) 额度不得低于已用量：调低到 0 → 409，原额度不变
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X PUT http://localhost:8000/api/v1/subjects/alice/redemption-quota \
  -H 'Content-Type: application/json' -d '{"limit": 0}'
# → 409

# 7) 调高到 2；第 5 步的 request_key 未被占用——同一把键重试即成功（used=2）
curl -sS -X PUT http://localhost:8000/api/v1/subjects/alice/redemption-quota \
  -H 'Content-Type: application/json' -d '{"limit": 2}'
# → ..., "limit":2, "used":1, "remaining":1, "previous_limit":1
curl -sS -X POST http://localhost:8000/api/v1/chains/quota-demo-2/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"quota-demo-2-leaf","request_key":"quota-rk-2",
       "request_path":"/files/reports/b","method":"GET"}'
# → 201，"redeemed": true, "quota": {..."limit":2,"used":2,"remaining":0}
```

会签一侧额度不足（在上面演练的基础上继续，此时 `alice` 已用满 2）：

```bash
# 8) 构造复核链：root -> service-b，末端 subject 为 bob（不设额度 = 不限额）
PYTHONPATH=. python3 - > /tmp/quota-co-r.json <<'PY'
import json
from datetime import datetime, timedelta, timezone
from app.security import compute_signature
root_secret = "dev-root-secret-change-me"
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")
def token(tid, parent, iss, sub, secret):
    t = {"token_id": tid, "parent_id": parent, "chain_id": "quota-demo-r",
         "issuer": iss, "subject": sub, "path_pattern": "/files/reports/*",
         "methods": ["GET"], "not_before": nb, "not_after": na,
         "allow_ip": None, "signature": ""}
    t["signature"] = compute_signature(t, secret)
    return t
print(json.dumps({"chain_id": "quota-demo-r", "tokens": [
    token("quota-demo-r-root", None, "root", "service-b", root_secret),
    token("quota-demo-r-leaf", "quota-demo-r-root", "service-b", "bob",
          "demo-secret-service-b"),
]}))
PY
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/quota-co-r.json
# → 201，"integrity": {"allow": true, ...}

# 9) 再造一条末端为 alice 的全新链（quota-demo-1/2 的末端已核销，不能复用）。
#    alice 额度已用满（2/2），会签时主授权侧余额不足：两侧都不核销、不占键。
build_alice_chain quota-demo-3 > /tmp/quota-3.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/quota-3.json
# → 201 allow
curl -sS -X POST http://localhost:8000/api/v1/co-redemptions \
  -H 'Content-Type: application/json' \
  -d '{
    "primary": {"chain_id": "quota-demo-3", "token_id": "quota-demo-3-leaf"},
    "review":  {"chain_id": "quota-demo-r", "token_id": "quota-demo-r-leaf"},
    "request_key": "quota-co-1",
    "request_path": "/files/reports/x",
    "method": "GET"
  }'
# → 200，"redeemed": false,
#   "primary": {"decision": "deny", "deny_reason": "quota_exhausted",
#               "quota": {"subject":"alice","limit":2,"used":2,"remaining":0,...}},
#   "review":  {"decision": "allow", "deny_reason": null, "quota": null}
#   —— 两侧均未核销、request_key 未占用；bob 的已用量仍为 0。

# 10) 调高 alice 额度后，同一把会签 request_key 重试：201 两侧同时核销
curl -sS -X PUT http://localhost:8000/api/v1/subjects/alice/redemption-quota \
  -H 'Content-Type: application/json' -d '{"limit": 3}' >/dev/null
curl -sS -X POST http://localhost:8000/api/v1/co-redemptions \
  -H 'Content-Type: application/json' \
  -d '{
    "primary": {"chain_id": "quota-demo-3", "token_id": "quota-demo-3-leaf"},
    "review":  {"chain_id": "quota-demo-r", "token_id": "quota-demo-r-leaf"},
    "request_key": "quota-co-1",
    "request_path": "/files/reports/x",
    "method": "GET"
  }'
# → 201，"redeemed": true；
#   primary.quota: used=3, remaining=0；bob 侧 unlimited（quota=null）。
curl -sS http://localhost:8000/api/v1/subjects/bob/redemption-quota
# → {"subject":"bob","limit":null,"used":1,"remaining":null,...}
#   —— bob 虽未设额度，会签参与侧仍照口径计 1 次（设置额度时即计入已用量）。
```

> 重启服务（`docker compose restart`）后再 `GET` 额度：额度行与只追加的核销记录
> 都在同一 SQLite 库中，口径保持不变；撤销某笔历史核销或停用其签发密钥都不会
> 减少 `used`，已成功核销的同键重放也不会让 `used` 再次增加。
> 对应回归测试见 `tests/test_quota.py`。

---

## 短时额度预留演练（可直接复制执行）

下面演练：给主体 `alice` 设置总额度 1 → 预留一份额度（返回 `expires_at`）→
额度查询区分已用 / 预留 / 可用 → 普通核销不得占用被预留的令牌 → 携带预留键、
同访问内容的核销成功并把预留转为已用 → 同键重试回放首次结果 → 过期自动释放。
前提同 [密钥轮换演练](#密钥轮换演练轮换前后签名求值与核销)：服务运行在
`http://localhost:8000`，仓库根目录，本地 Python 3.10+，演示主体已播种。

```bash
# 签名助手：生成 root -> service-a 的两级链，末端 subject 为 alice，链 id 取 $1
build_alice_chain() {
  PYTHONPATH=. CHAIN_ID="$1" python3 - <<'PY'
import json, os
from datetime import datetime, timedelta, timezone
from app.security import compute_signature
chain_id = os.environ["CHAIN_ID"]
root_secret = os.environ.get("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
now = datetime.now(timezone.utc)
nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")
def token(tid, parent, iss, sub, path, methods, secret):
    t = {"token_id": tid, "parent_id": parent, "chain_id": chain_id,
         "issuer": iss, "subject": sub, "path_pattern": path, "methods": methods,
         "not_before": nb, "not_after": na, "allow_ip": None, "signature": ""}
    t["signature"] = compute_signature(t, secret)
    return t
root_id, leaf_id = chain_id + "-root", chain_id + "-leaf"
print(json.dumps({"chain_id": chain_id, "tokens": [
    token(root_id, None, "root", "service-a", "/files/**", ["GET", "POST"], root_secret),
    token(leaf_id, root_id, "service-a", "alice", "/files/reports/*", ["GET"],
          "demo-secret-service-a"),
]}))
PY
}

# 1) 提交两条末端 subject 都是 alice 的链，并设置总额度 1
build_alice_chain rsv-demo-1 > /tmp/rsv-1.json
build_alice_chain rsv-demo-2 > /tmp/rsv-2.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/rsv-1.json
curl -sS -X POST http://localhost:8000/api/v1/chains \
  -H 'Content-Type: application/json' --data @/tmp/rsv-2.json
curl -sS -X PUT http://localhost:8000/api/v1/subjects/alice/redemption-quota \
  -H 'Content-Type: application/json' -d '{"limit": 1}'
# → {"limit":1,"used":0,"reserved":0,"remaining":1,"available":1,...}

# 2) 为 rsv-demo-1 的末端预留一份额度（120 秒）：201，返回到期时间
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-1/reservations \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-1-leaf","reservation_key":"rsv-0001",
       "ttl_seconds":120,"request_path":"/files/reports/a","method":"GET"}'
# → 201，"reserved": true，"expires_at": 接收时刻 + 120s，
#   "quota": {"limit":1,"used":0,"reserved":1,"remaining":1,"available":0,...}

# 2b) 同键同内容重放：200，replayed=true，到期时间与首次一致，不重复占份
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-1/reservations \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-1-leaf","reservation_key":"rsv-0001",
       "ttl_seconds":120,"request_path":"/files/reports/a","method":"GET"}'
# → 200，"replayed": true

# 3) 额度查询区分三分：历史已用 0 / 有效预留 1 / 可用量 0
curl -sS http://localhost:8000/api/v1/subjects/alice/redemption-quota
# → {"limit":1,"used":0,"reserved":1,"remaining":1,"available":0,...}

# 4) 可用量已被预留占满：为另一条链预留 / 普通核销都被拒绝，且不占键
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-2/reservations \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-2-leaf","reservation_key":"rsv-0002",
       "ttl_seconds":60,"request_path":"/files/reports/b","method":"GET"}'
# → 200，"reserved": false, "deny_reason": "quota_exhausted"
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-2/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-2-leaf","request_key":"rsv-access-2",
       "request_path":"/files/reports/b","method":"GET"}'
# → 200，"redeemed": false, "deny_reason": "quota_exhausted"（可用量不含预留份额）

# 5) 普通核销不得占用被预留的令牌：不带预留键核销 rsv-demo-1 被拒绝
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-1/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-1-leaf","request_key":"rsv-access-1",
       "request_path":"/files/reports/a","method":"GET"}'
# → 200，"redeemed": false, "deny_reason": "token_reserved"（不占 request_key）

# 5b) 携带预留键但访问内容不符（路径不同）：reservation_mismatch，不占键、不计已用
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-1/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-1-leaf","request_key":"rsv-access-1",
       "request_path":"/files/reports/WRONG","method":"GET",
       "reservation_key":"rsv-0001"}'
# → 200，"redeemed": false, "deny_reason": "reservation_mismatch"

# 6) 携带预留键、同访问内容：核销成功，同一事务内预留转为已用
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-1/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-1-leaf","request_key":"rsv-access-1",
       "request_path":"/files/reports/a","method":"GET",
       "reservation_key":"rsv-0001"}'
# → 201，"redeemed": true，
#   "quota": {"limit":1,"used":1,"reserved":0,"remaining":0,"available":0,...}

# 6b) 成功核销同键重试（request_key + 预留键一致）：回放首次结果
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-1/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-1-leaf","request_key":"rsv-access-1",
       "request_path":"/files/reports/a","method":"GET",
       "reservation_key":"rsv-0001"}'
# → 200，"replayed": true，quota 与首次一致（used=1，不重复计数）

# 7) 调低额度不得侵占预留：先为 rsv-demo-2 预留一份（此前可用量已随核销用满，
#    需先把额度调高到 2），再尝试调低到 1 -> 409（used=1 + reserved=1）
curl -sS -X PUT http://localhost:8000/api/v1/subjects/alice/redemption-quota \
  -H 'Content-Type: application/json' -d '{"limit": 2}' >/dev/null
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-2/reservations \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-2-leaf","reservation_key":"rsv-0003",
       "ttl_seconds":120,"request_path":"/files/reports/b","method":"GET"}'
# → 201
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X PUT http://localhost:8000/api/v1/subjects/alice/redemption-quota \
  -H 'Content-Type: application/json' -d '{"limit": 1}'
# → 409（1 < used 1 + reserved 1；调低到 2 不变，预留到期后才可调低）

# 8) 过期自动释放：等 120 秒（或换 ttl_seconds=1 重做一次）后，
#    预留不再占额度，rsv-demo-2 可直接普通核销
sleep 125
curl -sS http://localhost:8000/api/v1/subjects/alice/redemption-quota
# → {"limit":2,"used":1,"reserved":0,"remaining":1,"available":1,...}
curl -sS -X POST http://localhost:8000/api/v1/chains/rsv-demo-2/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token_id":"rsv-demo-2-leaf","request_key":"rsv-access-2",
       "request_path":"/files/reports/b","method":"GET"}'
# → 201，"redeemed": true（第 4 步的 request_key 当时未占用，这里直接成功）
```

> 预留只在**主体已设额度**时可用（未设额度 = 不限额，预留返回
> `deny_reason="quota_unset"`）；预留与核销都会**实时重算**验签 / 撤销 /
> 密钥停用 / 权限——预留后若令牌被撤销或密钥被停用，携带匹配预留键的核销
> 仍会被拒绝（不占 `request_key`、不计已用，预留保留至到期）。
> 对应回归测试见 `tests/test_reservation.py`。

---

## 规范化 JSON 与签名（重要）

签名覆盖除 `signature` 外的下列字段（固定集合、固定键顺序无关，因为规范化时按键排序）：

```
token_id, parent_id, chain_id, issuer, subject,
path_pattern, methods, not_before, not_after, allow_ip
```

规则：

1. **规范化 JSON**（RFC 8785 风格）：无多余空白；键按 UTF-16 码元升序；
   不转义非 ASCII；`methods` 排序后参与签名（集合顺序无关）；
2. 时间统一渲染为 UTC：`YYYY-MM-DDTHH:MM:SS[.ffffff]Z`。
   **因此提交时的时间字符串应使用 UTC 的 `Z` 形式**（如 `2026-01-01T00:00:00Z`），
   否则带偏移量（`+08:00`）的原始文本与服务规范化结果不一致会导致验签失败；
3. 用签发者的 HMAC 密钥对规范化字节串做 `HMAC-SHA256`，输出 64 位小写 hex 填入 `signature`。

Python 侧可直接复用 `app.security`：

```python
from app.security import compute_signature
token = { ...除 signature 外的字段... }
token["signature"] = compute_signature(token, issuer_secret)
```

使用其他语言/`curl` 时，请严格按上述规则自行构造规范化报文。

### 路径 glob 语义

- 以 `/` 开头，`*` 匹配单个非空路径段，`**` 只能作为**末段**且匹配任意数量段（含 0 段）：
  - `/files/**` 匹配 `/files`、`/files/a`、`/files/a/b/c`；
  - `/files/*` 只匹配 `/files/<单段>`；
  - 其余段为字面量精确匹配。
- 收窄判定按段比较：父 `*` 接受子为 `*` 或字面量；父字面量只接受相同字面量；
  子在父的 `**` 前结束（如 `/files` 收窄自 `/files/**`）合法。

### 收窄规则汇总

| 维度     | 规则                                                                 |
| -------- | -------------------------------------------------------------------- |
| 路径     | 子模式允许的所有具体路径必须被父模式覆盖                             |
| 方法     | `子方法集合 ⊆ 父方法集合`                                            |
| 时间窗   | `[子.nb, 子.na) ⊆ [父.nb, 父.na)`                                    |
| IP 网段  | 父无限制→子可加限制；父有限制而子取消→拒绝；都有→子网段必须是父子网段 |

---

## 完整性失败原因码

| reason                    | 触发条件                                   |
| ------------------------- | ------------------------------------------ |
| `missing_root`            | 没有 `parent_id=null` 的令牌               |
| `multiple_roots`          | 存在多个根授权                             |
| `duplicate_id`            | 同一 `token_id` 重复出现                   |
| `broken_link`             | `parent_id` 指向不存在的令牌               |
| `cycle`                   | 沿 `parent_id` 上行检测到环                |
| `branch`                  | 同一父令牌被两个子令牌引用（链不允许分叉） |
| `disconnected`            | 令牌无法从根授权到达                       |
| `unknown_issuer`          | 签发主体未注册，无法取密钥（提交时未注册即永久拒绝，事后注册不翻转旧链） |
| `bad_signature`           | HMAC 验签不通过                            |
| `issuer_mismatch`         | 根签发者不是配置根主体，或委托者 ≠ 父主体  |
| `path_widens`             | 子路径相对父路径构成放大                   |
| `method_widens`           | 方法集合放大                               |
| `time_window_widens`      | 时间窗放大                                 |
| `ip_widens`               | IP 网段放大                                |
| `revoked`                 | 求值时该节点自身（或其祖先）已被生效撤销   |
| `key_deactivated`         | 该节点签发主体在链锁定代次的密钥已因疑似失陷被停用（与请求时间无关，不可撤销，轮换不解除） |
| `quota_exhausted`         | 既有授权 / 撤销 / 停用检查均通过，但链末端 subject 的可用额度（`limit - used - reserved`）已用尽（仅核销 / 会签 / 预留响应的 `deny_reason` 使用，不写入轨迹） |
| `quota_unset`             | 预留要求主体已设额度，但该 subject 未设置额度（仅预留响应 `deny_reason` 使用） |
| `token_reserved`          | 目标令牌持有未过期的有效预留：普通单链核销 / 会签不得占用被预留的令牌（仅核销 / 会签响应 `deny_reason` 使用） |
| `reservation_mismatch`    | 核销携带的预留键不存在 / 已过期，或链、令牌、访问内容（路径 / 方法 / 来源 IP / 请求体）与预留不符（仅核销响应 `deny_reason` 使用） |

---

## 环境变量

| 变量                     | 默认值                         | 说明                                   |
| ------------------------ | ------------------------------ | -------------------------------------- |
| `DATABASE_PATH`          | `/data/capabilities.db`        | SQLite 文件路径（目录自动创建）        |
| `ROOT_PRINCIPAL`         | `root`                         | 根授权唯一合法签发者                   |
| `ROOT_HMAC_SECRET`       | `dev-root-secret-change-me`    | 根主体 HMAC 密钥，**生产必须覆盖**     |
| `SEED_DEMO_PRINCIPALS`   | `true`                         | 是否在启动时播种演示主体               |

---

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 路由：提交/重放/冲突/查询/求值/撤销/影响清单/一次性核销/双主体会签/密钥轮换/失陷密钥停用/链末端 subject 核销额度/短时额度预留
│   ├── models.py      # Pydantic 模型与输入校验
│   ├── security.py    # 规范化 JSON、HMAC、glob、收窄原语、内容指纹
│   ├── engine.py      # 结构/签名/签发者/密钥代次停用/收窄/请求级验证引擎、链末端识别与轨迹
│   ├── database.py    # SQLite 初始化与迁移、主体密钥代次/密钥停用/链/撤销/影响清单/核销/主体核销额度/短时额度预留持久化
│   └── config.py      # 环境变量配置
├── scripts/demo_chain.py
├── tests/             # pytest：209 个用例（端到端 API、原语单测、撤销审计、撤销影响清单、一次性核销、双主体会签、密钥轮换、unknown_issuer 冻结、失陷密钥停用、链末端 subject 跨链核销额度、短时额度预留）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 运行测试

```bash
pip install -r requirements-dev.txt
pytest -q
```
