# 跨安全区网络流量镜像授权模拟器

一套从零实现的**双边授权 + 最小导出**模拟器：安全团队只允许经发送区与
接收区双方批准、且双方签发机构相互独立的连接元数据，进入接收区的诊断
视图。

* 纯 Python 3.12 标准库 + SQLite，无第三方依赖；
* 输入全部为本地合成数据，地址只取 RFC 5737 / RFC 3849 文档网段；
* **无抓包、无套接字、无任何外部服务访问**。

## 1. 目录结构

```
mirror_auth/            可执行实现包
  __main__.py           python -m mirror_auth 入口
  cli.py                apply-policy / explain / export / verify 等命令
  models.py             连接与策略事件的数据模型、校验
  cidr.py               IPv4/IPv6 同族 CIDR 匹配（不逐地址展开）
  timeutil.py           UTC 半开时间区间
  engine.py             代次快照折叠、规则匹配、逐字段双边审批配对
  reference.py          独立暴力参考实现（测试交叉核对专用）
  storage.py            SQLite：代次/事件/回执，WAL 快照隔离
  export.py             流式暂存、代次核对、原子回执、故障恢复
  verifier.py           按绑定代次独立核对产物摘要与字段证据
  streaming.py          JSONL 流式读写与摘要
  generator.py          合成连接/策略生成器与手工演示夹具
  explain.py            explain 渲染（只输出理由与证据，不含字段值）
tests/                  6 个测试模块，含十万连接规模测试
run_tests.py            一键测试入口
```

## 2. 快速开始

```bash
# 生成演示夹具（13 条连接 + 三代策略）
python -m mirror_auth generate demo --outdir demo-data

# 逐代发布策略（代次单调递增，单事务原子发布）
python -m mirror_auth apply-policy --db work/policy.db --batch demo-data/policy-gen1.jsonl
python -m mirror_auth apply-policy --db work/policy.db --batch demo-data/policy-gen2.jsonl
python -m mirror_auth apply-policy --db work/policy.db --batch demo-data/policy-gen3.jsonl

# 解释每条连接的裁定（不打印任何实际字段值）
python -m mirror_auth explain --db work/policy.db --connections demo-data/connections.jsonl

# 导出：流式写不可变暂存产物，事务内核对代次并公布回执
python -m mirror_auth export --db work/policy.db --workdir work \
    --connections demo-data/connections.jsonl \
    --receiver-zone zone-b --request-id req-001

# 独立核对：按回执绑定的代次与输入重算摘要和逐字段证据
python -m mirror_auth verify --db work/policy.db --workdir work \
    --connections demo-data/connections.jsonl --request-id req-001

# 故障恢复 / 列回执
python -m mirror_auth recover --db work/policy.db --workdir work
python -m mirror_auth receipts --db work/policy.db
```

大规模合成输入：

```bash
python -m mirror_auth generate connections --count 100000 --seed 20261120 --out big.jsonl
```

## 3. 授权规则

### 3.1 连接与字段

每条连接含不可变 `connection_id`、事件时间、源/目的安全区、源/目的 IP、
传输协议、目的端口，以及合成扩展字段（`bytes_total`、`packets`、
`duration_ms`、`app_hint`、`risk_score`）。

固定基础字段（连接 ID 与五元组的每个成员）与扩展字段**受同一条逐字段
审批规则约束**，不存在默认放行的字段。

### 3.2 策略事件

三类事件在同一批次内原子发布：

| 事件 | 含义 |
|---|---|
| `approval` | 追加一条审批，携带允许导出的字段集合 |
| `deny` | 追加一条显式拒绝 |
| `revocation` | 引用某审批，从 `effective_from` 起撤回其授权 |

策略携带：负责安全区、负责方向（`send`/`recv`）、对端安全区、两侧
CIDR、协议、端口**闭区间**、有效时间**半开区间** `[valid_from, valid_until)`、
签发机构、字段集合。

### 3.3 匹配顺序

1. 按连接方向定位两侧规则：发送侧 `zone=src_zone, direction=send`，
   接收侧 `zone=dst_zone, direction=recv`，且 `peer_zone` 对得上；
2. 两侧分别匹配同族 CIDR（IPv4/IPv6 不跨族）、协议、目的端口闭区间、
   事件时间半开区间；
3. **任一侧命中显式拒绝 → 整条连接禁止导出**（窄前缀拒绝因此可以覆盖
   宽前缀审批），解释输出排序首条拒绝（按规则 ID 字典序）；
4. 无拒绝时**逐字段**判定：必须同时存在一个发送审批和一个接收审批，
   两者都覆盖该字段、在事件时间有效，且**签发机构不同**；
5. 逐字段枚举审批对，绝不把两侧审批拼接成整条连接的一份批准；
6. 证据取字典序最小的合法 `(发送审批 ID, 接收审批 ID)` 元组。

字段被拒的原因严格区分：

* `missing_one_side_approval`：发送侧或接收侧缺覆盖该字段的有效审批；
* `authorities_not_independent`：两侧审批都在，但机构相同。

### 3.4 撤回与代次

* 策略按单调代次发布，每批在单个 SQLite 事务内提交，读者要么看到
  整代、要么看不到，不存在半批策略；
* 撤回把目标审批的有效窗口截断为
  `[valid_from, min(valid_until, effective_from))`，截断后窗口为空则
  审批消失；多次撤回取最早生效点；
* 旧代次查询只读取截至该代的事件，**忠实返回该版裁定**；新的导出
  请求只能绑定当前代次。

## 4. 导出协议与可恢复性

1. 在读事务内绑定当前代次并构建不可快照旧；
2. 按输入顺序**流式**裁定，逐条写入 `work/artifacts/<请求>.<随机>.jsonl.partial`，
   完成后 `os.replace` 落地为不可变文件（此后永不修改）；
3. 提交阶段在 `BEGIN IMMEDIATE` 事务内重新核对代次：
   * 代次已变化 → 回滚、删除暂存产物、返回 `stale`（退出码 4）；
   * 代次一致 → 同事务插入回执并提交；
4. 读者**只通过回执**查看结果，没有回执的文件对任何命令不可见；
5. 重放：相同 `request_id` + 相同输入摘要 → 返回原回执；
   相同 `request_id` + 不同输入 → 拒绝冲突（退出码 3）；
6. 崩溃恢复：`recover` 删除所有无回执指向的孤儿文件（含 `.partial`），
   之后同一请求可幂等重新提交。

输入摘要对“每行去空白后的原始 UTF-8 字节 + 换行”做 SHA-256（每行仍
经过 JSON 解析与连接校验），与记录内容、记录顺序严格绑定，空行差异
不影响摘要。产物只包含**至少有一个获准字段**的连接；连接 ID 和五元组
成员仅在对应字段获准时写入。

## 5. verify 独立核对

`verify` 不信任产物本身，而是：

1. 重算输入摘要并与回执比对；
2. 重算产物文件 SHA-256 并与回执比对；
3. 按回执**绑定的代次**重建快照，对输入逐条重放裁定，逐行比对记录数、
   顺序、字段集合与每字段审批证据；
4. 额外核查证据中的两个审批确实存在、方向分别为 send/recv、机构相互
   独立且都覆盖该字段。

任一项失败即整体报错并返回非零退出码。另有 `mirror_auth.reference`
暴力参考实现（直接遍历原始事件、现算 CIDR、显式枚举全部审批对），
测试用它与引擎在全部小样本与大规模抽样上逐字段交叉核对。

## 6. 规模特性

* 连接按 JSONL 逐行解析、单条常驻内存，不累积全量连接或产物；
* CIDR 只做网络对象包含判断，**不逐地址展开**；建索引时把每个 CIDR
  预算成整数区间，匹配热路径只做整数比较；
* 规则按 `(区, 方向, 对端区, 协议)` 预分桶并按规则 ID 排序，单条
  连接只扫描少量候选，证据配对可提前终止；
* 导出为单趟流式：每行只解析一次，输入摘要、裁定、产物摘要同时完成；
* 实测（本机 CPython 3.12）10 万连接：导出约 33 秒、独立核对约 3 秒，
  稳态内存峰值约 1.7MB；1 万与 10 万连接峰值同量级，证明驻留不随
  连接总量增长。

## 7. 运行测试

```bash
python run_tests.py            # 全部测试（含 10 万连接规模测试）
python -m unittest discover -s tests -t .
```

## 8. 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 业务/校验/核对失败 |
| 2 | 命令行参数错误 |
| 3 | 同请求 ID 输入冲突 |
| 4 | 提交时代次已变化（过时） |
