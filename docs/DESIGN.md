# 固件安全更新引擎 — 设计与本地验证说明

本仓库是一套**完全本地运行**的固件安全更新引擎模拟：用本地文件模拟固件包、设备端
A/B 槽位状态存储与信任根。整个过程不访问任何网络服务，也不使用任何真实密钥材料；
所有签名密钥都由人类可读的种子字符串经 SHA-256 → Ed25519 确定性派生，仅存在于进程
内存中。

## 1. 目录结构

| 路径 | 职责 |
| --- | --- |
| `pkg/firmware` | 固件包格式、规范化元数据编码、容器序列化、载荷 SHA-256 |
| `pkg/trust` | 本地信任根（受信公钥、有效期、用途）、确定性测试密钥 |
| `pkg/verify` | 信任链判定 + 签名校验 + 完整性校验，按固定顺序给出可区分错误码 |
| `pkg/device` | 文件模拟的 A/B 双槽设备存储，原子落盘、暂存/激活/确认/回滚/掉电恢复 |
| `pkg/update` | 编排引擎：校验 → 版本策略 → 暂存 → 激活，所有入口共用同一结论 |
| `cmd/fwupdate` | 本地 CLI，驱动上述全部流程 |

## 2. 固件包格式

```
"SFW1" | len(metaJSON) | metaJSON | len(signature) | signature | payload
```

- `metaJSON` 为**固定字段顺序的结构体 JSON**（不使用 map），时间统一规范化为 UTC
  RFC3339Nano，因此同一份元数据在任何机器上编码结果一致（`CanonicalEncode`）。
- 签名覆盖元数据 JSON，元数据内含载荷的 SHA-256 与载荷长度，载荷本身不单独签名。
- 容器使用 `magic + 长度前缀`，截断、坏魔数、声明长度不符都会被判定为
  `malformed_package`。

## 3. 信任根与密钥轮换规则

每个受信公钥条目包含：`ID / Ed25519 公钥 / Purpose / NotBefore / NotAfter`。

1. **用途（Purpose）是硬过滤**：`recovery` 用途的密钥永远不能签发普通固件，错用得到
   `key_purpose_mismatch`。
2. **有效期为半开区间 `[NotBefore, NotAfter)`**：恰好在 `NotBefore` 时刻有效，恰好在
   `NotAfter` 时刻已过期（边界有单测覆盖）。
3. **轮换期允许多个密钥同时有效**（旧钥未过期、新钥已生效）。引擎**绝不“逐个试钥、
   静默择优”**：固件包元数据中写明唯一的 `KeyID`，判定只查这把钥：
   - ID 不存在 → `unknown_key`
   - 用途不符 → `key_purpose_mismatch`
   - 早于 NotBefore → `key_not_yet_valid`
   - 晚于/等于 NotAfter → `key_expired`
4. 同一个 `(KeyID, Purpose)` 若注册**互相重叠**的有效期窗口，会在注册时直接报错
   （避免“同一把钥在同一时刻对应两个窗口”的歧义）；首尾相接、不重叠的续期窗口允许
   注册。
5. 测试密钥由 `GenerateTestKey(id, seed, purpose, nb, na)` 用
   `SHA256("sfw-testkey|id|seed|purpose")` 作为 Ed25519 seed 确定性派生：相同入参永远
   得到同一密钥，无密钥文件、无真实密钥材料。

### 校验顺序（首个失败阶段决定唯一错误码）

1. 结构完整性（空字段、签名长度、容器可解析）
2. 信任链：`Lookup(KeyID)` + `Evaluate(KeyID, firmware, now)`
3. Ed25519 签名校验（只针对包内 KeyID 对应的那把公钥）
4. 载荷完整性：重算 SHA-256 并比对元数据，同时核对长度

错误码：`malformed_package / unknown_key / key_not_yet_valid / key_expired /
key_purpose_mismatch / bad_signature / payload_hash_mismatch`，每个 `Result` 都带
`KeyID / Version / Message` 作为判定依据。

## 4. 版本推进、连续升级与防回滚策略

引擎策略判定在签名/完整性通过之后进行：

- 型号不符 → `model_mismatch`
- 目标槽不符（如把 `bootloader` 包装给 `app` 设备）→ `target_mismatch`
- `pkg.Version < installed.Version` → `downgrade`
- `pkg.Version == installed.Version` → `same_version_replay`
- 已有未确认试运行（pending）时：
  - 同一 `(version, hash)` 重试 → `same_version_replay`（稳定幂等拒绝）
  - 其它任何版本 → `trial_unconfirmed`（必须先 confirm 或 rollback，
    否则 A/B 回滚链会出现歧义）
- 只有 `pkg.Version > installed.Version` 且无未确认试运行才允许进入安装。

### 连续升级（chained upgrade）语义

每一轮升级在新镜像 **Confirm（健康确认）** 后即成为当前已知良好版本；上一已知良好版本
原地保留在另一个物理槽，作为唯一回滚目标。此时再装下一版，直接覆盖那个“非当前”槽，
因此设备可以从出厂版本开始一轮轮 `v1 → v2 → v3 → …`：

- 每轮的生命周期相同：`install(试运行) → confirm(已知良好) → install 下一版 …`；
- 轮与轮之间**不需要回滚、清空或重新初始化**，也不会因为历史升过几轮而拒绝后续升级；
- 连续多轮之后，设备当前运行版本严格等于最后装上去并确认的版本；
- 每一步结论（接受/拒绝/回滚）都由结构化 `Outcome{code, reason, from, to, current_after}`
  表达，可解释、可复现，CLI 与库 API 走同一引擎方法。

### 轮换窗口内连续升级

多把固件钥在轮换窗口内同时受信时（见 §3），连续升级链上不同版本可由不同的
`KeyID` 签发：判定永远只查包内写明的那一把钥，旧钥签的包在旧钥过期后得到确定的
`key_expired`，新钥签的同版本包正常放行——换钥不会卡住升级链，也不会静默放行。

被拒绝时设备当前版本不变，返回结构化 `Outcome{code, reason, from, to, current_after}`。

## 5. 两版本容量、确认、回滚与启动对账（崩溃安全）

设备以本地文件模拟 **A/B 双物理槽 + 原子启动指针**。

### 5.1 容量下限：设备上永远只保留两个版本

- 每个槽位有独立的 `slot-A.json/slot-A.bin`、`slot-B.*`；
- 全局 `state.json`（JSON，含 `active_slot / 两个槽元数据 / pending / boot_count`）
  一律走 `临时文件 → rename` 原子替换，任何时刻只有“旧完整态”或“新完整态”。

| 时机 | 活动槽 | 非活动槽 |
| --- | --- | --- |
| 出厂后 | v1（当前） | 空 |
| v2 试运行中 | v2（trial） | v1（回滚目标，受保护） |
| v2 确认后 | v2（当前已知良好） | **v1（保留的上一已知良好，可回滚）** |
| 安装 v3 时 | v2（当前，不被触碰） | v1 被 v3 就地覆盖，随后 pending 指向 2→3 |
| v3 确认后 | v3（当前） | v2（保留的上一已知良好） |

因此无论连续升级、回滚多少轮，设备上可见版本数恒为 **≤ 2（当前 + 一个回滚目标）**：
不会越积越多把设备撑满或拖慢，也不会出现“因为前面升过几轮而拒绝后续升级”。
`status` 输出中：pending 期间非活动槽体现在 `staged`，确认后体现在 `retained`。

### 5.2 安装生命周期

1. **Stage（暂存）**：写入**非活动槽**，活动槽文件绝不被触碰；写入成功后才在
   `state.json` 中登记 `pending{from,to,hash}`。
   - 已有 pending 时：同 `(version, hash)` 重试幂等成功，不同内容拒绝；
   - 无 pending（连续升级的常态）：非活动槽里装的是“保留的上一已知良好”，新升级
     **直接覆盖**它，这是升级链能一路往上走的关键。
   - 写入过程中断（`stage.meta / stage.blob / stage.state` 均可注入故障）→ 活动槽
     保持已知良好。
2. **Activate（激活）**：仅在**一次原子 state 落盘**中翻转启动指针并记录
   `boot_count=0`，新镜像以“试运行（trial）”身份运行，等待确认。
3. **Boot（启动恢复）**：
   - 无 pending：正常；
   - pending 存在但活动槽还是旧版（激活前掉电）：丢弃暂存槽，停留旧版；
   - pending 存在且活动槽是新版：第 1 次未确认启动只计数；**第 2 次仍未确认**
     （模拟看门狗/健康检查失败）自动原子回滚到 `pending.FromVersion`。
   - 丢弃槽位时一律**按版本身份**识别（删除试运行的新版本），绝不按槽位名删文件，
     因此回滚目标槽里的保留版本不会被误删。
4. **Confirm（确认）**：新镜像健康后调用，清除 pending，成为新的已知良好；
   上一版本原地保留为 `retained` 回滚目标。
5. **Rollback（回滚）**，两种情况结论都唯一：
   - pending 存在（试运行未确认）：丢弃试运行版本，原子翻回 `pending.FromVersion`，
     与自动回滚路径最终状态完全一致；
   - 无 pending（已确认）：若非活动槽保留着**严格更旧**的已知良好版本，原子翻回它
     （两槽只是交换角色，新版本仍保留为再次回滚目标，容量仍为 2）；
   - 没有更旧的保留版本（出厂版本或已经回退过一次）：稳定 no-op（`idempotent_noop`）。
6. **Open 时对账（reconcile）**：每次打开存储，在无 pending 的情况下核对每个槽位的
   `.json/.bin` 与 `state.json` 记录（版本 + 载荷 SHA-256）：
   - 活动槽是正在运行的已知良好版本，只做核对，损坏即致命报错（绝不静默改写）；
   - 非活动槽若在“覆盖旧保留版本”中途掉电（槽文件已换、state 未换，或 `.bin` 只写了
     一半），判定为陈旧并整体丢弃（文件 + state 条目），设备仍正常启动活动槽的已知良好；
   - 对账本身幂等：对账过程中再次掉电，重启重复对账即可收敛，不会出现既升不上去也
     回不去的状态。

### 5.3 并发与重复提交约定

- **库入口（多 goroutine 共用一个 Engine）**：所有写操作先做进程内非阻塞 try-lock
  （串行门）。两个升级请求同时到达时恰有一个进入，另一个立即得到
  `rejected / update_busy`（不排队、不择优、结论稳定）；
- **CLI 入口（多进程）**：每个设备目录还有一把非阻塞建议文件锁 `update.lock`
  （Linux `flock`，仅标准库），保证两个 CLI 进程同时操作同一设备时同样恰有一个生效；
  持锁进程崩溃/退出时锁由内核自动释放，不会留下永久拒绝服务的锁；
- 两条入口共用同一引擎方法，逐步结论（含拒绝原因）完全一致；
- **幂等**：同一份更新重复提交——试运行中重试得 `same_version_replay`，确认后重放得
  `same_version_replay`，崩溃后重试同一更新则干净完成安装；设备状态不会被写坏。

故障注入通过 `device.WithFaultHook(func(step string) error)` 实现，测试覆盖
`stage.meta / stage.blob / stage.state / activate.state` 等中断点以及“覆盖保留槽中途掉电”。

## 6. 本地验证方法

要求 Go 1.25+（仓库在 Go 1.26 上开发验证），仅用标准库（文件锁用 `syscall.Flock`）。

```bash
# 全部单元测试（异常/边界/连续升级/并发链路为主）
go test -race -count=1 ./... -v

# 不带 -v 的快速回归
go test -race -count=1 ./...
```

测试日志在 `-v` 下按场景逐步打印“输入（版本、KeyID）→ 判定依据（code/reason）→
current_after”。新增场景与对应用例：

| 场景 | 用例 |
| --- | --- |
| 连续多轮升级 v1→…→v5，每轮确认，恒为两个版本 | `TestContinuousUpgradeChain`、`TestChainedUpgradesKeepOnlyTwoVersions` |
| 升级→回滚→再升级→继续升 | `TestUpgradeRollbackReupgrade` |
| 多轮升级/回滚后历史不堆积 | `TestManyUpgradeRollbackCyclesDoNotAccumulate` |
| 轮换窗口内换钥继续升级、旧钥过期唯一拒绝 | `TestContinuousUpgradeAcrossKeyRotation` |
| 覆盖保留版本中途掉电（.bin / state 前后两个中断点） | `TestCrashWhileOverwritingRetainedSlotRepairs`、`TestCrashAfterRetainedMetaBeforeStateRepairs`、`TestInstallCrashWhileOverwritingHistoryRecovers` |
| 同进程并发：恰一个生效，其余 update_busy | `TestConcurrentInstallsSingleWinner`、`TestConcurrentMixedOpsStayCoherent` |
| 跨入口（两个 Store/CLI 进程）并发 | `TestConcurrentInstallsAcrossEngineInstances`、`TestUpdateLockSerializesInstances` |
| 重复提交幂等 | 上述用例尾部 + `TestStageIdempotentIdenticalContent` 等既有幂等用例 |

### CLI 端到端演示（数据默认写在 $TMPDIR/sfw-demo，可用 SFW_HOME 覆盖）

演示信任根内置三把固件钥：`k1`（已过期）、`k2`（当前有效、12 小时后过期）、
`k3`（12 小时前刚生效）——`k2/k3` 正处轮换窗口，多钥并存。

```bash
export SFW_HOME=/tmp/sfw-demo && rm -rf $SFW_HOME

go run ./cmd/fwupdate init                        # 工厂版本 v1
go run ./cmd/fwupdate build v2.sfw 2             # 轮换窗口内由 k2 签发 v2
go run ./cmd/fwupdate install v2.sfw             # => installed (trial), 1->2
go run ./cmd/fwupdate install v2.sfw             # => rejected / same_version_replay
go run ./cmd/fwupdate install v2.sfw 2>/dev/null  # 两个几乎同时的 CLI（自行再开一个终端）：
# 真重叠时一个 installed，另一个 rejected / update_busy
go run ./cmd/fwupdate confirm                     # => confirmed，v1 保留为回滚目标
go run ./cmd/fwupdate rollback                    # => rolled_back, current=1（回到保留的 v1）
go run ./cmd/fwupdate install v2.sfw             # 无需清空：直接再升回 v2
go run ./cmd/fwupdate confirm

# 连续升级，经过新旧钥交替：
go run ./cmd/fwupdate build v3.sfw 3             # v3 由 k2 签发
go run ./cmd/fwupdate install v3.sfw
go run ./cmd/fwupdate confirm
go run ./cmd/fwupdate build v3k3.sfw 3 k3        # 同版本改由 k3 签：重放
go run ./cmd/fwupdate install v3k3.sfw           # => rejected / same_version_replay
go run ./cmd/fwupdate build v4.sfw 4 k3          # v4 由新钥 k3 签发
go run ./cmd/fwupdate install v4.sfw             # => installed, 3->4（换钥不卡链）
go run ./cmd/fwupdate confirm
go run ./cmd/fwupdate status                      # 只有两个版本：当前 v4 + 保留 v3

go run ./cmd/fwupdate build v1.sfw 1             # 签一个降级包
go run ./cmd/fwupdate install v1.sfw             # => rejected / downgrade
go run ./cmd/fwupdate build v3bad.sfw 3 --tamper
go run ./cmd/fwupdate install v3bad.sfw          # => rejected / payload_hash_mismatch
go run ./cmd/fwupdate build v3k1.sfw 3 k1        # 用过期钥签名
go run ./cmd/fwupdate install v3k1.sfw           # => rejected / key_expired

# 试运行未确认：当前已确认 v4（保留 v3）。装 v5 后第 1 次 boot 仍运行新镜像，
# 第 2 次未确认 boot 自动回滚到 v4。
go run ./cmd/fwupdate build v5.sfw 5 k3
go run ./cmd/fwupdate install v5.sfw              # => installed, 4->5 (trial)
go run ./cmd/fwupdate boot                        # 第 1 次试运行启动，仍为 v5
go run ./cmd/fwupdate boot                        # => rolled_back, current=4
go run ./cmd/fwupdate status                      # 停在可启动的已知良好 v4；
# 未确认试运行 v5 被丢弃，非活动槽为空（v4 在试运行期间一直是受保护的回滚目标）
```

每个结论都以 JSON 打印 `code / reason / from_version / to_version / current_after`，
拒绝结论带可区分的错误码与判定依据；测试断言失败时同样打印输入（KeyID、版本）与
判定依据（Message / Reason）。

## 7. 兼容范围

- 状态文件 `schema=1` 布局不变，仅新增对账读取与 `Retained` 视图字段；旧数据目录可直接
  打开（首次打开若发现无载荷文件的历史槽，只影响对账丢弃，不影响活动槽启动）。
- 平台：文件锁依赖 POSIX `flock`（Linux/macOS 可用）；其余文件语义为本地文件系统
  原子 rename。全程无网络、无真实密钥材料、无第三方依赖。
