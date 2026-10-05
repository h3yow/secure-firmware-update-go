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

## 4. 版本推进与防回滚策略

引擎策略判定在签名/完整性通过之后进行：

- 型号不符 → `model_mismatch`
- 目标槽不符（如把 `bootloader` 包装给 `app` 设备）→ `target_mismatch`
- `pkg.Version < installed.Version` → `downgrade`
- `pkg.Version == installed.Version` → `same_version_replay`
- 只有 `pkg.Version > installed.Version` 才允许进入安装
- 另有 `update_in_progress`：已有**另一个**更新在途（已暂存未确认）时的稳定拒绝，
  见第 6 节并发约定

被拒绝时设备当前版本不变，返回结构化 `Outcome{code, reason, from, to, current_after}`。

## 5. 暂存、激活、确认与回滚（崩溃安全）

设备以本地文件模拟 **A/B 双物理槽 + 原子启动指针**：

- 每个槽位有独立的 `slot-A.json/slot-A.bin`、`slot-B.*`；
- 全局 `state.json`（JSON，含 `active_slot / 两个槽元数据 / pending / boot_count`）
  一律走 `临时文件 → fsync → rename` 原子替换，任何时刻只有“旧完整态”或“新完整态”；
  临时文件名带进程号与序号（`*.tmp`），两个进程绝不会写同一个临时文件；
- 设备目录里还有一个 `lock` 文件：每个操作（读状态也包括）先对它加排他
  `flock`，**加锁后重新从磁盘读取 `state.json` 并与槽位文件对账**，然后才执行；
  因此跨进程也不会出现“各读各的旧缓存、互相覆盖提交”的丢失更新；
- 打开存储时在锁内清理上次中断遗留的 `*.tmp`，状态以最后一次成功落盘为准。

安装生命周期：

1. **Stage（暂存）**：写入**非活动槽**，活动槽文件绝不被触碰；写入成功后才在
   `state.json` 中登记 `pending{from,to,hash}`。
   - 写入过程中断（`stage.meta / stage.blob / stage.state` 均可注入故障）→ 活动槽
     保持已知良好；重启时 `RecoverOnBoot` 丢弃“已暂存未激活”的内容。
2. **Activate（激活）**：仅在**一次原子 state 落盘**中翻转启动指针并记录
   `boot_count=0`，新镜像以“试运行（trial）”身份运行，等待确认。掉电只会留下翻转
   前或翻转后的完整状态，绝不会出现半新半旧的槽。
3. **Boot（启动恢复）**：
   - 无 pending：正常；
   - pending 存在但活动槽还是旧版（激活前掉电）：丢弃暂存槽，停留旧版；
   - pending 存在且活动槽是新版：第 1 次未确认启动只计数；**第 2 次仍未确认**
     （模拟看门狗/健康检查失败）自动原子回滚到 `pending.FromVersion`。
4. **Confirm（确认）**：新镜像健康后调用，清除 pending，成为新的已知良好版本。
5. **Rollback（显式回滚）**：与自动回滚走同一套原子翻转逻辑，最终状态一致；无 pending
   时回滚是稳定 no-op。

### 幂等保证

- 对同一 `(version, hash)` 重复 Stage：成功且不改动状态；
- 已确认后重复安装同版本：稳定拒绝 `same_version_replay`（确定性的可解释结论）；
- 中断后重试同一更新：干净完成安装（见 `TestRetriedInstallAfterCrashIsStable`）；
- 重复 Confirm / 重复 Rollback / 已知良好态重复 Boot：均返回 `idempotent_noop`；
- 所有入口（库 API `Engine` 与 CLI）共用同一套引擎方法，结论结构完全一致。

故障注入通过 `device.WithFaultHook(func(step string) error)` 实现，测试覆盖
`stage.meta / stage.blob / stage.state / activate.state / revert.state` 等中断点。

## 6. 连续升级、版本保留与并发约定

### 连续升级语义

设备从出厂版本开始可以一轮一轮连续向上安装（v1 → v2 → v3 → …）：每个新版本
**确认健康（confirm）之后，可以立刻接着暂存并激活下一个更高版本**，中间不需要
回滚、清空或重新初始化。每一轮仍走完整管线（验签 → 在途仲裁 → 版本策略 → 暂存
→ 激活 → 确认），每一步都返回结构化 `Outcome`，结论可解释、可复现。

连续升级跨越**密钥轮换窗口**时结论仍然唯一确定：判定只看包内 `KeyID` 对应的那
一把钥及其有效期窗口。旧钥过期后签出的包得到 `key_expired`，新钥生效前签出的包
得到 `key_not_yet_valid`，窗口内两把钥各自独立判定——换钥既不会卡住升级链，也
不会悄悄放行。

### 版本保留（容量下限）与崩溃安全的清理

设备上**恰好保留两个版本**：当前确认运行的版本 + 上一个可以回滚的已知良好版本
（A/B 两个物理槽各居其一）。由此：

- 无在途更新时调用 `rollback`，表示**回退到保留的上一个已知良好版本**（revert）；
  被换下的槽位立即丢弃，设备仍只持有两个版本。
- 历史清理**融合在下一次暂存中**：无在途更新时 `Stage` 直接覆盖存放最旧版本的
  槽位。任何时刻设备目录里只有 `state.json` + 两个槽位的 `slot-*.json/.bin`，
  反复升级、回滚多少轮都不会越积越多（有单测断言文件集合有界）。
- **清理中途断电/写失败是安全的**：覆盖旧槽位时每个文件原子替换、`state.json`
  最后落盘；若崩溃发生在两者之间，`state.json` 记录的槽位元数据与磁盘上的
  `slot-*.json` 不一致。**每次读取或使用设备状态时都会先对账**（不只是开机恢复）：
  无在途更新时若保留槽与磁盘不一致，立即剪掉该槽并落盘，设备停留在已确认的
  已知良好版本上——查状态、回滚、继续安装的结论始终与磁盘实际内容一致，
  不会出现“报告回退到旧版本、磁盘上却是新载荷”的错位，也不会出现
  “既升不上去也回不去”的状态。开机时的 `RecoverOnBoot` 清扫是同一套逻辑
  在启动路径上的兜底。

### 并发与重复提交

并发约定在**两个层面**成立：进程内，引擎用一把互斥锁串行化所有入口
（Install / ConfirmBoot / Rollback / Boot）；跨进程，设备存储对每个操作
（包括读状态）持有设备目录下 `lock` 文件的排他 `flock`，并在加锁后重新
从磁盘加载状态再执行。因此同一台设备上任何时刻**只有一个更新在途**，
与调用方是一个进程还是多个进程无关。

- 两个不同的更新几乎同时到达（同一进程或两个独立进程都一样）：先完成暂存
  的生效，另一个得到稳定结论 `rejected / update_in_progress`——与该包的版本
  高低无关，不会因为“另一个版本更高”而放行；不会出现两个都报成功，也不会
  出现“报成功的那个最后被悄悄覆盖”。有测试真的启动多个独立 OS 进程并发
  安装不同版本，逐轮断言恰好一个 `installed`、其余 `update_in_progress`，
  且设备最终版本与报成功的那个一致。
- **同一份更新重复提交是幂等的**（包括跨进程并发重复）：与在途更新同版本同
  哈希的包会被识别为同一更新，已完成的暂存/激活步骤自动跳过，每个进程都
  得到与单次提交一致的 `installed`；已确认之后再提交同版本则得到
  `same_version_replay`。并发重复提交绝不会把 `state.json` 写坏：写状态
  全程在排他锁内、走唯一临时文件 + 原子替换，任何交错之后状态文件都可读、
  可继续开机恢复与安装。
- 并发的 Confirm / Rollback / Revert 同样是幂等的：一个进程先完成后，另一
  个进程得到 `idempotent_noop` 而不是莫名其妙的失败。
- CLI 与库 API 共用同一个引擎与同一套结论结构，`cmd/fwupdate` 的每条命令只是
  引擎方法的薄封装；有测试把同一串连续升级/回滚操作分别走两条入口并逐步断言
  `Outcome` 完全一致（含被拒绝时的原因码）。

### 兼容范围

- `state.json` 的 schema 仍为 1，旧版本引擎写下的状态文件可直接打开继续使用。
- 设备目录新增一个 `lock` 文件（跨进程互斥用，不含状态）；目录内容仍然
  有界：`state.json + lock + 两个槽位文件`。
- 相对上一轮的行为变化只有两处**放宽**：无在途更新时 `Stage` 允许覆盖保留槽
  （原为拒绝）；无在途更新且有保留版本时 `rollback` 执行 revert（原为 no-op）。
  所有既有的拒绝结论（验签类、策略类）与崩溃恢复行为保持不变。

## 7. 本地验证方法

要求 Go 1.25+（仓库在 Go 1.26 上开发验证），仅用标准库。

```bash
# 全部单元测试（异常/边界链路为主）
go test ./... -v

# 竞态检测
go test -race ./...
```

### CLI 端到端演示（数据默认写在 $TMPDIR/sfw-demo，可用 SFW_HOME 覆盖）

演示信任根内置两把固件钥：`k1`（已过期）与 `k2`（当前有效，处于轮换窗口）。
下面每条命令的预期结论都按实际运行结果写明（`code` / 原因码 /
`current_after`），完整输出为 JSON，含 `reason / from_version / to_version`。

```bash
export SFW_HOME=/tmp/sfw-demo && rm -rf $SFW_HOME

go run ./cmd/fwupdate init                       # 工厂版本 v1，打印完整状态
go run ./cmd/fwupdate build v2.sfw 2             # 用当前有效钥 k2 签名 v2
go run ./cmd/fwupdate install v2.sfw             # => installed, 1->2（试运行）
go run ./cmd/fwupdate install v2.sfw             # => installed（同一更新在途，幂等重试，不重复安装）
go run ./cmd/fwupdate build v1.sfw 1
go run ./cmd/fwupdate install v1.sfw             # => rejected / update_in_progress（v2 在途，先仲裁）
go run ./cmd/fwupdate build v3bad.sfw 3 --tamper # 翻转载荷字节
go run ./cmd/fwupdate install v3bad.sfw          # => rejected / payload_hash_mismatch（验签先于仲裁）
go run ./cmd/fwupdate build v3k1.sfw 3 k1        # 用过期钥签名
go run ./cmd/fwupdate install v3k1.sfw           # => rejected / key_expired

# 试运行未确认：第 1 次 boot 计数并保持试运行（current=2），第 2 次自动回滚
go run ./cmd/fwupdate boot                       # => idempotent_noop, current=2
go run ./cmd/fwupdate boot                       # => rolled_back, current=1

# 显式回滚路径（最终状态与自动回滚一致）
go run ./cmd/fwupdate install v2.sfw             # => installed, 1->2
go run ./cmd/fwupdate rollback                   # => rolled_back, current=1

# 正常升级并确认
go run ./cmd/fwupdate install v2.sfw             # => installed, 1->2
go run ./cmd/fwupdate boot                       # 第 1 次试运行启动
go run ./cmd/fwupdate confirm                    # => confirmed, 成为已知良好 v2

# 确认后再演示版本策略：降级与同版本重放
go run ./cmd/fwupdate install v1.sfw             # => rejected / downgrade
go run ./cmd/fwupdate install v2.sfw             # => rejected / same_version_replay

# 连续升级：确认后直接接着装 v3、v4，不需要回滚/清空/重新初始化
go run ./cmd/fwupdate build v3.sfw 3
go run ./cmd/fwupdate build v4.sfw 4
go run ./cmd/fwupdate install v3.sfw             # => installed, 2->3
go run ./cmd/fwupdate confirm                    # => confirmed, current=3
go run ./cmd/fwupdate install v4.sfw             # => installed, 3->4
go run ./cmd/fwupdate confirm                    # => confirmed, current=4
go run ./cmd/fwupdate status                     # Committed.version=4，Staged.version=3（仅保留上一个）

# 无在途更新时的 rollback = 回退到保留的上一个已知良好版本
go run ./cmd/fwupdate rollback                   # => rolled_back, current=3
go run ./cmd/fwupdate install v4.sfw             # => installed, 3->4（链可以继续向前）
go run ./cmd/fwupdate confirm                    # => confirmed, current=4
```

跨进程并发演示（真的起两个独立进程，任一时刻只有一个更新生效）：

```bash
go run ./cmd/fwupdate build v5.sfw 5
go run ./cmd/fwupdate build v6.sfw 6

# 两个不同的更新同时到达：恰好一个 installed，另一个 update_in_progress；
# 哪个赢取决于时序，但绝不会两个都成功
go run ./cmd/fwupdate install v5.sfw & go run ./cmd/fwupdate install v6.sfw & wait
go run ./cmd/fwupdate status                     # Committed 一定是报成功那个版本

# 同一份更新被两个进程同时提交：两个进程都报 installed（幂等），设备只装上一次
go run ./cmd/fwupdate confirm                    # 先确认上一轮的胜者
go run ./cmd/fwupdate build v7.sfw 7
go run ./cmd/fwupdate install v7.sfw & go run ./cmd/fwupdate install v7.sfw & wait
go run ./cmd/fwupdate status                     # Committed.version=7，状态文件完好可读
```

每个结论都以 JSON 打印 `code / reason / from_version / to_version / current_after`，
拒绝结论带可区分的错误码与判定依据；测试断言失败时同样打印输入（KeyID、版本）与
判定依据（Message / Reason）。
