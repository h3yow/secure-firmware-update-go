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
- 全局 `state.json`（JSON，schema=1，含 `active_slot / 两个槽元数据 / pending / boot_count`）
  一律走 `临时文件 → rename` 原子替换，任何时刻只有“旧完整态”或“新完整态”；
- 设备目录里还有一个 `store.lock`：所有入口（安装 / 确认 / 回滚 / boot / 读状态 /
  工厂初始化）都通过它做**跨进程**排他（Unix 上是 `flock(LOCK_EX)`），见第 6 节；
- 打开存储时清理上次中断遗留的 `*.tmp`，状态以最后一次成功落盘为准；
- **每次打开存储、以及每次拿到排他锁开始一个事务时，都先做一次“磁盘对账”**
  （reconcile，见下），保证 state.json 声称的版本与磁盘上真实载荷一致。

安装生命周期：

1. **Stage（暂存）**：写入**非活动槽**，活动槽文件绝不被触碰；写入成功后才在
   `state.json` 中登记 `pending{from,to,hash}`。
   - 写入过程中断（`stage.meta / stage.blob / stage.state` 均可注入故障）→ 活动槽
     保持已知良好；重启时 `RecoverOnBoot` 丢弃“已暂存未激活”的内容。
2. **Activate（激活）**：仅在**一次原子 state 落盘**中翻转启动指针并记录
   `boot_count=0`，新镜像以“试运行（trial）”身份运行，等待确认。掉电只会留下翻转
   前或翻转后的完整状态，绝不会出现半新半旧的槽。
3. **Boot（启动恢复）**：每个 boot 入口先做磁盘对账（见第 6 节），随后应用试运行
   策略——
   - 无 pending：正常，返回 `idempotent_noop`（即使当前正跑着刚激活的试运行镜像，
     第 1 次未确认启动也只计数、镜像继续运行）；
   - pending 存在但活动槽还是旧版（激活前掉电）：丢弃暂存槽，停留旧版；
   - pending 存在且活动槽是新版：第 1 次未确认启动只计数；**第 2 次仍未确认**
     （模拟看门狗/健康检查失败）自动原子回滚到 `pending.FromVersion`。
4. **Confirm（确认）**：新镜像健康后调用，清除 pending，成为新的已知良好版本。
5. **Rollback（显式回滚）**：与自动回滚走同一套原子翻转逻辑，最终状态一致；无 pending
   时回滚是稳定 no-op（除非还保留着上一个已知良好版本，此时执行 revert，见第 6 节）。

### 幂等保证

- 对同一 `(version, hash)` 重复 Stage：成功且不改动状态；
- **同一更新在试运行（pending）期间重复安装，包括几乎同时的并发重复提交：稳定得到
  `installed`，状态只落地一次**（不是失败，也不会退回旧版本）；
- 已确认后重复安装同版本：稳定拒绝 `same_version_replay`（确定性的可解释结论）；
- 中断后重试同一更新：干净完成安装（见 `TestRetriedInstallAfterCrash`）；
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
  槽位。任何时刻设备目录里只有 `state.json` + `store.lock` + 两个槽位的
  `slot-*.json/.bin`，反复升级、回滚多少轮都不会越积越多（有单测断言文件集合有界）。

### 磁盘对账（reconcile-on-use）：报告版本必须等于真实在跑的载荷

覆盖旧槽位时每个文件原子替换、`state.json` 最后落盘。但断电/写失败仍可能发生在
“槽文件已换、state.json 还没换”（或反过来、或只换掉一半载荷）的中间点。旧实现只在
`RecoverOnBoot` 里清扫一次，于是**不走开机恢复直接查状态/回滚**时，设备会报一个与
磁盘实际载荷对不上的版本（例如报告回退到旧版，磁盘载荷其实是新的），此后越走越歪。

现在对账在**每次 `Open`、以及每个排他事务开始时**自动执行（“只要状态被重新读取或
使用，就先跟磁盘实际内容对一次账”），判定完全以磁盘为准：

- 对 state.json 里每个有记录的槽，读取 `slot-*.json`（必须可解析，版本与记录一致）
  和 `slot-*.bin`（SHA-256 必须等于记录的 `payload_hash`）；
- **记录存在但磁盘内容对不上 → 该槽判定为坏槽，立即剪掉**（删记录、删文件），坏槽
  永远不会被当成启动目标，也不会被当成“可回滚的已知良好版本”；
- state.json 没记录但磁盘上残留的槽文件（中断的删除遗留）→ 当作未经证实的孤儿文件
  删除，绝不参与启动决策；
- **记录的活动槽坏了、另一个槽健康** → 启动指针原子翻转到唯一健康槽，清掉悬空的
  pending 与 boot 计数：任何中断后设备都停在一个可启动的已知良好版本上；
- 两个槽都坏/都空 → 返回 `no healthy slot` 错误而不是编造一个状态（在本引擎的故障
  模型下不可达，仅用于外部整体损坏的兜底）；
- pending 记录指向的暂存内容已不存在 → 清掉悬空 pending，避免幽灵“在途更新”永久
  挡住后续升级。

对账最多落盘一次，只做“向磁盘事实对齐”的修复，从不凭空生成固件内容。这样：

- 清理旧版本中途断电后，**不经过 boot**，直接 `status`/`rollback`/新开进程安装，
  结论都与磁盘一致；坏掉的旧槽不会再被启用；
- 对账完成后后续升级照常继续（有端到端单测
  `TestInterruptedCleanupReconciledOnReopenWithoutBoot` /
  `TestReconcileWithoutBootInterruptedCleanup` 覆盖）。

### 并发与重复提交（跨进程互斥，不只是进程内锁）

- 设备目录中的 `store.lock` 提供**跨进程**排他锁（Unix `flock(2)`）；进程内同一把
  `Store` 的互斥量与之叠加。引擎的每个入口（`Install / ConfirmBoot / Rollback /
  Boot`，以及读状态）都在**一个排他事务**里完成“重载磁盘状态 → 磁盘对账 → 判定 →
  落盘”，事务期间其他 goroutine 和其他 OS 进程都进不来。
- 持锁进程异常退出时内核会自动释放 flock，不会出现死设备。
- 一次完整的 `Install`（读状态 → 验签 → 在途仲裁 → 版本策略 → 暂存 → 激活）全程
  不释放锁，因此两个独立进程几乎同时升级同一台设备时被**整段串行化**：后到者一定
  看到先到者已经提交的 pending 状态——
  - 两个**不同**的更新：先进入者生效，另一个拿到稳定、可复现的
    `rejected / update_in_progress`，与它的版本高低无关；绝不可能两个都成功，也
    不可能后到者把已经报成功的更新悄悄覆盖掉。谁赢取决于进程调度，但
    “恰好一个 installed、一个 update_in_progress、设备状态自洽”是确定的。
  - **同一份更新**（版本与载荷哈希都相同）重复提交，包括几乎同时提交：后到者识别
    为同一更新，走幂等路径，结论与单次提交一致——两边都得到 `installed`，版本只
    落地一次；之后再提交同版本得到稳定的 `same_version_replay`。并发交错绝不会
    把 `state.json` 与槽文件写得对不上（新事务必先重载+对账再写）。
- CLI 与库 API 共用同一个引擎与同一套结论结构，`cmd/fwupdate` 的每条命令只是
  引擎方法的薄封装；有测试把同一串连续升级/回滚操作分别走两条入口并逐步断言
  `Outcome` 完全一致（含被拒绝时的原因码）。
- 并发约定有**真实跨进程**测试覆盖：`pkg/update` 的
  `TestCrossProcess*` 用 `go test -test.run=...` 真正拉起两个独立 OS 进程打开同一
  设备目录、在同一个栅栏后同时安装，而不是同进程里开 goroutine。

### 兼容范围

- `state.json` 的 schema 仍为 1，旧版本引擎写下的状态文件可直接打开继续使用。
  旧状态若存在 state 与磁盘槽文件不一致，首次打开会被自动对账修复（只向磁盘事实
  对齐）。
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
下面每条命令后的注释是**实跑打印的结论**（`code / 原因码 / current_after`），可直接
对照；先构建一次二进制可避免反复 `go run` 编译：

```bash
go build -o /tmp/fwupdate ./cmd/fwupdate
export SFW_HOME=/tmp/sfw-demo && rm -rf $SFW_HOME

/tmp/fwupdate init                       # 工厂版本 v1，随后打印 status（Committed v1）
/tmp/fwupdate build v2.sfw 2             # 用当前有效钥 k2 签名 v2
/tmp/fwupdate install v2.sfw             # => code=installed, 1->2, current=2（trial）
/tmp/fwupdate install v2.sfw             # => 仍是 installed（pending 期间同一更新幂等重放，2 只落地一次）
/tmp/fwupdate build v1.sfw 1             # 签一个降级包
/tmp/fwupdate install v1.sfw             # => rejected / update_in_progress（此刻 v2 仍在试运行，在途仲裁先于版本策略）
/tmp/fwupdate build v3bad.sfw 3 --tamper # 翻转载荷字节
/tmp/fwupdate install v3bad.sfw          # => rejected / payload_hash_mismatch, current=1
/tmp/fwupdate build v3k1.sfw 3 k1        # 用过期钥签名
/tmp/fwupdate install v3k1.sfw           # => rejected / key_expired, current=1

# 试运行未确认：第 1 次 boot 仍运行新镜像（idempotent_noop, current=2），第 2 次自动回滚
/tmp/fwupdate boot                       # => code=idempotent_noop, to=2, current=2（第 1 次未确认启动，只计数）
/tmp/fwupdate boot                       # => code=rolled_back, 1->2, current=1

# 显式回滚路径（最终状态与自动回滚一致）
/tmp/fwupdate install v2.sfw             # => installed, 1->2, current=2
/tmp/fwupdate rollback                   # => rolled_back（returned ... to known-good 1）, current=1

# 正常升级并确认
/tmp/fwupdate install v2.sfw             # => installed, 1->2
/tmp/fwupdate boot                        # 第 1 次试运行启动：idempotent_noop, current=2
/tmp/fwupdate confirm                    # => confirmed, 1->2, current=2，成为已知良好 v2
/tmp/fwupdate status                     # Committed v2，Staged（保留）v1

# 连续升级：确认后直接接着装 v3、v4，不需要回滚/清空/重新初始化
/tmp/fwupdate build v3.sfw 3
/tmp/fwupdate build v4.sfw 4
/tmp/fwupdate install v3.sfw             # => installed (trial), 2->3
/tmp/fwupdate confirm
/tmp/fwupdate install v4.sfw             # => installed (trial), 3->4
/tmp/fwupdate confirm
/tmp/fwupdate status                     # 当前 v4，仅保留 v3 作为可回滚版本

# 无在途更新时的 rollback = 回退到保留的上一个已知良好版本
/tmp/fwupdate rollback                   # => rolled_back（reverted ... to retained known-good 3）, current=3
/tmp/fwupdate install v4.sfw             # => installed (trial), 3->4，链可以继续向前
/tmp/fwupdate confirm

# 已确认之后再提交同版本，才是版本策略意义上的重放
/tmp/fwupdate install v4.sfw             # => rejected / same_version_replay, current=4
```

> 注意两个容易混淆的时序结论（都是有意设计、且有单测锁定）：
> 1. **试运行（pending）期间**重复安装同一更新 → 幂等 `installed`；重复提交别的更新
>    （哪怕版本更低）→ 先撞上在途仲裁，得到 `update_in_progress`，不会走到降级判定。
> 2. **确认之后**没有在途更新，此时提交同版本 → `same_version_replay`，提交更低版本
>    → `downgrade`。

### 跨进程并发的本地复现

并发仲裁是跨 OS 进程的，可以直接开两个真正的进程同时安装：

```bash
export SFW_HOME=/tmp/sfw-concur && rm -rf $SFW_HOME && mkdir -p $SFW_HOME
cp -r /tmp/sfw-demo/packages $SFW_HOME/   # 复用上面签好的 v2.sfw / v3.sfw
/tmp/fwupdate init >/dev/null
( /tmp/fwupdate install v2.sfw > $SFW_HOME/a.json &
  /tmp/fwupdate install v3.sfw > $SFW_HOME/b.json &
  wait )
grep -h '"code"' $SFW_HOME/a.json $SFW_HOME/b.json   # 必然恰好一个 installed、一个 rejected
grep -l update_in_progress $SFW_HOME/a.json $SFW_HOME/b.json   # 输家文件
```

同一份更新的并发重复提交把两条命令都换成 `install v2.sfw`：两边都打印
`installed / current=2`，设备上 v2 只落地一次，`status` 始终可读。对应的自动化版本
（真的 `exec` 两个测试进程）是 `pkg/update` 里的 `TestCrossProcessDistinctUpdatesSingleWinner`、
`TestCrossProcessDuplicateSubmissionIdempotent` 与 `TestCrossProcessMixedRoundsRepeated`。

每个结论都以 JSON 打印 `code / reason / from_version / to_version / current_after`，
拒绝结论带可区分的错误码与判定依据；测试断言失败时同样打印输入（KeyID、版本）与
判定依据（Message / Reason）。运行带场景说明的详细日志：

```bash
go test -race -count=1 ./... -v 2>&1 | grep -E 'scenario=|step=|concurrent-install'
```
