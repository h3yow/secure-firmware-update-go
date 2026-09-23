# Secure Firmware Update Engine (local, self-contained)

一套完全本地运行的固件安全更新引擎。用本地文件模拟固件包、设备端 A/B 状态存储与
信任根，使**签名校验、版本推进与失败回滚**在不同入口（一键安装 / 暂存后激活）下
得到一致且可解释的结论。

无任何网络依赖；签名密钥为从种子标签确定性派生的 **Ed25519 测试密钥**，仓库中不
包含、运行时也不接触任何真实密钥材料。

## 目录结构

```
cmd/fwupdate       本地 CLI：初始化信任根/设备、签名、校验、安装、暂存、激活、回滚
internal/demo      演示环境装配（含轮换、过期、未生效、错用途四类密钥）
pkg/verdict        稳定、可区分的失败码与“输入 + 判定依据”解释
pkg/firmware       固件包容器、规范化清单、语义版本
pkg/signing        Ed25519 确定性测试密钥与打包签名
pkg/trust          本地信任根：受信公钥、有效期窗口、用途
pkg/security       信任链 -> 签名 -> 完整性 -> 型号 的有序校验
pkg/device         A/B 槽位、原子写入、掉电恢复、回滚
pkg/update         编排层：版本策略、防回滚、幂等、双入口一致性
```

## 固件包格式

自定界二进制容器（任何截断都能在解析期被发现）：

```
magic "FWPKG01\n"
u32be manifest_len   规范化 JSON 清单（紧凑、字段固定、以 '\n' 结尾）
u32be sig_len        对“清单精确字节”的原始 Ed25519 签名
u8    key_id_len     签名密钥 ID
u64be payload_len    固件负载
```

清单中包含型号 `model`、**目标槽位** `target_slot`、版本 `version`、负载长度与
`SHA-256`。负载哈希在签名覆盖范围内，因此改一个负载字节或一个清单字段都会使校验
失败。签名只对一种精确字节串生效：非规范化清单直接被解析器拒绝。

## 信任根与密钥轮换规则

信任根是本地 JSON（原子写入），每个受信公钥记录：

| 字段 | 含义 |
| --- | --- |
| `id` | 唯一密钥 ID（加载时拒绝重复 ID，保证“按 ID 解析密钥”是全函数） |
| `algorithm` | 仅接受 `ed25519` |
| `public` | 32 字节公钥 |
| `not_before` / `not_after` | 有效期窗口（Unix 秒，**边界包含**） |
| `purposes` | 用途列表；固件签名必须包含 `firmware-signing` |

轮换规则与确定性：

1. **允许多个密钥同时有效**。轮换重叠期内，用旧密钥或新密钥签的包都可被接受，
   但每个包通过其携带的**唯一密钥 ID** 解析到唯一密钥，引擎**从不**在多个匹配
   密钥之间静默择优；一旦出现歧义（例如重复 ID），信任根本身加载即失败。
2. 校验时钟可注入（CLI 的 `--at RFC3339`）。窗口外分别给出
   `signing_key_not_yet_valid` / `signing_key_expired`，用途不符给
   `signing_key_purpose_mismatch`，ID 未知给 `unknown_signing_key`——四类结论
   互不混淆。
3. 演示信任根内置四把确定性密钥：

   | ID | 窗口 | 用途 | 2026-09-23 结论 |
   | --- | --- | --- | --- |
   | `key-fw-2026` | 2026 全年 | firmware-signing | 接受 |
   | `key-fw-2027` | 2027–2028 | firmware-signing | 未生效 |
   | `key-fw-2024` | 2024–2025 | firmware-signing | 已过期 |
   | `key-maint` | 2026 全年 | other | 用途不匹配 |

## 校验顺序（所有入口共用同一条流水线）

固定顺序保证“同一输入在任何入口得到同一失败码”：

1. 容器/清单格式与 schema
2. **信任链**：密钥 ID 已知 → 当前时间在窗口内 → 用途含 `firmware-signing`
3. **签名**：Ed25519 验签覆盖精确清单字节（长度不对也算签名失败）
4. **完整性**：负载长度与 SHA-256 必须等于签名清单中的值
5. **型号**：`model` 必须等于设备型号
6. **版本策略**（编排层）：包版本必须**严格大于**当前活动版本
7. **槽位策略**（编排层）：`target_slot` 必须等于设备计划写入的非活动槽

失败码（`pkg/verdict`）：`malformed_package`、`unknown_signing_key`、
`signing_key_expired`、`signing_key_not_yet_valid`、`signing_key_purpose_mismatch`、
`ambiguous_signing_keys`、`bad_signature`、`payload_tampered`、`model_mismatch`、
`target_mismatch`、`downgrade_rejected`、`same_version_replay`、
`staging_failure`、`nothing_staged`、`staged_image_mismatch`、`no_rollback_target`、
`io_failure`。每次拒绝都打印 `reason / input / basis`（判定依据）。

## 版本与回滚策略

- 版本为严格语义化 `MAJOR.MINOR.PATCH`，按**数值**比较（`1.10.0 > 1.9.0`）。
- 只允许**严格升级**：低版本 → `downgrade_rejected`；同版本重放 →
  `same_version_replay`（版本判定先于槽位判定，所以槽位轮换不会把重放误报成
  `target_mismatch`）。
- A/B 槽位与原子性：
  - 写入永远落在**非活动槽**：先写临时文件 → `fsync` → `rename` 落位，然后才
    原子替换状态文件提交“已暂存”指针。
  - **写入中断**：临时文件被丢弃，状态文件未改，设备仍在已知良好版本。
  - **激活前掉电**：重启后状态只有“完整暂存”或“没有暂存”两种；暂存镜像在
    激活时会从磁盘重新哈希，损坏的暂存会在设备打开时被丢弃。
  - **激活失败（提交前）**：活动槽不变，暂存保留，掉电重启后仍可激活。
- 回滚：激活时旧活动槽被保留为唯一回滚目标；`rollback` 前同样重新校验该槽
  镜像哈希。回滚本身可逆（再回滚一次即恢复新槽）。
- 幂等：同一更新重复 `prepare` 返回相同成功结论；重复 `activate` 在无暂存时
  返回稳定的 `nothing_staged`；重复 `install` 已安装版本稳定返回
  `same_version_replay`。升级 → 回滚 → 再次升级，最终槽位内容哈希与首次升级
  完全一致（有测试断言）。

## 本地验证方法

```bash
go test -race -count=1 ./...
```

或使用 CLI 端到端手动验证：

```bash
go build -o /tmp/fwupdate ./cmd/fwupdate
cd /tmp && rm -rf fwdemo && mkdir fwdemo && cd fwdemo
/tmp/fwupdate init

# 正常升级（一键入口：verify -> stage -> activate）
/tmp/fwupdate sign 1.0.0 key-fw-2026 p1.fwpkg
/tmp/fwupdate verify p1.fwpkg
/tmp/fwupdate install p1.fwpkg
/tmp/fwupdate status

# 分阶段入口：prepare 后掉电也没关系，之后再 activate
/tmp/fwupdate sign 1.1.0 key-fw-2026 p2.fwpkg --target A
/tmp/fwupdate prepare p2.fwpkg
/tmp/fwupdate activate

# 回滚 / 再升级
/tmp/fwupdate rollback

# 异常链路
/tmp/fwupdate tamper p1.fwpkg bad.fwpkg && /tmp/fwupdate verify bad.fwpkg   # payload_tampered
/tmp/fwupdate install p1.fwpkg                                              # same_version_replay
/tmp/fwupdate sign 0.5.0 key-fw-2026 low.fwpkg --target B && /tmp/fwupdate install low.fwpkg  # downgrade
/tmp/fwupdate sign 2.0.0 key-fw-2024 old.fwpkg && /tmp/fwupdate verify old.fwpkg              # expired
/tmp/fwupdate sign 2.0.0 key-fw-2027 nxt.fwpkg && /tmp/fwupdate verify nxt.fwpkg              # not_yet_valid
/tmp/fwupdate sign 2.0.0 key-maint oth.fwpkg && /tmp/fwupdate verify oth.fwpkg                # purpose
# 指定时钟验证轮换边界（重叠期内旧密钥仍可接受）
/tmp/fwupdate verify old.fwpkg --at 2025-06-01T00:00:00Z
```

所有拒绝都以 `[REJECT] code=...` 输出稳定失败码，并附输入与判定依据。
