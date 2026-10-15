# Unreleased

## English

### Added

- `wireshark_analyze_protocol` gains five Bluetooth Low Energy protocol values
  (the tool surface stays at 52): `ble_devices` (advertising device inventory:
  frame counts, names, manufacturer company IDs, TxAdd address type, dual-address
  same-name detection), `ble_scan_activity` (active scanners from SCAN_REQ
  aggregation with scanned-target distribution), `ble_gatt_timeline` (semantic
  ATT/GATT operation timeline — Read Request, Write Request, Notification, etc. —
  for both over-the-air btle and HCI snoop/H4 captures, with services and handle
  labels resolved from the discovery exchange itself), and `ble_connections`
  (connection lifecycle: HCI sessions per handle with link parameters, parameter
  updates, session duration, HCI error-code attribution on disconnects, plus
  over-the-air CONNECT_IND frames with LL parameters), and `ble_pairing`
  (SMP exchange timeline, LE pairing-method inference — Just Works gets a
  low-severity finding — distributed key material with LTK/EDIV/IRK values,
  and SMP failure reason attribution). `wireshark_open_file` recommends
  these values with their `protocol` argument for captures containing `btle`,
  `btatt`, `btsmp`, `bthci_acl`, `bthci_evt`, or `bthci_cmd`.

### Fixed

- BLE pairing inference follows the negotiated SC, either-side MITM, OOB and
  IO-capability rules. Connection sessions stay separate across handle reuse and
  capture interfaces; failed connection attempts do not overwrite active links.
- GATT discovery and pending queries are isolated per connection and ATT server.
  Multi-server results expose scoped `handle_maps` plus per-event `connection`
  and `server`; the legacy flat `handle_map` is retained only for a single server.
- BLE recommendations are alternatives, not an automatic checklist; callers are
  guided to start with `limit=20`. H4 fixtures now encode direction in network
  byte order and real-tshark coverage includes interleaved links and reconnects.
- Legacy exit-code-2 tolerance requires tshark's short-read diagnostic, not just
  nonempty stdout. Partial outputs bypass the stdout-only cache so repeated calls
  retain the capture warning; ordinary read/write failures remain errors.

- Truncated captures no longer fail every tool: when a capture ends mid-packet
  (exactly what a sniffer killed with pkill leaves behind), tshark exits 14
  while still dissecting the rows it read. The client previously rejected any
  non-zero exit; it now downgrades exit 14 with output present to a success
  envelope carrying the "cut short" note on `stderr`, with the same downgrade
  in the streaming field path. A `truncated_capture.pcap` fixture integration
  test pins the behavior.

## 中文

### 新增

- `wireshark_analyze_protocol` 新增五个蓝牙低功耗（BLE）协议值（工具面保持
  52 个）：`ble_devices`（广播设备清单：帧数、设备名、厂商 company ID、TxAdd
  地址类型判别，以及双地址同名设备识别）、`ble_scan_activity`（通过 SCAN_REQ
  聚合发现主动扫描者，含被扫目标分布）、`ble_gatt_timeline`（语义化 ATT/GATT
  操作时间线——Read Request、Write Request、Notification 等——同时支持空口
  btle 抓包与 HCI snoop/H4 抓包，并从发现流程本身还原服务表与句柄语义标注）、
  `ble_connections`（连接生命周期：按句柄聚合的 HCI 会话与链路参数、参数更新、
  会话时长、断链 HCI 错误码归因，以及空口 CONNECT_IND 帧的 LL 层参数），
  以及 `ble_pairing`（SMP 配对时间线、配对方式推断、LTK/EDIV/IRK 密钥分发和失败原因）。
  包含 `btle`、`btatt`、`btsmp`、`bthci_acl`、`bthci_evt` 或 `bthci_cmd` 协议的抓包，
  `wireshark_open_file` 现在会带着对应 `protocol` 参数推荐这些值。

### Fixed（修复）

- BLE 配对推断按双方协商的 SC、任一端 MITM 请求、OOB 和 IO 能力规则判定。
  连接会话按生命周期与抓包接口隔离，句柄复用和失败连接尝试不会覆盖已有会话。
- GATT 发现表及待匹配请求按连接和 ATT 服务端隔离；多服务端结果通过 `handle_maps`
  和每个事件的 `connection`、`server` 标识区分。仅单服务端结果保留全局 `handle_map`。
- BLE 推荐列表按需选择，默认建议从 `limit=20` 开始；H4 测试抓包修正为网络字节序方向头，
  新增真实 tshark 的交错连接、断连和重连测试。
- 旧版 tshark 的退出码 2 仅在诊断明确为截断读取时降级；部分结果绕过纯 stdout 缓存，
  重复调用仍保留截断提示，普通读写失败继续返回错误。

- 截断抓包不再让所有工具失败：抓包在包中途被切断时（嗅探工具被 pkill 杀掉正是这种形态），
  tshark 以退出码 14 结束但仍解出有效数据。client 此前对任何非零退出一票否决，
  现在会把退出码 14 且已有输出的情况降级为成功结果，并把"cut short"提示附在
  `stderr` 字段；流式字段路径做同样降级。新增 `truncated_capture.pcap` fixture
  的集成回归测试钉死此行为。
