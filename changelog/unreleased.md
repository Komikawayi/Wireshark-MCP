# Unreleased

## English

### Added

- `wireshark_analyze_protocol` gains four Bluetooth Low Energy protocol values
  (the tool surface stays at 52): `ble_devices` (advertising device inventory:
  frame counts, names, manufacturer company IDs, TxAdd address type, dual-address
  same-name detection), `ble_scan_activity` (active scanners from SCAN_REQ
  aggregation with scanned-target distribution), `ble_gatt_timeline` (semantic
  ATT/GATT operation timeline — Read Request, Write Request, Notification, etc. —
  for both over-the-air btle and HCI snoop/H4 captures, with services and handle
  labels resolved from the discovery exchange itself), and `ble_connections`
  (connection lifecycle: HCI sessions per handle with link parameters, parameter
  updates, session duration, HCI error-code attribution on disconnects, plus
  over-the-air CONNECT_IND frames with LL parameters). `wireshark_open_file`
  recommends these values with their `protocol` argument for captures containing
  `btle`, `btatt`, `bthci_acl`, `bthci_evt`, or `bthci_cmd`.

## Fixed

- Truncated captures no longer fail every tool: when a capture ends mid-packet
  (exactly what a sniffer killed with pkill leaves behind), tshark exits 14
  while still dissecting the rows it read. The client previously rejected any
  non-zero exit; it now downgrades exit 14 with output present to a success
  envelope carrying the "cut short" note on `stderr`, with the same downgrade
  in the streaming field path. A `truncated_capture.pcap` fixture integration
  test pins the behavior.

## 中文

### 新增

- `wireshark_analyze_protocol` 新增四个蓝牙低功耗（BLE）协议值（工具面保持
  52 个）：`ble_devices`（广播设备清单：帧数、设备名、厂商 company ID、TxAdd
  地址类型判别，以及双地址同名设备识别）、`ble_scan_activity`（通过 SCAN_REQ
  聚合发现主动扫描者，含被扫目标分布）、`ble_gatt_timeline`（语义化 ATT/GATT
  操作时间线——Read Request、Write Request、Notification 等——同时支持空口
  btle 抓包与 HCI snoop/H4 抓包，并从发现流程本身还原服务表与句柄语义标注）、
  `ble_connections`（连接生命周期：按句柄聚合的 HCI 会话与链路参数、参数更新、
  会话时长、断链 HCI 错误码归因，以及空口 CONNECT_IND 帧的 LL 层参数）。
  包含 `btle`、`btatt`、`bthci_acl`、`bthci_evt` 或 `bthci_cmd` 协议的抓包，
  `wireshark_open_file` 现在会带着对应 `protocol` 参数推荐这些值。

## Fixed（修复）

- 截断抓包不再让所有工具失败：抓包在包中途被切断时（嗅探工具被 pkill 杀掉正是这种形态），
  tshark 以退出码 14 结束但仍解出有效数据。client 此前对任何非零退出一票否决，
  现在会把退出码 14 且已有输出的情况降级为成功结果，并把"cut short"提示附在
  `stderr` 字段；流式字段路径做同样降级。新增 `truncated_capture.pcap` fixture
  的集成回归测试钉死此行为。
