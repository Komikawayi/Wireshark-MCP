# Unreleased

## English

### Added

- Added three dedicated Bluetooth Low Energy (BLE) analysis tools:
  `wireshark_extract_ble_devices` (advertising device inventory: frame counts, device
  names, manufacturer company IDs, TxAdd address type, and dual-address same-name
  detection), `wireshark_detect_ble_scan_activity` (active scanners discovered from
  SCAN_REQ aggregation, with scanned-target distribution), and
  `wireshark_extract_gatt_timeline` (semantic ATT/GATT operation timeline — Read
  Request, Write Request, Notification, etc. — working for both over-the-air btle
  captures and HCI snoop/H4 captures). Tool surface grows from 52 to 55;
  `wireshark_open_file` now recommends these tools for captures containing `btle`,
  `btatt`, or `bthci_acl`.

## 中文

### 新增

- 新增三个蓝牙低功耗（BLE）专用分析工具：`wireshark_extract_ble_devices`（广播
  设备清单：帧数、设备名、厂商 company ID、TxAdd 地址类型判别，以及双地址同名设备
  识别）、`wireshark_detect_ble_scan_activity`（通过 SCAN_REQ 聚合发现主动扫描者，
  含被扫目标分布）、`wireshark_extract_gatt_timeline`（语义化 ATT/GATT 操作时间线
  ——Read Request、Write Request、Notification 等——同时支持空口 btle 抓包与 HCI
  snoop/H4 抓包）。工具面从 52 个扩展到 55 个；包含 `btle`、`btatt` 或 `bthci_acl`
  协议的抓包，`wireshark_open_file` 现在会推荐这些工具。
