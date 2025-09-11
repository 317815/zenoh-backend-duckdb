# Suricata Flow Event Schema 文档

## 概述

本文档描述了如何从 Suricata 源码 `output-json-flow.c` 中分析提取字段，并生成 `flow_schema.json`。该 Schema 定义了 `event_type=flow` 的 JSON 日志格式。

**重要说明**: `flow_schema.json` 是 `schema.json` 的子集，所有字段定义都直接来源于主 schema，确保完全一致性。

## 字段提取结果

### 需要提取的字段及其实现函数

#### `CreateEveHeaderFromFlow` 函数
- **文件**: `suricata/src/output-json-flow.c`
- **生成字段**:
  ```
  timestamp
  flow_id
  event_type
  src_ip
  dest_ip
  src_port
  dest_port
  proto
  ip_v
  in_iface
  vlan
  icmp_type
  icmp_code
  response_icmp_type
  response_icmp_code
  spi
  ```

#### `EveAddAppProto` 函数
- **文件**: `suricata/src/output-json-flow.c`
- **生成字段**:
  ```
  app_proto
  app_proto_ts
  app_proto_tc
  app_proto_orig
  app_proto_expected
  ```

#### `EveAddFlow` 函数
- **文件**: `suricata/src/output-json-flow.c`
- **生成字段**:
  ```
  flow (对象及其所有子字段)
  ```

#### `EveFlowLogJSON` 函数
- **文件**: `suricata/src/output-json-flow.c`
- **生成字段**:
  ```
  tcp (对象及其所有子字段)
  ```

#### `EveAddCommonOptions` 函数
- **文件**: `suricata/src/output-json.c`
- **生成字段**:
  ```
  suricata_version
  host
  pcap_filename
  pkt_src
  metadata
  ether
  ```

## 生成方法

使用 `extract_schema_fields.py` 脚本从 `schema.json` 中提取上述字段：

```bash
python3 extract_schema_fields.py schema.json flow_fields.txt > flow_schema.json
```

## 结论

✅ **源码验证**: 所有字段都在 `suricata/src/output-json-flow.c` 中有对应的生成代码

✅ **子集验证**: `flow_schema.json` 是 `schema.json` 的完整子集，所有字段定义都直接来源于主 schema

## 使用方法

```bash
# 使用默认参数
python3 extract_schema_fields.py > flow_schema.json

# 指定字段文件
python3 extract_schema_fields.py flow_fields.txt > flow_schema.json

# 指定 schema 和字段文件
python3 extract_schema_fields.py schema.json flow_fields.txt > flow_schema.json
```

## 文件说明

- **`flow_schema.json`**: 最终的 JSON Schema 文件
- **`flow_fields.txt`**: 需要提取的字段列表
- **`extract_schema_fields.py`**: 通用的字段提取脚本
