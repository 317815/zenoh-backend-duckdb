# Schema 工具集

这个目录包含了用于处理JSON Schema的工具集，主要用于从Suricata JSON Schema生成DuckDB DDL。

## 文件说明

### 核心工具
- **`schema2sql.py`** - 主要的Schema到SQL DDL转换器
- **`evedoc.py`** - JSON Schema扁平化工具（来自Suricata项目）
- **`extract_schema.py`** - 从主Schema中提取子集Schema的工具

### Schema文件
- **`schema.json`** - 完整的Suricata JSON Schema（8109行）
- **`flow_schema.json`** - 提取的Flow事件Schema（634行）
- **`flow_schema.txt`** - Flow事件字段列表
- **`flow_schema.md`** - Flow事件Schema文档
- **`test_flow_schema.json`** - 测试用的Flow Schema

## 使用方法

### 1. 生成Flow事件DDL

```bash
# 步骤1: 生成扁平化输出
python3 evedoc.py --flat flow_schema.json > flat_output.txt

# 步骤2: 生成DDL
python3 schema2sql.py flat_output.txt flow_events

# 步骤3: 执行DDL创建表
# 将生成的DDL复制到DuckDB中执行
```

### 2. 从主Schema提取子集

```bash
# 提取指定字段的子集Schema
python3 extract_schema.py schema.json flow_fields.txt > subset_schema.json
```

### 3. 生成其他事件类型的DDL

```bash
# 为其他事件类型生成DDL（如alert、dns等）
python3 evedoc.py --flat schema.json | grep "event_type.*alert" > alert_fields.txt
python3 schema2sql.py alert_fields.txt alert_events
```

## 设计原则

### 边界规则
1. **所有JSON数组** → DuckDB JSON类型
2. **一级对象字段** → DuckDB JSON类型  
3. **其他字段** → 按Schema类型映射到DuckDB类型

### 类型映射
- `string` → `VARCHAR` (带长度限制)
- `integer` → `BIGINT`
- `number` → `DOUBLE`
- `boolean` → `BOOLEAN`
- `array` → `JSON`
- `object` → `JSON`

## 示例输出

生成的DDL示例：
```sql
CREATE TABLE IF NOT EXISTS flow_events (
    timestamp VARCHAR(64),
    flow_id BIGINT,
    event_type VARCHAR(32),
    src_ip VARCHAR(45),
    dest_ip VARCHAR(45),
    src_port BIGINT,
    dest_port BIGINT,
    proto VARCHAR(16),
    vlan JSON,
    flow JSON,
    tcp JSON,
    metadata JSON,
    ether JSON
);
```

## 注意事项

- 确保DuckDB支持JSON类型（DuckDB 0.8.0+）
- JSON字段查询使用`json_extract()`函数
- 建议在常用字段上创建索引以提高查询性能
