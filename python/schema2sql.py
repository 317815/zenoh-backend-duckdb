#!/usr/bin/env python3
"""
简单的Schema到DDL转换器
输入: evedoc.py --flat 的输出
输出: DuckDB DDL

规则:
- 一级字段: 按类型映射到DuckDB类型
- JSON value类型: 存储为JSON类型
"""

import sys
import re

def parse_flat_line(line):
    """解析flat输出的一行: field: type"""
    line = line.strip()
    if not line or ':' not in line:
        return None
    
    field_path, field_type = line.split(':', 1)
    field_path = field_path.strip()
    field_type = field_type.strip()
    
    return {
        'path': field_path,
        'type': field_type,
        'is_top_level': '.' not in field_path and not field_path.endswith('[]')
    }

def get_duckdb_type(field_type):
    """类型映射: JSON Schema -> DuckDB"""
    type_mapping = {
        'string': 'VARCHAR',
        'integer': 'BIGINT',
        'number': 'DOUBLE',
        'boolean': 'BOOLEAN',
        'object': 'JSON',
        'array': 'JSON'
    }
    
    # 处理数组类型 (如 number[])
    if field_type.endswith('[]'):
        return 'JSON'
    
    return type_mapping.get(field_type, 'VARCHAR')

def generate_ddl(flat_lines, table_name="flow_events"):
    """生成DDL"""
    
    # 解析所有字段
    fields = []
    for line in flat_lines:
        field = parse_flat_line(line)
        if field:
            fields.append(field)
    
    # 只处理一级字段
    top_level_fields = [f for f in fields if f['is_top_level']]
    
    # 生成DDL
    ddl_lines = [
        f"-- 从 evedoc.py --flat 输出生成的 DuckDB DDL",
        f"-- 表名: {table_name}",
        "",
        f"CREATE TABLE IF NOT EXISTS {table_name} ("
    ]
    
    # 生成列定义
    column_definitions = []
    for field in top_level_fields:
        field_name = field['path']
        duckdb_type = get_duckdb_type(field['type'])
        column_definitions.append(f"    {field_name} {duckdb_type}")
    
    # 添加列定义到DDL
    for i, column_def in enumerate(column_definitions):
        if i < len(column_definitions) - 1:
            ddl_lines.append(column_def + ",")
        else:
            ddl_lines.append(column_def)
    
    # 结束CREATE TABLE语句
    ddl_lines.append(");")
    
    return "\n".join(ddl_lines)

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python3 simple_schema2ddl.py <flat_output_file> [table_name]", file=sys.stderr)
        print("示例: python3 simple_schema2ddl.py flat_output.txt flow_events", file=sys.stderr)
        sys.exit(1)
    
    flat_file = sys.argv[1]
    table_name = sys.argv[2] if len(sys.argv) > 2 else "flow_events"
    
    try:
        # 读取flat输出
        with open(flat_file, 'r', encoding='utf-8') as f:
            flat_lines = f.readlines()
        
        # 生成DDL
        ddl = generate_ddl(flat_lines, table_name)
        
        # 输出DDL
        print(ddl)
        
    except FileNotFoundError:
        print(f"错误: 找不到文件 {flat_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
