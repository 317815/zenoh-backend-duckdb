#!/usr/bin/env python3
"""
通用的 JSON Schema 字段提取工具
从主 schema.json 中提取指定字段，生成子集 schema
只做字段提取，不做任何修改
"""

import json
import sys

def extract_fields(schema_path: str, fields_to_extract: list) -> dict:
    """
    从主 schema 中提取指定字段
    
    Args:
        schema_path: 主 schema 文件路径
        fields_to_extract: 要提取的字段列表
    
    Returns:
        提取的子集 schema
    """
    # 读取主 schema
    with open(schema_path, 'r', encoding='utf-8') as f:
        main_schema = json.load(f)
    
    # 创建子集 schema，保持原有结构
    subset_schema = main_schema.copy()
    subset_schema["properties"] = {}
    
    # 从主 schema 的 properties 中提取指定字段
    main_properties = main_schema.get("properties", {})
    missing_fields = []
    extracted_fields = []
    
    for field in fields_to_extract:
        if field in main_properties:
            # 直接复制整个字段定义（包括所有子字段）
            subset_schema["properties"][field] = main_properties[field]
            extracted_fields.append(field)
        else:
            missing_fields.append(field)
    
    # 报告结果
    print(f"成功提取 {len(extracted_fields)} 个字段", file=sys.stderr)
    if missing_fields:
        print(f"警告: 以下字段在 schema.json 中未找到: {missing_fields}", file=sys.stderr)
    
    return subset_schema

def read_fields_from_file(fields_file: str) -> list:
    """
    从文件中读取字段列表
    
    Args:
        fields_file: 字段文件路径
    
    Returns:
        字段列表
    """
    try:
        with open(fields_file, 'r', encoding='utf-8') as f:
            fields = [line.strip() for line in f if line.strip()]
        return fields
    except FileNotFoundError:
        print(f"错误: 找不到字段文件 {fields_file}", file=sys.stderr)
        sys.exit(1)

def main():
    """
    主函数 - 提取指定字段
    用法: python3 extract_schema_fields.py [schema_file] [fields_file]
    """
    # 获取命令行参数
    if len(sys.argv) >= 3:
        schema_path = sys.argv[1]
        fields_file = sys.argv[2]
    elif len(sys.argv) == 2:
        schema_path = "schema.json"
        fields_file = sys.argv[1]
    else:
        schema_path = "schema.json"
        fields_file = "flow_fields.txt"
    
    # 从文件中读取需要提取的字段
    fields_to_extract = read_fields_from_file(fields_file)
    
    # 提取 schema
    subset_schema = extract_fields(schema_path, fields_to_extract)
    
    # 输出到标准输出
    print(json.dumps(subset_schema, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()