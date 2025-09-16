#!/usr/bin/env python3
"""
统一的Schema更新工具
输入: schema.json
内置: event_type -> fields映射
输出: ${event_type}_schema.json
"""

import json
import sys
import argparse
import os

# =============================================================================
# 事件类型字段定义
# =============================================================================

# 基础事件头部字段 (来自CreateEveHeader函数)
CREATE_EVE_HEADER_FIELDS = [
    "timestamp", "flow_id", "event_type", "src_ip", "dest_ip", 
    "src_port", "dest_port", "proto", "ip_v", "in_iface", "vlan", 
    "pcap_cnt", "icmp_type", "icmp_code", "pkt_src"
]

# 交易ID字段 (来自CreateEveHeaderWithTxId函数)
CREATE_EVE_HEADER_WITH_TX_ID_FIELDS = ["tx_id"]

# HTTP基础字段 (来自EveHttpLogJSONBasic函数)
EVE_HTTP_LOG_JSON_BASIC_FIELDS = ["http"]

# HTTP扩展字段 (来自EveHttpLogJSONExtended函数)
EVE_HTTP_LOG_JSON_EXTENDED_FIELDS = []

# HTTP头部字段 (来自EveHttpLogJSONHeaders函数)
EVE_HTTP_LOG_JSON_HEADERS_FIELDS = []

# 通用选项字段 (来自EveAddCommonOptions函数)
EVE_ADD_COMMON_OPTIONS_FIELDS = [
    "suricata_version", "host", "pcap_filename", "metadata", "ether"
]

# Flow对象字段 (来自EveAddFlow函数)
EVE_ADD_FLOW_FIELDS = ["flow"]

# 应用协议字段 (来自EveAddAppProto函数)
EVE_ADD_APP_PROTO_FIELDS = [
    "app_proto", "app_proto_ts", "app_proto_tc", "app_proto_orig", "app_proto_expected"
]

# TCP字段 (来自EveFlowLogJSON函数)
EVE_FLOW_LOG_JSON_FIELDS = ["tcp"]

# 函数字段映射
FUNCTION_FIELDS = {
    "CreateEveHeader": CREATE_EVE_HEADER_FIELDS,
    "CreateEveHeaderWithTxId": CREATE_EVE_HEADER_WITH_TX_ID_FIELDS,
    "EveHttpLogJSONBasic": EVE_HTTP_LOG_JSON_BASIC_FIELDS,
    "EveHttpLogJSONExtended": EVE_HTTP_LOG_JSON_EXTENDED_FIELDS,
    "EveHttpLogJSONHeaders": EVE_HTTP_LOG_JSON_HEADERS_FIELDS,
    "EveAddCommonOptions": EVE_ADD_COMMON_OPTIONS_FIELDS,
    "EveAddFlow": EVE_ADD_FLOW_FIELDS,
    "EveAddAppProto": EVE_ADD_APP_PROTO_FIELDS,
    "EveFlowLogJSON": EVE_FLOW_LOG_JSON_FIELDS,
}

# 事件类型函数组合
EVENT_TYPE_FUNCTIONS = {
    "http": ["CreateEveHeader", "CreateEveHeaderWithTxId", "EveHttpLogJSONBasic", 
             "EveHttpLogJSONExtended", "EveHttpLogJSONHeaders", "EveAddCommonOptions"],
    "flow": ["CreateEveHeader", "EveAddFlow", "EveAddAppProto", "EveAddCommonOptions", "EveFlowLogJSON"],
    "alert": ["CreateEveHeader", "EveAddCommonOptions"],
    "dns": ["CreateEveHeader", "EveAddCommonOptions"],
    "tls": ["CreateEveHeader", "EveAddCommonOptions"],
    "smb": ["CreateEveHeader", "CreateEveHeaderWithTxId", "EveAddCommonOptions"],
    "pgsql": ["CreateEveHeader", "EveAddCommonOptions"],
    "mqtt": ["CreateEveHeader", "EveAddCommonOptions"],
    "nfs": ["CreateEveHeader", "EveAddCommonOptions"],
    "ike": ["CreateEveHeader", "EveAddCommonOptions"],
    "dcerpc": ["CreateEveHeader", "EveAddCommonOptions"],
    "arp": ["CreateEveHeader", "EveAddCommonOptions"],
    "mdns": ["CreateEveHeader", "EveAddCommonOptions"],
    "dnp3": ["CreateEveHeader", "EveAddCommonOptions"],
    "dhcp": ["CreateEveHeader", "EveAddCommonOptions"],
    "frame": ["CreateEveHeader", "EveAddCommonOptions"],
    "fileinfo": ["CreateEveHeader", "EveAddCommonOptions"],
    "drop": ["CreateEveHeader", "EveAddCommonOptions"],
    "stream_tcp": ["CreateEveHeader", "EveAddCommonOptions"],
    "inspectedrules": ["CreateEveHeader", "CreateEveHeaderWithTxId", "EveAddCommonOptions"],
    "netflow": ["EveAddCommonOptions"],
    "stats": ["EveAddCommonOptions"],
    "engine": ["EveAddCommonOptions"]
}

def get_function_fields(function_name):
    """获取指定函数的字段列表"""
    return FUNCTION_FIELDS.get(function_name, [])

def get_event_type_functions(event_type):
    """获取指定事件类型的函数列表"""
    return EVENT_TYPE_FUNCTIONS.get(event_type, [])

def get_event_type_fields(event_type):
    """获取指定事件类型的所有字段列表"""
    functions = get_event_type_functions(event_type)
    all_fields = []
    
    for function_name in functions:
        function_fields = get_function_fields(function_name)
        all_fields.extend(function_fields)
    
    # 去重并保持顺序
    seen = set()
    unique_fields = []
    for field in all_fields:
        if field not in seen:
            seen.add(field)
            unique_fields.append(field)
    
    return unique_fields

def get_all_event_types():
    """获取所有支持的事件类型"""
    return list(EVENT_TYPE_FUNCTIONS.keys())

# =============================================================================
# Schema生成核心逻辑
# =============================================================================

def find_all_refs(obj):
    """递归查找对象中所有的 $ref 引用"""
    refs = []
    
    if isinstance(obj, dict):
        if "$ref" in obj:
            refs.append(obj["$ref"])
        for value in obj.values():
            refs.extend(find_all_refs(value))
    elif isinstance(obj, list):
        for item in obj:
            refs.extend(find_all_refs(item))
    
    return refs

def extract_used_defs(schema, used_refs):
    """提取实际被使用的 $defs"""
    used_defs = {}
    
    if "$defs" not in schema:
        return used_defs
    
    for ref in used_refs:
        if ref.startswith("#/$defs/"):
            def_name = ref.replace("#/$defs/", "")
            if def_name in schema["$defs"]:
                used_defs[def_name] = schema["$defs"][def_name]
                print(f"包含 $defs: {def_name}", file=sys.stderr)
    
    return used_defs

def extract_fields(schema_path, fields_to_extract):
    """从主schema中提取指定字段，只包含实际被使用的 $defs"""
    # 读取主schema
    with open(schema_path, 'r', encoding='utf-8') as f:
        main_schema = json.load(f)
    
    # 创建子集schema，只复制基础结构
    subset_schema = {
        "type": main_schema.get("type", "object"),
        "additionalProperties": main_schema.get("additionalProperties", False),
        "required": main_schema.get("required", []),
        "properties": {}
    }
    
    # 从主schema的properties中提取指定字段
    main_properties = main_schema.get("properties", {})
    missing_fields = []
    extracted_fields = []
    
    for field in fields_to_extract:
        if field in main_properties:
            subset_schema["properties"][field] = main_properties[field]
            extracted_fields.append(field)
        else:
            missing_fields.append(field)
    
    # 查找所有被使用的 $ref 引用
    all_refs = find_all_refs(subset_schema["properties"])
    print(f"找到 {len(all_refs)} 个 $ref 引用", file=sys.stderr)
    
    # 提取实际被使用的 $defs
    used_defs = extract_used_defs(main_schema, all_refs)
    if used_defs:
        subset_schema["$defs"] = used_defs
        print(f"包含 {len(used_defs)} 个 $defs 定义", file=sys.stderr)
    else:
        print("没有找到被使用的 $defs 定义", file=sys.stderr)
    
    # 报告结果
    print(f"成功提取 {len(extracted_fields)} 个字段", file=sys.stderr)
    if missing_fields:
        print(f"警告: 以下字段在 schema.json 中未找到: {missing_fields}", file=sys.stderr)
    
    return subset_schema

def generate_event_schema(event_type, schema_path="etc/schema.json"):
    """生成指定事件类型的schema"""
    fields = get_event_type_fields(event_type)
    if not fields:
        return None
    
    schema = extract_fields(schema_path, fields)
    schema["description"] = f"{event_type.upper()}事件Schema，基于Suricata源码分析"
    return schema

def generate_schemas(event_types, schema_path):
    """输入event_types，返回schemas字典"""
    schemas = {}
    for event_type in event_types:
        schema = generate_event_schema(event_type, schema_path)
        if schema:
            schemas[event_type] = schema
        else:
            print(f"❌ {event_type} 生成失败")
    return schemas

def save_schemas(schemas, output_dir):
    """保存schemas到文件，返回event_types和paths"""
    os.makedirs(output_dir, exist_ok=True)
    event_types = []
    paths = []
    
    # 确保output_dir末尾没有斜杠
    output_dir = output_dir.rstrip('/')
    
    for event_type, schema in schemas.items():
        output_file = f"{output_dir}/{event_type}_schema.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(schema, f, indent=2, ensure_ascii=False)
        print(f"✅ {output_file}")
        event_types.append(event_type)
        paths.append(output_file)
    
    return event_types, paths


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="生成Suricata事件类型的JSON Schema",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
示例:
  python3 update_schema.py http                    # 生成HTTP事件schema到当前目录
  python3 update_schema.py all                     # 生成所有事件schema到当前目录
  python3 update_schema.py flow -i etc/schema.json # 指定输入schema文件
  python3 update_schema.py all -o schemas/         # 指定输出目录
  python3 update_schema.py http -i etc/schema.json -C event-type-schemas/  # 完整参数

支持的事件类型: {', '.join(get_all_event_types())}
        """
    )
    
    parser.add_argument('event_type', 
                       help='事件类型名称，或使用 "all" 生成所有事件类型')
    parser.add_argument('-i', '--input', 
                       default='etc/schema.json',
                       help='输入schema文件路径 (默认: etc/schema.json)')
    parser.add_argument('-C', '--directory', 
                       default='.',
                       help='输出目录路径 (默认: 当前目录)')
    
    args = parser.parse_args()
    
    # 验证事件类型
    if args.event_type != "all" and args.event_type not in get_all_event_types():
        print(f"错误: 不支持的事件类型 '{args.event_type}'")
        print(f"支持的事件类型: {', '.join(get_all_event_types())}")
        sys.exit(1)
    
    # 确定要处理的事件类型列表
    event_types = get_all_event_types() if args.event_type == "all" else [args.event_type]
    
    # 统一处理：输入event_types，返回schemas
    schemas = generate_schemas(event_types, args.input)
    
    # 统一处理：保存schemas，返回event_types和paths
    saved_event_types, saved_paths = save_schemas(schemas, args.directory)
    
    # 统一处理：输出结果
    print(f"\n🎉 完成！{len(saved_event_types)}/{len(event_types)} 个schema生成成功")
    if len(saved_event_types) != len(event_types):
        sys.exit(1)

if __name__ == "__main__":
    main()