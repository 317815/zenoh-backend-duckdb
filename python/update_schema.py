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
# 多层嵌套函数字段定义 - 支持函数包含函数的架构
# =============================================================================

# 基础函数字段集合
F_EveAddCommonOptions = [
    "suricata_version", "host", "pcap_filename", "metadata", "ether"
]

F_CreateEveFlowId = ["flow_id", "parent_id"]

F_CreateEveHeader = [
    "timestamp",F_CreateEveFlowId, "sensor_id", "in_iface", "pcap_cnt", "event_type",
    "vlan", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "ip_v",
    "icmp_type", "icmp_code", "pkt_src",
    F_EveAddCommonOptions
]
F_CreateEveHeaderWithTxId = [F_CreateEveHeader, "tx_id"]
F_CreateEveHeaderFromFlow = [
    "timestamp", F_CreateEveFlowId, "in_iface", "event_type",
     "vlan", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "ip_v",
     "icmp_type", "icmp_code", "response_icmp_type", "response_icmp_code", "spi"
]

F_EvePacket = ["packet", "packet_info"]
F_EveAddVerdict = ["verdict"]
F_EveAddMetadata = ["traffic", "metadata"]
F_SimpleApplayerLogger = ["ftp", "tls", "ssh", "dns", "mdns", "modbus", "enip", "dnp3", "ftp_data", "tftp", "krb5", "quic", "sip", "rfb", "pop3", "mqtt", "pgsql", "websocket", "ldap", "template", "rdp", "bittorrent_dht"]


# 复合函数字段集合 - 支持多层嵌套包含
# 基于 SURICATA_EVENT_TYPE_MAPPING.md 中的函数分析

# Flow事件 (output-json-flow.c) - CreateEveHeaderFromFlow + EveFlowLogJSON
F_EveAddAppProto = ["app_proto", "app_proto_ts", "app_proto_tc", "app_proto_orig", "app_proto_expected"]
F_EveFlowLogJSON = [F_EveAddAppProto, "flow", F_EveAddCommonOptions, "tcp"]
F_JsonFlowLogger = [F_CreateEveHeaderFromFlow, F_EveFlowLogJSON]

# =============================================================================
# 完整事件类型定义 - 每个事件类型一个完整代码块
# =============================================================================

# ===== NetFlow事件 (output-json-netflow.c) =====
F_CreateEveHeaderFromNetFlow = [
    "timestamp", "flow_id", "event_type", "src_ip", "dest_ip", 
    "src_port", "dest_port", "proto", "in_iface", "vlan", 
    "icmp_type", "icmp_code", "spi"
]
F_NetFlowLogEveToServer = ["app_proto", "netflow"]
F_NetFlowLogEveToClient = ["app_proto", "netflow"]
F_JsonNetFlowLogger = [F_CreateEveHeaderFromNetFlow, F_NetFlowLogEveToServer, F_EveAddCommonOptions, 
                       F_CreateEveHeaderFromNetFlow, F_NetFlowLogEveToClient, F_EveAddCommonOptions]

# ===== HTTP事件 (output-json-http.c) =====
F_EveHttpLogJSON = ["http"]
F_JsonHttpLogger = [F_CreateEveHeaderWithTxId, F_EveHttpLogJSON, "xff"]

# ===== TLS事件 (output-json-tls.c) =====
F_JsonTlsLogger = [F_CreateEveHeader, "tls"]

# ===== DNS事件 (output-json-dns.c) =====
F_JsonDnsLoggerToServer = [F_CreateEveHeader, "dns"]
F_JsonDnsLoggerToClient = [F_CreateEveHeader, "dns"]  
F_SCDnsLogJson = ["dns"]
F_JsonDnsLogger = [F_JsonDnsLoggerToServer, F_JsonDnsLoggerToClient, F_CreateEveHeader, F_SCDnsLogJson]

# ===== SMTP事件 (output-json-smtp.c) =====
F_EveEmailLogJson = ["email"]
F_JsonSmtpLogger = [F_CreateEveHeaderWithTxId, "smtp", F_EveEmailLogJson]

# ===== MQTT事件 (output-json-mqtt.c) =====
F_SCMqttLoggerLog = ["mqtt"]
F_JsonMQTTLogger = [F_CreateEveHeader, F_SCMqttLoggerLog]

# ===== NFS事件 (output-json-nfs.c) =====
F_JsonNFSLogger = [F_CreateEveHeader, "rpc", "nfs"]

# ===== SMB事件 (output-json-smb.c) =====
F_JsonSMBLogger = [F_CreateEveHeaderWithTxId, "smb"]

# ===== IKE事件 (output-json-ike.c) =====
F_SCIkeLoggerLog = ["ike"]
F_JsonIKELogger = [F_CreateEveHeader, F_SCIkeLoggerLog]

# ===== DHCP事件 (output-json-dhcp.c) =====
F_SCDhcpLoggerLog = ["dhcp"]
F_JsonDHCPLogger = [F_CreateEveHeader, F_SCDhcpLoggerLog]

# ===== PGSQL事件 (output-json-pgsql.c) =====
F_SCPgsqlLogger = ["pgsql"]
F_JsonPgsqlLogger = [F_CreateEveHeader, F_SCPgsqlLogger]

# ===== DCERPC事件 (output-json-dcerpc.c) =====
F_JsonDCERPCLogger = [F_CreateEveHeader, "dcerpc"]

# ===== MDNS事件 (output-json-mdns.c) =====
F_SCMdnsLogJson = ["mdns"]
F_JsonMdnsLogger = [F_CreateEveHeader, F_SCMdnsLogJson]

# ===== 使用JsonGenericLogger的事件类型 (Rust实现) =====
F_SCHttp2LogJson = ["http2"]  # rust/src/http2/logger.rs:298
F_SCSshLogJson = ["ssh"]  # rust/src/ssh/logger.rs:83
F_SCModbusToJson = ["modbus"]  # rust/src/modbus/log.rs:24
F_SCTftpLogJsonRequest = ["tftp"]  # rust/src/tftp/log.rs:37
F_EveFTPLogCommand = ["ftp"]  # output-json-ftp.c:49
F_SCKrb5LogJsonResponse = ["krb5"]  # rust/src/krb/log.rs:77
F_SCQuicLogJson = ["quic"]  # rust/src/quic/logger.rs:157
F_SCSipLogJson = ["sip"]  # rust/src/sip/log.rs:60
F_SCRfbJsonLogger = ["rfb"]  # rust/src/rfb/logger.rs:131
F_SCWebSocketLoggerLog = ["websocket"]  # rust/src/websocket/logger.rs:51
F_SCEnipLoggerLog = ["enip"]  # rust/src/enip/logger.rs:1893
F_SCLdapLoggerLog = ["ldap"]  # rust/src/ldap/logger.rs:355
F_SCPop3LoggerLog = ["pop3"]  # rust/src/pop3/logger.rs:58
F_SCRdpToJson = ["rdp"]  # rust/src/rdp/log.rs:27
F_SCBittorrentDhtLogger = ["bittorrent_dht"]  # rust/src/bittorrent_dht/logger.rs:134

# ===== PacketSubModule事件类型 =====

# ===== Alert事件 (output-json-alert.c) =====
F_AlertJsonHeader = ["tx_id", "tx_guessed", "alert"]
F_AlertJsonTunnel = ["tunnel"]
F_AlertAddFiles = ["files"]
F_AlertJsonStreamData = ["payload", "payload_length", "payload_printable"]
F_AlertAddPayload = ["payload", "payload_length", "payload_printable"]
F_FrameJsonLogOneFrame = ["frame"]
F_AlertAddFrame = [F_FrameJsonLogOneFrame]
F_AlertJson = [F_CreateEveHeader, F_AlertJsonHeader, F_AlertJsonTunnel, F_AlertAddFiles, F_EveAddAppProto, "direction", "flow", F_AlertJsonStreamData, F_AlertAddPayload, "stream", F_AlertAddFrame, F_EvePacket, "capture_file", F_EveAddVerdict]
F_AlertJsonDecoderEvent = [F_CreateEveHeader, F_AlertJsonHeader, F_AlertJsonTunnel, F_EvePacket, "capture_file", F_EveAddVerdict]
F_JsonAlertLogger = [F_AlertJson, F_AlertJsonDecoderEvent]

# ===== Anomaly事件 (output-json-anomaly.c) =====
F_AnomalyDecodeEventJson = [F_CreateEveHeader, "anomaly", F_EvePacket]
F_AnomalyAppLayerDecoderEventJson = [F_CreateEveHeader, F_CreateEveHeaderWithTxId, "anomaly"]
F_AnomalyJson = [F_AnomalyDecodeEventJson, F_AnomalyAppLayerDecoderEventJson]
F_JsonAnomalyLogger = [F_AnomalyJson]

# ===== Drop事件 (output-json-drop.c) =====
F_DropLogJSON = [F_CreateEveHeader, "direction", "drop", F_EveAddVerdict, F_AlertJsonHeader]
F_JsonDropLogger = [F_DropLogJSON]

# ===== Stream_TCP事件 (output-eve-stream.c) =====
F_EveStreamLogger = [F_CreateEveHeader, "direction", "stream_tcp", "events", "reason"]

# ===== ARP事件 (output-json-arp.c) =====
F_JsonArpLogger = [F_CreateEveHeader, "arp"]

# ===== Metadata事件 (output-json-metadata.c) =====
F_MetadataJson = [F_CreateEveHeader, F_EveAddMetadata]
F_JsonMetadataLogger = [F_MetadataJson]

# ===== Frame事件 (output-json-frame.c) =====
F_FrameJsonLogOneFrame = ["frame"]
F_FrameJsonUdp = [F_CreateEveHeader, "app_proto", F_FrameJsonLogOneFrame]
F_FrameJson = [F_FrameJsonUdp, F_CreateEveHeader, "app_proto", F_FrameJsonLogOneFrame]
F_JsonFrameLogger = [F_FrameJson]

# ===== FileSubModule事件类型 =====
# ===== Fileinfo事件 (output-json-file.c) =====
F_JsonBuildFileInfoRecord = [F_CreateEveHeader, "http", "smtp", "email", "rpc", "nfs", "smb", F_SimpleApplayerLogger, "app_proto", "fileinfo", "xff"]
F_FileWriteJsonRecord = [F_JsonBuildFileInfoRecord]
F_JsonFileLogger = [F_FileWriteJsonRecord]

# ===== StatsSubModule事件类型 =====
# ===== Stats事件 (output-json-stats.c) =====
F_JsonStatsLogger = ["timestamp", "event_type", "stats"]

# ===== Engine事件 (util-debug.c) =====
F_SCLogMessageJSON = ["timestamp", "log_level", "event_type", "engine"]

# ===== Inspectedrules事件 (detect-engine-profile.c) =====
F_RulesDumpTxMatchArray = [F_CreateEveHeaderWithTxId, "app_proto", "inspectedrules"]
F_RulesDumpMatchArray = [F_CreateEveHeader, "app_proto", "inspectedrules"]

# 事件类型到函数字段集合的映射 - 支持多层嵌套包含架构
# 按照Suricata注册顺序: Flow → Tx → Packet → File → Stats
EVENT_TYPE_FUNCTIONS = {
    # ===== OutputRegisterFlowSubModule (2个) =====
    "flow": [F_JsonFlowLogger],       # output-json-flow.c:419 (JsonFlowLogger)
    "netflow": [F_JsonNetFlowLogger], # output-json-netflow.c:282 (JsonNetFlowLogger双记录)
    
    # ===== OutputRegisterTxSubModule 系列 (28个) =====
    
    # 有独立封装函数的 (12个)
    "http": [F_JsonHttpLogger],       # output-json-http.c:450
    "tls": [F_JsonTlsLogger],         # output-json-tls.c:506
    "dns": [F_JsonDnsLogger],         # output-json-dns.c:407
    "smtp": [F_JsonSmtpLogger],       # output-json-smtp.c:73
    "mqtt": [F_JsonMQTTLogger],       # output-json-mqtt.c:68
    "nfs": [F_JsonNFSLogger],         # output-json-nfs.c:74
    "smb": [F_JsonSMBLogger],         # output-json-smb.c:62
    "ike": [F_JsonIKELogger],         # output-json-ike.c:78
    "dhcp": [F_JsonDHCPLogger],       # output-json-dhcp.c:58
    "pgsql": [F_JsonPgsqlLogger],     # output-json-pgsql.c:67
    "dcerpc": [F_JsonDCERPCLogger],   # output-json-dcerpc.c:27
    "mdns": [F_JsonMdnsLogger],       # output-json-mdns.c:47
    
    # 使用JsonGenericLogger的 (16个) - CreateEveHeader + Rust LogTx函数 (JsonGenericLogger:1012)
    "http2": [F_CreateEveHeader, F_SCHttp2LogJson],     # rust/src/http2/logger.rs:298
    "ssh": [F_CreateEveHeader, F_SCSshLogJson],         # rust/src/ssh/logger.rs:83
    "modbus": [F_CreateEveHeader, F_SCModbusToJson],    # rust/src/modbus/log.rs:24
    "tftp": [F_CreateEveHeader, F_SCTftpLogJsonRequest], # rust/src/tftp/log.rs:37
    "ftp": [F_CreateEveHeader, F_EveFTPLogCommand],     # output-json-ftp.c:49
    "krb5": [F_CreateEveHeader, F_SCKrb5LogJsonResponse], # rust/src/krb/log.rs:77
    "quic": [F_CreateEveHeader, F_SCQuicLogJson],       # rust/src/quic/logger.rs:157
    "sip": [F_CreateEveHeader, F_SCSipLogJson],         # rust/src/sip/log.rs:60
    "rfb": [F_CreateEveHeader, F_SCRfbJsonLogger],      # rust/src/rfb/logger.rs:131
    "websocket": [F_CreateEveHeader, F_SCWebSocketLoggerLog], # rust/src/websocket/logger.rs:51
    "enip": [F_CreateEveHeader, F_SCEnipLoggerLog],     # rust/src/enip/logger.rs:1893
    "ldap": [F_CreateEveHeader, F_SCLdapLoggerLog],     # rust/src/ldap/logger.rs:355
    "pop3": [F_CreateEveHeader, F_SCPop3LoggerLog],     # rust/src/pop3/logger.rs:58
    "rdp": [F_CreateEveHeader, F_SCRdpToJson],          # rust/src/rdp/log.rs:27
    "bittorrent_dht": [F_CreateEveHeader, F_SCBittorrentDhtLogger], # rust/src/bittorrent_dht/logger.rs:134
    
    # ===== OutputRegisterPacketSubModule (7个) =====
    "alert": [F_JsonAlertLogger],      # output-json-alert.c:869
    "anomaly": [F_JsonAnomalyLogger],  # output-json-anomaly.c:282
    "drop": [F_JsonDropLogger],        # output-json-drop.c:326
    "stream_tcp": [F_EveStreamLogger], # output-eve-stream.c:300
    "arp": [F_JsonArpLogger],          # output-json-arp.c:69
    "metadata": [F_JsonMetadataLogger], # output-json-metadata.c:83
    "frame": [F_JsonFrameLogger],      # output-json-frame.c:400
    
    # ===== OutputRegisterFileSubModule (1个) =====
    "fileinfo": [F_JsonFileLogger],    # output-json-file.c:230
    
    # ===== OutputRegisterStatsSubModule (1个) =====
    "stats": [F_JsonStatsLogger],      # output-json-stats.c:330 (不使用CreateEveHeader)
    
    # ===== 特殊事件类型 (不使用标准注册模式) =====
    "engine": [F_SCLogMessageJSON],    # util-debug.c:198 (不使用CreateEveHeader)
    # "inspectedrules": [F_RulesDumpTxMatchArray, F_RulesDumpMatchArray],  # detect-engine-profile.c:34,78 - 暂时注释
}

def resolve_fields(item):
    """递归解析字段，支持多层嵌套"""
    if isinstance(item, str):
        # 直接字段名
        return [item]
    elif isinstance(item, list):
        # 函数字段集合，递归解析每个元素
        all_fields = []
        for sub_item in item:
            all_fields.extend(resolve_fields(sub_item))
        return all_fields
    else:
        return []

def get_function_fields(function_name):
    """获取指定函数的字段列表 - 通过F_变量名获取"""
    f_var_name = f"F_{function_name}"
    if f_var_name in globals():
        func_fields = globals()[f_var_name]
        return resolve_fields(func_fields)
    else:
        print(f"警告: 未找到函数字段定义 {f_var_name}", file=sys.stderr)
        return []

def get_event_type_fields(event_type):
    """获取指定事件类型的所有字段列表"""
    field_sets = EVENT_TYPE_FUNCTIONS.get(event_type, None)
    if not field_sets:
        print(f"警告: 事件类型 {event_type} 没有对应的字段集合", file=sys.stderr)
        return []
    
    # 直接解析字段集合列表
    all_fields = resolve_fields(field_sets)
    
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