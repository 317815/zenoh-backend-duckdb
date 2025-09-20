#!/usr/bin/env python3
"""
Unified Schema Generation Tool for Suricata Event Types

This tool generates individual JSON Schema files for each Suricata event type
based on the master schema.json file and predefined field mappings.

Input: schema.json (master schema)
Built-in: event_type -> fields mapping
Output: ${event_type}_schema.json files

Copyright (C) 2025-2035 
Author: Zhenjun zhenjun@netprism.org  
License: GPL-2.0-only
"""

import json
import sys
import argparse
import os

# =============================================================================
# Multi-level Nested Function Field Definitions
# Supports function-containing-function architecture
# =============================================================================

# Basic function field collections
F_EveAddCommonOptions = [
    "suricata_version", "host", "pcap_filename", "metadata", "ether"
]

F_CreateEveFlowId = ["flow_id", "parent_id"]

F_CreateEveHeader = [
    "timestamp", F_CreateEveFlowId, "sensor_id", "in_iface", "pcap_cnt", "event_type",
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

# Composite function field collections - supports multi-level nested inclusion
# Based on function analysis from SURICATA_EVENT_TYPE_MAPPING.md

# Flow events (output-json-flow.c) - CreateEveHeaderFromFlow + EveFlowLogJSON
F_EveAddAppProto = ["app_proto", "app_proto_ts", "app_proto_tc", "app_proto_orig", "app_proto_expected"]
F_EveFlowLogJSON = [F_EveAddAppProto, "flow", F_EveAddCommonOptions, "tcp"]
F_JsonFlowLogger = [F_CreateEveHeaderFromFlow, F_EveFlowLogJSON]

# Complete event type definitions - each event type has one complete code block
# Event types are ordered by Suricata registration sequence

# ===== NetFlow events (output-json-netflow.c) =====
F_JsonNetFlowLogger = [
    F_CreateEveHeader,
    "netflow",
    F_EveAddCommonOptions
]

# ===== HTTP events (output-json-http.c) =====
F_JsonHttpLogger = [F_CreateEveHeaderWithTxId, "http", F_EveAddCommonOptions]

# ===== TLS events (output-json-tls.c) =====
F_JsonTlsLogger = [F_CreateEveHeaderWithTxId, "tls", F_EveAddCommonOptions]

# ===== DNS events (output-json-dns.c) =====
F_JsonDnsLogger = [
    F_CreateEveHeaderWithTxId,
    "dns",
    F_EveAddCommonOptions
]

# ===== SMTP events (output-json-smtp.c) =====
F_JsonSmtpLogger = [F_CreateEveHeaderWithTxId, "smtp", F_EveAddCommonOptions]

# ===== MQTT events (output-json-mqtt.c) =====
F_JsonMqttLogger = [F_CreateEveHeaderWithTxId, "mqtt", F_EveAddCommonOptions]

# ===== NFS events (output-json-nfs.c) =====
F_JsonNfsLogger = [F_CreateEveHeaderWithTxId, "nfs", F_EveAddCommonOptions]

# ===== SMB events (output-json-smb.c) =====
F_JsonSmbLogger = [F_CreateEveHeaderWithTxId, "smb", F_EveAddCommonOptions]

# ===== IKE events (output-json-ike.c) =====
F_JsonIkeLogger = [
    F_CreateEveHeaderWithTxId, "ike", F_EveAddCommonOptions
]

# ===== DHCP events (output-json-dhcp.c) =====
F_JsonDhcpLogger = [F_CreateEveHeaderWithTxId, "dhcp", F_EveAddCommonOptions]

# ===== PGSQL events (output-json-pgsql.c) =====
F_JsonPgsqlLogger = [F_CreateEveHeaderWithTxId, "pgsql", F_EveAddCommonOptions]

# ===== DCERPC events (output-json-dcerpc.c) =====
F_JsonDcerpcLogger = [F_CreateEveHeaderWithTxId, "dcerpc", F_EveAddCommonOptions]

# ===== MDNS events (output-json-mdns.c) =====
F_JsonMdnsLogger = [
    F_CreateEveHeaderWithTxId, "mdns", F_EveAddCommonOptions
]

# ===== Events using JsonGenericLogger (Rust implementation) =====
F_JsonGenericLogger = [
    F_CreateEveHeaderWithTxId,
    F_SimpleApplayerLogger,
    F_EveAddCommonOptions
]

# Event types using JsonGenericLogger
GENERIC_LOGGER_EVENTS = [
    "ftp", "ssh", "modbus", "enip", "dnp3", "ftp_data", "tftp",
    "krb5", "quic", "sip", "rfb", "pop3", "websocket", "ldap",
    "template", "rdp", "bittorrent_dht"
]

# ===== PacketSubModule event types =====

# ===== Alert events (output-json-alert.c) =====
F_AlertJsonHeader = ["alert", F_EvePacket, "payload", "payload_printable", "stream", "host", "files"]
F_JsonAlertLogger = [
    F_CreateEveHeader,
    F_AlertJsonHeader,
    F_EveAddVerdict,
    F_EveAddCommonOptions
]

# ===== Anomaly events (output-json-anomaly.c) =====
F_JsonAnomalyLogger = [
    F_CreateEveHeader, "anomaly", F_EveAddCommonOptions
]

# ===== Drop events (output-json-drop.c) =====
F_JsonDropLogger = [F_CreateEveHeader, F_EveAddVerdict, F_EveAddCommonOptions]

# ===== Stream_TCP events (output-eve-stream.c) =====
F_JsonStreamLogger = [F_CreateEveHeader, "stream", F_EveAddCommonOptions]

# ===== ARP events (output-json-arp.c) =====
F_JsonArpLogger = [F_CreateEveHeader, "arp", F_EveAddCommonOptions]

# ===== Metadata events (output-json-metadata.c) =====
F_JsonMetadataLogger = [F_CreateEveHeader, F_EveAddMetadata, F_EveAddCommonOptions]

# ===== Frame events (output-json-frame.c) =====
F_JsonFrameLogger = [
    F_CreateEveHeader, "frame", F_EveAddCommonOptions
]

# ===== FileSubModule event types =====
# ===== Fileinfo events (output-json-file.c) =====
F_JsonFileLogger = [F_CreateEveHeaderWithTxId, "fileinfo", F_EveAddCommonOptions]

# ===== StatsSubModule event types =====
# ===== Stats events (output-json-stats.c) =====
F_JsonStatsLogger = ["timestamp", "event_type", "stats"]

# ===== Engine events (util-debug.c) =====
F_SCLogMessageJSON = ["timestamp", "event_type", "engine"]

# ===== Inspectedrules events (detect-engine-profile.c) =====
# F_RulesDumpTxMatchArray = ["inspectedrules"]  # Currently commented out
# F_RulesDumpMatchArray = ["inspectedrules"]    # Currently commented out

# Event type to function field collection mapping - supports multi-level nested inclusion architecture
# Ordered by Suricata registration sequence: Flow → Tx → Packet → File → Stats
EVENT_TYPE_FIELD_MAPPING = {
    # ===== OutputRegisterFlowSubModule (2 types) =====
    "flow": [F_JsonFlowLogger],        # output-json-flow.c:1084 (JsonFlowLogger)
    "netflow": [F_JsonNetFlowLogger],  # output-json-netflow.c:282 (JsonNetFlowLogger dual record)

    # ===== OutputRegisterTxSubModule series (28 types) =====
    
    # Events with independent encapsulation functions (12 types)
    "http": [F_JsonHttpLogger],        # output-json-http.c:1030
    "tls": [F_JsonTlsLogger],          # output-json-tls.c:1491
    "dns": [F_JsonDnsLogger],          # output-json-dns.c:1139
    "smtp": [F_JsonSmtpLogger],        # output-json-smtp.c:419
    "mqtt": [F_JsonMqttLogger],        # output-json-mqtt.c:404
    "nfs": [F_JsonNfsLogger],          # output-json-nfs.c:525
    "smb": [F_JsonSmbLogger],          # output-json-smb.c:455
    "ike": [F_JsonIkeLogger],          # output-json-ike.c:404
    "dhcp": [F_JsonDhcpLogger],        # output-json-dhcp.c:237
    "pgsql": [F_JsonPgsqlLogger],      # output-json-pgsql.c:116
    "dcerpc": [F_JsonDcerpcLogger],    # output-json-dcerpc.c:226
    "mdns": [F_JsonMdnsLogger],        # output-json-mdns.c:139
    
    # Events using JsonGenericLogger (16 types) - CreateEveHeader + Rust LogTx function (JsonGenericLogger:1012)
    "ftp": [F_JsonGenericLogger],
    "ssh": [F_JsonGenericLogger],
    "modbus": [F_JsonGenericLogger],
    "enip": [F_JsonGenericLogger],
    "dnp3": [F_JsonGenericLogger],
    "ftp_data": [F_JsonGenericLogger],
    "tftp": [F_JsonGenericLogger],
    "krb5": [F_JsonGenericLogger],
    "quic": [F_JsonGenericLogger],
    "sip": [F_JsonGenericLogger],
    "rfb": [F_JsonGenericLogger],
    "pop3": [F_JsonGenericLogger],
    "websocket": [F_JsonGenericLogger],
    "ldap": [F_JsonGenericLogger],
    "template": [F_JsonGenericLogger],
    "rdp": [F_JsonGenericLogger],
    "bittorrent_dht": [F_JsonGenericLogger],
    
    # ===== OutputRegisterPacketSubModule (7 types) =====
    "alert": [F_JsonAlertLogger],      # output-json-alert.c:2070
    "anomaly": [F_JsonAnomalyLogger],  # output-json-anomaly.c:249
    "drop": [F_JsonDropLogger],        # output-json-drop.c:195
    "stream": [F_JsonStreamLogger],    # output-eve-stream.c:125 (stream_tcp)
    "arp": [F_JsonArpLogger],          # output-json-arp.c:138
    "metadata": [F_JsonMetadataLogger], # output-json-metadata.c:122
    "frame": [F_JsonFrameLogger],      # output-json-frame.c:157
    
    # ===== OutputRegisterFileSubModule (1 type) =====
    "fileinfo": [F_JsonFileLogger],    # output-json-file.c:1077
    
    # ===== OutputRegisterStatsSubModule (1 type) =====
    "stats": [F_JsonStatsLogger],      # output-json-stats.c:330 (does not use CreateEveHeader)
    
    # ===== Special event types (not using standard registration pattern) =====
    "engine": [F_SCLogMessageJSON],    # util-debug.c:198 (does not use CreateEveHeader)
    # "inspectedrules": [F_RulesDumpTxMatchArray, F_RulesDumpMatchArray],  # detect-engine-profile.c:34,78 - temporarily commented
}

def parse_field_recursive(field):
    """Recursively parse fields, supporting multi-level nesting"""
    if isinstance(field, str):
        # Direct field name
        return [field]
    elif isinstance(field, list):
        # Function field collection, recursively parse each element
        result = []
        for sub_field in field:
            result.extend(parse_field_recursive(sub_field))
        return result
    else:
        return []

def get_function_fields(f_var_name):
    """Get field list for specified function - retrieve through F_variable_name"""
    if f_var_name in globals():
        f_var = globals()[f_var_name]
        return parse_field_recursive(f_var)
    else:
        print(f"Warning: Function field definition {f_var_name} not found", file=sys.stderr)
        return []

def get_event_type_fields(event_type):
    """Get all field list for specified event type"""
    if event_type not in EVENT_TYPE_FIELD_MAPPING:
        print(f"Warning: Event type {event_type} has no corresponding field collection", file=sys.stderr)
        return []
    
    # Directly parse field collection list
    field_collections = EVENT_TYPE_FIELD_MAPPING[event_type]
    all_fields = []
    
    for collection in field_collections:
        all_fields.extend(parse_field_recursive(collection))
    
    # Remove duplicates and maintain order
    seen = set()
    unique_fields = []
    for field in all_fields:
        if field not in seen:
            seen.add(field)
            unique_fields.append(field)
    
    return unique_fields

def get_all_event_types():
    """Get all supported event types"""
    return sorted(EVENT_TYPE_FIELD_MAPPING.keys())

# Schema generation core logic

def find_all_refs(obj, refs=None):
    """Recursively find all $ref references in object"""
    if refs is None:
        refs = set()
    
    if isinstance(obj, dict):
        if "$ref" in obj:
            refs.add(obj["$ref"])
        for value in obj.values():
            find_all_refs(value, refs)
    elif isinstance(obj, list):
        for item in obj:
            find_all_refs(item, refs)
    
    return refs

def extract_used_defs(schema, all_refs):
    """Extract actually used $defs"""
    used_defs = {}
    if "$defs" in schema:
        for def_name, def_content in schema["$defs"].items():
            ref_key = f"#/$defs/{def_name}"
            if ref_key in all_refs:
                used_defs[def_name] = def_content
                print(f"Including $defs: {def_name}", file=sys.stderr)
    
    return used_defs

def extract_fields_from_schema(schema_file, field_names):
    """Extract specified fields from master schema, including only actually used $defs"""
    # Read master schema
    with open(schema_file, 'r', encoding='utf-8') as f:
        master_schema = json.load(f)
    
    # Create subset schema, only copy basic structure
    subset_schema = {
        "type": "object",
        "additionalProperties": master_schema.get("additionalProperties", False),
        "required": ["event_type", "timestamp"],
        "properties": {}
    }
    
    # Extract specified fields from master schema properties
    extracted_fields = []
    missing_fields = []
    
    for field_name in field_names:
        if field_name in master_schema.get("properties", {}):
            subset_schema["properties"][field_name] = master_schema["properties"][field_name]
            extracted_fields.append(field_name)
        else:
            missing_fields.append(field_name)
    
    # Find all used $ref references
    all_refs = find_all_refs(subset_schema)
    print(f"Found {len(all_refs)} $ref references", file=sys.stderr)
    
    # Extract actually used $defs
    used_defs = extract_used_defs(master_schema, all_refs)
    if used_defs:
        subset_schema["$defs"] = used_defs
        print(f"Including {len(used_defs)} $defs definitions", file=sys.stderr)
    else:
        print("No used $defs definitions found", file=sys.stderr)
    
    # Report results
    print(f"Successfully extracted {len(extracted_fields)} fields", file=sys.stderr)
    if missing_fields:
        print(f"Warning: Following fields not found in schema.json: {missing_fields}", file=sys.stderr)
    
    return subset_schema

def generate_event_schema(event_type, schema_file):
    """Generate schema for specified event type"""
    field_names = get_event_type_fields(event_type)
    if not field_names:
        return None
    
    schema = extract_fields_from_schema(schema_file, field_names)
    schema["description"] = f"{event_type.upper()} event schema based on Suricata source code analysis"
    
    return schema

def generate_schemas_batch(event_types, schema_file):
    """Input event_types, return schemas dictionary"""
    schemas = {}
    for event_type in event_types:
        try:
            schemas[event_type] = generate_event_schema(event_type, schema_file)
        except Exception as e:
            print(f"❌ {event_type} generation failed: {e}")
            schemas[event_type] = None
    return schemas

def save_schemas_batch(schemas, output_dir):
    """Save schemas to files, return event_types and paths"""
    saved_event_types = []
    saved_paths = []
    
    # Ensure output_dir has no trailing slash
    output_dir = output_dir.rstrip('/')
    
    for event_type, schema in schemas.items():
        if schema is not None:
            try:
                output_file = f"{output_dir}/{event_type}_schema.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(schema, f, indent=2, ensure_ascii=False)
                saved_event_types.append(event_type)
                saved_paths.append(output_file)
            except Exception as e:
                print(f"❌ Failed to save {event_type}: {e}")
    
    return saved_event_types, saved_paths

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Generate JSON Schema for Suricata event types",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 update_schema.py http                    # Generate HTTP event schema to current directory
  python3 update_schema.py all                     # Generate all event schemas to current directory
  python3 update_schema.py flow -i etc/schema.json # Specify input schema file
  python3 update_schema.py all -o schemas/         # Specify output directory
  python3 update_schema.py http -i etc/schema.json -C event-type-schemas/  # Complete parameters

Supported event types: {', '.join(get_all_event_types())}
""")
    
    parser.add_argument('event_type', 
                       help='Event type name, or use "all" to generate all event types')
    parser.add_argument('-i', '--input', default='etc/schema.json',
                       help='Input schema file path (default: etc/schema.json)')
    parser.add_argument('-o', '--output', default='.',
                       help='Output directory path (default: current directory)')
    parser.add_argument('-C', '--change-dir', help=argparse.SUPPRESS)  # Hidden compatibility option
    
    args = parser.parse_args()
    
    # Validate event type
    if args.event_type != "all" and args.event_type not in get_all_event_types():
        print(f"Error: Unsupported event type '{args.event_type}'")
        print(f"Supported event types: {', '.join(get_all_event_types())}")
        sys.exit(1)
    
    # Determine event type list to process
    event_types = get_all_event_types() if args.event_type == "all" else [args.event_type]
    
    # Unified processing: input event_types, return schemas
    schemas = generate_schemas_batch(event_types, args.input)
    
    # Unified processing: save schemas, return event_types and paths
    saved_event_types, saved_paths = save_schemas_batch(schemas, args.output)
    
    # Unified processing: output results
    print(f"\n🎉 Complete! {len(saved_event_types)}/{len(event_types)} schemas generated successfully")
    for event_type, path in zip(saved_event_types, saved_paths):
        print(f"✅ {event_type} -> {path}")

if __name__ == "__main__":
    main()