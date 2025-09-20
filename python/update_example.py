#!/usr/bin/env python3
"""
Schema-based Example Generator for Zenoh Backend DuckDB

This module generates realistic example JSON data files based on JSON Schema definitions
found in the event-type-schemas directory. It creates corresponding example files in the
event-type-examples directory, ensuring data consistency and schema compliance.

Author: Zenoh Backend DuckDB Team
License: GPL-2.0-only
"""

import json
import logging
import os
import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum


class LogLevel(Enum):
    """Logging levels for the application."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class GeneratorConfig:
    """Configuration for the example generator."""
    schema_dir: str = "etc/suricata-evelog-schemas"
    example_dir: str = "etc/suricata-evelog-examples"
    log_level: LogLevel = LogLevel.INFO
    overwrite_existing: bool = True
    max_array_items: int = 5
    min_array_items: int = 1
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self.schema_path = Path(self.schema_dir)
        self.example_path = Path(self.example_dir)


class SampleDataProvider:
    """Provides realistic sample data for various field types."""
    
    def __init__(self):
        self._ip_addresses = [
            "192.168.1.100", "10.0.0.1", "172.16.0.1", 
            "203.0.113.1", "198.51.100.1", "192.0.2.1",
            "192.168.0.50", "10.10.10.1", "172.20.0.100"
        ]
        
        self._hostnames = [
            "example.com", "test.local", "api.service.com",
            "web.example.org", "mail.company.net", "db.internal.local",
            "cdn.example.net", "auth.service.io"
        ]
        
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "curl/7.68.0",
            "Python-urllib/3.9",
            "Wget/1.20.3 (linux-gnu)"
        ]
        
        self._protocols = ["TCP", "UDP", "ICMP", "ICMP6"]
        self._http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        self._dns_types = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT", "SRV"]
        self._alert_categories = [
            "Attempted Information Leak", "Potentially Bad Traffic",
            "Misc Attack", "Web Application Attack", "Trojan Activity",
            "Policy Violation", "Attempted User Privilege Gain"
        ]
        self._alert_actions = ["allowed", "blocked", "dropped", "rejected"]
        self._tls_versions = ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
    
    @property
    def ip_addresses(self) -> List[str]:
        return self._ip_addresses
    
    @property
    def hostnames(self) -> List[str]:
        return self._hostnames
    
    @property
    def user_agents(self) -> List[str]:
        return self._user_agents
    
    @property
    def protocols(self) -> List[str]:
        return self._protocols
    
    @property
    def http_methods(self) -> List[str]:
        return self._http_methods
    
    @property
    def dns_types(self) -> List[str]:
        return self._dns_types
    
    @property
    def alert_categories(self) -> List[str]:
        return self._alert_categories
    
    @property
    def alert_actions(self) -> List[str]:
        return self._alert_actions
    
    @property
    def tls_versions(self) -> List[str]:
        return self._tls_versions


class SchemaValueGenerator:
    """Generates values based on JSON Schema definitions and field semantics."""
    
    def __init__(self, sample_data: SampleDataProvider):
        self.sample_data = sample_data
        self.logger = logging.getLogger(__name__)
    
    def generate_timestamp(self) -> str:
        """Generate fixed ISO8601 formatted timestamp for consistent examples."""
        # Use fixed timestamp for consistent example generation
        fixed_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        return fixed_time.isoformat()
    
    def _infer_string_value_from_name(self, property_name: str) -> Optional[str]:
        """Infer appropriate string value based on property name semantics."""
        name_lower = property_name.lower()
        
        semantic_mappings = {
            'ip': lambda: random.choice(self.sample_data.ip_addresses),
            'hostname': lambda: random.choice(self.sample_data.hostnames),
            'host': lambda: random.choice(self.sample_data.hostnames),
            'timestamp': self.generate_timestamp,
            'user_agent': lambda: random.choice(self.sample_data.user_agents),
            'proto': lambda: random.choice(self.sample_data.protocols),
            'method': lambda: random.choice(self.sample_data.http_methods),
            'category': lambda: random.choice(self.sample_data.alert_categories),
            'action': lambda: random.choice(self.sample_data.alert_actions),
            'version': lambda: "7.0.0",
            'signature': lambda: "ET SCAN Potential Security Event",
            'url': lambda: "/api/v1/endpoint",
            'filename': lambda: "capture.pcap",
            'rrname': lambda: random.choice(self.sample_data.hostnames),
            'rrtype': lambda: random.choice(self.sample_data.dns_types),
            'sni': lambda: random.choice(self.sample_data.hostnames),
        }
        
        for key, generator in semantic_mappings.items():
            if key in name_lower:
                return generator()
        
        return None
    
    def _validate_pattern_constraint(self, pattern: str, value: str) -> bool:
        """Validate if a value matches the given regex pattern."""
        try:
            return bool(re.match(pattern, value))
        except re.error as e:
            self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            return True  # Assume valid if pattern is malformed
    
    def generate_string_value(self, property_name: str, constraints: Dict[str, Any]) -> str:
        """Generate string value based on property name and schema constraints."""
        # Try semantic inference first
        inferred_value = self._infer_string_value_from_name(property_name)
        if inferred_value:
            # Validate against pattern if present
            pattern = constraints.get("pattern")
            if pattern and not self._validate_pattern_constraint(pattern, inferred_value):
                # If semantic value doesn't match pattern, handle special cases
                if "timestamp" in property_name.lower() and "\\d{4}-\\d{2}-\\d{2}T" in pattern:
                    return self.generate_timestamp()
            return inferred_value
        
        # Handle special patterns
        pattern = constraints.get("pattern", "")
        if "\\d{4}-\\d{2}-\\d{2}T" in pattern:
            return self.generate_timestamp()
        
        # Handle enum constraints
        enum_values = constraints.get("enum")
        if enum_values:
            return random.choice(enum_values)
        
        # Default fallback
        return f"example_{property_name}"
    
    def generate_integer_value(self, property_name: str, constraints: Dict[str, Any]) -> int:
        """Generate integer value based on property name and constraints."""
        name_lower = property_name.lower()
        
        # Semantic mappings for integer fields
        semantic_ranges = {
            'port': (1024, 65535),
            'id': (1000000, 9999999),
            'severity': (1, 4),
            'gid': (1, 1),  # Usually 1 for Suricata
            'rev': (1, 10),
            'length': (100, 10000),
            'size': (100, 10000),
            'count': (1, 1000),
            'cnt': (1, 1000),
            'bytes': (1000, 100000),
            'pkts': (10, 1000),
            'packets': (10, 1000),
            'age': (1, 3600),
            'ttl': (1, 86400),
            'status': (200, 599),  # HTTP status codes
        }
        
        # Check semantic mappings
        for key, (min_val, max_val) in semantic_ranges.items():
            if key in name_lower:
                return random.randint(min_val, max_val)
        
        # Use schema constraints
        minimum = constraints.get("minimum", 0)
        maximum = constraints.get("maximum", 1000000)
        
        # Handle enum constraints
        enum_values = constraints.get("enum")
        if enum_values:
            return random.choice([v for v in enum_values if isinstance(v, int)])
        
        return random.randint(minimum, maximum)
    
    def generate_number_value(self, property_name: str, constraints: Dict[str, Any]) -> int:
        """Generate number value as integer (no decimals) based on property name and constraints."""
        # Check constraints
        minimum = constraints.get("minimum", 0)
        maximum = constraints.get("maximum", 1000000)
        multipleOf = constraints.get("multipleOf")
        enum_values = constraints.get("enum")
        
        # If enum values exist, choose from them (prefer integers)
        if enum_values:
            integer_enums = [v for v in enum_values if isinstance(v, int)]
            if integer_enums:
                return random.choice(integer_enums)
            # If no integer enums, convert float enums to int
            return int(random.choice([v for v in enum_values if isinstance(v, (int, float))]))
        
        # If multipleOf is specified, generate integer multiples
        if multipleOf:
            base_value = random.randint(int(minimum // multipleOf), int(maximum // multipleOf))
            return int(base_value * multipleOf)
        
        # Always generate integers for number type
        return random.randint(int(minimum), int(maximum))
    
    def generate_array_value(self, property_name: str, schema: Dict[str, Any], config: GeneratorConfig, root_schema: Optional[Dict[str, Any]] = None) -> List[Any]:
        """Generate array value based on schema definition."""
        items_schema = schema.get("items", {})
        min_items = schema.get("minItems", config.min_array_items)
        max_items = min(schema.get("maxItems", config.max_array_items), config.max_array_items)
        
        count = random.randint(min_items, max_items)
        result = []
        
        for i in range(count):
            item_value = self.generate_value_from_schema(
                f"{property_name}_item_{i}", items_schema, config, root_schema
            )
            result.append(item_value)
        
        return result
    
    def generate_object_value(self, property_name: str, schema: Dict[str, Any], config: GeneratorConfig, root_schema: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate object value based on schema definition."""
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        result = {}
        
        # Generate required properties
        for prop_name in required:
            if prop_name in properties:
                result[prop_name] = self.generate_value_from_schema(
                    prop_name, properties[prop_name], config, root_schema
                )
        
        # Generate ALL optional properties for complete schema coverage
        # This ensures examples demonstrate the full schema structure
        optional_props = [p for p in properties.keys() if p not in required]
        for prop_name in optional_props:
            result[prop_name] = self.generate_value_from_schema(
                prop_name, properties[prop_name], config, root_schema
            )
        
        return result
    
    def resolve_ref(self, root_schema: Dict[str, Any], ref_path: str) -> Dict[str, Any]:
        """Resolve $ref references in JSON Schema."""
        if not ref_path.startswith("#/"):
            raise ValueError(f"Unsupported reference format: {ref_path}")

        # Remove "#/" prefix and split path
        path = ref_path[2:]
        parts = path.split('/')
        
        current = root_schema
        for part in parts:
            if part not in current:
                raise ValueError(f"Reference not found: {ref_path}")
            current = current[part]
        
        return current
    
    def handle_typeless_schema(self, property_name: str, schema: Dict[str, Any], config: GeneratorConfig, root_schema: Optional[Dict[str, Any]] = None) -> Any:
        """Handle schemas without explicit type but with constraints like oneOf, const, enum."""
        
        # Handle oneOf constraint
        if "oneOf" in schema:
            # Pick one of the options randomly
            options = schema["oneOf"]
            if options:
                chosen_option = random.choice(options)
                return self.generate_value_from_schema(property_name, chosen_option, config, root_schema)
        
        # Handle const constraint
        if "const" in schema:
            return schema["const"]
        
        # Handle enum constraint
        if "enum" in schema:
            return random.choice(schema["enum"])
        
        # Handle allOf constraint (merge all schemas)
        if "allOf" in schema:
            merged_schema = {}
            for sub_schema in schema["allOf"]:
                if isinstance(sub_schema, dict):
                    merged_schema.update(sub_schema)
            return self.generate_value_from_schema(property_name, merged_schema, config, root_schema)
        
        # Handle anyOf constraint (pick one randomly)
        if "anyOf" in schema:
            options = schema["anyOf"]
            if options:
                chosen_option = random.choice(options)
                return self.generate_value_from_schema(property_name, chosen_option, config, root_schema)
        
        # If no recognizable constraints, return a default value
        self.logger.debug(f"No recognizable constraints for typeless schema '{property_name}', using default string")
        return f"default_{property_name}"
    
    def generate_value_from_schema(self, property_name: str, schema: Dict[str, Any], config: GeneratorConfig, root_schema: Optional[Dict[str, Any]] = None) -> Any:
        """Generate value from JSON schema definition."""
        if not isinstance(schema, dict):
            self.logger.warning(f"Invalid schema for property '{property_name}': {schema}")
            return f"invalid_schema_{property_name}"
        
        # Handle $ref references
        if "$ref" in schema:
            if root_schema is None:
                self.logger.warning(f"Cannot resolve $ref '{schema['$ref']}' for property '{property_name}' - no root schema provided")
                return f"unresolved_ref_{property_name}"
            
            try:
                resolved_schema = self.resolve_ref(root_schema, schema["$ref"])
                return self.generate_value_from_schema(property_name, resolved_schema, config, root_schema)
            except Exception as e:
                self.logger.warning(f"Failed to resolve $ref '{schema['$ref']}' for property '{property_name}': {e}")
                return f"failed_ref_{property_name}"
        
        schema_type = schema.get("type")
        
        try:
            if schema_type == "string":
                return self.generate_string_value(property_name, schema)
            elif schema_type == "integer":
                return self.generate_integer_value(property_name, schema)
            elif schema_type == "number":
                return self.generate_number_value(property_name, schema)
            elif schema_type == "boolean":
                return random.choice([True, False])
            elif schema_type == "array":
                return self.generate_array_value(property_name, schema, config, root_schema)
            elif schema_type == "object":
                return self.generate_object_value(property_name, schema, config, root_schema)
            elif schema_type is None and "properties" in schema:
                # Object without explicit type declaration
                return self.generate_object_value(property_name, schema, config, root_schema)
            elif schema_type is None:
                # Handle schemas without explicit type but with other constraints
                return self.handle_typeless_schema(property_name, schema, config, root_schema)
            else:
                self.logger.warning(f"Unsupported schema type '{schema_type}' for property '{property_name}'")
                return f"unsupported_type_{property_name}"
        except Exception as e:
            self.logger.error(f"Error generating value for property '{property_name}': {e}")
            return f"error_generating_{property_name}"


class SchemaExampleGenerator:
    """Main class for generating example files from JSON schemas."""
    
    def __init__(self, config: GeneratorConfig):
        self.config = config
        self.sample_data = SampleDataProvider()
        self.value_generator = SchemaValueGenerator(self.sample_data)
        self.logger = self._setup_logging()
        
        # Ensure output directory exists
        self.config.example_path.mkdir(parents=True, exist_ok=True)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.value),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger(__name__)
    
    def _extract_event_type_from_filename(self, filename: str) -> str:
        """Extract event type from schema filename."""
        return filename.replace("_schema.json", "")
    
    def _post_process_example(self, example: Dict[str, Any], event_type: str) -> Dict[str, Any]:
        """Post-process generated example to ensure required fields and consistency."""
        if not isinstance(example, dict):
            self.logger.warning(f"Generated example for {event_type} is not a dictionary")
            example = {}
        
        # Ensure required fields
        example["event_type"] = event_type
        
        if "timestamp" not in example:
            example["timestamp"] = self.value_generator.generate_timestamp()
        
        # Special handling for alert events
        if event_type == "alert" and "alert" not in example:
            example["alert"] = {
                "action": random.choice(self.sample_data.alert_actions),
                "gid": 1,
                "signature_id": random.randint(2000000, 2999999),
                "rev": random.randint(1, 10),
                "signature": f"ET {event_type.upper()} Example Rule",
                "category": random.choice(self.sample_data.alert_categories),
                "severity": random.randint(1, 4)
            }
        
        return example
    
    def generate_example_from_schema_file(self, schema_path: Path) -> Optional[Dict[str, Any]]:
        """Generate example data from a schema file."""
        try:
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.error(f"Failed to load schema file {schema_path}: {e}")
            return None
        
        event_type = self._extract_event_type_from_filename(schema_path.name)
        
        try:
            example = self.value_generator.generate_value_from_schema("root", schema, self.config, schema)
            return self._post_process_example(example, event_type)
        except Exception as e:
            self.logger.error(f"Failed to generate example for {event_type}: {e}")
            return None
    
    def save_example_file(self, example_data: Dict[str, Any], output_path: Path) -> bool:
        """Save example data to file."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(example_data, f, indent=2, ensure_ascii=False, sort_keys=True)
            return True
        except IOError as e:
            self.logger.error(f"Failed to save example file {output_path}: {e}")
            return False
    
    def process_schema_file(self, schema_path: Path) -> bool:
        """Process a single schema file and generate corresponding example."""
        example_filename = schema_path.name.replace("_schema.json", "_example.json")
        example_path = self.config.example_path / example_filename
        
        # Check if file exists and overwrite policy
        if example_path.exists() and not self.config.overwrite_existing:
            self.logger.info(f"Skipping existing file: {example_filename}")
            return True
        
        self.logger.info(f"Processing {schema_path.name} -> {example_filename}")
        
        example_data = self.generate_example_from_schema_file(schema_path)
        if example_data is None:
            return False
        
        success = self.save_example_file(example_data, example_path)
        if success:
            self.logger.info(f"✓ Successfully generated {example_filename}")
        else:
            self.logger.error(f"✗ Failed to save {example_filename}")
        
        return success
    
    def process_all_schemas(self) -> Dict[str, int]:
        """Process all schema files in the schema directory."""
        if not self.config.schema_path.exists():
            self.logger.error(f"Schema directory not found: {self.config.schema_path}")
            return {"processed": 0, "successful": 0, "failed": 0}
        
        schema_files = list(self.config.schema_path.glob("*_schema.json"))
        
        if not schema_files:
            self.logger.warning(f"No schema files found in {self.config.schema_path}")
            return {"processed": 0, "successful": 0, "failed": 0}
        
        self.logger.info(f"Found {len(schema_files)} schema files to process")
        
        successful = 0
        failed = 0
        
        for schema_file in sorted(schema_files):
            try:
                if self.process_schema_file(schema_file):
                    successful += 1
                else:
                    failed += 1
            except Exception as e:
                self.logger.error(f"Unexpected error processing {schema_file}: {e}")
                failed += 1
        
        return {
            "processed": len(schema_files),
            "successful": successful,
            "failed": failed
        }


def main():
    """Main entry point for the schema example generator."""
    # Set fixed random seed for consistent example generation
    random.seed(42)
    
    # Change to script directory to handle relative paths correctly
    script_dir = Path(__file__).parent
    os.chdir(script_dir.parent)  # Change to project root
    
    config = GeneratorConfig()
    generator = SchemaExampleGenerator(config)
    
    logger = logging.getLogger(__name__)
    logger.info("Starting comprehensive schema example generation...")
    logger.info(f"Schema directory: {config.schema_dir}")
    logger.info(f"Example directory: {config.example_dir}")
    
    results = generator.process_all_schemas()
    
    logger.info("Generation completed!")
    logger.info(f"Processed: {results['processed']} files")
    logger.info(f"Successful: {results['successful']} files")
    logger.info(f"Failed: {results['failed']} files")
    
    if results['failed'] > 0:
        logger.warning(f"{results['failed']} files failed to process")
        sys.exit(1)
    
    logger.info("All example files have been generated successfully!")


if __name__ == "__main__":
    main()