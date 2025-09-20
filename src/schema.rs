/* Copyright (C) 2025-2035 NetPrism Technology
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * Contributors:
 * - Zhenjun <zhenjun@netprism.org>
 *
 * This is a schema parser for Zenoh to store data in DuckDB.
 */

use std::{collections::HashMap, path::{Path, PathBuf}};
use serde_json::Value;
use zenoh_util;

/// JSON Schema field information
#[derive(Debug, Clone)]
pub struct SchemaField {
    pub name: String,
    pub field_type: String,
    pub is_top_level: bool,
    pub is_array: bool,
    pub is_object: bool,
    pub is_required: bool,
    pub description: Option<String>,
}

/// Table Schema handler - High performance Rust implementation
pub struct TableSchema {
    /// Field type to DuckDB type mapping
    type_mapping: HashMap<String, String>,
    /// Cached schema fields for performance
    schema_fields: Option<Vec<SchemaField>>,
}

impl TableSchema {
    pub fn new() -> Self {
        let mut type_mapping = HashMap::new();
        type_mapping.insert("string".to_string(), "VARCHAR".to_string());
        type_mapping.insert("integer".to_string(), "BIGINT".to_string());
        type_mapping.insert("number".to_string(), "DOUBLE".to_string());
        type_mapping.insert("boolean".to_string(), "BOOLEAN".to_string());
        type_mapping.insert("array".to_string(), "JSON".to_string());
        type_mapping.insert("object".to_string(), "JSON".to_string());

        Self {
            type_mapping,
            schema_fields: None,
        }
    }

    /// Parse JSON Schema and flatten fields
    pub fn parse_schema(&self, schema: &Value) -> Result<Vec<SchemaField>, String> {
        let mut fields = Vec::new();
        let mut stack = Vec::new();
        
        // Get required fields from schema
        let required_fields = schema.get("required")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        
        // Start from root schema
        if let Some(properties) = schema.get("properties") {
            stack.push((properties, Vec::new()));
        }

        while let Some((current, path)) = stack.pop() {
            if let Some(properties) = current.as_object() {
                for (name, field_schema) in properties {
                    let is_top_level = path.is_empty();
                    
                    // Handle $ref references
                    let resolved_schema = if let Some(ref_path) = field_schema.get("$ref") {
                        self.resolve_ref(schema, ref_path.as_str().unwrap())?
                    } else {
                        field_schema
                    };

                    let field_type = self.extract_field_type(resolved_schema);
                    let is_array = field_type.ends_with("[]") || field_type == "array";
                    let is_object = field_type == "object";
                    
                    let description = resolved_schema
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let is_required = required_fields.contains(name);
                    
                    fields.push(SchemaField {
                        name: name.clone(),
                        field_type: field_type.clone(),
                        is_top_level,
                        is_array,
                        is_object,
                        is_required,
                        description,
                    });

                    // Continue processing nested structures
                    if is_object && resolved_schema.get("properties").is_some() {
                        let mut new_path = path.clone();
                        new_path.push(name.clone());
                        stack.push((resolved_schema.get("properties").unwrap(), new_path));
                    } else if is_array {
                        if let Some(items) = resolved_schema.get("items") {
                            if let Some(item_properties) = items.get("properties") {
                                let mut new_path = path.clone();
                                new_path.push(format!("{}[]", name));
                                stack.push((item_properties, new_path));
                            }
                        }
                    }
                }
            }
        }

        Ok(fields)
    }

    /// Parse $ref references
    fn resolve_ref<'a>(&self, schema: &'a Value, ref_path: &str) -> Result<&'a Value, String> {
        if !ref_path.starts_with("#/") {
            return Err(format!("Unsupported reference: {}", ref_path));
        }

        let path = &ref_path[2..]; // Remove "#/"
        let parts: Vec<&str> = path.split('/').collect();
        
        let mut current = schema;
        for part in parts {
            current = current.get(part)
                .ok_or_else(|| format!("Reference not found: {}", ref_path))?;
        }
        
        Ok(current)
    }

    /// Extract field type
    fn extract_field_type(&self, field_schema: &Value) -> String {
        if let Some(field_type) = field_schema.get("type") {
            match field_type {
                Value::String(s) => s.clone(),
                Value::Array(arr) => {
                    // Handle union types, take the first non-null type
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .find(|&t| t != "null")
                        .unwrap_or("string")
                        .to_string()
                }
                _ => "string".to_string(),
            }
        } else {
            "string".to_string()
        }
    }

    /// Get DuckDB type
    pub fn get_duckdb_type(&self, field: &SchemaField) -> String {
        // Boundary rule 1: All JSON arrays stored as JSON type
        if field.is_array {
            return "JSON".to_string();
        }
        
        // Boundary rule 2: First-level object fields stored as JSON type
        if field.is_top_level && field.is_object {
            return "JSON".to_string();
        }
        
        // Boundary rule 3: Other fields mapped according to schema type
        let base_type = field.field_type.replace("[]", "");
        let duckdb_type = self.type_mapping.get(&base_type)
            .unwrap_or(&"VARCHAR".to_string())
            .clone();

        duckdb_type
    }


    /// Load schema from file and cache field information
    pub fn load_file(&mut self, schema_file: &str) -> Result<(), String> {
        // Resolve path relative to ZENOH_HOME if needed
        let path = if Path::new(schema_file).is_absolute() {
            PathBuf::from(schema_file)
        } else {
            zenoh_util::zenoh_home().join(schema_file)
        };
        
        // Read schema file
        let schema_content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read schema file {} (path: {}): {}", schema_file, path.display(), e))?;
        
        // Parse JSON
        let schema: Value = serde_json::from_str(&schema_content)
            .map_err(|e| format!("Failed to parse JSON schema: {}", e))?;
        
        // Parse schema and cache fields
        let fields = self.parse_schema(&schema)?;
        self.schema_fields = Some(fields);
        
        Ok(())
    }

    /// Get cached schema fields
    pub fn get_fields(&self) -> Option<&[SchemaField]> {
        self.schema_fields.as_deref()
    }

    /// Generate DDL from cached fields (or basic DDL if no fields)
    pub fn generate_ddl(&self, table_name: &str) -> String {
        let fields = match self.schema_fields.as_ref() {
            Some(fields) => fields,
            None => {
                // No schema fields, generate basic DDL with only Zenoh fields
                return format!(
                    "CREATE TABLE IF NOT EXISTS {} (\
                    \n    zenoh_timestamp VARCHAR NOT NULL,\
                    \n    key_expr VARCHAR NOT NULL,\
                    \n    kind VARCHAR NOT NULL,\
                    \n    payload TEXT,\
                    \n    PRIMARY KEY (zenoh_timestamp)\
                    \n);\
                    \nCREATE INDEX IF NOT EXISTS idx_{}_zenoh_timestamp ON {} (zenoh_timestamp);",
                    table_name, table_name, table_name
                );
            }
        };
        
        let mut ddl_lines = Vec::new();
        
        // Generate DDL statement
        
        // Start CREATE TABLE statement
        ddl_lines.push(format!("CREATE TABLE IF NOT EXISTS {} (", table_name));
        
        // Only process first-level fields
        let top_level_fields: Vec<&SchemaField> = fields.iter()
            .filter(|f| f.is_top_level)
            .collect();
        
        let mut column_definitions = Vec::new();
        
        // First add Zenoh required fields (in order)
        column_definitions.push("    zenoh_timestamp VARCHAR NOT NULL".to_string());
        column_definitions.push("    key_expr VARCHAR NOT NULL".to_string());
        column_definitions.push("    kind VARCHAR NOT NULL".to_string());
        
        // Then add JSON Schema fields
        for field in &top_level_fields {
            let duckdb_type = self.get_duckdb_type(field);
            let is_required = field.is_required;
            
            let mut column_def = format!("    {} {}", field.name, duckdb_type);
            
            if is_required {
                column_def.push_str(" NOT NULL");
            }
            
            column_definitions.push(column_def);
        }
        
        // Join column definitions
        ddl_lines.push(column_definitions.join(",\n"));
        
        // Add primary key constraint (with comma)
        ddl_lines.push(",\n    PRIMARY KEY (zenoh_timestamp)".to_string());
        
        // Close CREATE TABLE statement
        ddl_lines.push(");".to_string());
        
        // Add index for timestamp
        ddl_lines.push(format!("CREATE INDEX IF NOT EXISTS idx_{}_zenoh_timestamp ON {} (zenoh_timestamp);", table_name, table_name));

        ddl_lines.join("\n")
    }

}

impl Default for TableSchema {
    fn default() -> Self {
        Self::new()
    }
}

