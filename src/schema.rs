use std::collections::HashMap;
use serde_json::Value;

/// JSON Schema字段信息
#[derive(Debug, Clone)]
pub struct SchemaField {
    pub name: String,
    pub field_type: String,
    pub is_top_level: bool,
    pub is_array: bool,
    pub is_object: bool,
    pub description: Option<String>,
}

/// Schema解析器 - 高性能的Rust实现
pub struct SchemaParser {
    /// 字段类型到DuckDB类型的映射
    type_mapping: HashMap<String, String>,
}

impl SchemaParser {
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
        }
    }

    /// 解析JSON Schema并扁平化字段
    pub fn parse_schema(&self, schema: &Value) -> Result<Vec<SchemaField>, String> {
        let mut fields = Vec::new();
        let mut stack = Vec::new();
        
        // 从根schema开始
        if let Some(properties) = schema.get("properties") {
            stack.push((properties, Vec::new()));
        }

        while let Some((current, path)) = stack.pop() {
            if let Some(properties) = current.as_object() {
                for (name, field_schema) in properties {
                    let is_top_level = path.is_empty();
                    
                    // 处理$ref引用
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

                    fields.push(SchemaField {
                        name: name.clone(),
                        field_type: field_type.clone(),
                        is_top_level,
                        is_array,
                        is_object,
                        description,
                    });

                    // 继续处理嵌套结构
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

    /// 解析$ref引用
    fn resolve_ref<'a>(&self, schema: &'a Value, ref_path: &str) -> Result<&'a Value, String> {
        if !ref_path.starts_with("#/") {
            return Err(format!("Unsupported reference: {}", ref_path));
        }

        let path = &ref_path[2..]; // 移除 "#/"
        let parts: Vec<&str> = path.split('/').collect();
        
        let mut current = schema;
        for part in parts {
            current = current.get(part)
                .ok_or_else(|| format!("Reference not found: {}", ref_path))?;
        }
        
        Ok(current)
    }

    /// 提取字段类型
    fn extract_field_type(&self, field_schema: &Value) -> String {
        if let Some(field_type) = field_schema.get("type") {
            match field_type {
                Value::String(s) => s.clone(),
                Value::Array(arr) => {
                    // 处理联合类型，取第一个非null类型
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

    /// 获取DuckDB类型
    pub fn get_duckdb_type(&self, field: &SchemaField) -> String {
        // 边界规则1: 所有JSON数组存储为JSON类型
        if field.is_array {
            return "JSON".to_string();
        }
        
        // 边界规则2: 一级对象字段存储为JSON类型
        if field.is_top_level && field.is_object {
            return "JSON".to_string();
        }
        
        // 边界规则3: 其他字段按schema类型映射
        let base_type = field.field_type.replace("[]", "");
        let duckdb_type = self.type_mapping.get(&base_type)
            .unwrap_or(&"VARCHAR".to_string())
            .clone();

        duckdb_type
    }

    /// 生成DDL
    pub fn generate_ddl(&self, fields: &[SchemaField], table_name: &str, required_fields: &[String]) -> String {
        let mut ddl_lines = Vec::new();
        
        // 生成DDL语句
        
        // 开始CREATE TABLE语句
        ddl_lines.push(format!("CREATE TABLE IF NOT EXISTS {} (", table_name));
        
        // 只处理一级字段
        let top_level_fields: Vec<&SchemaField> = fields.iter()
            .filter(|f| f.is_top_level)
            .collect();
        
        // 生成列定义
        let mut column_definitions = Vec::new();
        
        // 首先添加Zenoh必需的字段
        column_definitions.push("    zenoh_timestamp VARCHAR NOT NULL".to_string());
        column_definitions.push("    key_expr VARCHAR NOT NULL".to_string());
        column_definitions.push("    kind VARCHAR NOT NULL".to_string());
        
        // 然后添加JSON Schema字段
        for field in &top_level_fields {
            let duckdb_type = self.get_duckdb_type(field);
            let is_required = required_fields.contains(&field.name);
            
            let mut column_def = format!("    {} {}", field.name, duckdb_type);
            
            if is_required {
                column_def.push_str(" NOT NULL");
            }
            
            column_definitions.push(column_def);
        }
        
        // 添加列定义到DDL
        for (i, column_def) in column_definitions.iter().enumerate() {
            ddl_lines.push(format!("{},", column_def));
        }
        
        // 添加主键约束 - 使用Zenoh的zenoh_timestamp作为主键
        ddl_lines.push(format!("    PRIMARY KEY (zenoh_timestamp)"));

        // 结束CREATE TABLE语句
        ddl_lines.push(");".to_string());
        
        // 添加索引
        ddl_lines.push(String::new());
        ddl_lines.push(format!("CREATE INDEX IF NOT EXISTS idx_{}_zenoh_timestamp ON {} (zenoh_timestamp);", table_name, table_name));

        ddl_lines.join("\n")
    }

    /// 从文件加载schema并生成DDL
    pub fn load_schema_file(&self, schema_file: &str, table_name: &str) -> Result<String, String> {
        // 读取schema文件
        let schema_content = std::fs::read_to_string(schema_file)
            .map_err(|e| format!("Failed to read schema file {}: {}", schema_file, e))?;
        
        // 解析JSON
        let schema: Value = serde_json::from_str(&schema_content)
            .map_err(|e| format!("Failed to parse JSON schema: {}", e))?;
        
        // 获取必需字段
        let required_fields = schema.get("required")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        
        // 解析schema
        let fields = self.parse_schema(&schema)?;
        
        // 生成DDL
        let ddl = self.generate_ddl(&fields, table_name, &required_fields);
        
        Ok(ddl)
    }
}

impl Default for SchemaParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ddl_generation() {
        let parser = SchemaParser::new();
        
        // 测试DDL生成
        match parser.load_schema_file("etc/flow_schema.json", "flow") {
            Ok(ddl) => {
                // 验证DDL包含关键元素
                assert!(ddl.contains("CREATE TABLE"));
                assert!(ddl.contains("flow"));
                assert!(ddl.contains("timestamp"));
                assert!(ddl.contains("flow_id"));
                assert!(ddl.contains("src_ip"));
                assert!(ddl.contains("dest_ip"));
                
                // 验证复杂对象被存储为JSON
                assert!(ddl.contains("flow JSON"));
                assert!(ddl.contains("tcp JSON"));
                assert!(ddl.contains("metadata JSON"));
                
                // 验证主键约束
                assert!(ddl.contains("PRIMARY KEY"));
                
                // 验证索引创建
                assert!(ddl.contains("CREATE INDEX"));
            }
            Err(e) => {
                panic!("Error generating DDL: {}", e);
            }
        }
    }

    #[test]
    fn test_type_mapping() {
        let parser = SchemaParser::new();
        
        // 测试基础字段类型映射
        let basic_field = SchemaField {
            name: "timestamp".to_string(),
            field_type: "string".to_string(),
            is_top_level: true,
            is_array: false,
            is_object: false,
            description: None,
        };
        
        assert_eq!(parser.get_duckdb_type(&basic_field), "VARCHAR");
        
        // 测试复杂对象类型映射
        let object_field = SchemaField {
            name: "flow".to_string(),
            field_type: "object".to_string(),
            is_top_level: true,
            is_array: false,
            is_object: true,
            description: None,
        };
        
        assert_eq!(parser.get_duckdb_type(&object_field), "JSON");
        
        // 测试数组类型映射
        let array_field = SchemaField {
            name: "tags".to_string(),
            field_type: "array".to_string(),
            is_top_level: true,
            is_array: true,
            is_object: false,
            description: None,
        };
        
        assert_eq!(parser.get_duckdb_type(&array_field), "JSON");
    }

    #[test]
    fn test_schema_parsing() {
        let parser = SchemaParser::new();
        
        // 测试schema解析
        let test_schema = r#"{
            "type": "object",
            "required": ["event_type", "timestamp"],
            "properties": {
                "timestamp": {"type": "string"},
                "event_type": {"type": "string"},
                "flow_id": {"type": "integer"},
                "src_ip": {"type": "string"},
                "dest_ip": {"type": "string"},
                "flow": {"type": "object"},
                "tcp": {"type": "object"}
            }
        }"#;
        
        let schema: Value = serde_json::from_str(test_schema).unwrap();
        let fields = parser.parse_schema(&schema).unwrap();
        
        // 验证解析的字段数量
        assert_eq!(fields.len(), 7);
        
        // 验证必需字段
        let required_fields = schema.get("required")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        
        assert_eq!(required_fields.len(), 2);
        assert!(required_fields.contains(&"event_type".to_string()));
        assert!(required_fields.contains(&"timestamp".to_string()));
    }

    #[test]
    fn test_schema_parser() {
        let parser = SchemaParser::new();
        
        // 测试类型映射
        let field = SchemaField {
            name: "test_field".to_string(),
            field_type: "string".to_string(),
            is_top_level: true,
            is_array: false,
            is_object: false,
            description: None,
        };
        
        assert_eq!(parser.get_duckdb_type(&field), "VARCHAR");
    }
}
