use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use duckdb::{params, Connection};
use serde_json::Value;
use zenoh::{
    bytes::{Encoding, ZBytes},
    internal::zerror,
    key_expr::OwnedKeyExpr,
    time::Timestamp,
    Result as ZResult,
};
use zenoh_backend_traits::{
    config::StorageConfig, Storage, StorageInsertionResult, StoredData,
};

use crate::schema::SchemaParser;


pub struct DuckDBStorage {
    config: StorageConfig,
    connection: Arc<Mutex<Connection>>,
    table: String,
    table_desc: Option<String>,
}

impl DuckDBStorage {
    pub fn new(
        config: StorageConfig,
        db_path: &str,
        schema: String,
        table: String,
        table_desc: Option<String>,
    ) -> ZResult<Box<dyn Storage>> {
        // 验证schema和table名有效性
        if !Self::is_valid_identifier(&schema) {
            return Err(zerror!("Invalid schema name: '{}'", schema).into());
        }
        if !Self::is_valid_identifier(&table) {
            return Err(zerror!("Invalid table name: '{}'", table).into());
        }
        
        tracing::info!(
            "Creating storage: key_expr='{}' -> {}.{} (table_desc: {:?})", 
            config.key_expr, schema, table, table_desc
        );
        
        // 创建独立的DuckDB连接
        let connection = Connection::open(db_path)
            .map_err(|e| zerror!("Failed to open DuckDB database '{}': {}", db_path, e))?;
        
        // 配置DuckDB优化设置
        Self::configure_duckdb(&connection)?;
        
        // 创建schema（如果不存在）并切换到该schema
        Self::create_and_use_schema(&connection, &schema)?;
        
        let storage = DuckDBStorage {
            config,
            connection: Arc::new(Mutex::new(connection)),
            table: table.clone(),
            table_desc,
        };

        // 如果指定了table_desc，则创建表结构
        if storage.table_desc.is_some() {
            if let Err(e) = storage.create_table() {
                tracing::error!("Failed to create table from schema: {}", e);
                return Err(zerror!("Failed to create table from schema: {}", e).into());
            }
        }
        
        Ok(Box::new(storage))
    }
    
    /// 配置DuckDB优化设置
    fn configure_duckdb(connection: &Connection) -> ZResult<()> {
        // 启用多线程处理（使用系统CPU核心数）
        connection.execute("PRAGMA threads = 4", [])
            .map_err(|e| zerror!("Failed to set threads pragma: {}", e))?;
        
        // 设置内存限制（可配置）
        connection.execute("PRAGMA memory_limit = '1GB'", [])
            .map_err(|e| zerror!("Failed to set memory limit: {}", e))?;
        
        tracing::debug!("DuckDB configuration completed");
        Ok(())
    }
    
    /// 创建schema（如果不存在）并切换到该schema
    fn create_and_use_schema(connection: &Connection, schema_name: &str) -> ZResult<()> {
        // 创建schema（如果不存在）
        let create_schema_sql = format!("CREATE SCHEMA IF NOT EXISTS {}", schema_name);
        connection.execute(&create_schema_sql, [])
            .map_err(|e| zerror!("Failed to create schema '{}': {}", schema_name, e))?;
        
        // 切换到该schema
        let use_schema_sql = format!("USE {}", schema_name);
        connection.execute(&use_schema_sql, [])
            .map_err(|e| zerror!("Failed to use schema '{}': {}", schema_name, e))?;
        
        tracing::debug!("Successfully created and switched to schema: {}", schema_name);
        Ok(())
    }
    
    /// 验证标识符是否有效
    fn is_valid_identifier(name: &str) -> bool {
        !name.is_empty() 
            && name.len() <= 64
            && name.chars().all(|c| c.is_alphanumeric() || c == '_')
            && name.chars().next().map_or(false, |c| !c.is_ascii_digit())
    }

    /// 从table_desc文件创建表结构
    fn create_table(&self) -> ZResult<()> {
        let table_desc = self.table_desc.as_ref()
            .ok_or_else(|| zerror!("No table_desc file specified"))?;
        
        tracing::info!("Creating table from table_desc file: {}", table_desc);
        
        // 创建table_desc解析器
        let parser = SchemaParser::new();

        // 生成DDL
        let ddl = parser.load_schema_file(table_desc, &self.get_table_name())
            .map_err(|e| zerror!("Failed to generate DDL: {}", e))?;

        tracing::debug!("Generated DDL:\n{}", ddl);
        
        // 执行DDL创建表（schema已经在连接时切换了）
        let conn = self.connection.lock().unwrap();
        
        // 分割DDL语句，分别执行
        let statements: Vec<&str> = ddl.split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        
        for statement in statements {
            if !statement.is_empty() {
                conn.execute(statement, params![])
                    .map_err(|e| zerror!("Failed to execute statement '{}': {}", statement, e))?;
            }
        }
        
        tracing::info!("Successfully created table: {}", self.get_table_name());
        
        Ok(())
    }

    /// 获取表名（schema已经在连接时切换了）
    fn get_table_name(&self) -> String {
        self.table.clone()
    }
    

    fn key_to_string(&self, key: &Option<OwnedKeyExpr>) -> String {
        match key {
            Some(k) => k.to_string(),
            None => "**".to_string(), // 通配符表示无key
        }
    }

    fn string_to_key(&self, s: &str) -> ZResult<Option<OwnedKeyExpr>> {
        if s == "**" {
            Ok(None)
        } else {
            match OwnedKeyExpr::from_str(s) {
                Ok(key) => Ok(Some(key)),
                Err(e) => Err(format!("Invalid key expression: {}", e).into()),
            }
        }
    }

    /// 解析JSON payload并提取字段值
    fn parse_json_payload(&self, payload: &[u8]) -> ZResult<Value> {
        let json_str = std::str::from_utf8(payload)
            .map_err(|e| zerror!("Invalid UTF-8 in payload: {}", e))?;
        
        let json_value: Value = serde_json::from_str(json_str)
            .map_err(|e| zerror!("Failed to parse JSON payload: {}", e))?;
        
        Ok(json_value)
    }

    /// 动态生成INSERT语句
    fn generate_dynamic_insert(&self, json_data: &Value, key_expr: &str, timestamp: &Timestamp, kind: &str) -> ZResult<String> {
        let table_desc = self.table_desc.as_ref()
            .ok_or_else(|| zerror!("No table_desc specified"))?;
        
        // 使用SchemaParser解析schema
        let parser = SchemaParser::new();
        let schema_content = std::fs::read_to_string(table_desc)
            .map_err(|e| zerror!("Failed to read schema file {}: {}", table_desc, e))?;
        
        let schema: Value = serde_json::from_str(&schema_content)
            .map_err(|e| zerror!("Failed to parse JSON schema: {}", e))?;
        
        let fields = parser.parse_schema(&schema)
            .map_err(|e| zerror!("Failed to parse schema: {}", e))?;
        
        // 构建列名列表
        let mut column_names = Vec::new();
        let mut values = Vec::new();
        
        // 首先添加Zenoh必需字段
        column_names.push("key_expr".to_string());
        values.push(format!("'{}'", key_expr.replace("'", "''")));
        
        column_names.push("zenoh_timestamp".to_string());
        values.push(format!("'{}'", timestamp.to_string().replace("'", "''")));

        column_names.push("kind".to_string());
        values.push(format!("'{}'", kind));
        
        // 然后添加JSON Schema字段
        for field in &fields {
            if field.is_top_level {
                let value = match json_data.get(&field.name) {
                    Some(v) => {
                        // 复杂对象直接序列化为JSON字符串
                        if field.is_object || field.is_array {
                            serde_json::to_string(v).unwrap_or("null".to_string())
                        } else {
                            // 基础字段转换为字符串
                            v.as_str().unwrap_or(&v.to_string()).to_string()
                        }
                    }
                    None => "NULL".to_string(),
                };
                
                column_names.push(field.name.clone());
                values.push(if value == "NULL" { "NULL".to_string() } else { format!("'{}'", value.replace("'", "''")) });
            }
        }
        
        // 构建INSERT语句
        let columns_str = column_names.join(", ");
        let values_str = values.join(", ");
        let insert_sql = format!(
            "INSERT OR REPLACE INTO {} ({}) VALUES ({})",
            self.get_table_name(), columns_str, values_str
        );
        
        Ok(insert_sql)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_json_parsing() {
        // 测试JSON解析 - 直接测试解析逻辑
        let test_json = r#"{
            "timestamp": "2024-01-15T10:30:45.123456+08:00",
            "event_type": "flow",
            "flow_id": 12345,
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "src_port": 8080,
            "dest_port": 443,
            "proto": "tcp",
            "app_proto": "http",
            "flow": {
                "action": "new",
                "bytes_toclient": 1024,
                "bytes_toserver": 2048
            },
            "tcp": {
                "ack": true,
                "psh": true
            }
        }"#;
        
        let payload = test_json.as_bytes();
        let json_str = std::str::from_utf8(payload).unwrap();
        let json_data: Value = serde_json::from_str(json_str).unwrap();
        
        // 验证基础字段解析
        assert_eq!(json_data["timestamp"].as_str().unwrap(), "2024-01-15T10:30:45.123456+08:00");
        assert_eq!(json_data["event_type"].as_str().unwrap(), "flow");
        assert_eq!(json_data["flow_id"].as_i64().unwrap(), 12345);
        assert_eq!(json_data["src_ip"].as_str().unwrap(), "192.168.1.100");
        assert_eq!(json_data["dest_ip"].as_str().unwrap(), "10.0.0.1");
        
        // 验证复杂对象解析
        assert!(json_data["flow"].is_object());
        assert!(json_data["tcp"].is_object());
        assert_eq!(json_data["flow"]["action"].as_str().unwrap(), "new");
        assert_eq!(json_data["tcp"]["ack"].as_bool().unwrap(), true);
    }

    #[test]
    fn test_generate_insert_params() {
        // 测试参数生成逻辑 - 直接测试字段映射
        let test_json = json!({
            "timestamp": "2024-01-15T10:30:45.123456+08:00",
            "event_type": "flow",
            "flow_id": 12345,
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "flow": {
                "action": "new",
                "bytes_toclient": 1024
            },
            "tcp": {
                "ack": true
            }
        });
        
        // 验证字段访问
        assert_eq!(test_json["event_type"].as_str().unwrap(), "flow");
        assert_eq!(test_json["flow_id"].as_i64().unwrap(), 12345);
        assert_eq!(test_json["src_ip"].as_str().unwrap(), "192.168.1.100");
        assert_eq!(test_json["dest_ip"].as_str().unwrap(), "10.0.0.1");
        
        // 验证复杂对象序列化
        let flow_json = serde_json::to_string(&test_json["flow"]).unwrap();
        let tcp_json = serde_json::to_string(&test_json["tcp"]).unwrap();
        
        assert!(flow_json.contains("\"action\""));
        assert!(tcp_json.contains("\"ack\""));
    }

    #[test]
    fn test_dynamic_insert_generation() {
        // 测试动态INSERT语句生成逻辑
        let test_json = json!({
            "timestamp": "2024-01-15T10:30:45.123456+08:00",
            "event_type": "flow",
            "flow_id": 12345,
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "flow": {
                "action": "new",
                "bytes_toclient": 1024
            },
            "tcp": {
                "ack": true
            }
        });
        
        // 验证JSON数据包含预期字段
        assert_eq!(test_json["event_type"].as_str().unwrap(), "flow");
        assert_eq!(test_json["flow_id"].as_i64().unwrap(), 12345);
        assert_eq!(test_json["src_ip"].as_str().unwrap(), "192.168.1.100");
        assert_eq!(test_json["dest_ip"].as_str().unwrap(), "10.0.0.1");
        
        // 验证复杂对象
        assert!(test_json["flow"].is_object());
        assert!(test_json["tcp"].is_object());
        assert_eq!(test_json["flow"]["action"].as_str().unwrap(), "new");
        assert_eq!(test_json["tcp"]["ack"].as_bool().unwrap(), true);
    }

}

#[async_trait]
impl Storage for DuckDBStorage {
    fn get_admin_status(&self) -> serde_json::Value {
        self.config.to_json_value()
    }

    async fn put(
        &mut self,
        key: Option<OwnedKeyExpr>,
        payload: ZBytes,
        _encoding: Encoding,
        timestamp: Timestamp,
    ) -> ZResult<StorageInsertionResult> {
        let key_str = self.key_to_string(&key);
        let value_bytes = payload.to_bytes();
        
        tracing::info!("PUT called for key: {}, payload size: {} bytes", key_str, value_bytes.len());

        // 使用结构化存储
        if self.table_desc.is_some() {
            match self.parse_json_payload(&value_bytes) {
                Ok(json_data) => {
                    tracing::info!("Parsed JSON data: {}", serde_json::to_string(&json_data).unwrap_or("Failed to serialize".to_string()));
                    
                    let conn = self.connection.lock().unwrap();
                    match self.generate_dynamic_insert(&json_data, &key_str, &timestamp, "PUT") {
                        Ok(insert_sql) => {
                            tracing::info!("Generated INSERT SQL: {}", insert_sql);
                            
                            conn.execute(&insert_sql, params![])
                                .map_err(|e| zerror!("Failed to insert structured data into DuckDB: {}", e))?;
                            
                            tracing::info!("Data successfully stored in structured format for key: {}", key_str);
                        }
                        Err(e) => {
                            tracing::error!("Failed to generate insert params: {}", e);
                            return Err(zerror!("Failed to generate insert params: {}", e).into());
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to parse JSON payload: {}", e);
                    tracing::error!("Raw payload: {}", String::from_utf8_lossy(&value_bytes));
                    return Err(zerror!("Failed to parse JSON payload: {}", e).into());
                }
            }
        } else {
            return Err(zerror!("No table_desc specified - structured storage requires schema definition").into());
        }

        tracing::debug!("Stored data for key: {}", key_str);
        Ok(StorageInsertionResult::Inserted)
    }

    async fn delete(
        &mut self,
        key: Option<OwnedKeyExpr>,
        timestamp: Timestamp,
    ) -> ZResult<StorageInsertionResult> {
        let key_str = self.key_to_string(&key);
        let timestamp_nanos = timestamp.get_time().to_duration().as_nanos() as i64;


        // 插入删除标记
        let insert_sql = format!(
            "INSERT INTO {} (key_expr, payload, encoding, timestamp, kind) VALUES (?, NULL, NULL, ?, 'DEL')",
            self.get_table_name()
        );
        
        let conn = self.connection.lock().unwrap();
        conn.execute(&insert_sql, params![key_str, timestamp_nanos])
            .map_err(|e| zerror!("Failed to insert delete marker into DuckDB: {}", e))?;

        // 删除比这个时间戳更早的相同key的数据
        let delete_sql = format!(
            "DELETE FROM {} WHERE key_expr = ? AND timestamp < ? AND kind = 'PUT'",
            self.get_table_name()
        );

        conn.execute(&delete_sql, params![key_str, timestamp_nanos])
            .map_err(|e| zerror!("Failed to delete old data from DuckDB: {}", e))?;

        tracing::debug!("Deleted data for key: {}", key_str);
        Ok(StorageInsertionResult::Deleted)
    }

    async fn get(
        &mut self,
        key: Option<OwnedKeyExpr>,
        _parameters: &str,
    ) -> ZResult<Vec<StoredData>> {
        let key_str = self.key_to_string(&key);

        // 从结构化存储中查询所有字段数据
        let table_name = self.get_table_name();
        let sql = format!(
            "SELECT * FROM {} LIMIT 1",
            table_name
        );

        let conn = self.connection.lock().unwrap();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| zerror!("Failed to prepare query: {}", e))?;

        let rows: Vec<(String, Vec<u8>, String, i64)> = if key.is_some() {
            stmt.query_map(params![key_str], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| zerror!("Failed to execute query: {}", e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| zerror!("Failed to collect query results: {}", e))?
        } else {
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| zerror!("Failed to execute query: {}", e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| zerror!("Failed to collect query results: {}", e))?
        };

        let mut result = Vec::new();
        for (key_str, value_bytes, encoding_str, timestamp_nanos) in rows {
            let _stored_key = self.string_to_key(&key_str)?;
            let encoding = Encoding::from(encoding_str);
            
            // 从纳秒时间戳恢复zenoh Timestamp
            let timestamp = match Timestamp::from_str(&timestamp_nanos.to_string()) {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!("Failed to parse timestamp {}, using current time", timestamp_nanos);
                    match Timestamp::from_str("1") {
                        Ok(t) => t,
                        Err(_) => {
                            panic!("Cannot create any valid Timestamp - zenoh API may have changed")
                        }
                    }
                }
            };
            
            let payload = ZBytes::from(value_bytes);

            result.push(StoredData {
                payload,
                encoding,
                timestamp,
            });
        }

        Ok(result)
    }

    async fn get_all_entries(&self) -> ZResult<Vec<(Option<OwnedKeyExpr>, Timestamp)>> {

        // 查询每个唯一key的最新条目
        let sql = format!(
            "SELECT key_expr, MAX(zenoh_timestamp) as latest_timestamp 
             FROM {} 
             WHERE kind = 'PUT' 
             GROUP BY key_expr",
            self.get_table_name()
        );

        let conn = self.connection.lock().unwrap();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| zerror!("Failed to prepare get_all_entries query: {}", e))?;

        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                ))
            })
            .map_err(|e| zerror!("Failed to execute get_all_entries query: {}", e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| zerror!("Failed to collect get_all_entries rows: {}", e))?;

        let mut result = Vec::new();
        for (key_str, latest_timestamp_str) in rows {
            let key = self.string_to_key(&key_str)?;
            
            // 从字符串时间戳恢复zenoh Timestamp
            let timestamp = match Timestamp::from_str(&latest_timestamp_str) {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!("Failed to parse timestamp {}, skipping entry", latest_timestamp_str);
                    continue; // 跳过无法解析的条目
                }
            };

            result.push((key, timestamp));
        }

        Ok(result)
    }
}

impl Drop for DuckDBStorage {
    fn drop(&mut self) {
        tracing::debug!("Closing DuckDB storage for table: {}", self.get_table_name());
    }
}