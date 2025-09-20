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
 * This is a storage for Zenoh to store data in DuckDB.
 */

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

use crate::schema::{TableSchema, SchemaField};

pub struct DuckDBStorage {
    config: StorageConfig,
    connection: Arc<Mutex<Connection>>,
    db: String,
    table: String,
    table_schema: Option<TableSchema>,
}

impl DuckDBStorage {
    pub fn new(
        config: StorageConfig,
        db: String,
        table: String,
        schema_file_path: Option<String>,
        connection: Arc<Mutex<Connection>>,
    ) -> ZResult<Box<dyn Storage>> {
        tracing::info!(
            "Creating storage: key_expr='{}' -> {}.{} (schema_file_path: {:?})", 
            config.key_expr, db, table, schema_file_path
        );
        
        // Use shared connection provided by Volume
        // Create database (if not exists) and switch to that database
        {
            let conn = connection.lock().unwrap();
            Self::create_schema(&conn, &db)?;
            Self::use_schema(&conn, &db)?;
        }
        
        // Load table schema if provided
        let table_schema = Self::load_table_schema(schema_file_path.as_deref())?;
        
        // Create table structure before creating storage object
        Self::create_table(&connection, &db, &table, &table_schema)?;

        let storage = DuckDBStorage {
            config,
            connection,
            db,
            table,
            table_schema,
        };
        
        Ok(Box::new(storage))
    }

    /// Load table schema from file if provided
    fn load_table_schema(table_desc_path: Option<&str>) -> ZResult<Option<TableSchema>> {
        match table_desc_path {
            Some(path) => {
                let mut ts = TableSchema::new();
                ts.load_file(path)
                    .map_err(|e| zerror!("Failed to load schema file {}: {}", path, e))?;
                Ok(Some(ts))
            }
            None => Ok(None),
        }
    }
    
    /// Create database (if not exists)
    fn create_schema(connection: &Connection, db_name: &str) -> ZResult<()> {
        let create_db_sql = format!("CREATE SCHEMA IF NOT EXISTS {}", db_name);
        connection.execute(&create_db_sql, [])
            .map_err(|e| zerror!("Failed to create database '{}': {}", db_name, e))?;
        
        tracing::debug!("Successfully created database: {}", db_name);
        Ok(())
    }

    /// Switch to database
    fn use_schema(connection: &Connection, db_name: &str) -> ZResult<()> {
        let use_db_sql = format!("USE {}", db_name);
        connection.execute(&use_db_sql, [])
            .map_err(|e| zerror!("Failed to use database '{}': {}", db_name, e))?;
        
        tracing::debug!("Successfully switched to database: {}", db_name);
        Ok(())
    }

    /// Create table structure
    fn create_table(
        connection: &Arc<Mutex<Connection>>,
        db: &str,
        table: &str,
        table_schema: &Option<TableSchema>
    ) -> ZResult<()> {
        tracing::info!("Creating table structure for {}.{}", db, table);
        
        // Generate DDL - TableSchema handles both cases (with/without schema)
        let default_schema = TableSchema::new();
        let table_schema = table_schema.as_ref().unwrap_or(&default_schema);
        let ddl = table_schema.generate_ddl(table);

        tracing::debug!("Generated DDL:\n{}", ddl);
        
        // Execute DDL to create table (schema already switched during connection)
        let conn = connection.lock().unwrap();
        
        // Split DDL statements and execute separately
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
        
        tracing::info!("Successfully created table: {}", table);
        
        Ok(())
    }

    /// Get table name (schema already switched during connection)
    fn get_table_name(&self) -> String {
        self.table.clone()
    }

    /// Get schema fields (便利方法供外部使用)
    pub fn get_schema_fields(&self) -> Option<&[SchemaField]> {
        self.table_schema.as_ref().and_then(|ts| ts.get_fields())
    }

    fn key_to_string(&self, key: &Option<OwnedKeyExpr>) -> String {
        match key {
            Some(k) => k.to_string(),
            None => "**".to_string(), // Wildcard indicates no key
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

    /// Parse JSON payload and extract field values
    fn parse_json_payload(&self, payload: &[u8]) -> ZResult<Value> {
        let json_str = std::str::from_utf8(payload)
            .map_err(|e| zerror!("Invalid UTF-8 in payload: {}", e))?;
        
        let json_value: Value = serde_json::from_str(json_str)
            .map_err(|e| zerror!("Failed to parse JSON payload: {}", e))?;
        
        Ok(json_value)
    }

    /// Use DuckDB Appender for high-performance insertion
    /// 
    /// This method creates a new Appender for each call to ensure thread safety
    /// and data consistency. The overhead is minimal compared to the benefits.
    /// 
    /// Table structure (in order):
    /// 1. zenoh_timestamp VARCHAR NOT NULL (primary key)
    /// 2. key_expr VARCHAR NOT NULL  
    /// 3. kind VARCHAR NOT NULL
    /// 4. JSON Schema fields (from schema_fields)
    fn append_data_with_appender(&self, json_data: &Value, key_expr: &str, timestamp: &Timestamp, kind: &str) -> ZResult<()> {
        // Get schema fields
        let fields = self.table_schema.as_ref()
            .and_then(|ts| ts.get_fields())
            .ok_or_else(|| zerror!("No schema fields available - table_schema not specified"))?;
        
        // Prepare all values first (outside of connection lock for better concurrency)
        let timestamp_str = timestamp.to_string();
        let mut row_values: Vec<&dyn duckdb::ToSql> = Vec::new();
        
        // 1. Add Zenoh required fields in correct order (matching DDL generation)
        row_values.push(&timestamp_str);  // zenoh_timestamp (primary key, first column)
        row_values.push(&key_expr);       // key_expr (second column)  
        row_values.push(&kind);           // kind (third column)
        
        // 2. Prepare JSON Schema field values (in the order they appear in schema)
        let mut schema_field_values: Vec<Option<String>> = Vec::new();
        for field in fields.iter() {
            if field.is_top_level {
                let value = match json_data.get(&field.name) {
                    Some(v) => {
                        if field.is_object || field.is_array {
                            // Complex objects/arrays are serialized as JSON strings
                            Some(serde_json::to_string(v).unwrap_or_else(|_| "null".to_string()))
                        } else {
                            // Basic fields: convert to string
                            match v {
                                Value::String(s) => Some(s.clone()),
                                Value::Number(n) => Some(n.to_string()),
                                Value::Bool(b) => Some(b.to_string()),
                                Value::Null => None,
                                _ => Some(v.to_string()),
                            }
                        }
                    }
                    None => None, // Field not present in JSON -> NULL
                };
                schema_field_values.push(value);
            }
        }
        
        // 3. Add schema field values to row (maintaining order)
        for value in &schema_field_values {
            row_values.push(value);
        }
        
        // 4. Now acquire connection lock and perform the append operation
        let conn = self.connection.lock().unwrap();
        let table_name = self.get_table_name();
        
        // Create DuckDB Appender using the correct appender_to_db method
        let mut appender = conn.appender_to_db(&table_name, &self.db)
            .map_err(|e| zerror!("Failed to create appender for table '{}' in db '{}': {}", table_name, self.db, e))?;
        
        // Append the complete row with all fields
        appender.append_row(&row_values[..])
            .map_err(|e| zerror!("Failed to append row with {} columns: {}", row_values.len(), e))?;
        
        // Flush immediately to ensure data is written (no batching)
        appender.flush()
            .map_err(|e| zerror!("Failed to flush appender: {}", e))?;
        
        tracing::debug!("Successfully appended data using DuckDB Appender for key: {} with {} total columns", 
                       key_expr, row_values.len());
        Ok(())
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

        // Use structured storage
        if self.table_schema.is_some() {
            match self.parse_json_payload(&value_bytes) {
                Ok(json_data) => {
                    tracing::info!("Parsed JSON data: {}", serde_json::to_string(&json_data).unwrap_or("Failed to serialize".to_string()));
                    
                    // Use DuckDB Appender for high-performance insertion
                    match self.append_data_with_appender(&json_data, &key_str, &timestamp, "PUT") {
                        Ok(()) => {
                            tracing::info!("Data successfully stored using DuckDB Appender for key: {}", key_str);
                        }
                        Err(e) => {
                            tracing::error!("Failed to append data with DuckDB Appender: {}", e);
                            return Err(zerror!("Failed to append data with DuckDB Appender: {}", e).into());
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
            return Err(zerror!("No table_schema specified - structured storage requires schema definition").into());
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


        // Insert deletion marker
        let insert_sql = format!(
            "INSERT INTO {} (key_expr, zenoh_timestamp, kind) VALUES (?, ?, 'DEL')",
            self.get_table_name()
        );
        
        let conn = self.connection.lock().unwrap();
        conn.execute(&insert_sql, params![key_str, timestamp_nanos])
            .map_err(|e| zerror!("Failed to insert delete marker into DuckDB: {}", e))?;

        // Delete data with the same key that is earlier than this timestamp
        let delete_sql = format!(
            "DELETE FROM {} WHERE key_expr = ? AND zenoh_timestamp < ? AND kind = 'PUT'",
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

        // Construct JSON based on schema top-level fields
        let table_name = self.get_table_name();
        let fields = match self.table_schema.as_ref().and_then(|ts| ts.get_fields()) {
            Some(fields) => fields,
            None => {
                // No schema available, return empty result
                return Ok(vec![]);
            }
        };

        let mut json_pairs: Vec<String> = Vec::new();
        for f in fields.iter().filter(|f| f.is_top_level) {
            json_pairs.push(format!("'{}', {}", f.name, f.name));
        }
        let json_expr = if json_pairs.is_empty() { "'{}'".to_string() } else { format!("json_object({})", json_pairs.join(", ")) };

        let sql = if key.is_some() {
            format!(
                "SELECT {}, zenoh_timestamp FROM {} WHERE key_expr = ? ORDER BY zenoh_timestamp DESC LIMIT 1",
                json_expr, table_name
            )
        } else {
            format!(
                "SELECT {}, zenoh_timestamp FROM {} ORDER BY zenoh_timestamp DESC LIMIT 1",
                json_expr, table_name
            )
        };

        let conn = self.connection.lock().unwrap();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| zerror!("Failed to prepare query: {}", e))?;

        let rows: Vec<(String, String)> = if key.is_some() {
            stmt.query_map(params![key_str], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| zerror!("Failed to execute query: {}", e))?
            .collect::<Result<Vec<(String, String)>, _>>()
            .map_err(|e| zerror!("Failed to collect query results: {}", e))?
        } else {
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| zerror!("Failed to execute query: {}", e))?
            .collect::<Result<Vec<(String, String)>, _>>()
            .map_err(|e| zerror!("Failed to collect query results: {}", e))?
        };

        let mut result = Vec::new();
        for (json_str, timestamp_str) in rows {
            let timestamp = Timestamp::from_str(&timestamp_str)
                .map_err(|e| zerror!("Failed to parse timestamp: {:?}", e))?;
            let payload = ZBytes::from(json_str.as_bytes());
            let encoding = Encoding::default();

            result.push(StoredData { payload, encoding, timestamp });
        }

        Ok(result)
    }

    async fn get_all_entries(&self) -> ZResult<Vec<(Option<OwnedKeyExpr>, Timestamp)>> {

        // Query the latest entry for each unique key
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
            .collect::<Result<Vec<(String, String)>, _>>()
            .map_err(|e| zerror!("Failed to collect get_all_entries rows: {}", e))?;

        let mut result = Vec::new();
        for (key_str, latest_timestamp_str) in rows {
            let key = self.string_to_key(&key_str)?;
            
            // Recover zenoh Timestamp from string timestamp
            let timestamp = match Timestamp::from_str(&latest_timestamp_str) {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!("Failed to parse timestamp {}, skipping entry", latest_timestamp_str);
                    continue; // Skip entries that cannot be parsed
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