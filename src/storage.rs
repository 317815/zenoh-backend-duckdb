/* Copyright (C) 2025-2035 Open Information Security Foundation
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
        schema: String,
        table: String,
        table_desc: Option<String>,
        connection: Arc<Mutex<Connection>>,
    ) -> ZResult<Box<dyn Storage>> {
        // Validate schema and table name validity
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
        
        // Use shared connection provided by Volume
        // Create schema (if not exists) and switch to that schema
        {
            let conn = connection.lock().unwrap();
            Self::create_and_use_schema(&conn, &schema)?;
        }
        
        let storage = DuckDBStorage {
            config,
            connection,
            table: table.clone(),
            table_desc,
        };

        // If table_desc is specified, create table structure
        if storage.table_desc.is_some() {
            if let Err(e) = storage.create_table() {
                tracing::error!("Failed to create table from schema: {}", e);
                return Err(zerror!("Failed to create table from schema: {}", e).into());
            }
        }
        
        Ok(Box::new(storage))
    }
    
    /// Create schema (if not exists) and switch to that schema
    fn create_and_use_schema(connection: &Connection, schema_name: &str) -> ZResult<()> {
        // Create schema (if not exists)
        let create_schema_sql = format!("CREATE SCHEMA IF NOT EXISTS {}", schema_name);
        connection.execute(&create_schema_sql, [])
            .map_err(|e| zerror!("Failed to create schema '{}': {}", schema_name, e))?;
        
        // Switch to that schema
        let use_schema_sql = format!("USE {}", schema_name);
        connection.execute(&use_schema_sql, [])
            .map_err(|e| zerror!("Failed to use schema '{}': {}", schema_name, e))?;
        
        tracing::debug!("Successfully created and switched to schema: {}", schema_name);
        Ok(())
    }
    
    /// Validate if identifier is valid
    pub fn is_valid_identifier(name: &str) -> bool {
        !name.is_empty() 
            && name.len() <= 64
            && name.chars().all(|c| c.is_alphanumeric() || c == '_')
            && name.chars().next().map_or(false, |c| !c.is_ascii_digit())
    }

    /// Create table structure from table_desc file
    fn create_table(&self) -> ZResult<()> {
        let table_desc = self.table_desc.as_ref()
            .ok_or_else(|| zerror!("No table_desc file specified"))?;
        
        tracing::info!("Creating table from table_desc file: {}", table_desc);
        
        // Create table_desc parser
        let parser = SchemaParser::new();

        // Generate DDL
        let ddl = parser.load_schema_file(table_desc, &self.get_table_name())
            .map_err(|e| zerror!("Failed to generate DDL: {}", e))?;

        tracing::debug!("Generated DDL:\n{}", ddl);
        
        // Execute DDL to create table (schema already switched during connection)
        let conn = self.connection.lock().unwrap();
        
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
        
        tracing::info!("Successfully created table: {}", self.get_table_name());
        
        Ok(())
    }

    /// Get table name (schema already switched during connection)
    fn get_table_name(&self) -> String {
        self.table.clone()
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

    /// Dynamically generate INSERT statement
    fn generate_dynamic_insert(&self, json_data: &Value, key_expr: &str, timestamp: &Timestamp, kind: &str) -> ZResult<String> {
        let table_desc = self.table_desc.as_ref()
            .ok_or_else(|| zerror!("No table_desc specified"))?;
        
        // Use SchemaParser to parse schema
        let parser = SchemaParser::new();
        let schema_content = std::fs::read_to_string(table_desc)
            .map_err(|e| zerror!("Failed to read schema file {}: {}", table_desc, e))?;
        
        let schema: Value = serde_json::from_str(&schema_content)
            .map_err(|e| zerror!("Failed to parse JSON schema: {}", e))?;
        
        let fields = parser.parse_schema(&schema)
            .map_err(|e| zerror!("Failed to parse schema: {}", e))?;
        
        // Build column name list
        let mut column_names = Vec::new();
        let mut values = Vec::new();
        
        // First add Zenoh required fields
        column_names.push("key_expr".to_string());
        values.push(format!("'{}'", key_expr.replace("'", "''")));
        
        column_names.push("zenoh_timestamp".to_string());
        values.push(format!("'{}'", timestamp.to_string().replace("'", "''")));

        column_names.push("kind".to_string());
        values.push(format!("'{}'", kind));
        
        // Then add JSON Schema fields
        for field in &fields {
            if field.is_top_level {
                let value = match json_data.get(&field.name) {
                    Some(v) => {
                        // Complex objects are directly serialized as JSON strings
                        if field.is_object || field.is_array {
                            serde_json::to_string(v).unwrap_or("null".to_string())
                        } else {
                            // Basic fields converted to strings
                            v.as_str().unwrap_or(&v.to_string()).to_string()
                        }
                    }
                    None => "NULL".to_string(),
                };
                
                column_names.push(field.name.clone());
                values.push(if value == "NULL" { "NULL".to_string() } else { format!("'{}'", value.replace("'", "''")) });
            }
        }
        
        // Build INSERT statement
        let columns_str = column_names.join(", ");
        let values_str = values.join(", ");
        let insert_sql = format!(
            "INSERT OR REPLACE INTO {} ({}) VALUES ({})",
            self.get_table_name(), columns_str, values_str
        );
        
        Ok(insert_sql)
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
        let table_desc = match &self.table_desc {
            Some(d) => d.clone(),
            None => {
                return Ok(vec![]);
            }
        };

        let parser = SchemaParser::new();
        let schema_content = std::fs::read_to_string(&table_desc)
            .map_err(|e| zerror!("Failed to read schema file {}: {}", table_desc, e))?;
        let schema: Value = serde_json::from_str(&schema_content)
            .map_err(|e| zerror!("Failed to parse JSON schema: {}", e))?;
        let fields = parser.parse_schema(&schema)
            .map_err(|e| zerror!("Failed to parse schema: {}", e))?;

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