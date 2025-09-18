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
 * This is a volume for Zenoh to store data in DuckDB.
 */

use async_trait::async_trait;
use duckdb::Connection;
use std::sync::{Arc, Mutex};
use zenoh::{
    internal::zerror,
    Result as ZResult,
};
use zenoh_backend_traits::{
    config::{StorageConfig, VolumeConfig},
    Capability, History, Persistence, Storage, Volume,
};

use crate::storage::DuckDBStorage;

// Configuration constants
const PROP_DB_PATH: &str = "db_path";
const PROP_INIT_SQL: &str = "init_sql";

/// DuckDB Volume - Manages DuckDB database instance
/// 
/// Responsibilities:
/// 1. Manage database connection (especially shared connection in memory mode)
/// 2. Execute initialization SQL scripts
/// 3. Provide shared database connection to Storage
/// 4. Ensure Storage within Volume share the same database instance
pub struct DuckDBVolume {
    /// Volume configuration status
    admin_status: VolumeConfig,
    /// Shared database connection
    connection: Arc<Mutex<Connection>>,
}

impl DuckDBVolume {
    /// Create a new DuckDB Volume
    pub fn new(config: VolumeConfig) -> ZResult<Self> {
        // Parse database path
        let db_path = config
            .rest
            .get(PROP_DB_PATH)
            .and_then(|v| v.as_str())
            .unwrap_or(":memory:")
            .to_string();

        // Parse initialization SQL script path
        let init_sql = config
            .rest
            .get(PROP_INIT_SQL)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        tracing::info!("Initializing DuckDB Volume with database: {}, init_sql: {:?}", db_path, init_sql);

        // Create database connection
        let connection = Connection::open(&db_path)
            .map_err(|e| zerror!("Failed to open DuckDB database '{}': {}", db_path, e))?;

        // Configure DuckDB optimization settings
        Self::configure_duckdb(&connection)?;

        // Execute initialization SQL script if configured
        if let Some(init_sql_path) = &init_sql {
            Self::execute_duckdb_init_sql(&connection, init_sql_path)?;
        }

        Ok(DuckDBVolume {
            admin_status: config,
            connection: Arc::new(Mutex::new(connection)),
        })
    }
    
    /// Configure DuckDB optimization settings
    fn configure_duckdb(connection: &Connection) -> ZResult<()> {
        // Enable multi-threading (use system CPU cores)
        connection.execute("PRAGMA threads = 4", [])
            .map_err(|e| zerror!("Failed to set threads pragma: {}", e))?;
        
        // Set memory limit (configurable)
        connection.execute("PRAGMA memory_limit = '1GB'", [])
            .map_err(|e| zerror!("Failed to set memory limit: {}", e))?;
        
        tracing::debug!("DuckDB configuration completed");
        Ok(())
    }

    /// Execute initialization SQL script during Volume initialization
    fn execute_duckdb_init_sql(connection: &Connection, init_sql_path: &str) -> ZResult<()> {
        tracing::info!("Executing volume initialization SQL script: {}", init_sql_path);
        
        // Read SQL script file
        let sql_content = std::fs::read_to_string(init_sql_path)
            .map_err(|e| zerror!("Failed to read volume init SQL file '{}': {}", init_sql_path, e))?;
        
        // DuckDB can execute multiple SQL statements in one call
        // No need to split by semicolon manually
        tracing::debug!("Executing volume init SQL script: {}\n{}", init_sql_path, sql_content);
        connection.execute_batch(&sql_content)
            .map_err(|e| zerror!("Failed to execute volume init SQL batch from '{}': {}", init_sql_path, e))?;
        
        tracing::info!("Successfully executed volume init SQL script: {}", init_sql_path);
        Ok(())
    }
}

#[async_trait]
impl Volume for DuckDBVolume {
    /// Return Volume's management status
    fn get_admin_status(&self) -> serde_json::Value {
        self.admin_status.to_json_value()
    }

    /// Declare DuckDB backend capabilities
    fn get_capability(&self) -> Capability {
        Capability {
            persistence: Persistence::Durable,  // Persistent storage
            history: History::All,              // Keep all history records
        }
    }

    /// Create new Storage instance
    async fn create_storage(&self, config: StorageConfig) -> ZResult<Box<dyn Storage>> {
        // Read schema and table from volume configuration (required)
        let volume_cfg = config.volume_cfg.as_object()
            .ok_or_else(|| zerror!("Volume configuration is required"))?;
        
        let schema = volume_cfg.get("db_schema")
            .and_then(|v| v.as_str())
            .ok_or_else(|| zerror!("db_schema is required in volume configuration"))?
            .to_string();
        
        let table = volume_cfg.get("db_table")
            .and_then(|v| v.as_str())
            .ok_or_else(|| zerror!("db_table is required in volume configuration"))?
            .to_string();
        
        // Parse table_desc file path from volume configuration (optional)
        let table_desc = volume_cfg.get("db_table_desc")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        tracing::info!(
            "Creating DuckDB storage: key_expr='{}' -> {}.{} (table_desc: {:?})", 
            config.key_expr, schema, table, table_desc
        );

        DuckDBStorage::new(config, schema, table, table_desc, self.connection.clone())
    }
}
