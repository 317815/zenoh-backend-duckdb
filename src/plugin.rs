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
 * This is a plugin for Zenoh to store data in DuckDB.
 */

use std::path::{Path, PathBuf};

use zenoh::{
    internal::zerror,
    try_init_log_from_env, 
    Result as ZResult,
};
use zenoh_backend_traits::{
    config::VolumeConfig,
    VolumeInstance,
};
use zenoh_plugin_trait::{plugin_long_version, plugin_version, Plugin};
use zenoh_util;

use crate::volume::DuckDBVolume;

pub struct DuckDBBackend {}

#[cfg(feature = "dynamic_plugin")]
zenoh_plugin_trait::declare_plugin!(DuckDBBackend);

impl Plugin for DuckDBBackend {
    type StartArgs = VolumeConfig;
    type Instance = VolumeInstance;

    const DEFAULT_NAME: &'static str = "duckdb_backend";
    const PLUGIN_VERSION: &'static str = plugin_version!();
    const PLUGIN_LONG_VERSION: &'static str = plugin_long_version!();

    fn start(name: &str, config: &Self::StartArgs) -> ZResult<Self::Instance> {
        // 1. Initialize logging system
        try_init_log_from_env();
        
        // 2. Validate plugin name
        if name != Self::DEFAULT_NAME {
            tracing::warn!("Plugin started with non-default name: {} (expected: {})", 
                         name, Self::DEFAULT_NAME);
        }
        
        // 3. Log startup information
        tracing::info!("Starting DuckDB backend plugin {} (version: {})", 
                      name, Self::PLUGIN_VERSION);
        
        // 4. Validate configuration
        Self::validate_config(config)?;
        
        // 5. Prepare configuration and inject version information
        let mut enhanced_config = config.clone();
        enhanced_config.rest.insert("version".into(), Self::PLUGIN_VERSION.into());
        enhanced_config.rest.insert("plugin_name".into(), name.into());
        
        // 6. Create Volume instance
        let volume = DuckDBVolume::new(enhanced_config)
            .map_err(|e| {
                tracing::error!("Failed to create DuckDB volume: {}", e);
                zerror!("DuckDB backend initialization failed: {}", e)
            })?;
        
        // 7. Startup successful
        tracing::info!("DuckDB backend plugin started successfully");
        Ok(Box::new(volume))
    }
}

impl DuckDBBackend {
    /// Validate if identifier is valid for SQL
    pub fn is_valid_identifier(name: &str) -> bool {
        !name.is_empty() 
            && name.len() <= 64
            && name.chars().all(|c| c.is_alphanumeric() || c == '_')
            && name.chars().next().map_or(false, |c| !c.is_ascii_digit())
    }
    
    /// Validate the validity of plugin configuration
    fn validate_config(config: &VolumeConfig) -> ZResult<()> {
        tracing::debug!("Validating plugin configuration");
        
        // Check basic configuration structure
        if config.rest.is_empty() {
            tracing::warn!("No additional configuration provided, using defaults");
        }
        
        // Validate database path configuration (if exists)
        if let Some(db_path) = config.rest.get("db_path") {
            if let Some(path_str) = db_path.as_str() {
                if path_str.is_empty() {
                    return Err(zerror!("Database path cannot be empty").into());
                }
                tracing::debug!("Database path configured: {}", path_str);
            } else {
                return Err(zerror!("Database path must be a string").into());
            }
        }
        
        // Validate db identifier (if exists)
        if let Some(db) = config.rest.get("db") {
            if let Some(db_str) = db.as_str() {
                if !Self::is_valid_identifier(db_str) {
                    return Err(zerror!("Invalid database name '{}': must be non-empty, ≤64 chars, alphanumeric+underscore, not start with digit", db_str).into());
                }
                tracing::debug!("Database name validated: {}", db_str);
            } else {
                return Err(zerror!("Database name must be a string").into());
            }
        }
        
        // Validate table identifier (if exists)
        if let Some(table) = config.rest.get("table") {
            if let Some(table_str) = table.as_str() {
                if !Self::is_valid_identifier(table_str) {
                    return Err(zerror!("Invalid table name '{}': must be non-empty, ≤64 chars, alphanumeric+underscore, not start with digit", table_str).into());
                }
                tracing::debug!("Table name validated: {}", table_str);
            } else {
                return Err(zerror!("Table name must be a string").into());
            }
        }
        
        // Validate schema_file_path configuration (if exists)
        if let Some(schema_file_path) = config.rest.get("schema_file_path") {
            if let Some(path_str) = schema_file_path.as_str() {
                if path_str.is_empty() {
                    return Err(zerror!("schema_file_path cannot be empty").into());
                }
                
                // Resolve path relative to ZENOH_HOME if needed
                let path = if Path::new(path_str).is_absolute() {
                    PathBuf::from(path_str)
                } else {
                    zenoh_util::zenoh_home().join(path_str)
                };
                
                // Check if file exists
                if !path.exists() {
                    return Err(zerror!("schema_file_path file not found: {} (path: {})", 
                                     path_str, path.display()).into());
                }
                tracing::debug!("schema_file_path configured: {} (path: {})", 
                              path_str, path.display());
            } else {
                return Err(zerror!("schema_file_path must be a string").into());
            }
        }
        
        tracing::debug!("Configuration validation completed successfully");
        Ok(())
    }
}

