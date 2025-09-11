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

use crate::volume::DuckDBVolume;

struct DuckDBBackend {}

#[cfg(feature = "dynamic_plugin")]
zenoh_plugin_trait::declare_plugin!(DuckDBBackend);

impl Plugin for DuckDBBackend {
    type StartArgs = VolumeConfig;
    type Instance = VolumeInstance;

    const DEFAULT_NAME: &'static str = "duckdb_backend";
    const PLUGIN_VERSION: &'static str = plugin_version!();
    const PLUGIN_LONG_VERSION: &'static str = plugin_long_version!();

    fn start(name: &str, config: &Self::StartArgs) -> ZResult<Self::Instance> {
        // 1. 初始化日志系统
        try_init_log_from_env();
        
        // 2. 验证插件名称
        if name != Self::DEFAULT_NAME {
            tracing::warn!("Plugin started with non-default name: {} (expected: {})", 
                         name, Self::DEFAULT_NAME);
        }
        
        // 3. 记录启动信息
        tracing::info!("Starting DuckDB backend plugin {} (version: {})", 
                      name, Self::PLUGIN_VERSION);
        
        // 4. 验证配置
        Self::validate_config(config)?;
        
        // 5. 准备配置并注入版本信息
        let mut enhanced_config = config.clone();
        enhanced_config.rest.insert("version".into(), Self::PLUGIN_VERSION.into());
        enhanced_config.rest.insert("plugin_name".into(), name.into());
        
        // 6. 创建Volume实例
        let volume = DuckDBVolume::new(enhanced_config)
            .map_err(|e| {
                tracing::error!("Failed to create DuckDB volume: {}", e);
                zerror!("DuckDB backend initialization failed: {}", e)
            })?;
        
        // 7. 启动成功
        tracing::info!("DuckDB backend plugin started successfully");
        Ok(Box::new(volume))
    }
}

impl DuckDBBackend {
    /// 验证插件配置的有效性
    fn validate_config(config: &VolumeConfig) -> ZResult<()> {
        tracing::debug!("Validating plugin configuration");
        
        // 检查基本配置结构
        if config.rest.is_empty() {
            tracing::warn!("No additional configuration provided, using defaults");
        }
        
        // 验证数据库路径配置（如果存在）
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
        
        // Volume配置只需要db_path，db_schema和db_table在storage配置中
        
        // 验证db_table_desc配置（如果存在）
        if let Some(db_table_desc) = config.rest.get("db_table_desc") {
            if let Some(path_str) = db_table_desc.as_str() {
                if path_str.is_empty() {
                    return Err(zerror!("db_table_desc file path cannot be empty").into());
                }
                // 检查文件是否存在
                if !std::path::Path::new(path_str).exists() {
                    return Err(zerror!("db_table_desc file not found: {}", path_str).into());
                }
                tracing::debug!("db_table_desc file configured: {}", path_str);
            } else {
                return Err(zerror!("db_table_desc file path must be a string").into());
            }
        }
        
        tracing::debug!("Configuration validation completed successfully");
        Ok(())
    }
}
