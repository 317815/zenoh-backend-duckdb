use async_trait::async_trait;
use zenoh::{
    internal::zerror,
    Result as ZResult,
};
use zenoh_backend_traits::{
    config::{StorageConfig, VolumeConfig},
    Capability, History, Persistence, Storage, Volume,
};

use crate::storage::DuckDBStorage;

// 配置常量
const PROP_DB_PATH: &str = "db_path";

/// DuckDB Volume - 管理DuckDB数据库配置
/// 
/// 职责：
/// 1. 管理数据库文件路径配置
/// 2. 为Storage提供数据库路径
/// 3. 不管理连接，每个Storage独立连接
pub struct DuckDBVolume {
    /// Volume配置状态
    admin_status: VolumeConfig,
    /// 数据库文件路径
    db_path: String,
}

impl DuckDBVolume {
    /// 创建新的DuckDB Volume
    pub fn new(config: VolumeConfig) -> ZResult<Self> {
        // 解析数据库路径
        let db_path = config
            .rest
            .get(PROP_DB_PATH)
            .and_then(|v| v.as_str())
            .unwrap_or(":memory:")
            .to_string();

        tracing::info!("Initializing DuckDB Volume with database: {}", db_path);

        Ok(DuckDBVolume {
            admin_status: config,
            db_path,
        })
    }
}

#[async_trait]
impl Volume for DuckDBVolume {
    /// 返回Volume的管理状态
    fn get_admin_status(&self) -> serde_json::Value {
        self.admin_status.to_json_value()
    }

    /// 声明DuckDB backend的能力
    fn get_capability(&self) -> Capability {
        Capability {
            persistence: Persistence::Durable,  // 持久化存储
            history: History::All,              // 保留所有历史记录
        }
    }

    /// 创建新的Storage实例
    async fn create_storage(&self, config: StorageConfig) -> ZResult<Box<dyn Storage>> {
        // 从volume配置中读取schema和table（必需）
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
        
        // 解析volume配置中的table_desc文件路径（可选）
        let table_desc = volume_cfg.get("db_table_desc")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        tracing::info!(
            "Creating DuckDB storage: key_expr='{}' -> {}.{} (table_desc: {:?})", 
            config.key_expr, schema, table, table_desc
        );

        DuckDBStorage::new(config, &self.db_path, schema, table, table_desc)
    }
}