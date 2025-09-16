/* Copyright (C) 2025-2035 Open Information Security Foundation
 *
 * 测试DuckDBBackend Plugin整体对外能力
 */

use zenoh_backend_duckdb::plugin::DuckDBBackend;
use zenoh_backend_traits::config::VolumeConfig;
use zenoh_plugin_trait::Plugin;
use zenoh::{
    key_expr::OwnedKeyExpr,
    time::Timestamp,
    bytes::{ZBytes, Encoding},
};
use std::str::FromStr;
use tracing::info;

// 测试常量
const TEST_DB_PATH: &str = ":memory:";
const SAMPLE_EVENT_DATA: &str = r#"{"event_type": "flow", "timestamp": "2023-01-01T00:00:00.000+00:00", "flow_id": 123, "src_ip": "192.168.1.1"}"#;

// 测试辅助函数
fn create_volume_config(db_path: &str) -> VolumeConfig {
    let mut rest = serde_json::Map::new();
    rest.insert("db_path".to_string(), serde_json::Value::String(db_path.to_string()));
    
    VolumeConfig {
        name: "test_volume".to_string(),
        backend: None,
        paths: None,
        required: false,
        rest,
    }
}

fn create_storage_config(schema: &str, table: &str) -> zenoh_backend_traits::config::StorageConfig {
    let mut volume_cfg = serde_json::Map::new();
    volume_cfg.insert("db_schema".to_string(), serde_json::Value::String(schema.to_string()));
    volume_cfg.insert("db_table".to_string(), serde_json::Value::String(table.to_string()));
    volume_cfg.insert("db_table_desc".to_string(), serde_json::Value::String("etc/flow_schema.json".to_string()));
    
    zenoh_backend_traits::config::StorageConfig {
        name: "test_storage".to_string(),
        key_expr: OwnedKeyExpr::from_str("test/**").unwrap(),
        strip_prefix: None,
        complete: Default::default(),
        volume_id: "test_volume".to_string(),
        volume_cfg: serde_json::Value::Object(volume_cfg),
        garbage_collection_config: Default::default(),
        replication: Default::default(),
    }
}

/// 测试Plugin整体对外能力
#[tokio::test]
async fn test_plugin_start() {
    info!("测试: Plugin启动");
    
    // 测试：Plugin能成功启动并返回Volume实例
    let config = create_volume_config(TEST_DB_PATH);
    
    // 调用Plugin的start方法
    let result = DuckDBBackend::start("duckdb_backend", &config);
    assert!(result.is_ok(), "Plugin should start successfully");
    
    let volume = result.unwrap();
    
    // 验证返回的是有效的Volume实例
    let admin_status = volume.get_admin_status();
    assert!(admin_status.is_object(), "Volume should return valid admin status");
    
    let capability = volume.get_capability();
    assert_eq!(capability.persistence, zenoh_backend_traits::Persistence::Durable);
    assert_eq!(capability.history, zenoh_backend_traits::History::All);
    
    info!("✅ Plugin启动成功 - persistence: {:?}, history: {:?}", capability.persistence, capability.history);
}

#[tokio::test]
async fn test_plugin_create_storage() {
    info!("测试: Plugin创建Storage");
    
    // 测试：Plugin启动后能创建Storage
    let config = create_volume_config(TEST_DB_PATH);
    let volume = DuckDBBackend::start("duckdb_backend", &config).unwrap();
    
    // 通过Volume创建Storage
    let storage_config = create_storage_config("test_schema", "events");
    let storage_result = volume.create_storage(storage_config).await;
    
    assert!(storage_result.is_ok(), "Plugin should create storage successfully");
    let storage = storage_result.unwrap();
    
    // 验证Storage基本功能
    assert!(storage.get_admin_status().is_object(), "Storage should return valid admin status");
    
    info!("✅ Storage创建成功 - schema: test_schema, table: events");
}

#[tokio::test]
async fn test_plugin_put_get() {
    info!("测试: Plugin数据存储和检索");
    
    // 测试：Plugin的完整数据存储和检索能力
    let config = create_volume_config(TEST_DB_PATH);
    let volume = DuckDBBackend::start("duckdb_backend", &config).unwrap();
    
    // 创建Storage
    let storage_config = create_storage_config("test_schema", "events");
    let mut storage = volume.create_storage(storage_config).await.unwrap();
    
    // 测试PUT操作
    let key = OwnedKeyExpr::from_str("test/event/1").unwrap();
    let timestamp = Timestamp::from_str("1234567890/abcdef1234567890").unwrap();
    let payload = ZBytes::from(SAMPLE_EVENT_DATA.as_bytes());
    
    let put_result = storage.put(Some(key.clone()), payload, Encoding::default(), timestamp).await;
    assert!(put_result.is_ok(), "Plugin should support PUT operations");
    
    // 测试GET操作
    let get_result = storage.get(Some(key.clone()), "").await;
    if let Err(e) = &get_result {
        println!("GET operation failed: {:?}", e);
    }
    assert!(get_result.is_ok(), "Plugin should support GET operations");
    
    let samples = get_result.unwrap();
    assert!(!samples.is_empty(), "Plugin should return stored data");
    
    info!("✅ 数据存储和检索成功 - key: {}, 返回{}条数据", key, samples.len());
}

#[tokio::test]
async fn test_plugin_delete() {
    info!("测试: Plugin数据删除");
    
    // 测试：Plugin的数据删除能力
    let config = create_volume_config(TEST_DB_PATH);
    let volume = DuckDBBackend::start("duckdb_backend", &config).unwrap();
    
    // 创建Storage
    let storage_config = create_storage_config("test_schema", "events");
    let mut storage = volume.create_storage(storage_config).await.unwrap();
    
    // 先存储数据
    let key = OwnedKeyExpr::from_str("test/event/2").unwrap();
    let timestamp = Timestamp::from_str("1234567890/abcdef1234567890").unwrap();
    let payload = ZBytes::from(SAMPLE_EVENT_DATA.as_bytes());
    
    storage.put(Some(key.clone()), payload, Encoding::default(), timestamp).await.unwrap();
    
    // 测试DELETE操作
    let delete_result = storage.delete(Some(key.clone()), timestamp).await;
    if let Err(e) = &delete_result {
        println!("DELETE operation failed: {:?}", e);
    }
    assert!(delete_result.is_ok(), "Plugin should support DELETE operations");
    
    info!("✅ 数据删除成功 - key: {}", key);
}

#[tokio::test]
async fn test_plugin_query() {
    info!("测试: Plugin查询");
    
    // 测试：Plugin的查询能力
    let config = create_volume_config(TEST_DB_PATH);
    let volume = DuckDBBackend::start("duckdb_backend", &config).unwrap();
    
    // 创建Storage
    let storage_config = create_storage_config("test_schema", "events");
    let mut storage = volume.create_storage(storage_config).await.unwrap();
    
    // 存储一些测试数据
    for i in 1..=3 {
        let key = OwnedKeyExpr::from_str(&format!("test/event/{}", i)).unwrap();
        let timestamp = Timestamp::from_str("1234567890/abcdef1234567890").unwrap();
        let payload = ZBytes::from(SAMPLE_EVENT_DATA.as_bytes());
        storage.put(Some(key), payload, Encoding::default(), timestamp).await.unwrap();
    }
    
    // 测试查询操作
    let query_key = OwnedKeyExpr::from_str("test/**").unwrap();
    let query_result = storage.get(Some(query_key), "").await;
    assert!(query_result.is_ok(), "Plugin should support query operations");
    
    let samples = query_result.unwrap();
    assert!(samples.len() >= 3, "Plugin should return multiple matching samples");
    
    info!("✅ 查询成功 - 模式: test/**, 返回{}条数据", samples.len());
}

#[tokio::test]
async fn test_plugin_error_handling() {
    info!("测试: Plugin错误处理能力");
    
    // 测试：Plugin的错误处理能力
    let config = create_volume_config(TEST_DB_PATH);
    let volume = DuckDBBackend::start("duckdb_backend", &config).unwrap();
    
    // 创建Storage
    let storage_config = create_storage_config("test_schema", "events");
    let mut storage = volume.create_storage(storage_config).await.unwrap();
    
    // 测试无效key的处理
    let invalid_key = OwnedKeyExpr::from_str("invalid;key").unwrap();
    let timestamp = Timestamp::from_str("1234567890/abcdef1234567890").unwrap();
    let payload = ZBytes::from("test".as_bytes());
    
    let _put_result = storage.put(Some(invalid_key), payload, Encoding::default(), timestamp).await;
    // 应该能处理无效key（可能成功或失败，但不会崩溃）
    // 这里主要测试Plugin不会因为无效输入而崩溃
    
    info!("✅ 错误处理测试完成 - 无效key处理正常");
}

#[tokio::test]
async fn test_plugin_multiple_storages() {
    info!("测试: Plugin多Storage支持");
    
    // 测试：Plugin支持多个Storage实例
    let config = create_volume_config(TEST_DB_PATH);
    let volume = DuckDBBackend::start("duckdb_backend", &config).unwrap();
    
    // 创建多个Storage
    let storage1_config = create_storage_config("schema1", "events1");
    let mut storage1 = volume.create_storage(storage1_config).await.unwrap();
    
    let storage2_config = create_storage_config("schema2", "events2");
    let mut storage2 = volume.create_storage(storage2_config).await.unwrap();
    
    // 验证两个Storage都能正常工作
    assert!(storage1.get_admin_status().is_object(), "First storage should work");
    assert!(storage2.get_admin_status().is_object(), "Second storage should work");
    
    // 测试两个Storage的独立性
    let key1 = OwnedKeyExpr::from_str("test/event/1").unwrap();
    let key2 = OwnedKeyExpr::from_str("test/event/2").unwrap();
    let timestamp = Timestamp::from_str("1234567890/abcdef1234567890").unwrap();
    let payload = ZBytes::from("test data".as_bytes());
    
    storage1.put(Some(key1), payload.clone(), Encoding::default(), timestamp).await.unwrap();
    storage2.put(Some(key2), payload, Encoding::default(), timestamp).await.unwrap();
    
    // 验证数据隔离
    let result1 = storage1.get(Some(OwnedKeyExpr::from_str("test/**").unwrap()), "").await.unwrap();
    let result2 = storage2.get(Some(OwnedKeyExpr::from_str("test/**").unwrap()), "").await.unwrap();
    
    assert_eq!(result1.len(), 1, "First storage should have 1 sample");
    assert_eq!(result2.len(), 1, "Second storage should have 1 sample");
    
    info!("✅ 多Storage测试成功 - storage1: {}条数据, storage2: {}条数据", result1.len(), result2.len());
}
