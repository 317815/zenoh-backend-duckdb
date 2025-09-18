use zenoh_backend_duckdb::plugin::DuckDBBackend;
use zenoh_backend_traits::config::{VolumeConfig, StorageConfig};
use zenoh_backend_traits::VolumeInstance;
use zenoh_plugin_trait::Plugin;
use zenoh::bytes::{ZBytes, Encoding};
use zenoh::time::Timestamp;
use zenoh::key_expr::OwnedKeyExpr;
use tracing::{info, debug};

const BACKEND_NAME: &str = "duckdb_backend";
const VOLUME_NAME: &str = "duckdb_volume";

fn create_storage_config(
    storage_name: &str,
    volume_id: &str,
    key_expr: &str,
    db_schema: &str,
    db_table: &str,
    db_table_desc: Option<&str>,
) -> Result<zenoh_backend_traits::config::StorageConfig, String> {
    let mut volume_cfg = serde_json::Map::new();
    volume_cfg.insert("db_schema".to_string(), serde_json::Value::String(db_schema.to_string()));
    volume_cfg.insert("db_table".to_string(), serde_json::Value::String(db_table.to_string()));

    if let Some(table_desc) = db_table_desc {
        volume_cfg.insert("db_table_desc".to_string(), serde_json::Value::String(table_desc.to_string()));
    }

    Ok(zenoh_backend_traits::config::StorageConfig {
        name: storage_name.to_string(),
        key_expr: OwnedKeyExpr::new(key_expr)
            .map_err(|e| format!("Invalid key_expr: {}", e))?,
        strip_prefix: None,
        complete: Default::default(),
        volume_id: volume_id.to_string(),
        volume_cfg: serde_json::Value::Object(volume_cfg),
        garbage_collection_config: Default::default(),
        replication: Default::default(),
    })
}

// Test case: configuration variables + test data
#[derive(Debug)]
struct TestCase {
    // Configuration variables
    case_name: &'static str,
    storage_name: &'static str,
    volume_id: &'static str,
    key_expr: &'static str,
    db_schema: &'static str,
    db_table: &'static str,
    db_table_desc: Option<&'static str>,
    input_file_path: &'static str,
}

#[derive(Debug, Default)]
struct DiffSummary {
    missing: Vec<String>,
    mismatched: Vec<String>,
    extra: Vec<String>,
}

fn analyze_diff(
    input_json_obj: &serde_json::Map<String, serde_json::Value>,
    result_json_obj: &serde_json::Map<String, serde_json::Value>,
) -> DiffSummary {
    let mut summary = DiffSummary::default();

    for (k, vin) in input_json_obj.iter() {
        match result_json_obj.get(k) {
            Some(vout) => {
                if vout != vin {
                    summary.mismatched.push(k.clone());
                }
            }
            None => summary.missing.push(k.clone()),
        }
    }

    for k in result_json_obj.keys() {
        if !input_json_obj.contains_key(k) {
            summary.extra.push(k.clone());
        }
    }

    summary.missing.sort();
    summary.mismatched.sort();
    summary.extra.sort();
    summary
}

fn log_diff(
    input_json_obj: &serde_json::Map<String, serde_json::Value>,
    result_json_obj: &serde_json::Map<String, serde_json::Value>,
    summary: &DiffSummary,
) {
    info!(
        "Field comparison: {} input, {} output, {} missing, {} mismatched, {} extra",
        input_json_obj.len(),
        result_json_obj.len(),
        summary.missing.len(),
        summary.mismatched.len(),
        summary.extra.len()
    );

    if !summary.missing.is_empty() {
        info!("Missing fields: {:?}", summary.missing);
    }
    if !summary.mismatched.is_empty() {
        info!("Mismatched fields: {:?}", summary.mismatched);
        
        // Output detailed comparison for mismatched fields (JSON formatted)
        for field in &summary.mismatched {
            if let (Some(input_val), Some(result_val)) = (input_json_obj.get(field), result_json_obj.get(field)) {
                let input_formatted = serde_json::to_string_pretty(input_val)
                    .unwrap_or_else(|_| input_val.to_string());
                let result_formatted = serde_json::to_string_pretty(result_val)
                    .unwrap_or_else(|_| result_val.to_string());
                debug!("Field '{}' mismatch:\nInput value:\n{}\nResult value:\n{}", 
                        field, input_formatted, result_formatted);
            }
        }
    }
}

fn validate_diff(
    input_json_obj: &serde_json::Map<String, serde_json::Value>,
    result_json_obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let summary = analyze_diff(input_json_obj, result_json_obj);
    // Unified output of difference details in validation
    log_diff(input_json_obj, result_json_obj, &summary);
    if !summary.missing.is_empty() {
        return Err(format!("Result data missing input fields: {:?}", summary.missing));
    }
    if !summary.mismatched.is_empty() {
        return Err(format!("Field value mismatch: {:?}", summary.mismatched));
    }
    Ok(())
}

// Generic test process: one case -> one config -> one put -> one get
async fn run_storage_test_case(volume_instance: &VolumeInstance, storage_config: StorageConfig, input_json_str: &str) -> Result<String, String> {

    info!(
        "Storage Config: name = {}, volume_id = {}, key_expr = {}, db_schema = {}, db_table = {}, db_table_desc = {:?}",
        storage_config.name,
        storage_config.volume_id,
        storage_config.key_expr,
        storage_config.volume_cfg.get("db_schema").and_then(|v| v.as_str()).unwrap_or(""),
        storage_config.volume_cfg.get("db_table").and_then(|v| v.as_str()).unwrap_or(""),
        storage_config.volume_cfg.get("db_table_desc").and_then(|v| v.as_str()).unwrap_or("")
    );

    let key = OwnedKeyExpr::new(format!("{}/test", storage_config.key_expr.clone()))
        .map_err(|e| format!("Invalid key: {}", e))?;
    let timestamp = Timestamp::parse_rfc3339("2023-01-01T12:00:00Z/33")
        .map_err(|e| format!("Invalid timestamp: {:?}", e))?;
    let payload = ZBytes::from(input_json_str.as_bytes().to_vec());

    // 1. Create Storage
    let mut storage = volume_instance.create_storage(storage_config.clone()).await
        .map_err(|e| format!("Failed to create Storage: {}", e))?;
    
    // 2. PUT request
    storage.put(Some(key.clone()), payload, Encoding::default(), timestamp).await
        .map_err(|e| format!("PUT request failed: {}", e))?;
    
    // 3. GET request
    let samples = storage.get(Some(key.clone()), "").await
        .map_err(|e| format!("GET request failed: {}", e))?;
    
    if samples.is_empty() {
        return Err("GET request returned no data".to_string());
    }
    
    // 4. Return the retrieved data as JSON string
    let retrieved_data = samples[0]
        .payload
        .try_to_string()
        .map_err(|e| format!("Failed to deserialize data: {}", e))?
        .into_owned();

    Ok(retrieved_data)
}

fn run_storage_test_result_validate(input_json_str: String, result_json_str: String) -> Result<(), String> {
    // Parse JSON strings
    let input_json: serde_json::Value = serde_json::from_str(&input_json_str)
        .map_err(|e| format!("Input data is not valid JSON: {}", e))?;
    let result_json: serde_json::Value = serde_json::from_str(&result_json_str)
        .map_err(|e| format!("Result data is not valid JSON: {}", e))?;

    // Format for debug output
    let formatted_input = serde_json::to_string_pretty(&input_json)
        .unwrap_or_else(|_| input_json_str);
    let formatted_result = serde_json::to_string_pretty(&result_json)
        .unwrap_or_else(|_| result_json_str);

    debug!("Input JSON:\n{}", formatted_input);
    debug!("Result JSON:\n{}", formatted_result);

    // Get objects for comparison
    let input_obj = input_json.as_object()
        .ok_or_else(|| "Input JSON is not an object".to_string())?;
    let result_obj = result_json.as_object()
        .ok_or_else(|| "Result JSON is not an object".to_string())?;

    validate_diff(input_obj, result_obj)
}

fn get_test_cases() -> Vec<TestCase> {
    vec![
        TestCase {
            case_name: "http",
            storage_name: "http_storage",
            volume_id: VOLUME_NAME,
            key_expr: "http/**",
            db_schema: "evelog",
            db_table: "http",
            db_table_desc: Some("event-type-shcemas/http_schema.json"),
            input_file_path: "event-type-examples/http_example.json"
        },
        
        TestCase {
            case_name: "flow",
            storage_name: "flow_storage",
            volume_id: VOLUME_NAME,
            key_expr: "flow/**",
            db_schema: "evelog",
            db_table: "flow",
            db_table_desc: Some("event-type-shcemas/flow_schema.json"),
            input_file_path: "event-type-examples/flow_example.json",
        },
        
        TestCase {
            case_name: "alert",
            storage_name: "alert_storage",
            volume_id: VOLUME_NAME,
            key_expr: "alert/**",
            db_schema: "evelog",
            db_table: "alert",
            db_table_desc: Some("event-type-shcemas/alert_schema.json"),
            input_file_path: "event-type-examples/alert_example.json",
        },
        
        TestCase {
            case_name: "dns",
            storage_name: "dns_storage",
            volume_id: VOLUME_NAME,
            key_expr: "dns/**",
            db_schema: "evelog",
            db_table: "dns",
            db_table_desc: Some("event-type-shcemas/dns_schema.json"),
            input_file_path: "event-type-examples/dns_example.json",
        },
        
        TestCase {
            case_name: "tls",
            storage_name: "tls_storage",
            volume_id: VOLUME_NAME,
            key_expr: "tls/**",
            db_schema: "evelog",
            db_table: "tls",
            db_table_desc: Some("event-type-shcemas/tls_schema.json"),
            input_file_path: "event-type-examples/tls_example.json",
        },
    ]
}

fn create_default_volume_config() -> VolumeConfig {
    let mut rest = serde_json::Map::new();
    // Use :memory: as default for testing (non-persistent)
    rest.insert("db_path".to_string(), serde_json::Value::String(":memory:".to_string()));
    // Don't include init_sql if it's empty - let the backend handle the default
    VolumeConfig {
        name: VOLUME_NAME.to_string(),
        backend: Some(BACKEND_NAME.to_string()),
        paths: None, // paths is not used by our DuckDB backend
        required: false,
        rest: rest
    }
}

#[tokio::test]
async fn test_backend() -> Result<(), Box<dyn std::error::Error>> {
    info!("Test: DuckDB backend");

    // 1. Create VolumeConfig
    let volume_config = create_default_volume_config();

    // 2. Start Volume
    let volume_instance = DuckDBBackend::start(BACKEND_NAME, &volume_config)
        .map_err(|e| format!("Failed to start Volume: {}", e))?;
    
    // 3. Run test cases
    for test_case in get_test_cases()    {
        debug!("Running test case: {}", test_case.case_name);

        let storage_config = create_storage_config(
            test_case.storage_name,
            test_case.volume_id,
            test_case.key_expr,
            test_case.db_schema,
            test_case.db_table,
            test_case.db_table_desc
        )?;

        let input_json_str = std::fs::read_to_string(test_case.input_file_path)
            .map_err(|e| format!("Failed to read input data file {}: {}", test_case.input_file_path, e))?;

        let result_json_str = run_storage_test_case(&volume_instance, storage_config, &input_json_str).await.expect("Schema configuration test failed");

        run_storage_test_result_validate(input_json_str, result_json_str).expect("Schema configuration test failed");
    }

    info!("✅ All Schema configuration tests completed");
    Ok(())
}

#[tokio::test]
#[ignore] // Use --ignored to run this test
async fn test_serve_duckdb() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting DuckDB server with test data");

    // 1. Create VolumeConfig
    let mut volume_config = create_default_volume_config();
    volume_config.rest.insert("db_path".to_string(), serde_json::Value::String("duckdb.db".to_string()));
    volume_config.rest.insert("init_sql".to_string(), serde_json::Value::String("etc/init.sql".to_string()));

    // 2. Start Volume
    let volume_instance = DuckDBBackend::start(BACKEND_NAME, &volume_config)
        .map_err(|e| format!("Failed to start Volume: {}", e))?;

    info!("🚀 DuckDB server is running. Press Ctrl+C to stop.");

    // 3. Load test data into all storages
    for test_case in get_test_cases() {
        let storage_config = create_storage_config(
            test_case.storage_name,
            test_case.volume_id,
            test_case.key_expr,
            test_case.db_schema,
            test_case.db_table,
            test_case.db_table_desc
        )?;

        let input_json_str = std::fs::read_to_string(test_case.input_file_path)
            .map_err(|e| format!("Failed to read input data file {}: {}", test_case.input_file_path, e))?;

        let _result = run_storage_test_case(&volume_instance, storage_config, &input_json_str).await
            .expect("Failed to load test data");

        info!("✅ Test data loaded for {}", test_case.case_name);
    }
    
    info!("🚀 DuckDB server is running with all test data loaded. Press Ctrl+C to stop.");
    
    // Keep the server running
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}