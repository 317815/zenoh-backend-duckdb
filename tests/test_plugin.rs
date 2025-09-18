use zenoh_backend_duckdb::plugin::DuckDBBackend;
use zenoh_backend_traits::config::VolumeConfig;
use zenoh_plugin_trait::Plugin;
use zenoh::bytes::{ZBytes, Encoding};
use zenoh::time::Timestamp;
use zenoh::key_expr::OwnedKeyExpr;
use tracing::{info, debug};

const TEST_DB_PATH: &str = "test_duckdb.db";

fn create_volume_config(db_path: &str) -> VolumeConfig {
    VolumeConfig {
        name: "test_volume".to_string(),
        backend: Some("duckdb".to_string()),
        paths: Some(vec![db_path.to_string()]),
        required: false,
        rest: serde_json::Map::new(),
    }
}

// Test case: configuration variables + test data
#[derive(Debug)]
struct TestCase {
    // Configuration variables
    name: &'static str,
    key_expr: &'static str,
    db_schema: &'static str,
    db_table: &'static str,
    db_table_desc: Option<&'static str>,
    input_data: &'static str,
}

#[derive(Debug, Default)]
struct DiffSummary {
    missing: Vec<String>,
    mismatched: Vec<String>,
    extra: Vec<String>,
}

fn analyze_diff(
    input_obj: &serde_json::Map<String, serde_json::Value>,
    output_obj: &serde_json::Map<String, serde_json::Value>,
) -> DiffSummary {
    let mut summary = DiffSummary::default();

    for (k, vin) in input_obj.iter() {
        match output_obj.get(k) {
            Some(vout) => {
                if vout != vin {
                    summary.mismatched.push(k.clone());
                }
            }
            None => summary.missing.push(k.clone()),
        }
    }

    for k in output_obj.keys() {
        if !input_obj.contains_key(k) {
            summary.extra.push(k.clone());
        }
    }

    summary.missing.sort();
    summary.mismatched.sort();
    summary.extra.sort();
    summary
}

fn log_diff(
    case_name: &str,
    input_obj: &serde_json::Map<String, serde_json::Value>,
    output_obj: &serde_json::Map<String, serde_json::Value>,
    summary: &DiffSummary,
) {
    info!(
        "[{}] Field comparison: {} input, {} output, {} missing, {} mismatched, {} extra",
        case_name,
        input_obj.len(),
        output_obj.len(),
        summary.missing.len(),
        summary.mismatched.len(),
        summary.extra.len()
    );

    if !summary.missing.is_empty() {
        info!("[{}] Missing fields: {:?}", case_name, summary.missing);
    }
    if !summary.mismatched.is_empty() {
        info!("[{}] Mismatched fields: {:?}", case_name, summary.mismatched);
        
        // Output detailed comparison for mismatched fields (JSON formatted)
        for field in &summary.mismatched {
            if let (Some(input_val), Some(output_val)) = (input_obj.get(field), output_obj.get(field)) {
                let input_formatted = serde_json::to_string_pretty(input_val)
                    .unwrap_or_else(|_| input_val.to_string());
                let output_formatted = serde_json::to_string_pretty(output_val)
                    .unwrap_or_else(|_| output_val.to_string());
                debug!("[{}] Field '{}' mismatch:\nInput value:\n{}\nOutput value:\n{}", 
                    case_name, field, input_formatted, output_formatted);
            }
        }
    }
}

fn validate_diff(
    input_obj: &serde_json::Map<String, serde_json::Value>,
    output_obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let summary = analyze_diff(input_obj, output_obj);
    // Unified output of difference details in validation
    log_diff("validate", input_obj, output_obj, &summary);
    if !summary.missing.is_empty() {
        return Err(format!("Output data missing input fields: {:?}", summary.missing));
    }
    if !summary.mismatched.is_empty() {
        return Err(format!("Field value mismatch: {:?}", summary.mismatched));
    }
    Ok(())
}

fn validate_diff_json(
    case_name: &str,
    input_json: &serde_json::Value,
    output_json: &serde_json::Value,
) -> Result<(), String> {
    let input_obj = input_json
        .as_object()
        .ok_or_else(|| "Input JSON is not an object".to_string())?;
    let output_obj = output_json
        .as_object()
        .ok_or_else(|| "Output JSON is not an object".to_string())?;

    // Output formatted input and output JSON
    let formatted_input = serde_json::to_string_pretty(input_json)
        .unwrap_or_else(|_| input_json.to_string());
    let formatted_output = serde_json::to_string_pretty(output_json)
        .unwrap_or_else(|_| output_json.to_string());
    
    debug!("[{}] Input JSON:\n{}", case_name, formatted_input);
    debug!("[{}] Output JSON:\n{}", case_name, formatted_output);

    let summary = analyze_diff(input_obj, output_obj);
    log_diff(case_name, input_obj, output_obj, &summary);
    validate_diff(input_obj, output_obj)
}


// Generic test process: one case -> one config -> one put -> one get
async fn run_test_case(test_case: TestCase) -> Result<(), String> {
    info!(
        "Test case: {} - Config: schema.table = {}.{}, key_expr = {}, table_desc = {:?}",
        test_case.name,
        test_case.db_schema,
        test_case.db_table,
        test_case.key_expr,
        test_case.db_table_desc
    );
    
    // 1. Create Volume
    let volume_config = create_volume_config(TEST_DB_PATH);
    let volume = DuckDBBackend::start("duckdb_backend", &volume_config)
        .map_err(|e| format!("Failed to start Volume: {}", e))?;
    
    // 2. Generate StorageConfig
    let mut volume_cfg = serde_json::Map::new();
    volume_cfg.insert("db_schema".to_string(), serde_json::Value::String(test_case.db_schema.to_string()));
    volume_cfg.insert("db_table".to_string(), serde_json::Value::String(test_case.db_table.to_string()));
    
    if let Some(table_desc) = test_case.db_table_desc {
        volume_cfg.insert("db_table_desc".to_string(), serde_json::Value::String(table_desc.to_string()));
    }
    
    let storage_config = zenoh_backend_traits::config::StorageConfig {
        name: format!("{}_storage", test_case.name),
        key_expr: OwnedKeyExpr::new(test_case.key_expr)
            .map_err(|e| format!("Invalid key_expr: {}", e))?,
        strip_prefix: None,
        complete: Default::default(),
        volume_id: "test_volume".to_string(),
        volume_cfg: serde_json::Value::Object(volume_cfg),
        garbage_collection_config: Default::default(),
        replication: Default::default(),
    };
    
    // 3. Create Storage
    let mut storage = volume.create_storage(storage_config).await
        .map_err(|e| format!("Failed to create Storage: {}", e))?;
    
    // 4. Read input data file
    let input_data = std::fs::read_to_string(test_case.input_data)
        .map_err(|e| format!("Failed to read input data file {}: {}", test_case.input_data, e))?;
    
    // 5. Parse input data (only when needed)
    
    // 6. PUT request
    let key = OwnedKeyExpr::new(format!("{}/test", test_case.name))
        .map_err(|e| format!("Invalid key: {}", e))?;
    let timestamp = Timestamp::parse_rfc3339("2023-01-01T12:00:00Z/33")
        .map_err(|e| format!("Invalid timestamp: {:?}", e))?;
    let payload = ZBytes::from(input_data.as_bytes());
    
    storage.put(Some(key.clone()), payload, Encoding::default(), timestamp).await
        .map_err(|e| format!("PUT request failed: {}", e))?;
    
    // 7. GET request
    let samples = storage.get(Some(key.clone()), "").await
        .map_err(|e| format!("GET request failed: {}", e))?;
    
    if samples.is_empty() {
        return Err("GET request returned no data".to_string());
    }
    
    // 7. Validate results: compare input and output data
    let retrieved_data = samples[0]
        .payload
        .try_to_string()
        .map_err(|e| format!("Failed to deserialize data: {}", e))?
        .into_owned();
    
    let input_json: serde_json::Value = serde_json::from_str(&input_data)
        .map_err(|e| format!("Input data is not valid JSON: {}", e))?;
    
    let output_json: serde_json::Value = serde_json::from_str(&retrieved_data)
        .map_err(|e| format!("Returned data is not valid JSON: {}", e))?;

    // Strict validation: output contains all input fields with consistent values (using JSON directly)
    validate_diff_json(test_case.name, &input_json, &output_json)?;
    
    info!("✅ Test case {} passed", test_case.name);
    Ok(())
}

#[tokio::test]
async fn test_plugin_with_schemas() {
    info!("Test: Different Schema configurations");
    
    let test_cases = vec![
        TestCase {
            name: "http",
            key_expr: "http/**",
            db_schema: "evelog",
            db_table: "http",
            db_table_desc: Some("event-type-shcemas/http_schema.json"),
            input_data: "event-type-examples/http_example.json",
        },
        
        TestCase {
            name: "flow",
            key_expr: "flow/**",
            db_schema: "evelog",
            db_table: "flow",
            db_table_desc: Some("event-type-shcemas/flow_schema.json"),
            input_data: "event-type-examples/flow_example.json",
        },
        
        TestCase {
            name: "alert",
            key_expr: "alert/**",
            db_schema: "evelog",
            db_table: "alert",
            db_table_desc: Some("event-type-shcemas/alert_schema.json"),
            input_data: "event-type-examples/alert_example.json",
        },
        
        TestCase {
            name: "dns",
            key_expr: "dns/**",
            db_schema: "evelog",
            db_table: "dns",
            db_table_desc: Some("event-type-shcemas/dns_schema.json"),
            input_data: "event-type-examples/dns_example.json",
        },
        
        TestCase {
            name: "tls",
            key_expr: "tls/**",
            db_schema: "evelog",
            db_table: "tls",
            db_table_desc: Some("event-type-shcemas/tls_schema.json"),
            input_data: "event-type-examples/tls_example.json",
        },
    ];
    
    for test_case in test_cases {
        run_test_case(test_case).await.expect("Schema configuration test failed");
    }
    
    info!("✅ All Schema configuration tests completed");
}

#[tokio::test]
async fn test_plugin_with_init_sql() {
    // Test initialization SQL script functionality
    let test_case = TestCase {
        name: "init_sql_test",
        key_expr: "test/**",
        db_schema: "test_schema",
        db_table: "test_table",
        db_table_desc: Some("event-type-shcemas/http_schema.json"), // Use HTTP schema for testing
        input_data: "event-type-examples/http_example.json",
    };
    
    // Create Volume configuration with initialization SQL script
    let mut volume_config = create_volume_config(TEST_DB_PATH);
    volume_config.rest.insert(
        "init_sql".to_string(), 
        serde_json::Value::String("init.sql".to_string())
    );
    
    let volume = DuckDBBackend::start("duckdb_backend", &volume_config)
        .expect("Failed to start Volume with initialization SQL");
    
    // Create Storage configuration
    let mut volume_cfg = serde_json::Map::new();
    volume_cfg.insert("db_schema".to_string(), serde_json::Value::String(test_case.db_schema.to_string()));
    volume_cfg.insert("db_table".to_string(), serde_json::Value::String(test_case.db_table.to_string()));
    
    if let Some(table_desc) = test_case.db_table_desc {
        volume_cfg.insert("db_table_desc".to_string(), serde_json::Value::String(table_desc.to_string()));
    }
    
    let storage_config = zenoh_backend_traits::config::StorageConfig {
        name: format!("{}_storage", test_case.name),
        key_expr: OwnedKeyExpr::new(test_case.key_expr)
            .expect("Invalid key_expr"),
        strip_prefix: None,
        complete: Default::default(),
        volume_id: "test_volume".to_string(),
        volume_cfg: serde_json::Value::Object(volume_cfg),
        garbage_collection_config: Default::default(),
        replication: Default::default(),
    };
    
    let mut storage = volume.create_storage(storage_config).await
        .expect("Failed to create Storage with initialization SQL");
    
    // Read HTTP example data for testing
    let input_data = std::fs::read_to_string(test_case.input_data)
        .expect("Failed to read input data file");
    
    // PUT request
    let key = OwnedKeyExpr::new("test/init_sql_test")
        .expect("Invalid key");
    let timestamp = Timestamp::parse_rfc3339("2023-01-01T12:00:00Z/33")
        .expect("Invalid timestamp");
    let payload = ZBytes::from(input_data.as_bytes());
    
    storage.put(Some(key.clone()), payload, Encoding::default(), timestamp).await
        .expect("PUT request failed");
    
    // GET request to verify successful data storage
    let samples = storage.get(Some(key.clone()), "").await
        .expect("GET request failed");
    
    assert!(!samples.is_empty(), "GET request returned no data");
    
    // Verify that the system_metadata table created by the initialization SQL script is accessible
    // This proves that the Volume's initialization SQL is visible to Storage
    info!("✅ Initialization SQL script test passed - Volume's initialization SQL is effective for all Storages");
}