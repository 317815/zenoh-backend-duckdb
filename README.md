# zenoh-backend-duckdb

Backend and Storages for zenoh using DuckDB

## Overview

This backend provides storage capabilities for Zenoh using [DuckDB](https://duckdb.org/), an embedded analytical database. It allows storing and querying data through Zenoh's key-value interface while leveraging DuckDB's SQL capabilities.

## Features

- Store JSON data from Zenoh PUT operations
- Query stored data using SQL
- Optional JSON Schema-based table structure definition
- Embedded database (single file or in-memory)
- Integration with Zenoh storage manager

## Installation

### Manual installation

```bash
git clone https://github.com/netprism/zenoh-backend-duckdb
cd zenoh-backend-duckdb
cargo build --release
```

## Configuration

### Setup via configuration file

Create a JSON5 configuration file:

```json5
{
  plugins: {
    storage_manager: {
      volumes: {
        duckdb: {
          db_path: "./data.db"
        }
      },
      storages: {
        events: {
          key_expr: "events/**",
          volume: {
            id: "duckdb",
            db_schema: "network",
            db_table: "events"
          }
        }
      }
    }
  }
}
```

### Volume configuration

The DuckDB backend supports the following volume configuration:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_path` | String | `:memory:` | Path to DuckDB database file |
| `init_sql` | String | - | Optional SQL script to run on startup |

### Storage configuration

Each storage must specify:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `db_schema` | String | Yes | Database schema name |
| `db_table` | String | Yes | Table name |
| `db_table_desc` | String | No | JSON Schema file path |

### Running the Zenoh router

```bash
zenohd -c config.json5
```

## Usage

### Storing data

Use Zenoh's standard PUT operations:

```bash
z_pub -k "events/test" -v '{"message": "hello", "timestamp": "2023-01-01T12:00:00Z"}'
```

### Querying data

Data can be queried using the DuckDB CLI:

```sql
-- Connect to database file
duckdb data.db

-- Query stored data
SELECT * FROM network.events LIMIT 10;
```

## Building from source

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## License

This project is licensed under the GPL-2.0-only License.