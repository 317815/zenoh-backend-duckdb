-- DuckDB initialization SQL script example
-- This script is executed during Volume initialization and affects all Storage

-- Install and load basic extensions
INSTALL httpfs;
LOAD httpfs;

-- Install httpserver
INSTALL httpserver from community;
LOAD httpserver;

--- Configure httpserver settings

-- Start httpserver
SELECT httpserve_start('0.0.0.0', 9999, '');

INSTALL ui;
LOAD ui;

-- Configure UI settings
SET ui_polling_interval=0;

-- Start UI server (this will be available at http://localhost:9999)
CALL start_ui_server();
