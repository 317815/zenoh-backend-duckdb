-- DuckDB initialization SQL script example
-- This script is executed during Volume initialization and affects all Storage

INSTALL httpfs;
LOAD httpfs;

INSTALL httpserver from community;
LOAD httpserver;
SELECT httpserve_stop();
SELECT httpserve_start('0.0.0.0', 9999, '');

INSTALL ui;
LOAD ui;
set ui_polling_interval=0;
CALL start_ui_server();
