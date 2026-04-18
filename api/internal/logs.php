<?php
// VULN: No authentication required
// VULN: Exposes sensitive log contents over HTTP

header('Content-Type: text/plain');

require_once __DIR__ . '/../../config/constants.php';

$logType = $_GET['type'] ?? 'app';

// VULN: Path traversal via type parameter
$logFiles = [
    'app'       => APP_LOG,
    'errors'    => ERROR_LOG,
    'sql'       => SQL_LOG,       // VULN: Contains SQL queries with user data
    'websocket' => WEBSOCKET_LOG, // VULN: Contains auth tokens and messages
];

if (isset($logFiles[$logType])) {
    $path = $logFiles[$logType];
} else {
    // VULN: Direct path traversal - ?type=../../etc/passwd
    $path = LOG_PATH . '/' . $logType . '.log';
}

if (file_exists($path)) {
    // VULN: No truncation - may return MBs of sensitive data
    echo file_get_contents($path);
} else {
    echo "Log file not found: $path";
}
