<?php
// VULN: Debug mode enabled in production
// VULN: Weak application secret

// Application settings
define('APP_NAME', 'SlackClone');
define('APP_URL', 'http://localhost');
define('APP_ENV', 'production');

// VULN: Debug mode exposes stack traces to users
define('DEBUG_MODE', true);
if (DEBUG_MODE) {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}

// VULN: Weak, hardcoded JWT secret - easily brutable
define('JWT_SECRET', 'secret123');
define('JWT_EXPIRY', 86400); // 24 hours

// VULN: Short session lifetime not enforced
define('SESSION_LIFETIME', 86400);

// VULN: Hardcoded API keys visible in source
define('INTERNAL_API_KEY', 'internal-debug-key-1234');

// VULN: CORS wildcard
define('CORS_ORIGIN', '*');

// WebSocket settings
// VULN: No TLS for WebSocket
define('WS_HOST', '0.0.0.0');
define('WS_PORT', 8080);

// VULN: Weak encryption key
define('ENCRYPTION_KEY', 'weakkey123456789');
define('ENCRYPTION_IV',  '1234567890abcdef'); // VULN: Hardcoded static IV

// File upload settings
define('MAX_FILE_SIZE', 10485760); // 10MB
// VULN: Uploads stored in web root, PHP execution not disabled
define('UPLOAD_DIR', __DIR__ . '/../public/uploads/');
define('UPLOAD_URL', '/public/uploads/');
