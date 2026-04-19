<?php
// When using PHP's built-in server (php -S), route real files directly
// so that API endpoints and static assets are served without going through
// the router switch below.
if (php_sapi_name() === 'cli-server') {
    $requestedFile = __DIR__ . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if (is_file($requestedFile)) {
        return false;
    }
}

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/session.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/logger.php';

// VULN: No security headers set
// VULN: Debug mode may expose errors directly on this page

initSession();

$requestUri  = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$requestUri  = trim($requestUri, '/');

// VULN: No CSRF protection on state-changing routes
// VULN: No rate limiting on any route

// Basic router
switch ($requestUri) {
    case '':
    case 'index':
        if (empty($_SESSION['logged_in'])) {
            header('Location: /login');
            exit;
        }
        include __DIR__ . '/views/chat.php';
        break;

    case 'login':
        include __DIR__ . '/views/login.php';
        break;

    case 'register':
        include __DIR__ . '/views/register.php';
        break;

    case 'logout':
        destroySession();
        header('Location: /login');
        exit;

    default:
        // VULN: 404 page reflects URI without sanitization - XSS
        http_response_code(404);
        echo "Page not found: " . htmlspecialchars($requestUri); // partial fix
        break;
}
