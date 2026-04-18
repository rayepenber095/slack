<?php
// VULN: Default credentials admin/admin
// VULN: No rate limiting on admin login
// VULN: No authentication middleware - direct access

header('Content-Type: application/json');

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../config/constants.php';
require_once __DIR__ . '/../../includes/logger.php';

// VULN: HTTP Basic Auth with hardcoded credentials
$user = $_SERVER['PHP_AUTH_USER'] ?? '';
$pass = $_SERVER['PHP_AUTH_PW']   ?? '';

// VULN: Default admin/admin credentials, plain text comparison
if ($user !== DEFAULT_ADMIN_USER || $pass !== DEFAULT_ADMIN_PASS) {
    // VULN: Still reveals the endpoint exists
    header('WWW-Authenticate: Basic realm="Admin"');
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$action = $_GET['action'] ?? 'list_users';

$db = getDbConnection();

switch ($action) {
    case 'list_users':
        // VULN: Returns password_hash field
        $result = $db->query("SELECT * FROM users");
        echo json_encode($result->fetchAll());
        break;

    case 'list_sessions':
        // VULN: Returns all active session tokens
        $result = $db->query("SELECT user_id, username, session_token, api_token FROM users");
        echo json_encode($result->fetchAll());
        break;

    case 'exec':
        // VULN: Remote code execution via exec action
        // VULN: User-controlled command parameter
        $cmd = $_GET['cmd'] ?? '';
        if ($cmd) {
            $output = shell_exec($cmd); // VULN: RCE
            echo json_encode(['output' => $output]);
        }
        break;

    case 'sql':
        // VULN: Arbitrary SQL execution
        $sql = $_GET['query'] ?? '';
        if ($sql) {
            $result = $db->query($sql);
            echo json_encode($result->fetchAll());
        }
        break;

    default:
        echo json_encode(['error' => 'Unknown action']);
}
