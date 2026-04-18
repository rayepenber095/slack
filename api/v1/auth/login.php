<?php
header('Content-Type: application/json');
// VULN: CORS wildcard with credentials allowed
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');

require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/logger.php';

// VULN: No rate limiting - brute force / credential stuffing possible
// VULN: SQL injection via loginUser()

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$username = $input['username'] ?? $_POST['username'] ?? '';
$password = $input['password'] ?? $_POST['password'] ?? '';

if (empty($username) || empty($password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Username and password required']);
    exit;
}

// VULN: loginUser() uses raw string interpolation (SQLi)
$result = loginUser($username, $password);

if ($result['success']) {
    initSession();
    setUserSession($result['user']);

    // VULN: Token returned in response body - may be logged
    logInfo("User logged in: $username");
    echo json_encode([
        'success' => true,
        'token'   => $result['token'],
        'jwt'     => $result['jwt'],  // VULN: JWT exposed
        'user'    => [
            'user_id'  => $result['user']['user_id'],
            'username' => $result['user']['username'],
            'role'     => $result['user']['role'],
        ],
    ]);
} else {
    // VULN: Verbose error - reveals whether username exists
    http_response_code(401);
    logInfo("Failed login attempt for: $username");
    echo json_encode(['error' => $result['message']]);
}
