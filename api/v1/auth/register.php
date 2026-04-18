<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/logger.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input    = json_decode(file_get_contents('php://input'), true);
$username = $input['username'] ?? $_POST['username'] ?? '';
$email    = $input['email']    ?? $_POST['email']    ?? '';
$password = $input['password'] ?? $_POST['password'] ?? '';

if (empty($username) || empty($email) || empty($password)) {
    http_response_code(400);
    echo json_encode(['error' => 'All fields required']);
    exit;
}

// VULN: Weak password policy (min 4 chars)
// VULN: No email validation
// VULN: No CAPTCHA - bot registration possible
if (strlen($password) < 4) {
    echo json_encode(['error' => 'Password must be at least 4 characters']);
    exit;
}

$result = registerUser($username, $email, $password);

if ($result['success']) {
    logInfo("New user registered: $username ($email)");
    echo json_encode([
        'success' => true,
        'message' => 'Registration successful',
        'user_id' => $result['user_id'],
    ]);
} else {
    http_response_code(400);
    echo json_encode(['error' => $result['message']]);
}
