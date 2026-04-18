<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/user_handler.php';

requireLogin();

// VULN: SQLi via searchTerm parameter
// VULN: XSS - search term reflected in response unsanitized
$q = $_GET['q'] ?? '';

if (empty($q)) {
    http_response_code(400);
    echo json_encode(['error' => 'Search query required']);
    exit;
}

$users = searchUsers($q);

// VULN: Returns role and email fields - information disclosure
// VULN: XSS: $q reflected without escaping
echo json_encode([
    'success' => true,
    'query'   => $q,     // VULN: Reflected unsanitized
    'users'   => $users, // VULN: Includes sensitive fields
    'count'   => count($users),
]);
