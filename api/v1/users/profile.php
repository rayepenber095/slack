<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/user_handler.php';
require_once __DIR__ . '/../../../includes/logger.php';

requireLogin();

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // VULN: IDOR - any user can view any profile by supplying user_id
    $userId = $_GET['user_id'] ?? $_SESSION['user_id'];
    $profile = getUserProfile($userId);

    if (!$profile) {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
        exit;
    }
    echo json_encode(['success' => true, 'profile' => $profile]);

} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input  = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    // VULN: IDOR - user_id from POST, not from session
    $userId = $input['user_id'] ?? $_SESSION['user_id'];

    // VULN: Mass assignment - 'role' field allows privilege escalation
    unset($input['user_id']);
    $result = updateUserProfile($userId, $input);

    echo json_encode(['success' => $result]);
}
