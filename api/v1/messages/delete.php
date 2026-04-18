<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/message_handler.php';
require_once __DIR__ . '/../../../includes/logger.php';

requireLogin();

// VULN: No CSRF token required for state-changing DELETE operation
// VULN: IDOR - no ownership check in deleteMessage()
$messageId = $_POST['message_id'] ?? $_GET['message_id'] ?? '';

if (empty($messageId)) {
    http_response_code(400);
    echo json_encode(['error' => 'message_id required']);
    exit;
}

// VULN: Any authenticated user can delete any message
$result = deleteMessage($messageId);

logInfo("Message deleted: $messageId by user {$_SESSION['user_id']}");
echo json_encode(['success' => true, 'deleted' => $messageId]);
