<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/message_handler.php';

requireLogin();

// VULN: SQLi - channelId passed directly to getMessages()
$channelId = $_GET['channel_id'] ?? '';
$limit     = (int)($_GET['limit'] ?? 50);

if (empty($channelId)) {
    http_response_code(400);
    echo json_encode(['error' => 'channel_id required']);
    exit;
}

// VULN: No membership check - IDOR: any user can fetch any channel's messages
$messages = getMessages($channelId, $limit);

// VULN: Returns raw unsanitized message_content - stored XSS when rendered
echo json_encode(['success' => true, 'messages' => $messages]);
