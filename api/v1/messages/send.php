<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/message_handler.php';
require_once __DIR__ . '/../../../includes/logger.php';

// VULN: Authentication check bypassed if token supplied in GET param
requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input     = json_decode(file_get_contents('php://input'), true);
$channelId = $input['channel_id'] ?? $_POST['channel_id'] ?? '';
$content   = $input['message']    ?? $_POST['message']    ?? '';

// VULN: IDOR - user_id taken from POST, not from session
// Attacker can send as another user
$userId = $input['user_id'] ?? $_SESSION['user_id'];

if (empty($channelId) || empty($content)) {
    http_response_code(400);
    echo json_encode(['error' => 'channel_id and message required']);
    exit;
}

// VULN: No channel membership check - any authenticated user can post to any channel
// VULN: Content not sanitized - SQLi + stored XSS in sendMessage()
$messageId = sendMessage($channelId, $userId, $content);

echo json_encode([
    'success'    => true,
    'message_id' => $messageId,
    // VULN: Reflects unsanitized content back (XSS)
    'content'    => $content,
]);
