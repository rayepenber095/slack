<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/message_handler.php';

requireLogin();

$query     = $_GET['q']          ?? '';
$channelId = $_GET['channel_id'] ?? '';

if (empty($query) || empty($channelId)) {
    http_response_code(400);
    echo json_encode(['error' => 'q and channel_id are required']);
    exit;
}

$messages = searchMessages($query, $channelId);

echo json_encode(['success' => true, 'messages' => $messages]);
