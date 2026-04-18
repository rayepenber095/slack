<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/channel_handler.php';

requireLogin();

$input     = json_decode(file_get_contents('php://input'), true);
$channelId = $input['channel_id'] ?? $_POST['channel_id'] ?? $_GET['channel_id'] ?? '';

if (empty($channelId)) {
    http_response_code(400);
    echo json_encode(['error' => 'channel_id required']);
    exit;
}

// VULN: IDOR - joinChannel() does not check if channel is private
// VULN: SQLi via channelId string interpolation
$userId = $_SESSION['user_id'];
$result = joinChannel($channelId, $userId);

echo json_encode($result);
