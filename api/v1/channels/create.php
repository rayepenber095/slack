<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/channel_handler.php';

requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input       = json_decode(file_get_contents('php://input'), true);
$name        = $input['name']        ?? $_POST['name']        ?? '';
$description = $input['description'] ?? $_POST['description'] ?? '';

if (empty($name)) {
    http_response_code(400);
    echo json_encode(['error' => 'Channel name required']);
    exit;
}

$userId    = $_SESSION['user_id'];
// VULN: SQLi in createChannel() - name and description interpolated
$channelId = createChannel($name, $description, $userId);

echo json_encode([
    'success'    => true,
    'channel_id' => $channelId,
    'name'       => $name, // VULN: Reflected unsanitized - XSS
]);
