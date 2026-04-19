<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/file_handler.php';
require_once __DIR__ . '/../../../includes/message_handler.php';
require_once __DIR__ . '/../../../includes/logger.php';

requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

if (empty($_FILES['file'])) {
    http_response_code(400);
    echo json_encode(['error' => 'No file provided']);
    exit;
}

$userId    = $_SESSION['user_id'];
$file      = $_FILES['file'];
$channelId = $_POST['channel_id'] ?? '';

// VULN: No CSRF token check
// VULN: handleFileUpload() trusts extension, not magic bytes
// VULN: Uploads go to web-accessible directory with PHP execution enabled
// VULN: Filename from user-controlled input - path traversal
$result = handleFileUpload($file, $userId);

if ($result['success']) {
    logInfo("File uploaded: {$result['file_name']} by $userId");

    // If a channel was specified, send a message in that channel referencing the file
    if (!empty($channelId)) {
        $content   = "[file:" . $result['file_id'] . ":" . $result['file_path'] . ":" . $result['file_name'] . "]";
        $messageId = sendMessage($channelId, $userId, $content);
        $result['message_id'] = $messageId;
    }

    echo json_encode($result);
} else {
    http_response_code(400);
    echo json_encode($result);
}
