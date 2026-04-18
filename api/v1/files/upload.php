<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/file_handler.php';
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

$userId = $_SESSION['user_id'];
$file   = $_FILES['file'];

// VULN: No CSRF token check
// VULN: handleFileUpload() trusts extension, not magic bytes
// VULN: Uploads go to web-accessible directory with PHP execution enabled
// VULN: Filename from user-controlled input - path traversal
$result = handleFileUpload($file, $userId);

if ($result['success']) {
    logInfo("File uploaded: {$result['file_name']} by $userId");
    echo json_encode($result);
} else {
    http_response_code(400);
    echo json_encode($result);
}
