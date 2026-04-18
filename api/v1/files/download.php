<?php
require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/file_handler.php';
require_once __DIR__ . '/../../../includes/logger.php';

requireLogin();

// VULN: Path traversal - file parameter not validated
$fileId   = $_GET['file_id']   ?? null;
$filePath = $_GET['file_path'] ?? null; // VULN: Direct path parameter - LFI

if ($fileId) {
    $file = getFilePath($fileId);
    if (!$file) {
        http_response_code(404);
        echo json_encode(['error' => 'File not found']);
        exit;
    }
    // VULN: No ownership check - IDOR: any user can download any file
    $path = $file['file_path'];
} elseif ($filePath) {
    // VULN: Direct path traversal - ../../etc/passwd
    $path = $filePath;
} else {
    http_response_code(400);
    echo 'file_id or file_path required';
    exit;
}

// VULN: serveFile() does not validate path is within allowed directory
if (!serveFile($path)) {
    http_response_code(404);
    echo 'File not found';
}
