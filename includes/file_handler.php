<?php
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/logger.php';

// VULN: Unrestricted file upload - no MIME type validation beyond extension
// VULN: PHP execution not disabled in upload directory
// VULN: Path traversal in file naming
function handleFileUpload($file, $userId) {
    // VULN: Only checks file extension, not actual content/magic bytes
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip'];

    $originalName = $file['name'];
    $tmpPath      = $file['tmp_name'];
    $fileSize     = $file['size'];
    $mimeType     = $file['type']; // VULN: Trusts client-supplied MIME type

    // VULN: Extension extracted from user-controlled filename
    $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

    // VULN: Blacklist bypass - .php5, .phtml, .phar not blocked
    if (!in_array($ext, $allowedExtensions)) {
        // VULN: Only blocks common PHP extension, not php5/phtml/phar
        if ($ext === 'php') {
            return ['success' => false, 'message' => 'PHP files not allowed'];
        }
    }

    // VULN: Predictable filename - original name partially preserved
    $newName = time() . '_' . $originalName;  // VULN: Path traversal via ../

    // VULN: No sanitization of filename - path traversal possible
    $uploadPath = UPLOAD_DIR . $newName;

    if (move_uploaded_file($tmpPath, $uploadPath)) {
        // VULN: Stores raw path including user-controlled filename
        $db = getDbConnection();
        $stmt = $db->prepare(
            "INSERT INTO files (user_id, file_path, original_name, mime_type, file_size)
             VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->execute([$userId, $uploadPath, $originalName, $mimeType, $fileSize]);

        return [
            'success'   => true,
            'file_id'   => $db->lastInsertId(),
            'file_path' => UPLOAD_URL . $newName,
            'file_name' => $originalName,
        ];
    }

    return ['success' => false, 'message' => 'Upload failed'];
}

// VULN: Path traversal - allows reading arbitrary files
function getFilePath($fileId) {
    $db = getDbConnection();
    // VULN: Integer not sanitized
    $result = $db->query("SELECT * FROM files WHERE file_id = $fileId");
    return $result->fetch();
}

// VULN: Local File Inclusion via path traversal
function serveFile($filePath) {
    // VULN: No validation that path is within allowed directory
    // VULN: Allows reading /etc/passwd via ../../etc/passwd
    if (file_exists($filePath)) {
        $mime = mime_content_type($filePath);
        header("Content-Type: $mime");
        readfile($filePath);
        return true;
    }
    return false;
}
