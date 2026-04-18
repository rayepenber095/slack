<?php
header('Content-Type: application/json');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/logger.php';

// VULN: Session not properly invalidated server-side
// VULN: Token not revoked in database
initSession();

$userId = $_SESSION['user_id'] ?? 'unknown';
logInfo("User logged out: $userId");

// VULN: Only clears local session - token still valid in DB
destroySession();

// VULN: Does not revoke API token from database
echo json_encode(['success' => true, 'message' => 'Logged out']);
