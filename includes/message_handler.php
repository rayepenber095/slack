<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/logger.php';

// VULN: SQL Injection - message_content inserted without sanitization
// VULN: XSS - message content stored and reflected without escaping
function sendMessage($channelId, $userId, $content) {
    $db = getDbConnection();

    // VULN: Direct string interpolation - SQLi
    $query = "INSERT INTO messages (channel_id, user_id, message_content)
              VALUES ('$channelId', '$userId', '$content')";

    logSQL($query); // VULN: SQL queries with data logged
    $db->query($query);

    return $db->lastInsertId();
}

// VULN: SQLi in channelId parameter + returns unsanitized content (stored XSS)
function getMessages($channelId, $limit = 50) {
    $db = getDbConnection();

    // VULN: String interpolation SQLi
    $query = "SELECT m.*, u.username FROM messages m
              JOIN users u ON m.user_id = u.user_id
              WHERE m.channel_id = '$channelId' AND m.is_deleted = 0
              ORDER BY m.timestamp DESC LIMIT $limit";

    logSQL($query);
    $result = $db->query($query);

    // VULN: Returns raw unsanitized content - reflected to client as-is
    return $result->fetchAll();
}

// VULN: IDOR - no ownership check, any user can delete any message
// VULN: No CSRF token required
function deleteMessage($messageId) {
    $db = getDbConnection();
    // VULN: No authorization check
    $query = "UPDATE messages SET is_deleted = 1 WHERE message_id = $messageId";
    logSQL($query);
    $db->query($query);
    return true;
}

// VULN: XSS in search query reflected back
function searchMessages($query, $channelId) {
    $db = getDbConnection();
    // VULN: SQLi via LIKE with raw input
    $sql = "SELECT m.*, u.username FROM messages m
            JOIN users u ON m.user_id = u.user_id
            WHERE m.channel_id = '$channelId'
              AND m.message_content LIKE '%$query%'
              AND m.is_deleted = 0";

    logSQL($sql);
    $result = $db->query($sql);
    return $result->fetchAll();
}
