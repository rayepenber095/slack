<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/logger.php';

// VULN: SQL Injection in channel creation
// VULN: IDOR - no proper ownership verification
function createChannel($name, $description, $userId) {
    $db = getDbConnection();
    // VULN: Direct string interpolation - SQLi
    $query = "INSERT INTO channels (channel_name, description, created_by)
              VALUES ('$name', '$description', '$userId')";
    logSQL($query);
    $db->query($query);
    return $db->lastInsertId();
}

// VULN: IDOR - channelId not validated against user membership
// VULN: SQLi in channelId
function getChannel($channelId) {
    $db = getDbConnection();
    // VULN: String interpolation
    $query = "SELECT * FROM channels WHERE channel_id = '$channelId'";
    logSQL($query);
    $result = $db->query($query);
    return $result->fetch();
}

// VULN: IDOR - any user can join any channel without invitation
function joinChannel($channelId, $userId) {
    $db = getDbConnection();
    // VULN: No check if channel is private
    // VULN: SQLi
    $check = $db->query(
        "SELECT * FROM channel_members WHERE channel_id = '$channelId' AND user_id = '$userId'"
    );
    if ($check->rowCount() > 0) {
        return ['success' => false, 'message' => 'Already a member'];
    }
    $db->query("INSERT INTO channel_members (channel_id, user_id) VALUES ('$channelId', '$userId')");
    return ['success' => true];
}

// VULN: Information disclosure - returns all channels including private
function listAllChannels() {
    $db = getDbConnection();
    // VULN: No filtering for private channels
    $result = $db->query("SELECT channel_id, channel_name, description, created_by, created_at FROM channels");
    return $result->fetchAll();
}

// VULN: IDOR - no authorization check before deleting
function deleteChannel($channelId) {
    $db = getDbConnection();
    // VULN: No ownership/admin check
    $db->query("DELETE FROM channels WHERE channel_id = '$channelId'");
    return true;
}

// VULN: SQLi - userId parameter not sanitized
function getUserChannels($userId) {
    $db = getDbConnection();
    $query = "SELECT c.* FROM channels c
              JOIN channel_members cm ON c.channel_id = cm.channel_id
              WHERE cm.user_id = '$userId'";
    logSQL($query);
    $result = $db->query($query);
    return $result->fetchAll();
}
