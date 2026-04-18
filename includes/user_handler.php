<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/logger.php';

// VULN: IDOR - getUserById exposes any user's data without authorization check
function getUserProfile($userId) {
    $db = getDbConnection();
    // VULN: String interpolation - SQLi
    $query = "SELECT user_id, username, email, role, created_at, last_login FROM users WHERE user_id = '$userId'";
    logSQL($query);
    $result = $db->query($query);
    return $result->fetch();
}

// VULN: IDOR - any user can update any user's profile
// VULN: Privilege escalation - role parameter not validated
function updateUserProfile($userId, $data) {
    $db = getDbConnection();

    // VULN: Mass assignment - role can be escalated to 'admin' by passing role=admin
    $allowedFields = ['username', 'email', 'role']; // VULN: 'role' should not be user-controlled
    $updates = [];
    foreach ($data as $key => $value) {
        if (in_array($key, $allowedFields)) {
            // VULN: String interpolation - SQLi
            $updates[] = "$key = '$value'";
        }
    }

    if (empty($updates)) return false;

    // VULN: No ownership check - any authenticated user can update any user_id
    $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE user_id = '$userId'";
    logSQL($sql);
    $db->query($sql);
    return true;
}

// VULN: SQLi + XSS - search term reflected unsanitized
function searchUsers($searchTerm) {
    $db = getDbConnection();
    // VULN: Direct interpolation - SQLi
    $query = "SELECT user_id, username, email, role FROM users
              WHERE username LIKE '%$searchTerm%' OR email LIKE '%$searchTerm%'";
    logSQL($query);
    $result = $db->query($query);
    return $result->fetchAll();
}

// VULN: Privilege escalation - no admin check to promote users
function promoteUser($userId, $newRole) {
    $db = getDbConnection();
    // VULN: No check that the caller is admin
    $db->query("UPDATE users SET role = '$newRole' WHERE user_id = '$userId'");
    return true;
}

// VULN: IDOR - delete any user without admin check
function deleteUser($userId) {
    $db = getDbConnection();
    // VULN: No authorization check
    $db->query("DELETE FROM users WHERE user_id = '$userId'");
    return true;
}
