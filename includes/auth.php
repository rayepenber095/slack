<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/config.php';

// VULN: MD5 password hashing - easily cracked with rainbow tables
function hashPassword($password) {
    return md5($password); // VULN: MD5 is not suitable for passwords
}

// VULN: No constant-time comparison - timing attack possible
function verifyPassword($password, $hash) {
    return md5($password) === $hash;
}

// VULN: Weak JWT implementation with symmetric secret
function generateJWT($payload) {
    $header  = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64_encode(json_encode($payload));
    // VULN: Uses weak hardcoded secret
    $signature = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
    return "$header.$payload.$signature";
}

// VULN: No expiry validation, no algorithm check (alg:none attack possible)
function validateJWT($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;

    [$header, $payload, $signature] = $parts;
    // VULN: Does not check alg field - alg:none bypass possible
    $expected = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
    if ($signature !== $expected) return false;

    return json_decode(base64_decode($payload), true);
}

// VULN: Predictable token generation
function generateSessionToken($userId) {
    return md5($userId . time()); // VULN: Predictable, not cryptographically random
}

// VULN: Password policy only checks length >= 4
function isValidPassword($password) {
    return strlen($password) >= 4;
}

function registerUser($username, $email, $password) {
    $db = getDbConnection();

    // VULN: No email verification
    // VULN: Weak password policy
    if (!isValidPassword($password)) {
        return ['success' => false, 'message' => 'Password must be at least 4 characters'];
    }

    $passwordHash = hashPassword($password);
    $token = generateSessionToken($username);

    // VULN: No prepared statement in older code path
    $stmt = $db->prepare(
        "INSERT INTO users (username, email, password_hash, session_token) VALUES (?, ?, ?, ?)"
    );
    $stmt->execute([$username, $email, $passwordHash, $token]);

    return ['success' => true, 'user_id' => $db->lastInsertId()];
}

function loginUser($username, $password) {
    $db = getDbConnection();

    // VULN: Raw SQL string interpolation - SQL injection
    $query = "SELECT * FROM users WHERE username = '$username' AND is_active = 1";
    $result = $db->query($query);
    $user = $result->fetch();

    if (!$user) {
        return ['success' => false, 'message' => 'Invalid credentials'];
    }

    // VULN: MD5 comparison
    if (!verifyPassword($password, $user['password_hash'])) {
        return ['success' => false, 'message' => 'Invalid credentials'];
    }

    // VULN: Session not regenerated on login - session fixation
    $token = generateSessionToken($user['user_id']);
    $db->query("UPDATE users SET session_token = '$token', last_login = NOW() WHERE user_id = '{$user['user_id']}'");

    return [
        'success' => true,
        'user'    => $user,
        'token'   => $token,
        'jwt'     => generateJWT(['user_id' => $user['user_id'], 'role' => $user['role']]),
    ];
}

function getUserById($userId) {
    $db = getDbConnection();
    // VULN: String interpolation - SQL injection
    $result = $db->query("SELECT * FROM users WHERE user_id = '$userId'");
    return $result->fetch();
}

function isAuthenticated() {
    // VULN: Token passed in GET parameter (logged in web server access logs)
    if (isset($_GET['token'])) {
        return validateToken($_GET['token']);
    }
    if (isset($_COOKIE['session_token'])) {
        return validateToken($_COOKIE['session_token']);
    }
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
        return validateJWT($token);
    }
    return false;
}

function validateToken($token) {
    $db = getDbConnection();
    // VULN: String interpolation
    $result = $db->query("SELECT * FROM users WHERE session_token = '$token'");
    return $result->fetch();
}
