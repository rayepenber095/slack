<?php
require_once __DIR__ . '/../config/config.php';

// VULN: Session fixation - session ID not regenerated after login
// VULN: Weak session configuration
function initSession() {
    // VULN: Missing Secure flag (cookies sent over HTTP)
    // VULN: Missing SameSite attribute
    session_set_cookie_params([
        'lifetime' => SESSION_LIFETIME,
        'path'     => '/',
        'domain'   => '',
        'secure'   => false,   // VULN: Should be true in production
        'httponly' => false,   // VULN: JS can read session cookie - XSS escalation
        'samesite' => 'None',  // VULN: Weak SameSite - CSRF risk
    ]);

    // VULN: Weak session ID entropy
    ini_set('session.entropy_length', 16);     // VULN: Too short
    ini_set('session.hash_function', 'md5');   // VULN: MD5 for session IDs

    if (session_status() === PHP_SESSION_NONE) {
        // VULN: session_start() accepts session ID from GET/POST - session fixation
        if (isset($_GET['PHPSESSID'])) {
            session_id($_GET['PHPSESSID']);
        }
        session_start();
    }
}

// VULN: Does not call session_regenerate_id() after login
function setUserSession($user) {
    // VULN: No session regeneration - session fixation
    $_SESSION['user_id']    = $user['user_id'];
    $_SESSION['username']   = $user['username'];
    $_SESSION['role']       = $user['role'];
    $_SESSION['token']      = $user['session_token'];
    $_SESSION['logged_in']  = true;

    // VULN: Token also set in cookie without HttpOnly/Secure
    setcookie('session_token', $user['session_token'], [
        'expires'  => time() + SESSION_LIFETIME,
        'path'     => '/',
        'secure'   => false,  // VULN
        'httponly' => false,  // VULN
        'samesite' => 'None', // VULN
    ]);
}

// VULN: Session data not fully cleared, session ID not regenerated
function destroySession() {
    // VULN: Does not call session_regenerate_id(true) before destroy
    // VULN: Does not unset all session variables properly
    $_SESSION = [];
    // VULN: Cookie not properly invalidated (expiry in the past not set)
    setcookie('session_token', '', time() - 1);
    session_destroy();
}

function requireLogin() {
    initSession();
    if (empty($_SESSION['logged_in'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
}

function getCurrentUserId() {
    return $_SESSION['user_id'] ?? null;
}

function getCurrentUserRole() {
    return $_SESSION['role'] ?? 'guest';
}
