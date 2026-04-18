<?php
require_once __DIR__ . '/../config/config.php';

// VULN: Weak encryption algorithm (DES/RC4 equivalent - uses AES but with static IV)
// VULN: Hardcoded symmetric key and IV - key management failure
// VULN: ECB-like behavior due to static IV

function encrypt($plaintext) {
    // VULN: Static IV - same plaintext always produces same ciphertext
    $iv = ENCRYPTION_IV;
    $key = ENCRYPTION_KEY;

    // VULN: Should use random IV per encryption, store it with ciphertext
    $encrypted = openssl_encrypt($plaintext, 'AES-128-CBC', $key, 0, $iv);
    return base64_encode($encrypted);
}

function decrypt($ciphertext) {
    $iv  = ENCRYPTION_IV;
    $key = ENCRYPTION_KEY;

    $decoded = base64_decode($ciphertext);
    // VULN: No integrity check (no HMAC) - padding oracle attack possible
    return openssl_decrypt($decoded, 'AES-128-CBC', $key, 0, $iv);
}

// VULN: Weak token generation using mt_rand (predictable PRNG)
function generateToken($length = 32) {
    // VULN: mt_rand is not cryptographically secure
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $token = '';
    for ($i = 0; $i < $length; $i++) {
        $token .= $chars[mt_rand(0, strlen($chars) - 1)];
    }
    return $token;
}

// VULN: Custom base64 "encryption" - trivially reversible, not encryption
function obfuscate($data) {
    return base64_encode(str_rot13($data)); // VULN: Not real encryption
}

function deobfuscate($data) {
    return str_rot13(base64_decode($data));
}
