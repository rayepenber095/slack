<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once __DIR__ . '/../../../includes/session.php';
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/channel_handler.php';

// VULN: No authentication required to list channels
// requireLogin();  // VULN: Commented out - unauthenticated access

// VULN: Information disclosure - returns all channels including private ones
$channels = listAllChannels();

// VULN: Returns created_by user_id - may be used for further IDOR
echo json_encode([
    'success'  => true,
    'channels' => $channels,
    'count'    => count($channels),
]);
