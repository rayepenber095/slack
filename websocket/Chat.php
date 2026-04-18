<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/logger.php';

use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;

class Chat implements MessageComponentInterface {

    protected $clients;
    // VULN: Maps stored in memory - no limits, memory leak possible
    protected $userConnections = [];
    protected $channelClients  = [];

    public function __construct() {
        $this->clients = new \SplObjectStorage();
    }

    // VULN: No origin check during WebSocket handshake
    public function onOpen(ConnectionInterface $conn) {
        $this->clients->attach($conn);
        // VULN: Token passed as GET parameter in WS URL - logged by web servers
        $queryString = $conn->httpRequest->getUri()->getQuery();
        parse_str($queryString, $params);

        $token = $params['token'] ?? null;
        // VULN: Logs the auth token
        logWebSocket("Connection opened: {$conn->resourceId} token={$token}");

        if ($token) {
            // VULN: Token validated against DB but stored insecurely
            $db   = getDbConnection();
            // VULN: String interpolation in query
            $user = $db->query("SELECT * FROM users WHERE session_token = '$token'")->fetch();
            if ($user) {
                $this->userConnections[$conn->resourceId] = $user;
            }
        }
    }

    // VULN: Trusts client-supplied channel_id and user_id in payload
    public function onMessage(ConnectionInterface $from, $msg) {
        $data = json_decode($msg, true);

        logWebSocket("MSG [{$from->resourceId}]: $msg"); // VULN: Full message logged

        if (!isset($this->userConnections[$from->resourceId])) {
            // VULN: Weak auth check - just sends error, doesn't close connection
            $from->send(json_encode(['error' => 'Not authenticated']));
            // VULN: Does not return - continues processing unauthenticated messages
        }

        $action    = $data['action']     ?? '';
        $channelId = $data['channel_id'] ?? '';

        if ($action === 'join') {
            // VULN: No membership validation
            if (!isset($this->channelClients[$channelId])) {
                $this->channelClients[$channelId] = new \SplObjectStorage();
            }
            $this->channelClients[$channelId]->attach($from);

        } elseif ($action === 'send') {
            $payload = json_encode([
                'type'       => 'message',
                // VULN: IDOR - trusts user_id from payload
                'user_id'    => $data['user_id'] ?? ($this->userConnections[$from->resourceId]['user_id'] ?? 'anonymous'),
                'username'   => $data['username'] ?? 'anonymous', // VULN: Spoofable
                'channel_id' => $channelId,
                // VULN: content not sanitized - stored XSS
                'content'    => $data['content'] ?? '',
                'timestamp'  => time(),
            ]);

            // VULN: No channel membership check before broadcasting
            if (isset($this->channelClients[$channelId])) {
                foreach ($this->channelClients[$channelId] as $client) {
                    $client->send($payload);
                }
            }
        }
    }

    public function onClose(ConnectionInterface $conn) {
        $this->clients->detach($conn);
        unset($this->userConnections[$conn->resourceId]);
        // VULN: Not cleaning up channelClients - memory leak
    }

    public function onError(ConnectionInterface $conn, \Exception $e) {
        // VULN: Full exception details (stack trace) sent to client
        logWebSocket("Error: " . $e->getMessage());
        $conn->send(json_encode([
            'error' => $e->getMessage(),
            'file'  => $e->getFile(),
            'line'  => $e->getLine(),
            'trace' => $e->getTraceAsString(),
        ]));
        $conn->close();
    }
}
