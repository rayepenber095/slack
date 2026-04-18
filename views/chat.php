<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- VULN: No Content-Security-Policy -->
    <!-- VULN: No X-Frame-Options - clickjacking possible -->
    <!-- VULN: No X-Content-Type-Options -->
    <title>SlackClone</title>
    <link rel="stylesheet" href="/public/css/style.css">
</head>
<body>
<div class="sidebar">
    <div class="sidebar-header">
        <span class="workspace-name">SlackClone</span>
        <!-- VULN: Username reflected directly - XSS if username contains HTML -->
        <span><?php echo $_SESSION['username']; ?></span>
    </div>
    <div id="channel-list" class="channel-list"></div>
    <div style="padding:12px 20px;border-top:1px solid #333;">
        <button onclick="window.location='/logout'" style="background:transparent;border:none;color:#717274;cursor:pointer;">Sign out</button>
    </div>
</div>

<div class="main">
    <div id="chat-header" class="chat-header">Select a channel</div>
    <div id="messages-list" class="messages-container"></div>
    <div class="input-area">
        <div class="message-input-wrapper">
            <textarea
                id="message-input"
                class="message-input"
                placeholder="Message..."
                rows="1"
            ></textarea>
            <!-- VULN: File upload with no server-side restrictions visible here -->
            <input type="file" id="file-upload-input" style="display:none">
            <button id="upload-btn" class="upload-btn" title="Attach file">📎</button>
            <button class="send-btn" onclick="sendMessage()">Send</button>
        </div>
    </div>
</div>

<script>
// VULN: Session data injected into JS without proper escaping
var CURRENT_USER = {
    // VULN: PHP session data directly interpolated into JS - XSS if username contains JS
    user_id:  '<?php echo $_SESSION['user_id']; ?>',
    username: '<?php echo $_SESSION['username']; ?>',
    role:     '<?php echo $_SESSION['role']; ?>',
    token:    '<?php echo $_SESSION['token']; ?>'  // VULN: Token in JS
};
// VULN: Also store in localStorage for API calls
localStorage.setItem('api_token', CURRENT_USER.token);
localStorage.setItem('user_id',   CURRENT_USER.user_id);
localStorage.setItem('username',  CURRENT_USER.username);
</script>
<script src="/public/js/app.js"></script>
<script src="/public/js/websocket.js"></script>
<script src="/public/js/upload.js"></script>
</body>
</html>
