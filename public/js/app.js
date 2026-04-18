// VULN: DOM XSS - user-controlled data inserted via innerHTML
// VULN: Auth tokens stored in localStorage - accessible to XSS
// VULN: Exposed API tokens hardcoded in JS

// VULN: Sensitive tokens stored in localStorage (accessible to XSS)
const API_TOKEN    = localStorage.getItem('api_token');
const USER_ID      = localStorage.getItem('user_id');
const USERNAME     = localStorage.getItem('username');

// VULN: Hardcoded internal API key exposed to all users
const INTERNAL_KEY = 'internal-debug-key-1234';
const API_BASE_URL = '/api/v1';

let currentChannelId = null;

// DOM references
const messagesList    = document.getElementById('messages-list');
const messageInput    = document.getElementById('message-input');
const channelList     = document.getElementById('channel-list');
const chatHeader      = document.getElementById('chat-header');

// VULN: XSS - channel name injected directly into DOM via innerHTML
function setActiveChannel(channelId, channelName) {
    currentChannelId = channelId;
    // VULN: channelName comes from server but may contain user-supplied data
    chatHeader.innerHTML = `# ${channelName}`;  // VULN: DOM XSS if channelName contains <script>
    loadMessages(channelId);

    document.querySelectorAll('.channel-item').forEach(el => {
        el.classList.remove('active');
    });
    const el = document.querySelector(`[data-channel-id="${channelId}"]`);
    if (el) el.classList.add('active');
}

// VULN: Stored XSS - message content rendered via innerHTML without sanitization
function renderMessage(msg) {
    const div = document.createElement('div');
    div.className = 'message';
    // VULN: msg.message_content and msg.username rendered directly via innerHTML
    div.innerHTML = `
        <div class="message-avatar">${msg.username ? msg.username[0].toUpperCase() : '?'}</div>
        <div class="message-content">
            <span class="username">${msg.username}</span>
            <span class="timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</span>
            <div class="text">${msg.message_content}</div>
        </div>
    `;
    messagesList.appendChild(div);
}

async function loadMessages(channelId) {
    messagesList.innerHTML = '';
    try {
        const resp = await fetch(`${API_BASE_URL}/messages/fetch.php?channel_id=${channelId}`, {
            headers: { 'Authorization': `Bearer ${API_TOKEN}` }
        });
        const data = await resp.json();
        if (data.messages) {
            data.messages.reverse().forEach(renderMessage);
        }
        messagesList.scrollTop = messagesList.scrollHeight;
    } catch (e) {
        console.error('Failed to load messages', e);
    }
}

async function sendMessage() {
    const content = messageInput.value.trim();
    if (!content || !currentChannelId) return;

    try {
        await fetch(`${API_BASE_URL}/messages/send.php`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${API_TOKEN}`,
            },
            // VULN: user_id sent from client - IDOR on server
            body: JSON.stringify({
                channel_id: currentChannelId,
                message: content,
                user_id: USER_ID,
            }),
        });
        messageInput.value = '';
    } catch (e) {
        console.error('Failed to send message', e);
    }
}

async function loadChannels() {
    try {
        const resp = await fetch(`${API_BASE_URL}/channels/list.php`);
        const data = await resp.json();
        channelList.innerHTML = '';
        if (data.channels) {
            data.channels.forEach(ch => {
                const el = document.createElement('div');
                el.className = 'channel-item';
                el.dataset.channelId = ch.channel_id;
                // VULN: channel_name from server injected via innerHTML - XSS
                el.innerHTML = ch.channel_name;
                el.addEventListener('click', () => setActiveChannel(ch.channel_id, ch.channel_name));
                channelList.appendChild(el);
            });
        }
    } catch (e) {
        console.error('Failed to load channels', e);
    }
}

// VULN: XSS via URL parameter - reflected into DOM
function getQueryParam(name) {
    const url = new URLSearchParams(window.location.search);
    return url.get(name);
}

const highlightChannel = getQueryParam('channel');
if (highlightChannel) {
    // VULN: DOM XSS - channel param from URL inserted via innerHTML
    chatHeader.innerHTML = `Searching: ${highlightChannel}`;
}

// VULN: User info stored in DOM as data attributes - accessible to injected scripts
document.body.dataset.userId   = USER_ID;
document.body.dataset.apiToken = API_TOKEN;  // VULN: Token in DOM

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    if (!API_TOKEN) {
        window.location.href = '/login';
        return;
    }
    loadChannels();
});

// Send on Enter
messageInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});
