# Slack Clone - PHP Security Penetration Testing Testbed

A deliberately vulnerable Slack-like messaging application built with PHP, MySQL, and WebSockets (Ratchet).

> ⚠️ **Warning:** This project intentionally contains security vulnerabilities for legal lab testing and security education only.

## Project Structure

```
project-root/
├── api/                    # REST and internal endpoints
├── config/                 # DB/app constants and runtime settings
├── includes/               # Core handlers (auth, channels, messages, users, files)
├── public/                 # JS/CSS + uploaded files
├── sql/                    # Schema + seed data
├── views/                  # login/register/chat UI
├── websocket/              # Ratchet server and connection handling
├── vulnerabilities/        # Vulnerability-file map + testing guides
├── function.md             # Application functionality map
└── docker/                 # Docker compose and image setup
```

## Quick Start (Docker)

```bash
cd docker
docker-compose up --build
```

### Access
- Web UI: `http://localhost`
- WebSocket endpoint: `ws://localhost:8080`
- Admin endpoint: `http://localhost:8081/api/internal/admin.php`
- MySQL: `localhost:3306`

### Default credentials
- Admin UI/API basic auth: `admin / admin`
- MySQL root: `root / root`
- App DB user: `slackuser / slackpass`

## Quick Start (Local PHP)

From repository root:

```bash
composer install
mysql -u root -p < sql/schema.sql
php websocket/server.php
php -S localhost:8000 index.php
```

Open `http://localhost:8000`.

## Data Seeding

`sql/schema.sql` now includes:
- default admin and general channel
- additional users/channels/channel memberships
- more than 100 seeded message records across multiple channels
- sample file metadata records

This gives enough sample data for chat browsing, searching, and security testing.

## Documentation Added

- **Functionality map:** `function.md`
- **Vulnerability file guides:**
  - `vulnerabilities/01-broken-access-control.md`
  - `vulnerabilities/02-injection.md`
  - `vulnerabilities/03-crypto-auth-session.md`
  - `vulnerabilities/04-misconfiguration-and-files.md`

## Validation / Checks

Run PHP syntax checks from repo root:

```bash
find . -name '*.php' -not -path './vendor/*' -print0 | xargs -0 -n1 php -l
```

## Legal Notice

Use only in authorized environments where you have explicit permission to test.
