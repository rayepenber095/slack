-- Slack Clone Database Schema
-- VULN: Weak root password, world-readable grants

CREATE DATABASE IF NOT EXISTS slack_clone;
USE slack_clone;

-- VULN: No encryption at rest, passwords stored as MD5
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,  -- VULN: stored as MD5 hash
    session_token VARCHAR(255) DEFAULT NULL,
    api_token VARCHAR(255) DEFAULT NULL,
    role ENUM('admin','user','guest') NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME DEFAULT NULL,
    is_active TINYINT(1) DEFAULT 1,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS channels (
    channel_id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    channel_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT DEFAULT NULL,
    created_by VARCHAR(36) NOT NULL,
    is_private TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (channel_id),
    FOREIGN KEY (created_by) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS channel_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    channel_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (channel_id) REFERENCES channels(channel_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    channel_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    message_content TEXT NOT NULL,  -- VULN: no sanitization
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted TINYINT(1) DEFAULT 0,
    FOREIGN KEY (channel_id) REFERENCES channels(channel_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS files (
    file_id INT AUTO_INCREMENT PRIMARY KEY,
    message_id INT DEFAULT NULL,
    user_id VARCHAR(36) NOT NULL,
    file_path VARCHAR(500) NOT NULL,  -- VULN: stores raw path
    original_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) DEFAULT NULL,
    file_size INT DEFAULT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES messages(message_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
) ENGINE=InnoDB;

-- VULN: Default admin credentials admin/admin (MD5: 21232f297a57a5a743894a0e4a801fc3)
INSERT IGNORE INTO users (user_id, username, email, password_hash, role)
VALUES (
    'aaaaaaaa-0000-0000-0000-000000000001',
    'admin',
    'admin@slack.local',
    '21232f297a57a5a743894a0e4a801fc3',
    'admin'
);

-- Default general channel
INSERT IGNORE INTO channels (channel_id, channel_name, description, created_by)
VALUES (
    'bbbbbbbb-0000-0000-0000-000000000001',
    'general',
    'General discussion',
    'aaaaaaaa-0000-0000-0000-000000000001'
);
