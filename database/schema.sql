-- PhishGuard database schema (MySQL / MariaDB)

CREATE TABLE IF NOT EXISTS users (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    full_name     VARCHAR(120) NOT NULL,
    email         VARCHAR(190) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('admin','user') NOT NULL DEFAULT 'user',
    department    VARCHAR(120) NULL,
    is_active     TINYINT(1) NOT NULL DEFAULT 1,
    last_login    DATETIME NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scans (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NULL,
    url         VARCHAR(2048) NOT NULL,
    host        VARCHAR(255) NOT NULL,
    score       TINYINT UNSIGNED NOT NULL,
    verdict     ENUM('safe','suspicious','phishing') NOT NULL,
    features    LONGTEXT NULL,
    source      ENUM('web','api','extension') NOT NULL DEFAULT 'web',
    ip_address  VARCHAR(45) NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_scans_user (user_id),
    INDEX idx_scans_verdict (verdict),
    INDEX idx_scans_created (created_at),
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS blacklist (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain     VARCHAR(255) NOT NULL UNIQUE,
    reason     VARCHAR(255) NULL,
    added_by   INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_bl_user FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Trusted domains. "brand" (optional) is used for brand-impersonation and look-alike detection.
CREATE TABLE IF NOT EXISTS whitelist (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain     VARCHAR(255) NOT NULL UNIQUE,
    brand      VARCHAR(60) NULL,
    added_by   INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_wl_user FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS reports (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NULL,
    reporter    VARCHAR(190) NULL,
    url         VARCHAR(2048) NOT NULL,
    description TEXT NULL,
    status      ENUM('pending','confirmed','rejected') NOT NULL DEFAULT 'pending',
    reviewed_by INT UNSIGNED NULL,
    reviewed_at DATETIME NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reports_status (status),
    CONSTRAINT fk_rep_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_rep_rev  FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS evaluations (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    run_by       INT UNSIGNED NULL,
    dataset_name VARCHAR(190) NOT NULL,
    network      TINYINT(1) NOT NULL DEFAULT 0,
    total        INT UNSIGNED NOT NULL,
    tp INT UNSIGNED NOT NULL, fp INT UNSIGNED NOT NULL,
    tn INT UNSIGNED NOT NULL, fn INT UNSIGNED NOT NULL,
    accuracy     DECIMAL(6,4) NOT NULL,
    precision_v  DECIMAL(6,4) NOT NULL,
    recall       DECIMAL(6,4) NOT NULL,
    f1           DECIMAL(6,4) NOT NULL,
    duration_ms  INT UNSIGNED NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_eval_user FOREIGN KEY (run_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
