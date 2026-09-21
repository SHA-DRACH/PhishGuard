-- v2: staff positions, responsibilities and report assignments
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS position VARCHAR(120) NULL AFTER department,
    ADD COLUMN IF NOT EXISTS responsibilities TEXT NULL AFTER position,
    ADD COLUMN IF NOT EXISTS must_change_password TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active,
    ADD COLUMN IF NOT EXISTS created_by INT UNSIGNED NULL AFTER must_change_password;

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS assigned_to INT UNSIGNED NULL AFTER status,
    ADD COLUMN IF NOT EXISTS assigned_at DATETIME NULL AFTER assigned_to,
    ADD COLUMN IF NOT EXISTS analyst_verdict ENUM('phishing','legitimate') NULL AFTER assigned_at,
    ADD COLUMN IF NOT EXISTS analyst_note TEXT NULL AFTER analyst_verdict,
    ADD COLUMN IF NOT EXISTS analyst_at DATETIME NULL AFTER analyst_note,
    ADD INDEX IF NOT EXISTS idx_reports_assigned (assigned_to);
