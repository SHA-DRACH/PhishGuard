-- v4: admin-managed system settings
CREATE TABLE IF NOT EXISTS settings (
    name       VARCHAR(64) NOT NULL PRIMARY KEY,
    value      MEDIUMTEXT NOT NULL,
    updated_by INT UNSIGNED NULL,
    updated_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
