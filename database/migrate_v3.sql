-- v3: cache for domain registration (RDAP) lookups
CREATE TABLE IF NOT EXISTS domain_cache (
    domain     VARCHAR(255) NOT NULL PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
