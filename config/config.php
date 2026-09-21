<?php
/**
 * PhishGuard – Phishing Detection System for Liberia Telecommunications Corporation (LTC)
 * Server configuration. Everything else (names, texts, detection rules, access rules)
 * is managed by administrators under Admin → System settings.
 */

// Database (XAMPP defaults)
define('DB_HOST', '127.0.0.1');
define('DB_PORT', 3306);
define('DB_NAME', 'phishguard');
define('DB_USER', 'root');
define('DB_PASS', '');

// URL path of the app inside htdocs (no trailing slash)
define('BASE_URL', '/PhishGuard');

// Hard limit on downloaded page size during content analysis
define('FETCH_MAX_BYTES', 1048576);

date_default_timezone_set('Africa/Monrovia');
error_reporting(E_ALL);
ini_set('display_errors', '0');
