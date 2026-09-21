<?php
/**
 * PhishGuard – Phishing Detection System for Liberia Telecommunications Corporation (LTC)
 * Global configuration.
 */

define('APP_NAME', 'PhishGuard');
define('ORG_NAME', 'Liberia Telecommunications Corporation');
define('ORG_SHORT', 'LTC');

// Database (XAMPP defaults)
define('DB_HOST', '127.0.0.1');
define('DB_PORT', 3306);
define('DB_NAME', 'phishguard');
define('DB_USER', 'root');
define('DB_PASS', '');

// URL path of the app inside htdocs (no trailing slash)
define('BASE_URL', '/PhishGuard');

// Detection engine
define('FETCH_CONTENT', true);   // download the page HTML for content analysis
define('FETCH_TIMEOUT', 6);      // seconds
define('FETCH_MAX_BYTES', 1048576);
define('THRESHOLD_SUSPICIOUS', 25); // score >= this => suspicious
define('THRESHOLD_PHISHING', 50);   // score >= this => phishing

// Simple abuse protection: max full scans per session per minute
define('SCAN_RATE_LIMIT', 20);

date_default_timezone_set('Africa/Monrovia');
error_reporting(E_ALL);
ini_set('display_errors', '0');
