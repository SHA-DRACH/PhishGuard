<?php
require_once __DIR__ . '/../config/config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']),
    ]);
    session_name('PHISHGUARD');
    session_start();
}

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/settings.php';

// Admin-managed settings exposed as constants used throughout the application
define('APP_NAME', setting('app_name'));
define('ORG_NAME', setting('org_name'));
define('ORG_SHORT', setting('org_short'));
define('THRESHOLD_SUSPICIOUS', setting('threshold_suspicious'));
define('THRESHOLD_PHISHING', setting('threshold_phishing'));
define('FETCH_CONTENT', setting('fetch_content'));
define('FETCH_TIMEOUT', setting('fetch_timeout'));
define('SCAN_RATE_LIMIT', setting('scan_rate_limit'));
define('SAFE_BROWSING_API_KEY', (string)setting('safe_browsing_key'));

if (setting('timezone') !== date_default_timezone_get() && in_array(setting('timezone'), DateTimeZone::listIdentifiers(), true)) {
    date_default_timezone_set(setting('timezone'));
    db()->exec("SET time_zone = '" . date('P') . "'");
}

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Detector.php';

enforce_maintenance();
