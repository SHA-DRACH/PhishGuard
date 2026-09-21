<?php
/**
 * Scan API
 *   GET  api/scan.php?quick=1&url=...  – instant URL-only check (not stored), used for live typing feedback
 *   POST api/scan.php  url=...&deep=1  – full scan (URL + host + content), stored in history
 */
require_once __DIR__ . '/../includes/bootstrap.php';

$quick = ($_SERVER['REQUEST_METHOD'] === 'GET');
$url = trim((string)($quick ? ($_GET['url'] ?? '') : ($_POST['url'] ?? '')));

if ($url === '' || strlen($url) > 2048) {
    json_response(['ok' => false, 'error' => 'Please enter a website address to scan.'], 422);
}

try {
    if ($quick) {
        $r = (new PhishingDetector(db(), false))->analyze($url);
        json_response(['ok' => true, 'score' => $r['score'], 'verdict' => $r['verdict']]);
    }

    verify_csrf();
    if (rate_limited()) {
        json_response(['ok' => false, 'error' => 'Too many scans in a short time. Please wait a minute and try again.'], 429);
    }

    $deep = !empty($_POST['deep']);
    $result = (new PhishingDetector(db(), $deep))->analyze($url);
    $id = save_scan($result, current_user()['id'] ?? null, 'web');
    json_response(['ok' => true, 'scan_id' => $id, 'result' => $result]);
} catch (InvalidArgumentException $e) {
    json_response(['ok' => false, 'error' => $e->getMessage()], 422);
} catch (Throwable $e) {
    error_log('PhishGuard scan error: ' . $e->getMessage());
    json_response(['ok' => false, 'error' => 'The scan could not be completed. Please try again.'], 500);
}
