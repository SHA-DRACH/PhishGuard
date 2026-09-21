<?php
/**
 * PhishGuard test suite (CLI):  php tests/run_tests.php
 * Unit tests for the detection engine plus integration checks of the database layer.
 */
require __DIR__ . '/../includes/bootstrap.php';

$results = [];
function check(string $id, string $area, string $description, bool $pass, string $detail = ''): void
{
    global $results;
    $results[] = compact('id', 'area', 'description', 'pass', 'detail');
    printf("%-6s %-4s %s%s\n", $id, $pass ? 'PASS' : 'FAIL', $description, $detail ? "  [$detail]" : '');
}

$d = new PhishingDetector(db(), false);
$feature = fn(array $r, string $id) => current(array_filter($r['features'], fn($f) => $f['id'] === $id)) ?: null;

// ---------- Unit tests: individual features ----------
$cases = [
    ['UT01', 'IP address host is flagged',              'http://192.168.4.20/login',                'ip_host',     true],
    ['UT02', '"@" symbol trick is flagged',             'http://www.paypal.com@198.51.100.23/',     'at_symbol',   true],
    ['UT03', 'Missing HTTPS is flagged',                'http://example.org',                       'https',       true],
    ['UT04', 'HTTPS site passes HTTPS check',           'https://example.org',                      'https',       false],
    ['UT05', 'Suspicious TLD (.tk) is flagged',         'http://free-gift.tk',                      'tld',         true],
    ['UT06', 'URL shortener is flagged',                'https://bit.ly/3xYz',                      'shortener',   true],
    ['UT07', 'Sensitive keywords are detected',         'https://example.org/login/verify-account', 'keywords',    true],
    ['UT08', 'Brand impersonation is detected',         'https://paypal-support-center.com',        'brand',       true],
    ['UT09', 'Look-alike domain (g00gle) is detected',  'https://g00gle.com',                       'typosquat',   true],
    ['UT10', 'Look-alike domain (paypa1) is detected',  'https://paypa1.com',                       'typosquat',   true],
    ['UT11', 'Punycode domain is flagged',              'https://xn--pypal-4ve.com',                'punycode',    true],
    ['UT12', 'Deep sub-domain nesting is flagged',      'http://a.b.c.example.com',                 'subdomains',  true],
    ['UT13', 'Non-standard port is flagged',            'http://203.0.113.5:8080/',                 'port',        true],
    ['UT14', 'Double-slash redirect is flagged',        'http://example.org//http://evil.test',     'double_slash', true],
];
foreach ($cases as [$id, $desc, $url, $fid, $expectRisk]) {
    $r = $d->analyze($url);
    $f = $feature($r, $fid);
    $risky = $f && $f['risk'] > 0;
    check($id, 'Unit', $desc, $risky === $expectRisk, $f ? "+{$f['risk']}" : 'feature absent');
}

// ---------- Unit tests: verdicts ----------
$verdicts = [
    ['UT15', 'Trusted domain is classified safe',          'https://www.libtelco.com.lr',                  'safe'],
    ['UT16', 'Legitimate sub-domain of trusted site is safe', 'https://accounts.google.com/signin',        'safe'],
    ['UT17', 'Fake LTC billing page is phishing',          'http://libtelco.com.lr.account-suspend.xyz/pay', 'phishing'],
    ['UT18', 'Blacklisted domain is always phishing',      'https://ltc-account-verify.tk/anything',        'phishing'],
    ['UT19', 'Plain unknown site is safe',                 'https://example.org',                          'safe'],
];
foreach ($verdicts as [$id, $desc, $url, $expected]) {
    $r = $d->analyze($url);
    check($id, 'Unit', $desc, $r['verdict'] === $expected, "{$r['verdict']} / {$r['score']}");
}

// ---------- Input validation ----------
try { $d->analyze('   '); $ok = false; } catch (InvalidArgumentException) { $ok = true; }
check('UT20', 'Unit', 'Empty input is rejected with a validation error', $ok);
$r = $d->analyze('libtelco.com.lr');
check('UT21', 'Unit', 'Address without scheme is normalised', str_starts_with($r['url'], 'http://'), $r['url']);
check('UT22', 'Unit', 'Score is capped between 0 and 100',
    $d->analyze('http://login.verify.secure.account.paypa1-update.tk@192.0.2.1:8080//x')['score'] <= 100);

// ---------- Integration: database ----------
$r = $d->analyze('http://integration-test.example/login');
$id = save_scan($r, null, 'web');
$row = db()->query('SELECT * FROM scans WHERE id = ' . (int)$id)->fetch();
check('IT01', 'Integration', 'Scan result is stored in the database', $row && $row['verdict'] === $r['verdict']);
db()->exec('DELETE FROM scans WHERE id = ' . (int)$id);

db()->prepare('INSERT IGNORE INTO blacklist (domain, reason) VALUES (?, ?)')->execute(['it-blacklist.example', 'test']);
check('IT02', 'Integration', 'Newly blacklisted domain is detected immediately',
    $d->analyze('https://it-blacklist.example')['verdict'] === 'phishing');
db()->exec("DELETE FROM blacklist WHERE domain = 'it-blacklist.example'");

$hash = password_hash('Sample123', PASSWORD_DEFAULT);
check('IT03', 'Integration', 'Passwords are stored as one-way hashes', password_verify('Sample123', $hash) && !str_contains($hash, 'Sample123'));
check('IT04', 'Integration', 'Staff responsibilities fall back to position presets',
    count(user_responsibilities(['position' => 'Cybersecurity Analyst', 'responsibilities' => ''])) === 4);

// ---------- Performance ----------
$t = microtime(true);
for ($i = 0; $i < 100; $i++) $d->analyze("https://perf-$i.example.com/login");
$avg = (microtime(true) - $t) * 10;
check('PT01', 'Performance', 'URL-only analysis completes in under 100 ms', $avg < 100, sprintf('avg %.1f ms', $avg));

$passed = count(array_filter($results, fn($r) => $r['pass']));
printf("\n%d of %d tests passed\n", $passed, count($results));
file_put_contents(__DIR__ . '/last_results.json', json_encode(['avg_ms' => $avg, 'results' => $results], JSON_PRETTY_PRINT));
exit($passed === count($results) ? 0 : 1);
