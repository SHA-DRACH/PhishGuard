<?php
/**
 * Demo data for presentations / screenshots (CLI only).
 *   php database/demo_seed.php          – load demo staff, scans, reports and an evaluation
 *   php database/demo_seed.php --remove – delete all demo data again
 * Demo accounts use @demo.local emails and random passwords (they cannot sign in).
 */
if (PHP_SAPI !== 'cli') exit('CLI only');
require __DIR__ . '/../includes/bootstrap.php';
$pdo = db();
$DEMO_IP = '203.0.113.99';

// Always start clean
$pdo->exec("DELETE FROM reports WHERE reporter LIKE '%@demo.local'");
$pdo->exec("DELETE FROM scans WHERE ip_address = '$DEMO_IP'");
$pdo->exec("DELETE FROM evaluations WHERE dataset_name = 'demo_sample_dataset.csv'");
$pdo->exec("DELETE FROM users WHERE email LIKE '%@demo.local'");
if (in_array('--remove', $argv, true)) { echo "Demo data removed.\n"; exit; }

$presets = position_presets();
$staff = [
    ['Grace Toe',      'grace.toe@demo.local',      'ICT Security',   'Cybersecurity Analyst'],
    ['Emmanuel Kollie','emmanuel.kollie@demo.local','ICT Support',    'ICT Support Officer'],
    ['Precious Wesseh','precious.wesseh@demo.local','Customer Care',  'Customer Care Officer'],
];
$ids = [];
$ins = $pdo->prepare('INSERT INTO users (full_name, email, password_hash, department, position, responsibilities, created_by, last_login) VALUES (?,?,?,?,?,?,1, NOW() - INTERVAL ? HOUR)');
foreach ($staff as $i => [$n, $e, $d, $p]) {
    $ins->execute([$n, $e, password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT), $d, $p, implode("\n", $presets[$p]), $i * 5 + 1]);
    $ids[] = (int)$pdo->lastInsertId();
}

// Scans over the last 7 days using the sample dataset
$detector = new PhishingDetector($pdo, false);
$fh = fopen(__DIR__ . '/../data/sample_dataset.csv', 'r');
fgetcsv($fh);
$scan = $pdo->prepare('INSERT INTO scans (user_id, url, host, score, verdict, features, source, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?, NOW() - INTERVAL ? MINUTE)');
$n = 0;
while ($row = fgetcsv($fh)) {
    $r = $detector->analyze($row[0]);
    $who = [null, $ids[0], $ids[1], $ids[2], null][$n % 5];
    $scan->execute([$who, $r['url'], $r['host'], $r['score'], $r['verdict'],
        json_encode(['features' => $r['features'], 'list_match' => $r['list_match'], 'final_url' => $r['url'], 'duration_ms' => 1]),
        'web', $DEMO_IP, ($n * 157) % (7 * 24 * 60)]);
    $n++;
}

// Reports: one with an analyst finding, one assigned, one unassigned, one confirmed
$rep = $pdo->prepare('INSERT INTO reports (reporter, url, description, status, assigned_to, assigned_at, analyst_verdict, analyst_note, analyst_at, reviewed_by, reviewed_at, created_at)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?, NOW() - INTERVAL ? HOUR)');
$rep->execute(['customer1@demo.local', 'http://ltc-fibre-billing.top/pay', 'SMS said my LTC fibre internet will be disconnected today unless I pay through this link.',
    'pending', $ids[0], date('Y-m-d H:i:s', strtotime('-5 hours')), 'phishing',
    'Domain imitates LTC billing, uses the .top TLD, was registered recently and the payment form posts to an external server.', date('Y-m-d H:i:s', strtotime('-2 hours')), null, null, 6]);
$rep->execute(['staff2@demo.local', 'http://lonestar-momo-verify.xyz/pin', 'WhatsApp message asking customers to confirm their Mobile Money PIN.',
    'pending', $ids[1], date('Y-m-d H:i:s', strtotime('-1 hours')), null, null, null, null, null, 3]);
$rep->execute(['customer3@demo.local', 'https://libtelco-webmail-login.com/owa', 'Email to staff asking them to re-activate their webmail account.',
    'pending', null, null, null, null, null, null, null, 1]);
$rep->execute(['customer4@demo.local', 'http://ltc-account-verify.tk/login', 'Fake LTC login page shared on Facebook.',
    'confirmed', $ids[0], date('Y-m-d H:i:s', strtotime('-3 days')), 'phishing', 'Clone of the LTC customer portal.', date('Y-m-d H:i:s', strtotime('-3 days')), 1, date('Y-m-d H:i:s', strtotime('-2 days')), 80]);

// Evaluation record (URL-only run on the sample dataset)
$pdo->prepare('INSERT INTO evaluations (run_by, dataset_name, network, total, tp, fp, tn, fn, accuracy, precision_v, recall, f1, duration_ms) VALUES (1,?,0,60,30,0,30,0,1,1,1,1,31)')
    ->execute(['demo_sample_dataset.csv']);

echo "Demo data loaded: " . count($ids) . " staff, $n scans, 4 reports, 1 evaluation.\n";
