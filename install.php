<?php
/**
 * One-time installer: creates the database, tables, default admin and seed data.
 * Visit http://localhost/PhishGuard/install.php (or run: php install.php).
 */
require_once __DIR__ . '/config/config.php';
defined('APP_NAME') || define('APP_NAME', 'PhishGuard');

$cli = PHP_SAPI === 'cli';
$log = [];

try {
    $pdo = new PDO(sprintf('mysql:host=%s;port=%d;charset=utf8mb4', DB_HOST, DB_PORT), DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('CREATE DATABASE IF NOT EXISTS `' . DB_NAME . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $pdo->exec('USE `' . DB_NAME . '`');
    $log[] = 'Database "' . DB_NAME . '" ready.';

    foreach (['schema.sql', 'migrate_v2.sql', 'migrate_v3.sql', 'migrate_v4.sql'] as $file) {
        $schema = preg_replace('/^\s*--.*$/m', '', file_get_contents(__DIR__ . '/database/' . $file));
        foreach (array_filter(array_map('trim', explode(';', $schema))) as $sql) {
            $pdo->exec($sql);
        }
    }
    $log[] = 'Tables created.';

    $adminEmail = 'admin@ltc.com.lr';
    $exists = $pdo->prepare('SELECT id FROM users WHERE email = ?');
    $exists->execute([$adminEmail]);
    if (!$exists->fetch()) {
        $pdo->prepare('INSERT INTO users (full_name, email, password_hash, role, department) VALUES (?,?,?,?,?)')
            ->execute(['System Administrator', $adminEmail, password_hash('Admin@123', PASSWORD_DEFAULT), 'admin', 'ICT / Cybersecurity']);
        $log[] = "Default admin created: $adminEmail / Admin@123 (change this password after first login).";
    } else {
        $log[] = 'Admin account already exists – skipped.';
    }

    // Trusted domains (brand keyword powers impersonation & look-alike detection).
    // Verify local domains with LTC ICT before production use.
    $trusted = [
        ['libtelco.com.lr', 'libtelco'], ['lonestarcell.com', 'lonestar'], ['orange.com', 'orange'],
        ['google.com', 'google'], ['gmail.com', 'gmail'], ['youtube.com', 'youtube'],
        ['microsoft.com', 'microsoft'], ['office.com', 'office365'], ['live.com', null], ['microsoftonline.com', null], ['outlook.com', 'outlook'],
        ['apple.com', 'apple'], ['icloud.com', 'icloud'], ['paypal.com', 'paypal'], ['amazon.com', 'amazon'],
        ['facebook.com', 'facebook'], ['instagram.com', 'instagram'], ['whatsapp.com', 'whatsapp'],
        ['linkedin.com', 'linkedin'], ['netflix.com', 'netflix'], ['yahoo.com', 'yahoo'],
        ['ecobank.com', 'ecobank'], ['westernunion.com', 'westernunion'], ['moneygram.com', 'moneygram'],
        ['github.com', 'github'], ['wikipedia.org', 'wikipedia'], ['dropbox.com', 'dropbox'],
    ];
    $ins = $pdo->prepare('INSERT IGNORE INTO whitelist (domain, brand) VALUES (?, ?)');
    foreach ($trusted as [$d, $b]) $ins->execute([$d, $b]);
    $log[] = count($trusted) . ' trusted domains seeded.';

    // Sample blacklist entries (fictitious, for demonstration)
    $bl = [
        ['ltc-account-verify.tk', 'Demo: impersonates LTC billing portal'],
        ['secure-paypa1-login.com', 'Demo: PayPal credential harvesting'],
        ['lonestar-free-airtime.xyz', 'Demo: fake airtime giveaway'],
    ];
    $ins = $pdo->prepare('INSERT IGNORE INTO blacklist (domain, reason) VALUES (?, ?)');
    foreach ($bl as [$d, $r]) $ins->execute([$d, $r]);
    $log[] = count($bl) . ' demo blacklist entries seeded.';

    $ok = true;
} catch (Throwable $e) {
    $ok = false;
    $log[] = 'ERROR: ' . $e->getMessage();
}

if ($cli) {
    echo implode(PHP_EOL, $log) . PHP_EOL;
    exit($ok ? 0 : 1);
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Install – <?= APP_NAME ?></title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="auth-page">
<main class="auth-card">
  <h1><?= $ok ? 'Installation complete' : 'Installation failed' ?></h1>
  <ul class="install-log">
    <?php foreach ($log as $line): ?><li><?= htmlspecialchars($line) ?></li><?php endforeach; ?>
  </ul>
  <?php if ($ok): ?>
    <p class="muted">For security, delete or rename <code>install.php</code> once you are done.</p>
    <a class="btn btn-primary" href="login.php">Go to sign in</a>
  <?php endif; ?>
</main>
</body>
</html>
