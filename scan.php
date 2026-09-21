<?php
require_once __DIR__ . '/includes/bootstrap.php';
$user = require_login();
if ($user['role'] === 'admin') redirect('admin/scan.php' . (isset($_GET['url']) ? '?url=' . urlencode($_GET['url']) : ''));
$pageTitle = 'Scan a link';
$layout = 'auto';
require __DIR__ . '/includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Scanner</span><h1>Scan a link</h1>
  <p class="muted">Results are saved to <a href="<?= url('history.php') ?>">My scans</a>.</p></div></div>
<div class="card scanner-card"><?php require __DIR__ . '/includes/scanner.php'; ?></div>
<section id="result" class="result" aria-live="polite"></section>
<?php require __DIR__ . '/includes/footer.php'; ?>
