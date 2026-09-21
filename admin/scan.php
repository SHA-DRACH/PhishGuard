<?php
require_once __DIR__ . '/../includes/bootstrap.php';
require_admin();
$pageTitle = 'Scanner';
require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Investigation</span><h1>Scanner</h1>
  <p class="muted">Investigate a reported or suspicious URL. Every scan is logged in <a href="<?= url('admin/scans.php') ?>">All scans</a>.</p></div></div>
<div class="card scanner-card"><?php require __DIR__ . '/../includes/scanner.php'; ?></div>
<section id="result" class="result" aria-live="polite"></section>
<?php require __DIR__ . '/../includes/footer.php'; ?>
