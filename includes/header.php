<?php
/** @var string $pageTitle */
$user = current_user();
$current = basename($_SERVER['SCRIPT_NAME']);
$inAdmin = str_contains($_SERVER['SCRIPT_NAME'], '/admin/');
$nav = fn(string $file, string $label, bool $admin = false) =>
    '<a href="' . url(($admin ? 'admin/' : '') . $file) . '"' .
    (($current === $file && $inAdmin === $admin) ? ' aria-current="page"' : '') . '>' . $label . '</a>';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="<?= csrf_token() ?>">
  <meta name="color-scheme" content="light dark">
  <title><?= e($pageTitle ?? 'Home') ?> – <?= APP_NAME ?></title>
  <link rel="icon" href="<?= url('assets/img/shield.svg') ?>" type="image/svg+xml">
  <script>try{const t=localStorage.getItem('pg-theme');if(t)document.documentElement.dataset.theme=t;}catch(e){}</script>
  <link rel="stylesheet" href="<?= url('assets/css/style.css') ?>">
  <script src="<?= url('assets/js/app.js') ?>" defer></script>
</head>
<body data-base="<?= BASE_URL ?>">
<header class="site-header">
  <div class="container header-inner">
    <a class="brand" href="<?= url('index.php') ?>">
      <img src="<?= url('assets/img/shield.svg') ?>" alt="" width="32" height="32">
      <span><strong><?= APP_NAME ?></strong><small><?= ORG_SHORT ?> Phishing Detection</small></span>
    </a>
    <button class="nav-toggle" aria-expanded="false" aria-controls="main-nav" aria-label="Menu">
      <span></span><span></span><span></span>
    </button>
    <nav id="main-nav" class="main-nav">
      <?= $nav('index.php', 'Scan') ?>
      <?= $nav('awareness.php', 'Awareness') ?>
      <?= $nav('report.php', 'Report a site') ?>
      <?php if ($user): ?>
        <?= $nav('dashboard.php', 'Dashboard') ?>
        <?= $nav('history.php', 'My scans') ?>
        <?php if ($user['role'] === 'admin'): ?>
          <?= $nav('index.php', 'Admin', true) ?>
        <?php endif; ?>
        <details class="user-menu">
          <summary data-initials="<?= e(implode('', array_map(fn($p) => mb_strtoupper(mb_substr($p, 0, 1)), array_slice(explode(' ', $user['full_name']), 0, 2)))) ?>"><?= e(strtok($user['full_name'], ' ')) ?></summary>
          <div class="user-menu-panel">
            <p><strong><?= e($user['full_name']) ?></strong><br><small><?= e($user['email']) ?></small></p>
            <a href="<?= url('profile.php') ?>">Profile &amp; password</a>
            <form method="post" action="<?= url('logout.php') ?>"><?= csrf_field() ?><button type="submit" class="linklike">Sign out</button></form>
          </div>
        </details>
      <?php else: ?>
        <a class="btn btn-sm btn-outline" href="<?= url('login.php') ?>">Sign in</a>
      <?php endif; ?>
      <button class="theme-toggle" type="button" aria-label="Toggle light/dark theme" title="Toggle theme">◐</button>
    </nav>
  </div>
</header>
<?php if ($inAdmin): ?>
<nav class="subnav" aria-label="Administration">
  <div class="container">
    <?= $nav('index.php', 'Overview', true) ?>
    <?= $nav('scans.php', 'All scans', true) ?>
    <?= $nav('reports.php', 'Reports', true) ?>
    <?= $nav('lists.php', 'Blacklist &amp; trusted', true) ?>
    <?= $nav('evaluate.php', 'Evaluation', true) ?>
    <?= $nav('users.php', 'Users', true) ?>
  </div>
</nav>
<?php endif; ?>
<main class="container page">
<?php foreach (take_flashes() as $f): ?>
  <div class="alert alert-<?= e($f['type']) ?>" role="status"><?= e($f['message']) ?></div>
<?php endforeach; ?>
