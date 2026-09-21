<?php
/**
 * Page header. Three separate layouts – links never cross between them:
 *   public – top navigation (home, awareness, report, sign in)
 *   user   – sidebar for signed-in users
 *   admin  – sidebar for administrators (everything under /admin/)
 *
 * Pages may set $layout = 'public' | 'auto' before including this file.
 * 'auto' picks the signed-in user's area, or public for guests.
 *
 * @var string $pageTitle
 */
$user = current_user();
$inAdmin = str_contains($_SERVER['SCRIPT_NAME'], '/admin/');
$layout = $inAdmin ? 'admin' : ($layout ?? 'public');
if ($layout === 'auto') {
    $layout = $user ? ($user['role'] === 'admin' ? 'admin' : 'user') : 'public';
}
$currentPath = ltrim(substr($_SERVER['SCRIPT_NAME'], strlen(BASE_URL)), '/');
$initials = $user ? implode('', array_map(fn($p) => mb_strtoupper(mb_substr($p, 0, 1)), array_slice(explode(' ', $user['full_name']), 0, 2))) : '';

/** Sidebar link */
$side = function (string $path, string $label, string $icon, ?int $count = null) use ($currentPath): string {
    $aliases = ['admin/user_edit.php' => 'admin/users.php'];
    $active = ($aliases[$currentPath] ?? $currentPath) === $path ? ' aria-current="page"' : '';
    $badge = $count ? '<span class="side-count">' . $count . '</span>' : '';
    return '<a href="' . url($path) . '"' . $active . ' title="' . e(strip_tags($label)) . '">' . icon($icon)
         . '<span class="side-label">' . $label . '</span>' . $badge . '</a>';
};
/** Top-nav link (public site) */
$top = fn(string $path, string $label) =>
    '<a href="' . url($path) . '"' . ($currentPath === $path ? ' aria-current="page"' : '') . '>' . $label . '</a>';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="csrf-token" content="<?= csrf_token() ?>">
  <meta name="color-scheme" content="light dark">
  <title><?= e($pageTitle ?? 'Home') ?> – <?= APP_NAME ?></title>
  <link rel="icon" href="<?= url('assets/img/shield.svg') ?>" type="image/svg+xml">
  <script>try{const d=document.documentElement,t=localStorage.getItem('pg-theme');if(t)d.dataset.theme=t;if(localStorage.getItem('pg-sidebar')==='collapsed')d.dataset.sidebar='collapsed';}catch(e){}</script>
  <link rel="stylesheet" href="<?= url('assets/css/style.css') ?>">
  <script src="<?= url('assets/js/app.js') ?>" defer></script>
</head>
<body data-base="<?= BASE_URL ?>" data-layout="<?= $layout ?>">
<?php if ($layout === 'public'): ?>
<header class="site-header">
  <div class="container header-inner">
    <a class="brand" href="<?= url('index.php') ?>">
      <img src="<?= url('assets/img/shield.svg') ?>" alt="" width="32" height="32">
      <span><strong><?= APP_NAME ?></strong><small><?= ORG_SHORT ?> Phishing Detection</small></span>
    </a>
    <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="main-nav" aria-label="Menu">
      <span></span><span></span><span></span>
    </button>
    <nav id="main-nav" class="main-nav">
      <?= $top('index.php', 'Scan') ?>
      <?= $top('awareness.php', 'Awareness') ?>
      <?= $top('report.php', 'Report a site') ?>
      <?php if ($user): ?>
        <a class="btn btn-sm btn-primary" href="<?= url($user['role'] === 'admin' ? 'admin/index.php' : 'dashboard.php') ?>">
          <?= $user['role'] === 'admin' ? 'Admin console' : 'My dashboard' ?></a>
      <?php else: ?>
        <a class="btn btn-sm btn-outline" href="<?= url('login.php') ?>">Sign in</a>
      <?php endif; ?>
      <button class="theme-toggle" type="button" aria-label="Toggle light/dark theme" title="Toggle theme"><?= icon('theme') ?></button>
    </nav>
  </div>
</header>
<main class="container page">
<?php else: /* ---------------- app layouts (user / admin) ---------------- */
  $pending = $layout === 'admin' ? (int)db()->query("SELECT COUNT(*) FROM reports WHERE status = 'pending'")->fetchColumn() : 0;
?>
<div class="app-shell">
  <aside class="sidebar" id="sidebar" aria-label="<?= $layout === 'admin' ? 'Admin' : 'Account' ?> navigation">
    <div class="sidebar-head">
      <a class="brand" href="<?= url($layout === 'admin' ? 'admin/index.php' : 'dashboard.php') ?>">
        <img src="<?= url('assets/img/shield.svg') ?>" alt="" width="32" height="32">
        <span class="side-label"><strong><?= APP_NAME ?></strong><small><?= $layout === 'admin' ? 'Admin console' : 'My account' ?></small></span>
      </a>
      <button class="sidebar-close" type="button" aria-label="Close menu"><?= icon('close') ?></button>
    </div>

    <nav class="side-nav">
      <?php if ($layout === 'admin'): ?>
        <p class="side-heading">Monitor</p>
        <?= $side('admin/index.php', 'Overview', 'grid') ?>
        <?= $side('admin/scan.php', 'Scanner', 'scan') ?>
        <?= $side('admin/scans.php', 'All scans', 'list') ?>
        <?= $side('admin/reports.php', 'Reports', 'flag', $pending) ?>
        <p class="side-heading">Threat intelligence</p>
        <?= $side('admin/lists.php', 'Blacklist &amp; trusted', 'shield') ?>
        <?= $side('admin/evaluate.php', 'Evaluation', 'chart') ?>
        <p class="side-heading">Administration</p>
        <?= $side('admin/users.php', 'Users', 'users') ?>
        <?= $side('admin/profile.php', 'My profile', 'user') ?>
      <?php else: ?>
        <p class="side-heading">Menu</p>
        <?= $side('dashboard.php', 'Dashboard', 'grid') ?>
        <?= $side('scan.php', 'Scan a link', 'scan') ?>
        <?= $side('tasks.php', 'My tasks', 'check', open_task_count((int)$user['id'])) ?>
        <?= $side('history.php', 'My scans', 'list') ?>
        <?= $side('report.php', 'Report a site', 'flag') ?>
        <p class="side-heading">Account</p>
        <?= $side('profile.php', 'Profile &amp; security', 'user') ?>
      <?php endif; ?>
    </nav>

    <div class="sidebar-foot">
      <div class="side-user">
        <span class="avatar"><?= e($initials) ?></span>
        <span class="side-label"><strong><?= e($user['full_name']) ?></strong><small><?= e($user['email']) ?></small></span>
      </div>
      <form method="post" action="<?= url('logout.php') ?>"><?= csrf_field() ?>
        <button type="submit" class="side-logout" title="Sign out"><?= icon('logout') ?><span class="side-label">Sign out</span></button>
      </form>
    </div>
  </aside>
  <div class="sidebar-backdrop" hidden></div>

  <div class="app-main">
    <header class="topbar">
      <button class="sidebar-open" type="button" aria-label="Open menu" aria-controls="sidebar"><?= icon('menu') ?></button>
      <button class="sidebar-collapse" type="button" aria-label="Collapse sidebar" title="Collapse sidebar"><?= icon('sidebar') ?></button>
      <div class="topbar-title">
        <small><?= $layout === 'admin' ? 'Admin' : 'Account' ?></small>
        <strong><?= e($pageTitle ?? '') ?></strong>
      </div>
      <div class="topbar-actions">
        <button class="theme-toggle" type="button" aria-label="Toggle light/dark theme" title="Toggle theme"><?= icon('theme') ?></button>
        <span class="avatar" title="<?= e($user['full_name']) ?>"><?= e($initials) ?></span>
      </div>
    </header>
    <main class="app-content">
<?php endif; ?>
<?php foreach (take_flashes() as $f): ?>
  <div class="alert alert-<?= e($f['type']) ?>" role="status"><?= e($f['message']) ?></div>
<?php endforeach; ?>
