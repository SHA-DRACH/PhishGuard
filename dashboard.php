<?php
require_once __DIR__ . '/includes/bootstrap.php';
$user = require_login();
if ($user['role'] === 'admin') redirect('admin/index.php');
$pageTitle = 'Dashboard';
$layout = 'auto';

$stats = scan_stats((int)$user['id']);
$stmt = db()->prepare('SELECT id, url, score, verdict, created_at FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 6');
$stmt->execute([$user['id']]);
$recent = $stmt->fetchAll();
$stmt = db()->prepare('SELECT COUNT(*) FROM reports WHERE user_id = ?');
$stmt->execute([$user['id']]);
$reportCount = (int)$stmt->fetchColumn();

$responsibilities = user_responsibilities($user);
$stmt = db()->prepare("SELECT id, url, assigned_at FROM reports WHERE assigned_to = ? AND status = 'pending' AND analyst_verdict IS NULL ORDER BY assigned_at LIMIT 5");
$stmt->execute([$user['id']]);
$tasks = $stmt->fetchAll();
$openTasks = open_task_count((int)$user['id']);
$stmt = db()->prepare('SELECT COUNT(*) FROM reports WHERE assigned_to = ? AND analyst_verdict IS NOT NULL');
$stmt->execute([$user['id']]);
$doneTasks = (int)$stmt->fetchColumn();

require __DIR__ . '/includes/header.php';
?>
<section class="card welcome-card">
  <div class="welcome-id">
    <span class="avatar avatar-lg"><?= e($initials) ?></span>
    <div>
      <span class="eyebrow">Personal dashboard</span>
      <h1>Hello, <?= e(strtok($user['full_name'], ' ')) ?></h1>
      <p class="muted">
        <?= $user['position'] ? '<strong>' . e($user['position']) . '</strong>' : 'Member' ?><?= $user['department'] ? ' · ' . e($user['department']) : '' ?>
        · <?= e(ORG_NAME) ?>
      </p>
    </div>
  </div>
  <div class="welcome-stats">
    <div><strong><?= $openTasks ?></strong><span>Open tasks</span></div>
    <div><strong><?= $doneTasks ?></strong><span>Findings sent</span></div>
    <div><strong><?= $reportCount ?></strong><span>Sites reported</span></div>
  </div>
</section>

<div class="grid grid-2" style="margin-top:20px">
  <section class="card">
    <div class="card-head"><h3>My responsibilities</h3><?php if ($user['position']): ?><span class="badge badge-admin"><?= e($user['position']) ?></span><?php endif; ?></div>
    <ol class="duty-list">
      <?php foreach ($responsibilities as $duty): ?><li><?= e($duty) ?></li><?php endforeach; ?>
    </ol>
    <p class="small muted" style="margin:14px 0 0">Assigned by the <?= e(ORG_SHORT) ?> security administrator. Contact them if your duties change.</p>
  </section>

  <section class="card">
    <div class="card-head"><h3>Assigned investigations</h3><a class="small" href="<?= url('tasks.php') ?>">All tasks →</a></div>
    <?php if (!$tasks): ?>
      <div class="empty" style="padding:24px 10px">No open investigations. New assignments from the security team will appear here.</div>
    <?php else: ?>
      <ul class="task-list">
        <?php foreach ($tasks as $t): ?>
          <li><span class="dot"></span><code title="<?= e($t['url']) ?>"><?= e($t['url']) ?></code>
            <small class="muted"><?= e(time_ago($t['assigned_at'])) ?></small>
            <a class="btn btn-sm btn-outline" href="<?= url('tasks.php') ?>#t<?= $t['id'] ?>">Investigate</a></li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
    <div class="quick-actions">
      <a class="btn btn-primary" href="<?= url('scan.php') ?>"><?= icon('scan') ?> Scan a link</a>
      <a class="btn btn-ghost" href="<?= url('report.php') ?>"><?= icon('flag') ?> Report a site</a>
    </div>
  </section>
</div>

<h2 style="margin:32px 0 16px">My scanning activity</h2>
<?php require __DIR__ . '/includes/stats_panels.php'; ?>

<div class="card" style="margin-top:20px">
  <div class="card-head"><h3>Recent scans</h3><a class="small" href="<?= url('history.php') ?>">View all →</a></div>
  <?php if (!$recent): ?>
    <div class="empty">No scans yet. <a href="<?= url('scan.php') ?>">Scan your first link</a>.</div>
  <?php else: ?>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>URL</th><th>Score</th><th>Verdict</th><th>When</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($recent as $s): ?>
        <tr>
          <td class="url-cell" title="<?= e($s['url']) ?>"><?= e($s['url']) ?></td>
          <td><?= score_pill((int)$s['score']) ?></td>
          <td><?= verdict_badge($s['verdict']) ?></td>
          <td class="muted small"><?= e(time_ago($s['created_at'])) ?></td>
          <td class="actions"><a class="btn btn-sm btn-ghost" href="<?= url('result.php?id=' . $s['id']) ?>">Details</a></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table></div>
  <?php endif; ?>
</div>
<?php require __DIR__ . '/includes/footer.php'; ?>
