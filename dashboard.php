<?php
require_once __DIR__ . '/includes/bootstrap.php';
$user = require_login();
$pageTitle = 'Dashboard';

$stats = scan_stats((int)$user['id']);
$stmt = db()->prepare('SELECT id, url, score, verdict, created_at FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 6');
$stmt->execute([$user['id']]);
$recent = $stmt->fetchAll();
$stmt = db()->prepare('SELECT COUNT(*) FROM reports WHERE user_id = ?');
$stmt->execute([$user['id']]);
$reportCount = (int)$stmt->fetchColumn();

require __DIR__ . '/includes/header.php';
?>
<div class="page-head">
  <div>
    <span class="eyebrow">Personal dashboard</span>
    <h1>Hello, <?= e(strtok($user['full_name'], ' ')) ?></h1>
    <p class="muted">Your scanning activity and threats caught. You have submitted <?= $reportCount ?> report<?= $reportCount === 1 ? '' : 's' ?>.</p>
  </div>
  <a class="btn btn-primary" href="<?= url('index.php') ?>">New scan</a>
</div>

<?php require __DIR__ . '/includes/stats_panels.php'; ?>

<div class="card" style="margin-top:20px">
  <div class="card-head"><h3>Recent scans</h3><a class="small" href="<?= url('history.php') ?>">View all →</a></div>
  <?php if (!$recent): ?>
    <div class="empty">No scans yet. <a href="<?= url('index.php') ?>">Scan your first link</a>.</div>
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
