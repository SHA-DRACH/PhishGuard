<?php
require_once __DIR__ . '/../includes/bootstrap.php';
require_admin();
$pageTitle = 'Admin overview';

$stats = scan_stats(null);
$counts = db()->query("SELECT
    (SELECT COUNT(*) FROM users) users,
    (SELECT COUNT(*) FROM reports WHERE status = 'pending') pending,
    (SELECT COUNT(*) FROM blacklist) blacklist,
    (SELECT COUNT(*) FROM whitelist) whitelist")->fetch();
$lastEval = db()->query('SELECT * FROM evaluations ORDER BY id DESC LIMIT 1')->fetch();
$latestThreats = db()->query("SELECT s.id, s.url, s.score, s.verdict, s.created_at, u.full_name FROM scans s
    LEFT JOIN users u ON u.id = s.user_id WHERE s.verdict <> 'safe' ORDER BY s.id DESC LIMIT 8")->fetchAll();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head">
  <div><span class="eyebrow">Security operations</span><h1>Threat overview</h1>
    <p class="muted">Organisation-wide phishing activity for <?= ORG_NAME ?>.</p></div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <a class="btn btn-ghost" href="scans.php?export=csv">Export CSV</a>
    <a class="btn btn-primary" href="reports.php">Review reports<?= $counts['pending'] ? " ({$counts['pending']})" : '' ?></a>
  </div>
</div>

<?php require __DIR__ . '/../includes/stats_panels.php'; ?>

<div class="grid grid-4" style="margin-top:20px">
  <a class="card kpi" href="users.php" style="color:inherit;text-decoration:none"><div class="kpi-label">Users</div><div class="kpi-value"><?= (int)$counts['users'] ?></div><div class="kpi-sub">Registered accounts</div></a>
  <a class="card kpi kpi-warn" href="reports.php" style="color:inherit;text-decoration:none"><div class="kpi-label">Pending reports</div><div class="kpi-value"><?= (int)$counts['pending'] ?></div><div class="kpi-sub">Awaiting review</div></a>
  <a class="card kpi kpi-danger" href="lists.php" style="color:inherit;text-decoration:none"><div class="kpi-label">Blacklist</div><div class="kpi-value"><?= (int)$counts['blacklist'] ?></div><div class="kpi-sub"><?= (int)$counts['whitelist'] ?> trusted domains</div></a>
  <a class="card kpi kpi-safe" href="evaluate.php" style="color:inherit;text-decoration:none"><div class="kpi-label">Detection accuracy</div>
    <div class="kpi-value"><?= $lastEval ? round($lastEval['accuracy'] * 100, 1) . '%' : '—' ?></div>
    <div class="kpi-sub"><?= $lastEval ? 'F1 ' . round($lastEval['f1'] * 100, 1) . '% · last evaluation' : 'Run an evaluation' ?></div></a>
</div>

<div class="card" style="margin-top:20px">
  <div class="card-head"><h3>Latest threats detected</h3><a class="small" href="scans.php?verdict=phishing">All phishing →</a></div>
  <?php if (!$latestThreats): ?>
    <div class="empty">No threats detected yet.</div>
  <?php else: ?>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>URL</th><th>Score</th><th>Verdict</th><th>User</th><th>When</th><th></th></tr></thead>
    <tbody>
    <?php foreach ($latestThreats as $s): ?>
      <tr>
        <td class="url-cell" title="<?= e($s['url']) ?>"><?= e($s['url']) ?></td>
        <td><?= score_pill((int)$s['score']) ?></td>
        <td><?= verdict_badge($s['verdict']) ?></td>
        <td class="small"><?= e($s['full_name'] ?? 'Guest') ?></td>
        <td class="muted small"><?= e(time_ago($s['created_at'])) ?></td>
        <td class="actions"><a class="btn btn-sm btn-ghost" href="<?= url('result.php?id=' . $s['id']) ?>">Details</a></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
  <?php endif; ?>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
