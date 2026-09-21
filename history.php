<?php
require_once __DIR__ . '/includes/bootstrap.php';
$user = require_login();
if ($user['role'] === 'admin') redirect('admin/scans.php');
$pageTitle = 'My scans';
$layout = 'auto';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    db()->prepare('DELETE FROM scans WHERE id = ? AND user_id = ?')->execute([(int)$_POST['id'], $user['id']]);
    flash('success', 'Scan removed from your history.');
    redirect('history.php');
}

$q = trim($_GET['q'] ?? '');
$verdict = in_array($_GET['verdict'] ?? '', ['safe', 'suspicious', 'phishing'], true) ? $_GET['verdict'] : '';
$page = max(1, (int)($_GET['page'] ?? 1));
$per = 15;

$where = ['user_id = ?'];
$args = [$user['id']];
if ($q !== '') { $where[] = 'url LIKE ?'; $args[] = '%' . $q . '%'; }
if ($verdict) { $where[] = 'verdict = ?'; $args[] = $verdict; }
$sqlWhere = implode(' AND ', $where);

$stmt = db()->prepare("SELECT COUNT(*) FROM scans WHERE $sqlWhere");
$stmt->execute($args);
$total = (int)$stmt->fetchColumn();

$stmt = db()->prepare("SELECT id, url, score, verdict, created_at FROM scans WHERE $sqlWhere ORDER BY id DESC LIMIT $per OFFSET " . (($page - 1) * $per));
$stmt->execute($args);
$rows = $stmt->fetchAll();

require __DIR__ . '/includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">History</span><h1>My scans</h1><p class="muted"><?= number_format($total) ?> result<?= $total === 1 ? '' : 's' ?></p></div></div>

<form class="toolbar" method="get">
  <input type="search" name="q" value="<?= e($q) ?>" placeholder="Search URL…">
  <select name="verdict">
    <option value="">All verdicts</option>
    <?php foreach (['safe' => 'Safe', 'suspicious' => 'Suspicious', 'phishing' => 'Phishing'] as $k => $v): ?>
      <option value="<?= $k ?>" <?= $verdict === $k ? 'selected' : '' ?>><?= $v ?></option>
    <?php endforeach; ?>
  </select>
  <button class="btn" type="submit">Filter</button>
</form>

<?php if (!$rows): ?>
  <div class="card empty">No scans match your filters.</div>
<?php else: ?>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>URL</th><th>Score</th><th>Verdict</th><th>Date</th><th></th></tr></thead>
    <tbody>
    <?php foreach ($rows as $s): ?>
      <tr>
        <td class="url-cell" title="<?= e($s['url']) ?>"><?= e($s['url']) ?></td>
        <td><?= score_pill((int)$s['score']) ?></td>
        <td><?= verdict_badge($s['verdict']) ?></td>
        <td class="muted small"><?= e(date('M j, Y H:i', strtotime($s['created_at']))) ?></td>
        <td class="actions">
          <a class="btn btn-sm btn-ghost" href="<?= url('result.php?id=' . $s['id']) ?>">Details</a>
          <form method="post" data-confirm="Remove this scan from your history?"><?= csrf_field() ?>
            <input type="hidden" name="id" value="<?= $s['id'] ?>"><button class="btn btn-sm btn-ghost" type="submit">Delete</button></form>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
  <?= paginate($total, $page, $per, array_filter(['q' => $q, 'verdict' => $verdict])) ?>
<?php endif; ?>
<?php require __DIR__ . '/includes/footer.php'; ?>
