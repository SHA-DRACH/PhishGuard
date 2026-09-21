<?php
require_once __DIR__ . '/../includes/bootstrap.php';
$admin = require_admin();
$pageTitle = 'All scans';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $id = (int)($_POST['id'] ?? 0);
    if (($_POST['action'] ?? '') === 'blacklist') {
        $stmt = db()->prepare('SELECT host FROM scans WHERE id = ?');
        $stmt->execute([$id]);
        if ($host = $stmt->fetchColumn()) {
            db()->prepare('INSERT IGNORE INTO blacklist (domain, reason, added_by) VALUES (?, ?, ?)')
                ->execute([$host, "Blacklisted from scan #$id", $admin['id']]);
            flash('success', "$host added to the blacklist.");
        }
    } elseif (($_POST['action'] ?? '') === 'delete') {
        db()->prepare('DELETE FROM scans WHERE id = ?')->execute([$id]);
        flash('success', 'Scan deleted.');
    }
    redirect('admin/scans.php?' . http_build_query(array_intersect_key($_GET, array_flip(['q', 'verdict', 'page']))));
}

$q = trim($_GET['q'] ?? '');
$verdict = in_array($_GET['verdict'] ?? '', ['safe', 'suspicious', 'phishing'], true) ? $_GET['verdict'] : '';
$where = ['1=1'];
$args = [];
if ($q !== '') { $where[] = '(s.url LIKE ? OR u.full_name LIKE ?)'; $args[] = "%$q%"; $args[] = "%$q%"; }
if ($verdict) { $where[] = 's.verdict = ?'; $args[] = $verdict; }
$sqlWhere = implode(' AND ', $where);

if (($_GET['export'] ?? '') === 'csv') {
    $stmt = db()->prepare("SELECT s.id, s.created_at, s.url, s.host, s.score, s.verdict, COALESCE(u.email, 'guest') user, s.ip_address
        FROM scans s LEFT JOIN users u ON u.id = s.user_id WHERE $sqlWhere ORDER BY s.id DESC");
    $stmt->execute($args);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="phishguard-scans-' . date('Ymd-His') . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['id', 'date', 'url', 'host', 'score', 'verdict', 'user', 'ip']);
    foreach ($stmt as $row) fputcsv($out, $row);
    exit;
}

$page = max(1, (int)($_GET['page'] ?? 1));
$per = 20;
$stmt = db()->prepare("SELECT COUNT(*) FROM scans s LEFT JOIN users u ON u.id = s.user_id WHERE $sqlWhere");
$stmt->execute($args);
$total = (int)$stmt->fetchColumn();
$stmt = db()->prepare("SELECT s.*, u.full_name FROM scans s LEFT JOIN users u ON u.id = s.user_id
    WHERE $sqlWhere ORDER BY s.id DESC LIMIT $per OFFSET " . (($page - 1) * $per));
$stmt->execute($args);
$rows = $stmt->fetchAll();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Audit log</span><h1>All scans</h1><p class="muted"><?= number_format($total) ?> records</p></div>
  <a class="btn btn-ghost" href="?<?= e(http_build_query(array_filter(['q' => $q, 'verdict' => $verdict]) + ['export' => 'csv'])) ?>">Export CSV</a></div>

<form class="toolbar" method="get">
  <input type="search" name="q" value="<?= e($q) ?>" placeholder="Search URL or user…">
  <select name="verdict"><option value="">All verdicts</option>
    <?php foreach (['safe' => 'Safe', 'suspicious' => 'Suspicious', 'phishing' => 'Phishing'] as $k => $v): ?>
      <option value="<?= $k ?>" <?= $verdict === $k ? 'selected' : '' ?>><?= $v ?></option><?php endforeach; ?>
  </select>
  <button class="btn" type="submit">Filter</button>
</form>

<?php if (!$rows): ?>
  <div class="card empty">No scans found.</div>
<?php else: ?>
<div class="table-wrap"><table class="table">
  <thead><tr><th>#</th><th>URL</th><th>Score</th><th>Verdict</th><th>User</th><th>Date</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($rows as $s): ?>
    <tr>
      <td class="mono small muted"><?= $s['id'] ?></td>
      <td class="url-cell" title="<?= e($s['url']) ?>"><?= e($s['url']) ?></td>
      <td><?= score_pill((int)$s['score']) ?></td>
      <td><?= verdict_badge($s['verdict']) ?></td>
      <td class="small"><?= e($s['full_name'] ?? 'Guest') ?></td>
      <td class="muted small"><?= e(date('M j, H:i', strtotime($s['created_at']))) ?></td>
      <td class="actions">
        <a class="btn btn-sm btn-ghost" href="<?= url('result.php?id=' . $s['id']) ?>">View</a>
        <?php if ($s['verdict'] !== 'safe'): ?>
        <form method="post" data-confirm="Blacklist <?= e($s['host']) ?>?"><?= csrf_field() ?>
          <input type="hidden" name="id" value="<?= $s['id'] ?>"><input type="hidden" name="action" value="blacklist">
          <button class="btn btn-sm btn-ghost" type="submit">Blacklist</button></form>
        <?php endif; ?>
        <form method="post" data-confirm="Delete this scan record?"><?= csrf_field() ?>
          <input type="hidden" name="id" value="<?= $s['id'] ?>"><input type="hidden" name="action" value="delete">
          <button class="btn btn-sm btn-ghost" type="submit">Delete</button></form>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table></div>
<?= paginate($total, $page, $per, array_filter(['q' => $q, 'verdict' => $verdict])) ?>
<?php endif; ?>
<?php require __DIR__ . '/../includes/footer.php'; ?>
