<?php
require_once __DIR__ . '/../includes/bootstrap.php';
$admin = require_admin();
$pageTitle = 'User reports';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $id = (int)($_POST['id'] ?? 0);
    $action = $_POST['action'] ?? '';
    $stmt = db()->prepare('SELECT * FROM reports WHERE id = ?');
    $stmt->execute([$id]);
    if ($report = $stmt->fetch()) {
        if ($action === 'confirm') {
            $host = strtolower(parse_url($report['url'], PHP_URL_HOST) ?? '');
            if ($host) {
                db()->prepare('INSERT IGNORE INTO blacklist (domain, reason, added_by) VALUES (?, ?, ?)')
                    ->execute([$host, "Confirmed from user report #$id", $admin['id']]);
            }
            db()->prepare("UPDATE reports SET status = 'confirmed', reviewed_by = ?, reviewed_at = NOW() WHERE id = ?")->execute([$admin['id'], $id]);
            flash('success', "Report confirmed – $host is now blacklisted.");
        } elseif ($action === 'reject') {
            db()->prepare("UPDATE reports SET status = 'rejected', reviewed_by = ?, reviewed_at = NOW() WHERE id = ?")->execute([$admin['id'], $id]);
            flash('success', 'Report rejected.');
        }
    }
    redirect('admin/reports.php?status=' . urlencode($_GET['status'] ?? 'pending'));
}

$status = in_array($_GET['status'] ?? 'pending', ['pending', 'confirmed', 'rejected', 'all'], true) ? ($_GET['status'] ?? 'pending') : 'pending';
$sql = 'SELECT r.*, u.full_name, rv.full_name reviewer FROM reports r
        LEFT JOIN users u ON u.id = r.user_id LEFT JOIN users rv ON rv.id = r.reviewed_by';
$stmt = $status === 'all' ? db()->query("$sql ORDER BY r.id DESC LIMIT 200")
                          : db()->prepare("$sql WHERE r.status = ? ORDER BY r.id DESC LIMIT 200");
if ($status !== 'all') $stmt->execute([$status]);
$rows = $stmt->fetchAll();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Community intelligence</span><h1>Phishing reports</h1>
  <p class="muted">Confirming a report adds its domain to the blacklist immediately.</p></div></div>

<nav class="toolbar">
  <?php foreach (['pending' => 'Pending', 'confirmed' => 'Confirmed', 'rejected' => 'Rejected', 'all' => 'All'] as $k => $v): ?>
    <a class="btn btn-sm <?= $status === $k ? 'btn-outline' : 'btn-ghost' ?>" href="?status=<?= $k ?>"><?= $v ?></a>
  <?php endforeach; ?>
</nav>

<?php if (!$rows): ?>
  <div class="card empty">No <?= $status === 'all' ? '' : e($status) ?> reports.</div>
<?php else: ?>
<div class="table-wrap"><table class="table">
  <thead><tr><th>URL</th><th>Details</th><th>Reporter</th><th>Status</th><th>Date</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($rows as $r): ?>
    <tr>
      <td class="url-cell" title="<?= e($r['url']) ?>"><?= e($r['url']) ?></td>
      <td class="small muted" style="max-width:280px"><?= e(mb_strimwidth((string)$r['description'], 0, 140, '…')) ?: '—' ?></td>
      <td class="small"><?= e($r['full_name'] ?? $r['reporter'] ?? 'Anonymous') ?></td>
      <td><span class="badge badge-<?= e($r['status']) ?>"><?= e($r['status']) ?></span>
        <?php if ($r['reviewer']): ?><br><small class="muted">by <?= e($r['reviewer']) ?></small><?php endif; ?></td>
      <td class="muted small"><?= e(date('M j, Y', strtotime($r['created_at']))) ?></td>
      <td class="actions">
        <a class="btn btn-sm btn-ghost" href="<?= url('index.php?url=' . urlencode($r['url'])) ?>" target="_blank" rel="noopener">Scan</a>
        <?php if ($r['status'] === 'pending'): ?>
          <form method="post"><?= csrf_field() ?><input type="hidden" name="id" value="<?= $r['id'] ?>">
            <button class="btn btn-sm btn-danger" name="action" value="confirm">Confirm</button>
            <button class="btn btn-sm btn-ghost" name="action" value="reject">Reject</button></form>
        <?php endif; ?>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table></div>
<?php endif; ?>
<?php require __DIR__ . '/../includes/footer.php'; ?>
