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
        } elseif ($action === 'assign' && $report['status'] === 'pending') {
            $staff = (int)($_POST['assigned_to'] ?? 0);
            if ($staff) {
                $ok = db()->prepare("SELECT full_name FROM users WHERE id = ? AND role = 'user' AND is_active = 1");
                $ok->execute([$staff]);
                if ($name = $ok->fetchColumn()) {
                    // Re-assigning clears any earlier finding
                    db()->prepare('UPDATE reports SET assigned_to = ?, assigned_at = NOW(), analyst_verdict = NULL, analyst_note = NULL, analyst_at = NULL WHERE id = ?')
                        ->execute([$staff, $id]);
                    flash('success', "Report assigned to $name. It now appears on their dashboard.");
                }
            } else {
                db()->prepare('UPDATE reports SET assigned_to = NULL, assigned_at = NULL, analyst_verdict = NULL, analyst_note = NULL, analyst_at = NULL WHERE id = ?')->execute([$id]);
                flash('success', 'Assignment removed.');
            }
        }
    }
    redirect('admin/reports.php?status=' . urlencode($_GET['status'] ?? 'pending'));
}

$status = in_array($_GET['status'] ?? 'pending', ['pending', 'confirmed', 'rejected', 'all'], true) ? ($_GET['status'] ?? 'pending') : 'pending';
$sql = 'SELECT r.*, u.full_name, rv.full_name reviewer, a.full_name analyst, a.position analyst_position FROM reports r
        LEFT JOIN users u ON u.id = r.user_id LEFT JOIN users rv ON rv.id = r.reviewed_by LEFT JOIN users a ON a.id = r.assigned_to';
$stmt = $status === 'all' ? db()->query("$sql ORDER BY r.id DESC LIMIT 200")
                          : db()->prepare("$sql WHERE r.status = ? ORDER BY (r.analyst_verdict IS NOT NULL) DESC, r.id DESC LIMIT 200");
if ($status !== 'all') $stmt->execute([$status]);
$rows = $stmt->fetchAll();
$staff = db()->query("SELECT id, full_name, position FROM users WHERE role = 'user' AND is_active = 1 ORDER BY full_name")->fetchAll();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Community intelligence</span><h1>Phishing reports</h1>
  <p class="muted">Assign reports to staff for investigation. Confirming a report blacklists its domain immediately.</p></div></div>

<nav class="toolbar">
  <?php foreach (['pending' => 'Pending', 'confirmed' => 'Confirmed', 'rejected' => 'Rejected', 'all' => 'All'] as $k => $v): ?>
    <a class="btn btn-sm <?= $status === $k ? 'btn-outline' : 'btn-ghost' ?>" href="?status=<?= $k ?>"><?= $v ?></a>
  <?php endforeach; ?>
</nav>

<?php if (!$rows): ?>
  <div class="card empty">No <?= $status === 'all' ? '' : e($status) ?> reports.</div>
<?php endif; ?>

<div class="grid" style="gap:16px">
<?php foreach ($rows as $r): ?>
  <article class="card report-card">
    <div class="report-main">
      <div class="report-meta">
        <span class="badge badge-<?= e($r['status']) ?>"><?= e($r['status']) ?></span>
        <span class="small muted">#<?= $r['id'] ?> · <?= e(date('M j, Y', strtotime($r['created_at']))) ?> · by <?= e($r['full_name'] ?? $r['reporter'] ?? 'Anonymous') ?></span>
      </div>
      <h3 class="mono report-url"><?= e($r['url']) ?></h3>
      <?php if ($r['description']): ?><blockquote class="quote"><?= nl2br(e($r['description'])) ?></blockquote><?php endif; ?>

      <?php if ($r['analyst_verdict']): ?>
        <div class="finding finding-<?= $r['analyst_verdict'] ?>">
          <strong><?= e($r['analyst']) ?></strong><?= $r['analyst_position'] ? ' <span class="muted small">(' . e($r['analyst_position']) . ')</span>' : '' ?>
          recommends <span class="badge badge-<?= $r['analyst_verdict'] === 'phishing' ? 'phishing' : 'safe' ?>"><?= e($r['analyst_verdict']) ?></span>
          <span class="small muted"><?= e(time_ago($r['analyst_at'])) ?></span>
          <p><?= nl2br(e($r['analyst_note'])) ?></p>
        </div>
      <?php elseif ($r['analyst']): ?>
        <p class="small muted">Assigned to <strong><?= e($r['analyst']) ?></strong> <?= e(time_ago($r['assigned_at'])) ?> – awaiting their finding.</p>
      <?php endif; ?>
      <?php if ($r['reviewer']): ?><p class="small muted">Decision by <?= e($r['reviewer']) ?> · <?= e(time_ago($r['reviewed_at'])) ?></p><?php endif; ?>
    </div>

    <div class="report-actions">
      <a class="btn btn-sm btn-ghost" href="<?= url('admin/scan.php?url=' . urlencode($r['url'])) ?>">Scan URL</a>
      <?php if ($r['status'] === 'pending'): ?>
        <form method="post" class="assign-form"><?= csrf_field() ?>
          <input type="hidden" name="id" value="<?= $r['id'] ?>"><input type="hidden" name="action" value="assign">
          <label class="visually-hidden" for="as<?= $r['id'] ?>">Assign to</label>
          <select id="as<?= $r['id'] ?>" name="assigned_to">
            <option value="0">— Unassigned —</option>
            <?php foreach ($staff as $s): ?>
              <option value="<?= $s['id'] ?>" <?= (int)$r['assigned_to'] === (int)$s['id'] ? 'selected' : '' ?>><?= e($s['full_name']) ?><?= $s['position'] ? ' – ' . e($s['position']) : '' ?></option>
            <?php endforeach; ?>
          </select>
          <button class="btn btn-sm" type="submit">Assign</button>
        </form>
        <form method="post" class="decide-form"><?= csrf_field() ?><input type="hidden" name="id" value="<?= $r['id'] ?>">
          <button class="btn btn-sm btn-danger" name="action" value="confirm">Confirm phishing</button>
          <button class="btn btn-sm btn-ghost" name="action" value="reject">Reject</button>
        </form>
      <?php endif; ?>
    </div>
  </article>
<?php endforeach; ?>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
