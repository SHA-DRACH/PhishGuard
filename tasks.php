<?php
/** Investigations assigned to the signed-in staff member by an administrator. */
require_once __DIR__ . '/includes/bootstrap.php';
$user = require_login();
if ($user['role'] === 'admin') redirect('admin/reports.php');
$pageTitle = 'My tasks';
$layout = 'auto';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $verdict = in_array($_POST['verdict'] ?? '', ['phishing', 'legitimate'], true) ? $_POST['verdict'] : null;
    $note = trim($_POST['note'] ?? '');
    if (!$verdict || mb_strlen($note) < 5) {
        flash('error', 'Choose a finding and write a short note explaining it.');
    } else {
        $stmt = db()->prepare("UPDATE reports SET analyst_verdict = ?, analyst_note = ?, analyst_at = NOW()
                               WHERE id = ? AND assigned_to = ? AND status = 'pending'");
        $stmt->execute([$verdict, mb_substr($note, 0, 2000), (int)$_POST['id'], $user['id']]);
        flash($stmt->rowCount() ? 'success' : 'error',
              $stmt->rowCount() ? 'Finding submitted. An administrator will make the final decision.' : 'This task is no longer open.');
    }
    redirect('tasks.php');
}

$stmt = db()->prepare("SELECT r.*, u.full_name reporter_name FROM reports r LEFT JOIN users u ON u.id = r.user_id
                       WHERE r.assigned_to = ? ORDER BY (r.status = 'pending' AND r.analyst_verdict IS NULL) DESC, r.assigned_at DESC");
$stmt->execute([$user['id']]);
$tasks = $stmt->fetchAll();
$open = array_filter($tasks, fn($t) => $t['status'] === 'pending' && $t['analyst_verdict'] === null);
$done = array_filter($tasks, fn($t) => !($t['status'] === 'pending' && $t['analyst_verdict'] === null));

require __DIR__ . '/includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Assigned investigations</span><h1>My tasks</h1>
  <p class="muted">Reported sites the security team asked you to investigate. Scan each one, then submit your finding.</p></div></div>

<?php if (!$open): ?>
  <div class="card empty">No open tasks – you're all caught up.</div>
<?php endif; ?>

<div class="grid" style="gap:16px">
<?php foreach ($open as $t): ?>
  <article class="card task-card" id="t<?= $t['id'] ?>">
    <div class="card-head">
      <div style="min-width:0">
        <span class="badge badge-pending">Open</span>
        <h3 class="mono" style="margin:8px 0 0;word-break:break-all;font-size:.95rem"><?= e($t['url']) ?></h3>
      </div>
      <a class="btn btn-sm btn-outline" href="<?= url('scan.php?url=' . urlencode($t['url'])) ?>">Scan this URL</a>
    </div>
    <p class="small muted">Assigned <?= e(time_ago($t['assigned_at'])) ?> · reported by <?= e($t['reporter_name'] ?? $t['reporter'] ?? 'anonymous user') ?></p>
    <?php if ($t['description']): ?><blockquote class="quote"><?= nl2br(e($t['description'])) ?></blockquote><?php endif; ?>
    <form method="post" class="task-form">
      <?= csrf_field() ?><input type="hidden" name="id" value="<?= $t['id'] ?>">
      <fieldset class="choice">
        <legend class="small muted">Your finding</legend>
        <label><input type="radio" name="verdict" value="phishing" required> <span class="badge badge-phishing">Phishing</span></label>
        <label><input type="radio" name="verdict" value="legitimate"> <span class="badge badge-safe">Legitimate</span></label>
      </fieldset>
      <div class="field"><label for="note<?= $t['id'] ?>">Investigation note</label>
        <textarea id="note<?= $t['id'] ?>" name="note" rows="3" required placeholder="e.g. Domain imitates libtelco.com.lr, registered last week, login form posts to a foreign server."></textarea></div>
      <button class="btn btn-primary" type="submit">Submit finding</button>
    </form>
  </article>
<?php endforeach; ?>
</div>

<?php if ($done): ?>
<section class="card" style="margin-top:24px">
  <h3>Completed</h3>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>URL</th><th>Your finding</th><th>Final decision</th><th>Submitted</th></tr></thead>
    <tbody>
    <?php foreach ($done as $t): ?>
      <tr>
        <td class="url-cell" title="<?= e($t['url']) ?>"><?= e($t['url']) ?></td>
        <td><?= $t['analyst_verdict'] ? '<span class="badge badge-' . ($t['analyst_verdict'] === 'phishing' ? 'phishing' : 'safe') . '">' . e($t['analyst_verdict']) . '</span>' : '<span class="muted small">—</span>' ?></td>
        <td><span class="badge badge-<?= e($t['status']) ?>"><?= e($t['status']) ?></span></td>
        <td class="small muted"><?= $t['analyst_at'] ? e(time_ago($t['analyst_at'])) : '—' ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
</section>
<?php endif; ?>
<?php require __DIR__ . '/includes/footer.php'; ?>
