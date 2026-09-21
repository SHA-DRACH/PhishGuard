<?php
require_once __DIR__ . '/../includes/bootstrap.php';
$admin = require_admin();
$pageTitle = 'Users';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $id = (int)($_POST['id'] ?? 0);
    $action = $_POST['action'] ?? '';
    if ($action === 'create') {
        $name = trim($_POST['full_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $pass = $_POST['password'] ?? '';
        $role = ($_POST['role'] ?? '') === 'admin' ? 'admin' : 'user';
        $position = trim($_POST['position'] ?? '');
        $duties = trim($_POST['responsibilities'] ?? '');
        $exists = db()->prepare('SELECT 1 FROM users WHERE email = ?');
        $exists->execute([$email]);
        if (mb_strlen($name) < 3 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($pass) < 8) {
            flash('error', 'Enter a name, a valid email and a temporary password of at least 8 characters.');
        } elseif ($exists->fetch()) {
            flash('error', 'That email is already registered.');
        } else {
            db()->prepare('INSERT INTO users (full_name, email, password_hash, role, department, position, responsibilities, must_change_password, created_by)
                           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)')
                ->execute([$name, $email, password_hash($pass, PASSWORD_DEFAULT), $role, trim($_POST['department'] ?? '') ?: null,
                           $position ?: null, $duties ?: null, $admin['id']]);
            flash('success', "Account created for $email. They will be asked to set a new password at first sign-in.");
        }
    } elseif ($id === (int)$admin['id']) {
        flash('error', 'You cannot change your own role or status here.');
    } elseif ($action === 'toggle_active') {
        db()->prepare('UPDATE users SET is_active = 1 - is_active WHERE id = ?')->execute([$id]);
        flash('success', 'Account status updated.');
    }
    redirect('admin/users.php');
}

$users = db()->query("SELECT u.*,
        (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) scans,
        (SELECT COUNT(*) FROM reports r WHERE r.assigned_to = u.id AND r.status = 'pending' AND r.analyst_verdict IS NULL) open_tasks
    FROM users u ORDER BY u.id DESC")->fetchAll();
$presets = position_presets();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Access control</span><h1>Users</h1><p class="muted"><?= count($users) ?> accounts</p></div></div>

<details class="card" style="margin-bottom:20px" <?= empty($users) || count($users) < 2 ? 'open' : '' ?>>
  <summary style="cursor:pointer;font-weight:600">+ Add a staff member</summary>
  <form method="post" style="margin-top:16px">
    <?= csrf_field() ?><input type="hidden" name="action" value="create">
    <div class="form-row">
      <div class="field"><label for="n">Full name</label><input id="n" name="full_name" type="text" required></div>
      <div class="field"><label for="em">Email</label><input id="em" name="email" type="email" required></div>
      <div class="field"><label for="dp">Department</label><input id="dp" name="department" type="text" placeholder="e.g. ICT, Customer Care"></div>
    </div>
    <div class="form-row">
      <div class="field"><label for="pos">Position</label>
        <input id="pos" name="position" type="text" list="position-list" placeholder="Choose or type a position" data-duties-target="#duties">
        <datalist id="position-list"><?php foreach (array_keys($presets) as $p): ?><option value="<?= e($p) ?>"><?php endforeach; ?></datalist></div>
      <div class="field"><label for="rl">System role</label>
        <select id="rl" name="role"><option value="user">User – personal dashboard</option><option value="admin">Administrator – admin console</option></select></div>
      <div class="field"><label for="pw">Temporary password</label><input id="pw" name="password" type="text" minlength="8" required autocomplete="off"></div>
    </div>
    <div class="field"><label for="duties">Responsibilities <span class="muted">(one per line – shown on the user's dashboard)</span></label>
      <textarea id="duties" name="responsibilities" rows="4" placeholder="Pick a position to pre-fill standard responsibilities"></textarea></div>
    <button class="btn btn-primary" type="submit">Create account</button>
  </form>
</details>
<script type="application/json" id="position-presets"><?= json_encode($presets, JSON_HEX_TAG) ?></script>

<div class="table-wrap"><table class="table">
  <thead><tr><th>Name</th><th>Position</th><th>Role</th><th>Scans</th><th>Open tasks</th><th>Last login</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($users as $u): ?>
    <tr style="<?= $u['is_active'] ? '' : 'opacity:.55' ?>">
      <td><strong><?= e($u['full_name']) ?></strong><?= $u['is_active'] ? '' : ' <small class="muted">(disabled)</small>' ?><br><small class="muted"><?= e($u['email']) ?></small></td>
      <td class="small"><?= e($u['position'] ?? '—') ?><?= $u['department'] ? '<br><small class="muted">' . e($u['department']) . '</small>' : '' ?></td>
      <td><span class="badge badge-<?= e($u['role']) ?>"><?= e($u['role']) ?></span></td>
      <td class="mono small"><?= (int)$u['scans'] ?></td>
      <td class="mono small"><?= (int)$u['open_tasks'] ?></td>
      <td class="small muted"><?= $u['last_login'] ? e(time_ago($u['last_login'])) : ($u['must_change_password'] ? 'awaiting first sign-in' : 'never') ?></td>
      <td class="actions">
        <a class="btn btn-sm btn-ghost" href="user_edit.php?id=<?= $u['id'] ?>">Edit</a>
        <?php if ((int)$u['id'] !== (int)$admin['id']): ?>
        <form method="post"><?= csrf_field() ?><input type="hidden" name="id" value="<?= $u['id'] ?>">
          <button class="btn btn-sm btn-ghost" name="action" value="toggle_active"><?= $u['is_active'] ? 'Disable' : 'Enable' ?></button></form>
        <?php endif; ?>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table></div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
