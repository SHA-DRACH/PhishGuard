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
        $exists = db()->prepare('SELECT 1 FROM users WHERE email = ?');
        $exists->execute([$email]);
        if (mb_strlen($name) < 3 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($pass) < 8) {
            flash('error', 'Enter a name, a valid email and a password of at least 8 characters.');
        } elseif ($exists->fetch()) {
            flash('error', 'That email is already registered.');
        } else {
            db()->prepare('INSERT INTO users (full_name, email, password_hash, role, department) VALUES (?, ?, ?, ?, ?)')
                ->execute([$name, $email, password_hash($pass, PASSWORD_DEFAULT), $role, trim($_POST['department'] ?? '') ?: null]);
            flash('success', "Account created for $email.");
        }
    } elseif ($id === (int)$admin['id']) {
        flash('error', 'You cannot change your own role or status here.');
    } elseif ($action === 'toggle_role') {
        db()->prepare("UPDATE users SET role = IF(role = 'admin', 'user', 'admin') WHERE id = ?")->execute([$id]);
        flash('success', 'Role updated.');
    } elseif ($action === 'toggle_active') {
        db()->prepare('UPDATE users SET is_active = 1 - is_active WHERE id = ?')->execute([$id]);
        flash('success', 'Account status updated.');
    }
    redirect('admin/users.php');
}

$users = db()->query('SELECT u.*, (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) scans FROM users u ORDER BY u.id DESC')->fetchAll();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Access control</span><h1>Users</h1><p class="muted"><?= count($users) ?> accounts</p></div></div>

<details class="card" style="margin-bottom:20px">
  <summary style="cursor:pointer;font-weight:600">+ Add a user</summary>
  <form method="post" class="form-row" style="margin-top:16px">
    <?= csrf_field() ?><input type="hidden" name="action" value="create">
    <div class="field"><label>Full name</label><input name="full_name" type="text" required></div>
    <div class="field"><label>Email</label><input name="email" type="email" required></div>
    <div class="field"><label>Department</label><input name="department" type="text"></div>
    <div class="field"><label>Temporary password</label><input name="password" type="password" minlength="8" required autocomplete="new-password"></div>
    <div class="field"><label>Role</label><select name="role"><option value="user">User</option><option value="admin">Administrator</option></select></div>
    <div class="field"><button class="btn btn-primary" type="submit">Create</button></div>
  </form>
</details>

<div class="table-wrap"><table class="table">
  <thead><tr><th>Name</th><th>Email</th><th>Department</th><th>Role</th><th>Scans</th><th>Last login</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($users as $u): ?>
    <tr style="<?= $u['is_active'] ? '' : 'opacity:.5' ?>">
      <td><strong><?= e($u['full_name']) ?></strong><?= $u['is_active'] ? '' : ' <small class="muted">(disabled)</small>' ?></td>
      <td class="small"><?= e($u['email']) ?></td>
      <td class="small muted"><?= e($u['department'] ?? '—') ?></td>
      <td><span class="badge badge-<?= e($u['role']) ?>"><?= e($u['role']) ?></span></td>
      <td class="mono small"><?= (int)$u['scans'] ?></td>
      <td class="small muted"><?= $u['last_login'] ? e(time_ago($u['last_login'])) : 'never' ?></td>
      <td class="actions">
        <?php if ((int)$u['id'] !== (int)$admin['id']): ?>
        <form method="post"><?= csrf_field() ?><input type="hidden" name="id" value="<?= $u['id'] ?>">
          <button class="btn btn-sm btn-ghost" name="action" value="toggle_role"><?= $u['role'] === 'admin' ? 'Make user' : 'Make admin' ?></button>
          <button class="btn btn-sm btn-ghost" name="action" value="toggle_active"><?= $u['is_active'] ? 'Disable' : 'Enable' ?></button>
        </form>
        <?php else: ?><span class="muted small">you</span><?php endif; ?>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table></div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
