<?php
require_once __DIR__ . '/../includes/bootstrap.php';
$admin = require_admin();
$pageTitle = 'Edit user';

$id = (int)($_GET['id'] ?? 0);
$stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
$u = $stmt->fetch();
if (!$u) {
    flash('error', 'User not found.');
    redirect('admin/users.php');
}
$isSelf = (int)$u['id'] === (int)$admin['id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $name = trim($_POST['full_name'] ?? '');
    if (mb_strlen($name) < 3) {
        flash('error', 'Please enter the full name.');
    } else {
        $role = $isSelf ? $u['role'] : (($_POST['role'] ?? '') === 'admin' ? 'admin' : 'user');
        db()->prepare('UPDATE users SET full_name = ?, department = ?, position = ?, responsibilities = ?, role = ? WHERE id = ?')
            ->execute([$name, trim($_POST['department'] ?? '') ?: null, trim($_POST['position'] ?? '') ?: null,
                       trim($_POST['responsibilities'] ?? '') ?: null, $role, $id]);
        $newPass = $_POST['new_password'] ?? '';
        if ($newPass !== '' && !$isSelf) {
            if (strlen($newPass) < setting('password_min_length')) {
                flash('error', 'Temporary password must be at least ' . setting('password_min_length') . ' characters – password not changed.');
            } else {
                db()->prepare('UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?')
                    ->execute([password_hash($newPass, PASSWORD_DEFAULT), $id]);
                flash('success', 'Temporary password set. The user must change it at next sign-in.');
            }
        }
        flash('success', 'User details saved.');
        redirect('admin/users.php');
    }
}

$presets = position_presets();
require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Access control</span><h1><?= e($u['full_name']) ?></h1>
  <p class="muted"><?= e($u['email']) ?> · joined <?= e(date('M j, Y', strtotime($u['created_at']))) ?></p></div>
  <a class="btn btn-ghost" href="users.php">← Back to users</a></div>

<form class="card" method="post">
  <?= csrf_field() ?>
  <div class="form-row">
    <div class="field"><label for="n">Full name</label><input id="n" name="full_name" type="text" value="<?= e($u['full_name']) ?>" required></div>
    <div class="field"><label for="dp">Department</label><input id="dp" name="department" type="text" value="<?= e($u['department']) ?>"></div>
    <div class="field"><label for="pos">Position</label>
      <input id="pos" name="position" type="text" list="position-list" value="<?= e($u['position']) ?>" data-duties-target="#duties">
      <datalist id="position-list"><?php foreach (array_keys($presets) as $p): ?><option value="<?= e($p) ?>"><?php endforeach; ?></datalist></div>
    <div class="field"><label for="rl">System role</label>
      <select id="rl" name="role" <?= $isSelf ? 'disabled' : '' ?>>
        <option value="user" <?= $u['role'] === 'user' ? 'selected' : '' ?>>User – personal dashboard</option>
        <option value="admin" <?= $u['role'] === 'admin' ? 'selected' : '' ?>>Administrator – admin console</option>
      </select></div>
  </div>
  <div class="field"><label for="duties">Responsibilities <span class="muted">(one per line – shown on the user's dashboard)</span></label>
    <textarea id="duties" name="responsibilities" rows="5"><?= e($u['responsibilities']) ?></textarea></div>
  <?php if (!$isSelf): ?>
  <div class="field" style="max-width:360px"><label for="np">Reset password <span class="muted">(optional temporary password)</span></label>
    <input id="np" name="new_password" type="text" minlength="8" autocomplete="off"></div>
  <?php endif; ?>
  <button class="btn btn-primary" type="submit">Save changes</button>
</form>
<script type="application/json" id="position-presets"><?= json_encode($presets, JSON_HEX_TAG) ?></script>
<?php require __DIR__ . '/../includes/footer.php'; ?>
