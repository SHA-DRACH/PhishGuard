<?php
/** Shared profile page. Expects $user (current user) and $selfPath (this page path). */
$pageTitle = 'Profile & security';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    if (($_POST['action'] ?? '') === 'profile') {
        $name = trim($_POST['full_name'] ?? '');
        $dept = trim($_POST['department'] ?? '');
        if (mb_strlen($name) < 3) {
            flash('error', 'Please enter your full name.');
        } else {
            db()->prepare('UPDATE users SET full_name = ?, department = ? WHERE id = ?')->execute([$name, $dept ?: null, $user['id']]);
            flash('success', 'Profile updated.');
        }
    } else {
        $stmt = db()->prepare('SELECT password_hash FROM users WHERE id = ?');
        $stmt->execute([$user['id']]);
        $new = $_POST['new_password'] ?? '';
        if (!password_verify($_POST['current_password'] ?? '', $stmt->fetchColumn())) {
            flash('error', 'Your current password is incorrect.');
        } elseif (strlen($new) < 8 || !preg_match('/[A-Za-z]/', $new) || !preg_match('/\d/', $new)) {
            flash('error', 'New password must be at least 8 characters and contain letters and numbers.');
        } elseif ($new !== ($_POST['new_password_confirm'] ?? '')) {
            flash('error', 'New passwords do not match.');
        } else {
            db()->prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?')->execute([password_hash($new, PASSWORD_DEFAULT), $user['id']]);
            flash('success', 'Password changed successfully.');
            if ($user['must_change_password']) {
                redirect($user['role'] === 'admin' ? 'admin/index.php' : 'dashboard.php');
            }
        }
    }
    redirect($selfPath);
}

require __DIR__ . '/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Account</span><h1>Profile &amp; security</h1></div></div>
<div class="grid grid-2">
  <form class="card" method="post">
    <?= csrf_field() ?><input type="hidden" name="action" value="profile">
    <h3>Personal details</h3>
    <div class="field"><label for="full_name">Full name</label><input id="full_name" name="full_name" type="text" value="<?= e($user['full_name']) ?>" required></div>
    <div class="field"><label>Email</label><input type="email" value="<?= e($user['email']) ?>" disabled></div>
    <?php if (!empty($user['position'])): ?><div class="field"><label>Position</label><input type="text" value="<?= e($user['position']) ?>" disabled></div><?php endif; ?>
    <div class="field"><label for="department">Department / organisation</label><input id="department" name="department" type="text" value="<?= e($user['department']) ?>"></div>
    <button class="btn btn-primary" type="submit">Save changes</button>
  </form>
  <form class="card<?= $user['must_change_password'] ? ' card-attention' : '' ?>" method="post" id="password">
    <?= csrf_field() ?><input type="hidden" name="action" value="password">
    <h3>Change password</h3>
    <div class="field"><label for="cp">Current password</label><input id="cp" name="current_password" type="password" required autocomplete="current-password"></div>
    <div class="field"><label for="np">New password</label><input id="np" name="new_password" type="password" required autocomplete="new-password"></div>
    <div class="field"><label for="np2">Confirm new password</label><input id="np2" name="new_password_confirm" type="password" required autocomplete="new-password"></div>
    <button class="btn btn-primary" type="submit">Update password</button>
  </form>
</div>
<?php require __DIR__ . '/footer.php'; ?>
