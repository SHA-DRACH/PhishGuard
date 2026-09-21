<?php
require_once __DIR__ . '/includes/bootstrap.php';
if (current_user()) redirect('dashboard.php');

$old = ['full_name' => '', 'email' => '', 'department' => ''];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $old = array_map(fn($v) => trim((string)$v), array_intersect_key($_POST, $old)) + $old;
    $password = $_POST['password'] ?? '';
    $errors = [];

    if (mb_strlen($old['full_name']) < 3) $errors[] = 'Please enter your full name.';
    if (!filter_var($old['email'], FILTER_VALIDATE_EMAIL)) $errors[] = 'Please enter a valid email address.';
    if (strlen($password) < 8 || !preg_match('/[A-Za-z]/', $password) || !preg_match('/\d/', $password)) {
        $errors[] = 'Password must be at least 8 characters and contain letters and numbers.';
    }
    if ($password !== ($_POST['password_confirm'] ?? '')) $errors[] = 'Passwords do not match.';

    if (!$errors) {
        $stmt = db()->prepare('SELECT 1 FROM users WHERE email = ?');
        $stmt->execute([$old['email']]);
        if ($stmt->fetch()) $errors[] = 'An account with this email already exists.';
    }

    if ($errors) {
        foreach ($errors as $err) flash('error', $err);
    } else {
        db()->prepare('INSERT INTO users (full_name, email, password_hash, department) VALUES (?, ?, ?, ?)')
            ->execute([$old['full_name'], $old['email'], password_hash($password, PASSWORD_DEFAULT), $old['department'] ?: null]);
        login_user(['id' => db()->lastInsertId()]);
        flash('success', 'Welcome to ' . APP_NAME . '! Your account has been created.');
        redirect('dashboard.php');
    }
}

$pageTitle = 'Create account';
ob_start(); ?>
<h1>Create your account</h1>
<p class="muted">Keep a history of your scans and report suspicious sites.</p>
<form method="post" novalidate>
  <?= csrf_field() ?>
  <div class="field"><label for="full_name">Full name</label>
    <input id="full_name" name="full_name" type="text" value="<?= e($old['full_name']) ?>" required autocomplete="name"></div>
  <div class="field"><label for="email">Email address</label>
    <input id="email" name="email" type="email" value="<?= e($old['email']) ?>" required autocomplete="email"></div>
  <div class="field"><label for="department">Department / organisation <span class="muted">(optional)</span></label>
    <input id="department" name="department" type="text" value="<?= e($old['department']) ?>" placeholder="e.g. Customer Care, or LTC customer"></div>
  <div class="form-row">
    <div class="field"><label for="password">Password</label>
      <input id="password" name="password" type="password" required minlength="8" autocomplete="new-password"></div>
    <div class="field"><label for="password_confirm">Confirm password</label>
      <input id="password_confirm" name="password_confirm" type="password" required autocomplete="new-password"></div>
  </div>
  <button class="btn btn-primary btn-block" type="submit">Create account</button>
</form>
<p class="muted small" style="margin-top:20px">Already registered? <a href="<?= url('login.php') ?>">Sign in</a></p>
<?php $formHtml = ob_get_clean();
require __DIR__ . '/includes/auth_layout.php';
