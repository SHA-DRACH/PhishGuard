<?php
require_once __DIR__ . '/includes/bootstrap.php';
if (current_user()) redirect('dashboard.php');

$email = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // Basic brute-force throttle per session
    $_SESSION['login_fails'] ??= 0;
    $lockMinutes = setting('login_lock_minutes');
    if ($_SESSION['login_fails'] >= setting('login_max_attempts') && time() - ($_SESSION['login_last'] ?? 0) < $lockMinutes * 60) {
        flash('error', "Too many failed attempts. Please wait $lockMinutes minute" . ($lockMinutes === 1 ? '' : 's') . ' and try again.');
    } else {
        $stmt = db()->prepare('SELECT * FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if ($user && password_verify($password, $user['password_hash'])) {
            if (!$user['is_active']) {
                flash('error', 'Your account has been deactivated. Contact the administrator.');
            } else {
                $_SESSION['login_fails'] = 0;
                login_user($user);
                redirect($user['role'] === 'admin' ? 'admin/index.php' : 'dashboard.php');
            }
        } else {
            $_SESSION['login_fails']++;
            $_SESSION['login_last'] = time();
            flash('error', 'Incorrect email or password.');
        }
    }
}

$pageTitle = 'Sign in';
ob_start(); ?>
<h1>Welcome back</h1>
<p class="muted">Sign in to view your scan history and dashboard.</p>
<form method="post" novalidate>
  <?= csrf_field() ?>
  <div class="field"><label for="email">Email address</label>
    <input id="email" name="email" type="email" value="<?= e($email) ?>" required autofocus autocomplete="username"></div>
  <div class="field"><label for="password">Password</label>
    <input id="password" name="password" type="password" required autocomplete="current-password"></div>
  <button class="btn btn-primary btn-block" type="submit">Sign in</button>
</form>
<p class="muted small" style="margin-top:20px"><?php if (setting('allow_registration')): ?>No account yet? <a href="<?= url('register.php') ?>">Create one</a><?php endif; ?><?php if (setting('allow_registration') && setting('allow_guest_scan')): ?> &middot; <?php endif; ?><?php if (setting('allow_guest_scan')): ?><a href="<?= url('index.php') ?>">Scan without signing in</a><?php endif; ?></p>
<?php $formHtml = ob_get_clean();
require __DIR__ . '/includes/auth_layout.php';
