<?php
function current_user(): ?array
{
    static $user = false;
    if ($user === false) {
        $user = null;
        if (!empty($_SESSION['user_id'])) {
            $stmt = db()->prepare('SELECT id, full_name, email, role, department FROM users WHERE id = ? AND is_active = 1');
            $stmt->execute([$_SESSION['user_id']]);
            $user = $stmt->fetch() ?: null;
            if (!$user) {
                unset($_SESSION['user_id']);
            }
        }
    }
    return $user;
}

function is_admin(): bool
{
    return (current_user()['role'] ?? '') === 'admin';
}

function require_login(): array
{
    $user = current_user();
    if (!$user) {
        flash('warning', 'Please sign in to continue.');
        redirect('login.php');
    }
    return $user;
}

function require_admin(): array
{
    $user = require_login();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        exit('Access denied. Administrator role required.');
    }
    return $user;
}

function login_user(array $user): void
{
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$user['id'];
    db()->prepare('UPDATE users SET last_login = NOW() WHERE id = ?')->execute([$user['id']]);
}
