<?php
require_once __DIR__ . '/includes/bootstrap.php';
$user = require_login();
if ($user['role'] === 'admin') redirect('admin/profile.php');
$layout = 'auto';
$selfPath = 'profile.php';
require __DIR__ . '/includes/profile_page.php';
