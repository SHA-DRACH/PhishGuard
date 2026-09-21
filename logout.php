<?php
require_once __DIR__ . '/includes/bootstrap.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') redirect('index.php');
verify_csrf();
$_SESSION = [];
session_regenerate_id(true);
flash('success', 'You have been signed out.');
redirect('login.php');
