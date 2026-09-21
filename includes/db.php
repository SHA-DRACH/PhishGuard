<?php
function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', DB_HOST, DB_PORT, DB_NAME);
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
            $pdo->exec("SET time_zone = '" . date('P') . "'"); // keep MySQL dates in sync with PHP
        } catch (PDOException $e) {
            http_response_code(500);
            $install = BASE_URL . '/install.php';
            exit("<p style='font-family:sans-serif'>Database connection failed. "
               . "Make sure MySQL is running in XAMPP and run the <a href='$install'>installer</a>.</p>");
        }
    }
    return $pdo;
}
