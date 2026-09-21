<?php
function e(?string $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function url(string $path = ''): string
{
    return BASE_URL . '/' . ltrim($path, '/');
}

function redirect(string $path): never
{
    header('Location: ' . url($path));
    exit;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . csrf_token() . '">';
}

function verify_csrf(): void
{
    $token = $_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($token) || !hash_equals(csrf_token(), $token)) {
        http_response_code(419);
        exit('Invalid or expired form token. Please go back and try again.');
    }
}

function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}

function take_flashes(): array
{
    $f = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $f;
}

function verdict_badge(string $verdict): string
{
    $labels = ['safe' => 'Safe', 'suspicious' => 'Suspicious', 'phishing' => 'Phishing'];
    return '<span class="badge badge-' . e($verdict) . '">' . e($labels[$verdict] ?? $verdict) . '</span>';
}

function time_ago(string $datetime): string
{
    $diff = time() - strtotime($datetime);
    if ($diff < 60)     return 'just now';
    if ($diff < 3600)   return floor($diff / 60) . ' min ago';
    if ($diff < 86400)  return floor($diff / 3600) . ' h ago';
    if ($diff < 604800) return floor($diff / 86400) . ' d ago';
    return date('M j, Y', strtotime($datetime));
}

function json_response(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

/** Store a completed scan and return its id. */
function save_scan(array $result, ?int $userId, string $source = 'web'): int
{
    $stmt = db()->prepare(
        'INSERT INTO scans (user_id, url, host, score, verdict, features, source, ip_address)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([
        $userId,
        mb_substr($result['url'], 0, 2048),
        mb_substr($result['host'], 0, 255),
        $result['score'],
        $result['verdict'],
        json_encode(['features' => $result['features'], 'list_match' => $result['list_match'],
                     'final_url' => $result['final_url'], 'duration_ms' => $result['duration_ms']]),
        $source,
        $_SERVER['REMOTE_ADDR'] ?? null,
    ]);
    return (int)db()->lastInsertId();
}

function rate_limited(): bool
{
    $now = time();
    $_SESSION['scan_times'] = array_filter($_SESSION['scan_times'] ?? [], fn($t) => $t > $now - 60);
    if (count($_SESSION['scan_times']) >= SCAN_RATE_LIMIT) {
        return true;
    }
    $_SESSION['scan_times'][] = $now;
    return false;
}

/** Aggregate scan statistics, optionally for one user. */
function scan_stats(?int $userId = null, int $days = 7): array
{
    $where = $userId ? 'WHERE user_id = ?' : '';
    $args = $userId ? [$userId] : [];

    $stmt = db()->prepare("SELECT COUNT(*) total, COALESCE(SUM(verdict='safe'),0) safe,
        COALESCE(SUM(verdict='suspicious'),0) suspicious, COALESCE(SUM(verdict='phishing'),0) phishing,
        COALESCE(ROUND(AVG(score)),0) avg_score FROM scans $where");
    $stmt->execute($args);
    $totals = array_map('intval', $stmt->fetch());

    $stmt = db()->prepare("SELECT DATE(created_at) d, verdict, COUNT(*) c FROM scans
        " . ($where ? "$where AND" : 'WHERE') . " created_at >= DATE_SUB(CURDATE(), INTERVAL " . ($days - 1) . " DAY)
        GROUP BY d, verdict");
    $stmt->execute($args);
    $series = [];
    for ($i = $days - 1; $i >= 0; $i--) {
        $d = date('Y-m-d', strtotime("-$i day"));
        $series[$d] = ['label' => date('D', strtotime($d)), 'safe' => 0, 'suspicious' => 0, 'phishing' => 0];
    }
    foreach ($stmt as $row) {
        if (isset($series[$row['d']])) $series[$row['d']][$row['verdict']] = (int)$row['c'];
    }

    $stmt = db()->prepare("SELECT host, COUNT(*) c, MAX(score) max_score FROM scans
        " . ($where ? "$where AND" : 'WHERE') . " verdict <> 'safe' GROUP BY host ORDER BY c DESC, max_score DESC LIMIT 6");
    $stmt->execute($args);
    $top = $stmt->fetchAll();

    return ['totals' => $totals, 'series' => array_values($series), 'top' => $top];
}

function score_pill(int $score): string
{
    $c = $score >= THRESHOLD_PHISHING ? 'var(--danger)' : ($score >= THRESHOLD_SUSPICIOUS ? 'var(--warn)' : 'var(--safe)');
    return '<span class="score-pill" style="--s:' . $score . ';--c:' . $c . '"><i></i>' . $score . '</span>';
}

function paginate(int $total, int $page, int $perPage, array $query = []): string
{
    $pages = (int)ceil($total / $perPage);
    if ($pages <= 1) return '';
    $html = '<nav class="pagination" aria-label="Pagination">';
    for ($p = max(1, $page - 3); $p <= min($pages, $page + 3); $p++) {
        $html .= $p === $page
            ? '<span class="current">' . $p . '</span>'
            : '<a href="?' . e(http_build_query($query + ['page' => $p])) . '">' . $p . '</a>';
    }
    return $html . '</nav>';
}
