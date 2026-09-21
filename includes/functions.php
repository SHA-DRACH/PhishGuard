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
        http_response_code(403);
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
                     'domain_info' => $result['domain_info'] ?? null, 'deep' => $result['deep'] ?? false,
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

/** Inline stroke icon (24x24 grid). */
function icon(string $name): string
{
    static $paths = [
        'grid'    => '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        'scan'    => '<path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="11" cy="11" r="4"/><path d="m14 14 3 3"/>',
        'list'    => '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="3.5" cy="6" r="1"/><circle cx="3.5" cy="12" r="1"/><circle cx="3.5" cy="18" r="1"/>',
        'flag'    => '<path d="M4 22V4a1 1 0 0 1 1-1h11l-2 4 2 4H5"/>',
        'shield'  => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
        'chart'   => '<path d="M3 3v18h18"/><path d="m7 14 4-4 3 3 5-6"/>',
        'users'   => '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
        'user'    => '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
        'logout'  => '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
        'menu'    => '<path d="M3 6h18M3 12h18M3 18h18"/>',
        'close'   => '<path d="M18 6 6 18M6 6l12 12"/>',
        'sidebar' => '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 9l-3 3 3 3"/>',
        'check'   => '<path d="M9 11l3 3 8-8"/><path d="M20 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
        'settings'=> '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
        'theme'   => '<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor"/>',
    ];
    return '<svg class="icon" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
         . ($paths[$name] ?? '') . '</svg>';
}

/** Standard LTC positions and their default responsibilities (admins may edit per user). */
function position_presets(): array
{
    return parse_positions((string)setting('positions'));
}

/** Responsibilities shown on a user's dashboard. */
function user_responsibilities(array $user): array
{
    $lines = array_values(array_filter(array_map('trim', preg_split('/\R/', (string)($user['responsibilities'] ?? '')))));
    if ($lines) return $lines;
    return position_presets()[$user['position'] ?? ''] ?? [
        'Scan unfamiliar links before opening them or entering any details',
        'Report suspicious websites, emails and SMS links you receive',
        'Learn the warning signs on the Awareness page',
    ];
}

/** Open (pending, not yet answered) investigations assigned to a user. */
function open_task_count(int $userId): int
{
    $stmt = db()->prepare("SELECT COUNT(*) FROM reports WHERE assigned_to = ? AND status = 'pending' AND analyst_verdict IS NULL");
    $stmt->execute([$userId]);
    return (int)$stmt->fetchColumn();
}
