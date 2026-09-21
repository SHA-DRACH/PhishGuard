<?php
require_once __DIR__ . '/includes/bootstrap.php';
$pageTitle = 'Scan result';
$layout = 'auto';

$id = (int)($_GET['id'] ?? 0);
$stmt = db()->prepare('SELECT s.*, u.full_name FROM scans s LEFT JOIN users u ON u.id = s.user_id WHERE s.id = ?');
$stmt->execute([$id]);
$scan = $stmt->fetch();

// Guests may view anonymous scans; signed-in users their own; admins everything.
$user = current_user();
$allowed = $scan && ($scan['user_id'] === null || ($user && ((int)$scan['user_id'] === (int)$user['id'] || $user['role'] === 'admin')));

require __DIR__ . '/includes/header.php';
if (!$allowed): ?>
  <div class="card empty"><h2>Scan not found</h2><p>This result does not exist or you don't have access to it.</p>
    <a class="btn btn-primary" href="<?= url($user ? ($user['role'] === 'admin' ? 'admin/scan.php' : 'scan.php') : 'index.php') ?>">Scan a website</a></div>
<?php else:
  $data = json_decode($scan['features'] ?? '{}', true) ?: [];
  $payload = [
      'url' => $scan['url'], 'host' => $scan['host'],
      'domain' => PhishingDetector::registrableDomain($scan['host']),
      'score' => (int)$scan['score'], 'verdict' => $scan['verdict'],
      'list_match' => $data['list_match'] ?? null, 'final_url' => $data['final_url'] ?? $scan['url'],
      'features' => $data['features'] ?? [], 'duration_ms' => $data['duration_ms'] ?? 0,
      'network' => (bool)array_filter($data['features'] ?? [], fn($f) => in_array($f['group'], ['host', 'content'], true)),
  ];
?>
  <div class="page-head">
    <div>
      <span class="eyebrow">Scan #<?= $scan['id'] ?></span>
      <h1 class="mono" style="font-size:1.2rem;word-break:break-all"><?= e($scan['url']) ?></h1>
      <p class="muted small">Scanned <?= e(date('M j, Y g:i A', strtotime($scan['created_at']))) ?><?= $scan['full_name'] ? ' by ' . e($scan['full_name']) : '' ?></p>
    </div>
    <a class="btn btn-primary" href="<?= url(($user ? ($user['role'] === 'admin' ? 'admin/scan.php' : 'scan.php') : 'index.php') . '?url=' . urlencode($scan['url'])) ?>">Re-scan now</a>
  </div>
  <section id="result" class="result"></section>
  <script type="application/json" id="scan-data"><?= json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES) ?></script>
<?php endif;
require __DIR__ . '/includes/footer.php';
