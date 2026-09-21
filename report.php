<?php
require_once __DIR__ . '/includes/bootstrap.php';
$user = current_user();
$pageTitle = 'Report a phishing site';

$old = ['url' => trim($_GET['url'] ?? ''), 'description' => '', 'reporter' => ''];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $old = ['url' => trim($_POST['url'] ?? ''), 'description' => trim($_POST['description'] ?? ''), 'reporter' => trim($_POST['reporter'] ?? '')];
    $normalized = PhishingDetector::normalizeUrl($old['url']);
    if (!parse_url($normalized, PHP_URL_HOST) || strlen($normalized) > 2048) {
        flash('error', 'Please enter a valid website address.');
    } elseif (!$user && $old['reporter'] !== '' && !filter_var($old['reporter'], FILTER_VALIDATE_EMAIL)) {
        flash('error', 'Please enter a valid email address, or leave it blank.');
    } else {
        db()->prepare('INSERT INTO reports (user_id, reporter, url, description) VALUES (?, ?, ?, ?)')
            ->execute([$user['id'] ?? null, $user['email'] ?? ($old['reporter'] ?: null), $normalized, mb_substr($old['description'], 0, 2000) ?: null]);
        flash('success', 'Thank you! Your report has been sent to the LTC ICT security team for review.');
        redirect('report.php');
    }
}

require __DIR__ . '/includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Community defence</span><h1>Report a phishing site</h1>
  <p class="muted">Received a suspicious link by SMS, WhatsApp or email? Report it. Confirmed sites are blacklisted for every user.</p></div></div>

<div class="grid grid-2">
  <form class="card" method="post" novalidate>
    <?= csrf_field() ?>
    <div class="field"><label for="url">Suspicious website address</label>
      <input id="url" name="url" type="text" class="mono" value="<?= e($old['url']) ?>" placeholder="http://ltc-billing-verify.xyz/login" required></div>
    <div class="field"><label for="description">How did you receive it? <span class="muted">(optional)</span></label>
      <textarea id="description" name="description" placeholder="e.g. SMS claiming my LTC internet will be disconnected unless I pay…"><?= e($old['description']) ?></textarea></div>
    <?php if (!$user): ?>
      <div class="field"><label for="reporter">Your email <span class="muted">(optional, for follow-up)</span></label>
        <input id="reporter" name="reporter" type="email" value="<?= e($old['reporter']) ?>"></div>
    <?php endif; ?>
    <button class="btn btn-primary" type="submit">Submit report</button>
  </form>

  <div class="card">
    <h3>What happens next?</h3>
    <ul class="advice">
      <li>An LTC ICT security analyst reviews your report, usually within one working day.</li>
      <li>If confirmed, the domain is added to the <?= APP_NAME ?> blacklist and flagged instantly for everyone.</li>
      <li>Never reply to the sender or click the link again while waiting.</li>
      <li>If you entered a password or PIN, change it immediately and contact your provider.</li>
    </ul>
  </div>
</div>
<?php require __DIR__ . '/includes/footer.php'; ?>
