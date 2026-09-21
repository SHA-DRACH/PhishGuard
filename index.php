<?php
require_once __DIR__ . '/includes/bootstrap.php';
$pageTitle = 'Scan a website';

$stats = db()->query(
    "SELECT COUNT(*) total,
            SUM(verdict = 'phishing') phishing,
            SUM(verdict = 'suspicious') suspicious,
            SUM(created_at >= CURDATE()) today
     FROM scans"
)->fetch();
$blocked = (int)db()->query('SELECT COUNT(*) FROM blacklist')->fetchColumn();

require __DIR__ . '/includes/header.php';
?>
<section class="hero">
  <div>
    <span class="eyebrow"><?= e(setting('home_eyebrow')) ?> · <?= e(ORG_SHORT) ?></span>
    <h1><?= preg_replace('/\*([^*]+)\*/', '<span>$1</span>', e(setting('home_title'))) ?></h1>
    <p class="lead"><?= e(setting_text('home_lead')) ?></p>

    <?php if (setting('allow_guest_scan') || current_user()): ?>
      <?php require __DIR__ . '/includes/scanner.php'; ?>
    <?php else: ?>
      <div class="card" style="margin-top:26px"><p style="margin:0">Please <a href="<?= url('login.php') ?>">sign in</a> to scan websites.</p></div>
    <?php endif; ?>
  </div>

  <div class="radar" aria-hidden="true">
    <div class="sweep"></div>
    <div class="blip" style="left:68%;top:30%"><span>paypa1-verify.tk</span></div>
    <div class="blip" style="left:30%;top:64%;--c:var(--warn)"><span>bit.ly/3xK…</span></div>
    <div class="blip" style="left:58%;top:74%;--c:var(--safe)"><span>libtelco.com.lr</span></div>
  </div>
</section>

<section id="result" class="result" aria-live="polite"></section>

<div class="stat-strip">
  <div><strong><?= number_format((int)$stats['total']) ?></strong><span>Sites scanned</span></div>
  <div><strong style="color:var(--danger)"><?= number_format((int)$stats['phishing']) ?></strong><span>Phishing detected</span></div>
  <div><strong style="color:var(--warn)"><?= number_format((int)$stats['suspicious']) ?></strong><span>Suspicious</span></div>
  <div><strong><?= number_format((int)$stats['today']) ?></strong><span>Scans today</span></div>
  <div><strong><?= number_format($blocked) ?></strong><span>Blacklisted domains</span></div>
</div>

<section class="grid grid-3" style="margin-top:28px">
  <article class="card">
    <h3><?= e(setting('home_card1_title')) ?></h3>
    <p class="muted small"><?= e(setting('home_card1_text')) ?></p>
  </article>
  <article class="card">
    <h3><?= e(setting('home_card2_title')) ?></h3>
    <p class="muted small"><?= e(setting('home_card2_text')) ?></p>
  </article>
  <article class="card">
    <h3><?= e(setting('home_card3_title')) ?></h3>
    <p class="muted small"><?= e(setting('home_card3_text')) ?></p>
  </article>
</section>
<?php require __DIR__ . '/includes/footer.php'; ?>
