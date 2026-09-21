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
    <span class="eyebrow">Real-time phishing detection · <?= ORG_SHORT ?></span>
    <h1>Check the link <span>before</span> you trust it.</h1>
    <p class="lead">Paste any website address. <?= APP_NAME ?> inspects the URL, the domain, its security certificate and the page itself, then tells you in seconds whether it is safe to enter your details.</p>

    <?php require __DIR__ . '/includes/scanner.php'; ?>
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
    <h3>01 · URL analysis</h3>
    <p class="muted small">Over 15 lexical checks: IP-address hosts, the "@" trick, look-alike domains (g00gle, paypa1), brand impersonation, risky TLDs, shorteners and more.</p>
  </article>
  <article class="card">
    <h3>02 · Host verification</h3>
    <p class="muted small">Confirms the domain resolves, validates the SSL certificate against the domain and flags brand-new certificates often used by attackers.</p>
  </article>
  <article class="card">
    <h3>03 · Page inspection</h3>
    <p class="muted small">Looks for password forms that submit elsewhere, hidden iframes, fake brand titles and cross-domain redirects – before you type anything.</p>
  </article>
</section>
<?php require __DIR__ . '/includes/footer.php'; ?>
