<?php
/** Split-screen layout for sign-in / registration. Expects $pageTitle and $formHtml. */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title><?= e($pageTitle) ?> – <?= APP_NAME ?></title>
  <link rel="icon" href="<?= url('assets/img/shield.svg') ?>" type="image/svg+xml">
  <script>try{const t=localStorage.getItem('pg-theme');if(t)document.documentElement.dataset.theme=t;}catch(e){}</script>
  <link rel="stylesheet" href="<?= url('assets/css/style.css') ?>">
</head>
<body class="auth-page">
  <div class="auth-shell">
    <aside class="auth-side">
      <div>
        <span class="eyebrow"><?= ORG_NAME ?></span>
        <h2>Stay one step ahead of phishing.</h2>
        <p class="muted">A secure workspace for LTC staff and customers to verify links, report fraud and track threats.</p>
      </div>
      <ul>
        <li>Real-time URL, certificate &amp; page analysis</li>
        <li>Personal scan history and threat dashboard</li>
        <li>One-click reporting to the ICT security team</li>
      </ul>
      <div class="radar" style="width:180px;margin:0" aria-hidden="true"><div class="sweep"></div>
        <div class="blip" style="left:66%;top:34%"></div><div class="blip" style="left:36%;top:62%;--c:var(--safe)"></div></div>
    </aside>
    <section class="auth-form">
      <a class="brand" href="<?= url('index.php') ?>">
        <img src="<?= url('assets/img/shield.svg') ?>" alt="" width="34" height="34">
        <span><strong><?= APP_NAME ?></strong><small><?= ORG_SHORT ?> Phishing Detection</small></span>
      </a>
      <?php foreach (take_flashes() as $f): ?>
        <div class="alert alert-<?= e($f['type']) ?>"><?= e($f['message']) ?></div>
      <?php endforeach; ?>
      <?= $formHtml ?>
    </section>
  </div>
</body>
</html>
