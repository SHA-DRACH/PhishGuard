<?php
/** Split-screen layout for sign-in / registration. Expects $pageTitle and $formHtml. */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title><?= e($pageTitle) ?> – <?= e(APP_NAME) ?></title>
  <link rel="icon" href="<?= logo_url() ?>">
  <script>try{const d=document.documentElement,t=localStorage.getItem('pg-theme')||'<?= e(setting('default_theme')) ?>';if(t)d.dataset.theme=t;if(localStorage.getItem('pg-sidebar')==='collapsed')d.dataset.sidebar='collapsed';}catch(e){}</script>
  <link rel="stylesheet" href="<?= url('assets/css/style.css') ?>">
  <style>:root{--accent:<?= e(setting('accent_color')) ?>;--accent-2:<?= e(setting('accent_color_2')) ?>}:root[data-theme="light"]{--accent:color-mix(in srgb,<?= e(setting('accent_color')) ?> 75%,#000);--accent-2:color-mix(in srgb,<?= e(setting('accent_color_2')) ?> 80%,#000)}</style>
</head>
<body class="auth-page">
  <div class="auth-shell">
    <aside class="auth-side">
      <div>
        <span class="eyebrow"><?= e(ORG_NAME) ?></span>
        <h2><?= e(setting('login_headline')) ?></h2>
        <p class="muted"><?= e(setting_text('login_text')) ?></p>
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
        <img src="<?= logo_url() ?>" alt="" width="34" height="34">
        <span><strong><?= e(APP_NAME) ?></strong><small><?= e(ORG_SHORT . ' ' . setting('tagline')) ?></small></span>
      </a>
      <?php foreach (take_flashes() as $f): ?>
        <div class="alert alert-<?= e($f['type']) ?>"><?= e($f['message']) ?></div>
      <?php endforeach; ?>
      <?= $formHtml ?>
    </section>
  </div>
</body>
</html>
