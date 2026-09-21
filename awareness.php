<?php
require_once __DIR__ . '/includes/bootstrap.php';
$pageTitle = 'Phishing awareness';

$quiz = [
    ['https://www.libtelco.com.lr/services', 'safe', 'This is the real LTC domain, served over HTTPS.'],
    ['http://libtelco-com-lr.account-verify.tk/pay', 'phish', 'The real domain here is "account-verify.tk". "libtelco-com-lr" is just a sub-domain the attacker chose.'],
    ['https://paypa1.com/signin', 'phish', 'Look closely: "paypa1" uses the number 1 instead of the letter l.'],
    ['https://accounts.google.com/signin', 'safe', 'The registered domain is google.com – "accounts" is a legitimate Google sub-domain.'],
    ['http://197.231.12.8/lonestar/free-airtime', 'phish', 'Real companies do not send you to raw IP addresses, and "free airtime" is a classic lure.'],
    ['https://www.google.com@bit.ly/3kPz', 'phish', 'Everything before "@" is ignored by the browser. This actually opens bit.ly, a link shortener.'],
];

require __DIR__ . '/includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Security awareness</span><h1><?= e(setting('awareness_title')) ?></h1>
  <p class="muted"><?= e(setting_text('awareness_intro')) ?></p></div></div>

<section class="grid grid-3">
  <article class="card tip-card"><span class="tip-num">SIGN 01</span><h3>Read the real domain</h3>
    <p class="muted small">The owner of a website is the part right before the first single "/" – e.g. <code>libtelco.com.lr</code>. Anything to its left is a sub-domain anyone can invent.</p></article>
  <article class="card tip-card"><span class="tip-num">SIGN 02</span><h3>Watch for look-alikes</h3>
    <p class="muted small">Attackers swap characters: <code>0</code> for <code>o</code>, <code>1</code> for <code>l</code>, <code>rn</code> for <code>m</code>, or add words like <code>-secure</code>, <code>-verify</code>.</p></article>
  <article class="card tip-card"><span class="tip-num">SIGN 03</span><h3>Urgency is a red flag</h3>
    <p class="muted small">"Your line will be disconnected today", "confirm your mobile money PIN", "you won airtime" – pressure is designed to stop you thinking.</p></article>
  <article class="card tip-card"><span class="tip-num">SIGN 04</span><h3>HTTPS ≠ safe</h3>
    <p class="muted small">The padlock only means the connection is encrypted – many phishing sites have one. Always combine it with checking the domain.</p></article>
  <article class="card tip-card"><span class="tip-num">SIGN 05</span><h3>Short links hide the destination</h3>
    <p class="muted small">bit.ly, tinyurl and similar services hide where you'll land. Scan them with <?= e(APP_NAME) ?> first.</p></article>
  <article class="card tip-card"><span class="tip-num">SIGN 06</span><h3>Never share PINs or OTPs</h3>
    <p class="muted small">LTC, banks and mobile-money providers will never ask for your password, PIN or one-time code by link, SMS or phone call.</p></article>
</section>

<section class="card" style="margin-top:24px">
  <h2>Genuine vs. fake</h2>
  <div class="compare">
    <div class="good">https://www.libtelco.com.lr/billing<small>Real domain: libtelco.com.lr</small></div>
    <div class="evil">https://libtelco.com.lr.billing-update.xyz/login<small>Real domain: billing-update.xyz</small></div>
    <div class="good">https://www.paypal.com/signin<small>Real domain: paypal.com</small></div>
    <div class="evil">https://www.paypa1-secure.com/signin<small>Look-alike + "secure" keyword</small></div>
  </div>
</section>

<section class="card" style="margin-top:24px">
  <div class="card-head"><h2>Quick quiz: safe or phishing?</h2><span class="badge" id="quiz-score">0 / 0 correct</span></div>
  <div class="quiz">
    <?php foreach ($quiz as [$u, $truth, $explain]): ?>
      <div class="quiz-item" data-truth="<?= $truth ?>" data-explain="<?= e($explain) ?>">
        <code><?= e($u) ?></code>
        <div class="quiz-actions">
          <button class="btn btn-sm btn-ghost" data-answer="safe">Safe</button>
          <button class="btn btn-sm btn-ghost" data-answer="phish">Phishing</button>
        </div>
        <div class="quiz-feedback"></div>
      </div>
    <?php endforeach; ?>
  </div>
</section>

<section class="card" style="margin-top:24px">
  <h2>If you think you've been phished</h2>
  <ul class="advice">
    <li>Change the password of the affected account immediately – and anywhere you reused it.</li>
    <li>Turn on two-factor authentication wherever possible.</li>
    <li>Call your bank or mobile-money provider if you shared financial details.</li>
    <li>Staff: inform the LTC ICT security team straight away. Everyone: <a href="<?= url('report.php') ?>">report the site here</a>.</li>
  </ul>
</section>
<?php require __DIR__ . '/includes/footer.php'; ?>
