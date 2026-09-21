<?php if (($layout ?? 'public') === 'public'): ?>
</main>
<footer class="site-footer">
  <div class="container">
    <p>&copy; <?= date('Y') ?> <?= e(ORG_NAME) ?> &middot; <?= e(APP_NAME) ?> · <?= e(setting('tagline')) ?></p>
    <p class="muted"><?= e(setting('footer_note')) ?></p>
    <?php if (setting('support_email') || setting('support_phone')): ?>
      <p class="muted">Need help? <?= setting('support_email') ? '<a href="mailto:' . e(setting('support_email')) . '">' . e(setting('support_email')) . '</a>' : '' ?><?= setting('support_email') && setting('support_phone') ? ' · ' : '' ?><?= e(setting('support_phone')) ?></p>
    <?php endif; ?>
  </div>
</footer>
<?php else: ?>
    </main>
    <footer class="app-footer">&copy; <?= date('Y') ?> <?= e(ORG_NAME) ?> &middot; <?= e(APP_NAME) ?></footer>
  </div>
</div>
<?php endif; ?>

<dialog id="phish-alert" class="phish-alert">
  <div class="phish-alert-icon" aria-hidden="true">!</div>
  <h2>Warning: likely phishing site</h2>
  <p>This page shows strong signs of phishing. <strong>Do not enter passwords, PINs, card or mobile-money details.</strong></p>
  <p class="phish-alert-url"></p>
  <div class="phish-alert-actions">
    <button class="btn btn-danger" data-close>Keep me safe</button>
    <button class="btn btn-ghost" data-details>View details</button>
  </div>
</dialog>
</body>
</html>
