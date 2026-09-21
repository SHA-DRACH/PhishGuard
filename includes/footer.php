<?php if (($layout ?? 'public') === 'public'): ?>
</main>
<footer class="site-footer">
  <div class="container">
    <p>&copy; <?= date('Y') ?> <?= ORG_NAME ?> &middot; <?= APP_NAME ?> Phishing Detection System</p>
    <p class="muted">Never enter passwords, PINs or mobile-money codes on a site you did not type yourself.</p>
  </div>
</footer>
<?php else: ?>
    </main>
    <footer class="app-footer">&copy; <?= date('Y') ?> <?= ORG_NAME ?> &middot; <?= APP_NAME ?></footer>
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
