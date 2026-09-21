<?php /** Reusable scanner form + live pulse + result area (used by public, user and admin scan pages). */ ?>
<form id="scan-form" class="scanner" autocomplete="off" novalidate>
  <?= csrf_field() ?>
  <label for="scan-url" class="visually-hidden">Website address</label>
  <div class="scan-bar">
    <span class="prompt" aria-hidden="true">URL&gt;</span>
    <input id="scan-url" name="url" type="text" inputmode="url" spellcheck="false"
           placeholder="https://example.com/login" required autofocus>
    <button class="btn btn-primary" type="submit">Scan</button>
  </div>
  <div class="scan-options">
    <label class="check"><input type="checkbox" name="deep" value="1" <?= setting('deep_default') ? 'checked' : '' ?>> Deep scan (also inspect SSL certificate &amp; page content)</label>
    <?php if (setting('domain_checks')): ?><span class="scan-note">Every scan checks that the domain really exists, is registered and is reachable.</span><?php endif; ?>
  </div>
  <div class="pulse" aria-live="polite">
    <div class="pulse-track"><div class="pulse-fill"></div></div>
    <span class="pulse-label"></span>
  </div>
</form>
