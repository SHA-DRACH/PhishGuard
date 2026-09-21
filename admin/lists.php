<?php
require_once __DIR__ . '/../includes/bootstrap.php';
$admin = require_admin();
$pageTitle = 'Blacklist & trusted domains';

function clean_domain(string $input): string
{
    $input = strtolower(trim($input));
    $host = parse_url(PhishingDetector::normalizeUrl($input), PHP_URL_HOST) ?: '';
    $host = preg_replace('/^www\./', '', rtrim($host, '.'));
    return preg_match('/^[a-z0-9.-]+\.[a-z0-9-]{2,}$|^\d{1,3}(\.\d{1,3}){3}$/', $host) ? $host : '';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $list = ($_POST['list'] ?? '') === 'whitelist' ? 'whitelist' : 'blacklist';
    if (($_POST['action'] ?? '') === 'delete') {
        db()->prepare("DELETE FROM $list WHERE id = ?")->execute([(int)$_POST['id']]);
        flash('success', 'Entry removed.');
    } else {
        $domain = clean_domain($_POST['domain'] ?? '');
        if (!$domain) {
            flash('error', 'Please enter a valid domain, e.g. example.com');
        } else {
            $other = $list === 'blacklist' ? 'whitelist' : 'blacklist';
            db()->prepare("DELETE FROM $other WHERE domain = ?")->execute([$domain]);
            if ($list === 'blacklist') {
                db()->prepare('INSERT INTO blacklist (domain, reason, added_by) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE reason = VALUES(reason)')
                    ->execute([$domain, trim($_POST['reason'] ?? '') ?: null, $admin['id']]);
            } else {
                $brand = strtolower(preg_replace('/[^a-z0-9]/i', '', $_POST['brand'] ?? ''));
                db()->prepare('INSERT INTO whitelist (domain, brand, added_by) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE brand = VALUES(brand)')
                    ->execute([$domain, $brand ?: null, $admin['id']]);
            }
            flash('success', "$domain saved to the " . ($list === 'blacklist' ? 'blacklist' : 'trusted list') . '.');
        }
    }
    redirect('admin/lists.php#' . $list);
}

$black = db()->query('SELECT b.*, u.full_name FROM blacklist b LEFT JOIN users u ON u.id = b.added_by ORDER BY b.id DESC')->fetchAll();
$white = db()->query('SELECT * FROM whitelist ORDER BY domain')->fetchAll();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Reputation data</span><h1>Blacklist &amp; trusted domains</h1>
  <p class="muted">Blacklisted domains are always flagged as phishing. Trusted domains with a <strong>brand keyword</strong> power impersonation and look-alike detection.</p></div></div>

<div class="grid grid-2">
  <section class="card" id="blacklist">
    <div class="card-head"><h3>Blacklist</h3><span class="badge badge-phishing"><?= count($black) ?> domains</span></div>
    <form method="post" class="form-row" style="margin-bottom:16px">
      <?= csrf_field() ?><input type="hidden" name="list" value="blacklist">
      <input name="domain" type="text" class="mono" placeholder="evil-domain.tk" required>
      <input name="reason" type="text" placeholder="Reason (optional)">
      <button class="btn btn-danger" type="submit">Block</button>
    </form>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Domain</th><th>Reason</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($black as $b): ?>
        <tr><td class="mono small"><?= e($b['domain']) ?></td>
          <td class="small muted"><?= e($b['reason'] ?? '—') ?></td>
          <td class="actions"><form method="post" data-confirm="Remove <?= e($b['domain']) ?> from the blacklist?"><?= csrf_field() ?>
            <input type="hidden" name="list" value="blacklist"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= $b['id'] ?>">
            <button class="btn btn-sm btn-ghost">Remove</button></form></td></tr>
      <?php endforeach; if (!$black): ?><tr><td colspan="3" class="empty">Empty</td></tr><?php endif; ?>
      </tbody>
    </table></div>
  </section>

  <section class="card" id="whitelist">
    <div class="card-head"><h3>Trusted domains</h3><span class="badge badge-safe"><?= count($white) ?> domains</span></div>
    <form method="post" class="form-row" style="margin-bottom:16px">
      <?= csrf_field() ?><input type="hidden" name="list" value="whitelist">
      <input name="domain" type="text" class="mono" placeholder="libtelco.com.lr" required>
      <input name="brand" type="text" placeholder="Brand keyword (e.g. libtelco)">
      <button class="btn btn-primary" type="submit">Trust</button>
    </form>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Domain</th><th>Brand</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($white as $w): ?>
        <tr><td class="mono small"><?= e($w['domain']) ?></td>
          <td class="small"><?= $w['brand'] ? '<code>' . e($w['brand']) . '</code>' : '<span class="muted">—</span>' ?></td>
          <td class="actions"><form method="post" data-confirm="Remove <?= e($w['domain']) ?> from trusted domains?"><?= csrf_field() ?>
            <input type="hidden" name="list" value="whitelist"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= $w['id'] ?>">
            <button class="btn btn-sm btn-ghost">Remove</button></form></td></tr>
      <?php endforeach; ?>
      </tbody>
    </table></div>
  </section>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
