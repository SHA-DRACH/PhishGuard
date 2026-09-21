<?php
require_once __DIR__ . '/../includes/bootstrap.php';
$admin = require_admin();
$pageTitle = 'System settings';

$schema = settings_schema();
$tab = isset($schema[$_GET['tab'] ?? '']) ? $_GET['tab'] : 'general';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $group = $_POST['group'] ?? '';
    if (!isset($schema[$group])) redirect('admin/settings.php');
    if (($_POST['action'] ?? '') === 'reset') {
        settings_reset($group);
        flash('success', $schema[$group]['label'] . ' settings were restored to their defaults.');
    } else {
        $errors = settings_save($group, $_POST, $_FILES, (int)$admin['id']);
        if ($errors) {
            foreach ($errors as $err) flash('error', $err);
            $_SESSION['settings_old'] = [$group => $_POST];
        } else {
            flash('success', $schema[$group]['label'] . ' settings saved. Changes are live on every page.');
        }
    }
    redirect('admin/settings.php?tab=' . urlencode($group));
}

// Re-show submitted values after a validation error
$old = $_SESSION['settings_old'][$tab] ?? null;
unset($_SESSION['settings_old']);
$val = function (string $key) use ($old) {
    if ($old !== null && array_key_exists($key, $old)) return $old[$key];
    $v = setting($key);
    return is_bool($v) ? ($v ? '1' : '') : (string)$v;
};

$keys = array_keys($schema[$tab]['fields']);
$in = implode(',', array_fill(0, count($keys), '?'));
$stmt = db()->prepare("SELECT s.updated_at, u.full_name FROM settings s LEFT JOIN users u ON u.id = s.updated_by
                       WHERE s.name IN ($in) ORDER BY s.updated_at DESC LIMIT 1");
$stmt->execute($keys);
$lastChange = $stmt->fetch();
$customised = (int)db()->query('SELECT COUNT(*) FROM settings')->fetchColumn();

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head">
  <div><span class="eyebrow">Configuration</span><h1>System settings</h1>
    <p class="muted">Change how <?= e(APP_NAME) ?> looks, what it says and how it detects phishing. Changes apply to every page immediately.</p></div>
  <span class="badge"><?= $customised ?> customised setting<?= $customised === 1 ? '' : 's' ?></span>
</div>

<div class="settings-layout">
  <nav class="settings-tabs" aria-label="Settings sections">
    <?php foreach ($schema as $key => $g): ?>
      <a href="?tab=<?= $key ?>" <?= $key === $tab ? 'aria-current="page"' : '' ?>><?= icon($g['icon']) ?><span><?= e($g['label']) ?></span></a>
    <?php endforeach; ?>
  </nav>

  <section class="settings-panel">
    <form class="card" method="post" enctype="multipart/form-data">
      <?= csrf_field() ?><input type="hidden" name="group" value="<?= $tab ?>">
      <div class="card-head">
        <div><h2 style="margin:0"><?= e($schema[$tab]['label']) ?></h2><p class="muted small" style="margin:4px 0 0"><?= e($schema[$tab]['intro']) ?></p></div>
        <?php if ($lastChange): ?><span class="small muted">Last changed <?= e(time_ago($lastChange['updated_at'])) ?> by <?= e($lastChange['full_name'] ?? 'unknown') ?></span><?php endif; ?>
      </div>

      <div class="settings-fields">
      <?php foreach ($schema[$tab]['fields'] as $key => $f):
          $id = 'f_' . $key; $help = $f['help'] ?? ''; $wide = in_array($f['type'], ['textarea', 'list', 'weights', 'positions'], true); ?>
        <div class="field setting-field<?= $wide ? ' wide' : '' ?><?= $f['type'] === 'bool' ? ' is-toggle' : '' ?>">
        <?php switch ($f['type']):
          case 'bool': ?>
            <label class="switch" for="<?= $id ?>">
              <input type="checkbox" id="<?= $id ?>" name="<?= $key ?>" value="1" <?= $val($key) ? 'checked' : '' ?>>
              <span class="switch-track" aria-hidden="true"></span>
              <span><strong><?= e($f['label']) ?></strong><?php if ($help): ?><small class="muted"><?= e($help) ?></small><?php endif; ?></span>
            </label>
            <?php break;
          case 'weights': $weights = setting_weights(); ?>
            <div class="weights-grid">
              <?php foreach (weight_defaults() as $wid => [$wlabel, $wdefault]):
                  $cur = $old['w'][$wid] ?? $weights[$wid]; ?>
                <label class="weight-item<?= (int)$cur !== $wdefault ? ' changed' : '' ?>">
                  <span><?= e($wlabel) ?><small>default <?= $wdefault ?></small></span>
                  <input type="number" name="w[<?= $wid ?>]" value="<?= (int)$cur ?>" min="0" max="100" required>
                </label>
              <?php endforeach; ?>
            </div>
            <?php break;
          default: ?>
            <label for="<?= $id ?>"><?= e($f['label']) ?></label>
            <?php if ($f['type'] === 'textarea'): ?>
              <textarea id="<?= $id ?>" name="<?= $key ?>" rows="3" maxlength="<?= $f['max'] ?? 500 ?>"><?= e($val($key)) ?></textarea>
            <?php elseif ($f['type'] === 'list' || $f['type'] === 'positions'): ?>
              <textarea id="<?= $id ?>" name="<?= $key ?>" rows="<?= $f['type'] === 'positions' ? 18 : 8 ?>" class="mono" spellcheck="false"><?= e($val($key)) ?></textarea>
            <?php elseif ($f['type'] === 'select'):
                $options = $f['options'] === 'timezones' ? array_combine(DateTimeZone::listIdentifiers(), DateTimeZone::listIdentifiers()) : $f['options']; ?>
              <select id="<?= $id ?>" name="<?= $key ?>">
                <?php foreach ($options as $ov => $ol): ?><option value="<?= e($ov) ?>" <?= $val($key) === (string)$ov ? 'selected' : '' ?>><?= e($ol) ?></option><?php endforeach; ?>
              </select>
            <?php elseif ($f['type'] === 'color'): ?>
              <div class="color-field"><input type="color" id="<?= $id ?>" name="<?= $key ?>" value="<?= e($val($key)) ?>"><code><?= e($val($key)) ?></code></div>
            <?php elseif ($f['type'] === 'secret'): $saved = (string)setting($key); ?>
              <input type="password" id="<?= $id ?>" name="<?= $key ?>" value="" autocomplete="off" placeholder="<?= $saved ? 'Key saved (ending …' . e(substr($saved, -4)) . ') – type to replace' : 'Paste API key' ?>">
              <?php if ($saved): ?><label class="check"><input type="checkbox" name="<?= $key ?>_clear" value="1"> Remove the saved key</label><?php endif; ?>
            <?php elseif ($f['type'] === 'image'): ?>
              <div class="logo-field">
                <img src="<?= logo_url() ?>" alt="Current logo" width="56" height="56">
                <div><input type="file" id="<?= $id ?>" name="<?= $key ?>" accept="image/png,image/jpeg,image/webp">
                  <?php if (setting($key)): ?><label class="check"><input type="checkbox" name="<?= $key ?>_remove" value="1"> Restore the default logo</label><?php endif; ?></div>
              </div>
            <?php else: ?>
              <input type="<?= $f['type'] === 'int' ? 'number' : ($f['type'] === 'email' ? 'email' : 'text') ?>" id="<?= $id ?>" name="<?= $key ?>"
                     value="<?= e($val($key)) ?>" <?= isset($f['min']) ? "min=\"{$f['min']}\" max=\"{$f['max']}\"" : '' ?>
                     <?= isset($f['max']) && $f['type'] !== 'int' ? "maxlength=\"{$f['max']}\"" : '' ?> <?= !empty($f['required']) ? 'required' : '' ?>>
            <?php endif; ?>
            <?php if ($help): ?><small class="muted"><?= e($help) ?></small><?php endif; ?>
        <?php endswitch; ?>
        </div>
      <?php endforeach; ?>
      </div>

      <div class="settings-actions">
        <button class="btn btn-primary" type="submit">Save changes</button>
      </div>
    </form>

    <form method="post" class="reset-form" data-confirm="Restore all <?= e($schema[$tab]['label']) ?> settings to their defaults?">
      <?= csrf_field() ?><input type="hidden" name="group" value="<?= $tab ?>"><input type="hidden" name="action" value="reset">
      <button class="linklike small" type="submit">Restore <?= e(strtolower($schema[$tab]['label'])) ?> defaults</button>
    </form>
  </section>
</div>
<?php require __DIR__ . '/../includes/footer.php'; ?>
