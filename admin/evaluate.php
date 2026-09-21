<?php
/**
 * Performance evaluation (Specific Objective 5): run the detector against a labelled
 * dataset and compute accuracy, precision, recall, F1 and the confusion matrix.
 * CSV format: url,label   (label = phishing|legitimate, or 1|0)
 */
require_once __DIR__ . '/../includes/bootstrap.php';
$admin = require_admin();
$pageTitle = 'Evaluation';
set_time_limit(300);

$run = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $network = !empty($_POST['network']);
    $suspiciousIsPhish = ($_POST['suspicious_as'] ?? 'phishing') === 'phishing';
    $limit = $network ? 60 : 2000;

    if (!empty($_FILES['dataset']['tmp_name']) && is_uploaded_file($_FILES['dataset']['tmp_name'])) {
        $path = $_FILES['dataset']['tmp_name'];
        $name = basename($_FILES['dataset']['name']);
    } else {
        $path = __DIR__ . '/../data/sample_dataset.csv';
        $name = 'sample_dataset.csv';
    }

    $rows = [];
    if (($fh = fopen($path, 'r')) !== false) {
        while (($line = fgetcsv($fh)) !== false && count($rows) < $limit) {
            if (count($line) < 2) continue;
            $label = strtolower(trim($line[1]));
            $isPhish = match (true) {
                in_array($label, ['phishing', 'phish', '1', 'bad', 'malicious'], true) => true,
                in_array($label, ['legitimate', 'legit', 'safe', '0', 'good', 'benign'], true) => false,
                default => null,
            };
            if ($isPhish !== null && trim($line[0]) !== '') $rows[] = [trim($line[0]), $isPhish];
        }
        fclose($fh);
    }

    if (!$rows) {
        flash('error', 'No valid rows found. Expected a CSV with columns: url,label');
        redirect('admin/evaluate.php');
    }

    $detector = new PhishingDetector(db(), $network);
    $tp = $fp = $tn = $fn = 0;
    $mistakes = [];
    $start = microtime(true);
    foreach ($rows as [$url, $actual]) {
        try { $r = $detector->analyze($url); } catch (Throwable) { continue; }
        $predicted = $r['verdict'] === 'phishing' || ($suspiciousIsPhish && $r['verdict'] === 'suspicious');
        if ($predicted && $actual) $tp++;
        elseif ($predicted && !$actual) { $fp++; $mistakes[] = [$url, 'False positive', $r['score'], $r['verdict']]; }
        elseif (!$predicted && !$actual) $tn++;
        else { $fn++; $mistakes[] = [$url, 'False negative', $r['score'], $r['verdict']]; }
    }
    $total = $tp + $fp + $tn + $fn;
    $accuracy = $total ? ($tp + $tn) / $total : 0;
    $precision = ($tp + $fp) ? $tp / ($tp + $fp) : 0;
    $recall = ($tp + $fn) ? $tp / ($tp + $fn) : 0;
    $f1 = ($precision + $recall) ? 2 * $precision * $recall / ($precision + $recall) : 0;
    $ms = (int)round((microtime(true) - $start) * 1000);

    db()->prepare('INSERT INTO evaluations (run_by, dataset_name, network, total, tp, fp, tn, fn, accuracy, precision_v, recall, f1, duration_ms)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
        ->execute([$admin['id'], $name, (int)$network, $total, $tp, $fp, $tn, $fn, $accuracy, $precision, $recall, $f1, $ms]);

    $run = compact('name', 'network', 'total', 'tp', 'fp', 'tn', 'fn', 'accuracy', 'precision', 'recall', 'f1', 'ms', 'mistakes');
}

$history = db()->query('SELECT e.*, u.full_name FROM evaluations e LEFT JOIN users u ON u.id = e.run_by ORDER BY e.id DESC LIMIT 15')->fetchAll();
$pct = fn($v) => number_format($v * 100, 1) . '%';

require __DIR__ . '/../includes/header.php';
?>
<div class="page-head"><div><span class="eyebrow">Objective 5 · Performance evaluation</span><h1>Detection accuracy</h1>
  <p class="muted">Test the detector against a labelled dataset of phishing and legitimate URLs.</p></div></div>

<div class="grid grid-2">
  <form class="card" method="post" enctype="multipart/form-data">
    <?= csrf_field() ?>
    <h3>Run an evaluation</h3>
    <div class="field"><label for="dataset">Dataset (CSV: <code>url,label</code>)</label>
      <input id="dataset" name="dataset" type="file" accept=".csv,text/csv">
      <small class="muted">Leave empty to use the bundled sample dataset. <a href="<?= url('data/sample_dataset.csv') ?>" download>Download sample</a></small></div>
    <div class="field"><label for="suspicious_as">Treat "suspicious" verdicts as</label>
      <select id="suspicious_as" name="suspicious_as"><option value="phishing">Phishing (security-first)</option><option value="legitimate">Legitimate (strict)</option></select></div>
    <label class="check" style="margin-bottom:18px"><input type="checkbox" name="network" value="1"> Include network checks (DNS, SSL, content) – slower, max 60 URLs</label>
    <button class="btn btn-primary" type="submit">Run evaluation</button>
  </form>

  <div class="card">
    <h3>How the metrics are computed</h3>
    <ul class="advice small">
      <li><b>Accuracy</b> = (TP + TN) / total – share of URLs classified correctly.</li>
      <li><b>Precision</b> = TP / (TP + FP) – of the URLs flagged, how many were truly phishing.</li>
      <li><b>Recall</b> = TP / (TP + FN) – of all phishing URLs, how many were caught.</li>
      <li><b>F1-score</b> – harmonic mean of precision and recall.</li>
      <li>Positive class = phishing. TP/FP/TN/FN = true/false positives/negatives.</li>
    </ul>
  </div>
</div>

<?php if ($run): ?>
<section class="card" style="margin-top:20px">
  <div class="card-head"><h2>Results – <?= e($run['name']) ?></h2>
    <span class="muted small mono"><?= $run['total'] ?> URLs · <?= $run['network'] ? 'with network checks' : 'URL-only' ?> · <?= number_format($run['ms']) ?> ms</span></div>
  <div class="grid grid-4">
    <div class="kpi kpi-safe"><div class="kpi-label">Accuracy</div><div class="kpi-value"><?= $pct($run['accuracy']) ?></div></div>
    <div class="kpi"><div class="kpi-label">Precision</div><div class="kpi-value"><?= $pct($run['precision']) ?></div></div>
    <div class="kpi"><div class="kpi-label">Recall</div><div class="kpi-value"><?= $pct($run['recall']) ?></div></div>
    <div class="kpi kpi-warn"><div class="kpi-label">F1-score</div><div class="kpi-value"><?= $pct($run['f1']) ?></div></div>
  </div>
  <div class="grid grid-2" style="margin-top:20px">
    <div>
      <h3>Confusion matrix</h3>
      <div class="matrix">
        <div class="h"></div><div class="h">Predicted phishing</div><div class="h">Predicted legitimate</div>
        <div class="h">Actual phishing</div><div class="ok"><strong><?= $run['tp'] ?></strong>TP</div><div class="bad"><strong><?= $run['fn'] ?></strong>FN</div>
        <div class="h">Actual legitimate</div><div class="bad"><strong><?= $run['fp'] ?></strong>FP</div><div class="ok"><strong><?= $run['tn'] ?></strong>TN</div>
      </div>
    </div>
    <div>
      <h3>Misclassified URLs (<?= count($run['mistakes']) ?>)</h3>
      <?php if (!$run['mistakes']): ?><p class="muted">None – every URL was classified correctly.</p><?php else: ?>
      <div class="table-wrap" style="max-height:300px;overflow:auto"><table class="table">
        <thead><tr><th>URL</th><th>Error</th><th>Score</th></tr></thead>
        <tbody><?php foreach ($run['mistakes'] as [$u, $type, $score, $v]): ?>
          <tr><td class="url-cell" title="<?= e($u) ?>"><?= e($u) ?></td><td class="small"><?= $type ?></td><td><?= score_pill($score) ?></td></tr>
        <?php endforeach; ?></tbody>
      </table></div><?php endif; ?>
    </div>
  </div>
</section>
<?php endif; ?>

<section class="card" style="margin-top:20px">
  <h3>Evaluation history</h3>
  <?php if (!$history): ?><p class="muted">No evaluations run yet.</p><?php else: ?>
  <div class="table-wrap"><table class="table">
    <thead><tr><th>Date</th><th>Dataset</th><th>Mode</th><th>URLs</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>By</th></tr></thead>
    <tbody><?php foreach ($history as $h): ?>
      <tr><td class="small muted"><?= e(date('M j, H:i', strtotime($h['created_at']))) ?></td>
        <td class="small"><?= e($h['dataset_name']) ?></td>
        <td class="small"><?= $h['network'] ? 'Deep' : 'URL-only' ?></td>
        <td class="mono small"><?= (int)$h['total'] ?></td>
        <td class="mono"><?= $pct($h['accuracy']) ?></td><td class="mono"><?= $pct($h['precision_v']) ?></td>
        <td class="mono"><?= $pct($h['recall']) ?></td><td class="mono"><?= $pct($h['f1']) ?></td>
        <td class="small"><?= e($h['full_name'] ?? '—') ?></td></tr>
    <?php endforeach; ?></tbody>
  </table></div><?php endif; ?>
</section>
<?php require __DIR__ . '/../includes/footer.php'; ?>
