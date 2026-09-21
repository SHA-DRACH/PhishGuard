<?php
/** Renders KPI cards + charts. Expects $stats from scan_stats(). */
$t = $stats['totals'];
$pct = fn($n) => $t['total'] ? round($n / $t['total'] * 100) : 0;
?>
<div class="grid grid-4">
  <div class="card kpi"><div class="kpi-label">Total scans</div><div class="kpi-value"><?= number_format($t['total']) ?></div><div class="kpi-sub">Average risk score <?= $t['avg_score'] ?>/100</div></div>
  <div class="card kpi kpi-safe"><div class="kpi-label">Safe</div><div class="kpi-value"><?= number_format($t['safe']) ?></div><div class="kpi-sub"><?= $pct($t['safe']) ?>% of scans</div></div>
  <div class="card kpi kpi-warn"><div class="kpi-label">Suspicious</div><div class="kpi-value"><?= number_format($t['suspicious']) ?></div><div class="kpi-sub"><?= $pct($t['suspicious']) ?>% of scans</div></div>
  <div class="card kpi kpi-danger"><div class="kpi-label">Phishing</div><div class="kpi-value"><?= number_format($t['phishing']) ?></div><div class="kpi-sub"><?= $pct($t['phishing']) ?>% of scans</div></div>
</div>

<div class="grid grid-2" style="margin-top:20px">
  <div class="card">
    <div class="card-head"><h3>Scans – last 7 days</h3><span class="muted small">stacked by verdict</span></div>
    <div data-chart="bars" data-series='<?= e(json_encode($stats['series'])) ?>'></div>
  </div>
  <div class="grid" style="gap:20px">
    <div class="card">
      <h3>Verdict distribution</h3>
      <div data-chart="donut" data-parts='<?= e(json_encode([
          ['label' => 'Safe', 'value' => $t['safe'], 'color' => 'var(--safe)'],
          ['label' => 'Suspicious', 'value' => $t['suspicious'], 'color' => 'var(--warn)'],
          ['label' => 'Phishing', 'value' => $t['phishing'], 'color' => 'var(--danger)'],
      ])) ?>'></div>
    </div>
  </div>
</div>

<div class="card" style="margin-top:20px">
  <h3>Most-flagged hosts</h3>
  <?php if (!$stats['top']): ?>
    <p class="muted small">No suspicious or phishing hosts yet.</p>
  <?php else: $max = max(array_column($stats['top'], 'c')); ?>
    <ul class="bar-list">
      <?php foreach ($stats['top'] as $row): ?>
        <li><code><?= e($row['host']) ?></code><span class="mono small"><?= (int)$row['c'] ?> scans · max <?= (int)$row['max_score'] ?></span>
          <span class="bar"><i style="width:<?= round($row['c'] / $max * 100) ?>%"></i></span></li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>
</div>
