export const SCORING_VERSION = '0.2.0';

export function annotateLegacyHistory(row) {
  if (row.data_quality && row.metric_validity) return row;
  return { ...row, scoring_version: row.scoring_version || 'legacy_unverified',
    data_quality: { state: 'legacy_unverified', comparable: false,
      note: 'Original values retained. Per-run source access and score validity were not recorded; zeros and old percentiles are unverified.' },
    metric_validity: Object.fromEntries(Object.keys(row.metrics || {}).map(key => [key, 'legacy_unverified'])) };
}

export function historicalValues(rows, metric, { minDays = 14, version = SCORING_VERSION, configurationHash = null } = {}) {
  const daily = new Map();
  for (const row of rows || []) {
    const value = metric === 'hat_score' ? row.hat_score : row.metrics?.[metric];
    const valid = metric === 'hat_score' ? row.data_quality?.cyber_score_valid : row.metric_validity?.[metric] === 'valid';
    if (!valid || row.scoring_version !== version || !Number.isFinite(value)
      || configurationHash && row.configuration_hash !== configurationHash) continue;
    const date = String(row.generated_at || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) continue;
    const values = daily.get(date) || [];
    values.push(value);
    daily.set(date, values);
  }
  const values = [...daily.values()].map(items => items.reduce((a, b) => a + b, 0) / items.length);
  return { values: values.length >= minDays ? values : [], days: values.length, ready: values.length >= minDays };
}

export function sourceQuality(health, names) {
  const rows = names.map(name => health.find(row => row.source === name))
    .filter(row => row && row.status !== 'disabled');
  const expected = rows.reduce((sum, row) => sum + (row.queries ?? 1), 0);
  const successful = rows.reduce((sum, row) => sum + (row.ok_queries ?? (row.status === 'ok' ? 1 : 0)), 0);
  const scoreValid = rows.length > 0 && rows.every(row => row.status === 'ok');
  return { state: scoreValid ? 'valid' : successful > 0 ? 'partial' : rows.length ? 'unavailable' : 'disabled',
    score_valid: scoreValid, successful_queries: successful, expected_queries: expected,
    coverage_ratio: expected ? Number((successful / expected).toFixed(3)) : 0,
    sources: Object.fromEntries(rows.map(row => [row.source, row.status])) };
}

export function narrativeAlert(fimi, thresholds = {}) {
  if (!fimi?.data_quality?.score_valid || !Number.isFinite(fimi.score)) {
    return { schema: 'mard-hat-narrative-alert-v3', level: null, label: 'not_assessable',
      mode: 'insufficient_source_coverage', fimi_lite_score: null,
      note: 'Narrative pressure is not assessable for this run. Cyber/IOC activity does not set this alert.' };
  }
  const score = fimi.score;
  const level = score >= (thresholds.level_3_fimi_score ?? 80) ? 3
    : score >= (thresholds.level_2_fimi_score ?? 55) ? 2
    : score >= (thresholds.level_1_fimi_score ?? 25) ? 1 : 0;
  return { schema: 'mard-hat-narrative-alert-v3', level,
    label: ['no_matching_signal', 'low', 'elevated', 'high'][level],
    mode: 'maritime_narrative_pressure_only', fimi_lite_score: score,
    note: 'Media/topic pressure from retrieved sources. It does not establish falsehood, automated amplification or attribution.' };
}
