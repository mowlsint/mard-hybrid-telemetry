import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
for (const file of ['public/hat_latest.json','public/hat_history.json','public/hat_source_health.json','public/index.html','public/activity_compare.mjs','public/downloads/hat_analyst_bundle_latest.json','public/downloads/fimi_maritime_articles_latest.csv','public/downloads/fimi_maritime_articles_latest.json','public/downloads/source_health_latest.csv','public/downloads/README_downloads.txt']) {
  const stat = await fs.stat(file).catch(() => null);
  assert(stat?.size > 0, `Missing or empty output: ${file}`);
}
const latest = JSON.parse(await fs.readFile('public/hat_latest.json','utf8'));
const history = JSON.parse(await fs.readFile('public/hat_history.json','utf8'));
const health = JSON.parse(await fs.readFile('public/hat_source_health.json','utf8'));
const nullableScore = value => value === null || Number.isFinite(value) && value >= 0 && value <= 100;
assert.equal(latest.scoring_version,'0.2.0');
assert(nullableScore(latest.hat_score));
assert.equal(Number.isFinite(latest.hat_score),latest.data_quality.cyber_score_valid);
assert(latest.score_interpretation?.color && latest.score_interpretation?.scale);
assert(latest.bot_activity_state?.primary_code);
const fimi = latest.metrics.fimi_lite;
assert(nullableScore(fimi.score));
assert.equal(Number.isFinite(fimi.score),fimi.data_quality.score_valid);
assert(fimi.maritime_filter);
assert.equal(latest.narrative_alert_level.level === null,!fimi.data_quality.score_valid);
assert.notEqual(latest.narrative_alert_level.mode,'bot_ioc_proxy_only_no_fimi_signal');
assert(latest.obscuration_context?.claim_limit);
assert(Array.isArray(health) && health.length);
assert(Array.isArray(history) && history.length);
for (const row of history) {
  assert(row.metric_validity && row.data_quality,'History must retain validity metadata');
  for (const [key,status] of Object.entries(row.metric_validity)) if (status === 'valid') assert(Number.isFinite(row.metrics[key]),key);
}
assert.equal(history.at(-1).generated_at,latest.generated_at);
assert.equal(history.at(-1).metrics.fimi_lite_score,fimi.score);
const accepted = JSON.parse(await fs.readFile('public/downloads/fimi_maritime_articles_latest.json','utf8'));
assert.equal(accepted.length,(fimi.gdelt?.articles || fimi.gdelt?.sample || []).length);
console.log('Output check ok: nullable scores, source validity, separate narrative alert and full downloads.');
