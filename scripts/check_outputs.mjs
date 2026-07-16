import fs from 'node:fs/promises';

const files = [
  'public/hat_latest.json',
  'public/hat_history.json',
  'public/hat_source_health.json',
  'public/index.html',
  'public/downloads/hat_analyst_bundle_latest.json',
  'public/downloads/fimi_maritime_articles_latest.csv',
  'public/downloads/source_health_latest.csv'
];
for (const file of files) {
  const stat = await fs.stat(file).catch(() => null);
  if (!stat || stat.size === 0) {
    console.error(`Missing or empty output: ${file}`);
    process.exit(1);
  }
}
const latest = JSON.parse(await fs.readFile('public/hat_latest.json', 'utf8'));
if (!latest.schema || typeof latest.hat_score !== 'number') {
  console.error('Invalid latest schema/score.');
  process.exit(1);
}
if (!latest.score_interpretation?.color || !latest.score_interpretation?.scale) {
  console.error('Missing score_interpretation color/scale.');
  process.exit(1);
}
if (!latest.bot_activity_state?.primary_code) {
  console.error('Missing bot_activity_state.primary_code.');
  process.exit(1);
}
if (!latest.disinformation_alert_level || typeof latest.disinformation_alert_level.level !== 'number') {
  console.error('Missing disinformation_alert_level.level.');
  process.exit(1);
}
if (!latest.metrics?.fimi_lite || typeof latest.metrics.fimi_lite.score !== 'number') {
  console.error('Missing metrics.fimi_lite.score.');
  process.exit(1);
}
if (!latest.metrics?.fimi_lite?.maritime_filter) {
  console.error('Missing metrics.fimi_lite.maritime_filter.');
  process.exit(1);
}
if (!latest.obscuration_context?.claim_limit) {
  console.error('Missing obscuration_context claim limit.');
  process.exit(1);
}
const sourceHealth = JSON.parse(await fs.readFile('public/hat_source_health.json', 'utf8'));
if (!Array.isArray(sourceHealth) || !sourceHealth.length) {
  console.error('Invalid source health output.');
  process.exit(1);
}
console.log('Output check ok.');
