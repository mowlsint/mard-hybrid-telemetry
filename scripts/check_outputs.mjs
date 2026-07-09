import fs from 'node:fs/promises';

const files = ['public/hat_latest.json', 'public/hat_history.json', 'public/hat_source_health.json', 'public/index.html'];
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
if (!latest.bot_activity_state?.primary_code) {
  console.error('Missing bot_activity_state.primary_code.');
  process.exit(1);
}
if (!latest.disinformation_alert_level || typeof latest.disinformation_alert_level.level !== 'number') {
  console.error('Missing disinformation_alert_level.level.');
  process.exit(1);
}
console.log('Output check ok.');
