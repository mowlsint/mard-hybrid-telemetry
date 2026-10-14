import fs from 'node:fs/promises';
import { compareActivity } from '../../public/activity_compare.mjs';

const [date, days = '7', country = 'all'] = process.argv.slice(2);
if (!date) {
  console.error('Usage: node scripts/influence/compare_influence_event.mjs YYYY-MM-DD [days=7] [country=all]');
  process.exitCode = 1;
} else {
  const series = JSON.parse(await fs.readFile('public/influence_activity_daily.json', 'utf8'));
  console.log(JSON.stringify(compareActivity(series, date, Number(days), country), null, 2));
}
