import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import vm from 'node:vm';
import { compareActivity } from '../public/activity_compare.mjs';

test('The dashboard renders unavailable signals without a false zero or active alert', async () => {
  const html = await fs.readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const script = html.split('<script type="module">')[1].split('</script>')[0]
    .replace('import { compareActivity } from "./activity_compare.mjs";', '')
    .replace(/main\(\)\.catch\(err=>\{document\.body[\s\S]*?\}\);/, '')
    + '\nglobalThis.runDashboard = main;';
  const elements = new Map();
  for (const [, id] of html.matchAll(/id="([^"]+)"/g)) elements.set(id, { style: {}, value: '', innerHTML: '', textContent: '',
    disabled: false, addEventListener() {} });
  elements.get('eventDays').value = '7';
  elements.get('eventCountry').value = 'all';
  const latest = { generated_at: new Date().toISOString(), hat_score: null, level: 'not_assessable', data_quality: { cyber_score_valid: false },
    baseline: { status: 'warming_up', points: 0, minimum_days: 14 }, trend: 'unknown',
    bot_activity_state: { primary_code: 'UNRATED', basis: {} }, metrics: { fimi_lite: { score: null, status: 'unavailable', data_quality: { score_valid: false } } },
    narrative_alert_level: { level: null, note: 'Narrative observations unavailable' } };
  const responses = {
    'hat_latest.json': latest, 'hat_history.json': [], 'hat_source_health.json': [],
    'influence_watch_latest.json': { generated_at: '2026-07-18T00:00:00Z', data_quality: { successful_sources: 0 } },
    'influence_activity_daily.json': { days: [] }
  };
  const context = vm.createContext({ console, Date, Math, Number, String, Object, Array, Set, Map, compareActivity, setTimeout,
    document: { getElementById: id => elements.get(id), body: { insertAdjacentHTML() { throw new Error('Dashboard failed'); } } },
    fetch: async url => ({ ok: true, json: async () => responses[url.split('?')[0]] }) });
  vm.runInContext(script, context);
  await context.runDashboard();
  assert.equal(elements.get('score').textContent, '—');
  assert.match(elements.get('fimi').innerHTML, /Not assessable/);
  assert.doesNotMatch(elements.get('fimi').innerHTML, /<b>0%<\/b>/);
  assert.match(elements.get('dal').innerHTML, /Not assessable/);
  assert.match(elements.get('influence').innerHTML, /Not assessable \/ stale/);
  assert.match(elements.get('eventResult').textContent, /Not assessable/);
  assert.equal(elements.get('trend').textContent, 'trend collecting baseline');
  assert.match(elements.get('baseline').textContent, /0\/14 prior measurement days/);
  assert.match(elements.get('trendNote').textContent, /14 prior days with valid measurements/);
});

test('The history chart shows isolated valid measurements and keeps unverified scores separate', async () => {
  const html = await fs.readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const script = html.split('<script type="module">')[1].split('</script>')[0]
    .replace('import { compareActivity } from "./activity_compare.mjs";', '')
    .replace(/main\(\)\.catch\(err=>\{document\.body[\s\S]*?\}\);/, '')
    + '\nglobalThis.drawHistory = renderChart;';
  const chart = { innerHTML: '' }, status = { textContent: '' };
  const context = vm.createContext({ document: { getElementById: id => id === 'chart' ? chart : status } });
  vm.runInContext(script, context);
  const latest = { scoring_version: '0.2.0', configuration_hash: 'current' };
  const valid = (date,score=66) => ({ ...latest, generated_at: date, hat_score: score, data_quality: { cyber_score_valid: true } });
  const observed = valid('2026-10-14T07:35:16Z');
  context.drawHistory([observed], latest);
  assert.match(chart.innerHTML, /<circle[^>]+data-series="current-valid"[^>]+cx="400"/);
  assert.doesNotMatch(chart.innerHTML, /<polyline/);
  assert.match(status.textContent, /1 current valid measurement shown in gold as a point/);

  const archive = date => ({ generated_at: date, hat_score: 90, data_quality: { state: 'legacy_unverified' } });
  context.drawHistory([archive('2026-10-12T00:00:00Z'),archive('2026-10-13T00:00:00Z'),observed], latest);
  assert.match(chart.innerHTML, /<polyline data-series="archived-unverified"[^>]+stroke-dasharray/);
  assert.match(chart.innerHTML, /<circle data-series="current-valid"/);
  assert.doesNotMatch(chart.innerHTML, /<polyline data-series="current-valid"/);
  assert.match(status.textContent, /2 older stored scores/);

  context.drawHistory([observed, { ...valid('2026-10-14T12:00:00Z'), hat_score: null },
    valid('2026-10-14T18:00:00Z',0), { ...valid('2026-10-15T00:00:00Z'),configuration_hash:'old' },
    valid('2026-10-15T06:00:00Z'), valid('invalid date')],latest);
  assert.equal((chart.innerHTML.match(/<circle data-series="current-valid"/g)||[]).length,3);
  assert.doesNotMatch(chart.innerHTML, /<polyline|NaN/);
  assert.match(chart.innerHTML, /Current valid score: 0%/);
});
