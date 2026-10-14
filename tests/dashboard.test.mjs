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
});
