import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const registryPath = path.join(root, 'config/influence/mard_influence_registry_v1.json');

async function fixture(t) {
  const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'mard-ingest-'));
  t.after(() => fs.rm(cwd, { recursive: true, force: true }));
  const write = async (file, value) => {
    const target = path.join(cwd, file);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, typeof value === 'string' ? value : JSON.stringify(value));
  };
  const read = async file => JSON.parse(await fs.readFile(path.join(cwd, file), 'utf8'));
  // Every real collector request is intercepted; the regression suite stays offline.
  await write('offline.mjs', 'globalThis.fetch = async () => new Response("Forbidden", { status: 403 });');
  const run = (script, extra = {}) => spawnSync(process.execPath,
    ['--import', path.join(cwd, 'offline.mjs'), path.join(root, 'scripts/influence', script)],
    { cwd, encoding: 'utf8', timeout: 15000, env: { ...process.env,
      MARD_INFLUENCE_REGISTRY: registryPath, MARD_INFLUENCE_MAX_ENDPOINTS: '2', ...extra } });
  const pass = script => {
    const result = run(script);
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    return result;
  };
  const registry = JSON.parse(await fs.readFile(registryPath, 'utf8'));
  const endpoint = registry.endpoints.find(row => row.platform === 'website' && row.ingest_enabled);
  const actor = registry.entities.find(row => row.actor_id === endpoint.actor_id);
  const now = new Date().toISOString();
  const item = { item_id: 'retained-observation', endpoint_id: endpoint.endpoint_id, actor_id: actor.actor_id,
    country: actor.country, actor_class: actor.actor_class, platform: 'website', item_type: 'feed_item',
    source_stage: 'stage2', source_url: 'https://example.test/retained', source_domain: 'example.test',
    observed_at: now, published_at: now, content_sha256: 'a'.repeat(64), content_simhash64: '0'.repeat(16),
    content_length: 80, referenced_domains: [] };
  await write('data/influence/ingest/items_latest.json', { source_stages: ['stage2'], items: [item] });
  return { cwd, write, read, run, pass, item, now };
}

test('A complete social outage preserves other observations and still builds a valid watch', async t => {
  const f = await fixture(t);
  await f.write('data/influence/ingest/source_health_latest.json', { generated_at: f.now,
    sources: [{ endpoint_id: f.item.endpoint_id, status: 'ok', checked_at: f.now, item_count: 1 }] });
  const run = f.pass('fetch_influence_stage4_social.mjs');
  assert.match(run.stderr, /source_failure .*"platform":"youtube".*"error":"HTTP 403"/);
  assert.match(run.stderr, /source_failure .*"platform":"bluesky".*"error":"HTTP 403"/);
  const status = await f.read('public/influence_social_ingest_status.json');
  assert.equal(status.source_health.state, 'error');
  assert.equal(status.counts.checked_endpoints, 10);
  assert.equal(status.counts.failed_endpoints, 10);
  assert.equal(status.counts.collected_social_items, 0);
  assert.equal((await f.read('data/influence/ingest/items_latest.json')).items[0].item_id, f.item.item_id);
  const health = await f.read('data/influence/ingest/social_source_health_latest.json');
  assert(health.sources.every(source => source.status === 'error' && source.error === 'HTTP 403'));
  f.pass('check_influence_stage4_social.mjs');
  f.pass('build_influence_stage3.mjs');
  f.pass('check_influence_stage3.mjs');
  const watch = await f.read('public/influence_watch_latest.json');
  assert.equal(watch.history.current_run_items, 1);
  assert.equal(watch.data_quality.successful_sources, 1);
  assert.equal(watch.data_quality.platforms.youtube.state, 'unavailable');
  assert.equal(watch.data_quality.platforms.bluesky.state, 'unavailable');
  const daily = await f.read('public/influence_activity_daily.json');
  assert(daily.days.flatMap(day => day.endpoints).filter(source => ['youtube', 'bluesky'].includes(source.platform))
    .every(source => source.successful_runs === 0 && source.coverage_ratio === 0));
});

test('An outage of all collected sources preserves history and publishes an unassessable watch', async t => {
  const f = await fixture(t);
  await f.write('data/influence/history/items_history.jsonl', JSON.stringify(f.item) + '\n');
  const run = f.pass('fetch_influence_stage2.mjs');
  assert.match(run.stderr, /source_failure .*HTTP 403/);
  assert.equal((await f.read('public/influence_ingest_status.json')).source_health.state, 'error');
  f.pass('check_influence_stage2.mjs');
  f.pass('fetch_influence_stage4_social.mjs');
  f.pass('check_influence_stage4_social.mjs');
  f.pass('build_influence_stage3.mjs');
  f.pass('check_influence_stage3.mjs');
  const watch = await f.read('public/influence_watch_latest.json');
  assert.equal(watch.history.total_items, 1);
  assert.equal(watch.history.current_run_items, 0);
  assert.equal(watch.data_quality.successful_sources, 0);
  assert.equal(watch.data_quality.state, 'unavailable');
  assert.equal(watch.level, 'not_assessable');
});

test('Social source tolerance still rejects invalid input and missing files', async t => {
  const f = await fixture(t);
  for (const value of [{ items: {} }, 'invalid JSON', null]) {
    if (value === null) await fs.unlink(path.join(f.cwd, 'data/influence/ingest/items_latest.json'));
    else await f.write('data/influence/ingest/items_latest.json', value);
    const run = f.run('fetch_influence_stage4_social.mjs');
    assert.equal(run.status, 1);
    assert.match(run.stderr, /items array|SyntaxError|ENOENT/);
  }
});
