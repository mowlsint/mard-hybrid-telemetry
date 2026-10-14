import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { compareActivity } from '../public/activity_compare.mjs';
import { buildDailyActivity } from '../scripts/influence/activity_daily.mjs';
const endpoint = (key,posts = 10) => ({ key, country: 'RU', platform: 'telegram', coverage_ratio: 1, successful_runs: 4, observed_posts: posts, shared_fingerprint_posts: 0 });
const series = () => ({ generated_at: '2026-10-15T00:00:00Z', days: ['2026-10-10','2026-10-11','2026-10-12','2026-10-13'].map(date => ({ date, complete: true, registry_hashes: ['one'], endpoints: Array.from({ length: 6 },(_,i) => endpoint(String(i))) })) });
test('A collection failure cannot manufacture an activity decline', () => {
  const data = series();
  for (const row of data.days.slice(2)) { row.endpoints[5].coverage_ratio = 0; row.endpoints[5].successful_runs = 0; row.endpoints[5].observed_posts = 0; }
  const result = compareActivity(data,'2026-10-12',2,'RU');
  assert.equal(result.stable_sources,5); assert.equal(result.change_percent,0); assert.equal(result.causal_finding,false);
});
test('A stable covered cohort can show a decline without an automation claim', () => {
  const data = series(); for (const row of data.days.slice(2)) for (const endpoint of row.endpoints) endpoint.observed_posts = 5;
  const result = compareActivity(data,'2026-10-12',2,'RU');
  assert.equal(result.change_percent,-50); assert.equal(result.automation_finding,false); assert.equal(result.disinformation_finding,false);
});
test('Missing days, unfinished days and small cohorts remain unassessable', () => {
  const data = series(); data.days[2].complete = false;
  assert.equal(compareActivity(data,'2026-10-12',2).change_percent,null);
  assert.equal(compareActivity(series(),'2026-10-08',2).status,'insufficient_data');
  const small = series(); for (const row of small.days) row.endpoints = row.endpoints.slice(0,4);
  assert.equal(compareActivity(small,'2026-10-12',2).status,'insufficient_coverage');
  assert.throws(() => compareActivity(series(),'2026-02-30'),/date/);
});
test('An empty observed baseline is not divided by zero', () => {
  const data = series(); for (const row of data.days.slice(0,2)) for (const endpoint of row.endpoints) endpoint.observed_posts = 0;
  assert.equal(compareActivity(data,'2026-10-12',2).change_percent,null);
});
test('Publication timestamps and distinct crawl slots determine daily counts', () => {
  const key = crypto.createHash('sha256').update('source').digest('hex').slice(0,20);
  const runs = [0,1,2].map(i => ({ generated_at: `2026-10-12T01:0${i}:00Z`, registry_hash: 'one', endpoints: [{ key, country: 'RU', platform: 'telegram', status: 'ok' }] }));
  const items = [{ endpoint_id: 'source', item_type: 'telegram_post', published_at: '2026-10-12T03:00:00Z', source_url: 'https://example.test/1', item_id: 'a' },
    { endpoint_id: 'source', item_type: 'website_snapshot', published_at: '2026-10-12T03:00:00Z', item_id: 'b' },
    { endpoint_id: 'source', item_type: 'telegram_post', observed_at: '2026-10-12T03:00:00Z', item_id: 'c' }];
  const result = buildDailyActivity(items,runs,'2026-10-14T00:00:00Z');
  assert.equal(result.days[0].endpoints[0].observed_posts,1); assert.equal(result.days[0].endpoints[0].successful_runs,1);
  assert.equal(result.days[0].endpoints[0].coverage_ratio,0.25); assert.equal(buildDailyActivity(items,[],'2026-10-14T00:00:00Z').days.length,0);
});
test('Repeat collection is deduplicated by publication identity', () => {
  const key = crypto.createHash('sha256').update('source').digest('hex').slice(0,20);
  const runs = [{ generated_at: '2026-10-12T12:00:00Z', registry_hash: 'one', endpoints: [{ key, country: 'RU', platform: 'telegram', status: 'ok' }] }];
  const item = { endpoint_id: 'source', item_type: 'telegram_post', published_at: '2026-10-12T03:00:00Z', source_url: 'https://example.test/1', item_id: 'a' };
  assert.equal(buildDailyActivity([item,{ ...item,item_id: 'new-ingest-id' }],runs,'2026-10-14T00:00:00Z').days[0].endpoints[0].observed_posts,1);
});
