import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { summariseThreatFoxData, buildBotActivityState, buildDisinformationAlert,
  computeScores, keywordMatches, fetchFimiLite, createHistoryItem } from '../scripts/build_hat.mjs';
import { annotateLegacyHistory, historicalValues, sourceQuality } from '../scripts/lib/quality.mjs';
import { createJsonClient, retryAfterMs } from '../scripts/lib/http.mjs';
const scoring = JSON.parse(await readFile(new URL('../config/scoring.json', import.meta.url)));
const sources = JSON.parse(await readFile(new URL('../config/sources.json', import.meta.url)));
const fimiConfig = JSON.parse(await readFile(new URL('../config/fimi_keywords.json', import.meta.url)));
const reference = new Date('2026-10-14T12:00:00Z');
const ioc = (date, bot = true) => ({ first_seen: date, threat_type: bot ? 'botnet_cc' : 'payload', malware: 'known' });

test('An unavailable export cannot manufacture a 100th-percentile baseline', () => {
  const result = summariseThreatFoxData([ioc('2026-10-14T10:00:00Z')], [ioc('2026-10-14T10:00:00Z')], [], scoring, [], reference);
  assert.equal(result.historical.current_36h_botnet_c2_count, 1);
  assert.equal(result.historical.trailing_36h_botnet_c2_percentile, null);
  assert.equal(buildBotActivityState({ threatfox: result }, scoring).primary_code, 'UNRATED');
});
test('A successful zero in 36 hours remains zero', () => {
  const result = summariseThreatFoxData([], [ioc('2026-10-11T10:00:00Z')], [], scoring, [], reference);
  assert.equal(result.historical.current_36h_botnet_c2_count, 0);
});
test('A valid all-zero baseline does not classify zero C2 reports as busy', () => {
  const keys = ['threatfox_botnet_c2_count_1d','threatfox_botnet_c2_36h'];
  const rows = Array.from({ length: 14 }, (_, i) => ({ generated_at: `2026-09-${String(i + 1).padStart(2,'0')}T12:00:00Z`, scoring_version: '0.2.0',
    metrics: Object.fromEntries(keys.map(key => [key,0])), metric_validity: Object.fromEntries(keys.map(key => [key,'valid'])) }));
  const result = summariseThreatFoxData([],[],[],scoring,rows,reference);
  assert.equal(result.historical.trailing_36h_botnet_c2_percentile,50);
  assert.equal(buildBotActivityState({ threatfox: result },scoring).primary_code,'BIL');
});
test('Unparseable timestamps make a rolling count unavailable', () => {
  const result = summariseThreatFoxData([], [ioc('not a date')], [], scoring, [], reference);
  assert.equal(result.historical.current_36h_botnet_c2_count, null);
});
test('Legacy numbers are retained and excluded from valid baselines', () => {
  const original = { generated_at: '2026-10-01T00:00:00Z', hat_score: 66, metrics: { fimi_lite_score: 0, threatfox_botnet_c2_36h: 100 } };
  const result = annotateLegacyHistory(original);
  assert.deepEqual(result.metrics, original.metrics);
  assert.equal(result.data_quality.state, 'legacy_unverified');
  assert.deepEqual(historicalValues([result], 'threatfox_botnet_c2_36h', { minDays: 1 }).values, []);
});
test('Baselines require distinct days and compare identical windows', () => {
  const keys = ['threatfox_botnet_c2_count_1d','threatfox_botnet_c2_36h','threatfox_ioc_count_1d','threatfox_ioc_count_36h'];
  const rows = Array.from({ length: 14 }, (_, i) => ({ generated_at: `2026-09-${String(i + 1).padStart(2,'0')}T12:00:00Z`, scoring_version: '0.2.0',
    metrics: { threatfox_botnet_c2_count_1d: 20, threatfox_botnet_c2_36h: 100, threatfox_ioc_count_1d: 20, threatfox_ioc_count_36h: 100 }, metric_validity: Object.fromEntries(keys.map(key => [key,'valid'])) }));
  const current = Array.from({ length: 30 }, () => ioc('2026-10-14T10:00:00Z'));
  const result = summariseThreatFoxData(current,current,[],scoring,rows,reference);
  assert.equal(result.historical.current_botnet_c2_percentile,100);
  assert.equal(result.historical.trailing_36h_botnet_c2_percentile,0);
  assert.equal(historicalValues(Array(50).fill(rows[0]),'threatfox_botnet_c2_36h').ready,false);
});
test('Cyber activity cannot raise a narrative alert without narrative evidence', () => {
  const alert = buildDisinformationAlert({ primary_code: 'BAB', basis: { botnet_c2_current_percentile: 100 } }, { level: 'critical' }, scoring,{ score: 0, data_quality: { score_valid: true } });
  assert.equal(alert.level,0);
  assert.equal(buildDisinformationAlert({}, {}, scoring,{ score: null, data_quality: { score_valid: false } }).level,null);
});
test('Missing required cyber inputs cannot appear as a low valid score', () => {
  const score = computeScores({ kev: { recent_7d: null, recent_30d: null, epss_mean_recent_kev: null, epss_enrichment_coverage: 0 }, epss: { hot_global_count: null }, threatfox: {}, fimi_lite: {} },[],scoring,[]);
  assert.equal(score.hat_score,null); assert.equal(score.level,'not_assessable'); assert.equal(score.confidence,'low');
});
test('Short topic words do not match fragments of unrelated words', () => {
  assert.deepEqual(keywordMatches('friendship European Reuters reports',['ship','eu','port']),[]);
  assert.deepEqual(keywordMatches('A ship near the EU port',['ship','eu','port']),['ship','eu','port']);
  assert(fimiConfig.disarm_aligned_tags.every(tag => !/False attribution|Discrediting|fear framing/.test(tag.label)));
});
test('Complete empty queries are a valid zero; failed queries are not', async () => {
  const empty = async () => ({ ok: true, articles: [], raw: '{"articles":[]}', count: 0 });
  const valid = await fetchFimiLite(sources,scoring,fimiConfig,[],null,{ fetchQuery: empty, persistRaw: false });
  assert.equal(valid.score,0); assert.equal(valid.data_quality.score_valid,true);
  const failed = async () => { throw new Error('HTTP 429'); };
  const missing = await fetchFimiLite(sources,scoring,fimiConfig,[],null,{ fetchQuery: failed, persistRaw: false });
  assert.equal(missing.score,null); assert.equal(missing.gdelt.unique_articles_raw,null); assert.equal(missing.data_quality.state,'unavailable');
  const latest = { generated_at: reference.toISOString(), configuration_hash: 'test', hat_score: 50, data_quality: { narrative_score_valid: false }, source_health: missing.source_health,
    metrics: { kev: {}, epss: {}, threatfox: {}, fimi_lite: missing }, bot_activity_state: { primary_code: 'UNRATED' }, narrative_alert_level: { level: null } };
  const history = createHistoryItem(latest);
  assert.equal(history.metrics.fimi_lite_score,null); assert.equal(history.metrics.gdelt_unique_articles_36h,null); assert.equal(history.metric_validity.fimi_lite_score,'unavailable');
});
test('Partial collection retains observations without a complete score', async () => {
  let calls = 0;
  const query = async () => {
    if (++calls > 1) throw new Error('HTTP 429');
    return { ok: true, articles: [{ title: 'German tanker attacked in the Baltic Sea', url: 'https://example.test/ship', domain: 'example.test' }], raw: '{"articles":[]}', count: 1 };
  };
  const result = await fetchFimiLite(sources,scoring,fimiConfig,[],{ metrics: { fimi_lite: { last_successful: { generated_at: '2026-10-12T00:00:00Z', score: 12 } } } },{ fetchQuery: query, persistRaw: false });
  assert.equal(result.score,null); assert.equal(result.gdelt.observed_articles,1); assert.equal(result.gdelt.articles.length,1); assert.equal(result.last_successful.score,12); assert.equal(result.data_quality.state,'partial');
});
test('Retry-After is respected and a long cooldown stops further requests', async () => {
  assert.equal(retryAfterMs('2',0),2000);
  let now = 0, calls = 0; const sleeps = [];
  const request = createJsonClient({ clock: () => now, sleep: async ms => { sleeps.push(ms); now += ms; }, minIntervalMs: 100,
    fetchImpl: async () => ++calls === 1 ? new Response('',{ status: 429, headers: { 'retry-after': '2' } }) : new Response('{"articles":[]}') });
  await request('https://example.test','test'); assert.equal(calls,2); assert(sleeps.some(ms => ms >= 2000));
  let deferredCalls = 0;
  const deferred = createJsonClient({ clock: () => 0, sleep: async () => {}, fetchImpl: async () => { deferredCalls++; return new Response('',{ status: 429, headers: { 'retry-after': '120' } }); } });
  await assert.rejects(deferred('https://example.test','test'),/HTTP 429/);
  await assert.rejects(deferred('https://example.test','test2'),/cooldown/); assert.equal(deferredCalls,1);
});
test('Error objects and HTML cannot become successful empty ArticleLists', async () => {
  for (const raw of ['{"error":"rate limited"}','<html>error</html>']) {
    const request = createJsonClient({ minIntervalMs: 0, fetchImpl: async () => new Response(raw) });
    await assert.rejects(request('https://example.test','test'),/ArticleList|JSON/);
  }
  assert.equal(sourceQuality([{ source: 'gdelt_fimi', status: 'error', queries: 3, ok_queries: 0 }],['gdelt_fimi']).score_valid,false);
});
