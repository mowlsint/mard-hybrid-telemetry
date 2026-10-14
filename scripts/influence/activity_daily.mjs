import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const DAY = 86400000;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const read = async (file, fallback) => {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
};

export function buildDailyActivity(items, coverageHistory, generatedAt, { expectedRuns = 4, retainedDays = 90 } = {}) {
  const now = Date.parse(generatedAt);
  const cutoff = now - retainedDays * DAY;
  const daily = new Map();
  const day = date => {
    if (!daily.has(date)) daily.set(date, { date, complete: Date.parse(date) + DAY <= now, registry_hashes: new Set(), endpoints: new Map() });
    return daily.get(date);
  };
  for (const run of coverageHistory) {
    if (Date.parse(run.generated_at) < cutoff || Date.parse(run.generated_at) > now) continue;
    day(run.generated_at.slice(0, 10));
    for (const source of run.endpoints || []) {
      const checkedAt = source.checked_at || run.generated_at;
      const row = day(checkedAt.slice(0, 10));
      row.registry_hashes.add(run.registry_hash);
      if (!row.endpoints.has(source.key)) row.endpoints.set(source.key, { key: source.key, country: source.country,
        platform: source.platform, successful_runs: 0, expected_runs: expectedRuns, observed_posts: 0,
        shared_fingerprint_posts: 0, items_truncated: false, successful_slots: new Set() });
      const endpoint = row.endpoints.get(source.key);
      if (source.status === 'ok') endpoint.successful_slots.add(Math.floor(new Date(checkedAt).getUTCHours() / 6));
      endpoint.successful_runs = endpoint.successful_slots.size;
      if (source.sample_limit_reached) endpoint.items_truncated = true;
    }
  }
  const published = items.filter(item => item.item_type !== 'website_snapshot' && item.published_at
    && Number.isFinite(Date.parse(item.published_at)) && Date.parse(item.published_at) >= cutoff && Date.parse(item.published_at) <= now);
  const fingerprints = new Map();
  for (const item of published) {
    if (item.content_length >= 40 && item.content_sha256) {
      const key = `${item.published_at.slice(0, 10)}|${item.content_sha256}`;
      const sources = fingerprints.get(key) || new Set();
      sources.add(item.endpoint_id); fingerprints.set(key, sources);
    }
  }
  const seen = new Set();
  for (const item of published) {
    // Exact URLs/native IDs deduplicate repeat collection; identical texts in
    // different sources remain separate observed posts.
    const identity = `${item.endpoint_id}|${item.source_url || item.item_id}|${item.published_at}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    const endpoint = daily.get(item.published_at.slice(0, 10))?.endpoints.get(hash(item.endpoint_id).slice(0, 20));
    if (!endpoint) continue; // Historical posts without crawl coverage are not zero-filled or backfilled.
    endpoint.observed_posts++;
    if ((fingerprints.get(`${item.published_at.slice(0, 10)}|${item.content_sha256}`)?.size || 0) > 1) endpoint.shared_fingerprint_posts++;
  }
  return { schema_version: '1.0.0', generated_at: generatedAt, timezone: 'UTC', expected_runs_per_day: expectedRuns,
    minimum_successful_runs_per_day: 3, retention_days: retainedDays,
    method: 'Published timestamps only; website snapshots and undated observations excluded. Stable source keys are opaque. Coverage starts when actually recorded.',
    days: [...daily.values()].sort((a, b) => a.date.localeCompare(b.date)).map(row => ({ ...row,
      registry_hashes: [...row.registry_hashes], endpoints: [...row.endpoints.values()].map(({ successful_slots, ...endpoint }) => ({ ...endpoint,
        coverage_ratio: Math.min(1, endpoint.successful_runs / expectedRuns) })) })) };
}

export async function recordInfluenceActivity({ registry, items, generatedAt, retainedDays = 90, itemsTruncated = false }) {
  const archivePath = 'data/influence/history/coverage_history.jsonl';
  const archive = await fs.readFile(archivePath, 'utf8').catch(error => { if (error.code === 'ENOENT') return ''; throw error; });
  const previous = archive.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  const files = ['source_health_latest.json', 'social_source_health_latest.json', 'x_source_health_latest.json'];
  const healthBundles = await Promise.all(files.map(file => read(`data/influence/ingest/${file}`, { sources: [] })));
  const entities = new Map((registry.entities || []).map(entity => [entity.actor_id, entity]));
  const health = new Map(healthBundles.flatMap(bundle => (bundle.sources || []).map(source => [source.endpoint_id,
    { ...source, bundle_at: bundle.generated_at }])));
  const endpoints = (registry.endpoints || []).filter(endpoint => endpoint.ingest_enabled).map(endpoint => {
    const source = health.get(endpoint.endpoint_id);
    const at = source?.checked_at || source?.bundle_at;
    const fresh = at && Date.parse(at) <= Date.parse(generatedAt) && Date.parse(generatedAt) - Date.parse(at) < 3 * 3600000;
    const limit = endpoint.platform === 'x' ? Number(process.env.MARD_INFLUENCE_MAX_ITEMS_PER_X_SOURCE || 30)
      : ['youtube', 'bluesky'].includes(endpoint.platform) ? Number(process.env.MARD_INFLUENCE_MAX_ITEMS_PER_SOCIAL_SOURCE || 30)
      : Number(process.env.MARD_INFLUENCE_MAX_ITEMS_PER_SOURCE || 50);
    return { key: hash(endpoint.endpoint_id).slice(0, 20), platform: endpoint.platform,
      country: entities.get(endpoint.actor_id)?.country || 'unknown',
      checked_at: fresh ? at : generatedAt,
      sample_limit_reached: fresh && source.item_count >= limit,
      status: fresh ? source.status : source ? 'stale' : 'not_collected' };
  });
  const snapshot = { generated_at: generatedAt, registry_hash: hash(JSON.stringify(registry)), items_truncated: itemsTruncated, endpoints };
  const cutoff = Date.parse(generatedAt) - retainedDays * DAY;
  const snapshots = [...previous.filter(row => row.generated_at !== generatedAt && Date.parse(row.generated_at) >= cutoff), snapshot];
  const series = buildDailyActivity(items, snapshots, generatedAt, { retainedDays });
  if (itemsTruncated) {
    const publishedTimes = items.map(item => Date.parse(item.published_at)).filter(Number.isFinite);
    const earliest = publishedTimes.length ? new Date(publishedTimes.reduce((value, time) => Math.min(value, time), Infinity)).toISOString().slice(0, 10) : generatedAt.slice(0, 10);
    for (const row of series.days) if (row.date <= earliest) row.complete = false;
    series.item_history_available_since = earliest;
  }
  // A stale retained item bundle must not masquerade as a new publishing run.
  const successful = endpoints.filter(endpoint => endpoint.status === 'ok').length;
  const platforms = Object.fromEntries([...new Set(endpoints.map(endpoint => endpoint.platform))].map(platform => {
    const sources = endpoints.filter(endpoint => endpoint.platform === platform);
    return [platform, { expected_sources: sources.length, successful_sources: sources.filter(source => source.status === 'ok').length,
      state: sources.some(source => source.status === 'ok') ? 'partial_or_best_effort' : 'unavailable' }];
  }));
  const quality = { state: successful ? 'best_effort' : 'unavailable', successful_sources: successful,
    expected_sources: endpoints.length, coverage_ratio: endpoints.length ? successful / endpoints.length : 0,
    platforms, items_truncated: itemsTruncated, comparison_coverage_started_at: snapshots[0]?.generated_at || generatedAt,
    complete_platform_coverage: false, automation_finding: false, disinformation_finding: false };
  await fs.mkdir(path.dirname(archivePath), { recursive: true });
  await fs.mkdir('public/downloads', { recursive: true });
  await fs.writeFile(archivePath, snapshots.map(row => JSON.stringify(row)).join('\n') + '\n');
  await fs.writeFile('public/influence_activity_daily.json', JSON.stringify(series));
  await fs.writeFile('public/downloads/influence_activity_daily.json', JSON.stringify(series));
  const csv = ['date,country,platform,observed_posts,successful_source_runs,expected_source_runs,complete_day'];
  for (const row of series.days) {
    const groups = new Map();
    for (const endpoint of row.endpoints) {
      const key = `${endpoint.country},${endpoint.platform}`;
      const group = groups.get(key) || { posts: 0, successful: 0, expected: 0 };
      group.posts += endpoint.observed_posts; group.successful += endpoint.successful_runs; group.expected += endpoint.expected_runs;
      groups.set(key, group);
    }
    for (const [key, group] of groups) csv.push(`${row.date},${key},${group.posts},${group.successful},${group.expected},${row.complete}`);
  }
  await fs.writeFile('public/downloads/influence_activity_daily.csv', csv.join('\n') + '\n');
  return { quality, series };
}
