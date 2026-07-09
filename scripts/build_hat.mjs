import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const ROOT = process.cwd();
const SOURCES_PATH = path.join(ROOT, 'config', 'sources.json');
const SCORING_PATH = path.join(ROOT, 'config', 'scoring.json');
const PUBLIC_DIR = path.join(ROOT, 'public');
const RAW_DIR = path.join(ROOT, 'data', 'raw');
const HISTORY_DIR = path.join(ROOT, 'data', 'history');
const EVIDENCE_DIR = path.join(PUBLIC_DIR, 'evidence_cards');

const now = new Date();
const generatedAt = now.toISOString();
const stamp = generatedAt.replaceAll(':', '').replaceAll('-', '').slice(0, 15);

function clamp(n, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number.isFinite(n) ? n : 0));
}

function daysAgo(dateString) {
  if (!dateString) return Infinity;
  const d = new Date(`${dateString}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return Infinity;
  return (now.getTime() - d.getTime()) / 86400000;
}

function scoreFromCount(count, cap) {
  return clamp((count / cap) * 100);
}

function levelFromScore(score, thresholds) {
  if (score <= thresholds.normal_max) return 'normal';
  if (score <= thresholds.elevated_max) return 'elevated';
  if (score <= thresholds.watch_max) return 'watch';
  if (score <= thresholds.high_max) return 'high';
  return 'critical';
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

async function ensureDirs() {
  for (const dir of [PUBLIC_DIR, RAW_DIR, HISTORY_DIR, EVIDENCE_DIR]) {
    await fs.mkdir(dir, { recursive: true });
  }
}

async function readJson(filePath, fallback = null) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

async function fetchText(url, label, timeoutMs = 30000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: {
        'user-agent': 'mard-hybrid-telemetry/0.1.2 (+public OSINT telemetry; no attribution)'
      },
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJson(url, label) {
  const text = await fetchText(url, label);
  return { json: JSON.parse(text), raw: text, hash: sha256(text) };
}

function chunkArray(items, size) {
  const chunks = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
}

async function fetchCisaKev(sources) {
  const source = sources.sources.cisa_kev;
  if (!source?.enabled) return { ok: false, reason: 'disabled' };
  const { json, raw, hash } = await fetchJson(source.url, 'cisa_kev');
  const rawPath = path.join(RAW_DIR, `cisa_kev_${stamp}.json`);
  await fs.writeFile(rawPath, raw);
  const vulns = Array.isArray(json.vulnerabilities) ? json.vulnerabilities : [];
  return {
    ok: true,
    hash,
    count: vulns.length,
    raw_file: path.relative(ROOT, rawPath),
    vulnerabilities: vulns
  };
}

async function fetchEpssTop(sources) {
  const source = sources.sources.first_epss;
  if (!source?.enabled) return { ok: false, reason: 'disabled' };
  const url = `${source.base_url}?percentile-gt=0.99&order=!epss&limit=250`;
  const { json, raw, hash } = await fetchJson(url, 'first_epss_top');
  const rawPath = path.join(RAW_DIR, `first_epss_top_${stamp}.json`);
  await fs.writeFile(rawPath, raw);
  const data = Array.isArray(json.data) ? json.data : [];
  return {
    ok: true,
    hash,
    count: data.length,
    raw_file: path.relative(ROOT, rawPath),
    data
  };
}

async function fetchEpssForCves(sources, cves) {
  const source = sources.sources.first_epss;
  if (!source?.enabled || cves.length === 0) return { ok: false, reason: 'disabled_or_empty', data: [] };
  const results = [];
  // FIRST supports comma-separated batch queries. Keep chunks conservative for URL length.
  for (const chunk of chunkArray([...new Set(cves)].slice(0, 300), 80)) {
    const url = `${source.base_url}?cve=${encodeURIComponent(chunk.join(','))}`;
    const { json } = await fetchJson(url, 'first_epss_kev_batch');
    if (Array.isArray(json.data)) results.push(...json.data);
  }
  return { ok: true, count: results.length, data: results };
}

async function postThreatFox(source, key, body, label) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  try {
    const res = await fetch(source.url, {
      method: 'POST',
      headers: {
        'Auth-Key': key,
        'content-type': 'application/json',
        'user-agent': 'mard-hybrid-telemetry/0.1.2'
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
    const text = await res.text();
    const json = JSON.parse(text);
    return { json, raw: text, hash: sha256(text) };
  } finally {
    clearTimeout(timer);
  }
}

function asLower(value) {
  return String(value ?? '').toLowerCase();
}

function getThreatFoxFamily(item) {
  return item.malware_printable || item.malware || item.signature || 'unknown';
}

function isThreatFoxBotnetC2(item) {
  const threatType = asLower(item.threat_type);
  const malware = asLower(item.malware || item.malware_printable || item.signature);
  const tags = Array.isArray(item.tags) ? item.tags.map(asLower).join(' ') : asLower(item.tags);
  // ThreatFox commonly uses threat_type values such as botnet_cc and payload_delivery.
  // Keep this conservative: direct botnet/c2 indicators only.
  return threatType.includes('botnet') || tags.includes('botnet') || (tags.includes('c2') && malware !== 'unknown');
}

function topCounts(items, keyFn, limit = 10) {
  const counts = new Map();
  for (const item of items) {
    const key = String(keyFn(item) || 'unknown').trim() || 'unknown';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

function summariseThreatFoxData(data1d, data7d) {
  const day1 = Array.isArray(data1d) ? data1d : [];
  const day7 = Array.isArray(data7d) ? data7d : [];
  const botnet1d = day1.filter(isThreatFoxBotnetC2);
  const botnet7d = day7.filter(isThreatFoxBotnetC2);

  return {
    enabled: true,
    ioc_count_1d: day1.length,
    ioc_count_7d: day7.length,
    botnet_c2_count_1d: botnet1d.length,
    botnet_c2_count_7d: botnet7d.length,
    threat_types_1d: topCounts(day1, x => x.threat_type || 'unknown', 8),
    malware_families_1d: topCounts(day1, getThreatFoxFamily, 10),
    botnet_families_7d: topCounts(botnet7d, getThreatFoxFamily, 10)
  };
}

async function fetchThreatFoxOptional(sources) {
  const source = sources.sources.threatfox;
  const key = process.env.ABUSECH_AUTH_KEY;
  if (!source?.enabled) return { ok: false, status: 'disabled', summary: { enabled: false } };
  if (!key) return { ok: false, status: 'missing_ABUSECH_AUTH_KEY', summary: { enabled: true, missing_secret: true } };

  const oneDay = await postThreatFox(source, key, { query: 'get_iocs', days: 1 }, 'threatfox_iocs_1d');
  const sevenDays = await postThreatFox(source, key, { query: 'get_iocs', days: 7 }, 'threatfox_iocs_7d');

  const raw1d = path.join(RAW_DIR, `threatfox_iocs_1d_${stamp}.json`);
  const raw7d = path.join(RAW_DIR, `threatfox_iocs_7d_${stamp}.json`);
  await fs.writeFile(raw1d, oneDay.raw);
  await fs.writeFile(raw7d, sevenDays.raw);

  const data1d = Array.isArray(oneDay.json.data) ? oneDay.json.data : [];
  const data7d = Array.isArray(sevenDays.json.data) ? sevenDays.json.data : [];
  const summary = summariseThreatFoxData(data1d, data7d);

  return {
    ok: true,
    status: 'ok',
    count: data1d.length,
    count_7d: data7d.length,
    botnet_cc_count: summary.botnet_c2_count_7d,
    hash_1d: oneDay.hash,
    hash_7d: sevenDays.hash,
    raw_files: [path.relative(ROOT, raw1d), path.relative(ROOT, raw7d)],
    summary
  };
}

function summariseKev(kevVulns, epssByCve, scoring) {
  const shortDays = scoring.windows.short_days;
  const mediumDays = scoring.windows.medium_days;
  const recent7 = kevVulns.filter(v => daysAgo(v.dateAdded) <= shortDays);
  const recent30 = kevVulns.filter(v => daysAgo(v.dateAdded) <= mediumDays);

  const epssValues = recent30
    .map(v => Number.parseFloat(epssByCve.get(v.cveID)?.epss ?? '0'))
    .filter(Number.isFinite);

  const epssMeanRecentKev = epssValues.length
    ? epssValues.reduce((a, b) => a + b, 0) / epssValues.length
    : 0;

  const highEpssRecentKev = recent30
    .map(v => ({
      cve: v.cveID,
      vendor_project: v.vendorProject,
      product: v.product,
      vulnerability_name: v.vulnerabilityName,
      date_added: v.dateAdded,
      epss: Number.parseFloat(epssByCve.get(v.cveID)?.epss ?? '0'),
      percentile: Number.parseFloat(epssByCve.get(v.cveID)?.percentile ?? '0')
    }))
    .sort((a, b) => b.epss - a.epss)
    .slice(0, 12);

  return {
    total_kev: kevVulns.length,
    recent_7d: recent7.length,
    recent_30d: recent30.length,
    epss_mean_recent_kev: Number(epssMeanRecentKev.toFixed(4)),
    top_recent_kev_by_epss: highEpssRecentKev
  };
}

function computeScores(metrics, sourceHealth, scoring, previousHistory) {
  const weights = scoring.weights;
  const caps = scoring.caps;
  const thresholds = scoring.thresholds;

  const parts = {
    kev_recent_7d: scoreFromCount(metrics.kev.recent_7d, caps.kev_recent_7d_cap),
    kev_recent_30d: scoreFromCount(metrics.kev.recent_30d, caps.kev_recent_30d_cap),
    epss_hot_global: scoreFromCount(metrics.epss.hot_global_count, caps.epss_hot_count_cap),
    kev_epss_mean: clamp(metrics.kev.epss_mean_recent_kev * 100),
    threatfox_ioc_1d: scoreFromCount(metrics.threatfox.ioc_count_1d || 0, caps.threatfox_ioc_1d_cap),
    threatfox_botnet_c2_7d: scoreFromCount(metrics.threatfox.botnet_c2_count_7d || 0, caps.threatfox_botnet_c2_7d_cap),
    source_coverage: clamp((sourceHealth.filter(s => s.status === 'ok').length / sourceHealth.length) * 100)
  };

  const hatScore = clamp(
    parts.kev_recent_7d * weights.kev_recent_7d +
    parts.kev_recent_30d * weights.kev_recent_30d +
    parts.epss_hot_global * weights.epss_hot_global +
    parts.kev_epss_mean * weights.kev_epss_mean +
    parts.threatfox_ioc_1d * weights.threatfox_ioc_1d +
    parts.threatfox_botnet_c2_7d * weights.threatfox_botnet_c2_7d +
    parts.source_coverage * weights.source_coverage
  );

  const historyScores = Array.isArray(previousHistory) ? previousHistory.map(h => h.hat_score).filter(Number.isFinite) : [];
  const baselineReady = historyScores.length >= scoring.windows.history_points_for_baseline;
  const baselineMean = historyScores.length ? historyScores.reduce((a, b) => a + b, 0) / historyScores.length : null;
  const delta = baselineMean === null ? null : Number((hatScore - baselineMean).toFixed(1));

  return {
    hat_score: Math.round(hatScore),
    level: levelFromScore(hatScore, thresholds),
    confidence: baselineReady ? 'medium' : 'low',
    baseline: {
      status: baselineReady ? 'active' : 'warming_up',
      points: historyScores.length,
      mean_hat_score: baselineMean === null ? null : Number(baselineMean.toFixed(1)),
      delta_from_mean: delta
    },
    score_parts: Object.fromEntries(Object.entries(parts).map(([k, v]) => [k, Math.round(v)]))
  };
}

async function writeEvidenceCard(latest) {
  const card = {
    schema: 'mard-hat-evidence-card-v1',
    generated_at: generatedAt,
    title: 'Daily open-source exploit and IOC-pressure snapshot',
    claim_limit: latest.assessment.claim_limit,
    score: latest.hat_score,
    level: latest.level,
    confidence: latest.confidence,
    drivers: latest.drivers,
    key_metrics: latest.metrics,
    source_health: latest.source_health
  };
  const file = path.join(EVIDENCE_DIR, `${stamp}_open_source_exploit_ioc_pressure.json`);
  await fs.writeFile(file, JSON.stringify(card, null, 2));
  return path.relative(PUBLIC_DIR, file);
}

async function main() {
  await ensureDirs();
  const sources = await readJson(SOURCES_PATH);
  const scoring = await readJson(SCORING_PATH);
  if (!sources || !scoring) throw new Error('Missing config files.');

  const previousHistoryPath = path.join(PUBLIC_DIR, 'hat_history.json');
  const previousHistory = await readJson(previousHistoryPath, []);

  const sourceHealth = [];

  let kev = { ok: false, vulnerabilities: [] };
  try {
    kev = await fetchCisaKev(sources);
    sourceHealth.push({ source: 'cisa_kev', status: kev.ok ? 'ok' : 'disabled', count: kev.count ?? 0, hash: kev.hash ?? null });
  } catch (err) {
    sourceHealth.push({ source: 'cisa_kev', status: 'error', error: String(err.message || err) });
  }

  let epssTop = { ok: false, data: [] };
  try {
    epssTop = await fetchEpssTop(sources);
    sourceHealth.push({ source: 'first_epss_top', status: epssTop.ok ? 'ok' : 'disabled', count: epssTop.count ?? 0, hash: epssTop.hash ?? null });
  } catch (err) {
    sourceHealth.push({ source: 'first_epss_top', status: 'error', error: String(err.message || err) });
  }

  const kevRecentCves = (kev.vulnerabilities || [])
    .filter(v => daysAgo(v.dateAdded) <= scoring.windows.medium_days)
    .map(v => v.cveID)
    .filter(Boolean);

  let epssKev = { ok: false, data: [] };
  try {
    epssKev = await fetchEpssForCves(sources, kevRecentCves);
    sourceHealth.push({ source: 'first_epss_kev_enrichment', status: epssKev.ok ? 'ok' : 'empty_or_disabled', count: epssKev.count ?? 0 });
  } catch (err) {
    sourceHealth.push({ source: 'first_epss_kev_enrichment', status: 'error', error: String(err.message || err) });
  }

  let threatfox = { ok: false, status: 'disabled', summary: { enabled: false } };
  try {
    threatfox = await fetchThreatFoxOptional(sources);
    sourceHealth.push({
      source: 'threatfox_optional',
      status: threatfox.ok ? 'ok' : threatfox.status,
      count: threatfox.count ?? 0,
      count_7d: threatfox.count_7d ?? 0,
      botnet_cc_count: threatfox.botnet_cc_count ?? 0,
      hash_1d: threatfox.hash_1d ?? null,
      hash_7d: threatfox.hash_7d ?? null
    });
  } catch (err) {
    sourceHealth.push({ source: 'threatfox_optional', status: 'error', error: String(err.message || err) });
  }

  const epssByCve = new Map((epssKev.data || []).map(row => [row.cve, row]));
  const kevSummary = summariseKev(kev.vulnerabilities || [], epssByCve, scoring);
  const epssHotGlobal = (epssTop.data || []).length;

  const threatfoxSummary = {
    enabled: Boolean(sources.sources.threatfox?.enabled),
    ...(threatfox.summary || {})
  };

  const metrics = {
    kev: kevSummary,
    epss: {
      hot_global_count: epssHotGlobal,
      top_global: (epssTop.data || []).slice(0, 12).map(x => ({
        cve: x.cve,
        epss: Number.parseFloat(x.epss),
        percentile: Number.parseFloat(x.percentile),
        date: x.date
      }))
    },
    threatfox: threatfoxSummary,
    optional_abusech: {
      threatfox_enabled: Boolean(sources.sources.threatfox?.enabled),
      threatfox_count: threatfoxSummary.ioc_count_1d ?? null,
      botnet_cc_count: threatfoxSummary.botnet_c2_count_7d ?? null
    }
  };

  const score = computeScores(metrics, sourceHealth, scoring, previousHistory);

  const drivers = [];
  drivers.push(`${kevSummary.recent_7d} CISA KEV additions in the last ${scoring.windows.short_days} days`);
  drivers.push(`${kevSummary.recent_30d} CISA KEV additions in the last ${scoring.windows.medium_days} days`);
  drivers.push(`${epssHotGlobal} EPSS entries above the configured hot percentile query window`);
  if (kevSummary.epss_mean_recent_kev > 0) drivers.push(`Mean EPSS of recent KEV items: ${kevSummary.epss_mean_recent_kev}`);
  if (threatfox.ok) {
    drivers.push(`${threatfoxSummary.ioc_count_1d ?? 0} ThreatFox IOCs in the last 1 day`);
    drivers.push(`${threatfoxSummary.botnet_c2_count_7d ?? 0} ThreatFox botnet/C2-like indicators in the last 7 days`);
  } else if (threatfox.status === 'missing_ABUSECH_AUTH_KEY') {
    drivers.push('ThreatFox is enabled but ABUSECH_AUTH_KEY is missing');
  } else if (threatfox.status === 'error') {
    drivers.push('ThreatFox feed error: see source health');
  }
  if (score.baseline.status === 'warming_up') drivers.push(`Baseline warming up: ${score.baseline.points}/${scoring.windows.history_points_for_baseline} prior points available`);

  const latest = {
    schema: 'mard-hat-v0.1.2',
    generated_at: generatedAt,
    window_days: scoring.windows.medium_days,
    hat_score: score.hat_score,
    level: score.level,
    confidence: score.confidence,
    trend: score.baseline.delta_from_mean === null ? 'unknown' : score.baseline.delta_from_mean > 8 ? 'rising' : score.baseline.delta_from_mean < -8 ? 'falling' : 'stable',
    baseline: score.baseline,
    score_parts: score.score_parts,
    metrics,
    drivers,
    source_health: sourceHealth,
    source_health_map: Object.fromEntries(sourceHealth.map(s => [s.source, s.status])),
    assessment: {
      label: 'open-source cyber/exploit and IOC pressure telemetry',
      magic_paws_use: 'contextual indicator only',
      claim_limit: scoring.claim_limit,
      no_attribution: true,
      no_proof_by_itself: true
    },
    links: {
      latest_json: 'hat_latest.json',
      history_json: 'hat_history.json',
      source_health_json: 'hat_source_health.json'
    }
  };

  const evidencePath = await writeEvidenceCard(latest);
  latest.evidence_cards = [evidencePath];

  const newHistoryItem = {
    generated_at: latest.generated_at,
    hat_score: latest.hat_score,
    level: latest.level,
    confidence: latest.confidence,
    trend: latest.trend,
    metrics: {
      kev_recent_7d: latest.metrics.kev.recent_7d,
      kev_recent_30d: latest.metrics.kev.recent_30d,
      epss_hot_global_count: latest.metrics.epss.hot_global_count,
      epss_mean_recent_kev: latest.metrics.kev.epss_mean_recent_kev,
      threatfox_ioc_count_1d: latest.metrics.threatfox.ioc_count_1d ?? 0,
      threatfox_botnet_c2_count_7d: latest.metrics.threatfox.botnet_c2_count_7d ?? 0
    }
  };

  const history = [...(Array.isArray(previousHistory) ? previousHistory : []), newHistoryItem].slice(-120);

  await fs.writeFile(path.join(PUBLIC_DIR, 'hat_latest.json'), JSON.stringify(latest, null, 2));
  await fs.writeFile(path.join(PUBLIC_DIR, 'hat_history.json'), JSON.stringify(history, null, 2));
  await fs.writeFile(path.join(PUBLIC_DIR, 'hat_source_health.json'), JSON.stringify(sourceHealth, null, 2));
  await fs.appendFile(path.join(HISTORY_DIR, 'hat_history.jsonl'), `${JSON.stringify(newHistoryItem)}\n`);

  console.log(`HAT score: ${latest.hat_score} (${latest.level}), confidence: ${latest.confidence}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
