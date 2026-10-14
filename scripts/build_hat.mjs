import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { createJsonClient } from './lib/http.mjs';
import { SCORING_VERSION, annotateLegacyHistory, historicalValues, sourceQuality, narrativeAlert } from './lib/quality.mjs';

const execFileAsync = promisify(execFile);
const ROOT = process.cwd();
const SOURCES_PATH = path.join(ROOT, 'config', 'sources.json');
const SCORING_PATH = path.join(ROOT, 'config', 'scoring.json');
const FIMI_CONFIG_PATH = path.join(ROOT, 'config', 'fimi_keywords.json');
const PUBLIC_DIR = path.join(ROOT, 'public');
const RAW_DIR = path.join(ROOT, 'data', 'raw');
const HISTORY_DIR = path.join(ROOT, 'data', 'history');
const EVIDENCE_DIR = path.join(PUBLIC_DIR, 'evidence_cards');
const DOWNLOADS_DIR = path.join(PUBLIC_DIR, 'downloads');

const now = new Date();
const gdeltClient = createJsonClient();
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
  for (const dir of [PUBLIC_DIR, RAW_DIR, HISTORY_DIR, EVIDENCE_DIR, DOWNLOADS_DIR]) {
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
        'user-agent': 'mard-hybrid-telemetry/0.1.4 (+public OSINT telemetry; no attribution)'
      },
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBinary(url, label, timeoutMs = 90000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: {
        'user-agent': 'mard-hybrid-telemetry/0.1.4 (+public OSINT telemetry; no attribution)'
      },
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
    const ab = await res.arrayBuffer();
    return Buffer.from(ab);
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

async function unzipToText(zipPath) {
  const { stdout } = await execFileAsync('unzip', ['-p', zipPath], {
    maxBuffer: 300 * 1024 * 1024
  });
  return stdout;
}

async function bufferToTextMaybeZip(buffer, storedPath) {
  // ZIP files start with PK. ThreatFox/export endpoints may return either a ZIP
  // or a plain JSON/CSV response depending on the endpoint variant.
  if (buffer.length >= 2 && buffer[0] === 0x50 && buffer[1] === 0x4b) {
    return await unzipToText(storedPath);
  }
  return buffer.toString('utf8');
}

async function fetchCisaKev(sources) {
  const source = sources.sources.cisa_kev;
  if (!source?.enabled) return { ok: false, reason: 'disabled' };
  const { json, raw, hash } = await fetchJson(source.url, 'cisa_kev');
  const rawPath = path.join(RAW_DIR, `cisa_kev_${stamp}.json`);
  await fs.writeFile(rawPath, raw);
  if (!Array.isArray(json.vulnerabilities)) throw new Error('cisa_kev: missing vulnerabilities array');
  const vulns = json.vulnerabilities;
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
  if (!Array.isArray(json.data)) throw new Error('first_epss_top: missing data array');
  const data = json.data;
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
  for (const chunk of chunkArray([...new Set(cves)].slice(0, 300), 80)) {
    const url = `${source.base_url}?cve=${encodeURIComponent(chunk.join(','))}`;
    const { json } = await fetchJson(url, 'first_epss_kev_batch');
    if (!Array.isArray(json.data)) throw new Error('first_epss_kev_batch: missing data array');
    results.push(...json.data);
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
        'user-agent': 'mard-hybrid-telemetry/0.1.4'
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
    const text = await res.text();
    const json = JSON.parse(text);
    if (json.query_status !== 'ok' && json.query_status !== 'no_result') throw new Error(`${label}: unexpected query status`);
    if (json.query_status === 'ok' && !Array.isArray(json.data)) throw new Error(`${label}: missing IOC data array`);
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

function getThreatFoxFirstSeen(item) {
  return item.first_seen || item.first_seen_utc || item.first_seen_utc_timestamp || item.date_added || item.timestamp || item.created_at || null;
}

function parseThreatFoxDate(item) {
  const raw = getThreatFoxFirstSeen(item);
  if (raw === null || raw === undefined || raw === '') return null;
  if (/^\d{10,13}$/.test(String(raw))) {
    const date = new Date(Number(raw) * (String(raw).length === 10 ? 1000 : 1));
    return Number.isNaN(date.getTime()) ? null : date;
  }
  let normalized = String(raw).replace(/ UTC$/i, 'Z').replace(' ', 'T');
  if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(normalized)) normalized += 'Z';
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function isThreatFoxBotnetC2(item) {
  const threatType = asLower(item.threat_type);
  const malware = asLower(item.malware || item.malware_printable || item.signature);
  const tags = Array.isArray(item.tags) ? item.tags.map(asLower).join(' ') : asLower(item.tags);
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


function uniqueBy(items, keyFn) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = keyFn(item);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function stripHtml(value) {
  return String(value ?? '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function buildGdeltUrl(baseUrl, query, timespan, maxrecords = 75) {
  const params = new URLSearchParams({
    query,
    mode: 'artlist',
    format: 'json',
    sort: 'DateDesc',
    maxrecords: String(maxrecords),
    timespan
  });
  return `${baseUrl}?${params.toString()}`;
}

function normaliseGdeltArticle(article, queryLabel = '') {
  const title = stripHtml(article.title || article.name || '');
  const url = article.url || article.link || '';
  const domain = article.domain || article.sourceCommonName || article.source || '';
  const seen = article.seendate || article.date || article.datetime || null;
  return {
    title,
    url,
    domain,
    language: article.language || article.lang || null,
    source_country: article.sourcecountry || article.sourceCountry || null,
    seen_date: seen,
    query: queryLabel
  };
}

function normalizeText(value) {
  return String(value ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9а-яёäöüß\-\.\/\s]/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function keywordMatches(text, keywords = []) {
  const norm = normalizeText(text);
  const matches = [];
  for (const keyword of keywords || []) {
    const k = normalizeText(keyword);
    if (!k) continue;
    const escaped = k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`(?<![\\p{L}\\p{N}])${escaped}(?![\\p{L}\\p{N}])`, 'u').test(norm)) matches.push(keyword);
  }
  return [...new Set(matches)];
}

function classifyMaritimeArticle(article, fimiConfig, scoring) {
  const filter = fimiConfig.maritime_filter || {};
  const weights = scoring.maritime_relevance || {};
  let articlePath = '';
  try { articlePath = decodeURIComponent(new URL(article.url).pathname); } catch {}
  const text = [article.title, articlePath].filter(Boolean).join(' ');
  const domain = normalizeText(article.domain || '');
  const noiseDomains = new Set((filter.noise_domains || []).map(d => normalizeText(d)));
  const maritime = keywordMatches(text, filter.maritime_anchors || []);
  const threat = keywordMatches(text, filter.threat_fimi_anchors || []);
  const region = keywordMatches(text, filter.core_mard_eu_region_anchors || []);
  const spillover = keywordMatches(text, filter.global_maritime_spillover_anchors || []);
  const isNoiseDomain = Boolean(domain && noiseDomains.has(domain));

  const hasMaritimeThreat = maritime.length > 0 && threat.length > 0;
  const isCore = hasMaritimeThreat && region.length > 0 && !isNoiseDomain;
  const isGlobalSpillover = hasMaritimeThreat && !isCore && spillover.length > 0 && !isNoiseDomain;
  const classification = isCore ? 'core_mard_eu' : isGlobalSpillover ? 'global_maritime_spillover' : 'rejected_noise_or_context';
  const weight = isCore ? (weights.core_weight ?? 1.0) : isGlobalSpillover ? (weights.global_spillover_weight ?? 0.4) : 0;
  const reason = isNoiseDomain
    ? 'noise_domain'
    : isCore
      ? 'maritime+threat+regional_anchor'
      : isGlobalSpillover
        ? 'maritime+threat+global_spillover_anchor'
        : 'missing_required_maritime_threat_region_combination';

  return {
    ...article,
    maritime_relevance: {
      accepted: weight > 0,
      classification_basis: 'headline_and_url_path_only',
      classification,
      weight,
      reason,
      matched: { maritime, threat_fimi: threat, region, global_spillover: spillover }
    }
  };
}

function sourceStatusFromResults(enabled, results = []) {
  if (!enabled) return 'disabled';
  const okCount = results.filter(r => r.ok).length;
  const errorCount = results.filter(r => !r.ok).length;
  if (okCount > 0 && errorCount > 0) return 'partial';
  if (okCount > 0) return 'ok';
  if (errorCount > 0) return 'error';
  return 'empty_or_disabled';
}

function statusIsUsable(status) {
  return ['ok', 'partial', 'degraded_with_partial_source_signal'].includes(String(status || ''));
}

async function fetchGdeltArticleQuery(source, query, timespan, maxrecords, label) {
  const url = buildGdeltUrl(source.base_url, query, timespan, maxrecords);
  const { json, raw, attempts } = await gdeltClient(url, label);
  const articles = json.articles.map(a => normaliseGdeltArticle(a, query));
  return { ok: true, query, url, raw, hash: sha256(raw), attempts, count: articles.length, sample_cap_reached: articles.length >= maxrecords, articles };
}

function applyDisarmAlignedTags(items, fimiConfig) {
  const tags = [];
  const text = items.map(item => `${item.title || ''} ${item.domain || ''} ${item.url || ''}`).join(' \n ').toLowerCase();
  for (const tag of fimiConfig.disarm_aligned_tags || []) {
    const matched = keywordMatches(text, tag.keywords || []);
    if (matched.length) {
      tags.push({
        id: tag.id,
        label: tag.label,
        count: matched.length,
        matched_keywords: matched.slice(0, 12)
      });
    }
  }
  return tags.sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

async function fetchFimiLite(sources, scoring, fimiConfig, previousHistory = [], previousLatest = null, { fetchQuery = fetchGdeltArticleQuery, persistRaw = true, configurationHash = null } = {}) {
  const gdeltSource = sources.sources.gdelt;
  const euvsSource = sources.sources.euvsdisinfo;
  const disarmSource = sources.sources.disarm;
  const fimiHealth = [];

  const gdeltQueries = Array.isArray(fimiConfig.maritime_watch_queries) ? fimiConfig.maritime_watch_queries : [];
  const euvsQueries = Array.isArray(fimiConfig.euvsdisinfo_queries) ? fimiConfig.euvsdisinfo_queries : [];

  const gdeltResults = [];
  if (gdeltSource?.enabled) {
    for (const [i, query] of gdeltQueries.entries()) {
      try {
        const r = await fetchQuery(gdeltSource, query, gdeltSource.timespan || '36h', gdeltSource.maxrecords_per_query || 75, `gdelt_fimi_${i + 1}`);
        const rawPath = path.join(RAW_DIR, `gdelt_fimi_${i + 1}_${stamp}.json`);
        if (persistRaw) await fs.writeFile(rawPath, r.raw);
        r.raw_file = path.relative(ROOT, rawPath);
        gdeltResults.push(r);
      } catch (err) {
        gdeltResults.push({ ok: false, query, error: String(err.message || err), articles: [] });
      }
    }
  }

  const rawGdeltArticles = uniqueBy(gdeltResults.flatMap(r => r.articles || []), a => a.url || `${a.title}|${a.domain}`);
  const gdeltClassified = rawGdeltArticles.map(article => classifyMaritimeArticle(article, fimiConfig, scoring));
  const gdeltAccepted = gdeltClassified.filter(a => a.maritime_relevance?.accepted);
  const gdeltCore = gdeltAccepted.filter(a => a.maritime_relevance?.classification === 'core_mard_eu');
  const gdeltSpillover = gdeltAccepted.filter(a => a.maritime_relevance?.classification === 'global_maritime_spillover');
  const gdeltRejected = gdeltClassified.filter(a => !a.maritime_relevance?.accepted);
  const gdeltWeightedCount = gdeltAccepted.reduce((sum, a) => sum + (Number(a.maritime_relevance?.weight) || 0), 0);
  const gdeltStatus = sourceStatusFromResults(Boolean(gdeltSource?.enabled), gdeltResults);
  fimiHealth.push({
    source: 'gdelt_fimi',
    status: gdeltStatus,
    count: gdeltAccepted.length,
    raw_count: rawGdeltArticles.length,
    core_count: gdeltCore.length,
    global_spillover_count: gdeltSpillover.length,
    rejected_count: gdeltRejected.length,
    weighted_count: Number(gdeltWeightedCount.toFixed(2)),
    queries: gdeltQueries.length,
    ok_queries: gdeltResults.filter(r => r.ok).length,
    failed_queries: gdeltResults.filter(r => !r.ok).length,
    errors: gdeltResults.filter(r => !r.ok).map(r => r.error).slice(0, 3)
  });

  const euvsResults = [];
  if (euvsSource?.enabled && gdeltSource?.enabled) {
    for (const [i, query] of euvsQueries.entries()) {
      try {
        const r = await fetchQuery(gdeltSource, query, euvsSource.timespan || '90d', euvsSource.maxrecords_per_query || 50, `euvsdisinfo_case_watch_${i + 1}`);
        const rawPath = path.join(RAW_DIR, `euvsdisinfo_case_watch_${i + 1}_${stamp}.json`);
        if (persistRaw) await fs.writeFile(rawPath, r.raw);
        r.raw_file = path.relative(ROOT, rawPath);
        euvsResults.push(r);
      } catch (err) {
        euvsResults.push({ ok: false, query, error: String(err.message || err), articles: [] });
      }
    }
  }

  const euvsArticles = uniqueBy(euvsResults.flatMap(r => r.articles || []), a => a.url || `${a.title}|${a.domain}`);
  const euvsStatus = sourceStatusFromResults(Boolean(euvsSource?.enabled), euvsResults);
  fimiHealth.push({
    source: 'euvsdisinfo_case_watch',
    status: euvsStatus,
    count: euvsArticles.length,
    queries: euvsQueries.length,
    ok_queries: euvsResults.filter(r => r.ok).length,
    failed_queries: euvsResults.filter(r => !r.ok).length,
    method: 'gdelt_domain_restricted_artlist',
    errors: euvsResults.filter(r => !r.ok).map(r => r.error).slice(0, 3)
  });

  const scoreRelevantFimiArticles = uniqueBy([...gdeltAccepted, ...euvsArticles], a => a.url || `${a.title}|${a.domain}`);
  const disarmTags = disarmSource?.enabled ? applyDisarmAlignedTags(scoreRelevantFimiArticles, fimiConfig) : [];
  fimiHealth.push({
    source: 'disarm_aligned_taxonomy',
    status: !disarmSource?.enabled ? 'disabled' : [gdeltStatus, euvsStatus].every(s => ['ok', 'disabled'].includes(s)) ? 'ok' : 'partial',
    derived: true,
    independent_evidence: false,
    count: disarmTags.length,
    method: 'local_topic_keyword_mapping; no falsehood or TTP finding',
    applied_to_articles: scoreRelevantFimiArticles.length
  });

  const histGdelt = historicalValues(previousHistory, 'gdelt_mard_eu_weighted_articles_36h', { configurationHash }).values;
  const histFimiScore = historicalValues(previousHistory, 'fimi_lite_score', { configurationHash }).values;
  const gdeltPercentile = percentileRank(histGdelt.length >= 14 ? histGdelt : [], gdeltWeightedCount);

  const caps = scoring.caps || {};
  const fimiWeights = scoring.fimi_weights || {};
  const maritimeCfg = scoring.maritime_relevance || {};
  const fallbackMax = caps.fimi_fallback_max_score ?? 65;
  const externalHealth = fimiHealth.filter(s => ['gdelt_fimi', 'euvsdisinfo_case_watch'].includes(s.source));
  const externalErrors = externalHealth.some(s => ['error', 'partial'].includes(s.status));
  const externalOk = externalHealth.some(s => ['ok', 'partial'].includes(s.status));
  const fimiSourceCount = gdeltAccepted.length + euvsArticles.length + disarmTags.length;
  const hasFimiSourceSignal = fimiSourceCount > 0;

  const gdeltScore = gdeltWeightedCount <= 0
    ? 0
    : (gdeltPercentile === null
      ? Math.min(fallbackMax, scoreFromCount(gdeltWeightedCount, maritimeCfg.accepted_article_cap_for_score || caps.gdelt_articles_36h_cap_fallback || 75))
      : gdeltPercentile);
  const euvsScore = euvsArticles.length <= 0 ? 0 : scoreFromCount(euvsArticles.length, caps.euvsdisinfo_cases_90d_cap || 12);
  const disarmScore = disarmTags.length <= 0 ? 0 : scoreFromCount(disarmTags.length, caps.disarm_tags_cap || 8);
  const fimiScoreRaw = clamp(
    gdeltScore * (fimiWeights.gdelt_narrative_pressure ?? 0.45) +
    euvsScore * (fimiWeights.euvsdisinfo_case_signal ?? 0.35) +
    disarmScore * (fimiWeights.disarm_tag_relevance ?? 0.20)
  );
  const quality = sourceQuality(fimiHealth, ['gdelt_fimi', 'euvsdisinfo_case_watch']);
  quality.sample_limited = [...gdeltResults, ...euvsResults].some(r => r.sample_cap_reached);
  const observedScore = hasFimiSourceSignal ? Math.round(fimiScoreRaw) : 0;
  const fimiScore = quality.score_valid ? observedScore : null;
  const previousFimi = previousLatest?.metrics?.fimi_lite;
  const lastSuccessful = quality.score_valid
    ? { generated_at: generatedAt, score: fimiScore, accepted_articles: gdeltAccepted.length }
    : previousFimi?.last_successful || (previousFimi?.source_health && sourceQuality(previousFimi.source_health, ['gdelt_fimi', 'euvsdisinfo_case_watch']).score_valid ? { generated_at: previousLatest.generated_at, score: previousFimi.score, accepted_articles: previousFimi.gdelt?.unique_articles } : null);
  const fimiStatus = externalErrors
    ? (hasFimiSourceSignal ? 'partial' : 'degraded_no_source_signal')
    : (externalOk || hasFimiSourceSignal || disarmSource?.enabled ? 'ok' : 'error_or_disabled');
  const fimiMode = externalErrors && !hasFimiSourceSignal
    ? 'fimi_lite_degraded_no_source_signal'
    : 'fimi_lite_maritime_relevance_filtered';
  const mediumCoreMin = maritimeCfg.min_core_signal_for_medium_confidence ?? 3;
  const mediumTagMin = maritimeCfg.min_disarm_tags_for_medium_confidence ?? 2;
  const confidence = hasFimiSourceSignal && !externalErrors && gdeltCore.length >= mediumCoreMin && disarmTags.length >= mediumTagMin
    ? 'medium'
    : 'low';

  return {
    enabled: Boolean(gdeltSource?.enabled || euvsSource?.enabled || disarmSource?.enabled),
    status: quality.score_valid ? 'ok' : quality.state,
    score: fimiScore,
    observed_partial_score: quality.score_valid ? null : (quality.successful_queries ? observedScore : null),
    data_quality: quality,
    last_successful: lastSuccessful,
    last_successful_age_hours: lastSuccessful ? Number(((now.getTime() - Date.parse(lastSuccessful.generated_at)) / 3600000).toFixed(1)) : null,
    confidence: quality.score_valid && !quality.sample_limited ? confidence : 'low',
    mode: 'maritime_narrative_pressure; not a disinformation determination',
    source_state: {
      external_ok: externalOk,
      external_errors: externalErrors,
      source_signal_present: hasFimiSourceSignal,
      note: externalErrors && !hasFimiSourceSignal
        ? 'GDELT/EUvsDisinfo source access was degraded or rate-limited and no score-relevant maritime FIMI-lite signal was detected.'
        : 'FIMI-lite source state derived from open-source crawl health and score-relevant maritime/FIMI source signals.'
    },
    score_parts: {
      gdelt_narrative_pressure: Math.round(gdeltScore),
      euvsdisinfo_case_signal: Math.round(euvsScore),
      disarm_tag_relevance: Math.round(disarmScore)
    },
    maritime_filter: {
      schema: 'mard-hat-maritime-filter-v1',
      rule: 'score only if headline or URL path contains a maritime anchor and a threat/FIMI anchor; Core MARD-Eu also requires a North/Baltic/Northern Europe anchor; Global Maritime Spillover is retained but down-weighted.',
      raw_unique_articles: rawGdeltArticles.length,
      accepted_articles: gdeltAccepted.length,
      core_mard_eu_articles: gdeltCore.length,
      global_maritime_spillover_articles: gdeltSpillover.length,
      rejected_as_noise_or_broad_context: gdeltRejected.length,
      weighted_article_count: Number(gdeltWeightedCount.toFixed(2)),
      rejected_samples: gdeltRejected.slice(0, maritimeCfg.max_rejected_samples ?? 8).map(a => ({
        title: a.title,
        domain: a.domain,
        reason: a.maritime_relevance?.reason,
        matched: a.maritime_relevance?.matched
      }))
    },
    gdelt: {
      timespan: gdeltSource?.timespan || '36h',
      query_count: gdeltQueries.length,
      article_count: gdeltResults.reduce((a, r) => a + (r.count || 0), 0),
      unique_articles_raw: gdeltStatus === 'ok' ? rawGdeltArticles.length : null,
      unique_articles: gdeltStatus === 'ok' ? gdeltAccepted.length : null,
      observed_articles: rawGdeltArticles.length,
      sample_limited: gdeltResults.some(r => r.sample_cap_reached),
      core_mard_eu_articles: gdeltCore.length,
      global_maritime_spillover_articles: gdeltSpillover.length,
      rejected_articles: gdeltRejected.length,
      weighted_articles: gdeltStatus === 'ok' ? Number(gdeltWeightedCount.toFixed(2)) : null,
      historical_percentile: gdeltPercentile === null ? null : Math.round(gdeltPercentile),
      top_domains: topCounts(gdeltAccepted, a => a.domain || 'unknown', 8),
      sample: gdeltAccepted.slice(0, 20),
      articles: gdeltAccepted.slice(0, scoring.downloads?.fimi_article_limit ?? 500)
    },
    euvsdisinfo: {
      timespan: euvsSource?.timespan || '90d',
      query_count: euvsQueries.length,
      candidate_count: euvsStatus === 'ok' ? euvsArticles.length : null,
      observed_candidates: euvsArticles.length,
      method: 'GDELT domain-restricted ArticleList query for euvsdisinfo.eu',
      sample: euvsArticles.slice(0, 10)
    },
    disarm_aligned: {
      method: 'local transparent keyword mapping; no official DISARM technique IDs claimed',
      tag_count: disarmTags.length,
      tags: disarmTags.slice(0, 12)
    },
    downloads_hint: 'See public/downloads/hat_analyst_bundle_latest.json and public/downloads/fimi_maritime_articles_latest.csv for re-use.',
    source_health: fimiHealth,
    history: {
      gdelt_points: histGdelt.length,
      fimi_score_points: histFimiScore.length
    },
    note: 'FIMI-lite is a legacy field name for maritime narrative pressure. Topic tags do not determine falsehood or DISARM techniques. FIMI-lite is a contextual signal. GDELT measures media/narrative volume after a local maritime relevance filter; EUvsDisinfo provides curated case exposure; DISARM-aligned tags structure observations. This is not attribution-grade.'
  };
}

function percentileRank(values, current) {
  const nums = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!nums.length || !Number.isFinite(current)) return null;
  const below = nums.filter(value => value < current).length;
  const equal = nums.filter(value => value === current).length;
  return clamp(((below + equal / 2) / nums.length) * 100);
}

function dateKey(d) {
  return d.toISOString().slice(0, 10);
}

function extractThreatFoxItems(json) {
  if (Array.isArray(json)) return json;
  if (Array.isArray(json?.data)) return json.data;
  if (Array.isArray(json?.iocs)) return json.iocs;
  if (json && typeof json === 'object') {
    const values = Object.values(json);
    if (values.every(v => v && typeof v === 'object')) return values;
  }
  return [];
}

function parseCsvLine(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i + 1] === '"') {
      cur += '"';
      i++;
    } else if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      out.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

function parseThreatFoxCsv(text) {
  const lines = text.split(/\r?\n/).filter(line => line.trim() && !line.startsWith('#'));
  if (lines.length < 2) return [];
  const header = parseCsvLine(lines[0]).map(h => h.trim());
  return lines.slice(1).map(line => {
    const cols = parseCsvLine(line);
    return Object.fromEntries(header.map((h, i) => [h, cols[i] ?? '']));
  });
}

async function fetchThreatFoxHistoricalExport(source, key, scoring) {
  if (!source?.historical_export_enabled) return { ok: false, status: 'disabled', items: [] };

  const makeCandidates = (kind) => {
    const list = [];
    const plural = source[`export_${kind}_url_templates`];
    const singular = source[`export_${kind}_url_template`];
    if (Array.isArray(plural)) list.push(...plural);
    if (singular) list.push(singular);
    return [...new Set(list)]
      .filter(Boolean)
      .map(template => template.replace('{auth_key}', encodeURIComponent(key)));
  };

  const tryCandidate = async (url, kind) => {
    const buffer = await fetchBinary(url, `threatfox_full_${kind}_export`);
    const ext = url.includes('.zip') ? 'zip' : kind;
    const stored = path.join(RAW_DIR, `threatfox_full_${kind}_${stamp}.${ext}`);
    await fs.writeFile(stored, buffer);
    const text = await bufferToTextMaybeZip(buffer, stored);
    if (kind === 'json') {
      const json = JSON.parse(text);
      const items = extractThreatFoxItems(json);
      if (!items.length) throw new Error('ThreatFox JSON export parsed but returned zero items');
      return {
        ok: true,
        status: 'ok',
        format: url.includes('.zip') ? 'json.zip' : 'json',
        count: items.length,
        hash: sha256(buffer),
        raw_file: path.relative(ROOT, stored),
        items
      };
    }
    const items = parseThreatFoxCsv(text);
    if (!items.length) throw new Error('ThreatFox CSV export parsed but returned zero items');
    return {
      ok: true,
      status: 'ok',
      format: url.includes('.zip') ? 'csv.zip' : 'csv',
      count: items.length,
      hash: sha256(buffer),
      raw_file: path.relative(ROOT, stored),
      items
    };
  };

  const errors = [];
  for (const url of makeCandidates('json')) {
    try {
      return await tryCandidate(url, 'json');
    } catch (err) {
      errors.push(`json:${String(err.message || err)}`);
    }
  }
  for (const url of makeCandidates('csv')) {
    try {
      return await tryCandidate(url, 'csv');
    } catch (err) {
      errors.push(`csv:${String(err.message || err)}`);
    }
  }

  return { ok: false, status: 'error', error: errors.slice(0, 4).join(' | ') || 'no export candidate succeeded', items: [] };
}

function summariseThreatFoxData(data1d, data7d, historicalItems, scoring, previousHistory = [], referenceTime = now) {
  const day1 = Array.isArray(data1d) ? data1d : [];
  const day7 = Array.isArray(data7d) ? data7d : [];
  const botnet1d = day1.filter(isThreatFoxBotnetC2);
  const botnet7d = day7.filter(isThreatFoxBotnetC2);
  const historicalDays = scoring.windows.threatfox_historical_days || 180;
  const botHours = scoring.windows.bot_activity_hours || 36;
  const end = referenceTime.getTime();
  const parse = items => items.map(item => ({ item, date: parseThreatFoxDate(item), bot: isThreatFoxBotnetC2(item) }));
  const recentParsed = parse(day7);
  const timeFilterValid = recentParsed.every(item => item.date && item.date.getTime() <= end);
  const recent = recentParsed.filter(item => item.date && item.date.getTime() <= end);
  const recent36 = recent.filter(item => item.date.getTime() > end - botHours * 3600000);
  const recent36Bot = recent36.filter(item => item.bot);
  const hist = parse(Array.isArray(historicalItems) ? historicalItems : [])
    .filter(item => item.date && item.date.getTime() > end - historicalDays * 86400000 && item.date.getTime() <= end);
  // Never create synthetic zero windows when the historical export is absent.
  // Export and current API counts both use rolling windows ending at this UTC hour.
  const allTimes = hist.map(item => item.date.getTime()).sort((a, b) => a - b);
  const botTimes = hist.filter(item => item.bot).map(item => item.date.getTime()).sort((a, b) => a - b);
  const oldest = allTimes[0] ?? end;
  const upperBound = (values, target) => { let low = 0, high = values.length; while (low < high) { const middle = Math.floor((low + high) / 2); if (values[middle] <= target) low = middle + 1; else high = middle; } return low; };
  const countAt = (at, hours, botsOnly) => { const times = botsOnly ? botTimes : allTimes; return upperBound(times, at) - upperBound(times, at - hours * 3600000); };
  const windows = [];
  for (let at = end - 86400000; at - botHours * 3600000 >= oldest; at -= 86400000) windows.push(at);
  const exportReady = hist.length > 0 && windows.length >= 14;
  const specifications = [
    ['current_ioc_percentile', 'threatfox_ioc_count_1d', day1.length, 24, false],
    ['current_botnet_c2_percentile', 'threatfox_botnet_c2_count_1d', botnet1d.length, 24, true],
    ['trailing_36h_ioc_percentile', 'threatfox_ioc_count_36h', timeFilterValid ? recent36.length : null, botHours, false],
    ['trailing_36h_botnet_c2_percentile', 'threatfox_botnet_c2_36h', timeFilterValid ? recent36Bot.length : null, botHours, true]
  ];
  const percentiles = {};
  const baseline = {};
  for (const [name, metric, current, hours, botsOnly] of specifications) {
    const local = historicalValues(previousHistory, metric);
    const values = exportReady ? windows.map(at => countAt(at, hours, botsOnly)) : local.values;
    percentiles[name] = percentileRank(values, current);
    baseline[name] = { source: exportReady ? 'historical_export' : local.ready ? 'valid_local_daily_history' : 'unavailable', days: exportReady ? windows.length : local.days, window_hours: hours };
  }
  return {
    enabled: true, ioc_count_1d: day1.length, ioc_count_7d: day7.length,
    botnet_c2_count_1d: botnet1d.length, botnet_c2_count_7d: botnet7d.length,
    threat_types_1d: topCounts(day1, item => item.threat_type || 'unknown', 8),
    malware_families_1d: topCounts(day1, getThreatFoxFamily, 10),
    botnet_families_7d: topCounts(botnet7d, getThreatFoxFamily, 10),
    historical: {
      status: exportReady ? 'active' : 'warming_up_or_unavailable',
      method: exportReady ? 'same_utc_hour_rolling_export_windows' : 'recent_7d_api_plus_valid_local_history',
      fallback_limited: !exportReady, window_days: historicalDays,
      source_items: hist.length, days_with_iocs: new Set(hist.map(item => dateKey(item.date))).size,
      bot_activity_hours: botHours, time_filter_valid: timeFilterValid,
      current_36h_ioc_count: timeFilterValid ? recent36.length : null,
      current_36h_botnet_c2_count: timeFilterValid ? recent36Bot.length : null,
      ...Object.fromEntries(Object.entries(percentiles).map(([key, value]) => [key, value === null ? null : Math.round(value)])),
      percentile_baselines: baseline
    }
  };
}

async function fetchThreatFoxOptional(sources, scoring, previousHistory) {
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
  let exportResult;
  try { exportResult = await fetchThreatFoxHistoricalExport(source, key, scoring); }
  catch (error) { exportResult = { ok: false, status: 'error', error: String(error.message || error), items: [] }; }
  const data1d = oneDay.json.data || [];
  const data7d = sevenDays.json.data || [];
  const summary = summariseThreatFoxData(data1d, data7d, exportResult.items, scoring, previousHistory);
  return { ok: true, status: exportResult.ok ? 'ok' : 'partial',
    count: data1d.length, count_7d: data7d.length, botnet_cc_count: summary.botnet_c2_count_7d,
    hash_1d: oneDay.hash, hash_7d: sevenDays.hash, export_status: exportResult.status,
    export_count: exportResult.count ?? 0, export_format: exportResult.format ?? null,
    export_hash: exportResult.hash ?? null, export_error: exportResult.error ?? null,
    raw_files: [path.relative(ROOT, raw1d), path.relative(ROOT, raw7d)].concat(exportResult.raw_file ? [exportResult.raw_file] : []), summary };
}

function summariseKev(kevVulns, epssByCve, scoring) {
  const recent7 = kevVulns.filter(item => daysAgo(item.dateAdded) <= scoring.windows.short_days);
  const recent30 = kevVulns.filter(item => daysAgo(item.dateAdded) <= scoring.windows.medium_days);
  const epssValues = recent30.map(item => Number.parseFloat(epssByCve.get(item.cveID)?.epss)).filter(Number.isFinite);
  return { total_kev: kevVulns.length, recent_7d: recent7.length, recent_30d: recent30.length,
    epss_mean_recent_kev: epssValues.length ? Number((epssValues.reduce((a, b) => a + b, 0) / epssValues.length).toFixed(4)) : recent30.length ? null : 0,
    epss_enriched_count: epssValues.length,
    epss_enrichment_coverage: recent30.length ? epssValues.length / recent30.length : 1,
    top_recent_kev_by_epss: recent30.map(item => ({ cve: item.cveID, vendor_project: item.vendorProject, product: item.product, vulnerability_name: item.vulnerabilityName,
      date_added: item.dateAdded, epss: Number.isFinite(Number.parseFloat(epssByCve.get(item.cveID)?.epss)) ? Number.parseFloat(epssByCve.get(item.cveID)?.epss) : null }))
      .sort((a, b) => (b.epss ?? -1) - (a.epss ?? -1)).slice(0, 12) };
}

function fallbackThreatFoxScore(value, cap, maxScore = 65) {
  return Number.isFinite(value) ? Math.min(maxScore, scoreFromCount(value, cap)) : null;
}

function sourceHealthWeight(status, scoring) {
  const weights = scoring.health_weights || { ok: 1, partial: 0.5, degraded: 0.35, error: 0, disabled: 0 };
  const key = String(status || '').toLowerCase();
  if (Object.prototype.hasOwnProperty.call(weights, key)) return Number(weights[key]) || 0;
  if (key.startsWith('degraded')) return Number(weights.degraded ?? 0.35);
  if (key.includes('partial')) return Number(weights.partial ?? 0.5);
  if (key.includes('error')) return Number(weights.error ?? 0);
  return 0;
}

function sourceCoverageScore(sourceHealth, scoring) {
  const items = Array.isArray(sourceHealth) ? sourceHealth.filter(s => s && s.status !== 'disabled' && !s.derived) : [];
  if (!items.length) return 0;
  const total = items.reduce((sum, s) => sum + sourceHealthWeight(s.status, scoring), 0);
  return clamp((total / items.length) * 100);
}

function scoreBand(score) {
  if (!Number.isFinite(score)) return { label: 'not_assessable', color: 'grey', css: 'unknown', meaning: 'required source data unavailable' };
  const s = score;
  if (s <= 20) return { label: 'normal', color: 'green', css: 'normal', meaning: 'low contextual pressure' };
  if (s <= 40) return { label: 'elevated', color: 'yellow', css: 'elevated', meaning: 'elevated contextual pressure' };
  if (s <= 60) return { label: 'watch', color: 'orange', css: 'watch', meaning: 'watch-level contextual pressure' };
  if (s <= 80) return { label: 'high', color: 'deep orange', css: 'high', meaning: 'high contextual pressure' };
  return { label: 'critical', color: 'red', css: 'critical', meaning: 'critical contextual pressure' };
}

function buildObscurationContext(latestLike, scoring) {
  const score = latestLike.hat_score ?? 0;
  const bot = latestLike.bot_activity_state || {};
  const fimi = latestLike.metrics?.fimi_lite || {};
  const maritime = fimi.maritime_filter || {};
  const threatfox = latestLike.metrics?.threatfox || {};
  const sourceHealth = latestLike.source_health || [];
  const partialSources = sourceHealth.filter(s => ['partial', 'error'].includes(String(s.status || ''))).map(s => s.source);
  const signals = [];
  if (bot.primary_code === 'BAB') signals.push('current bot/IOC proxy telemetry is elevated (BAB)');
  if (bot.primary_code === 'BWB') signals.push('trailing bot/IOC proxy telemetry was elevated recently (BWB)');
  if ((threatfox.historical?.current_36h_botnet_c2_count ?? 0) > 0) signals.push(`${threatfox.historical.current_36h_botnet_c2_count} botnet/C2-like indicators in the current 36h window`);
  if ((maritime.core_mard_eu_articles ?? 0) > 0) signals.push(`${maritime.core_mard_eu_articles} score-relevant Core MARD-Eu maritime/FIMI articles`);
  if ((maritime.global_maritime_spillover_articles ?? 0) > 0) signals.push(`${maritime.global_maritime_spillover_articles} Global Maritime Spillover articles retained with lower weight`);
  if (partialSources.length) signals.push(`partial/degraded source access: ${partialSources.join(', ')}`);

  let level = !Number.isFinite(latestLike.hat_score) && !Number.isFinite(fimi.score) ? 'not_assessable' : 'low';
  if (bot.primary_code === 'BAB' && ((maritime.core_mard_eu_articles ?? 0) > 0 || (fimi.score ?? 0) >= 45)) level = 'watch';
  if (score >= 80 && bot.primary_code === 'BAB' && (maritime.core_mard_eu_articles ?? 0) >= 8) level = 'high';

  return {
    schema: 'mard-hat-obscuration-context-v1',
    level,
    signals,
    explanation: 'This is not proof that botnets or narratives are intentionally hiding maritime events. It marks conditions compatible with information fog or obscuration: elevated botnet/C2 proxy telemetry can support access, spam, amplification or disruption infrastructure, while broad narrative volume can bury or blur maritime/security signals. Source rate-limits or partial fetches can add analytical blind spots.',
    claim_limit: 'Context only. No attribution, no proof of coordination, and no proof of sabotage or disinformation by itself.'
  };
}

function computeScores(metrics, sourceHealth, scoring, previousHistory, configurationHash = null) {
  const { weights, caps, thresholds } = scoring;
  const hist = metrics.threatfox?.historical || {};
  const bySource = name => sourceHealth.find(item => item.source === name);
  const kevValid = bySource('cisa_kev')?.status === 'ok';
  const threatfoxValid = ['ok', 'partial'].includes(bySource('threatfox_optional')?.status);
  const epssValid = kevValid && Number.isFinite(metrics.kev.epss_mean_recent_kev) && metrics.kev.epss_enrichment_coverage >= 0.8;
  const maximum = hist.status === 'active' ? 100 : caps.threatfox_fallback_max_score ?? 65;
  const iocScore = Number.isFinite(hist.current_ioc_percentile) ? Math.min(maximum, hist.current_ioc_percentile)
    : fallbackThreatFoxScore(metrics.threatfox.ioc_count_1d, caps.threatfox_ioc_1d_cap_fallback, maximum);
  const botScore = Number.isFinite(hist.trailing_36h_botnet_c2_percentile) ? Math.min(maximum, hist.trailing_36h_botnet_c2_percentile)
    : fallbackThreatFoxScore(hist.current_36h_botnet_c2_count, caps.threatfox_botnet_c2_36h_cap_fallback, maximum);
  const parts = {
    kev_recent_7d: kevValid ? scoreFromCount(metrics.kev.recent_7d, caps.kev_recent_7d_cap) : null,
    kev_recent_30d: kevValid ? scoreFromCount(metrics.kev.recent_30d, caps.kev_recent_30d_cap) : null,
    kev_epss_mean: epssValid ? clamp(metrics.kev.epss_mean_recent_kev * 100) : null,
    threatfox_ioc_current: threatfoxValid ? iocScore : null,
    threatfox_botnet_c2_36h: threatfoxValid ? botScore : null
  };
  const complete = Object.entries(parts).every(([key, value]) => !weights[key] || Number.isFinite(value));
  const knownParts = Object.values(parts).filter(Number.isFinite).length;
  const observed = Object.entries(parts).reduce((sum, [key, value]) => sum + (Number.isFinite(value) ? value * (weights[key] || 0) : 0), 0);
  const score = complete ? Math.round(clamp(observed)) : null;
  const contextParts = { epss_hot_global: bySource('first_epss_top')?.status === 'ok' ? scoreFromCount(metrics.epss.hot_global_count, caps.epss_hot_count_cap) : null,
    source_coverage: sourceCoverageScore(sourceHealth, scoring) };
  const history = historicalValues(previousHistory, 'hat_score', { configurationHash });
  const mean = history.ready ? history.values.reduce((a, b) => a + b, 0) / history.values.length : null;
  const delta = Number.isFinite(score) && Number.isFinite(mean) ? Number((score - mean).toFixed(1)) : null;
  return { hat_score: score, observed_partial_score: complete || !knownParts ? null : Math.round(observed),
    level: Number.isFinite(score) ? levelFromScore(score, thresholds) : 'not_assessable',
    score_interpretation: { percentage: score, ...scoreBand(score), scale: '0-100 contextual pressure; not probability' },
    confidence: complete && history.ready && hist.status === 'active' && metrics.kev.epss_enrichment_coverage === 1 ? 'medium' : 'low',
    data_quality: { state: complete ? 'valid' : knownParts ? 'partial' : 'unavailable', cyber_score_valid: complete,
      narrative_score_valid: Boolean(metrics.fimi_lite?.data_quality?.score_valid),
      missing_score_parts: Object.keys(parts).filter(key => weights[key] && !Number.isFinite(parts[key])),
      threatfox_baseline_limited: hist.status !== 'active' },
    baseline: { status: history.ready ? 'active' : 'warming_up', points: history.days, minimum_days: 14,
      mean_hat_score: mean === null ? null : Number(mean.toFixed(1)), delta_from_mean: delta },
    score_parts: Object.fromEntries(Object.entries(parts).map(([key, value]) => [key, Number.isFinite(value) ? Math.round(value) : null])), context_parts: contextParts };
}

function buildBotActivityState(metrics, scoring) {
  const history = metrics.threatfox?.historical || {};
  const current = history.current_botnet_c2_percentile;
  const trailing = history.trailing_36h_botnet_c2_percentile;
  const threshold = scoring.bot_activity?.busy_percentile ?? 75;
  const code = !Number.isFinite(current) || !Number.isFinite(trailing) ? 'UNRATED'
    : current >= threshold ? 'BAB' : trailing >= threshold ? 'BWB' : 'BIL';
  return { schema: 'mard-hat-c2-state-v2', primary_code: code,
    primary_number: code === 'UNRATED' ? null : code === 'BAB' ? 2 : code === 'BWB' ? 1 : 0,
    primary_label: { UNRATED: 'Baseline unavailable', BAB: 'Current C2 indicator pressure elevated', BWB: 'Recent C2 indicator pressure elevated', BIL: 'C2 indicators below threshold' }[code],
    confidence: code === 'UNRATED' ? 'unavailable' : history.status === 'active' ? 'medium' : 'low',
    finding: 'reported malware infrastructure indicators; no social-bot or attribution finding',
    basis: { threshold_percentile: threshold, ioc_current_percentile: history.current_ioc_percentile ?? null,
      botnet_c2_current_percentile: current ?? null, ioc_36h_percentile: history.trailing_36h_ioc_percentile ?? null,
      botnet_c2_36h_percentile: trailing ?? null, ioc_36h_count: history.current_36h_ioc_count ?? null,
      botnet_c2_36h_count: history.current_36h_botnet_c2_count ?? null, percentile_baselines: history.percentile_baselines || {} } };
}

function buildDisinformationAlert(botActivityState, score, scoring, fimiLite = null) {
  return narrativeAlert(fimiLite, scoring.disinformation_alert || {});
}

async function writeEvidenceCard(latest) {
  const card = { schema: 'mard-hat-evidence-card-v2', generated_at: generatedAt,
    scoring_version: SCORING_VERSION, title: 'Cyber/C2 and maritime narrative snapshot',
    claim_limit: latest.assessment.claim_limit, score: latest.hat_score, level: latest.level,
    confidence: latest.confidence, data_quality: latest.data_quality,
    bot_activity_state: latest.bot_activity_state, narrative_alert_level: latest.narrative_alert_level,
    drivers: latest.drivers, key_metrics: latest.metrics, source_health: latest.source_health };
  const file = path.join(EVIDENCE_DIR, `${stamp}_open_source_exploit_ioc_botstate_pressure.json`);
  await fs.writeFile(file, JSON.stringify(card, null, 2));
  return path.relative(PUBLIC_DIR, file);
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

async function writeAnalystDownloads(latest) {
  await fs.mkdir(DOWNLOADS_DIR, { recursive: true });
  const fimi = latest.metrics?.fimi_lite || {};
  const accepted = Array.isArray(fimi.gdelt?.articles) ? fimi.gdelt.articles : fimi.gdelt?.sample || [];
  const bundle = {
    schema: 'mard-hat-analyst-download-bundle-v1',
    generated_at: latest.generated_at,
    scoring_version: SCORING_VERSION,
    data_quality: latest.data_quality,
    created_for: 'analyst re-use; no secrets; no raw Auth-Key material',
    score: {
      hat_score: latest.hat_score,
      level: latest.level,
      interpretation: latest.score_interpretation,
      trend: latest.trend,
      confidence: latest.confidence,
      baseline: latest.baseline,
      score_parts: latest.score_parts,
      context_parts: latest.context_parts
    },
    bot_activity_state: latest.bot_activity_state,
    disinformation_alert_level: latest.disinformation_alert_level,
    obscuration_context: latest.obscuration_context,
    maritime_fimi: {
      score: fimi.score ?? null,
      data_quality: fimi.data_quality,
      last_successful: fimi.last_successful,
      confidence: fimi.confidence ?? 'low',
      mode: fimi.mode ?? null,
      maritime_filter: fimi.maritime_filter ?? null,
      gdelt_summary: fimi.gdelt ?? null,
      euvsdisinfo_summary: fimi.euvsdisinfo ?? null,
      disarm_aligned: fimi.disarm_aligned ?? null
    },
    threatfox_summary: latest.metrics?.threatfox ?? null,
    kev_summary: latest.metrics?.kev ?? null,
    source_health: latest.source_health,
    drivers: latest.drivers,
    assessment: latest.assessment,
    evidence_cards: latest.evidence_cards || []
  };
  await fs.writeFile(path.join(DOWNLOADS_DIR, 'hat_analyst_bundle_latest.json'), JSON.stringify(bundle, null, 2));

  const rows = accepted.map(article => ({
    classification: article.maritime_relevance?.classification || '',
    weight: article.maritime_relevance?.weight ?? '',
    reason: article.maritime_relevance?.reason || '',
    title: article.title || '',
    domain: article.domain || '',
    language: article.language || '',
    source_country: article.source_country || '',
    seen_date: article.seen_date || '',
    maritime_matches: (article.maritime_relevance?.matched?.maritime || []).join('|'),
    threat_fimi_matches: (article.maritime_relevance?.matched?.threat_fimi || []).join('|'),
    region_matches: (article.maritime_relevance?.matched?.region || []).join('|'),
    global_spillover_matches: (article.maritime_relevance?.matched?.global_spillover || []).join('|'),
    url: article.url || ''
  }));
  const headers = ['classification','weight','reason','title','domain','language','source_country','seen_date','maritime_matches','threat_fimi_matches','region_matches','global_spillover_matches','url'];
  const csv = [headers.join(','), ...rows.map(row => headers.map(h => csvEscape(row[h])).join(','))].join('\n') + '\n';
  await fs.writeFile(path.join(DOWNLOADS_DIR, 'fimi_maritime_articles_latest.csv'), csv);
  await fs.writeFile(path.join(DOWNLOADS_DIR, 'fimi_maritime_articles_latest.json'), JSON.stringify(accepted, null, 2));

  const shHeaders = ['source','status','count','raw_count','core_count','global_spillover_count','rejected_count','ok_queries','failed_queries','errors'];
  const shCsv = [shHeaders.join(','), ...(latest.source_health || []).map(row => shHeaders.map(h => csvEscape(h === 'errors' ? (row.errors || []).join('|') : row[h])).join(','))].join('\n') + '\n';
  await fs.writeFile(path.join(DOWNLOADS_DIR, 'source_health_latest.csv'), shCsv);
  await fs.writeFile(path.join(DOWNLOADS_DIR, 'README_downloads.txt'), [
    'MARD-HAT analyst downloads',
    '',
    'hat_analyst_bundle_latest.json: compact machine-readable bundle for re-use.',
    'fimi_maritime_articles_latest.csv/json: all accepted sampled maritime narrative articles after local post-filtering.',
    'source_health_latest.csv: source status with partial/error details.',
    '',
    'Claim limit: contextual telemetry only. No attribution and no proof of sabotage, disinformation, hybrid activity, or state involvement by itself.'
  ].join('\n'));
  return {
    analyst_bundle: 'downloads/hat_analyst_bundle_latest.json',
    fimi_maritime_csv: 'downloads/fimi_maritime_articles_latest.csv',
    fimi_maritime_json: 'downloads/fimi_maritime_articles_latest.json',
    source_health_csv: 'downloads/source_health_latest.csv',
    download_readme: 'downloads/README_downloads.txt'
  };
}

function createHistoryItem(latest) {
  const health = latest.source_health || [];
  const state = name => health.find(row => row.source === name)?.status;
  const fox = ['ok', 'partial'].includes(state('threatfox_optional'));
  const gdelt = state('gdelt_fimi') === 'ok';
  const euvs = state('euvsdisinfo_case_watch') === 'ok';
  const fimi = latest.metrics.fimi_lite;
  const metrics = {
    kev_recent_7d: latest.metrics.kev.recent_7d, kev_recent_30d: latest.metrics.kev.recent_30d,
    epss_hot_global_count: latest.metrics.epss.hot_global_count, epss_mean_recent_kev: latest.metrics.kev.epss_mean_recent_kev,
    threatfox_ioc_count_1d: latest.metrics.threatfox.ioc_count_1d ?? null,
    threatfox_ioc_count_36h: latest.metrics.threatfox.historical?.current_36h_ioc_count ?? null,
    threatfox_botnet_c2_count_1d: latest.metrics.threatfox.botnet_c2_count_1d ?? null,
    threatfox_botnet_c2_count_7d: latest.metrics.threatfox.botnet_c2_count_7d ?? null,
    threatfox_botnet_c2_36h: latest.metrics.threatfox.historical?.current_36h_botnet_c2_count ?? null,
    threatfox_ioc_current_percentile: latest.metrics.threatfox.historical?.current_ioc_percentile ?? null,
    threatfox_botnet_c2_36h_percentile: latest.metrics.threatfox.historical?.trailing_36h_botnet_c2_percentile ?? null,
    fimi_lite_score: fimi.score, gdelt_unique_articles_36h: gdelt ? fimi.gdelt?.unique_articles_raw ?? null : null,
    gdelt_mard_eu_weighted_articles_36h: gdelt ? fimi.gdelt?.weighted_articles ?? null : null,
    gdelt_core_mard_eu_articles_36h: gdelt ? fimi.gdelt?.core_mard_eu_articles ?? null : null,
    gdelt_global_spillover_articles_36h: gdelt ? fimi.gdelt?.global_maritime_spillover_articles ?? null : null,
    euvsdisinfo_case_candidates_90d: euvs ? fimi.euvsdisinfo?.candidate_count ?? null : null,
    disarm_aligned_tag_count: fimi.data_quality?.score_valid ? fimi.disarm_aligned?.tag_count ?? 0 : null
  };
  const valid = key => key.startsWith('threatfox_') ? fox : key.startsWith('gdelt_') ? gdelt
    : key.startsWith('euvs') ? euvs : ['fimi_lite_score', 'disarm_aligned_tag_count'].includes(key) ? fimi.data_quality?.score_valid
    : key.startsWith('kev_') ? state('cisa_kev') === 'ok' : key === 'epss_hot_global_count' ? state('first_epss_top') === 'ok'
    : latest.metrics.kev.epss_enrichment_coverage >= 0.8;
  return { generated_at: latest.generated_at, scoring_version: SCORING_VERSION,
    configuration_hash: latest.configuration_hash, hat_score: latest.hat_score, level: latest.level,
    confidence: latest.confidence, trend: latest.trend, data_quality: latest.data_quality,
    source_health: health, metric_validity: Object.fromEntries(Object.keys(metrics).map(key => [key, valid(key) && Number.isFinite(metrics[key]) ? 'valid' : 'unavailable'])),
    bot_activity_state: latest.bot_activity_state.primary_code,
    disinformation_alert_level: latest.narrative_alert_level.level, metrics };
}

async function main() {
  await ensureDirs();
  const sources = await readJson(SOURCES_PATH);
  const scoring = await readJson(SCORING_PATH);
  const fimiConfig = await readJson(FIMI_CONFIG_PATH, { maritime_watch_queries: [], euvsdisinfo_queries: [], disarm_aligned_tags: [] });
  if (!sources || !scoring) throw new Error('Missing config files.');
  const configurationHash = sha256(JSON.stringify({ sources, scoring, fimiConfig }));

  const previousHistoryPath = path.join(PUBLIC_DIR, 'hat_history.json');
  const previousPublicHistory = await readJson(previousHistoryPath, []);
  const archived = await fs.readFile(path.join(HISTORY_DIR, 'hat_history.jsonl'), 'utf8').catch(() => '');
  const archivedHistory = archived.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  const previousHistory = [...new Map([...archivedHistory, ...previousPublicHistory].map(row => [row.generated_at, annotateLegacyHistory(row)])).values()].sort((a, b) => a.generated_at.localeCompare(b.generated_at));
  const previousLatest = await readJson(path.join(PUBLIC_DIR, 'hat_latest.json'), null);

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
    sourceHealth.push({ source: 'first_epss_kev_enrichment', status: epssKev.ok || (kev.ok && kevRecentCves.length === 0) ? 'ok' : 'empty_or_disabled', count: epssKev.count ?? 0 });
  } catch (err) {
    sourceHealth.push({ source: 'first_epss_kev_enrichment', status: 'error', error: String(err.message || err) });
  }

  let threatfox = { ok: false, status: 'disabled', summary: { enabled: false } };
  try {
    threatfox = await fetchThreatFoxOptional(sources, scoring, previousHistory);
    sourceHealth.push({
      source: 'threatfox_optional',
      status: threatfox.status,
      recent_api_status: threatfox.ok ? 'ok' : threatfox.status,
      count: threatfox.count ?? 0,
      count_7d: threatfox.count_7d ?? 0,
      botnet_cc_count: threatfox.botnet_cc_count ?? 0,
      historical_export_status: threatfox.export_status ?? null,
      historical_export_count: threatfox.export_count ?? 0,
      historical_export_format: threatfox.export_format ?? null,
      hash_1d: threatfox.hash_1d ?? null,
      hash_7d: threatfox.hash_7d ?? null,
      export_hash: threatfox.export_hash ?? null,
      export_error: threatfox.export_error ?? null
    });
  } catch (err) {
    sourceHealth.push({ source: 'threatfox_optional', status: 'error', error: String(err.message || err) });
  }


  let fimiLite = { enabled: false, status: 'disabled', score: null, data_quality: { score_valid: false }, source_health: [] };
  try {
    fimiLite = await fetchFimiLite(sources, scoring, fimiConfig, previousHistory, previousLatest, { configurationHash });
    sourceHealth.push(...(fimiLite.source_health || []));
  } catch (err) {
    fimiLite = { enabled: true, status: 'error', score: null, data_quality: { score_valid: false }, source_health: [{ source: 'fimi_lite', status: 'error', error: String(err.message || err) }] };
    sourceHealth.push(...fimiLite.source_health);
  }

  const epssByCve = new Map((epssKev.data || []).map(row => [row.cve, row]));
  const kevSummary = summariseKev(kev.vulnerabilities || [], epssByCve, scoring);
  if (!kev.ok) Object.assign(kevSummary, { total_kev: null, recent_7d: null, recent_30d: null, epss_mean_recent_kev: null });
  const enrichmentHealth = sourceHealth.find(row => row.source === 'first_epss_kev_enrichment');
  if (enrichmentHealth) enrichmentHealth.coverage_ratio = kev.ok ? kevSummary.epss_enrichment_coverage : 0;
  const epssHotGlobal = (epssTop.data || []).length;

  const threatfoxSummary = {
    enabled: Boolean(sources.sources.threatfox?.enabled),
    ...(threatfox.summary || {})
  };

  const metrics = {
    kev: kevSummary,
    epss: {
      hot_global_count: epssTop.ok ? epssHotGlobal : null,
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
      botnet_cc_count: threatfoxSummary.botnet_c2_count_7d ?? null,
      historical_export_status: threatfox.export_status ?? null
    },
    fimi_lite: fimiLite
  };

  const score = computeScores(metrics, sourceHealth, scoring, previousHistory, configurationHash);
  const botActivityState = buildBotActivityState(metrics, scoring);
  const disinfoAlert = buildDisinformationAlert(botActivityState, score, scoring, fimiLite);

  const drivers = [];
  if (kev.ok) drivers.push(`${kevSummary.recent_7d} CISA KEV additions in the last ${scoring.windows.short_days} days`);
  if (kev.ok) drivers.push(`${kevSummary.recent_30d} CISA KEV additions in the last ${scoring.windows.medium_days} days`);
  if (!kev.ok) drivers.push('CISA KEV data unavailable; see source health');
  if (epssTop.ok) drivers.push(`${epssHotGlobal} EPSS entries above the configured hot percentile query window (context only)`);
  if (kevSummary.epss_mean_recent_kev > 0) drivers.push(`Mean EPSS of recent KEV items: ${kevSummary.epss_mean_recent_kev}`);
  if (threatfox.ok) {
    drivers.push(`${threatfoxSummary.ioc_count_1d ?? 0} ThreatFox IOCs in the last 1 day`);
    drivers.push(`${threatfoxSummary.botnet_c2_count_7d ?? 0} ThreatFox botnet/C2-like indicators in the last 7 days`);
    if (threatfoxSummary.historical?.status === 'active') {
      drivers.push(`ThreatFox historical approximation active: ${threatfoxSummary.historical.source_items} items over approx. ${threatfoxSummary.historical.window_days} days`);
    } else {
      drivers.push('ThreatFox historical approximation not fully active; conservative fallback scoring is capped and BAB/BWB should be read cautiously');
    }
    drivers.push(`Bot state: ${botActivityState.primary_code} — ${botActivityState.primary_label}`);
    drivers.push(`Maritime narrative alert: ${disinfoAlert.level ?? 'not assessable'} (${disinfoAlert.label})`);
  } else if (threatfox.status === 'missing_ABUSECH_AUTH_KEY') {
    drivers.push('ThreatFox is enabled but ABUSECH_AUTH_KEY is missing');
  } else if (threatfox.status === 'error') {
    drivers.push('ThreatFox feed error: see source health');
  }
  if (fimiLite?.enabled) {
    const gdeltCount = Number(fimiLite.gdelt?.unique_articles ?? 0);
    const euvsCount = Number(fimiLite.euvsdisinfo?.candidate_count ?? 0);
    const tagList = (fimiLite.disarm_aligned?.tags || []).slice(0, 3).map(t => t.label).join(', ');
    const hasFimiSourceSignal = Boolean(fimiLite.source_state?.source_signal_present) || gdeltCount > 0 || euvsCount > 0 || Boolean(tagList);
    const sourceDegraded = !fimiLite.data_quality?.score_valid;
    if (hasFimiSourceSignal) {
      drivers.push(`Maritime narrative pressure: ${fimiLite.score ?? 'not assessable'} (${fimiLite.confidence ?? 'low'} confidence)`);
      drivers.push(`GDELT maritime/FIMI watch: ${gdeltCount} score-relevant articles in ${fimiLite.gdelt?.timespan ?? '36h'} after local maritime filtering`);
      if (fimiLite.maritime_filter) drivers.push(`Maritime filter: ${fimiLite.maritime_filter.core_mard_eu_articles || 0} Core MARD-Eu, ${fimiLite.maritime_filter.global_maritime_spillover_articles || 0} Global Maritime Spillover, ${fimiLite.maritime_filter.rejected_as_noise_or_broad_context || 0} rejected as broad/noisy context`);
      drivers.push(`EUvsDisinfo case watch: ${euvsCount} maritime/FIMI candidate items in ${fimiLite.euvsdisinfo?.timespan ?? '90d'}`);
      if (tagList) drivers.push(`Narrative topic tags observed: ${tagList}`);
    } else if (sourceDegraded) {
      drivers.push('FIMI-lite sources degraded or rate-limited; no corroborating source signal detected in this run');
    } else {
      drivers.push('FIMI-lite crawls returned no matching source signals in this run');
    }
  }
  if (score.baseline.status === 'warming_up') drivers.push(`Baseline warming up: ${score.baseline.points}/${scoring.windows.history_points_for_baseline} prior points available`);

  const latest = {
    schema: 'mard-hat-v0.2.0',
    scoring_version: SCORING_VERSION,
    configuration_hash: configurationHash,
    data_quality: score.data_quality,
    observed_partial_score: score.observed_partial_score,
    generated_at: generatedAt,
    window_days: scoring.windows.medium_days,
    hat_score: score.hat_score,
    level: score.level,
    score_interpretation: score.score_interpretation,
    confidence: score.confidence,
    trend: score.baseline.delta_from_mean === null ? 'unknown' : score.baseline.delta_from_mean > 8 ? 'rising' : score.baseline.delta_from_mean < -8 ? 'falling' : 'stable',
    baseline: score.baseline,
    score_parts: score.score_parts,
    context_parts: score.context_parts,
    bot_activity_state: botActivityState,
    disinformation_alert_level: disinfoAlert,
    narrative_alert_level: disinfoAlert,
    metrics,
    drivers,
    source_health: sourceHealth,
    source_health_map: Object.fromEntries(sourceHealth.map(s => [s.source, s.status])),
    assessment: {
      label: 'open-source cyber/exploit, IOC, bot-state and FIMI-lite telemetry',
      magic_paws_use: 'contextual indicator only',
      claim_limit: scoring.claim_limit,
      no_attribution: true,
      no_proof_by_itself: true
    },
    roadmap: {
      next: 'Accumulate valid source coverage for event comparisons',
      active: 'v0.2.0 source validity, rate-limit handling, corrected baselines and separate narrative/influence telemetry',
      open_measures: 'later'
    },
    links: {
      latest_json: 'hat_latest.json',
      history_json: 'hat_history.json',
      source_health_json: 'hat_source_health.json'
    }
  };

  latest.obscuration_context = buildObscurationContext(latest, scoring);
  latest.links = {
    ...(latest.links || {}),
    analyst_bundle: 'downloads/hat_analyst_bundle_latest.json',
    fimi_maritime_csv: 'downloads/fimi_maritime_articles_latest.csv',
    fimi_maritime_json: 'downloads/fimi_maritime_articles_latest.json',
    source_health_csv: 'downloads/source_health_latest.csv'
  };

  const evidencePath = await writeEvidenceCard(latest);
  latest.evidence_cards = [evidencePath];
  latest.downloads = await writeAnalystDownloads(latest);

  const newHistoryItem = createHistoryItem(latest);
  const allHistory = [...previousHistory, newHistoryItem];
  const history = allHistory.slice(-(scoring.windows.public_history_points || 720));

  await fs.writeFile(path.join(PUBLIC_DIR, 'hat_latest.json'), JSON.stringify(latest, null, 2));
  await fs.writeFile(path.join(PUBLIC_DIR, 'hat_history.json'), JSON.stringify(history, null, 2));
  await fs.writeFile(path.join(PUBLIC_DIR, 'hat_source_health.json'), JSON.stringify(sourceHealth, null, 2));
  await fs.writeFile(path.join(HISTORY_DIR, 'hat_history.jsonl'), allHistory.map(row => JSON.stringify(row)).join('\n') + '\n');

  console.log(`HAT score: ${latest.hat_score} (${latest.level}), confidence: ${latest.confidence}`);
}

export { summariseThreatFoxData, buildBotActivityState, buildDisinformationAlert, computeScores, keywordMatches, fetchFimiLite, createHistoryItem, writeAnalystDownloads };

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(err => { console.error(err); process.exitCode = 1; });
}
