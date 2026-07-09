import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const ROOT = process.cwd();
const SOURCES_PATH = path.join(ROOT, 'config', 'sources.json');
const SCORING_PATH = path.join(ROOT, 'config', 'scoring.json');
const FIMI_CONFIG_PATH = path.join(ROOT, 'config', 'fimi_keywords.json');
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
        'user-agent': 'mard-hybrid-telemetry/0.1.4'
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

function getThreatFoxFirstSeen(item) {
  return item.first_seen || item.first_seen_utc || item.first_seen_utc_timestamp || item.date_added || item.timestamp || item.created_at || null;
}

function parseThreatFoxDate(item) {
  const raw = getThreatFoxFirstSeen(item);
  if (!raw) return null;
  const normalized = String(raw).includes('T') ? String(raw) : String(raw).replace(' ', 'T') + 'Z';
  const d = new Date(normalized);
  return Number.isNaN(d.getTime()) ? null : d;
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

async function fetchGdeltArticleQuery(source, query, timespan, maxrecords, label) {
  const url = buildGdeltUrl(source.base_url, query, timespan, maxrecords);
  const { json, raw, hash } = await fetchJson(url, label);
  const articles = Array.isArray(json.articles) ? json.articles.map(a => normaliseGdeltArticle(a, query)) : [];
  return { ok: true, query, url, raw, hash, count: articles.length, articles };
}

function applyDisarmAlignedTags(items, fimiConfig) {
  const tags = [];
  const text = items.map(item => `${item.title || ''} ${item.domain || ''} ${item.url || ''}`).join(' \n ').toLowerCase();
  for (const tag of fimiConfig.disarm_aligned_tags || []) {
    const matched = [];
    for (const keyword of tag.keywords || []) {
      const k = String(keyword).toLowerCase();
      if (k && text.includes(k)) matched.push(keyword);
    }
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

async function fetchFimiLite(sources, scoring, fimiConfig, previousHistory = []) {
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
        const r = await fetchGdeltArticleQuery(gdeltSource, query, gdeltSource.timespan || '36h', gdeltSource.maxrecords_per_query || 75, `gdelt_fimi_${i + 1}`);
        const rawPath = path.join(RAW_DIR, `gdelt_fimi_${i + 1}_${stamp}.json`);
        await fs.writeFile(rawPath, r.raw);
        r.raw_file = path.relative(ROOT, rawPath);
        gdeltResults.push(r);
      } catch (err) {
        gdeltResults.push({ ok: false, query, error: String(err.message || err), articles: [] });
      }
    }
  }

  const gdeltArticles = uniqueBy(gdeltResults.flatMap(r => r.articles || []), a => a.url || `${a.title}|${a.domain}`);
  const gdeltOk = gdeltSource?.enabled && gdeltResults.some(r => r.ok);
  fimiHealth.push({
    source: 'gdelt_fimi',
    status: gdeltSource?.enabled ? (gdeltOk ? 'ok' : 'error') : 'disabled',
    count: gdeltArticles.length,
    queries: gdeltQueries.length,
    errors: gdeltResults.filter(r => !r.ok).map(r => r.error).slice(0, 3)
  });

  const euvsResults = [];
  if (euvsSource?.enabled && gdeltSource?.enabled) {
    for (const [i, query] of euvsQueries.entries()) {
      try {
        const r = await fetchGdeltArticleQuery(gdeltSource, query, euvsSource.timespan || '90d', euvsSource.maxrecords_per_query || 50, `euvsdisinfo_case_watch_${i + 1}`);
        const rawPath = path.join(RAW_DIR, `euvsdisinfo_case_watch_${i + 1}_${stamp}.json`);
        await fs.writeFile(rawPath, r.raw);
        r.raw_file = path.relative(ROOT, rawPath);
        euvsResults.push(r);
      } catch (err) {
        euvsResults.push({ ok: false, query, error: String(err.message || err), articles: [] });
      }
    }
  }

  const euvsArticles = uniqueBy(euvsResults.flatMap(r => r.articles || []), a => a.url || `${a.title}|${a.domain}`);
  const euvsOk = euvsSource?.enabled && euvsResults.some(r => r.ok);
  fimiHealth.push({
    source: 'euvsdisinfo_case_watch',
    status: euvsSource?.enabled ? (euvsOk ? 'ok' : 'error') : 'disabled',
    count: euvsArticles.length,
    queries: euvsQueries.length,
    method: 'gdelt_domain_restricted_artlist',
    errors: euvsResults.filter(r => !r.ok).map(r => r.error).slice(0, 3)
  });

  const allFimiArticles = uniqueBy([...gdeltArticles, ...euvsArticles], a => a.url || `${a.title}|${a.domain}`);
  const disarmTags = disarmSource?.enabled ? applyDisarmAlignedTags(allFimiArticles, fimiConfig) : [];
  fimiHealth.push({
    source: 'disarm_aligned_taxonomy',
    status: disarmSource?.enabled ? 'ok' : 'disabled',
    count: disarmTags.length,
    method: 'local_keyword_mapping'
  });

  const histGdelt = (previousHistory || []).map(h => h?.metrics?.gdelt_unique_articles_36h).filter(Number.isFinite);
  const histFimiScore = (previousHistory || []).map(h => h?.metrics?.fimi_lite_score).filter(Number.isFinite);
  const gdeltPercentile = percentileRank(histGdelt.length >= 14 ? histGdelt : [], gdeltArticles.length);

  const caps = scoring.caps || {};
  const fimiWeights = scoring.fimi_weights || {};
  const fallbackMax = caps.fimi_fallback_max_score ?? 65;
  const gdeltScore = gdeltPercentile === null
    ? Math.min(fallbackMax, scoreFromCount(gdeltArticles.length, caps.gdelt_articles_36h_cap_fallback || 120))
    : gdeltPercentile;
  const euvsScore = scoreFromCount(euvsArticles.length, caps.euvsdisinfo_cases_90d_cap || 12);
  const disarmScore = scoreFromCount(disarmTags.length, caps.disarm_tags_cap || 8);
  const fimiScore = clamp(
    gdeltScore * (fimiWeights.gdelt_narrative_pressure ?? 0.45) +
    euvsScore * (fimiWeights.euvsdisinfo_case_signal ?? 0.35) +
    disarmScore * (fimiWeights.disarm_tag_relevance ?? 0.20)
  );

  return {
    enabled: Boolean(gdeltSource?.enabled || euvsSource?.enabled || disarmSource?.enabled),
    status: fimiHealth.some(s => s.status === 'ok') ? 'ok' : 'error_or_disabled',
    score: Math.round(fimiScore),
    confidence: histGdelt.length >= 14 ? 'medium' : 'low',
    mode: 'fimi_lite_open_source_proxy',
    score_parts: {
      gdelt_narrative_pressure: Math.round(gdeltScore),
      euvsdisinfo_case_signal: Math.round(euvsScore),
      disarm_tag_relevance: Math.round(disarmScore)
    },
    gdelt: {
      timespan: gdeltSource?.timespan || '36h',
      query_count: gdeltQueries.length,
      article_count: gdeltResults.reduce((a, r) => a + (r.count || 0), 0),
      unique_articles: gdeltArticles.length,
      historical_percentile: gdeltPercentile === null ? null : Math.round(gdeltPercentile),
      top_domains: topCounts(gdeltArticles, a => a.domain || 'unknown', 8),
      sample: gdeltArticles.slice(0, 10)
    },
    euvsdisinfo: {
      timespan: euvsSource?.timespan || '90d',
      query_count: euvsQueries.length,
      candidate_count: euvsArticles.length,
      method: 'GDELT domain-restricted ArticleList query for euvsdisinfo.eu',
      sample: euvsArticles.slice(0, 10)
    },
    disarm_aligned: {
      method: 'local transparent keyword mapping; no official DISARM technique IDs claimed',
      tag_count: disarmTags.length,
      tags: disarmTags.slice(0, 12)
    },
    source_health: fimiHealth,
    history: {
      gdelt_points: histGdelt.length,
      fimi_score_points: histFimiScore.length
    },
    note: 'FIMI-lite is a contextual signal. GDELT measures media/narrative volume, EUvsDisinfo provides curated case exposure, and DISARM-aligned tags structure the observations. This is not attribution-grade.'
  };
}

function percentileRank(values, current) {
  const nums = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!nums.length || !Number.isFinite(current)) return null;
  const belowOrEqual = nums.filter(v => v <= current).length;
  return clamp((belowOrEqual / nums.length) * 100);
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

function summariseThreatFoxData(data1d, data7d, historicalItems, scoring, previousHistory = []) {
  const day1 = Array.isArray(data1d) ? data1d : [];
  const day7 = Array.isArray(data7d) ? data7d : [];
  const botnet1d = day1.filter(isThreatFoxBotnetC2);
  const botnet7d = day7.filter(isThreatFoxBotnetC2);

  const historicalDays = scoring.windows.threatfox_historical_days || 180;
  const botHours = scoring.windows.bot_activity_hours || 36;
  const windowMs = botHours * 3600000;
  const currentBegin = now.getTime() - windowMs;

  // Current 36h counts can be derived from the recent 7d API response even when
  // the full export is unavailable. This prevents using a full 7d count as a
  // fake 36h value.
  const recent7Parsed = day7
    .map(item => ({ item, d: parseThreatFoxDate(item), bot: isThreatFoxBotnetC2(item) }))
    .filter(x => x.d && x.d.getTime() <= now.getTime());
  const recent36 = recent7Parsed.filter(x => x.d.getTime() > currentBegin && x.d.getTime() <= now.getTime());
  const recent36Bot = recent36.filter(x => x.bot);

  const histRaw = Array.isArray(historicalItems) ? historicalItems : [];
  const cutoff = now.getTime() - historicalDays * 86400000;
  const hist = histRaw
    .map(item => ({ item, d: parseThreatFoxDate(item), bot: isThreatFoxBotnetC2(item) }))
    .filter(x => x.d && x.d.getTime() >= cutoff && x.d.getTime() <= now.getTime());

  const perDayIoc = new Map();
  const perDayBot = new Map();
  for (const x of hist) {
    const k = dateKey(x.d);
    perDayIoc.set(k, (perDayIoc.get(k) || 0) + 1);
    if (x.bot) perDayBot.set(k, (perDayBot.get(k) || 0) + 1);
  }

  const dayCounts = [...perDayIoc.values()];
  const dayBotCounts = [...perDayBot.values()];
  const endTimes = [];
  const start = new Date(now.getTime() - historicalDays * 86400000);
  start.setUTCHours(23, 59, 59, 999);
  for (let t = start.getTime(); t <= now.getTime(); t += 86400000) endTimes.push(t);

  const rolling36Ioc = [];
  const rolling36Bot = [];
  for (const end of endTimes) {
    const begin = end - windowMs;
    let ioc = 0;
    let bot = 0;
    for (const x of hist) {
      const ts = x.d.getTime();
      if (ts > begin && ts <= end) {
        ioc++;
        if (x.bot) bot++;
      }
    }
    rolling36Ioc.push(ioc);
    rolling36Bot.push(bot);
  }

  const current36 = hist.length
    ? hist.filter(x => x.d.getTime() > currentBegin && x.d.getTime() <= now.getTime())
    : recent36;
  const current36Bot = hist.length
    ? current36.filter(x => x.bot)
    : recent36Bot;

  // If export parsing failed or is thin, fall back to local run history for rough percentile inputs.
  const histFromRunsIoc = (previousHistory || [])
    .map(h => h?.metrics?.threatfox_ioc_count_1d)
    .filter(Number.isFinite);
  const histFromRunsBot = (previousHistory || [])
    .map(h => h?.metrics?.threatfox_botnet_c2_36h)
    .filter(Number.isFinite);

  const currentIocPercentile = percentileRank(dayCounts.length >= 14 ? dayCounts : histFromRunsIoc, day1.length);
  const currentBotPercentile = percentileRank(dayBotCounts.length >= 14 ? dayBotCounts : histFromRunsBot, botnet1d.length);
  const trailing36IocPercentile = percentileRank(rolling36Ioc.length >= 14 ? rolling36Ioc : histFromRunsIoc, current36.length || recent36.length || day1.length);
  const trailing36BotPercentile = percentileRank(rolling36Bot.length >= 14 ? rolling36Bot : histFromRunsBot, current36Bot.length || recent36Bot.length || botnet1d.length);

  const historicalAvailable = hist.length > 0 && dayCounts.length >= 7;
  const fallbackLimited = !historicalAvailable;

  return {
    enabled: true,
    ioc_count_1d: day1.length,
    ioc_count_7d: day7.length,
    botnet_c2_count_1d: botnet1d.length,
    botnet_c2_count_7d: botnet7d.length,
    threat_types_1d: topCounts(day1, x => x.threat_type || 'unknown', 8),
    malware_families_1d: topCounts(day1, getThreatFoxFamily, 10),
    botnet_families_7d: topCounts(botnet7d, getThreatFoxFamily, 10),
    historical: {
      status: historicalAvailable ? 'active' : 'warming_up_or_unavailable',
      method: historicalAvailable ? 'threatfox_export_percentile_approximation' : 'recent_7d_api_plus_local_history_limited_fallback',
      fallback_limited: fallbackLimited,
      window_days: historicalDays,
      source_items: hist.length,
      days_with_iocs: dayCounts.length,
      bot_activity_hours: botHours,
      current_36h_ioc_count: current36.length || recent36.length || null,
      current_36h_botnet_c2_count: current36Bot.length || recent36Bot.length || null,
      current_ioc_percentile: currentIocPercentile === null ? null : Math.round(currentIocPercentile),
      current_botnet_c2_percentile: currentBotPercentile === null ? null : Math.round(currentBotPercentile),
      trailing_36h_ioc_percentile: trailing36IocPercentile === null ? null : Math.round(trailing36IocPercentile),
      trailing_36h_botnet_c2_percentile: trailing36BotPercentile === null ? null : Math.round(trailing36BotPercentile)
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

  let exportResult = { ok: false, status: 'disabled', items: [] };
  try {
    exportResult = await fetchThreatFoxHistoricalExport(source, key, scoring);
  } catch (err) {
    exportResult = { ok: false, status: 'error', error: String(err.message || err), items: [] };
  }

  const data1d = Array.isArray(oneDay.json.data) ? oneDay.json.data : [];
  const data7d = Array.isArray(sevenDays.json.data) ? sevenDays.json.data : [];
  const summary = summariseThreatFoxData(data1d, data7d, exportResult.items, scoring, previousHistory);

  return {
    ok: true,
    status: 'ok',
    count: data1d.length,
    count_7d: data7d.length,
    botnet_cc_count: summary.botnet_c2_count_7d,
    hash_1d: oneDay.hash,
    hash_7d: sevenDays.hash,
    export_status: exportResult.status,
    export_count: exportResult.count ?? 0,
    export_format: exportResult.format ?? null,
    export_hash: exportResult.hash ?? null,
    export_error: exportResult.error ?? null,
    raw_files: [path.relative(ROOT, raw1d), path.relative(ROOT, raw7d)].concat(exportResult.raw_file ? [exportResult.raw_file] : []),
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

function fallbackThreatFoxScore(value, cap, maxScore = 65) {
  return Math.min(maxScore, scoreFromCount(value || 0, cap));
}

function computeScores(metrics, sourceHealth, scoring, previousHistory) {
  const weights = scoring.weights;
  const caps = scoring.caps;
  const thresholds = scoring.thresholds;
  const hist = metrics.threatfox?.historical || {};

  const fallbackMax = caps.threatfox_fallback_max_score ?? 65;
  const threatfoxIocCurrent = Number.isFinite(hist.current_ioc_percentile)
    ? hist.current_ioc_percentile
    : fallbackThreatFoxScore(metrics.threatfox.ioc_count_1d || 0, caps.threatfox_ioc_1d_cap_fallback, fallbackMax);
  const bot36Count = hist.current_36h_botnet_c2_count ?? metrics.threatfox.botnet_c2_count_1d ?? 0;
  const threatfoxBot36 = Number.isFinite(hist.trailing_36h_botnet_c2_percentile)
    ? hist.trailing_36h_botnet_c2_percentile
    : fallbackThreatFoxScore(bot36Count, caps.threatfox_botnet_c2_36h_cap_fallback, fallbackMax);

  const parts = {
    kev_recent_7d: scoreFromCount(metrics.kev.recent_7d, caps.kev_recent_7d_cap),
    kev_recent_30d: scoreFromCount(metrics.kev.recent_30d, caps.kev_recent_30d_cap),
    kev_epss_mean: clamp(metrics.kev.epss_mean_recent_kev * 100),
    threatfox_ioc_current: clamp(threatfoxIocCurrent),
    threatfox_botnet_c2_36h: clamp(threatfoxBot36)
  };

  const contextParts = {
    epss_hot_global: scoreFromCount(metrics.epss.hot_global_count, caps.epss_hot_count_cap),
    source_coverage: clamp((sourceHealth.filter(s => s.status === 'ok').length / sourceHealth.length) * 100)
  };

  const hatScore = clamp(
    parts.kev_recent_7d * weights.kev_recent_7d +
    parts.kev_recent_30d * weights.kev_recent_30d +
    parts.kev_epss_mean * weights.kev_epss_mean +
    parts.threatfox_ioc_current * weights.threatfox_ioc_current +
    parts.threatfox_botnet_c2_36h * weights.threatfox_botnet_c2_36h +
    contextParts.epss_hot_global * weights.epss_hot_global +
    contextParts.source_coverage * weights.source_coverage
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
    score_parts: Object.fromEntries(Object.entries(parts).map(([k, v]) => [k, Math.round(v)])),
    context_parts: Object.fromEntries(Object.entries(contextParts).map(([k, v]) => [k, Math.round(v)]))
  };
}

function buildBotActivityState(metrics, scoring) {
  const h = metrics.threatfox?.historical || {};
  const busy = scoring.bot_activity?.busy_percentile ?? 75;
  const currentMax = Math.max(h.current_ioc_percentile ?? 0, h.current_botnet_c2_percentile ?? 0);
  const trailingMax = Math.max(h.trailing_36h_ioc_percentile ?? 0, h.trailing_36h_botnet_c2_percentile ?? 0);
  const currentBusy = currentMax >= busy;
  const trailingBusy = trailingMax >= busy;

  const primaryCode = currentBusy ? 'BAB' : trailingBusy ? 'BWB' : 'BIL';
  const primaryNumber = currentBusy ? 2 : trailingBusy ? 1 : 0;

  return {
    schema: 'mard-hat-bot-state-v1',
    primary_code: primaryCode,
    primary_number: primaryNumber,
    primary_label: primaryCode === 'BAB' ? 'Bots are busy' : primaryCode === 'BWB' ? 'Bots were busy' : 'Bots in Lurking Position',
    current_code: currentBusy ? 'BAB' : 'BIL',
    current_label: currentBusy ? 'Bots are busy' : 'Bots in Lurking Position',
    trailing_36h_code: trailingBusy ? 'BWB' : 'BIL',
    trailing_36h_label: trailingBusy ? 'Bots were busy' : 'Bots in Lurking Position',
    confidence: h.status === 'active' ? 'medium' : 'low',
    basis: {
      threshold_percentile: busy,
      ioc_current_percentile: h.current_ioc_percentile ?? null,
      botnet_c2_current_percentile: h.current_botnet_c2_percentile ?? null,
      ioc_36h_percentile: h.trailing_36h_ioc_percentile ?? null,
      botnet_c2_36h_percentile: h.trailing_36h_botnet_c2_percentile ?? null,
      ioc_36h_count: h.current_36h_ioc_count ?? null,
      botnet_c2_36h_count: h.current_36h_botnet_c2_count ?? null
    }
  };
}

function buildDisinformationAlert(botActivityState, score, scoring, fimiLite = null) {
  const cfg = scoring.disinformation_alert || {};
  const maxBasis = Math.max(
    botActivityState.basis?.ioc_current_percentile ?? 0,
    botActivityState.basis?.botnet_c2_current_percentile ?? 0,
    botActivityState.basis?.ioc_36h_percentile ?? 0,
    botActivityState.basis?.botnet_c2_36h_percentile ?? 0
  );

  const fimiScore = Number(fimiLite?.score ?? 0);
  const euvsCount = Number(fimiLite?.euvsdisinfo?.candidate_count ?? 0);
  const gdeltCount = Number(fimiLite?.gdelt?.unique_articles ?? 0);
  const tagCount = Number(fimiLite?.disarm_aligned?.tag_count ?? 0);
  const hasFimiSourceSignal = fimiScore > 0 || euvsCount > 0 || gdeltCount > 0 || tagCount > 0;
  const proxyElevated = botActivityState.primary_code === 'BAB' || botActivityState.primary_code === 'BWB' || maxBasis >= (cfg.level_1_percentile ?? 65) || ['watch', 'high', 'critical'].includes(score.level);

  let level = 0;
  if (
    fimiScore >= (cfg.level_1_fimi_score ?? 25) ||
    botActivityState.primary_code === 'BWB' ||
    maxBasis >= (cfg.level_1_percentile ?? 65) ||
    score.level === 'watch'
  ) level = 1;

  if (
    fimiScore >= (cfg.level_2_fimi_score ?? 55) ||
    botActivityState.primary_code === 'BAB' ||
    maxBasis >= (cfg.level_2_percentile ?? 75) ||
    ['high', 'critical'].includes(score.level)
  ) level = 2;

  if (
    cfg.auto_level_3_enabled &&
    fimiScore >= (cfg.level_3_fimi_score ?? 80) &&
    euvsCount > 0 &&
    tagCount >= 2 &&
    (botActivityState.primary_code !== 'BIL' || gdeltCount >= 20)
  ) level = 3;

  const labels = ['none', 'low', 'elevated', 'high'];
  let mode = 'fimi_lite_with_bot_ioc_proxy';
  let note = 'FIMI-lite and bot/IOC proxy telemetry are contextual side signals only. Not attribution-grade.';
  if (level === 0 && !hasFimiSourceSignal) {
    mode = 'no_fimi_signal_no_proxy_elevation';
    note = 'No matching FIMI-lite source signals were detected in this run, and bot/IOC proxy telemetry did not elevate the DAL. Not attribution-grade.';
  } else if (!hasFimiSourceSignal && proxyElevated) {
    mode = 'bot_ioc_proxy_only_no_fimi_signal';
    note = `Driven primarily by bot/IOC proxy telemetry. FIMI-lite crawls did not add corroborating narrative or curated-case signals in this run. Not attribution-grade.`;
  } else if (hasFimiSourceSignal && proxyElevated) {
    note = 'Derived from FIMI-lite source signals plus bot/IOC proxy telemetry. Contextual only; not attribution-grade.';
  } else if (hasFimiSourceSignal) {
    mode = 'fimi_lite_source_signal_only';
    note = 'Derived from FIMI-lite source signals. Contextual only; not attribution-grade and not sufficient to prove coordination or attribution.';
  }

  return {
    schema: 'mard-hat-dal-v2',
    level,
    label: labels[level],
    scale: [0, 1, 2, 3],
    mode,
    fimi_lite_score: Math.round(fimiScore),
    corroboration: {
      gdelt_unique_articles: gdeltCount,
      euvsdisinfo_candidates: euvsCount,
      disarm_aligned_tags: tagCount,
      bot_state: botActivityState.primary_code,
      fimi_source_signal_present: hasFimiSourceSignal,
      bot_ioc_proxy_elevated: proxyElevated
    },
    note
  };
}

async function writeEvidenceCard(latest) {
  const card = {
    schema: 'mard-hat-evidence-card-v1',
    generated_at: generatedAt,
    title: 'Daily open-source exploit, IOC and bot-state snapshot',
    claim_limit: latest.assessment.claim_limit,
    score: latest.hat_score,
    level: latest.level,
    confidence: latest.confidence,
    bot_activity_state: latest.bot_activity_state,
    disinformation_alert_level: latest.disinformation_alert_level,
    drivers: latest.drivers,
    key_metrics: latest.metrics,
    source_health: latest.source_health
  };
  const file = path.join(EVIDENCE_DIR, `${stamp}_open_source_exploit_ioc_botstate_pressure.json`);
  await fs.writeFile(file, JSON.stringify(card, null, 2));
  return path.relative(PUBLIC_DIR, file);
}

async function main() {
  await ensureDirs();
  const sources = await readJson(SOURCES_PATH);
  const scoring = await readJson(SCORING_PATH);
  const fimiConfig = await readJson(FIMI_CONFIG_PATH, { maritime_watch_queries: [], euvsdisinfo_queries: [], disarm_aligned_tags: [] });
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
    threatfox = await fetchThreatFoxOptional(sources, scoring, previousHistory);
    sourceHealth.push({
      source: 'threatfox_optional',
      status: threatfox.ok ? 'ok' : threatfox.status,
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


  let fimiLite = { enabled: false, status: 'disabled', score: 0, source_health: [] };
  try {
    fimiLite = await fetchFimiLite(sources, scoring, fimiConfig, previousHistory);
    sourceHealth.push(...(fimiLite.source_health || []));
  } catch (err) {
    fimiLite = { enabled: true, status: 'error', score: 0, source_health: [{ source: 'fimi_lite', status: 'error', error: String(err.message || err) }] };
    sourceHealth.push(...fimiLite.source_health);
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
      botnet_cc_count: threatfoxSummary.botnet_c2_count_7d ?? null,
      historical_export_status: threatfox.export_status ?? null
    },
    fimi_lite: fimiLite
  };

  const score = computeScores(metrics, sourceHealth, scoring, previousHistory);
  const botActivityState = buildBotActivityState(metrics, scoring);
  const disinfoAlert = buildDisinformationAlert(botActivityState, score, scoring, fimiLite);

  const drivers = [];
  drivers.push(`${kevSummary.recent_7d} CISA KEV additions in the last ${scoring.windows.short_days} days`);
  drivers.push(`${kevSummary.recent_30d} CISA KEV additions in the last ${scoring.windows.medium_days} days`);
  drivers.push(`${epssHotGlobal} EPSS entries above the configured hot percentile query window (context only)`);
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
    drivers.push(`Disinformation Alert Level proxy: ${disinfoAlert.level} (${disinfoAlert.label})`);
  } else if (threatfox.status === 'missing_ABUSECH_AUTH_KEY') {
    drivers.push('ThreatFox is enabled but ABUSECH_AUTH_KEY is missing');
  } else if (threatfox.status === 'error') {
    drivers.push('ThreatFox feed error: see source health');
  }
  if (fimiLite?.enabled) {
    const gdeltCount = Number(fimiLite.gdelt?.unique_articles ?? 0);
    const euvsCount = Number(fimiLite.euvsdisinfo?.candidate_count ?? 0);
    const tagList = (fimiLite.disarm_aligned?.tags || []).slice(0, 3).map(t => t.label).join(', ');
    const hasFimiSourceSignal = Number(fimiLite.score ?? 0) > 0 || gdeltCount > 0 || euvsCount > 0 || Boolean(tagList);
    if (hasFimiSourceSignal) {
      drivers.push(`FIMI-lite score: ${fimiLite.score ?? 0} (${fimiLite.confidence ?? 'low'} confidence)`);
      drivers.push(`GDELT narrative watch: ${gdeltCount} unique articles in ${fimiLite.gdelt?.timespan ?? '36h'}`);
      drivers.push(`EUvsDisinfo case watch: ${euvsCount} maritime/FIMI candidate items in ${fimiLite.euvsdisinfo?.timespan ?? '90d'}`);
      if (tagList) drivers.push(`DISARM-aligned tags observed: ${tagList}`);
    } else {
      drivers.push('FIMI-lite crawls returned no matching source signals in this run');
    }
  }
  if (score.baseline.status === 'warming_up') drivers.push(`Baseline warming up: ${score.baseline.points}/${scoring.windows.history_points_for_baseline} prior points available`);

  const latest = {
    schema: 'mard-hat-v0.1.4a',
    generated_at: generatedAt,
    window_days: scoring.windows.medium_days,
    hat_score: score.hat_score,
    level: score.level,
    confidence: score.confidence,
    trend: score.baseline.delta_from_mean === null ? 'unknown' : score.baseline.delta_from_mean > 8 ? 'rising' : score.baseline.delta_from_mean < -8 ? 'falling' : 'stable',
    baseline: score.baseline,
    score_parts: score.score_parts,
    context_parts: score.context_parts,
    bot_activity_state: botActivityState,
    disinformation_alert_level: disinfoAlert,
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
      next: 'v0.1.5: refine FIMI-lite calibration, optional URLhaus, and maritime relevance weighting',
      active: 'v0.1.4a FIMI-lite display-clarity: zero-result FIMI crawls and proxy-only DAL are labelled explicitly',
      open_measures: 'later'
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
    bot_activity_state: latest.bot_activity_state.primary_code,
    disinformation_alert_level: latest.disinformation_alert_level.level,
    metrics: {
      kev_recent_7d: latest.metrics.kev.recent_7d,
      kev_recent_30d: latest.metrics.kev.recent_30d,
      epss_hot_global_count: latest.metrics.epss.hot_global_count,
      epss_mean_recent_kev: latest.metrics.kev.epss_mean_recent_kev,
      threatfox_ioc_count_1d: latest.metrics.threatfox.ioc_count_1d ?? 0,
      threatfox_botnet_c2_count_7d: latest.metrics.threatfox.botnet_c2_count_7d ?? 0,
      threatfox_botnet_c2_36h: latest.metrics.threatfox.historical?.current_36h_botnet_c2_count ?? 0,
      threatfox_ioc_current_percentile: latest.metrics.threatfox.historical?.current_ioc_percentile ?? null,
      threatfox_botnet_c2_36h_percentile: latest.metrics.threatfox.historical?.trailing_36h_botnet_c2_percentile ?? null,
      fimi_lite_score: latest.metrics.fimi_lite?.score ?? 0,
      gdelt_unique_articles_36h: latest.metrics.fimi_lite?.gdelt?.unique_articles ?? 0,
      euvsdisinfo_case_candidates_90d: latest.metrics.fimi_lite?.euvsdisinfo?.candidate_count ?? 0,
      disarm_aligned_tag_count: latest.metrics.fimi_lite?.disarm_aligned?.tag_count ?? 0
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
