#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  createRegistryIndexes,
  loadInfluenceRegistry,
} from "./load_influence_registry.mjs";
import { validateInfluenceRegistry } from "./validate_influence_registry.mjs";

const ITEMS_PATH =
  process.env.MARD_INFLUENCE_CURRENT_ITEMS ||
  "data/influence/ingest/items_latest.json";
const INSTANCE_CONFIG_PATH =
  process.env.MARD_NITTER_INSTANCE_CONFIG ||
  "config/influence/nitter_instances.json";
const HEALTH_PATH =
  process.env.MARD_INFLUENCE_X_HEALTH ||
  "data/influence/ingest/x_source_health_latest.json";
const PUBLIC_STATUS_PATH =
  process.env.MARD_INFLUENCE_X_PUBLIC_STATUS ||
  "public/influence_x_ingest_status.json";
const PUBLIC_HEALTH_PATH =
  process.env.MARD_INFLUENCE_X_PUBLIC_HEALTH ||
  "public/influence_x_source_health.json";

const USER_AGENT =
  process.env.MARD_INFLUENCE_X_USER_AGENT ||
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/138.0 Safari/537.36 " +
    "MARD-HAT-Influence-Watch/0.5";
const REQUEST_TIMEOUT_MS = Number(
  process.env.MARD_INFLUENCE_X_REQUEST_TIMEOUT_MS || 18000,
);
const MAX_BODY_BYTES = Number(
  process.env.MARD_INFLUENCE_X_MAX_BODY_BYTES || 3_000_000,
);
const MAX_ITEMS_PER_SOURCE = Math.max(
  1,
  Number(process.env.MARD_INFLUENCE_MAX_ITEMS_PER_X_SOURCE || 30),
);
const MAX_ENDPOINTS = Math.max(
  1,
  Number(process.env.MARD_INFLUENCE_MAX_X_ENDPOINTS || 180),
);
const CONCURRENCY = Math.max(
  1,
  Math.min(6, Number(process.env.MARD_INFLUENCE_X_CONCURRENCY || 3)),
);
const MAX_INSTANCE_ATTEMPTS = Math.max(
  1,
  Math.min(10, Number(process.env.MARD_NITTER_MAX_INSTANCE_ATTEMPTS || 5)),
);
const STRICT_MODE =
  String(process.env.MARD_INFLUENCE_X_STRICT || "false").toLowerCase() === "true";
const PREFLIGHT_UNAVAILABLE =
  String(process.env.MARD_NITTER_PREFLIGHT_USABLE || "1") === "0";
const PREFLIGHT_SKIP_REASON =
  process.env.MARD_NITTER_SKIP_REASON ||
  "no_usable_public_nitter_instance";

const RESTRICTED_ACTORS = new Set([
  "ru_rt_global",
  "ru_rt_de",
  "ru_sputnik",
  "ru_sputnik_de",
]);

function sha256(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function normalizeWhitespace(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function decodeEntities(value) {
  const map = {
    amp: "&",
    quot: '"',
    apos: "'",
    lt: "<",
    gt: ">",
    nbsp: " ",
    ndash: "–",
    mdash: "—",
    hellip: "…",
  };
  return String(value || "")
    .replace(/&#(\d+);/g, (_, number) => String.fromCodePoint(Number(number)))
    .replace(/&#x([0-9a-f]+);/gi, (_, number) =>
      String.fromCodePoint(parseInt(number, 16)),
    )
    .replace(/&([a-z]+);/gi, (match, name) => map[name.toLowerCase()] ?? match);
}

function stripHtml(value) {
  return normalizeWhitespace(
    decodeEntities(
      String(value || "")
        .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
        .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/p>/gi, "\n")
        .replace(/<[^>]+>/g, " "),
    ),
  );
}

function canonicalizeUrl(value, baseUrl = undefined) {
  try {
    const url = new URL(value, baseUrl);
    for (const key of [...url.searchParams.keys()]) {
      const normalized = key.toLowerCase();
      if (
        normalized.startsWith("utm_") ||
        ["fbclid", "gclid", "mc_cid", "mc_eid"].includes(normalized)
      ) {
        url.searchParams.delete(key);
      }
    }
    url.hash = "";
    return url.toString();
  } catch {
    return "";
  }
}

function domainOf(value) {
  try {
    return new URL(value).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

function extractUrls(value, baseUrl) {
  const urls = new Set();
  const hrefRegex = /\bhref=["']([^"'#]+)["']/gi;
  let match;

  while ((match = hrefRegex.exec(String(value || "")))) {
    const url = canonicalizeUrl(decodeEntities(match[1]), baseUrl);
    if (url) urls.add(url);
    if (urls.size >= 30) break;
  }

  const plainRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  while ((match = plainRegex.exec(String(value || "")))) {
    const url = canonicalizeUrl(match[0], baseUrl);
    if (url) urls.add(url);
    if (urls.size >= 30) break;
  }

  return [...urls];
}

function toIsoDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function simhash64(value) {
  const tokens = normalizeWhitespace(value)
    .toLowerCase()
    .replace(/[^\p{L}\p{N}_-]+/gu, " ")
    .split(/\s+/)
    .filter((token) => token.length >= 3)
    .slice(0, 4000);

  if (!tokens.length) return "0000000000000000";

  const vector = new Array(64).fill(0);
  for (const token of tokens) {
    const digest = crypto.createHash("sha256").update(token).digest();
    for (let bit = 0; bit < 64; bit += 1) {
      const byte = digest[Math.floor(bit / 8)];
      const mask = 1 << (7 - (bit % 8));
      vector[bit] += byte & mask ? 1 : -1;
    }
  }

  let result = 0n;
  for (let bit = 0; bit < 64; bit += 1) {
    if (vector[bit] >= 0) result |= 1n << BigInt(63 - bit);
  }
  return result.toString(16).padStart(16, "0");
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function countBy(items, selector) {
  const counts = {};
  for (const item of items) {
    const key = selector(item) || "unknown";
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.fromEntries(
    Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
  );
}

function handleFromEndpoint(endpoint) {
  const direct = String(endpoint.handle_or_domain || "")
    .trim()
    .replace(/^@/, "");
  if (/^[A-Za-z0-9_]{1,30}$/.test(direct)) return direct;

  try {
    const url = new URL(endpoint.profile_url);
    const candidate = url.pathname.split("/").filter(Boolean)[0] || "";
    return /^[A-Za-z0-9_]{1,30}$/.test(candidate) ? candidate : "";
  } catch {
    return "";
  }
}

function statusIdFromUrl(value) {
  const match = /\/status\/(\d+)/i.exec(String(value || ""));
  return match?.[1] || "";
}

function xStatusUrl(handle, statusId) {
  return statusId
    ? `https://x.com/${handle}/status/${statusId}`
    : `https://x.com/${handle}`;
}

function convertNitterUrlToX(value, handle) {
  try {
    const url = new URL(value);
    const statusId = statusIdFromUrl(url.pathname);
    return xStatusUrl(handle, statusId);
  } catch {
    const statusId = statusIdFromUrl(value);
    return xStatusUrl(handle, statusId);
  }
}

function getTag(xml, names) {
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const cdata = new RegExp(
      `<${escaped}\\b[^>]*>\\s*<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>\\s*</${escaped}>`,
      "i",
    ).exec(xml);
    if (cdata) return normalizeWhitespace(cdata[1]);

    const match = new RegExp(
      `<${escaped}\\b[^>]*>([\\s\\S]*?)</${escaped}>`,
      "i",
    ).exec(xml);
    if (match) return normalizeWhitespace(match[1]);
  }
  return "";
}

function xmlLink(block, baseUrl) {
  const link = stripHtml(getTag(block, ["link", "guid"]));
  if (/^https?:\/\//i.test(link)) return canonicalizeUrl(link, baseUrl);
  const href = /<link\b[^>]*\bhref=["']([^"']+)["']/i.exec(block)?.[1];
  return href ? canonicalizeUrl(decodeEntities(href), baseUrl) : "";
}

function parseNitterRss(xml, feedUrl, handle) {
  const blocks = xml.match(/<item\b[\s\S]*?<\/item>/gi) || [];
  return blocks.slice(0, MAX_ITEMS_PER_SOURCE).map((block, index) => {
    const title = stripHtml(getTag(block, ["title"]));
    const descriptionHtml = getTag(block, ["description", "content:encoded"]);
    const description = stripHtml(descriptionHtml);
    const rawLink = xmlLink(block, feedUrl);
    const statusId = statusIdFromUrl(rawLink) || statusIdFromUrl(block);
    const text = normalizeWhitespace(description || title);

    return {
      source_item_index: index,
      item_type: "x_post",
      native_id: statusId,
      text,
      url: xStatusUrl(handle, statusId),
      published_at: toIsoDate(stripHtml(getTag(block, ["pubDate", "dc:date"]))),
      referenced_urls: extractUrls(descriptionHtml || block, feedUrl)
        .map((url) => {
          const domain = domainOf(url);
          return domain.includes("nitter") || statusIdFromUrl(url)
            ? convertNitterUrlToX(url, handle)
            : url;
        })
        .filter((url) => domainOf(url) !== "x.com"),
    };
  }).filter((item) => item.native_id && item.text);
}

function parseNitterHtml(html, profileUrl, handle) {
  const blocks = html
    .split(/<div\b[^>]*class=["'][^"']*\btimeline-item\b[^"']*["'][^>]*>/i)
    .slice(1);
  const items = [];

  for (const block of blocks) {
    if (items.length >= MAX_ITEMS_PER_SOURCE) break;

    const statusPath =
      /href=["']([^"']*\/status\/\d+(?:#m)?)["']/i.exec(block)?.[1] || "";
    const statusId = statusIdFromUrl(statusPath);
    if (!statusId) continue;

    const contentHtml =
      /<div\b[^>]*class=["'][^"']*\btweet-content\b[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(
        block,
      )?.[1] || "";
    const text = stripHtml(contentHtml);
    if (!text) continue;

    const dateTitle =
      /<span\b[^>]*class=["'][^"']*\btweet-date\b[^"']*["'][^>]*>[\s\S]*?<a\b[^>]*title=["']([^"']+)["']/i.exec(
        block,
      )?.[1] || "";
    const referencedUrls = extractUrls(contentHtml, profileUrl)
      .map((url) => {
        if (domainOf(url).includes("nitter") || statusIdFromUrl(url)) {
          return convertNitterUrlToX(url, handle);
        }
        return url;
      })
      .filter((url) => domainOf(url) !== "x.com");

    items.push({
      source_item_index: items.length,
      item_type: "x_post",
      native_id: statusId,
      text,
      url: xStatusUrl(handle, statusId),
      published_at: toIsoDate(dateTitle),
      referenced_urls: referencedUrls,
    });
  }

  return items;
}

function responseLooksBlocked(body) {
  const value = String(body || "").toLowerCase();
  return [
    "just a moment",
    "checking your browser",
    "cf-chl-",
    "attention required",
    "rate limited",
    "rate-limited",
    "instance has been rate limited",
    "enable javascript and cookies",
  ].some((needle) => value.includes(needle));
}

async function readLimitedBody(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error(`Response exceeded ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(value);
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(output);
}

async function fetchText(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": USER_AGENT,
        accept:
          "application/rss+xml, application/xml, text/xml, text/html;q=0.9, */*;q=0.5",
        "accept-language": "en-US,en;q=0.8,de;q=0.6",
        "cache-control": "no-cache",
      },
    });

    const body = await readLimitedBody(response);
    if (!response.ok) {
      const error = new Error(`HTTP ${response.status}`);
      error.httpStatus = response.status;
      error.responseBody = body.slice(0, 200);
      throw error;
    }
    if (responseLooksBlocked(body)) {
      const error = new Error("Instance blocked or rate-limited the request");
      error.blocked = true;
      throw error;
    }

    return {
      body,
      finalUrl: response.url || url,
      contentType: response.headers.get("content-type") || "",
      status: response.status,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function loadInstances() {
  const override = String(process.env.MARD_NITTER_INSTANCES || "").trim();
  if (override) {
    return override
      .split(",")
      .map((value, index) => ({
        base_url: value.trim().replace(/\/+$/, ""),
        enabled: true,
        rss_enabled: true,
        priority: index,
        notes: "Provided through MARD_NITTER_INSTANCES.",
      }))
      .filter((item) => /^https?:\/\//i.test(item.base_url));
  }

  const config = JSON.parse(await fs.readFile(INSTANCE_CONFIG_PATH, "utf8"));
  return (config.instances || [])
    .filter((item) => item.enabled !== false && /^https?:\/\//i.test(item.base_url))
    .map((item) => ({
      ...item,
      base_url: item.base_url.replace(/\/+$/, ""),
    }))
    .sort((a, b) => Number(a.priority || 999) - Number(b.priority || 999));
}

function rotateInstances(instances, handle) {
  if (!instances.length) return [];
  const seed = parseInt(sha256(handle).slice(0, 8), 16);
  const offset = seed % instances.length;
  return [...instances.slice(offset), ...instances.slice(0, offset)].slice(
    0,
    MAX_INSTANCE_ATTEMPTS,
  );
}

function priorityRank(priority) {
  return { critical: 0, high: 1, normal: 2, low: 3 }[priority] ?? 9;
}

function normalizeItem(item, endpoint, actor, selectedInstance, collectionMode) {
  const restricted =
    RESTRICTED_ACTORS.has(actor.actor_id) ||
    actor.public_export_policy === "metadata_analysis_only" ||
    endpoint.public_export_policy === "metadata_analysis_only";
  const text = normalizeWhitespace(item.text);
  const sourceUrl = canonicalizeUrl(item.url) || xStatusUrl(handleFromEndpoint(endpoint), item.native_id);
  const referencedDomains = unique(
    (item.referenced_urls || [])
      .map(domainOf)
      .filter((domain) => domain && domain !== "x.com"),
  ).slice(0, 30);

  return {
    item_id: sha256(
      `${endpoint.actor_id}|x|${item.native_id || sourceUrl}|${text}`,
    ).slice(0, 32),
    actor_id: actor.actor_id,
    endpoint_id: endpoint.endpoint_id,
    country: actor.country,
    actor_class: actor.actor_class,
    platform: "x",
    item_type: "x_post",
    source_stage: "stage5_x_nitter",
    observed_at: new Date().toISOString(),
    published_at: item.published_at,
    source_domain: "x.com",
    source_url: restricted ? "https://x.com/" : sourceUrl,
    title: "",
    title_sha256: sha256(""),
    content_sha256: sha256(text),
    content_simhash64: simhash64(text),
    content_length: text.length,
    referenced_domains: referencedDomains,
    restricted_publication: restricted,
    collection_proxy: "nitter",
    collection_mode: collectionMode,
    collection_instance_hash: sha256(selectedInstance).slice(0, 16),
  };
}

async function collectFromInstance(instance, handle) {
  const attempts = [];
  const base = instance.base_url;

  if (instance.rss_enabled !== false) {
    const rssUrl = `${base}/${encodeURIComponent(handle)}/rss`;
    try {
      const response = await fetchText(rssUrl);
      const items = parseNitterRss(response.body, response.finalUrl, handle);
      attempts.push({
        mode: "rss",
        status: items.length ? "ok" : "empty",
        http_status: response.status,
        item_count: items.length,
      });
      if (items.length) {
        return { items, collectionMode: "rss", attempts };
      }
    } catch (error) {
      attempts.push({
        mode: "rss",
        status: "error",
        http_status: error.httpStatus || null,
        blocked: Boolean(error.blocked),
        error: error?.name === "AbortError" ? "Request timeout" : error.message,
      });
    }
  }

  const profileUrl = `${base}/${encodeURIComponent(handle)}`;
  try {
    const response = await fetchText(profileUrl);
    const items = parseNitterHtml(response.body, response.finalUrl, handle);
    attempts.push({
      mode: "html",
      status: items.length ? "ok" : "empty",
      http_status: response.status,
      item_count: items.length,
    });
    if (items.length) {
      return { items, collectionMode: "html", attempts };
    }
  } catch (error) {
    attempts.push({
      mode: "html",
      status: "error",
      http_status: error.httpStatus || null,
      blocked: Boolean(error.blocked),
      error: error?.name === "AbortError" ? "Request timeout" : error.message,
    });
  }

  return { items: [], collectionMode: "", attempts };
}

async function processEndpoint(endpoint, actor, instances) {
  const started = Date.now();
  const handle = handleFromEndpoint(endpoint);
  const health = {
    endpoint_id: endpoint.endpoint_id,
    actor_id: endpoint.actor_id,
    country: actor.country,
    actor_class: actor.actor_class,
    platform: "x",
    priority: endpoint.priority,
    handle_hash: sha256(handle.toLowerCase()).slice(0, 16),
    status: "error",
    checked_at: new Date().toISOString(),
    duration_ms: 0,
    selected_instance_hash: "",
    collection_mode: "",
    item_count: 0,
    instance_attempts: [],
    error: "",
  };

  try {
    if (!handle) throw new Error("Unable to resolve X handle from registry endpoint");

    for (const instance of rotateInstances(instances, handle)) {
      const result = await collectFromInstance(instance, handle);
      health.instance_attempts.push({
        instance_hash: sha256(instance.base_url).slice(0, 16),
        attempts: result.attempts,
      });

      if (!result.items.length) continue;

      const uniqueItems = new Map();
      for (const item of result.items.slice(0, MAX_ITEMS_PER_SOURCE)) {
        const normalized = normalizeItem(
          item,
          endpoint,
          actor,
          instance.base_url,
          result.collectionMode,
        );
        uniqueItems.set(normalized.item_id, normalized);
      }

      health.status = "ok";
      health.selected_instance_hash = sha256(instance.base_url).slice(0, 16);
      health.collection_mode = result.collectionMode;
      health.item_count = uniqueItems.size;
      return { health, items: [...uniqueItems.values()] };
    }

    health.error = "All configured Nitter instances failed or returned no public posts";
    return { health, items: [] };
  } catch (error) {
    health.error = error?.name === "AbortError" ? "Request timeout" : error.message;
    return { health, items: [] };
  } finally {
    health.duration_ms = Date.now() - started;
  }
}

async function mapConcurrent(items, limit, handler) {
  const results = new Array(items.length);
  let cursor = 0;

  async function worker() {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await handler(items[index], index);
      await new Promise((resolve) => setTimeout(resolve, 350));
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, () => worker()),
  );
  return results;
}

function recomputeItemCounts(items) {
  return {
    items: items.length,
    restricted_items: items.filter((item) => item.restricted_publication).length,
    website_snapshots: items.filter((item) => item.item_type === "website_snapshot").length,
    feed_items: items.filter((item) => item.item_type === "feed_item").length,
    telegram_posts: items.filter((item) => item.item_type === "telegram_post").length,
    bluesky_posts: items.filter((item) => item.item_type === "bluesky_post").length,
    youtube_videos: items.filter((item) => item.item_type === "youtube_video").length,
    x_posts: items.filter((item) => item.item_type === "x_post").length,
  };
}

function instanceStatistics(health) {
  const summary = new Map();

  for (const source of health) {
    for (const attempted of source.instance_attempts || []) {
      const current = summary.get(attempted.instance_hash) || {
        instance_hash: attempted.instance_hash,
        endpoint_attempts: 0,
        successful_methods: 0,
        errors: 0,
        blocked: 0,
        empty: 0,
      };
      current.endpoint_attempts += 1;

      for (const method of attempted.attempts || []) {
        if (method.status === "ok") current.successful_methods += 1;
        if (method.status === "error") current.errors += 1;
        if (method.status === "empty") current.empty += 1;
        if (method.blocked) current.blocked += 1;
      }
      summary.set(attempted.instance_hash, current);
    }
  }

  return [...summary.values()].sort(
    (a, b) =>
      b.successful_methods - a.successful_methods ||
      a.errors - b.errors ||
      a.instance_hash.localeCompare(b.instance_hash),
  );
}

async function main() {
  const { registry } = await loadInfluenceRegistry();
  const validation = validateInfluenceRegistry(registry);
  if (validation.errors.length) {
    throw new Error(
      `Registry validation failed with ${validation.errors.length} error(s).`,
    );
  }

  const instances = PREFLIGHT_UNAVAILABLE ? [] : await loadInstances();
  if (!PREFLIGHT_UNAVAILABLE && !instances.length) {
    throw new Error("No enabled Nitter instances configured");
  }

  const { endpoints, entityById } = createRegistryIndexes(registry);
  const eligible = endpoints
    .filter(
      (endpoint) =>
        endpoint.ingest_enabled === true &&
        endpoint.platform === "x" &&
        Boolean(handleFromEndpoint(endpoint)),
    )
    .sort(
      (left, right) =>
        priorityRank(left.priority) - priorityRank(right.priority) ||
        left.endpoint_id.localeCompare(right.endpoint_id),
    )
    .slice(0, MAX_ENDPOINTS);

  console.log(
    `[influence-stage5] eligible=${eligible.length} instances=${instances.length} concurrency=${CONCURRENCY} attempts=${MAX_INSTANCE_ATTEMPTS}`,
  );

  const results = PREFLIGHT_UNAVAILABLE
    ? []
    : await mapConcurrent(eligible, CONCURRENCY, (endpoint) =>
        processEndpoint(endpoint, entityById.get(endpoint.actor_id), instances),
      );
  const health = results.map((result) => result.health);
  const xItems = results.flatMap((result) => result.items);

  const existing = JSON.parse(await fs.readFile(ITEMS_PATH, "utf8"));
  if (!Array.isArray(existing.items)) {
    throw new Error(`${ITEMS_PATH} does not contain an items array.`);
  }

  const merged = new Map();
  const previousBaseItems = PREFLIGHT_UNAVAILABLE
    ? existing.items
    : existing.items.filter((item) => item.source_stage !== "stage5_x_nitter");

  for (const item of [
    ...previousBaseItems,
    ...xItems,
  ]) {
    if (item?.item_id) merged.set(item.item_id, item);
  }
  const mergedItems = [...merged.values()];
  const generatedAt = new Date().toISOString();
  const okCount = health.filter((item) => item.status === "ok").length;
  const errorCount = health.filter((item) => item.status === "error").length;
  const state =
    PREFLIGHT_UNAVAILABLE
      ? "unavailable"
      : health.length === 0
        ? "disabled"
        : okCount / health.length >= 0.75
        ? "ok"
        : okCount > 0
          ? "partial"
          : "error";

  const itemBundle = {
    ...existing,
    schema_version: existing.schema_version || "1.0.0",
    generated_at: generatedAt,
    mode: "website_rss_telegram_bluesky_youtube_x_nitter_metadata",
    data_policy: {
      ...(existing.data_policy || {}),
      full_text_persisted: false,
      sanctioned_source_full_text_persisted: false,
      score_integration: false,
      x_collection_completeness_guaranteed: false,
    },
    source_stages: unique([
      ...(existing.source_stages || ["stage2"]),
      "stage5_x_nitter",
    ]),
    counts: recomputeItemCounts(mergedItems),
    items: mergedItems,
  };

  const detailedHealth = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    mode: "nitter_multi_instance_rss_html_fallback",
    preflight_unavailable: PREFLIGHT_UNAVAILABLE,
    preflight_skip_reason: PREFLIGHT_UNAVAILABLE ? PREFLIGHT_SKIP_REASON : "",
    score_integration: false,
    completeness_guaranteed: false,
    configured_instances: instances.map((instance) => ({
      instance_hash: sha256(instance.base_url).slice(0, 16),
      rss_enabled: instance.rss_enabled !== false,
      priority: instance.priority ?? null,
    })),
    endpoint_count: eligible.length,
    status_counts: countBy(health, (item) => item.status),
    collection_mode_counts: countBy(
      health.filter((item) => item.status === "ok"),
      (item) => item.collection_mode,
    ),
    instance_statistics: instanceStatistics(health),
    sources: health,
  };

  const publicStatus = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    title: "MARD Influence & Narrative Watch — X/Nitter Ingest",
    mode: "nitter_multi_instance_rss_html_fallback",
    assessment_limit:
      "Best-effort public X collection through third-party Nitter instances. Missing posts or accounts are possible. No attribution, automation finding or HAT score integration.",
    collection_notice: PREFLIGHT_UNAVAILABLE
      ? "No configured public Nitter instance was usable from the GitHub runner. Per-account X collection was skipped and prior X metadata, if any, was retained."
      : "At least one public Nitter instance passed preflight; per-account collection was attempted.",
    counts: {
      configured_instances: instances.length,
      eligible_endpoints: eligible.length,
      checked_endpoints: health.length,
      successful_endpoints: okCount,
      failed_endpoints: errorCount,
      skipped_endpoints: PREFLIGHT_UNAVAILABLE ? eligible.length : 0,
      collected_x_items: xItems.length,
      merged_current_items: mergedItems.length,
    },
    coverage: {
      countries: countBy(health, (item) => item.country),
      actor_classes: countBy(health, (item) => item.actor_class),
      collection_modes: detailedHealth.collection_mode_counts,
    },
    source_health: {
      state,
      success_ratio: Number((okCount / Math.max(1, health.length)).toFixed(3)),
      completeness_guaranteed: false,
      skip_reason: PREFLIGHT_UNAVAILABLE ? PREFLIGHT_SKIP_REASON : "",
    },
  };

  const publicHealth = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    state,
    configured_instances: instances.length,
    preflight_unavailable: PREFLIGHT_UNAVAILABLE,
    skip_reason: PREFLIGHT_UNAVAILABLE ? PREFLIGHT_SKIP_REASON : "",
    status_counts: detailedHealth.status_counts,
    collection_mode_counts: detailedHealth.collection_mode_counts,
    instance_statistics: detailedHealth.instance_statistics,
    failures_by_country: countBy(
      health.filter((item) => item.status === "error"),
      (item) => item.country,
    ),
    failure_note:
      "Failures can reflect instance outages, rate limits, bot challenges, account availability or incomplete Nitter timelines.",
  };

  await fs.mkdir(path.dirname(ITEMS_PATH), { recursive: true });
  await fs.mkdir(path.dirname(HEALTH_PATH), { recursive: true });
  await fs.mkdir(path.dirname(PUBLIC_STATUS_PATH), { recursive: true });

  await fs.writeFile(ITEMS_PATH, JSON.stringify(itemBundle, null, 2), "utf8");
  await fs.writeFile(HEALTH_PATH, JSON.stringify(detailedHealth, null, 2), "utf8");
  await fs.writeFile(PUBLIC_STATUS_PATH, JSON.stringify(publicStatus, null, 2), "utf8");
  await fs.writeFile(PUBLIC_HEALTH_PATH, JSON.stringify(publicHealth, null, 2), "utf8");

  console.log(
    `[influence-stage5] checked=${health.length} ok=${okCount} error=${errorCount} x_items=${xItems.length} merged=${mergedItems.length} state=${state}`,
  );

  if (
    STRICT_MODE &&
    !PREFLIGHT_UNAVAILABLE &&
    eligible.length > 0 &&
    okCount === 0
  ) {
    throw new Error("Strict mode: no X endpoint completed successfully through Nitter.");
  }
}

export {
  handleFromEndpoint,
  normalizeItem,
  parseNitterHtml,
  parseNitterRss,
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
