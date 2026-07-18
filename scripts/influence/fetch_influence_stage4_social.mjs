#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  createRegistryIndexes,
  loadInfluenceRegistry,
} from "./load_influence_registry.mjs";
import { validateInfluenceRegistry } from "./validate_influence_registry.mjs";

const ITEMS_PATH =
  process.env.MARD_INFLUENCE_CURRENT_ITEMS ||
  "data/influence/ingest/items_latest.json";
const HEALTH_PATH =
  process.env.MARD_INFLUENCE_SOCIAL_HEALTH ||
  "data/influence/ingest/social_source_health_latest.json";
const PUBLIC_STATUS_PATH =
  process.env.MARD_INFLUENCE_SOCIAL_PUBLIC_STATUS ||
  "public/influence_social_ingest_status.json";
const PUBLIC_HEALTH_PATH =
  process.env.MARD_INFLUENCE_SOCIAL_PUBLIC_HEALTH ||
  "public/influence_social_source_health.json";

const USER_AGENT =
  process.env.MARD_INFLUENCE_USER_AGENT ||
  "MARD-HAT Influence Watch/0.4 (+public OSINT telemetry; contact via repository)";
const REQUEST_TIMEOUT_MS = Number(
  process.env.MARD_INFLUENCE_REQUEST_TIMEOUT_MS || 15000,
);
const MAX_BODY_BYTES = Number(
  process.env.MARD_INFLUENCE_MAX_BODY_BYTES || 3_000_000,
);
const MAX_ITEMS_PER_SOURCE = Number(
  process.env.MARD_INFLUENCE_MAX_ITEMS_PER_SOCIAL_SOURCE || 30,
);
const MAX_ENDPOINTS = Number(
  process.env.MARD_INFLUENCE_MAX_SOCIAL_ENDPOINTS || 180,
);
const CONCURRENCY = Math.max(
  1,
  Math.min(10, Number(process.env.MARD_INFLUENCE_SOCIAL_CONCURRENCY || 6)),
);
const ELIGIBLE_PLATFORMS = new Set(["bluesky", "youtube"]);
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
    decodeEntities(String(value || "").replace(/<[^>]+>/g, " ")),
  );
}

function canonicalizeUrl(value, baseUrl = undefined) {
  try {
    const url = new URL(value, baseUrl);
    for (const key of [...url.searchParams.keys()]) {
      if (
        key.toLowerCase().startsWith("utm_") ||
        ["fbclid", "gclid", "mc_cid", "mc_eid"].includes(key.toLowerCase())
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

function unique(values) {
  return [...new Set(values.filter(Boolean))];
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

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(joined);
}

async function fetchResponse(url, accept, attempt = 1) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": USER_AGENT,
        accept,
      },
    });

    if (attempt === 1 && (response.status === 429 || response.status >= 500)) {
      await new Promise((resolve) => setTimeout(resolve, 1200));
      return fetchResponse(url, accept, 2);
    }

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    return {
      body: await readLimitedBody(response),
      finalUrl: response.url || url,
      status: response.status,
      contentType: response.headers.get("content-type") || "",
    };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJson(url) {
  const response = await fetchResponse(url, "application/json");
  try {
    return { json: JSON.parse(response.body), ...response };
  } catch (error) {
    throw new Error(`Invalid JSON from ${url}: ${error.message}`);
  }
}

async function fetchText(url, accept = "text/html,application/xml;q=0.9,*/*;q=0.5") {
  return fetchResponse(url, accept);
}

function extractBlueskyUris(record) {
  const urls = [];
  for (const facet of record?.facets || []) {
    for (const feature of facet?.features || []) {
      if (feature?.uri) urls.push(canonicalizeUrl(feature.uri));
    }
  }

  const externalUri = record?.embed?.external?.uri;
  if (externalUri) urls.push(canonicalizeUrl(externalUri));

  return unique(urls);
}

function bskyPublicPostUrl(authorHandle, uri) {
  const rkey = String(uri || "").split("/").pop();
  if (!authorHandle || !rkey) return "";
  return `https://bsky.app/profile/${encodeURIComponent(authorHandle)}/post/${encodeURIComponent(rkey)}`;
}

async function fetchBluesky(endpoint, actor) {
  const handle = normalizeWhitespace(endpoint.handle_or_domain).replace(/^@/, "");
  if (!handle) throw new Error("Bluesky handle is empty");

  const apiUrl = new URL(
    "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed",
  );
  apiUrl.searchParams.set("actor", handle);
  apiUrl.searchParams.set("limit", String(Math.min(100, MAX_ITEMS_PER_SOURCE)));
  apiUrl.searchParams.set("filter", "posts_no_replies");

  const response = await fetchJson(apiUrl.toString());
  const feed = Array.isArray(response.json?.feed) ? response.json.feed : [];

  return feed.slice(0, MAX_ITEMS_PER_SOURCE).map((entry, index) => {
    const post = entry?.post || {};
    const record = post?.record || {};
    const postHandle = post?.author?.handle || handle;
    const text = normalizeWhitespace(record?.text || "");
    const referencedUrls = extractBlueskyUris(record);
    const publicUrl = bskyPublicPostUrl(postHandle, post?.uri);

    return {
      source_item_index: index,
      item_type: "bluesky_post",
      title: "",
      text,
      url: publicUrl,
      published_at: toIsoDate(record?.createdAt || post?.indexedAt),
      referenced_urls: referencedUrls,
      native_id: post?.uri || post?.cid || publicUrl,
    };
  });
}

function extractYouTubeChannelId(profileUrl, html) {
  const direct = /\/channel\/(UC[A-Za-z0-9_-]{20,})/i.exec(profileUrl)?.[1];
  if (direct) return direct;

  const patterns = [
    /<meta\b[^>]*itemprop=["']channelId["'][^>]*content=["'](UC[A-Za-z0-9_-]{20,})["']/i,
    /<link\b[^>]*rel=["']canonical["'][^>]*href=["']https?:\/\/(?:www\.)?youtube\.com\/channel\/(UC[A-Za-z0-9_-]{20,})/i,
    /["']channelId["']\s*:\s*["'](UC[A-Za-z0-9_-]{20,})["']/i,
    /["']externalId["']\s*:\s*["'](UC[A-Za-z0-9_-]{20,})["']/i,
    /["']browseId["']\s*:\s*["'](UC[A-Za-z0-9_-]{20,})["']/i,
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(html);
    if (match) return match[1];
  }
  return "";
}

function getXmlTag(block, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const cdata = new RegExp(
    `<${escaped}\\b[^>]*>\\s*<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>\\s*</${escaped}>`,
    "i",
  ).exec(block);
  if (cdata) return normalizeWhitespace(cdata[1]);
  const match = new RegExp(
    `<${escaped}\\b[^>]*>([\\s\\S]*?)</${escaped}>`,
    "i",
  ).exec(block);
  return match ? normalizeWhitespace(match[1]) : "";
}

function parseYouTubeFeed(xml) {
  const entries = xml.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];
  return entries.slice(0, MAX_ITEMS_PER_SOURCE).map((entry, index) => {
    const videoId = stripHtml(getXmlTag(entry, "yt:videoId"));
    const title = stripHtml(getXmlTag(entry, "title"));
    const publishedAt = toIsoDate(stripHtml(getXmlTag(entry, "published")));
    const href = /<link\b[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i.exec(entry)?.[1];
    const url = canonicalizeUrl(
      href || (videoId ? `https://www.youtube.com/watch?v=${videoId}` : ""),
    );
    const text = normalizeWhitespace(`${title}\n${videoId}`);

    return {
      source_item_index: index,
      item_type: "youtube_video",
      title,
      text,
      url,
      published_at: publishedAt,
      referenced_urls: url ? [url] : [],
      native_id: videoId || url,
    };
  });
}

async function fetchYouTube(endpoint) {
  const page = await fetchText(endpoint.profile_url, "text/html,*/*;q=0.5");
  const channelId = extractYouTubeChannelId(page.finalUrl, page.body);
  if (!channelId) {
    throw new Error("Unable to resolve YouTube channel ID from profile page");
  }

  const feedUrl = `https://www.youtube.com/feeds/videos.xml?channel_id=${encodeURIComponent(channelId)}`;
  const feed = await fetchText(feedUrl, "application/atom+xml,application/xml,text/xml,*/*;q=0.5");
  const items = parseYouTubeFeed(feed.body);
  if (!items.length) throw new Error("YouTube channel feed contained no entries");

  return { items, channelId, feedUrl, finalUrl: page.finalUrl };
}

function restrictedActor(actor, endpoint) {
  return (
    RESTRICTED_ACTORS.has(actor.actor_id) ||
    actor.public_export_policy === "metadata_analysis_only" ||
    endpoint.public_export_policy === "metadata_analysis_only"
  );
}

function normalizeItem(item, endpoint, actor) {
  const restricted = restrictedActor(actor, endpoint);
  const sourceUrl = canonicalizeUrl(item.url || endpoint.profile_url);
  const text = normalizeWhitespace(item.text);
  const title = normalizeWhitespace(item.title);
  const referencedDomains = unique(
    (item.referenced_urls || []).map(domainOf),
  ).slice(0, 20);

  return {
    item_id: sha256(
      `${endpoint.endpoint_id}|${item.native_id || sourceUrl}|${item.published_at || ""}|${text}`,
    ).slice(0, 32),
    actor_id: actor.actor_id,
    endpoint_id: endpoint.endpoint_id,
    country: actor.country,
    actor_class: actor.actor_class,
    platform: endpoint.platform,
    item_type: item.item_type,
    source_stage: "stage4_social",
    observed_at: new Date().toISOString(),
    published_at: item.published_at,
    source_domain: domainOf(sourceUrl || endpoint.profile_url),
    source_url:
      restricted && sourceUrl
        ? `${new URL(sourceUrl).origin}/`
        : sourceUrl || endpoint.profile_url,
    title: restricted ? "" : title.slice(0, 400),
    title_sha256: sha256(title),
    content_sha256: sha256(text),
    content_simhash64: simhash64(text),
    content_length: text.length,
    referenced_domains: referencedDomains,
    restricted_publication: restricted,
  };
}

function priorityRank(priority) {
  return { critical: 0, high: 1, normal: 2, low: 3 }[priority] ?? 9;
}

async function processEndpoint(endpoint, actor) {
  const started = Date.now();
  const health = {
    endpoint_id: endpoint.endpoint_id,
    actor_id: endpoint.actor_id,
    country: actor.country,
    actor_class: actor.actor_class,
    platform: endpoint.platform,
    priority: endpoint.priority,
    status: "error",
    checked_at: new Date().toISOString(),
    duration_ms: 0,
    item_count: 0,
    resolved_identifier: "",
    feed_url: "",
    error: "",
  };

  try {
    let parsedItems = [];
    if (endpoint.platform === "bluesky") {
      parsedItems = await fetchBluesky(endpoint, actor);
      health.resolved_identifier = endpoint.handle_or_domain;
    } else if (endpoint.platform === "youtube") {
      const result = await fetchYouTube(endpoint);
      parsedItems = result.items;
      health.resolved_identifier = result.channelId;
      health.feed_url = result.feedUrl;
    } else {
      throw new Error(`Unsupported Stage 4 platform: ${endpoint.platform}`);
    }

    const uniqueItems = new Map();
    for (const item of parsedItems) {
      const normalized = normalizeItem(item, endpoint, actor);
      uniqueItems.set(normalized.item_id, normalized);
    }

    health.item_count = uniqueItems.size;
    health.status = "ok";
    return { health, items: [...uniqueItems.values()] };
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
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, () => worker()),
  );
  return results;
}

function countBy(items, selector) {
  const result = {};
  for (const item of items) {
    const key = selector(item) || "unknown";
    result[key] = (result[key] || 0) + 1;
  }
  return Object.fromEntries(
    Object.entries(result).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
  );
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
  };
}

async function main() {
  const { registry } = await loadInfluenceRegistry();
  const validation = validateInfluenceRegistry(registry);
  if (validation.errors.length) {
    throw new Error(`Registry validation failed with ${validation.errors.length} error(s).`);
  }

  const { endpoints, entityById } = createRegistryIndexes(registry);
  const eligible = endpoints
    .filter(
      (endpoint) =>
        endpoint.ingest_enabled === true &&
        ELIGIBLE_PLATFORMS.has(endpoint.platform) &&
        /^https?:\/\//i.test(endpoint.profile_url || ""),
    )
    .sort(
      (left, right) =>
        priorityRank(left.priority) - priorityRank(right.priority) ||
        left.platform.localeCompare(right.platform) ||
        left.endpoint_id.localeCompare(right.endpoint_id),
    )
    .slice(0, MAX_ENDPOINTS);

  console.log(
    `[influence-stage4] eligible=${eligible.length} concurrency=${CONCURRENCY}`,
  );

  const results = await mapConcurrent(eligible, CONCURRENCY, (endpoint) =>
    processEndpoint(endpoint, entityById.get(endpoint.actor_id)),
  );
  const health = results.map((result) => result.health);
  const socialItems = results.flatMap((result) => result.items);

  const existing = JSON.parse(await fs.readFile(ITEMS_PATH, "utf8"));
  if (!Array.isArray(existing.items)) {
    throw new Error(`${ITEMS_PATH} does not contain an items array.`);
  }

  const merged = new Map();
  for (const item of [...existing.items, ...socialItems]) {
    if (item?.item_id) merged.set(item.item_id, item);
  }
  const mergedItems = [...merged.values()];
  const generatedAt = new Date().toISOString();

  const itemBundle = {
    ...existing,
    schema_version: existing.schema_version || "1.0.0",
    generated_at: generatedAt,
    mode: "website_rss_telegram_bluesky_youtube_metadata",
    data_policy: {
      ...(existing.data_policy || {}),
      full_text_persisted: false,
      sanctioned_source_full_text_persisted: false,
      score_integration: false,
    },
    source_stages: unique([...(existing.source_stages || ["stage2"]), "stage4_social"]),
    counts: recomputeItemCounts(mergedItems),
    items: mergedItems,
  };

  const detailedHealth = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    mode: "bluesky_public_api_youtube_atom",
    score_integration: false,
    endpoint_count: eligible.length,
    status_counts: countBy(health, (item) => item.status),
    platform_counts: countBy(health, (item) => item.platform),
    sources: health,
  };

  const okCount = health.filter((item) => item.status === "ok").length;
  const state =
    okCount / Math.max(1, health.length) >= 0.75
      ? "ok"
      : okCount > 0
        ? "partial"
        : health.length === 0
          ? "disabled"
          : "error";

  const publicStatus = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    title: "MARD Influence & Narrative Watch — Social Ingest Status",
    mode: "bluesky_public_api_youtube_atom",
    assessment_limit:
      "Public post metadata and fingerprints only. No attribution, automation finding or HAT score integration.",
    counts: {
      eligible_endpoints: eligible.length,
      checked_endpoints: health.length,
      successful_endpoints: okCount,
      failed_endpoints: health.filter((item) => item.status === "error").length,
      collected_social_items: socialItems.length,
      merged_current_items: mergedItems.length,
    },
    coverage: {
      platforms: countBy(health, (item) => item.platform),
      countries: countBy(health, (item) => item.country),
      item_types: countBy(socialItems, (item) => item.item_type),
    },
    source_health: {
      state,
      success_ratio: Number((okCount / Math.max(1, health.length)).toFixed(3)),
    },
  };

  const publicHealth = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    state,
    status_counts: detailedHealth.status_counts,
    platform_counts: detailedHealth.platform_counts,
    failures_by_country: countBy(
      health.filter((item) => item.status === "error"),
      (item) => item.country,
    ),
  };

  await fs.mkdir(path.dirname(ITEMS_PATH), { recursive: true });
  await fs.mkdir(path.dirname(HEALTH_PATH), { recursive: true });
  await fs.mkdir(path.dirname(PUBLIC_STATUS_PATH), { recursive: true });

  await fs.writeFile(ITEMS_PATH, JSON.stringify(itemBundle, null, 2), "utf8");
  await fs.writeFile(HEALTH_PATH, JSON.stringify(detailedHealth, null, 2), "utf8");
  await fs.writeFile(PUBLIC_STATUS_PATH, JSON.stringify(publicStatus, null, 2), "utf8");
  await fs.writeFile(PUBLIC_HEALTH_PATH, JSON.stringify(publicHealth, null, 2), "utf8");

  console.log(
    `[influence-stage4] checked=${health.length} ok=${okCount} errors=${publicStatus.counts.failed_endpoints} social_items=${socialItems.length} merged_items=${mergedItems.length}`,
  );

  if (health.length > 0 && okCount === 0) {
    throw new Error("No Bluesky or YouTube endpoint completed successfully.");
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
