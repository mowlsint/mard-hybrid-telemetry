#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  createRegistryIndexes,
  loadInfluenceRegistry,
} from "./load_influence_registry.mjs";
import { validateInfluenceRegistry } from "./validate_influence_registry.mjs";

const USER_AGENT =
  process.env.MARD_INFLUENCE_USER_AGENT ||
  "MARD-HAT Influence Watch/0.2 (+public OSINT telemetry; contact via repository)";
const REQUEST_TIMEOUT_MS = Number(
  process.env.MARD_INFLUENCE_REQUEST_TIMEOUT_MS || 12000,
);
const MAX_BODY_BYTES = Number(
  process.env.MARD_INFLUENCE_MAX_BODY_BYTES || 2_000_000,
);
const MAX_ITEMS_PER_SOURCE = Number(
  process.env.MARD_INFLUENCE_MAX_ITEMS_PER_SOURCE || 10,
);
const MAX_ENDPOINTS = Number(
  process.env.MARD_INFLUENCE_MAX_ENDPOINTS || 180,
);
const CONCURRENCY = Math.max(
  1,
  Math.min(10, Number(process.env.MARD_INFLUENCE_CONCURRENCY || 5)),
);
const ELIGIBLE_PLATFORMS = new Set(["website", "telegram"]);
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
    .replace(/&#(\d+);/g, (_, number) =>
      String.fromCodePoint(Number(number)),
    )
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

function getXmlLink(block, baseUrl) {
  const textLink = getTag(block, ["link", "guid"]);
  if (textLink && /^https?:\/\//i.test(stripHtml(textLink))) {
    return canonicalizeUrl(stripHtml(textLink), baseUrl);
  }

  const hrefMatch =
    /<link\b[^>]*\bhref=["']([^"']+)["'][^>]*\/?>/i.exec(block) ||
    /<link\b[^>]*\bhref=["']([^"']+)["'][^>]*>/i.exec(block);
  if (hrefMatch) return canonicalizeUrl(decodeEntities(hrefMatch[1]), baseUrl);

  return baseUrl;
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

function extractUrls(value, baseUrl) {
  const urls = new Set();
  const hrefRegex = /\bhref=["']([^"'#]+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(String(value || "")))) {
    const resolved = canonicalizeUrl(decodeEntities(match[1]), baseUrl);
    if (resolved) urls.add(resolved);
    if (urls.size >= 20) break;
  }

  const textRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  while ((match = textRegex.exec(String(value || "")))) {
    const resolved = canonicalizeUrl(match[0], baseUrl);
    if (resolved) urls.add(resolved);
    if (urls.size >= 20) break;
  }

  return [...urls];
}

function domainOf(value) {
  try {
    return new URL(value).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
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

async function fetchText(url, attempt = 1) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": USER_AGENT,
        accept:
          "application/rss+xml, application/atom+xml, application/xml, text/xml, text/html;q=0.9, */*;q=0.5",
      },
    });

    if (
      attempt === 1 &&
      (response.status === 429 || response.status >= 500)
    ) {
      await new Promise((resolve) => setTimeout(resolve, 1200));
      return fetchText(url, 2);
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    return {
      body: await readLimitedBody(response),
      finalUrl: response.url || url,
      contentType: response.headers.get("content-type") || "",
      status: response.status,
    };
  } finally {
    clearTimeout(timer);
  }
}

function isFeed(contentType, body) {
  return (
    /(?:rss|atom|xml)/i.test(contentType) ||
    /^\s*<\?xml/i.test(body) ||
    /<(?:rss|feed)\b/i.test(body)
  );
}

function parseFeed(xml, feedUrl) {
  const blocks = [
    ...(xml.match(/<item\b[\s\S]*?<\/item>/gi) || []),
    ...(xml.match(/<entry\b[\s\S]*?<\/entry>/gi) || []),
  ];

  return blocks.slice(0, MAX_ITEMS_PER_SOURCE).map((block, index) => {
    const title = stripHtml(getTag(block, ["title"]));
    const description = stripHtml(
      getTag(block, ["description", "summary", "content", "content:encoded"]),
    );
    const url = getXmlLink(block, feedUrl);
    const publishedAt = toIsoDate(
      stripHtml(getTag(block, ["pubDate", "published", "updated", "dc:date"])),
    );
    const combined = normalizeWhitespace(`${title}\n${description}`);

    return {
      source_item_index: index,
      item_type: "feed_item",
      title,
      text: combined,
      url,
      published_at: publishedAt,
      referenced_urls: extractUrls(block, feedUrl),
    };
  });
}

function discoverFeeds(html, pageUrl) {
  const feeds = new Set();
  const linkRegex = /<link\b[^>]*>/gi;
  let match;

  while ((match = linkRegex.exec(html))) {
    const tag = match[0];
    if (
      !/\brel=["'][^"']*alternate/i.test(tag) ||
      !/\btype=["']application\/(?:rss|atom)\+xml/i.test(tag)
    ) {
      continue;
    }

    const href = /\bhref=["']([^"']+)["']/i.exec(tag)?.[1];
    const resolved = canonicalizeUrl(decodeEntities(href), pageUrl);
    if (resolved) feeds.add(resolved);
  }

  return [...feeds].slice(0, 2);
}

function htmlMeta(html, pageUrl) {
  const title =
    stripHtml(/<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1] || "") ||
    stripHtml(
      /<meta\b[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["']/i.exec(
        html,
      )?.[1] || "",
    );

  const description =
    decodeEntities(
      /<meta\b[^>]*(?:name|property)=["'](?:description|og:description)["'][^>]*content=["']([^"']*)["']/i.exec(
        html,
      )?.[1] || "",
    ) || "";

  const bodyText = stripHtml(
    /<body\b[^>]*>([\s\S]*?)<\/body>/i.exec(html)?.[1] || html,
  ).slice(0, 12000);

  return {
    title: normalizeWhitespace(title).slice(0, 400),
    description: normalizeWhitespace(description).slice(0, 1000),
    bodyText,
    referenced_urls: extractUrls(html, pageUrl),
  };
}

function telegramPublicUrl(profileUrl) {
  const url = new URL(profileUrl);
  const parts = url.pathname.split("/").filter(Boolean);
  if (!parts.length) throw new Error("Telegram channel path is empty");
  if (parts[0] === "s") return url.toString();
  return `https://t.me/s/${parts[0]}`;
}

function parseTelegram(html, sourceUrl) {
  const parts = html.split(/<div class="tgme_widget_message_wrap[^>]*>/i).slice(1);
  const items = [];

  for (const part of parts) {
    if (items.length >= MAX_ITEMS_PER_SOURCE) break;

    const postId = /\bdata-post=["']([^"']+)["']/i.exec(part)?.[1] || "";
    if (!postId) continue;

    const datetime =
      /<time\b[^>]*datetime=["']([^"']+)["']/i.exec(part)?.[1] || "";
    const textHtml =
      /<div class="tgme_widget_message_text[^>]*>([\s\S]*?)<\/div>/i.exec(part)?.[1] ||
      "";
    const text = stripHtml(textHtml).slice(0, 12000);
    const url = canonicalizeUrl(`https://t.me/${postId}`);
    const referencedUrls = extractUrls(textHtml, sourceUrl);

    items.push({
      source_item_index: items.length,
      item_type: "telegram_post",
      title: "",
      text,
      url,
      published_at: toIsoDate(datetime),
      referenced_urls: referencedUrls,
    });
  }

  return items;
}

function priorityRank(priority) {
  return { critical: 0, high: 1, normal: 2, low: 3 }[priority] ?? 9;
}

function endpointSort(a, b) {
  return (
    priorityRank(a.priority) - priorityRank(b.priority) ||
    a.platform.localeCompare(b.platform) ||
    a.endpoint_id.localeCompare(b.endpoint_id)
  );
}

function safeItem(item, endpoint, actor) {
  const restricted =
    RESTRICTED_ACTORS.has(actor.actor_id) ||
    actor.public_export_policy === "metadata_analysis_only" ||
    endpoint.public_export_policy === "metadata_analysis_only";

  const canonicalUrl = canonicalizeUrl(item.url || endpoint.profile_url);
  const referencedDomains = [
    ...new Set((item.referenced_urls || []).map(domainOf).filter(Boolean)),
  ].slice(0, 20);
  const text = normalizeWhitespace(item.text);
  const title = normalizeWhitespace(item.title);

  return {
    item_id: sha256(
      `${endpoint.endpoint_id}|${canonicalUrl}|${item.published_at || ""}|${text}`,
    ).slice(0, 32),
    actor_id: actor.actor_id,
    endpoint_id: endpoint.endpoint_id,
    country: actor.country,
    actor_class: actor.actor_class,
    platform: endpoint.platform,
    item_type: item.item_type,
    observed_at: new Date().toISOString(),
    published_at: item.published_at,
    source_domain: domainOf(canonicalUrl || endpoint.profile_url),
    source_url:
      restricted && canonicalUrl
        ? `${new URL(canonicalUrl).origin}/`
        : canonicalUrl || endpoint.profile_url,
    title: restricted ? "" : title.slice(0, 400),
    title_sha256: sha256(title),
    content_sha256: sha256(text),
    content_simhash64: simhash64(text),
    content_length: text.length,
    referenced_domains: referencedDomains,
    restricted_publication: restricted,
  };
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
    http_status: null,
    final_url: "",
    discovered_feeds: [],
    item_count: 0,
    error: "",
  };

  try {
    let sourceUrl = endpoint.profile_url;
    if (endpoint.platform === "telegram") {
      sourceUrl = telegramPublicUrl(sourceUrl);
    }

    const response = await fetchText(sourceUrl);
    health.http_status = response.status;
    health.final_url = response.finalUrl;

    let parsedItems = [];
    if (endpoint.platform === "telegram") {
      parsedItems = parseTelegram(response.body, response.finalUrl);
      if (!parsedItems.length) {
        throw new Error("No public Telegram messages found");
      }
    } else if (isFeed(response.contentType, response.body)) {
      parsedItems = parseFeed(response.body, response.finalUrl);
    } else {
      const feeds = discoverFeeds(response.body, response.finalUrl);
      health.discovered_feeds = feeds;

      for (const feedUrl of feeds) {
        try {
          const feed = await fetchText(feedUrl);
          if (isFeed(feed.contentType, feed.body)) {
            parsedItems.push(...parseFeed(feed.body, feed.finalUrl));
          }
        } catch (error) {
          health.status = "partial";
          health.error = `Feed discovery partial: ${error.message}`;
        }
      }

      if (!parsedItems.length) {
        const meta = htmlMeta(response.body, response.finalUrl);
        const combined = normalizeWhitespace(
          `${meta.title}\n${meta.description}\n${meta.bodyText}`,
        );
        parsedItems = [
          {
            source_item_index: 0,
            item_type: "website_snapshot",
            title: meta.title,
            text: combined,
            url: response.finalUrl,
            published_at: null,
            referenced_urls: meta.referenced_urls,
          },
        ];
      }
    }

    const unique = new Map();
    for (const item of parsedItems.slice(0, MAX_ITEMS_PER_SOURCE)) {
      const normalized = safeItem(item, endpoint, actor);
      unique.set(normalized.item_id, normalized);
    }

    health.item_count = unique.size;
    health.status = health.status === "partial" ? "partial" : "ok";
    return { health, items: [...unique.values()] };
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

async function main() {
  const { registry, registryPath } = await loadInfluenceRegistry();
  const validation = validateInfluenceRegistry(registry);
  if (validation.errors.length) {
    throw new Error(
      `Registry validation failed with ${validation.errors.length} error(s).`,
    );
  }

  const { endpoints, entityById } = createRegistryIndexes(registry);
  const eligible = endpoints
    .filter(
      (endpoint) =>
        endpoint.ingest_enabled === true &&
        ELIGIBLE_PLATFORMS.has(endpoint.platform) &&
        /^https?:\/\//i.test(endpoint.profile_url || ""),
    )
    .sort(endpointSort)
    .slice(0, MAX_ENDPOINTS);

  console.log(
    `[influence-stage2] registry=${registryPath} eligible=${eligible.length} concurrency=${CONCURRENCY}`,
  );

  const results = await mapConcurrent(eligible, CONCURRENCY, (endpoint) =>
    processEndpoint(endpoint, entityById.get(endpoint.actor_id)),
  );

  const health = results.map((result) => result.health);
  const items = results.flatMap((result) => result.items);
  const deduplicatedItems = [...new Map(items.map((item) => [item.item_id, item])).values()];
  const generatedAt = new Date().toISOString();

  const detailedHealth = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    mode: "website_rss_telegram_metadata",
    score_integration: false,
    endpoint_count: eligible.length,
    status_counts: countBy(health, (item) => item.status),
    platform_counts: countBy(health, (item) => item.platform),
    sources: health,
  };

  const itemBundle = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    mode: "metadata_fingerprints_only",
    data_policy: {
      full_text_persisted: false,
      sanctioned_source_full_text_persisted: false,
      score_integration: false,
    },
    counts: {
      items: deduplicatedItems.length,
      restricted_items: deduplicatedItems.filter(
        (item) => item.restricted_publication,
      ).length,
      website_snapshots: deduplicatedItems.filter(
        (item) => item.item_type === "website_snapshot",
      ).length,
      feed_items: deduplicatedItems.filter(
        (item) => item.item_type === "feed_item",
      ).length,
      telegram_posts: deduplicatedItems.filter(
        (item) => item.item_type === "telegram_post",
      ).length,
    },
    items: deduplicatedItems,
  };

  const publicStatus = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    title: "MARD Influence & Narrative Watch — Ingest Status",
    mode: "website_rss_telegram_metadata",
    assessment_limit:
      "Source collection and fingerprints only. No attribution, coordination finding or HAT score integration.",
    counts: {
      eligible_endpoints: eligible.length,
      checked_endpoints: health.length,
      successful_endpoints: health.filter((item) => item.status === "ok").length,
      partial_endpoints: health.filter((item) => item.status === "partial").length,
      failed_endpoints: health.filter((item) => item.status === "error").length,
      collected_items: deduplicatedItems.length,
      discovered_feeds: health.reduce(
        (sum, item) => sum + item.discovered_feeds.length,
        0,
      ),
    },
    coverage: {
      platforms: countBy(health, (item) => item.platform),
      countries: countBy(health, (item) => item.country),
      actor_classes: countBy(health, (item) => item.actor_class),
      item_types: countBy(deduplicatedItems, (item) => item.item_type),
    },
    source_health: {
      state:
        health.filter((item) => item.status === "ok").length / Math.max(1, health.length) >=
        0.75
          ? "ok"
          : health.some((item) => item.status === "ok")
            ? "partial"
            : "error",
      success_ratio: Number(
        (
          health.filter((item) => item.status === "ok").length /
          Math.max(1, health.length)
        ).toFixed(3),
      ),
    },
  };

  const publicHealth = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    state: publicStatus.source_health.state,
    status_counts: detailedHealth.status_counts,
    platform_counts: detailedHealth.platform_counts,
    failures_by_country: countBy(
      health.filter((item) => item.status === "error"),
      (item) => item.country,
    ),
    failures_by_actor_class: countBy(
      health.filter((item) => item.status === "error"),
      (item) => item.actor_class,
    ),
  };

  await fs.mkdir("data/influence/ingest", { recursive: true });
  await fs.mkdir("public", { recursive: true });

  await fs.writeFile(
    "data/influence/ingest/items_latest.json",
    JSON.stringify(itemBundle, null, 2),
    "utf8",
  );
  await fs.writeFile(
    "data/influence/ingest/source_health_latest.json",
    JSON.stringify(detailedHealth, null, 2),
    "utf8",
  );
  await fs.writeFile(
    "public/influence_ingest_status.json",
    JSON.stringify(publicStatus, null, 2),
    "utf8",
  );
  await fs.writeFile(
    "public/influence_source_health.json",
    JSON.stringify(publicHealth, null, 2),
    "utf8",
  );

  console.log(
    `[influence-stage2] checked=${health.length} ok=${publicStatus.counts.successful_endpoints} partial=${publicStatus.counts.partial_endpoints} error=${publicStatus.counts.failed_endpoints} items=${deduplicatedItems.length}`,
  );

  if (!health.some((item) => item.status === "ok")) {
    throw new Error("No influence source completed successfully.");
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
