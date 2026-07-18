#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  normalizeItem,
  parseNitterHtml,
  parseNitterRss,
} from "./fetch_influence_stage5_x_nitter.mjs";

const rss = `<?xml version="1.0"?>
<rss><channel><item>
<title>Maritime test post</title>
<description><![CDATA[Maritime test with <a href="https://example.org/story?utm_source=x">external link</a>]]></description>
<link>https://nitter.example/Alice_Weidel/status/123456</link>
<pubDate>Sat, 18 Jul 2026 10:00:00 GMT</pubDate>
</item></channel></rss>`;

const rssItems = parseNitterRss(
  rss,
  "https://nitter.example/Alice_Weidel/rss",
  "Alice_Weidel",
);
assert.equal(rssItems.length, 1);
assert.equal(rssItems[0].native_id, "123456");
assert.equal(rssItems[0].url, "https://x.com/Alice_Weidel/status/123456");
assert.ok(rssItems[0].referenced_urls.includes("https://example.org/story"));

const html = `<html><body>
<div class="timeline-item">
  <a class="tweet-link" href="/Alice_Weidel/status/789012#m"></a>
  <div class="tweet-content media-body" dir="auto">Cable test <a href="https://example.net/report">report</a></div>
  <span class="tweet-date"><a title="Jul 18, 2026 · 11:00 AM UTC"></a></span>
</div>
</body></html>`;
const htmlItems = parseNitterHtml(
  html,
  "https://nitter.example/Alice_Weidel",
  "Alice_Weidel",
);
assert.equal(htmlItems.length, 1);
assert.equal(htmlItems[0].native_id, "789012");
assert.ok(htmlItems[0].referenced_urls.includes("https://example.net/report"));

const endpoint = {
  actor_id: "de_alice_weidel",
  endpoint_id: "de_alice_weidel__x__alice_weidel",
  platform: "x",
  handle_or_domain: "Alice_Weidel",
  profile_url: "https://x.com/Alice_Weidel",
  public_export_policy: "inherit",
};
const actor = {
  actor_id: "de_alice_weidel",
  country: "DE",
  actor_class: "political_actor",
  public_export_policy: "metadata_analysis_and_short_excerpts",
};
const normalized = normalizeItem(
  rssItems[0],
  endpoint,
  actor,
  "https://nitter.example",
  "rss",
);
assert.equal(normalized.item_type, "x_post");
assert.equal(normalized.source_stage, "stage5_x_nitter");
assert.equal(normalized.source_url, "https://x.com/Alice_Weidel/status/123456");
assert.deepEqual(normalized.referenced_domains, ["example.org"]);
assert.equal(Object.hasOwn(normalized, "text"), false);
assert.equal(Object.hasOwn(normalized, "description"), false);
assert.match(normalized.content_sha256, /^[0-9a-f]{64}$/);
assert.match(normalized.content_simhash64, /^[0-9a-f]{16}$/);

console.log("[influence-stage5-parser-test] RSS, HTML, URL and privacy checks passed");
