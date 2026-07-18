#!/usr/bin/env node
import fs from "node:fs/promises";

const FILES = {
  items: "data/influence/ingest/items_latest.json",
  health: "data/influence/ingest/social_source_health_latest.json",
  status: "public/influence_social_ingest_status.json",
  publicHealth: "public/influence_social_source_health.json",
};

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, "utf8"));
}

async function main() {
  const errors = [];
  const items = await readJson(FILES.items);
  const health = await readJson(FILES.health);
  const status = await readJson(FILES.status);
  const publicHealth = await readJson(FILES.publicHealth);

  if (!Array.isArray(items.items)) errors.push("items_latest.json: items must be an array");
  if (!Array.isArray(health.sources)) errors.push("social health: sources must be an array");
  if (!Array.isArray(items.source_stages) || !items.source_stages.includes("stage4_social")) {
    errors.push("items_latest.json does not record stage4_social");
  }
  if (status?.counts?.checked_endpoints !== health.sources.length) {
    errors.push("social checked endpoint count differs from detailed health");
  }
  if (!['ok', 'partial', 'error', 'disabled'].includes(publicHealth.state)) {
    errors.push("invalid public social source-health state");
  }

  const socialItems = (items.items || []).filter((item) =>
    ["bluesky_post", "youtube_video"].includes(item.item_type),
  );
  if (status?.counts?.merged_current_items !== items.items.length) {
    errors.push("merged item count differs from items_latest.json");
  }

  for (const item of socialItems) {
    if (Object.hasOwn(item, "text") || Object.hasOwn(item, "description")) {
      errors.push(`social item ${item.item_id} contains forbidden full text`);
      break;
    }
    if (!item.content_sha256 || !item.content_simhash64) {
      errors.push(`social item ${item.item_id} lacks fingerprints`);
      break;
    }
    if (item.source_stage !== "stage4_social") {
      errors.push(`social item ${item.item_id} lacks source_stage=stage4_social`);
      break;
    }
  }

  if (errors.length) {
    for (const error of errors) console.error(`ERROR: ${error}`);
    process.exit(1);
  }

  console.log(
    `[influence-stage4-check] sources=${health.sources.length} social_items=${socialItems.length} merged_items=${items.items.length} state=${publicHealth.state}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
