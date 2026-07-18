#!/usr/bin/env node
import fs from "node:fs/promises";

const FILES = {
  items: "data/influence/ingest/items_latest.json",
  health: "data/influence/ingest/x_source_health_latest.json",
  status: "public/influence_x_ingest_status.json",
  publicHealth: "public/influence_x_source_health.json",
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
  if (!Array.isArray(health.sources)) errors.push("X health: sources must be an array");
  if (!Array.isArray(health.configured_instances)) {
    errors.push("X health: configured_instances must be an array");
  }
  if (!Array.isArray(items.source_stages) || !items.source_stages.includes("stage5_x_nitter")) {
    errors.push("items_latest.json does not record stage5_x_nitter");
  }
  if (status?.counts?.checked_endpoints !== health.sources.length) {
    errors.push("X checked endpoint count differs from detailed health");
  }
  if (!["ok", "partial", "error", "disabled"].includes(publicHealth.state)) {
    errors.push("invalid public X source-health state");
  }
  if (status?.source_health?.completeness_guaranteed !== false) {
    errors.push("X status must explicitly mark completeness_guaranteed=false");
  }

  const xItems = (items.items || []).filter((item) => item.item_type === "x_post");
  if (status?.counts?.merged_current_items !== items.items.length) {
    errors.push("merged item count differs from items_latest.json");
  }
  if ((items.counts?.x_posts ?? -1) !== xItems.length) {
    errors.push("x_posts count differs from current item bundle");
  }

  for (const item of xItems) {
    if (Object.hasOwn(item, "text") || Object.hasOwn(item, "description")) {
      errors.push(`X item ${item.item_id} contains forbidden full text`);
      break;
    }
    if (!item.content_sha256 || !item.content_simhash64) {
      errors.push(`X item ${item.item_id} lacks fingerprints`);
      break;
    }
    if (item.source_stage !== "stage5_x_nitter") {
      errors.push(`X item ${item.item_id} lacks source_stage=stage5_x_nitter`);
      break;
    }
    if (item.collection_proxy !== "nitter") {
      errors.push(`X item ${item.item_id} lacks collection_proxy=nitter`);
      break;
    }
  }

  if (errors.length) {
    for (const error of errors) console.error(`ERROR: ${error}`);
    process.exit(1);
  }

  console.log(
    `[influence-stage5-check] sources=${health.sources.length} x_items=${xItems.length} instances=${health.configured_instances.length} state=${publicHealth.state}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
