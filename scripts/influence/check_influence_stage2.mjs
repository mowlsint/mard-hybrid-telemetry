#!/usr/bin/env node
import fs from "node:fs/promises";

const REQUIRED_FILES = [
  "data/influence/ingest/items_latest.json",
  "data/influence/ingest/source_health_latest.json",
  "public/influence_ingest_status.json",
  "public/influence_source_health.json",
];

async function readJson(file) {
  const raw = await fs.readFile(file, "utf8");
  return JSON.parse(raw);
}

async function main() {
  for (const file of REQUIRED_FILES) {
    await fs.access(file);
  }

  const items = await readJson(REQUIRED_FILES[0]);
  const health = await readJson(REQUIRED_FILES[1]);
  const status = await readJson(REQUIRED_FILES[2]);
  const publicHealth = await readJson(REQUIRED_FILES[3]);

  const errors = [];

  if (!Array.isArray(items.items)) {
    errors.push("items_latest.json: items must be an array");
  }
  if (!Array.isArray(health.sources)) {
    errors.push("source_health_latest.json: sources must be an array");
  }
  if (status?.counts?.checked_endpoints !== health.sources.length) {
    errors.push("checked endpoint count differs from detailed source health");
  }
  if (
    status?.counts?.collected_items !==
    (Array.isArray(items.items) ? items.items.length : -1)
  ) {
    errors.push("collected item count differs from item bundle");
  }
  if (!["ok", "partial", "error"].includes(publicHealth.state)) {
    errors.push("public source-health state is invalid");
  }

  for (const item of items.items || []) {
    if (Object.hasOwn(item, "text") || Object.hasOwn(item, "description")) {
      errors.push(`persisted item ${item.item_id} contains forbidden full-text field`);
      break;
    }
    if (!item.content_sha256 || !item.content_simhash64) {
      errors.push(`persisted item ${item.item_id} lacks fingerprints`);
      break;
    }
  }

  if (errors.length) {
    for (const error of errors) console.error(`ERROR: ${error}`);
    process.exit(1);
  }

  console.log(
    `[influence-stage2-check] sources=${health.sources.length} items=${items.items.length} state=${publicHealth.state}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
