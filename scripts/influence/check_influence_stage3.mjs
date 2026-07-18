#!/usr/bin/env node
import fs from "node:fs/promises";

const FILES = {
  history: "data/influence/history/items_history.jsonl",
  clusters: "data/influence/analysis/clusters_latest.json",
  activity: "data/influence/analysis/actor_activity_latest.json",
  publicLatest: "public/influence_watch_latest.json",
  publicHistory: "public/influence_watch_history.json",
};

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, "utf8"));
}

async function readJsonl(file) {
  const raw = await fs.readFile(file, "utf8");
  return raw
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function main() {
  const errors = [];
  const history = await readJsonl(FILES.history);
  const clusters = await readJson(FILES.clusters);
  const activity = await readJson(FILES.activity);
  const publicLatest = await readJson(FILES.publicLatest);
  const publicHistory = await readJson(FILES.publicHistory);

  if (!Array.isArray(clusters.clusters)) {
    errors.push("clusters_latest.json: clusters must be an array");
  }
  if (!Array.isArray(activity.actors)) {
    errors.push("actor_activity_latest.json: actors must be an array");
  }
  if (!Array.isArray(publicHistory.snapshots)) {
    errors.push("influence_watch_history.json: snapshots must be an array");
  }
  if (publicLatest.score_integration !== false) {
    errors.push("public latest must explicitly keep score_integration=false");
  }
  if (publicLatest?.history?.total_items !== history.length) {
    errors.push("public history item count differs from JSONL history");
  }

  const ids = new Set();
  for (const item of history) {
    if (!item.item_id) {
      errors.push("history contains an item without item_id");
      break;
    }
    if (ids.has(item.item_id)) {
      errors.push(`history contains duplicate item_id ${item.item_id}`);
      break;
    }
    ids.add(item.item_id);

    if (Object.hasOwn(item, "text") || Object.hasOwn(item, "description")) {
      errors.push(`history item ${item.item_id} contains a forbidden full-text field`);
      break;
    }
  }

  for (const cluster of clusters.clusters || []) {
    if (cluster.assessment?.attribution_grade !== false) {
      errors.push(`cluster ${cluster.cluster_id} must not be attribution-grade`);
      break;
    }
    if (cluster.assessment?.automation_finding !== false) {
      errors.push(`cluster ${cluster.cluster_id} must not claim automation`);
      break;
    }
    if (!Array.isArray(cluster.item_ids) || cluster.item_ids.length < 2) {
      errors.push(`cluster ${cluster.cluster_id} has insufficient items`);
      break;
    }
  }

  for (const cluster of publicLatest?.clusters?.top || []) {
    if (
      Object.hasOwn(cluster, "actor_ids") ||
      Object.hasOwn(cluster, "endpoint_ids") ||
      Object.hasOwn(cluster, "item_ids")
    ) {
      errors.push(`public cluster ${cluster.cluster_id} leaks internal identifiers`);
      break;
    }
  }

  if (errors.length) {
    for (const error of errors) console.error(`ERROR: ${error}`);
    process.exit(1);
  }

  console.log(
    `[influence-stage3-check] history=${history.length} clusters=${clusters.clusters.length} actors=${activity.actors.length} snapshots=${publicHistory.snapshots.length}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
