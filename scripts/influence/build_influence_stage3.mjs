#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  createRegistryIndexes,
  loadInfluenceRegistry,
} from "./load_influence_registry.mjs";
import { validateInfluenceRegistry } from "./validate_influence_registry.mjs";

const CURRENT_ITEMS_PATH =
  process.env.MARD_INFLUENCE_CURRENT_ITEMS ||
  "data/influence/ingest/items_latest.json";
const HISTORY_PATH =
  process.env.MARD_INFLUENCE_HISTORY ||
  "data/influence/history/items_history.jsonl";
const CLUSTERS_PATH =
  process.env.MARD_INFLUENCE_CLUSTERS ||
  "data/influence/analysis/clusters_latest.json";
const ACTIVITY_PATH =
  process.env.MARD_INFLUENCE_ACTIVITY ||
  "data/influence/analysis/actor_activity_latest.json";
const PUBLIC_LATEST_PATH =
  process.env.MARD_INFLUENCE_PUBLIC_LATEST ||
  "public/influence_watch_latest.json";
const PUBLIC_HISTORY_PATH =
  process.env.MARD_INFLUENCE_PUBLIC_HISTORY ||
  "public/influence_watch_history.json";

const RETENTION_DAYS = Math.max(
  7,
  Number(process.env.MARD_INFLUENCE_RETENTION_DAYS || 35),
);
const MAX_HISTORY_ITEMS = Math.max(
  1000,
  Number(process.env.MARD_INFLUENCE_MAX_HISTORY_ITEMS || 25000),
);
const MAX_HISTORY_BYTES = Math.max(
  1_000_000,
  Number(process.env.MARD_INFLUENCE_MAX_HISTORY_BYTES || 20_000_000),
);
const CLUSTER_WINDOW_HOURS = Math.max(
  6,
  Number(process.env.MARD_INFLUENCE_CLUSTER_WINDOW_HOURS || 72),
);
const MAX_PUBLIC_CLUSTERS = Math.max(
  5,
  Number(process.env.MARD_INFLUENCE_MAX_PUBLIC_CLUSTERS || 20),
);
const MAX_INTERNAL_CLUSTERS = Math.max(
  20,
  Number(process.env.MARD_INFLUENCE_MAX_INTERNAL_CLUSTERS || 200),
);
const PUBLIC_HISTORY_SNAPSHOTS = Math.max(
  24,
  Number(process.env.MARD_INFLUENCE_PUBLIC_HISTORY_SNAPSHOTS || 180),
);

function sha256(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function itemTimestamp(item) {
  const value = item?.published_at || item?.observed_at;
  const parsed = value ? new Date(value).getTime() : Number.NaN;
  return Number.isFinite(parsed) ? parsed : 0;
}

function hamming64(left, right) {
  if (!/^[0-9a-f]{16}$/i.test(left || "") || !/^[0-9a-f]{16}$/i.test(right || "")) {
    return 64;
  }
  let value = BigInt(`0x${left}`) ^ BigInt(`0x${right}`);
  let count = 0;
  while (value) {
    count += Number(value & 1n);
    value >>= 1n;
  }
  return count;
}

function simhashBands(value) {
  if (!/^[0-9a-f]{16}$/i.test(value || "")) return [];
  return [0, 1, 2, 3].map((index) => `${index}:${value.slice(index * 4, index * 4 + 4)}`);
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

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, "utf8"));
}

async function readJsonIfExists(file, fallback) {
  try {
    return await readJson(file);
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    throw error;
  }
}

async function readJsonlIfExists(file) {
  try {
    const raw = await fs.readFile(file, "utf8");
    return raw
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line, index) => {
        try {
          return JSON.parse(line);
        } catch (error) {
          throw new Error(`Invalid JSONL at ${file}:${index + 1}: ${error.message}`);
        }
      });
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

function serialiseJsonl(items) {
  return items.map((item) => JSON.stringify(item)).join("\n") + (items.length ? "\n" : "");
}

function pruneHistoryByBytes(items) {
  let selected = items.slice(0, MAX_HISTORY_ITEMS);
  let raw = serialiseJsonl(selected);

  while (Buffer.byteLength(raw, "utf8") > MAX_HISTORY_BYTES && selected.length > 1000) {
    selected = selected.slice(0, Math.max(1000, Math.floor(selected.length * 0.9)));
    raw = serialiseJsonl(selected);
  }

  return { items: selected, raw };
}

class UnionFind {
  constructor(size) {
    this.parent = Array.from({ length: size }, (_, index) => index);
    this.rank = new Array(size).fill(0);
  }

  find(value) {
    let current = value;
    while (this.parent[current] !== current) {
      this.parent[current] = this.parent[this.parent[current]];
      current = this.parent[current];
    }
    return current;
  }

  union(left, right) {
    let a = this.find(left);
    let b = this.find(right);
    if (a === b) return;
    if (this.rank[a] < this.rank[b]) [a, b] = [b, a];
    this.parent[b] = a;
    if (this.rank[a] === this.rank[b]) this.rank[a] += 1;
  }
}

function addBucket(map, key, index) {
  if (!key) return;
  const values = map.get(key) || [];
  values.push(index);
  map.set(key, values);
}

function candidateKey(left, right) {
  return left < right ? `${left}:${right}` : `${right}:${left}`;
}

function buildCandidatePairs(items) {
  const exact = new Map();
  const bands = new Map();
  const domains = new Map();

  for (const [index, item] of items.entries()) {
    addBucket(exact, item.content_sha256, index);

    const sixHourBucket = Math.floor(itemTimestamp(item) / (6 * 60 * 60 * 1000));
    for (const band of simhashBands(item.content_simhash64)) {
      addBucket(bands, `${sixHourBucket}:${band}`, index);
      addBucket(bands, `${sixHourBucket - 1}:${band}`, index);
    }

    for (const domain of item.referenced_domains || []) {
      addBucket(domains, `${sixHourBucket}:${domain}`, index);
      addBucket(domains, `${sixHourBucket - 1}:${domain}`, index);
    }
  }

  const pairs = new Set();
  for (const bucket of [...exact.values(), ...bands.values(), ...domains.values()]) {
    const limited = bucket.slice(0, 250);
    for (let left = 0; left < limited.length; left += 1) {
      for (let right = left + 1; right < limited.length; right += 1) {
        pairs.add(candidateKey(limited[left], limited[right]));
        if (pairs.size >= 250000) return pairs;
      }
    }
  }
  return pairs;
}

function comparePair(left, right) {
  const timeDeltaMinutes =
    Math.abs(itemTimestamp(left) - itemTimestamp(right)) / (60 * 1000);
  if (timeDeltaMinutes > 24 * 60) return null;

  const exactContent =
    left.content_sha256 &&
    right.content_sha256 &&
    left.content_sha256 === right.content_sha256;
  const simhashDistance = hamming64(
    left.content_simhash64,
    right.content_simhash64,
  );
  const sharedDomains = unique(
    (left.referenced_domains || []).filter((domain) =>
      (right.referenced_domains || []).includes(domain),
    ),
  );

  let score = 0;
  const signals = [];

  if (exactContent) {
    score += 70;
    signals.push("exact_content_hash");
  } else if (simhashDistance <= 3) {
    score += 55;
    signals.push("near_duplicate_text");
  } else if (simhashDistance <= 7) {
    score += 38;
    signals.push("similar_text");
  } else if (simhashDistance <= 11 && sharedDomains.length) {
    score += 22;
    signals.push("weak_text_similarity");
  }

  if (sharedDomains.length) {
    score += Math.min(20, 10 + sharedDomains.length * 3);
    signals.push("shared_referenced_domain");
  }

  if (timeDeltaMinutes <= 15) {
    score += 20;
    signals.push("within_15_minutes");
  } else if (timeDeltaMinutes <= 90) {
    score += 14;
    signals.push("within_90_minutes");
  } else if (timeDeltaMinutes <= 360) {
    score += 7;
    signals.push("within_6_hours");
  }

  if (left.actor_id !== right.actor_id) score += 5;
  if (left.endpoint_id !== right.endpoint_id) score += 3;

  return {
    score: Math.min(100, score),
    signals: unique(signals),
    exact_content: exactContent,
    simhash_distance: simhashDistance,
    shared_domains: sharedDomains,
    time_delta_minutes: Math.round(timeDeltaMinutes),
  };
}

function clusterAssessmentScore(items, edges) {
  const timestamps = items.map(itemTimestamp).filter(Boolean);
  const spanMinutes = timestamps.length
    ? (Math.max(...timestamps) - Math.min(...timestamps)) / (60 * 1000)
    : 0;
  const actorCount = unique(items.map((item) => item.actor_id)).length;
  const endpointCount = unique(items.map((item) => item.endpoint_id)).length;
  const exactEdges = edges.filter((edge) => edge.exact_content).length;
  const rapidEdges = edges.filter((edge) => edge.time_delta_minutes <= 90).length;
  const sharedLinkEdges = edges.filter((edge) => edge.shared_domains.length).length;

  const similarity =
    edges.length > 0
      ? Math.round(
          edges.reduce((sum, edge) => sum + Math.min(100, edge.score), 0) /
            edges.length,
        )
      : 0;
  const rapidRatio = edges.length ? rapidEdges / edges.length : 0;
  const exactRatio = edges.length ? exactEdges / edges.length : 0;
  const sharedLinkRatio = edges.length ? sharedLinkEdges / edges.length : 0;

  let score = similarity * 0.4;
  score += Math.min(20, actorCount * 4);
  score += rapidRatio * 18;
  score += exactRatio * 12;
  score += sharedLinkRatio * 10;
  if (spanMinutes > 24 * 60) score -= 10;

  return Math.max(0, Math.min(100, Math.round(score)));
}

function buildClusters(items) {
  const candidates = buildCandidatePairs(items);
  const unionFind = new UnionFind(items.length);
  const acceptedEdges = [];

  for (const key of candidates) {
    const [leftIndex, rightIndex] = key.split(":").map(Number);
    const left = items[leftIndex];
    const right = items[rightIndex];

    if (!left || !right) continue;
    if (left.actor_id === right.actor_id && left.endpoint_id === right.endpoint_id) {
      continue;
    }

    const comparison = comparePair(left, right);
    if (!comparison || comparison.score < 58) continue;

    unionFind.union(leftIndex, rightIndex);
    acceptedEdges.push({
      left: leftIndex,
      right: rightIndex,
      ...comparison,
    });
  }

  const groups = new Map();
  for (let index = 0; index < items.length; index += 1) {
    const root = unionFind.find(index);
    const values = groups.get(root) || [];
    values.push(index);
    groups.set(root, values);
  }

  const clusters = [];
  for (const indexes of groups.values()) {
    if (indexes.length < 2) continue;

    const clusterItems = indexes.map((index) => items[index]);
    const actorIds = unique(clusterItems.map((item) => item.actor_id));
    const endpointIds = unique(clusterItems.map((item) => item.endpoint_id));
    if (actorIds.length < 2 && endpointIds.length < 3) continue;

    const indexSet = new Set(indexes);
    const clusterEdges = acceptedEdges.filter(
      (edge) => indexSet.has(edge.left) && indexSet.has(edge.right),
    );
    if (!clusterEdges.length) continue;

    const timestamps = clusterItems.map(itemTimestamp).filter(Boolean);
    const signals = unique(clusterEdges.flatMap((edge) => edge.signals));
    const score = clusterAssessmentScore(clusterItems, clusterEdges);
    const startAt = timestamps.length
      ? new Date(Math.min(...timestamps)).toISOString()
      : null;
    const endAt = timestamps.length
      ? new Date(Math.max(...timestamps)).toISOString()
      : null;
    const spanMinutes = timestamps.length
      ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 60000)
      : null;
    const contentHashes = unique(clusterItems.map((item) => item.content_sha256));
    const sharedDomains = countBy(
      clusterEdges.flatMap((edge) => edge.shared_domains),
      (domain) => domain,
    );

    clusters.push({
      cluster_id: sha256(
        [...clusterItems.map((item) => item.item_id)].sort().join("|"),
      ).slice(0, 24),
      generated_at: new Date().toISOString(),
      assessment: {
        label:
          score >= 80
            ? "strong_amplification_pattern"
            : score >= 65
              ? "elevated_amplification_pattern"
              : "possible_amplification_pattern",
        coordination_indicator_score: score,
        confidence:
          score >= 80 && actorIds.length >= 4
            ? "medium"
            : score >= 65
              ? "low_medium"
              : "low",
        attribution_grade: false,
        automation_finding: false,
      },
      counts: {
        items: clusterItems.length,
        actors: actorIds.length,
        endpoints: endpointIds.length,
        unique_content_hashes: contentHashes.length,
        pair_edges: clusterEdges.length,
      },
      time: {
        start_at: startAt,
        end_at: endAt,
        span_minutes: spanMinutes,
      },
      signals,
      actor_ids: actorIds,
      endpoint_ids: endpointIds,
      item_ids: clusterItems.map((item) => item.item_id),
      platforms: countBy(clusterItems, (item) => item.platform),
      countries: countBy(clusterItems, (item) => item.country),
      actor_classes: countBy(clusterItems, (item) => item.actor_class),
      shared_referenced_domains: sharedDomains,
      restricted_item_count: clusterItems.filter(
        (item) => item.restricted_publication,
      ).length,
    });
  }

  return clusters
    .sort(
      (a, b) =>
        b.assessment.coordination_indicator_score -
          a.assessment.coordination_indicator_score ||
        b.counts.items - a.counts.items,
    )
    .slice(0, MAX_INTERNAL_CLUSTERS);
}

function timeWindowItems(items, hours) {
  const cutoff = Date.now() - hours * 60 * 60 * 1000;
  return items.filter((item) => itemTimestamp(item) >= cutoff);
}

function buildActorActivity(history, entityById, policy) {
  const last7d = timeWindowItems(history, 7 * 24);
  const last28d = timeWindowItems(history, 28 * 24);
  const byActor7d = new Map();
  const byActor28d = new Map();

  for (const item of last7d) {
    const values = byActor7d.get(item.actor_id) || [];
    values.push(item);
    byActor7d.set(item.actor_id, values);
  }
  for (const item of last28d) {
    const values = byActor28d.get(item.actor_id) || [];
    values.push(item);
    byActor28d.set(item.actor_id, values);
  }

  const minimum7d =
    policy?.political_actor_entry_rules?.minimum_political_posts_per_week ?? 10;
  const minimum28d =
    policy?.political_actor_entry_rules?.minimum_political_posts_in_window ?? 40;

  const actorIds = unique([...byActor7d.keys(), ...byActor28d.keys()]);
  return actorIds
    .map((actorId) => {
      const actor = entityById.get(actorId) || {};
      const items7d = byActor7d.get(actorId) || [];
      const items28d = byActor28d.get(actorId) || [];
      return {
        actor_id: actorId,
        display_name: actor.display_name || actorId,
        actor_class: actor.actor_class || "unknown",
        country: actor.country || "unknown",
        counts: {
          items_7d: items7d.length,
          items_28d: items28d.length,
          platforms_28d: unique(items28d.map((item) => item.platform)).length,
          endpoints_28d: unique(items28d.map((item) => item.endpoint_id)).length,
        },
        provisional_thresholds: {
          meets_10_per_week_observed: items7d.length >= minimum7d,
          meets_40_per_28d_observed: items28d.length >= minimum28d,
          final_selection_decision: false,
        },
      };
    })
    .sort((a, b) => b.counts.items_28d - a.counts.items_28d);
}

function publicCluster(cluster) {
  return {
    cluster_id: cluster.cluster_id,
    assessment: cluster.assessment,
    counts: cluster.counts,
    time: cluster.time,
    signals: cluster.signals,
    platforms: cluster.platforms,
    countries: cluster.countries,
    actor_classes: cluster.actor_classes,
    shared_domain_count: Object.keys(cluster.shared_referenced_domains).length,
    restricted_item_count: cluster.restricted_item_count,
  };
}

async function main() {
  const { registry } = await loadInfluenceRegistry();
  const validation = validateInfluenceRegistry(registry);
  if (validation.errors.length) {
    throw new Error(
      `Registry validation failed with ${validation.errors.length} error(s).`,
    );
  }

  const currentBundle = await readJson(CURRENT_ITEMS_PATH);
  if (!Array.isArray(currentBundle.items)) {
    throw new Error(`${CURRENT_ITEMS_PATH} does not contain an items array.`);
  }

  const previousHistory = await readJsonlIfExists(HISTORY_PATH);
  const merged = new Map();
  for (const item of [...previousHistory, ...currentBundle.items]) {
    if (item?.item_id) merged.set(item.item_id, item);
  }

  const retentionCutoff =
    Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const retained = [...merged.values()]
    .filter((item) => itemTimestamp(item) >= retentionCutoff)
    .sort((a, b) => itemTimestamp(b) - itemTimestamp(a));

  const pruned = pruneHistoryByBytes(retained);
  const history = pruned.items;

  const clusterItems = timeWindowItems(history, CLUSTER_WINDOW_HOURS);
  const clusters = buildClusters(clusterItems);

  const { entityById } = createRegistryIndexes(registry);
  const activity = buildActorActivity(
    history,
    entityById,
    registry.selection_policy,
  );

  const generatedAt = new Date().toISOString();
  const historyStats = {
    total_items: history.length,
    current_run_items: currentBundle.items.length,
    items_24h: timeWindowItems(history, 24).length,
    items_7d: timeWindowItems(history, 7 * 24).length,
    items_28d: timeWindowItems(history, 28 * 24).length,
    oldest_item_at: history.length
      ? new Date(Math.min(...history.map(itemTimestamp))).toISOString()
      : null,
    newest_item_at: history.length
      ? new Date(Math.max(...history.map(itemTimestamp))).toISOString()
      : null,
    retained_days: RETENTION_DAYS,
    max_items: MAX_HISTORY_ITEMS,
    max_bytes: MAX_HISTORY_BYTES,
    actual_bytes: Buffer.byteLength(pruned.raw, "utf8"),
  };

  const internalClusters = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    mode: "hash_simhash_domain_time_clustering",
    assessment_limit:
      "Clusters are analytical indicators of similar or synchronized public content. They are not attribution findings or bot determinations.",
    parameters: {
      cluster_window_hours: CLUSTER_WINDOW_HOURS,
      minimum_pair_score: 58,
      maximum_internal_clusters: MAX_INTERNAL_CLUSTERS,
    },
    counts: {
      analysed_items: clusterItems.length,
      clusters: clusters.length,
      elevated_clusters: clusters.filter(
        (cluster) =>
          cluster.assessment.coordination_indicator_score >= 65,
      ).length,
      strong_clusters: clusters.filter(
        (cluster) =>
          cluster.assessment.coordination_indicator_score >= 80,
      ).length,
    },
    clusters,
  };

  const actorActivity = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    coverage_complete: false,
    status: "provisional_stage2_sources_only",
    methodology_note:
      "The 10-post/week and 40-post/28-day rules cannot make a final account-selection decision until the social-platform ingest is complete.",
    actors: activity,
  };

  const publicLatest = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    title: "MARD Influence & Narrative Watch",
    level:
      clusters.some(
        (cluster) =>
          cluster.assessment.coordination_indicator_score >= 80,
      )
        ? "elevated"
        : clusters.some(
              (cluster) =>
                cluster.assessment.coordination_indicator_score >= 65,
            )
          ? "watch"
          : "baseline",
    confidence: clusters.length ? "low_medium" : "low",
    assessment_limit:
      "Early-warning context only. Similarity and synchronisation do not prove coordination, automation, attribution or disinformation.",
    score_integration: false,
    source_stage: "website_rss_telegram_metadata",
    history: historyStats,
    activity: {
      active_actors_7d: activity.filter(
        (actor) => actor.counts.items_7d > 0,
      ).length,
      provisional_10_per_week_actors: activity.filter(
        (actor) =>
          actor.provisional_thresholds.meets_10_per_week_observed,
      ).length,
      final_selection_decisions: 0,
    },
    clusters: {
      total: clusters.length,
      elevated: clusters.filter(
        (cluster) =>
          cluster.assessment.coordination_indicator_score >= 65,
      ).length,
      strong: clusters.filter(
        (cluster) =>
          cluster.assessment.coordination_indicator_score >= 80,
      ).length,
      top: clusters.slice(0, MAX_PUBLIC_CLUSTERS).map(publicCluster),
    },
  };

  const previousPublicHistory = await readJsonIfExists(
    PUBLIC_HISTORY_PATH,
    { schema_version: "1.0.0", snapshots: [] },
  );
  const snapshot = {
    generated_at: generatedAt,
    level: publicLatest.level,
    confidence: publicLatest.confidence,
    history_items: historyStats.total_items,
    items_24h: historyStats.items_24h,
    active_actors_7d: publicLatest.activity.active_actors_7d,
    clusters_total: publicLatest.clusters.total,
    clusters_elevated: publicLatest.clusters.elevated,
    clusters_strong: publicLatest.clusters.strong,
  };
  const snapshots = [
    snapshot,
    ...(Array.isArray(previousPublicHistory.snapshots)
      ? previousPublicHistory.snapshots
      : []),
  ]
    .filter(
      (item, index, values) =>
        values.findIndex(
          (candidate) => candidate.generated_at === item.generated_at,
        ) === index,
    )
    .slice(0, PUBLIC_HISTORY_SNAPSHOTS);

  await fs.mkdir(path.dirname(HISTORY_PATH), { recursive: true });
  await fs.mkdir(path.dirname(CLUSTERS_PATH), { recursive: true });
  await fs.mkdir(path.dirname(ACTIVITY_PATH), { recursive: true });
  await fs.mkdir(path.dirname(PUBLIC_LATEST_PATH), { recursive: true });

  await fs.writeFile(HISTORY_PATH, pruned.raw, "utf8");
  await fs.writeFile(
    CLUSTERS_PATH,
    JSON.stringify(internalClusters, null, 2),
    "utf8",
  );
  await fs.writeFile(
    ACTIVITY_PATH,
    JSON.stringify(actorActivity, null, 2),
    "utf8",
  );
  await fs.writeFile(
    PUBLIC_LATEST_PATH,
    JSON.stringify(publicLatest, null, 2),
    "utf8",
  );
  await fs.writeFile(
    PUBLIC_HISTORY_PATH,
    JSON.stringify(
      {
        schema_version: "1.0.0",
        generated_at: generatedAt,
        snapshots,
      },
      null,
      2,
    ),
    "utf8",
  );

  console.log(
    `[influence-stage3] history=${history.length} bytes=${historyStats.actual_bytes} cluster_items=${clusterItems.length} clusters=${clusters.length} elevated=${publicLatest.clusters.elevated}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
