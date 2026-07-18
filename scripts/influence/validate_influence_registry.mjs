#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import {
  createRegistryIndexes,
  loadInfluenceRegistry,
} from "./load_influence_registry.mjs";

const ALLOWED_VERIFICATION_STATUSES = new Set([
  "official_primary",
  "official_or_primary_crosslink",
  "official_platform",
  "official_platform_or_crosslink",
  "official_platform_or_research_attributed",
  "research_dataset_or_primary_crosslink",
  "research_attributed",
  "pending",
]);

const ALLOWED_PRIORITIES = new Set(["critical", "high", "normal", "low"]);
const SOCIAL_PLATFORMS = new Set([
  "x",
  "instagram",
  "tiktok",
  "youtube",
  "telegram",
  "facebook",
  "bluesky",
]);
const NON_URL_ENDPOINT_TYPES = new Set(["discovery_rule"]);

function pushIssue(collection, code, message, context = {}) {
  collection.push({ code, message, context });
}

function duplicateValues(values) {
  const seen = new Set();
  const duplicates = new Set();
  for (const value of values) {
    if (!value) continue;
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  return [...duplicates];
}

function isHttpUrl(value) {
  if (typeof value !== "string" || !value.trim()) return false;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function stableEndpointKey(endpoint) {
  return [
    endpoint.actor_id || "",
    endpoint.platform || "",
    String(endpoint.handle_or_domain || "").trim().toLowerCase(),
  ].join("::");
}

export function validateInfluenceRegistry(registry) {
  const errors = [];
  const warnings = [];
  const {
    entities,
    endpoints,
    verificationQueue,
    entityById,
  } = createRegistryIndexes(registry);

  if (!registry || typeof registry !== "object") {
    pushIssue(errors, "REGISTRY_NOT_OBJECT", "Registry root must be an object.");
    return { errors, warnings, summary: {} };
  }

  if (!registry.schema_version) {
    pushIssue(errors, "MISSING_SCHEMA_VERSION", "schema_version is required.");
  }
  if (!registry.registry_name) {
    pushIssue(errors, "MISSING_REGISTRY_NAME", "registry_name is required.");
  }
  if (!Array.isArray(registry.entities)) {
    pushIssue(errors, "ENTITIES_NOT_ARRAY", "entities must be an array.");
  }
  if (!Array.isArray(registry.endpoints)) {
    pushIssue(errors, "ENDPOINTS_NOT_ARRAY", "endpoints must be an array.");
  }

  for (const duplicate of duplicateValues(entities.map((entity) => entity.actor_id))) {
    pushIssue(errors, "DUPLICATE_ACTOR_ID", `Duplicate actor_id: ${duplicate}`, {
      actor_id: duplicate,
    });
  }

  for (const duplicate of duplicateValues(endpoints.map((endpoint) => endpoint.endpoint_id))) {
    pushIssue(errors, "DUPLICATE_ENDPOINT_ID", `Duplicate endpoint_id: ${duplicate}`, {
      endpoint_id: duplicate,
    });
  }

  for (const duplicate of duplicateValues(endpoints.map(stableEndpointKey))) {
    pushIssue(
      errors,
      "DUPLICATE_ACTOR_PLATFORM_HANDLE",
      `Duplicate actor/platform/handle combination: ${duplicate}`,
      { key: duplicate },
    );
  }

  for (const [index, entity] of entities.entries()) {
    const context = { index, actor_id: entity?.actor_id };

    if (!entity?.actor_id) {
      pushIssue(errors, "MISSING_ACTOR_ID", "Entity is missing actor_id.", context);
    }
    if (!entity?.display_name) {
      pushIssue(errors, "MISSING_DISPLAY_NAME", "Entity is missing display_name.", context);
    }
    if (!entity?.actor_class) {
      pushIssue(errors, "MISSING_ACTOR_CLASS", "Entity is missing actor_class.", context);
    }
    if (!ALLOWED_PRIORITIES.has(entity?.priority)) {
      pushIssue(
        errors,
        "INVALID_ENTITY_PRIORITY",
        `Entity priority must be one of ${[...ALLOWED_PRIORITIES].join(", ")}.`,
        { ...context, priority: entity?.priority },
      );
    }

    if (
      ["state_media", "official_state_source", "military_state_media"].includes(
        entity?.actor_class,
      ) &&
      !entity?.state_affiliation
    ) {
      pushIssue(
        warnings,
        "MISSING_STATE_AFFILIATION",
        "State-linked source has no state_affiliation.",
        context,
      );
    }
  }

  for (const [index, endpoint] of endpoints.entries()) {
    const context = {
      index,
      endpoint_id: endpoint?.endpoint_id,
      actor_id: endpoint?.actor_id,
    };

    if (!endpoint?.endpoint_id) {
      pushIssue(errors, "MISSING_ENDPOINT_ID", "Endpoint is missing endpoint_id.", context);
    }
    if (!endpoint?.actor_id || !entityById.has(endpoint.actor_id)) {
      pushIssue(
        errors,
        "UNKNOWN_ENDPOINT_ACTOR",
        "Endpoint references an unknown actor_id.",
        context,
      );
    }
    if (!endpoint?.platform) {
      pushIssue(errors, "MISSING_PLATFORM", "Endpoint is missing platform.", context);
    }
    if (!endpoint?.handle_or_domain) {
      pushIssue(
        errors,
        "MISSING_HANDLE_OR_DOMAIN",
        "Endpoint is missing handle_or_domain.",
        context,
      );
    }
    if (!ALLOWED_VERIFICATION_STATUSES.has(endpoint?.verification_status)) {
      pushIssue(
        errors,
        "INVALID_VERIFICATION_STATUS",
        `Unknown verification_status: ${endpoint?.verification_status}`,
        context,
      );
    }
    if (!ALLOWED_PRIORITIES.has(endpoint?.priority)) {
      pushIssue(
        errors,
        "INVALID_ENDPOINT_PRIORITY",
        `Endpoint priority must be one of ${[...ALLOWED_PRIORITIES].join(", ")}.`,
        context,
      );
    }

    const endpointType = endpoint?.endpoint_type || "account";
    if (
      !NON_URL_ENDPOINT_TYPES.has(endpointType) &&
      !isHttpUrl(endpoint?.profile_url)
    ) {
      pushIssue(
        errors,
        "INVALID_PROFILE_URL",
        "Enabled website/account endpoints require an HTTP(S) profile_url.",
        context,
      );
    }

    if (
      endpoint?.ingest_enabled === true &&
      endpoint?.verification_status === "pending"
    ) {
      pushIssue(
        errors,
        "PENDING_ENDPOINT_ENABLED",
        "A pending endpoint must not be ingest_enabled.",
        context,
      );
    }

    if (
      endpoint?.ingest_enabled === true &&
      SOCIAL_PLATFORMS.has(endpoint?.platform) &&
      ![
        "official_primary",
        "official_or_primary_crosslink",
        "official_platform",
        "official_platform_or_crosslink",
        "official_platform_or_research_attributed",
        "research_dataset_or_primary_crosslink",
        "research_attributed",
      ].includes(endpoint?.verification_status)
    ) {
      pushIssue(
        errors,
        "UNVERIFIED_SOCIAL_ENDPOINT_ENABLED",
        "Enabled social endpoint lacks an accepted verification status.",
        context,
      );
    }

    if (
      ["ru_rt_global", "ru_rt_de", "ru_sputnik", "ru_sputnik_de"].includes(
        endpoint?.actor_id,
      ) &&
      !["metadata_analysis_only", "inherit"].includes(
        endpoint?.public_export_policy,
      )
    ) {
      pushIssue(
        warnings,
        "SANCTIONED_SOURCE_EXPORT_POLICY",
        "Sanctioned-source endpoint should use metadata_analysis_only or inherit a restrictive actor policy.",
        context,
      );
    }
  }

  for (const [index, item] of verificationQueue.entries()) {
    if (!item?.actor_id || !entityById.has(item.actor_id)) {
      pushIssue(
        errors,
        "UNKNOWN_QUEUE_ACTOR",
        "Verification queue item references an unknown actor_id.",
        { index, actor_id: item?.actor_id },
      );
    }
  }

  const computedStatistics = {
    entities: entities.length,
    endpoints: endpoints.length,
    enabled_endpoints: endpoints.filter((item) => item.ingest_enabled === true).length,
    enabled_social_endpoints: endpoints.filter(
      (item) =>
        item.ingest_enabled === true && SOCIAL_PLATFORMS.has(item.platform),
    ).length,
    verification_queue_items: verificationQueue.length,
  };

  const declaredStatistics = registry?.statistics || {};
  for (const [key, value] of Object.entries(computedStatistics)) {
    if (
      Number.isFinite(declaredStatistics?.[key]) &&
      declaredStatistics[key] !== value
    ) {
      pushIssue(
        warnings,
        "STALE_DECLARED_STATISTIC",
        `Declared statistic ${key}=${declaredStatistics[key]} differs from computed value ${value}.`,
        { key, declared: declaredStatistics[key], computed: value },
      );
    }
  }

  return {
    errors,
    warnings,
    summary: {
      ...computedStatistics,
      schema_version: registry.schema_version || null,
      registry_name: registry.registry_name || null,
      valid: errors.length === 0,
    },
  };
}

async function main() {
  const { registry, registryPath } = await loadInfluenceRegistry();
  const report = validateInfluenceRegistry(registry);
  const outputPath = path.resolve(
    process.env.MARD_INFLUENCE_VALIDATION_REPORT ||
      "data/influence/validation_report.json",
  );

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(
    outputPath,
    JSON.stringify(
      {
        generated_at: new Date().toISOString(),
        registry_path: registryPath,
        ...report,
      },
      null,
      2,
    ),
    "utf8",
  );

  console.log(
    `[influence-registry] entities=${report.summary.entities} endpoints=${report.summary.endpoints} errors=${report.errors.length} warnings=${report.warnings.length}`,
  );
  console.log(`[influence-registry] report=${outputPath}`);

  if (report.errors.length) {
    for (const issue of report.errors) {
      console.error(`ERROR ${issue.code}: ${issue.message}`);
    }
    process.exitCode = 1;
  }

  for (const issue of report.warnings) {
    console.warn(`WARN ${issue.code}: ${issue.message}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
