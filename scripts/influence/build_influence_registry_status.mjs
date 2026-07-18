#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import {
  createRegistryIndexes,
  loadInfluenceRegistry,
} from "./load_influence_registry.mjs";
import { validateInfluenceRegistry } from "./validate_influence_registry.mjs";

const SOCIAL_PLATFORMS = new Set([
  "x",
  "instagram",
  "tiktok",
  "youtube",
  "telegram",
  "facebook",
  "bluesky",
]);

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

function selectionPolicySummary(policy = {}) {
  const rules = policy?.political_actor_entry_rules || {};
  return {
    minimum_political_posts_per_week:
      rules.minimum_political_posts_per_week ?? 10,
    activity_window_days: rules.activity_window_days ?? 28,
    minimum_political_posts_in_window:
      rules.minimum_political_posts_in_window ?? 40,
    minimum_active_weeks_in_window:
      rules.minimum_active_weeks_in_window ?? 3,
    top_percent_within_comparable_cohort:
      rules.top_percent_within_comparable_cohort ?? 15,
    followers_any_platform_min:
      rules.followers_any_platform_min ?? 100000,
  };
}

async function main() {
  const { registry, registryPath } = await loadInfluenceRegistry();
  const validation = validateInfluenceRegistry(registry);

  if (validation.errors.length) {
    throw new Error(
      `Registry validation failed with ${validation.errors.length} error(s).`,
    );
  }

  const { entities, endpoints, verificationQueue, entityById } =
    createRegistryIndexes(registry);
  const enabledEndpoints = endpoints.filter((item) => item.ingest_enabled === true);
  const enabledSocialEndpoints = enabledEndpoints.filter((item) =>
    SOCIAL_PLATFORMS.has(item.platform),
  );

  const status = {
    schema_version: "1.0.0",
    generated_at: new Date().toISOString(),
    registry: {
      name: registry.registry_name,
      schema_version: registry.schema_version,
      source_path: path.relative(process.cwd(), registryPath),
      verification_cutoff: registry.verification_cutoff || null,
      github_integration_status:
        registry.github_integration_status || "registry_loaded",
    },
    assessment_limit: {
      statement:
        "Inclusion in this registry is not an allegation of disinformation, automation, extremism or foreign coordination.",
      attribution_grade: false,
      score_integration: false,
    },
    counts: {
      entities: entities.length,
      endpoints: endpoints.length,
      enabled_endpoints: enabledEndpoints.length,
      enabled_social_endpoints: enabledSocialEndpoints.length,
      verification_queue_items: verificationQueue.length,
    },
    coverage: {
      countries: countBy(entities, (item) => item.country),
      actor_classes: countBy(entities, (item) => item.actor_class),
      priorities: countBy(entities, (item) => item.priority),
      enabled_platforms: countBy(enabledEndpoints, (item) => item.platform),
      endpoint_verification_statuses: countBy(
        endpoints,
        (item) => item.verification_status,
      ),
    },
    selection_policy: selectionPolicySummary(registry.selection_policy),
    source_health: {
      registry_file: "ok",
      referential_integrity: "ok",
      validation_errors: 0,
      validation_warnings: validation.warnings.length,
      state: validation.warnings.length ? "partial" : "ok",
    },
  };

  const methodology = {
    schema_version: "1.0.0",
    generated_at: status.generated_at,
    title: "MARD Influence & Narrative Watch — Registry Methodology",
    purpose:
      "Public-source observation of political amplification, foreign state communication, state media, FIMI infrastructure and maritime narratives.",
    safeguards:
      registry?.selection_policy?.important_limitations || [
        "Political position alone is not evidence of disinformation.",
        "Narrative overlap is assessed separately from coordination.",
        "High posting frequency alone is not evidence of automation.",
      ],
    assessment_fields:
      registry?.taxonomy?.assessment_fields || [
        "narrative_similarity",
        "coordination_confidence",
        "automation_likelihood",
        "foreign_origin_confidence",
        "source_attribution_confidence",
      ],
    public_data_policy: {
      full_internal_registry_public: false,
      public_outputs:
        "Aggregated counts, methodology and later derived analytical clusters.",
      sanctioned_source_handling:
        "Metadata, hashes, counts, timing and original analysis only.",
    },
  };

  const publicDir = path.resolve(
    process.env.MARD_INFLUENCE_PUBLIC_DIR || "public",
  );
  await fs.mkdir(publicDir, { recursive: true });
  await fs.writeFile(
    path.join(publicDir, "influence_registry_status.json"),
    JSON.stringify(status, null, 2),
    "utf8",
  );
  await fs.writeFile(
    path.join(publicDir, "influence_registry_methodology.json"),
    JSON.stringify(methodology, null, 2),
    "utf8",
  );

  console.log(
    `[influence-registry] public status built: entities=${entities.length}, enabled_endpoints=${enabledEndpoints.length}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
