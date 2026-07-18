import fs from "node:fs/promises";
import path from "node:path";

export const DEFAULT_REGISTRY_PATH =
  process.env.MARD_INFLUENCE_REGISTRY ||
  "config/influence/mard_influence_registry_v1.json";

export async function loadInfluenceRegistry(registryPath = DEFAULT_REGISTRY_PATH) {
  const resolved = path.resolve(registryPath);
  let raw;

  try {
    raw = await fs.readFile(resolved, "utf8");
  } catch (error) {
    throw new Error(`Unable to read influence registry at ${resolved}: ${error.message}`);
  }

  let registry;
  try {
    registry = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid JSON in influence registry ${resolved}: ${error.message}`);
  }

  return {
    registry,
    registryPath: resolved,
  };
}

export function createRegistryIndexes(registry) {
  const entities = Array.isArray(registry?.entities) ? registry.entities : [];
  const endpoints = Array.isArray(registry?.endpoints) ? registry.endpoints : [];
  const verificationQueue = Array.isArray(registry?.verification_queue)
    ? registry.verification_queue
    : [];

  return {
    entities,
    endpoints,
    verificationQueue,
    entityById: new Map(entities.map((entity) => [entity.actor_id, entity])),
    endpointById: new Map(endpoints.map((endpoint) => [endpoint.endpoint_id, endpoint])),
  };
}
