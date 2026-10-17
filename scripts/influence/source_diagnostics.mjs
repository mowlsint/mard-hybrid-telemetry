// Keep request failures in the Actions log as well as the detailed health JSON.
// JSON encoding keeps a source error on one line without interpreting its text.
export function logSourceFailures(stage, sources) {
  for (const source of sources) {
    if (source.status !== "error" && !source.error) continue;
    console.warn(`[${stage}] source_failure ${JSON.stringify({
      endpoint_id: source.endpoint_id,
      platform: source.platform,
      checked_at: source.checked_at,
      status: source.status,
      error: source.error || "Source collection failed",
    })}`);
  }
}
