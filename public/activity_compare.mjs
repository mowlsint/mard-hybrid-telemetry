// Shared by the dashboard and the offline event-comparison command.
const DAY = 86400000;
export function compareActivity(series, eventDate, windowDays = 7, country = 'all', minSources = 5) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(eventDate)) throw new Error('Choose an event date in YYYY-MM-DD format.');
  const event = Date.parse(`${eventDate}T00:00:00Z`);
  if (!Number.isFinite(event) || new Date(event).toISOString().slice(0, 10) !== eventDate) throw new Error('Invalid event date.');
  const length = Number(windowDays);
  if (!Number.isInteger(length) || length < 1 || length > 30) throw new Error('Comparison windows must contain 1–30 days.');
  const dates = (start, count) => Array.from({ length: count }, (_, i) => new Date(start + i * DAY).toISOString().slice(0, 10));
  const beforeDates = dates(event - length * DAY, length);
  const afterDates = dates(event, length);
  const rows = new Map((series.days || []).map(row => [row.date, row]));
  const requested = [...beforeDates, ...afterDates];
  const missingDays = requested.filter(date => !rows.get(date)?.complete);
  const base = { event_date: eventDate, window_days: length, country,
    before: { start: beforeDates[0], end: beforeDates.at(-1) }, after: { start: afterDates[0], end: afterDates.at(-1) },
    causal_finding: false, automation_finding: false, disinformation_finding: false,
    note: 'Observed published posts in a stable set of collected sources. Differences do not establish automation, falsehood, attribution or causation. All dates use UTC.' };
  if (missingDays.length) return { ...base, status: 'insufficient_data', missing_or_incomplete_days: missingDays, change_percent: null, stable_sources: 0 };
  const eligible = row => (row.endpoints || []).filter(endpoint => (country === 'all' || endpoint.country === country)
    && endpoint.coverage_ratio >= 0.75 && endpoint.successful_runs >= 3 && !endpoint.items_truncated);
  let cohort = new Set(eligible(rows.get(requested[0])).map(endpoint => endpoint.key));
  for (const date of requested.slice(1)) {
    const keys = new Set(eligible(rows.get(date)).map(endpoint => endpoint.key));
    cohort = new Set([...cohort].filter(key => keys.has(key)));
  }
  if (cohort.size < minSources) return { ...base, status: 'insufficient_coverage', stable_sources: cohort.size, minimum_sources: minSources, change_percent: null };
  const versions = new Set(requested.flatMap(date => rows.get(date).registry_hashes || []));
  const stats = days => {
    const endpoints = days.flatMap(date => rows.get(date).endpoints.filter(endpoint => cohort.has(endpoint.key)));
    const posts = endpoints.reduce((sum, endpoint) => sum + endpoint.observed_posts, 0);
    return { observed_posts: posts, posts_per_source_per_day: Number((posts / cohort.size / length).toFixed(3)),
      shared_fingerprint_posts: endpoints.reduce((sum, endpoint) => sum + endpoint.shared_fingerprint_posts, 0),
      source_days: cohort.size * length };
  };
  const before = stats(beforeDates), after = stats(afterDates);
  return { ...base, status: 'comparable_observations', stable_sources: cohort.size,
    registry_changed: versions.size > 1, registry_version_count: versions.size,
    before: { ...base.before, ...before }, after: { ...base.after, ...after },
    change_percent: before.observed_posts ? Number(((after.observed_posts / before.observed_posts - 1) * 100).toFixed(1)) : null,
    note: base.note + ' Collection is best-effort; feed truncation and posts deleted between runs can still cause undercounting.' };
}
