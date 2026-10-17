# MARD-HAT // Hybrid Activity Telemetry by MOwlSINT

MARD-HAT combines contextual cyber/exploit and malware-infrastructure indicators, maritime narrative pressure, and a separate Influence Watch. None of these measurements alone establishes automation, falsehood, coordination, attribution, sabotage or causation.

## v0.2.0: data quality and comparable observations

- Failed source access is **unavailable**, not zero activity. Nullable scores and per-metric validity are exported to the history and downloads.
- GDELT queries are serialized, retried within a bounded budget, and respect `Retry-After`. An invalid JSON/schema response is an error.
- A previous complete narrative observation remains available with its original timestamp; it is never scored as current data.
- ThreatFox percentiles compare matching rolling time windows. An unavailable export never supplies an artificial all-zero baseline. Local fallbacks require at least 14 distinct valid days under the current scoring version.
- Cyber/C2 pressure cannot raise the maritime narrative alert. Topic keyword matches are descriptive groups; they are not DISARM technique findings or determinations of disinformation.
- The Influence Watch runs every six hours and records actual collection coverage. X/Nitter remains best-effort; unavailable sources do not become zero publishing activity.
- Event comparisons use a stable cohort of sufficiently collected sources on both sides. The dashboard and CLI share the same comparison code.
- Analyst downloads are committed and deployed with the corresponding outputs. All accepted sampled articles are exported rather than only the 20 display examples.

## Interpretation

The HAT score is a 0–100 contextual cyber-pressure index, not a probability. It uses recent CISA KEV additions, EPSS enrichment and ThreatFox IOC/C2 reporting. Missing required score inputs produce a null score. Source access and baseline limitations affect confidence.

| Score | Band |
|---:|---|
| 0–20 | normal |
| 21–40 | elevated |
| 41–60 | watch |
| 61–80 | high |
| 81–100 | critical |
| null | not assessable |

ThreatFox counts are reports of malware infrastructure indicators, not numbers of social accounts, running bots, active connections or propaganda posts. An IOC's first-seen time is not its shutdown time. A quiet reporting period is not evidence that infrastructure disappeared.

GDELT measures retrieved media/topic exposure. Headline and URL-path hints are post-filtered for maritime, threat and regional relevance, with English, German and Russian terms. ArticleList sampling limits are reported. Search results and topic tags do not establish falsehood. EUvsDisinfo domain-restricted search candidates are not automatically verified individual cases.

The existing `metrics.fimi_lite` and `disinformation_alert_level` names remain compatibility aliases. In v0.2.0 their meaning is **maritime narrative pressure**, and their score/level may be null. New consumers should use `narrative_alert_level` and inspect `data_quality`.

## Data quality and history

Source states distinguish `ok`, `partial`, `error`, `unavailable` and `disabled`. Derived topic mapping is not counted as an independent evidence source.

Each new HAT history entry includes `scoring_version`, `configuration_hash`, `data_quality`, `source_health` and `metric_validity`. Valid observed zero counts remain zero. Missing measurements remain null. Old records keep their original numeric values and receive `legacy_unverified` flags; old zero values and percentiles are excluded from new baselines. The public HAT history retains up to 720 points; the archive is preserved in `data/history/hat_history.jsonl`.

Influence item history retains up to 90 days, subject to configured item/byte limits. Collection-coverage history begins when coverage is actually recorded. Earlier coverage is never invented from retained posts or today's source health. Changed registries, sample caps, pruned history, failed sources and incomplete days remain visible.

## Event comparison

The comparison counts **published posts**, using publication timestamps in UTC. Website snapshots and undated observations are excluded. Repeat collection is deduplicated; identical content in different sources remains distinct observed publication.

For each date on both sides, a source needs at least three successful, distinct six-hour collection slots. The comparison requires at least five sources meeting that condition throughout both periods, and uses only that intersection. Missing days, unfinished windows, insufficient coverage or known truncation return an unassessable result. A zero baseline does not yield an infinite percentage change.

Country filters describe the registry's source-country classification. They do not attribute operations to a government. Results describe observed publication and shared fingerprints; they do not prove bots, disinformation or an effect caused by the reference event. Undetected feed truncation and deleted posts can still produce undercounting.

```bash
npm run compare:event -- 2026-10-08 7 RU
```

The date above is an example reference date, not an independently established event timestamp. Choose the date and window in the dashboard, or use the command above. The same-source comparison needs newly accumulated coverage; earlier gaps may prevent a historical assessment.

## Outputs

```text
public/hat_latest.json
public/hat_history.json
public/hat_source_health.json
public/influence_watch_latest.json
public/influence_activity_daily.json
public/downloads/hat_analyst_bundle_latest.json
public/downloads/fimi_maritime_articles_latest.csv
public/downloads/fimi_maritime_articles_latest.json
public/downloads/source_health_latest.csv
public/downloads/influence_activity_daily.json
public/downloads/influence_activity_daily.csv
```

## Run and validate

```bash
npm test
npm run build
npm run check
node scripts/influence/build_influence_stage3.mjs
node scripts/influence/check_influence_stage3.mjs
```

Node.js >=22 is required; the existing Influence workflows use `.node-version`. `ABUSECH_AUTH_KEY` remains optional for deployment, but enabled ThreatFox measurements are unavailable without it. Never publish keys. Regression tests use synthetic fixtures and do not call external sources.

`Build HAT Index` runs every six hours. `Build Influence Watch Stage 3` collects the existing website/RSS/Telegram, Bluesky/YouTube and best-effort X sources every six hours, then builds histories and clusters. Source changes trigger fresh runs on main. Separate HAT and Influence writer groups, with bounded push/rebase retries, protect generated commits without cancelling each other’s pending runs. Cloudflare deployment hooks run after successful builds when configured.

Influence source access failures are recorded per endpoint and do not stop collection of other platforms. Unavailable platforms remain explicit coverage gaps; a run with no usable sources is published as not assessable. Registry, schema and file errors still fail the workflow. Each collection workflow logs endpoint errors and always attempts to save source-health and ingest-status JSON as an `influence-source-diagnostics` Actions artifact for 30 days, including after a later step fails. The JSON timestamps identify the original observations when a step failed before producing fresh health data. Successful publication also preserves detailed source health in Git history.
