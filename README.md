# MARD-HAT // Hybrid Activity Telemetry

**MARD-HAT** is an experimental, public, cost-neutral telemetry layer for cyber/exploit pressure. It is designed to provide contextual input for maritime and hybrid-activity assessments, for example in Magic Paws / MARD-Eu.

It does **not** attribute activity to a state actor. It does **not** prove sabotage or hybrid activity by itself.

## v0.1 Scope

Enabled by default:

- CISA Known Exploited Vulnerabilities (KEV), via the official GitHub mirror
- FIRST EPSS API, for exploitation-probability pressure
- Static HTML dashboard in `public/index.html`
- Public JSON outputs for downstream ingestion

Disabled by default:

- ThreatFox / URLhaus optional feeds, because they require a free abuse.ch Auth-Key. They remain suitable for a later zero-cost-but-secret-backed mode.
- Automated FIMI/threat-report document ingestion. This is intentionally omitted in the probe phase.

## Outputs

Magic Paws should only need:

```text
public/hat_latest.json
```

Additional files:

```text
public/hat_history.json
public/hat_source_health.json
data/history/hat_history.jsonl
data/evidence_cards/*.json
```

## Local run

```bash
npm run build
npm run check
```

Node 20+ is required. There are no npm dependencies.

## GitHub Actions

The workflow `.github/workflows/build_hat.yml` runs every six hours and commits updated JSON outputs back into the repository.

For public repositories, GitHub-hosted Actions minutes are generally free, but repository owners should still monitor usage and workflow permissions.

## Cloudflare Pages

Recommended settings:

```text
Build command:     npm run build
Build output dir:  public
Node version:      20
```

If the GitHub Action already commits `public/*.json`, Cloudflare Pages can also deploy the static folder without a separate heavy build.

## Claim limit

Use this language in downstream products:

> The external cyber telemetry shows elevated open-source exploit pressure. This is a contextual indicator only. It is not attribution-grade and cannot prove hybrid activity by itself.

## Suggested downstream use

Start as side indicator only:

```text
Magic Paws Dashboard: Cyber / Exploit Pressure card
Morning Summary: one cautious context paragraph
Hybrid Index: no weighting until at least 30–60 days baseline
```

After a baseline period, use only a low weight unless corroborated by maritime, FIMI, RF, AIS, ADS-B, KRITIS or incident evidence.
