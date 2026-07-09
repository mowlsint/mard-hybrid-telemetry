# MARD-HAT v0.1.1 Patch

Replace these files in the repository root:

- `package.json`
- `config/scoring.json`
- `scripts/build_hat.mjs`
- `.github/workflows/build_hat.yml`
- `public/index.html`

Do not replace `public/hat_latest.json`, `public/hat_history.json`, or `public/hat_source_health.json` manually unless you intentionally want to reset generated telemetry outputs.

## Changes

- Page title changed to `Hybrid Activity Telemetry by MOwlSINT`.
- UI remains English-only.
- Score-part hover/focus tooltips added.
- Workflow age is shown next to the generated timestamp.
- Footer now shows `© YYYY MOwlSINT.de`.
- Suggested Magic Paws usage text removed from the Claim Limit card.
- Global EPSS hot count is strongly down-weighted in scoring.
- Source coverage remains visible but no longer increases the activity score.
- Evidence cards are now written to `public/evidence_cards/` and linked as `evidence_cards/...`, making them reachable through Cloudflare Pages.
