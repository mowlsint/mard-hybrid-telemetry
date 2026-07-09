# MARD-HAT // Hybrid Activity Telemetry by MOwlSINT

**MARD-HAT** is a public, lightweight OSINT telemetry layer for cyber/exploit, IOC, botnet/C2 and FIMI-lite pressure. It is designed as contextual side input for maritime and hybrid-activity assessment, especially for downstream use in **Magic Paws / MARD-Eu**.

MARD-HAT does **not** attribute activity to a state actor. It does **not** prove sabotage, disinformation, or hybrid activity by itself. A high score should be treated as a prompt for further analysis, not as a conclusion.

## Positioning

MARD-HAT does not compete with professional influence-operation platforms, government counter-FIMI units, large commercial narrative-intelligence systems, or full cyber threat-intelligence platforms. Their data breadth, platform access, analyst teams and commercial tooling are much larger.

The specific value of MARD-HAT is different:

- small and transparent,
- public and community-readable,
- cost-neutral or low-cost by design,
- maritime-focus capable,
- machine-readable,
- compatible with Magic Paws / MARD-Eu,
- able to combine cyber/IOC pressure, botnet/C2 indicators and FIMI-lite signals as contextual telemetry.

Most existing systems focus primarily on either:

```text
Disinformation / narratives / influence networks
```

or:

```text
Cyber threat intelligence / botnet / IOC telemetry
```

MARD-HAT is intended to connect both layers in a cautious way:

```text
Cyber / botnet pressure
+ Narrative / disinformation signals
+ Maritime and critical-infrastructure context
+ Conservative hybrid-activity side indicator
```

## Current scope

The current MARD-HAT build uses open and low-cost sources to estimate public cyber, botnet-related and FIMI-lite pressure.

Enabled or prepared in the current line:

- **CISA Known Exploited Vulnerabilities (KEV)** for recently added, publicly known exploited vulnerabilities.
- **FIRST EPSS** for exploitation-probability enrichment and global exploit-pressure context.
- **ThreatFox / abuse.ch** for IOC and botnet/C2-like telemetry when `ABUSECH_AUTH_KEY` is configured as a GitHub Actions secret.
- **GDELT DOC API** as a fast narrative/media-volume sensor.
- **EUvsDisinfo exposure via GDELT domain-restricted queries** as a curated pro-Kremlin disinformation case signal.
- **DISARM-aligned local taxonomy mapping** for transparent FIMI-lite tag structuring.
- Static public JSON outputs for downstream ingestion.
- Static HTML dashboard under `public/index.html`.

The current bot-state model adds lightweight operational labels:

- **BIL — Bots in Lurking Position**: no clear elevated bot/IOC state.
- **BWB — Bots were busy**: elevated activity is visible or suspected in the recent trailing window.
- **BAB — Bots are busy**: elevated activity appears current.

The **Disinformation Alert Level** now combines FIMI-lite signals with bot/IOC proxy telemetry. It is still not attribution-grade and does not prove disinformation or hybrid activity by itself.

## Roadmap

### v0.1.x — Cyber / IOC / botnet telemetry

The current line focuses on:

- exploit-pressure telemetry,
- IOC pressure,
- botnet/C2-like indicators,
- short-window bot-state labels,
- conservative confidence and claim limits,
- historical approximation where possible.


### v0.1.4a — Display clarity for zero-result FIMI-lite runs

This patch does not change the basic data model. It makes the public dashboard clearer when FIMI-lite crawls return no matching source signals. Zero-result GDELT/EUvsDisinfo/DISARM values are now labelled as "no matching signals" rather than looking like broken counters. The Disinformation Alert Level note now distinguishes source-corroborated FIMI-lite elevation from bot/IOC proxy-only elevation. ThreatFox historical export counters also show "historical export unavailable / warming up" when the export has not been processed.

### v0.1.4 — FIMI-lite

The active FIMI-lite layer uses:

```text
GDELT = fast narrative and media-spike sensor
EUvsDisinfo = curated and validated disinformation case source
DISARM = structured FIMI taxonomy and tagging model
```

This makes the Disinformation Alert Level more meaningful, but it remains a contextual early-warning indicator. GDELT measures narrative/media volume; EUvsDisinfo provides curated case exposure; DISARM-aligned tags structure observations. None of these alone prove coordination or attribution.

### Later phases

Later candidates include additional social-media or web intelligence sources, such as Open Measures or comparable platforms, depending on access, cost, legality, licensing and operational usefulness.

## Outputs

Primary downstream file:

```text
public/hat_latest.json
```

Additional public outputs:

```text
public/hat_history.json
public/hat_source_health.json
public/evidence_cards/*.json
```

Internal / repository history:

```text
data/history/hat_history.jsonl
data/raw/*.json
```

## Suggested downstream use

Recommended initial use in Magic Paws / MARD-Eu:

```text
Magic Paws Dashboard: show as Cyber / IOC / Botnet Pressure side indicator
Morning Summary: one cautious context paragraph
Hybrid Index: no automatic weighting until a sufficient baseline exists
```

After a baseline period, MARD-HAT may be mixed into a broader Hybrid Index only with low weighting and only when corroborated by maritime, FIMI, RF, AIS, ADS-B, KRITIS or incident evidence.

## Claim limit

Use this language in downstream products:

> MARD-HAT is a contextual digital-pressure indicator. It is not attribution-grade and is not sufficient to prove sabotage, state activity, disinformation or a hybrid operation on its own.

## Operational notes

Secrets should never be committed to the repository. For ThreatFox, store the abuse.ch key as a GitHub Actions repository secret:

```text
ABUSECH_AUTH_KEY
```

If Cloudflare Pages automatic deployment is unreliable, use a Cloudflare Pages Deploy Hook stored as:

```text
CLOUDFLARE_DEPLOY_HOOK
```

The static site should be served from:

```text
public/
```

For Cloudflare Pages, the recommended static mirror setup is:

```text
Build command:     empty
Build output dir:  public
Root directory:    empty
Production branch: main
```

