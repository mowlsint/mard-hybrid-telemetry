# MARD-HAT // Hybrid Activity Telemetry by MOwlSINT

**MARD-HAT** is a public, lightweight OSINT telemetry layer for cyber/exploit, IOC, botnet/C2 and **maritime FIMI-lite** pressure. It is designed as contextual side input for maritime and hybrid-activity assessment, especially for downstream use in **Magic Paws / MARD-Eu**.

MARD-HAT does **not** attribute activity to a state actor. It does **not** prove sabotage, disinformation, coordination, or hybrid activity by itself. A high score should be treated as a prompt for further analysis, not as a conclusion.

## v0.1.5 evaluation and transparency patch

v0.1.5 changes the project from a raw pressure dashboard into a more transparent maritime risk telemetry view:

- the public score is explicitly shown as a **0–100% contextual pressure score**;
- the score uses visible bands: green, yellow, orange, deep orange and red;
- source health now supports **ok / partial / error** instead of hiding partial failures behind `ok`;
- GDELT FIMI-lite hits are post-filtered for maritime relevance;
- FIMI-lite is split into **Core MARD-Eu** and **Global Maritime Spillover** context;
- the dashboard explains when botnet/C2 and narrative signals may create **information fog / obscuration context**;
- machine-readable analyst downloads are published under `public/downloads/`.

## Score interpretation

The HAT score is a percentage-style contextual pressure score, not a probability.

| Range | Band | Meaning |
|---:|---|---|
| 0–20 | green / normal | low contextual pressure |
| 21–40 | yellow / elevated | elevated background pressure |
| 41–60 | orange / watch | watch-level pressure |
| 61–80 | deep orange / high | high contextual pressure |
| 81–100 | red / critical | critical contextual pressure |

The score is currently composed from:

```text
recent CISA KEV additions, 7 days
recent CISA KEV additions, 30 days
mean EPSS of recent KEV
ThreatFox IOC pressure
ThreatFox botnet/C2 pressure over 36h
```

Context-only values such as global EPSS hot set and source coverage are displayed but not used as pressure score drivers unless explicitly weighted.

When the ThreatFox long historical export is unavailable, ThreatFox score parts are capped and marked as fallback-limited. The raw current bot-state percentiles remain visible for transparency.

## Maritime FIMI-lite filter

GDELT is a narrative/media-volume sensor, not a disinformation classifier. v0.1.5 therefore applies a local post-filter:

```text
An article counts only if it contains:
1. at least one maritime anchor
2. at least one threat/FIMI anchor
3. for Core MARD-Eu, at least one North/Baltic/Northern-Europe regional anchor
```

Examples of anchors:

```text
Maritime anchors:
ship, vessel, tanker, port, offshore, cable, pipeline, shadow fleet, AIS, GNSS, GPS, jamming

Threat/FIMI anchors:
sabotage, attack, sanctions, blockade, drones, jamming, false flag, disinformation, Russia, NATO

Core MARD-Eu regional anchors:
Baltic Sea, North Sea, Denmark, Germany, Poland, Norway, Sweden, Finland, Baltic states, Kaliningrad, Northern flank
```

Global maritime spillover such as Hormuz, Iran, Red Sea, Suez or global oil blockade narratives is retained separately and down-weighted. It can matter for maritime risk context but should not dominate the North/Baltic MARD-Eu picture.

## Obscuration / information-fog context

MARD-HAT does **not** claim that botnets or maritime disinformation are intentionally hiding maritime events. It can only mark conditions **compatible with information fog or obscuration**.

Technically, this matters because:

- botnet/C2 infrastructure can support access, spam, amplification, credential theft, staging or disruption;
- broad narrative volume can bury or blur maritime/security signals;
- repeated frames around sabotage, sanctions, NATO, Russia, cables, pipelines or shipping can create a noisy context around real incidents;
- partial source access, rate limits or fetch failures create analytical blind spots.

The dashboard therefore phrases this as **obscuration context**, not as attribution or proof.

## Outputs

Primary public outputs:

```text
public/hat_latest.json
public/hat_history.json
public/hat_source_health.json
public/evidence_cards/*.json
```

Analyst downloads for re-use:

```text
public/downloads/hat_analyst_bundle_latest.json
public/downloads/fimi_maritime_articles_latest.csv
public/downloads/fimi_maritime_articles_latest.json
public/downloads/source_health_latest.csv
public/downloads/README_downloads.txt
```

The download bundle is intended for charts, customer extracts, external review, notebooks and local recalibration. It must still be read with the claim limits above.

## Source health semantics

```text
ok       = enough successful data for this source in this run
partial  = at least one query succeeded and at least one failed or was rate-limited
error    = not usable in this run
disabled = intentionally off
```

Partial sources only contribute partial source-health coverage. This avoids showing a false 100% source-health value when some GDELT/EUvsDisinfo calls failed.

## Positioning

MARD-HAT does not compete with professional influence-operation platforms, government counter-FIMI units, large commercial narrative-intelligence systems, or full cyber threat-intelligence platforms. Their data breadth, platform access, analyst teams and commercial tooling are much larger.

The specific value of MARD-HAT is different:

- small and transparent,
- public and community-readable,
- cost-neutral or low-cost by design,
- maritime-focus capable,
- machine-readable,
- compatible with Magic Paws / MARD-Eu,
- able to combine cyber/IOC pressure, botnet/C2 indicators and maritime FIMI-lite signals as contextual telemetry.

## Run

```bash
npm run build
npm run check
```

Required runtime:

```text
Node.js >= 22
```

Optional secret:

```text
ABUSECH_AUTH_KEY
```

Never commit or publish secrets. MARD-HAT outputs do not include Auth-Key material.

## Claim limit

MARD-HAT is a contextual digital-pressure and FIMI-lite indicator only. It is not attribution-grade and is not sufficient to prove hybrid activity, sabotage, disinformation, coordination or state involvement on its own.
