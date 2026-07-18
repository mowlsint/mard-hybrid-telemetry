# MARD Influence & Narrative Watch — Stage 4

## Zweck

Stage 4 ergänzt den bestehenden Website-, RSS- und Telegram-Ingest um:

- öffentliche Bluesky-Author-Feeds,
- öffentliche YouTube-Kanalfeeds.

Dafür werden keine kostenpflichtigen API-Schlüssel benötigt.

## Laufzeit

Die Workflows verwenden weiterhin zentral Node.js 24 über:

```text
.node-version
```

## Neue Dateien

```text
scripts/influence/fetch_influence_stage4_social.mjs
scripts/influence/check_influence_stage4_social.mjs
.github/workflows/build_influence_stage4.yml
```

## Zu ersetzen

```text
.github/workflows/build_influence_stage3.yml
```

Der Stage-3-Workflow führt danach automatisch aus:

```text
Stage 2 Website/RSS/Telegram
→ Stage 4 Bluesky/YouTube
→ Stage 3 Historie und Cluster
```

## Erzeugte Dateien

```text
data/influence/ingest/social_source_health_latest.json
public/influence_social_ingest_status.json
public/influence_social_source_health.json
```

Die Social-Items werden zusätzlich in folgende bestehende Datei gemischt:

```text
data/influence/ingest/items_latest.json
```

## Datenschutz und Methodik

Dauerhaft gespeichert werden keine vollständigen Posttexte. Gespeichert werden:

- Content-Hash,
- SimHash,
- Veröffentlichungszeit,
- Plattform,
- verlinkte Domains,
- Inhaltslänge,
- bei nicht eingeschränkten Quellen der Titel eines YouTube-Videos.

Die Daten begründen weder Attribution noch Botaktivität.

## Erster isolierter Test

GitHub → Actions → `Build Influence Social Stage 4`

```text
max_stage2_endpoints: 120
max_social_endpoints: 40
concurrency: 4
social_concurrency: 3
```

## Vollständiger kombinierter Lauf

Danach GitHub → Actions → `Build Influence Watch Stage 3`

```text
max_endpoints: 300
max_social_endpoints: 180
concurrency: 8
social_concurrency: 6
retention_days: 35
cluster_window_hours: 72
```

## Erhöhte Grenzen

```text
Stage-2-Endpunkte: 300
Social-Endpunkte: 180
Stage-2-Parallelität: 8
Social-Parallelität: 6
Workflow-Timeout: 50 Minuten
Historie: maximal 35.000 Items
Historiengröße: maximal 26 MB
Interne Cluster: maximal 300
Öffentliche Cluster: maximal 25
Öffentliche Snapshots: maximal 240
```

## Noch nicht enthalten

- X,
- Instagram,
- TikTok,
- Facebook,
- dynamische Entdeckung neuer Social-Accounts,
- endgültige Top-15-Prozent-Berechnung,
- HAT-Score-Anbindung.
