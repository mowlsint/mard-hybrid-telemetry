# MARD Influence & Narrative Watch — Stage 3

## Laufzeitstandard

Alle drei Influence-Workflows nutzen nun:

```yaml
uses: actions/checkout@v7
uses: actions/setup-node@v7
node-version-file: ".node-version"
```

Die zentrale Datei `.node-version` enthält:

```text
24
```

Node.js 20 wird in diesen Workflows nicht mehr verwendet.

## Stage-3-Funktionen

Stage 3 führt ein:

- 35 Tage begrenzte Historie,
- Deduplizierung über `item_id`,
- absolutes Größenlimit von 20 MB,
- maximales Historienlimit von 25.000 Items,
- exakte Content-Hash-Erkennung,
- SimHash-Ähnlichkeit,
- gemeinsame referenzierte Domains,
- Zeitfenster von 15 Minuten, 90 Minuten und 6 Stunden,
- erste interne Verstärkungscluster,
- vorläufige Aktivitätsauswertung über 7 und 28 Tage,
- öffentlichen aggregierten Influence-Watch-Status.

## Schutz vor Überinterpretation

Ein Cluster ist kein Nachweis für:

- Botaktivität,
- ausländische Steuerung,
- Desinformation,
- technische Automatisierung,
- Attribution.

Der öffentliche Export enthält keine internen Actor-, Endpoint- oder Item-IDs.

## Erzeugte Dateien

```text
data/influence/history/items_history.jsonl
data/influence/analysis/clusters_latest.json
data/influence/analysis/actor_activity_latest.json

public/influence_watch_latest.json
public/influence_watch_history.json
```

## Installation

Neu hinzufügen:

```text
.node-version
scripts/influence/build_influence_stage3.mjs
scripts/influence/check_influence_stage3.mjs
.github/workflows/build_influence_stage3.yml
```

Ersetzen:

```text
.github/workflows/validate_influence_registry.yml
.github/workflows/build_influence_stage2.yml
```

## Erster Lauf

GitHub → Actions → `Build Influence Watch Stage 3`

Empfohlene erste Werte:

```text
max_endpoints: 120
concurrency: 4
retention_days: 35
cluster_window_hours: 72
```

Danach bei grünem Lauf:

```text
max_endpoints: 240
concurrency: 6
retention_days: 35
cluster_window_hours: 72
```

## Noch nicht enthalten

- X-Ingest,
- Instagram-Ingest,
- TikTok-Ingest,
- YouTube-Ingest,
- Bluesky-Ingest,
- endgültige Top-15-Prozent-Auswahl,
- HAT-Score-Anbindung.
