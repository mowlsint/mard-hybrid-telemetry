# MARD Influence & Narrative Watch — Stage 2

## Zweck

Stage 2 ist der erste aktive Quellenabruf. Er verarbeitet ausschließlich:

- aktivierte Website-Endpunkte,
- automatisch entdeckte RSS-/Atom-Feeds,
- öffentlich sichtbare Telegram-Kanäle.

Noch nicht verarbeitet werden:

- X,
- Instagram,
- TikTok,
- Facebook,
- Bluesky,
- YouTube,
- dynamische Verstärkeraccounts.

## Datenschutz und Veröffentlichung

Der Lauf speichert keine Volltexte dauerhaft.

Persistiert werden:

- Zeitpunkte,
- Quelle und Plattform,
- Content-Hash,
- 64-Bit-SimHash,
- Inhaltslänge,
- referenzierte Domains,
- bei nicht eingeschränkten Quellen ein kurzer Titel,
- Source Health.

Für RT, RT DE, Sputnik und eingeschränkt markierte Quellen werden Titel und
vollständige Ziel-URLs im persistenten Item-Bestand reduziert.

## Neue Dateien

```text
scripts/influence/fetch_influence_stage2.mjs
scripts/influence/check_influence_stage2.mjs
.github/workflows/build_influence_stage2.yml
```

## Erzeugte Dateien

```text
data/influence/ingest/items_latest.json
data/influence/ingest/source_health_latest.json
public/influence_ingest_status.json
public/influence_source_health.json
```

## Erster Testlauf

1. GitHub → Actions
2. `Build Influence Ingest Stage 2`
3. `Run workflow`
4. `max_endpoints`: zunächst 40
5. `concurrency`: 3
6. Lauf starten

Wenn der Test grün ist:

- erneut mit `max_endpoints`: 180
- `concurrency`: 5

## Erwartbare Fehler

Einzelne Websites blockieren automatisierte Abrufe, verwenden JavaScript,
liefern HTTP 403/429 oder reagieren zu langsam. Das ist kein Workflowfehler,
solange mindestens eine Quelle erfolgreich verarbeitet wird.

Die Detaildatei:

```text
data/influence/ingest/source_health_latest.json
```

zeigt je Endpunkt:

- ok,
- partial,
- error,
- HTTP-Status,
- Dauer,
- entdeckte Feeds,
- Fehlergrund.

## Noch keine Score-Anbindung

Stage 2 erzeugt ausdrücklich keinen Kampagnenscore und verändert weder
`hat_score` noch `disinformation_alert_level`.
