# Stage 5b — Nitter preflight and graceful degradation

## Befund

Der erste vollständige Lauf ergab:

```text
configured_instances: 10
eligible_endpoints: 63
successful_endpoints: 0
failed_endpoints: 63
collected_x_items: 0
merged_current_items: 824
```

Damit funktionieren die übrigen Influence-Quellen. Der öffentliche
Nitter-Pfad war aus dem GitHub-Runner nicht nutzbar.

## Änderung

Vor jedem X-Lauf werden die öffentlichen Nitter-Instanzen einmal mit bis zu
zwei Testhandles geprüft.

Nur Instanzen, die tatsächlich eine parsebare RSS- oder HTML-Timeline
zurückgeben, gelangen in den Accountlauf.

Wenn keine Instanz nutzbar ist:

- werden nicht mehr 63 Accounts mehrfach erfolglos abgefragt,
- wird X als `unavailable` statt als Workflowfehler geführt,
- werden vorhandene ältere X-Metadaten nicht gelöscht,
- laufen Historie und Clusteranalyse mit den übrigen Quellen weiter,
- bleibt der kombinierte Workflow grün.

## Neue Datei

```text
scripts/influence/diagnose_nitter_instances.mjs
```

## Ersetzte Dateien

```text
scripts/influence/fetch_influence_stage5_x_nitter.mjs
scripts/influence/check_influence_stage5_x.mjs
.github/workflows/build_influence_stage5_x.yml
.github/workflows/build_influence_stage3.yml
```

## Neue Ausgaben

```text
data/influence/ingest/nitter_preflight_latest.json
public/influence_nitter_preflight.json
```

## Erwartetes Ergebnis bei weiterhin blockierten Instanzen

```json
{
  "state": "unavailable",
  "configured_instances": 10,
  "usable_instances": 0
}
```

In `public/influence_x_ingest_status.json` erscheint dann:

```json
{
  "counts": {
    "eligible_endpoints": 63,
    "checked_endpoints": 0,
    "skipped_endpoints": 63,
    "collected_x_items": 0
  },
  "source_health": {
    "state": "unavailable"
  }
}
```

Das bedeutet: Der Sensor ist extern nicht erreichbar, nicht dass der
Influence-Workflow oder die Registry defekt ist.
