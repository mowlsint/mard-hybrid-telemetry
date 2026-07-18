# MARD Influence & Narrative Watch — Stage 1

## Ziel

Diese Stufe lädt und validiert die vorhandene Registry. Sie startet noch keinen
Social-Media-Scraper und verändert weder den MARD-HAT-Score noch den bestehenden
MARD-HAT-Build.

## Neue Dateien

```text
scripts/influence/load_influence_registry.mjs
scripts/influence/validate_influence_registry.mjs
scripts/influence/build_influence_registry_status.mjs
.github/workflows/validate_influence_registry.yml
```

## Erzeugte Dateien

```text
data/influence/validation_report.json
public/influence_registry_status.json
public/influence_registry_methodology.json
```

Der vollständige interne Quellenbestand bleibt unter `config/influence/`.
Öffentlich ausgegeben werden nur Bestandszahlen, Methodik und Status.

## Installation

Die Patch-Dateien relativ zur Repository-Wurzel hochladen. Bestehende Dateien
werden nicht ersetzt.

Danach:

1. GitHub → Actions
2. `Validate Influence Registry`
3. `Run workflow`
4. Branch `main`
5. Lauf starten

## Erwartetes Ergebnis

Der Lauf muss grün enden und ungefähr folgende Werte melden:

```text
entities: 213
endpoints: 310
enabled endpoints: 268
enabled social endpoints: 128
verification queue: 25
```

Geringfügige Abweichungen sind korrekt, falls die Registry inzwischen bearbeitet
wurde.

## Wichtige Schutzregel

Die Registry ist ein Beobachtungsregister. Die Aufnahme eines Accounts ist keine
Behauptung, dass dieser Desinformation verbreitet, automatisiert handelt oder
mit einem ausländischen Akteur koordiniert ist.
