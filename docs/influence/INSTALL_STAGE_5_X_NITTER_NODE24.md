# MARD Influence & Narrative Watch — Stage 5 X/Nitter

## Ziel

Stage 5 sammelt öffentliche Beiträge der in der Registry aktivierten X-Accounts
über mehrere öffentliche Nitter-Instanzen.

Nitter wird als best-effort Sammelproxy verwendet. Der Ingest beansprucht keine
Vollständigkeit und ist kein Ersatz für eine offizielle X-API.

## Warum mehrere Instanzen?

Nitter-Instanzen können:

- ausfallen,
- rate-limited sein,
- GitHub-Actions-IP-Adressen blockieren,
- RSS deaktivieren,
- Bot-Challenges ausliefern,
- unvollständige Timelines liefern.

Pro X-Account wird die Instanzreihenfolge deterministisch rotiert. Dadurch
beginnen nicht alle Accounts auf derselben Instanz. Der Standardlauf versucht
höchstens fünf Instanzen je Account.

## Sammelmethoden

Je Instanz:

1. RSS unter `/<handle>/rss`, sofern für die Instanz aktiviert,
2. bei RSS-Fehler oder leerem Feed: öffentliche HTML-Timeline `/<handle>`,
3. danach Failover zur nächsten Instanz.

## Neue Dateien

```text
config/influence/nitter_instances.json

scripts/influence/fetch_influence_stage5_x_nitter.mjs
scripts/influence/check_influence_stage5_x.mjs
scripts/influence/test_influence_stage5_x_parser.mjs

.github/workflows/build_influence_stage5_x.yml
```

## Zu ersetzen

```text
.github/workflows/build_influence_stage3.yml
```

Der kombinierte Workflow läuft danach:

```text
Stage 2 Website/RSS/Telegram
→ Stage 4 Bluesky/YouTube
→ Stage 5 X/Nitter
→ Stage 3 Historie und Cluster
```

## Persistierte Daten

Kein vollständiger X-Posttext wird gespeichert.

Gespeichert werden:

- Content-Hash,
- SimHash,
- Veröffentlichungszeit,
- X-Status-URL, sofern nicht eingeschränkt,
- verlinkte Domains,
- Inhaltslänge,
- Akteur und Endpunkt,
- pseudonymisierter Hash der verwendeten Nitter-Instanz,
- Erfassungsmodus RSS oder HTML.

## Neue Outputs

```text
data/influence/ingest/x_source_health_latest.json

public/influence_x_ingest_status.json
public/influence_x_source_health.json
```

Die X-Items werden außerdem in:

```text
data/influence/ingest/items_latest.json
```

gemischt und anschließend von der bestehenden Historien- und Clusteranalyse
verarbeitet.

## Erster Test

GitHub → Actions → `Build Influence X Stage 5`

```text
max_stage2_endpoints: 120
max_social_endpoints: 40
max_x_endpoints: 20
x_concurrency: 2
nitter_instance_attempts: 4
strict_x: false
```

## Vollständiger Test

Nach einem grünen ersten Lauf:

```text
max_stage2_endpoints: 350
max_social_endpoints: 220
max_x_endpoints: 180
x_concurrency: 3
nitter_instance_attempts: 5
strict_x: false
```

## Wichtig

Ein grüner Workflow kann einen X-Source-Health-Zustand `error` enthalten. Das ist
beabsichtigt: Ein Nitter-Ausfall darf die übrigen Sensoren nicht zerstören.

Prüfe dann:

```text
public/influence_x_source_health.json
```

Die Datei zeigt aggregiert:

- erfolgreiche und fehlgeschlagene Accounts,
- RSS- gegenüber HTML-Erfassung,
- Instanz-Fehler,
- Blockaden und Rate Limits.

## Eigene Nitter-Instanz

Später kann über die Umgebungsvariable `MARD_NITTER_INSTANCES` eine eigene oder
bevorzugte Instanzliste gesetzt werden:

```text
https://nitter.example.org,https://second.example.org
```

Die Variable überschreibt dann die JSON-Konfiguration.

## Laufzeit

Alle Workflows verwenden weiterhin Node.js 24 über `.node-version`.
