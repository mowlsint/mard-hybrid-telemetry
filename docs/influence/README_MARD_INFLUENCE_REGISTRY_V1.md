# MARD Influence & Narrative Watch — Comprehensive Registry v1

**Stand:** 2026-07-18  
**GitHub-Integration:** bewusst noch nicht begonnen  
**Entitäten:** 213  
**Endpunkte:** 310  
**Davon aktiviert:** 268  
**Aktivierte Social-Media-Endpunkte:** 128  
**Transparente Prüfwarteschlange:** 25

## Zweck

Das Register bildet öffentliche Quellen und Accounts für folgende Untersuchungsbereiche ab:

- deutsche politische Verstärkung und plattformübergreifende Kampagnen,
- AfD, BSW/BSW-Legacy, Die Linke sowie demokratische Kontroll- und Vergleichsgruppen,
- deutsche Medien, Brückenquellen und reichweitenstarke politische Influencer,
- russische staatliche Kommunikation, Staatsmedien, pro-russische Brücken und bekannte FIMI-Infrastruktur,
- chinesische staatliche Kommunikation, Staatsmedien und bekannte Einflussnetzwerke,
- Iran, Huthi-Kommunikation mit maritimem Bezug und Belarus,
- Referenz-, Faktencheck- und FIMI-Forschungsquellen.

## Verbindliche Auswahlregeln

Ein deutscher Politiker-Account ist dauerhaft geeignet, wenn mindestens eines gilt:

1. manuell gesetzter Kernakteur,
2. durchschnittlich mindestens **10 politische Posts pro Woche**,
3. mindestens **40 politische Posts in 28 Tagen** und Aktivität in mindestens 3 von 4 Wochen,
4. **Top 15 %** der passenden Plattform-/Akteurskohorte,
5. mindestens 100.000 Follower auf einer Plattform,
6. wiederholte Beteiligung an relevanten Clustern,
7. besondere außen-, sicherheits- oder maritime Funktion.

Die quantitative Aktivitätsprüfung kann erst nach dem ersten 28-Tage-Ingest abgeschlossen werden.

## Methodischer Schutz

Die Aufnahme eines Akteurs bedeutet **nicht**, dass dieser:

- Desinformation verbreitet,
- automatisiert handelt,
- mit einem ausländischen Staat koordiniert ist,
- extremistisch ist,
- oder Teil eines Botnetzes ist.

Getrennt bewertet werden:

- Narrativähnlichkeit,
- Koordinationswahrscheinlichkeit,
- Automatisierungsindizien,
- ausländischer Ursprung,
- Quellen- und Attributionssicherheit.

## RT und RT DE

RT Global und RT DE sind getrennte Entitäten. RT DE wird zusätzlich als Quellenfamilie mit Spiegel- und Domainentdeckung geführt.

Öffentliche Exporte sollen für sanktionierte Quellen nur enthalten:

- Metadaten,
- Content- und Medienhashes,
- Clustergrößen,
- Zeitverläufe,
- eigene analytische Zusammenfassungen.

Vollständige Texte, eingebettete Videos oder werbliche Weiterverbreitung sind nicht vorgesehen.

## Dateien

- `mard_influence_registry_v1.json` — kanonische Gesamtdatei
- `mard_influence_entities_v1.csv` — flache Akteursübersicht
- `mard_influence_endpoints_v1.csv` — Plattform-, Feed-, Domain- und Musterendpunkte
- `mard_influence_verification_queue_v1.csv` — nicht aktivierte, noch offiziell gegenzuprüfende Social-Handles
- `mard_influence_selection_policy_v1.json` — Auswahl- und Schwellenregeln
- `mard_influence_taxonomy_v1.json` — Rollen- und Bewertungssystem
- `mard_influence_statistics_v1.json` — Bestandsstatistik
- `mard_influence_references_v1.csv` — Quellen- und Methodennachweise

## Noch nicht Teil dieses Pakets

- kein GitHub-Workflow,
- kein Scraper,
- kein API-Schlüssel,
- keine Bewertung einzelner Posts,
- keine automatische Bot- oder Attributionsentscheidung,
- keine Änderung am bestehenden MARD-HAT-Score.

Die spätere GitHub-Implementierung soll erst auf dieser geprüften Registry aufsetzen.
