# Caddy Sentinel – Handbuch

Dieses Handbuch beschreibt jede Funktion des Panels und des Caddy-Moduls: was sie tut, wie sie eingestellt
wird und was dabei zu beachten ist. Installation und Update stehen in [INSTALL.md](INSTALL.md), ein Überblick
in der [README](../README.md).

## Inhalt

- [1. Grundlagen](#1-grundlagen)
  - [1.1 Begriffe](#11-begriffe)
  - [1.2 Was passiert, wenn das Panel ausfällt?](#12-was-passiert-wenn-das-panel-ausfällt)
  - [1.3 Rollen](#13-rollen)
- [2. Nach der Installation](#2-nach-der-installation)
  - [2.1 Voreinstellungen im Überblick](#21-voreinstellungen-im-überblick)
  - [2.2 Checkliste für die ersten Tage](#22-checkliste-für-die-ersten-tage)
  - [2.3 Das Panel über Caddy veröffentlichen](#23-das-panel-über-caddy-veröffentlichen)
  - [2.4 Caddy hinter einem weiteren Proxy](#24-caddy-hinter-einem-weiteren-proxy)
- [3. Die Oberfläche](#3-die-oberfläche)
  - [3.1 Aufbau des Fensters](#31-aufbau-des-fensters)
  - [3.2 Navigation](#32-navigation)
  - [3.3 Statusanzeigen](#33-statusanzeigen)
  - [3.4 Zeitraum](#34-zeitraum)
  - [3.5 Instanz-Auswahl](#35-instanz-auswahl)
  - [3.6 Globale Suche](#36-globale-suche)
  - [3.7 Tastenkürzel](#37-tastenkürzel)
  - [3.8 Warnungen](#38-warnungen)
  - [3.9 Gespeicherte Ansichten](#39-gespeicherte-ansichten)
- [4. Überwachung und Analyse](#4-überwachung-und-analyse)
  - [4.1 Woher die Zahlen kommen](#41-woher-die-zahlen-kommen)
  - [4.2 Übersicht](#42-übersicht)
  - [4.3 Live-Traffic](#43-live-traffic)
  - [4.4 Analysen](#44-analysen)
  - [4.5 Request-Details und Diagnose](#45-request-details-und-diagnose)
  - [4.6 Fehleranalyse](#46-fehleranalyse)
  - [4.7 Sicherheit](#47-sicherheit)
  - [4.8 IP-Steckbrief und IP-Details](#48-ip-steckbrief-und-ip-details)
  - [4.9 Request-Fluss (Ablauf und Simulator)](#49-request-fluss-ablauf-und-simulator)
  - [4.10 Verfügbarkeit](#410-verfügbarkeit)
- [5. Policies](#5-policies)
  - [5.1 Überblick über die Policy-Seite](#51-überblick-über-die-policy-seite)
  - [5.2 Welche Policy gilt für eine Anfrage?](#52-welche-policy-gilt-für-eine-anfrage)
  - [5.3 Prüfreihenfolge pro Anfrage](#53-prüfreihenfolge-pro-anfrage)
  - [5.4 Auswirkung prüfen](#54-auswirkung-prüfen)
  - [5.5 Testmodus](#55-testmodus)
  - [5.6 Tab „Allgemein“](#56-tab-allgemein)
  - [5.7 Tab „Zugriff“](#57-tab-zugriff)
  - [5.8 Tab „Ratelimits“](#58-tab-ratelimits)
  - [5.9 Tab „Geo & Feeds“](#59-tab-geo--feeds)
  - [5.10 Tab „Bots“](#510-tab-bots)
  - [5.11 Tab „Bot-Challenge“](#511-tab-bot-challenge)
  - [5.12 Tab „Anmeldung“](#512-tab-anmeldung)
  - [5.13 Tab „Pfad-Regeln“](#513-tab-pfad-regeln)
  - [5.14 Tab „WAF“](#514-tab-waf)
  - [5.15 Regelsätze und WAF-Tester](#515-regelsätze-und-waf-tester)
  - [5.16 Threat-Feeds](#516-threat-feeds)
  - [5.17 Tab „Header“](#517-tab-header)
  - [5.18 Tab „IDS“](#518-tab-ids)
  - [5.19 Befristete Einträge](#519-befristete-einträge)
  - [5.20 Policy-Bereiche übertragen](#520-policy-bereiche-übertragen)
  - [5.21 Empfehlungen für den Einstieg](#521-empfehlungen-für-den-einstieg)
- [6. Bedrohungserkennung (IDS)](#6-bedrohungserkennung-ids)
  - [6.1 Funktionsweise](#61-funktionsweise)
  - [6.2 Globale Einstellungen](#62-globale-einstellungen)
  - [6.3 Signale und Standardgewichte](#63-signale-und-standardgewichte)
  - [6.4 Sperren und Eskalation](#64-sperren-und-eskalation)
  - [6.5 Testmodus der Bedrohungserkennung](#65-testmodus-der-bedrohungserkennung)
  - [6.6 Typische Anpassungen](#66-typische-anpassungen)
  - [6.7 Anpassungen pro Policy](#67-anpassungen-pro-policy)
- [7. Anmeldung und Zugriff](#7-anmeldung-und-zugriff)
  - [7.1 So funktioniert der Site-Login](#71-so-funktioniert-der-site-login)
  - [7.2 Anmeldemethoden einrichten](#72-anmeldemethoden-einrichten)
  - [7.3 Eine Site mit Anmeldung schützen](#73-eine-site-mit-anmeldung-schützen)
  - [7.4 Zweiter Faktor und Schutz vor Fehlversuchen](#74-zweiter-faktor-und-schutz-vor-fehlversuchen)
  - [7.5 Single Sign-on (SSO)](#75-single-sign-on-sso)
  - [7.6 Anmeldung aus Sicht der Benutzer](#76-anmeldung-aus-sicht-der-benutzer)
  - [7.7 Die Kontoseite „Mein Konto“](#77-die-kontoseite-mein-konto)
  - [7.8 Passwort vergessen (Zugangskonten)](#78-passwort-vergessen-zugangskonten)
  - [7.9 Konten verwalten](#79-konten-verwalten)
  - [7.10 Zugriffstokens für Skripte und Dienste](#710-zugriffstokens-für-skripte-und-dienste)
  - [7.11 Benutzer-Header ans Backend](#711-benutzer-header-ans-backend)
  - [7.12 Anmeldung am Panel](#712-anmeldung-am-panel)
  - [7.13 API-Tokens für das Panel](#713-api-tokens-für-das-panel)
  - [7.14 Sentinel als OIDC-Server für Anwendungen](#714-sentinel-als-oidc-server-für-anwendungen)
- [8. Caddyfile, Sites und Zertifikate](#8-caddyfile-sites-und-zertifikate)
  - [8.1 Der Caddyfile-Editor](#81-der-caddyfile-editor)
  - [8.2 Änderungen übernehmen](#82-änderungen-übernehmen)
  - [8.3 Versionen, Vergleich und Zurückrollen](#83-versionen-vergleich-und-zurückrollen)
  - [8.4 Sites im Formular bearbeiten](#84-sites-im-formular-bearbeiten)
  - [8.5 Die Seite „Sites“](#85-die-seite-sites)
  - [8.6 Neue Site mit dem Assistenten](#86-neue-site-mit-dem-assistenten)
  - [8.7 Zertifikate](#87-zertifikate)
  - [8.8 Interne CA](#88-interne-ca)
- [9. Mehrere Caddy-Server](#9-mehrere-caddy-server)
  - [9.1 Grundprinzip](#91-grundprinzip)
  - [9.2 Die Seite „Caddy-Instanzen“](#92-die-seite-caddy-instanzen)
  - [9.3 Zugriffsmodi](#93-zugriffsmodi)
  - [9.4 Einen weiteren Caddy-Server anbinden](#94-einen-weiteren-caddy-server-anbinden)
  - [9.5 Token erneuern](#95-token-erneuern)
  - [9.6 Instanz entfernen](#96-instanz-entfernen)
  - [9.7 Der Agent im Betrieb](#97-der-agent-im-betrieb)
- [10. Einstellungen](#10-einstellungen)
  - [10.1 Bedrohungserkennung](#101-bedrohungserkennung)
  - [10.2 Benachrichtigungen](#102-benachrichtigungen)
  - [10.3 Netz & Vertrauen](#103-netz--vertrauen)
  - [10.4 Telemetrie & Speicher](#104-telemetrie--speicher)
  - [10.5 Agent & Caddy](#105-agent--caddy)
  - [10.6 Benutzer](#106-benutzer)
  - [10.7 Sicherung](#107-sicherung)
  - [10.8 Konto & Sicherheit, API-Tokens](#108-konto--sicherheit-api-tokens)
  - [10.9 Über & Lizenzen](#109-über--lizenzen)
- [11. Betrieb](#11-betrieb)
  - [11.1 Benachrichtigungen einrichten](#111-benachrichtigungen-einrichten)
  - [11.2 Wochenbericht](#112-wochenbericht)
  - [11.3 Prometheus](#113-prometheus)
  - [11.4 Sicherung und Wiederherstellung](#114-sicherung-und-wiederherstellung)
  - [11.5 Update](#115-update)
  - [11.6 Rollback](#116-rollback)
  - [11.7 Deinstallation](#117-deinstallation)
  - [11.8 Docker](#118-docker)
  - [11.9 Panel über Caddy veröffentlichen](#119-panel-über-caddy-veröffentlichen)
  - [11.10 Datenmenge und Aufbewahrung](#1110-datenmenge-und-aufbewahrung)
  - [11.11 Fehlersuche](#1111-fehlersuche)
- [12. Rollen und Rechte](#12-rollen-und-rechte)
- [13. Bekannte Grenzen](#13-bekannte-grenzen)
- [Anhang A: Aktionen im Anfrageprotokoll](#anhang-a-aktionen-im-anfrageprotokoll)
- [Anhang B: Umgebungsvariablen und Dateien](#anhang-b-umgebungsvariablen-und-dateien)
  - [B.1 Panel (`caddy-sentinel`)](#b1-panel-caddy-sentinel)
  - [B.2 Agent (Caddy-Prozess)](#b2-agent-caddy-prozess)
  - [B.3 Skripte und Docker Compose](#b3-skripte-und-docker-compose)
  - [B.4 Dateien und Verzeichnisse (systemd-Installation)](#b4-dateien-und-verzeichnisse-systemd-installation)
  - [B.5 Docker-Volumes](#b5-docker-volumes)

## 1. Grundlagen

Caddy Sentinel besteht aus zwei Teilen, die zusammenarbeiten:

- **Agent**: ein Modul im Caddy-Webserver (Direktive `sentinel`). Er prüft jede Anfrage der Sites, in denen
  `sentinel` steht, nach den Regeln seiner Policy und meldet das Ergebnis an das Panel. Er entscheidet lokal und
  wartet nie auf das Panel.
- **Panel**: die Weboberfläche mit Datenbank (SQLite). Es verteilt Policies, Sperren und Konten an die Agents,
  speichert die Telemetrie, bewertet Clients (IDS), verschickt Benachrichtigungen und bearbeitet die Caddyfile.

```
Anfrage ──▶ Caddy mit Agent: Sperren → Pfad-Regeln → Wartung → IP/Geo/Feeds → Filter
                             → Ratelimits → Bot-Challenge → Anmeldung → WAF ──▶ Backend
                 │ Telemetrie (etwa 1×/s)            ▲ Policies, Sperren (Long-Poll, < 1 s)
                 ▼                                   │
           Panel: Datenbank · IDS · Alarme · Weboberfläche · /metrics · Caddyfile-Versionen
```

Die genaue Reihenfolge der Prüfungen steht in Kapitel 5.

### 1.1 Begriffe

| Begriff | Bedeutung |
|---|---|
| Site | Ein Block in der Caddyfile (z. B. `wiki.example.com { … }`). Geschützt und gemessen wird nur, wo `sentinel` steht. |
| Policy | Satz von Regeln für eine oder mehrere Sites: WAF, Ratelimits, Login, Pfad-Regeln, Geo, Bots usw. (Kapitel 5). |
| Standard-Policy | Gilt für jede Site mit `sentinel`, deren Host keiner Policy zugeordnet ist. Wird bei der Installation als „Standard“ angelegt. |
| Instanz | Ein Caddy-Server, der an das Panel angebunden ist. Der Caddy auf dem Panel-Server heißt „lokal“, weitere verbinden sich als Agent (Kapitel 9). |
| IDS | Bedrohungserkennung: vergibt Punkte für verdächtiges Verhalten und sperrt IPs ab einer Schwelle (Kapitel 6). |
| Sperre (Ban) | Eine IP oder ein Netz, das auf allen Sites mit `sentinel` abgewiesen wird – unabhängig von der Policy. |
| Vertrauenswürdig | IPs/Netze, die von allen Prüfungen ausgenommen sind (Einstellungen › Netz & Vertrauen). |
| Nie sperren | IPs/Netze, die das IDS nie sperrt; die Policy-Regeln gelten für sie weiter. |
| Testmodus | Regeln protokollieren nur, was sie getan hätten („Test: …“), und lassen die Anfrage durch. |
| Zugangskonto | Ein in Sentinel angelegtes Konto für den Site-Login (im Unterschied zu AD- oder OIDC-Konten). |

### 1.2 Was passiert, wenn das Panel ausfällt?

Der Agent arbeitet mit dem zuletzt bekannten Zustand weiter. Diesen speichert er in einer Cache-Datei im
Caddy-Datenverzeichnis (`sentinel-state.json`), er gilt also auch nach einem Neustart von Caddy. Nur wenn gar kein
Zustand vorliegt (erster Start ohne Panel), lässt der Agent alle Anfragen durch. Mit der globalen Option
`fail_closed` antwortet er stattdessen mit 503. Für Site-Logins braucht der Agent das Panel nur beim Anmelden;
bestehende Sitzungen prüft er selbst.

### 1.3 Rollen

Das Panel kennt vier Rollen: **Administrator** (alles), **Bearbeiter** (Caddyfile, Policies, Regelsätze, Feeds,
Monitore, Sperren), **Support** (alles sehen, Sperren setzen und aufheben) und **Leser** (nur lesen). Die
vollständige Übersicht steht in Kapitel 12.

## 2. Nach der Installation

Die Installation (docs/INSTALL.md) richtet ein funktionierendes, aber bewusst zurückhaltendes System ein: Es
misst alles, sperrt nur eindeutige Angriffe und blockiert mit der WAF noch nichts. Dieses Kapitel erklärt die
Voreinstellungen und was du in den ersten Tagen anpassen solltest.

### 2.1 Voreinstellungen im Überblick

| Bereich | Voreinstellung | Bewertung |
|---|---|---|
| Panel-Adresse | `127.0.0.1:7600`, nur lokal | Sicher. Zugriff per SSH-Tunnel oder über eine eigene Caddy-Site (2.3). |
| Caddyfile | Globale Option `sentinel` wird eingetragen; ohne vorhandene Caddyfile eine Beispielsite `:80` | `sentinel` muss zusätzlich in jeder Site stehen, die geschützt werden soll. |
| Standard-Policy „Standard“ | aktiv, WAF *Erkennen*, OWASP CRS Paranoia 1, Schwelle 5, Body-Prüfung bis 1 MiB | Blockiert mit der WAF noch nichts. Erst beobachten, dann scharf schalten (2.2, Schritt 4). |
| Honeypots | `/.env`, `/.git/`, `/.aws/`, `/.ssh/`, `/.svn/`, `/wp-config.php` | Pfade, die keine echte Site ausliefert. Ein Treffer sperrt die IP sofort. |
| Ratelimit „Allgemein pro IP“ | 1200 Anfragen pro Minute, dann 429 | Schutz vor Überflutung, großzügig für Büros hinter einer IP und Sync-Clients. |
| Sicherheits-Header | aus (vorbelegt: nosniff, SAMEORIGIN, Referrer-Policy) | Einschalten, wenn die Anwendungen sie nicht selbst setzen. |
| IDS | an, Sperre ab 100 Punkten, Halbwertszeit 15 Min., Sperre 1 h, ×3 je Wiederholung, höchstens 30 Tage | Ausgewogen. Eigene Netze unter „Nie sperren“ eintragen (2.2, Schritt 3). |
| Nie sperren | nur `127.0.0.0/8` und `::1` | Ergänzen. |
| Bot-Challenge ab Score | 40 | Wirkt nur in Policies mit Challenge-Modus „verdächtig“. |
| Telemetrie | 100 % der Anfragen, Query-String gespeichert (sensible Werte als `***`) | Für die meisten Installationen passend. |
| Aufbewahrung | Einzel-Anfragen 7 Tage, Ereignisse und Minuten-Statistik 90 Tage | Bei sehr viel Traffic kürzen oder Stichprobe setzen (Kapitel 11). |
| Alarme | 5xx-Quote ≥ 20 % (ab 50 Anfragen in 5 Min.), Traffic ×6 (ab 300/Min.), ≥ 200 blockierte Anfragen/Min., Agent offline, Zertifikat läuft ab, Monitor ausgefallen, Ursachen-Spitze | Sinnvoll – aber ohne Benachrichtigungskanal sieht sie niemand (2.2, Schritt 5). |
| Zertifikate | Warnung 14 Tage vor Ablauf | Passend. |
| Verzeichnis (AD) | aus; wenn aktiv: Sperre nach 5 Fehlversuchen für 15 Min., Site-Sitzung 12 h, 2FA für AD-Panel-Konten Pflicht | Passend. |

### 2.2 Checkliste für die ersten Tage

1. **Admin-Konto absichern**: *Einstellungen › Konto & Sicherheit* – Zwei-Faktor-Anmeldung einrichten.
2. **Sites einbinden**: Im *Caddyfile-Editor* „Sentinel einfügen“ verwenden oder `sentinel` in jede Site
   schreiben und übernehmen. Die Übersicht zeigt danach die Anfragen pro Host.
3. **Eigene Netze schützen**: *Einstellungen › Netz & Vertrauen* – das Büro-/VPN-Netz, Monitoring-Systeme und
   Gateways, hinter denen viele Nutzer eine IP teilen, unter „Nie sperren“ eintragen. Sonst sperrt ein
   einzelner infizierter Rechner oder ein Honeypot-Treffer alle Kollegen hinter dieser IP. „Vertrauenswürdig“
   nur für Quellen verwenden, die gar nicht geprüft werden sollen (z. B. interne Dienste).
4. **WAF beobachten, dann blockieren**: Ein bis zwei Wochen unter *Sicherheit* die WAF-Treffer ansehen. Fehlalarme
   mit dem Fehlalarm-Assistenten ausnehmen (Kapitel 5). Danach in der Policy die WAF auf „Blockieren“ stellen.
   Im Erkennungsmodus zählt das IDS WAF-Treffer pro Pfad nur einmal in 10 Minuten, echte Scanner werden trotzdem
   gesperrt.
5. **Benachrichtigungen einrichten**: *Einstellungen › Benachrichtigungen* – mindestens einen Kanal (E-Mail,
   Teams, Matrix, ntfy …) und die „Panel-URL für Links“ eintragen.
6. **Login-Pfade schützen**: In den Policies der Anwendungen die Ratelimit-Vorlage „Login-Schutz“ für die
   Anmeldeseiten hinzufügen.
7. **Verfügbarkeit**: *Verfügbarkeit › Sites übernehmen* legt Monitore für alle Hosts an.
8. **Warnungen prüfen**: Die Seitenleiste meldet unplausible Einstellungen (z. B. Passwort-Reset ohne
   Mailserver, Standard-Policy ausgeschaltet). Die Liste sollte leer sein.
9. **Sicherung**: *Einstellungen › Sicherung* – eine erste, mit Passwort verschlüsselte Sicherung herunterladen
   und Datei und Passwort getrennt aufbewahren (Kapitel 10.7).

### 2.3 Das Panel über Caddy veröffentlichen

Soll das Panel ohne SSH-Tunnel erreichbar sein, veröffentliche es über eine eigene Site mit HTTPS:

```caddy
sentinel.example.com {
	sentinel panel
	reverse_proxy 127.0.0.1:7600
}
```

Lege dafür eine eigene Policy (hier `panel`) an, statt die Standard-Policy zu verwenden:

- **WAF aus oder nur Erkennen**: Das Panel speichert Caddyfiles, WAF-Regeln und Testanfragen. Solche Inhalte
  sehen für das CRS wie Angriffe aus; eine blockierende WAF würde das Speichern verhindern.
- **Zugriff einschränken**: unter *Zugriff* nur die eigenen Netze erlauben oder einen Site-Login davorschalten.
- Das Panel übernimmt die echte Client-IP aus `X-Forwarded-For` nur von Proxys in `SENTINEL_TRUSTED_PROXIES`
  (Standard: localhost, passt für Caddy auf demselben Server).

Für OAuth/OIDC und den Passwort-Reset muss das Panel für die Benutzer erreichbar sein; trage die öffentliche
Adresse dann unter *Site-Login & Konten › OAuth / OIDC* als „Öffentliche Panel-Adresse“ ein.

### 2.4 Caddy hinter einem weiteren Proxy

Steht vor Caddy ein Load Balancer, Cloudflare oder ein Docker-Proxy, muss Caddy die echte Client-IP kennen.
Sonst sieht Sentinel nur die IP des Proxys – und das IDS würde im Ernstfall den Proxy und damit alle Besucher
sperren:

```caddy
{
	servers {
		trusted_proxies static 173.245.48.0/20 103.21.244.0/22
		client_ip_headers CF-Connecting-IP X-Forwarded-For
	}
}
```

Trage die IP des Proxys zusätzlich unter „Nie sperren“ ein.

**Hinweis (Docker):** Mit veröffentlichten Ports sieht Caddy bei IPv4 die echte Client-IP. Ohne IPv6 im
Docker-Netz leitet Docker IPv6-Verbindungen über seinen Proxy weiter; alle IPv6-Besucher erscheinen dann mit der
Gateway-Adresse des Docker-Netzes. Aktiviere in diesem Fall IPv6 für das Docker-Netz oder trage das Gateway
unter „Nie sperren“ ein.

## 3. Die Oberfläche

Dieses Kapitel beschreibt den Aufbau des Panels und die Funktionen, die auf allen Seiten zur Verfügung stehen: Navigation, Statusanzeigen, Zeitraum- und Instanz-Auswahl, die globale Suche, die Liste der Warnungen und gespeicherte Ansichten.

### 3.1 Aufbau des Fensters

Das Panel besteht aus drei Bereichen:

- **Seitenleiste** (links): Logo „Caddy Sentinel“ mit dem Zusatz „Caddy-Steuerzentrale“, die Navigation und unten der Statusblock. Ein Klick auf das Logo öffnet die „Übersicht“. Auf schmalen Bildschirmen ist die Seitenleiste eingeklappt und lässt sich über die Schaltfläche „☰“ öffnen.
- **Kopfleiste** (oben): Seitentitel, Schaltfläche „Suchen“, Puls-Leiste, gegebenenfalls die Instanz-Auswahl und rechts die Aktionen der jeweiligen Seite (z. B. Zeitraum-Auswahl, „Aktualisieren“, „Monitor hinzufügen“).
- **Inhaltsbereich** mit der gewählten Seite.

Details zu einzelnen Einträgen (Requests, Ereignisse, IP-Adressen, Fehlerursachen) öffnen sich in einer **Seitenleiste am rechten Rand**. Sie schließt sich mit „✕“, mit der Taste Esc oder beim Wechsel der Seite. Es ist immer nur eine solche Seitenleiste offen.

### 3.2 Navigation

Die Seitenleiste enthält folgende Einträge in dieser Reihenfolge. Die Adresse in der rechten Spalte lässt sich direkt in die Adresszeile hinter die Panel-Adresse setzen oder als Lesezeichen speichern.

| Gruppe | Eintrag | Adresse | Beschrieben in |
|---|---|---|---|
| – | „Übersicht“ | `#/` | Kapitel 4.2 |
| – | „Live-Traffic“ | `#/live` | Kapitel 4.3 |
| – | „Analysen“ | `#/analytics` | Kapitel 4.4 |
| – | „Fehleranalyse“ | `#/failures` | Kapitel 4.6 |
| – | „Sites“ | `#/sites` | Kapitel 8 |
| – | „Request-Fluss“ | `#/flow` | Kapitel 4.9 |
| – | „Verfügbarkeit“ | `#/uptime` | Kapitel 4.10 |
| – | „Zertifikate“ | `#/certs` | Kapitel 8 |
| – | „Interne CA“ | `#/pki` | Kapitel 8 |
| „Konfiguration“ | „Caddy-Instanzen“ | `#/instances` | Kapitel 9 |
| „Konfiguration“ | „Caddyfile-Editor“ | `#/editor` | Kapitel 8 |
| „Konfiguration“ | „Policies“ | `#/policies` | Kapitel 5 |
| „Konfiguration“ | „Regelsätze“ | `#/rulesets` | Kapitel 5 |
| „Schutz“ | „Sicherheit“ | `#/security` | Kapitel 4.7 |
| „Schutz“ | „Site-Login & Konten“ | `#/access` | Kapitel 7 |
| „Schutz“ | „Threat-Feeds“ | `#/feeds` | Kapitel 5 |
| „Schutz“ | „WAF-Tester“ | `#/waf` | Kapitel 5 |
| – | „Einstellungen“ | `#/settings` | Kapitel 10 |

Zusätzlich gibt es die Seite **„IP-Details“** unter `#/ip/<IP-Adresse>` (siehe Kapitel 4.8). Sie hat keinen eigenen Menüeintrag und wird über IP-Links, die Suche oder Top-Listen geöffnet.

Am Eintrag „Sicherheit“ zeigt eine Zahl die Anzahl der aktiven IP-Sperren an. Ohne aktive Sperre ist sie ausgeblendet.

Alle Seiten sind für alle Rollen sichtbar. Ob eine Rolle dort etwas ändern darf, steht bei der jeweiligen Funktion (Übersicht in Kapitel 12).

**Tipp:** Viele Seiten schreiben ihre Filter in die Adresse (z. B. `#/analytics?host=wiki.example.org&status=5xx`). So eine Adresse lässt sich kopieren und an Kollegen weitergeben; sie öffnet die Seite mit denselben Filtern.

### 3.3 Statusanzeigen

#### Statusblock in der Seitenleiste

| Anzeige | Bedeutung |
|---|---|
| Punkt und „Caddy erreichbar“ / „Caddy nicht erreichbar“ | Erreichbarkeit der Admin-API von Caddy. Der Tooltip nennt die Fehlermeldung bzw. die Adresse der Admin-API. Bei mehreren Instanzen und Auswahl „Alle Caddy-Instanzen“ steht hier „x von y Caddy-Instanzen verbunden“ (grün: alle, gelb: ein Teil, rot: keine); der Tooltip nennt die Instanzen, die offline sind. |
| Punkt und „N Agent(en) verbunden“ / „Kein Agent verbunden“ | Verbundene Sentinel-Agents. Gelb, wenn ein Agent Fehler beim Laden einer Policy meldet. |
| „Version …“ und „Lizenzen“ | Installierte Version; „Lizenzen“ öffnet *Einstellungen › Über & Lizenzen*. Ist eine neuere Version verfügbar, erscheint ein Hinweis „Update …“; ein Klick zeigt die Befehle zum Aktualisieren (siehe Kapitel 11). |
| „IP-Geodaten: …“ | Quellenangabe der verwendeten Geodatenbank (nur wenn vorhanden). |
| Benutzername, Rolle, „Abmelden“ | Angemeldeter Benutzer. Bei allen Rollen außer Administrator steht die Rolle als Kennzeichen daneben. |

Der Statusblock aktualisiert sich alle 15 Sekunden, solange das Browserfenster sichtbar ist.

#### Puls-Leiste

Die Puls-Leiste in der Kopfleiste zeigt die Requests pro Sekunde der letzten 90 Sekunden als kleines Balkendiagramm. Der rote Anteil eines Balkens steht für blockierte Requests. Daneben steht der Durchschnitt der letzten fünf Sekunden („… Req/s“) und, falls in dieser Zeit etwas blockiert wurde, „N blockiert“, sonst „live“. Die Werte folgen der Instanz-Auswahl.

#### Meldungen im Browser

Das Panel hält eine Live-Verbindung zum Server und blendet unten kurze Meldungen ein:

- bei jeder neuen IP-Sperre (rot, 6 Sekunden),
- bei Alarmen der Schwere „Hoch“ oder „Kritisch“, z. B. „Angriffswelle auf …“ oder ein ausgefallener Monitor (rot, 8 Sekunden).

Die Meldungen erscheinen nur, solange das Panel geöffnet ist. Für Benachrichtigungen per E-Mail, Chat oder Push siehe Kapitel 11.

### 3.4 Zeitraum

Auf den Seiten „Übersicht“, „Analysen“, „Fehleranalyse“, „Sicherheit“ und „IP-Details“ steht rechts in der Kopfleiste die Zeitraum-Auswahl mit „15 Min.“, „1 Std.“, „6 Std.“, „24 Std.“, „7 Tage“ und „30 Tage“. Voreingestellt ist „1 Std.“. Die Wahl gilt für alle diese Seiten und bleibt im Browser gespeichert.

Die Diagramme fassen die Werte je nach Zeitraum in Abschnitte zusammen: bis 2 Stunden je Minute, bis 8 Stunden je 5 Minuten, bis etwa einen Tag je 10 Minuten, bis 8 Tage je Stunde, darüber je 4 Stunden.

Kennzahlen mit Trendpfeil vergleichen den gewählten Zeitraum mit dem gleich langen Zeitraum unmittelbar davor (Tooltip „gegenüber dem vorherigen Zeitraum“). „neu“ bedeutet, dass der Wert vorher 0 war; Änderungen unter 2 % werden als „±“ angezeigt.

**Hinweis:** Auf der Seite „Sicherheit“ wirkt der Zeitraum nur auf den Reiter „Lage“, auf „IP-Details“ gar nicht (dort werden immer alle gespeicherten Daten der Adresse gezeigt). Welche Daten wie lange zurückreichen, beschreibt Kapitel 4.1.

### 3.5 Instanz-Auswahl

Sobald mehr als eine Caddy-Instanz eingerichtet ist (siehe Kapitel 9), erscheint in der Kopfleiste eine Auswahl mit „Alle Caddy-Instanzen“ und den einzelnen Instanzen. Instanzen ohne Verbindung tragen den Zusatz „(offline)“. Die Auswahl filtert Statistiken, Requests, Ereignisse und Warnungen auf die gewählte Instanz und bleibt im Browser gespeichert.

Bei der Auswahl „Alle Caddy-Instanzen“ gilt:

- Listen und Tabellen kennzeichnen jeden Eintrag mit einem farbigen Namensschild seiner Instanz.
- Die Übersicht zeigt oben eine Kachel je Instanz (siehe Kapitel 4.2).
- Anzeigen, die sich auf genau einen Caddy-Prozess beziehen (Erreichbarkeit im Statusblock, Panel „Caddy-Prozess“), zeigen die lokale Instanz auf dem Panel-Server.

Seiten, die immer genau eine Caddy-Instanz betreffen (z. B. „Request-Fluss“, „Caddyfile-Editor“, „Sites“, „Zertifikate“), zeigen oben eine Leiste „Caddy-Instanz“ mit Name, Verbindungsstatus („verbunden“, „offline seit …“, „noch nie verbunden“), Verwaltungsmodus („Lokal“, „Fernverwaltung“, „Nur lesen“, „Keine Fernverwaltung“) und der Auswahl „Wechseln:“. Steht die globale Auswahl auf „Alle“, merkt sich das Panel die dort zuletzt gewählte Instanz; andernfalls schaltet „Wechseln:“ die globale Auswahl um.

Gibt es im Caddyfile-Editor ungespeicherte Änderungen, fragt jeder Instanzwechsel zuerst „Ungespeicherte Änderungen verwerfen?“.

### 3.6 Globale Suche

Die Suche öffnest du über „Suchen“ in der Kopfleiste, mit Strg+K (macOS: ⌘K) oder mit der Taste `/`, sofern gerade kein Eingabefeld aktiv und kein Dialog geöffnet ist. Gesucht wird ab zwei Zeichen.

| Eingabe | Ergebnis |
|---|---|
| Referenz von einer Fehlerseite, z. B. `K7QM-3XPA` (auch ohne Bindestrich) | „Anfrage …“ mit Status, Host, Pfad und Zeit; öffnet die Fehleranalyse mit dieser Anfrage (siehe Kapitel 4.6). |
| IP-Adresse | „IP-Steckbrief“ der Adresse. |
| Anfang einer IP-Adresse, z. B. `203.0.113.` | bis zu acht gespeicherte Adressen mit diesem Anfang. |
| Netz in CIDR-Schreibweise | „Anfragen aus diesem Netz“ in den Analysen. |
| Hostname oder Teil davon | Hosts aus Policies und aus dem Traffic der letzten 7 Tage; öffnet die Analysen für diesen Host. |
| Name, Notiz oder Pfad | Policies, Pfad-Regeln, Ratelimits, Regelsätze, Caddy-Instanzen, Site-Konten, Threat-Feeds, Monitore, befristete Einträge, gespeicherte Ansichten. |
| Benutzername | Panel-Benutzer (nur für Administratoren). |
| Seitenname oder Stichwort | Seiten des Panels einschließlich Unterseiten wie „Einstellungen › Benachrichtigungen“ oder „Site-Login › Zugriffstokens“. |

Links steht bei jedem Treffer seine Art („Seite“, „Anfrage“, „IP“, „Host“, „Policy“, „Regel“, „Regelsatz“, „Instanz“, „Konto“, „Benutzer“, „Feed“, „Monitor“, „Befristet“, „Ansicht“). Mit den Pfeiltasten wählst du aus, Enter öffnet, Esc schließt.

**Hinweis:** Die Suche nach einem CIDR-Netz filtert die Analysen auf Adressen, die mit der Netzadresse beginnen. Für ein /24-Netz trage stattdessen im Feld „IP (Präfix mit *)“ der Analysen den Anfang mit Stern ein, z. B. `198.51.100.*`.

### 3.7 Tastenkürzel

| Taste | Wirkung |
|---|---|
| Strg+K (macOS: ⌘K) | Suche öffnen |
| `/` | Suche öffnen (nicht in Eingabefeldern) |
| ↑ / ↓, Enter | in der Suche auswählen und öffnen |
| Esc | Suche oder Seitenleiste schließen |
| Klick auf eine IP-Adresse | IP-Steckbrief als Seitenleiste |
| Strg-, ⌘- oder Umschalt-Klick, mittlere Maustaste auf eine IP-Adresse | ganze Seite „IP-Details“ |

Auf macOS ist Strg+K bewusst nicht belegt, weil es im Caddyfile-Editor „bis Zeilenende löschen“ bedeutet.

### 3.8 Warnungen

Oben auf der „Übersicht“ sammelt der Kasten **„Was Aufmerksamkeit braucht (N)“** alles, was ein Eingreifen erfordert. Er erscheint nur, wenn es etwas zu melden gibt, zeigt höchstens zwölf Einträge („… und N weitere“) und ist nach Schwere sortiert: „Kritisch“, „Problem“, „Warnung“, „Hinweis“. Die meisten Einträge sind Links zur Stelle, an der sich das Problem beheben lässt. Die Liste wird jede Minute aktualisiert und folgt der Instanz-Auswahl.

| Warnung | Schwere | Führt zu |
|---|---|---|
| Caddy-Instanz „…“ meldet sich nicht / hat sich noch nie verbunden. Ohne Verbindung gelten dort die zuletzt bekannten Regeln weiter; neue Sperren und Policies kommen nicht an. | Problem / Warnung | „Caddy-Instanzen“ |
| Policy „…“ ist auf einem Knoten fehlerhaft (vom Agent gemeldet) | Problem | Policy |
| Zertifikat abgelaufen | Kritisch | „Zertifikate“ |
| Zertifikat läuft in N Tagen ab (Warnschwelle aus den Einstellungen, Standard 14 Tage) | Problem | „Zertifikate“ |
| Backend … fällt aus (Caddy meldet fehlgeschlagene Verbindungen) | Problem | „Sites“ |
| „Nicht erreichbar: …“ (Monitor gestört) | Problem | „Verfügbarkeit“ |
| Testmodus in „…“ mit Angabe der betroffenen Regeln und der Zahl der Anfragen, die in 24 Stunden aufgehalten worden wären | Hinweis | Policy |
| Anstieg einer Fehlerursache in der letzten Stunde | je nach Alarm | „Fehleranalyse“ |
| „Wartungsmodus aktiv: …“ / „Wartung geplant: …“ (innerhalb der nächsten 7 Tage) | Warnung / Hinweis | Policy |
| Pfad-Regel endet innerhalb von 24 Stunden | Hinweis | Policy › Pfad-Regeln |
| Zugriffstoken laufen in den nächsten 7 Tagen ab | Hinweis | *Site-Login & Konten › Zugriffstokens* |
| „Bedrohungserkennung im Probebetrieb“ | Hinweis | *Einstellungen › Bedrohungserkennung* |
| Passwort-Reset per E-Mail eingeschaltet, aber kein Mailserver eingerichtet | Warnung | *Einstellungen › Benachrichtigungen* |
| Wochenbericht ohne Mailserver oder Empfänger | Hinweis | *Einstellungen › Benachrichtigungen* |
| Benachrichtigung per E-Mail ohne Mailserver | Warnung | *Einstellungen › Benachrichtigungen* |
| „Adresse des Panels fehlt“ (bei Benachrichtigungen, Bericht oder Passwort-Reset) | Hinweis | *Einstellungen › Benachrichtigungen* |
| „Single Sign-on ohne Domain“ | Warnung | *Site-Login & Konten › Verzeichnis* |
| „Challenge-Schwelle liegt nicht unter der Sperrschwelle“ | Hinweis | *Einstellungen › Bedrohungserkennung* |
| „Standard-Policy fehlt“ / Standard-Policy ist ausgeschaltet | Problem / Warnung | „Policies“ |

**Tipp:** Die Liste ist als tägliche Kontrolle gedacht. Ist sie leer, gibt es nach Einschätzung des Panels nichts zu tun.

### 3.9 Gespeicherte Ansichten

Auf „Live-Traffic“, „Analysen“ und „Fehleranalyse“ steht eine Leiste „Ansichten:“. Eine Ansicht speichert die Filter der Seite zusammen mit dem Zeitraum und, bei mehreren Instanzen, der gewählten Instanz.

So speicherst du eine Ansicht:

1. Stelle Filter, Zeitraum und Instanz ein.
2. Klicke auf „＋ Ansicht speichern“.
3. Gib einen Namen ein (höchstens 80 Zeichen), z. B. „403 auf dem Wiki, letzte Stunde“.
4. Schalte bei Bedarf „für alle Panel-Benutzer sichtbar“ ein.
5. Klicke auf „Speichern“.

Ein Klick auf den Namen stellt zuerst Zeitraum und Instanz um und öffnet dann die Seite mit den Filtern. Geteilte Ansichten sind mit „👥“ gekennzeichnet; der Tooltip nennt bei fremden Ansichten den Besitzer. Gespeicherte Ansichten findet auch die Suche.

Löschen („✕“) kann nur der Besitzer einer Ansicht oder ein Administrator. Ansichten anlegen dürfen alle Rollen, auch Leser.

**Tipp:** Geteilte Ansichten eignen sich als gemeinsame Arbeitslisten im Team, z. B. „Blockiert auf dem Kundenportal“ oder „5xx der letzten 24 Stunden“.

---

## 4. Überwachung und Analyse

Dieses Kapitel beschreibt die Seiten, mit denen du den Verkehr beobachtest, Fehler und Blockaden aufklärst und die Verfügbarkeit deiner Sites prüfst. Alle Seiten sind für alle Rollen sichtbar; Aktionen wie Sperren oder Monitore anlegen sind bei der jeweiligen Funktion mit ihrer Rolle genannt.

### 4.1 Woher die Zahlen kommen

Der Agent in Caddy liefert dem Panel zwei Arten von Daten:

| Daten | Inhalt | Verwendet für | Aufbewahrung (Standard) |
|---|---|---|---|
| Minuten-Statistik | Zähler je Minute, Host, Policy, Status und Aktion – immer vollständig und exakt | Diagramme, Kennzahlen, Host-Liste der Übersicht, Latenzverteilung | 90 Tage |
| Einzelne Requests | jeder sicherheitsrelevante oder fehlerhafte Request, normale Requests gemäß Stichprobe | Request-Listen, Live-Stream, Top-Listen, Fehleranalyse, IP-Steckbrief, WAF-Regel-Statistik, Referenzsuche, Diagnose | 168 Stunden (7 Tage) |
| Stunden-Zusammenfassungen der Einzel-Requests | Top-Werte und Fehlerursachen je Stunde | Top-Listen, Fehleranalyse und Wochenbericht über längere Zeiträume | mindestens 8 Tage, sonst wie Einzel-Requests |
| Ereignisse | Sicherheitsereignisse, Alarme, Konfigurationsänderungen, Audit-Log | Seite „Sicherheit“, Markierungen in der Fehleranalyse | 90 Tage |
| Monitor-Prüfungen | Ergebnis jeder Verfügbarkeitsprüfung | „Verfügbarkeit“ | 90 Tage |

Die Fristen stellst du unter *Einstellungen › Telemetrie & Speicher* im Bereich „Aufbewahrung“ ein („Einzelne Requests (Stunden)“, „Ereignisse (Tage)“, „Minuten-Statistik (Tage)“); siehe Kapitel 10 und 11.

**Hinweis:** Bei den Zeiträumen „7 Tage“ und „30 Tage“ reichen Diagramme und Kennzahlen über den ganzen Zeitraum, Request-Listen, Top-Listen und Fehleranalyse dagegen nur so weit, wie Einzel-Requests bzw. Stunden-Zusammenfassungen aufbewahrt werden (standardmäßig etwa eine Woche).

**Stichprobe:** Unter *Einstellungen › Telemetrie & Speicher* legt „Stichprobe normaler Requests (%)“ fest, welcher Anteil fehlerfreier Requests ohne Sentinel-Eingriff einzeln übertragen wird (Standard 100 %). Fehler, WAF-Treffer und blockierte Requests werden immer übertragen. Bei weniger als 100 % bleiben Diagramme und Kennzahlen exakt, Request-Listen, Live-Stream und Top-Listen enthalten vom normalen Verkehr aber nur die Stichprobe.

**Query-Strings:** Werte sensibler Parameter (z. B. `token`, `password`, `secret`, `code`, `state`, `key`, `sig`, `session`, `api_key`, `X-Amz-Signature`) werden als `***` gespeichert, auf Sentinels eigenen Seiten unter `/.sentinel/` alle Werte. Ob Query-Strings überhaupt gespeichert werden, regelt „Query-Strings – mitspeichern“ unter *Einstellungen › Telemetrie & Speicher*.

Bei sehr vielen verschiedenen Werten (Pfade, IP-Adressen, User-Agents, Referer, Netze) behalten die Stunden-Zusammenfassungen die 500 häufigsten je Stunde und Host. Top-Listen über mehrere Tage sind dann Näherungen; die Zahl der Clients und Pfade in der Fehleranalyse wird ab einigen hundert Werten auf etwa ±6 % geschätzt.

Die Aktionen, die Sentinel bei einem Request vermerkt, und welche davon als „blockiert“ zählen, listet Anhang A.

### 4.2 Übersicht

*Übersicht* (`#/`) ist die Startseite. Sie folgt dem Zeitraum und der Instanz-Auswahl und aktualisiert sich selbst: Kennzahlen und Diagramme alle 30 Sekunden, „Caddy-Prozess“ und Warnungen jede Minute, die Sicherheitsereignisse sofort.

Von oben nach unten:

1. **„Was Aufmerksamkeit braucht“** – siehe Kapitel 3.8.
2. **Instanz-Kacheln** (nur bei mehreren Instanzen und Auswahl „Alle“): Name, „verbunden“ oder „offline“ und die Art („Panel-Server“, „Fernverwaltung“, „nur lesen“). Ein Klick schaltet die Instanz-Auswahl auf diese Instanz.
3. **Hinweisbalken**, falls Caddy nicht erreichbar ist („Caddy ist nicht erreichbar: … Prüfe, ob Caddy läuft und die Admin-API unter … erreichbar ist.“) oder noch kein Agent verbunden ist („Es ist noch kein Sentinel-Agent verbunden. Caddy muss mit dem Sentinel-Modul gebaut sein und mindestens eine Site die Direktive `sentinel` enthalten.“).
4. **Kennzahlen:**

| Kachel | Bedeutung |
|---|---|
| „Requests“ | Anzahl im Zeitraum, dazu Durchschnitt pro Sekunde |
| „Server-Fehler (5xx)“ | Anteil der 5xx-Antworten; gelb ab 1 %, rot ab 5 %; Tooltip mit der absoluten Zahl |
| „Client-Fehler (4xx)“ | Anzahl der 4xx-Antworten |
| „Blockiert“ | von Sentinel blockierte Requests |
| „Antwortzeit p95“ | 95-%-Perzentil, dazu der Durchschnitt („Ø“) |
| „Datenvolumen“ | übertragene Bytes |
| „Aktive Sperren“ | derzeit gesperrte IPs und Netze, dazu „N IPs beobachtet“ (von der Bedrohungserkennung verfolgte Adressen); unabhängig vom Zeitraum |

5. **„Traffic“**: gestapeltes Diagramm der Antworten nach 2xx, 3xx, 4xx und 5xx. Ein Klick auf einen Eintrag der Legende blendet die Reihe aus oder ein (gilt für alle Diagramme mit Legende).
6. **„Schutzmaßnahmen“**: Balkendiagramm der blockierten Requests und darunter alle Sentinel-Eingriffe des Zeitraums nach Art mit Anzahl. In der Tabelle stehen auch Aktionen, nach denen der Request ausgeliefert wurde (z. B. „WAF erkannt“, „Angemeldet“, „Weitergeleitet“, „Test: …“); welche Aktionen blockieren, zeigt Anhang A.
7. **„Antwortzeit“**: Durchschnitt und p95 über die Zeit.
8. **„Latenzverteilung“**: Histogramm der Antwortzeiten (Obergrenzen in Millisekunden, letzte Säule „mehr“) mit p50, p95, p99 und Maximum.
9. **„Sites“**: die zehn Hosts mit den meisten Requests, mit „Fehler“, „Blockiert“ und „Ø Zeit“. Ein Klick öffnet die Analysen für diesen Host; „Alle Sites“ führt zur Seite „Sites“.
10. **„Neueste Sicherheitsereignisse“**: die zwölf neuesten Ereignisse der Arten WAF, Honeypot, Sperre, Alarm, Ratelimit und Agent, unabhängig vom Zeitraum. Ein Klick öffnet das Ereignis (siehe Kapitel 4.7.2).
11. **„Meistgetroffene WAF-Regeln“**: die acht häufigsten WAF-Regeln mit „Treffer“ und davon „Blockiert“. Die Sammelregeln der Anomalie-Auswertung des OWASP-CRS werden nicht mitgezählt, weil sie für sich nichts aussagen.
12. **„Caddy-Prozess“**: „Laufzeit“, „Speicher (RSS)“, „Goroutinen“, „CPU-Zeit“, „Letzter Reload“ (mit „erfolgreich“ oder „fehlgeschlagen“) und „Upstreams“ mit grünem oder rotem Punkt je Backend. Die Werte stammen aus den Metriken von Caddy.

**Tipp:** Erscheint bei „Upstreams“ „keine Health-Checks konfiguriert“ oder „Prozess-Metriken nicht verfügbar“, aktiviere in Caddy die globale Option `metrics` und gegebenenfalls Health-Checks für `reverse_proxy`.

### 4.3 Live-Traffic

*Live-Traffic* (`#/live`) zeigt den Verkehr in Echtzeit.

#### Diagramm

„Requests pro Sekunde (letzte 5 Minuten)“ zeigt „Requests/s“, „5xx/s“ und „Blockiert/s“ und wird sekündlich fortgeschrieben.

#### Request-Stream

Beim Öffnen lädt die Seite die letzten 150 Requests der vergangenen 15 Minuten; danach erscheinen neue Requests oben und werden kurz hervorgehoben.

| Bedienelement | Wirkung |
|---|---|
| „Alle“ / „Sicherheitsrelevant“ / „Blockiert“ / „Fehler“ | alle Requests / Requests mit irgendeinem Sentinel-Eingriff / nur blockierte / nur Status ab 400 |
| Host („Alle Hosts“) | Hosts, die bisher im Stream aufgetaucht sind |
| Status („Alle Status“) | 2xx, 3xx, 4xx, 5xx oder einzelne Codes 401, 403, 404, 429, 502, 503 |
| Aktion („Alle Aktionen“) | eine Aktion aus Anhang A; Entscheidungen derselben Regel im Testmodus („Test: …“) werden mit angezeigt |
| „IP / Präfix“ | Adressen, die mit der Eingabe beginnen, z. B. `203.0.113.` |
| „Volltext: Pfad, User-Agent, Benutzer …“ | sucht in Host, Pfad, Query, IP, Benutzer, User-Agent, Status und Methode |
| „Anhalten“ / „Fortsetzen“ | hält die Anzeige an |
| Zähler „x von y Requests im Puffer“ | Treffer der Filter im Verhältnis zum Puffer |

Die Tabelle zeigt „Zeit“, „Status“, „Methode“, „Host“, „Pfad“, „Client“ (Landesflagge und IP; Tooltip mit Land und Netz), „Dauer“ und „Aktion“. Bei WAF-Treffern steht „Score n“ (Anomalie-Wert der WAF) daneben, bei blockierten Requests eine Kurzbegründung. Blockierte Zeilen sind rot hinterlegt. Ein Klick auf eine Zeile öffnet die Request-Details mit Diagnose (siehe Kapitel 4.5).

Filter und Modus stehen in der Adresse und lassen sich als Ansicht speichern (siehe Kapitel 3.9).

Grenzen und Verhalten:

- Der Puffer fasst 2000 Requests, angezeigt werden höchstens 250 passende.
- Solange der Mauszeiger über der Tabelle steht, hält der Stream an, damit Zeilen nicht wegrutschen. Neue Requests werden gesammelt und mit dem nächsten Schwung nachgereicht.
- Bei mehreren Instanzen zeigt der Stream nur Requests der gewählten Instanz.

**Hinweis:** Mit „Anhalten“ eintreffende Requests werden verworfen und nach „Fortsetzen“ nicht nachgeholt. Für einen Rückblick nutze die Analysen.

**Hinweis:** Bei einer Stichprobe unter 100 % zeigt der Stream vom normalen Verkehr nur die Stichprobe (siehe Kapitel 4.1).

### 4.4 Analysen

*Analysen* (`#/analytics`) ist das Werkzeug für Rückblicke: Filtern, Aufschlüsseln, einzelne Requests finden und exportieren. Die Seite folgt Zeitraum und Instanz.

#### Filter

Alle Filter wirken sofort und stehen in der Adresse.

| Feld | Wirkung |
|---|---|
| Host („Alle Hosts“) | Hosts mit Traffic in den letzten 30 Tagen |
| Policy („Alle Policies“) | nur Requests, für die diese Policy galt |
| Status („Alle Status“) | „2xx Erfolg“, „3xx Umleitung“, „4xx Client-Fehler“, „5xx Server-Fehler“ oder 404, 403, 429, 500, 502 |
| Methode („Alle Methoden“) | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS |
| Aktion („Alle Aktionen“) | „Ohne Eingriff“, „Mit Eingriff“ (beliebige Aktion), „Blockiert“ (nur blockierende Aktionen) oder eine einzelne Aktion aus Anhang A. Testmodus-Entscheidungen („Test: …“) sind hier nicht wählbar; sie zeigt der Live-Traffic mit dem Aktionsfilter. |
| „Land (DE)“ | Ländercode aus zwei Buchstaben; `-` für unbekannt |
| „ASN“ | Nummer des Netzes, mit oder ohne „AS“ |
| „Pfad enthält …“ | Teil des Pfads |
| „IP (Präfix mit *)“ | genaue Adresse; mit `*` am Ende alle Adressen mit diesem Anfang, z. B. `198.51.100.*` |
| „User-Agent …“ | Teil des User-Agents |
| „Volltext …“ | sucht in Pfad, Query, User-Agent, Detail, IP, Benutzer, Begründung und Fehlerseiten-Referenz |
| „Zurücksetzen“ | leert alle Filter |

Darunter steht die Leiste „Ansichten:“ (siehe Kapitel 3.9).

#### Kennzahlen und Diagramm

Die Kacheln „Requests“, „Fehlerquote“ (4xx und 5xx), „Blockiert“, „Ø Antwortzeit“ (mit p95) und „Datenvolumen“ sowie das Diagramm („Requests“, „Fehler (4xx/5xx)“, „Blockiert“) beruhen auf der Minuten-Statistik. Sie berücksichtigen deshalb nur die Filter Host und Policy. Ist ein weiterer Filter gesetzt, erscheint die Kachel „Gefiltert – Rohdaten“ als Hinweis, dass das Diagramm alle Requests des Hosts zeigt, Top-Listen und Explorer aber gefiltert sind.

#### Top-Listen

Zehn Listen mit je zwölf Einträgen: „Pfade“, „Clients“, „User-Agents“, „Statuscodes“, „Länder“, „Netze (ASN)“, „Referer“, „Methoden“, „Sentinel-Aktionen“ und „Hosts“, jeweils mit „Requests“, „Fehler“, „Blockiert“ und „Ø Zeit“. Sie berücksichtigen alle Filter.

Ein Klick auf einen Eintrag setzt ihn als Filter, so dass du schrittweise eingrenzen kannst. Ausnahmen: Ein Klick auf einen Client öffnet die Seite „IP-Details“, Referer sind nicht anklickbar.

#### Request-Explorer

Der „Request-Explorer“ listet die passenden Einzel-Requests, neueste zuerst, in Schritten von 100 („Weitere laden“). Ein Klick auf eine Zeile öffnet die Request-Details (siehe Kapitel 4.5).

„Als CSV exportieren“ speichert die geladenen Zeilen als Datei `sentinel-requests-<Zeitstempel>.csv` (Semikolon als Trenner, UTF-8, direkt in Excel lesbar) mit den Spalten zeit, host, methode, pfad, query, status, ip, land, asn, dauer_ms, bytes, aktion, policy und user_agent.

**Achtung:** Der Export enthält nur die Zeilen, die im Explorer geladen sind. Klicke vorher so oft auf „Weitere laden“, bis alle gewünschten Requests angezeigt werden.

#### Typische Abfragen

| Frage | Einstellung |
|---|---|
| Was hat Sentinel auf dem Wiki in der letzten Stunde blockiert? | Zeitraum „1 Std.“, Host wählen, Aktion „Blockiert“ |
| Welche Pfade liefern Serverfehler? | Status „5xx Server-Fehler“, Liste „Pfade“ |
| Was hat eine bestimmte Adresse aufgerufen? | „IP (Präfix mit *)“ mit der Adresse oder IP-Steckbrief, Schaltfläche „Anfragen“ |

### 4.5 Request-Details und Diagnose

Ein Klick auf einen Request in Live-Traffic, Analysen, Fehleranalyse oder auf der Seite „IP-Details“ öffnet rechts die Request-Details mit dem Titel „<Methode> <Pfad>“.

#### Diagnose

Oben erstellt das Panel eine Diagnose: wer den Request gestoppt oder beantwortet hat, warum, mit welchen Belegen, wie es sich beheben lässt und ob es mit der heutigen Konfiguration noch genauso wäre.

- **Kopf**: Verursacher, Statuscode, Policy, Überschrift und Erklärung. Die Verursacher sind:

| Kennzeichen | Bedeutung |
|---|---|
| „Sentinel“ | von Sentinel entschieden (Policy, Pfad-Regel, Sperre, WAF …) |
| „Caddy“ | von Caddy selbst beantwortet (keine Route, Datei fehlt, Backend nicht erreichbar) |
| „Backend“ | vom Backend hinter Caddy beantwortet |
| „Client“ | liegt am Client (Anmeldung, API-Schlüssel, zu viele Anfragen) |

- **Weg der Anfrage**: die Prüfstufen in Sentinels Reihenfolge – „Sperren“, „Pfad-Regeln“, „Wartung“ (nur wenn sie zuständig war), „IP-Regeln“, „Geo & Feeds“, „Filter“, „Bots“, „Ratelimits“, „Bot-Challenge“, „Anmeldung“, „WAF“, „Caddy & Ziel“. ✓ heißt durchlaufen, ✕ gestoppt, ! Warnung (z. B. Challenge, Login oder Testmodus); Stufen ohne Zeichen wurden nicht mehr erreicht.
- **Fakten**: z. B. „Grund der Sperre“, „Sperre aktiv“, „Policy“, „Pfad-Regel“, „Angemeldet als“, „Referenz“, ausgelöste WAF-Regeln, „Site“, „Caddy-Route“, „Ziel“ und der Zustand der Backends.
- **„So lässt es sich beheben“** (bei erfolgreichen Requests „Falls das nicht gewollt ist“): Links zur zuständigen Einstellung, bei Sperren die Schaltfläche „Sperre aufheben“ (Support, Bearbeiter, Administrator), bei WAF-Blockaden der „Fehlalarm-Assistent“ (siehe Kapitel 5).
- **„Mit der aktuellen Konfiguration: …“**: Das Panel spielt den Request gegen die heutige Konfiguration durch.

| Ergebnis | Bedeutung |
|---|---|
| „Inzwischen behoben“ | würde jetzt durchgelassen |
| „Tritt weiterhin auf“ | würde an derselben Stelle scheitern |
| „Scheitert jetzt woanders“ | würde an einer anderen Stufe scheitern |
| „Würde jetzt blockiert“ | wurde durchgelassen, würde jetzt aber aufgehalten |
| „Aktuell unverändert“ | wurde und würde durchgelassen |
| „Nicht sicher vorhersagbar“ | hängt vom Verkehr ab (Ratelimits) |
| „Sentinel lässt weiterhin durch“ | der Fehler kam von Caddy oder dem Backend; Sentinel lässt den Request durch |

„Im Simulator öffnen“ übernimmt den Request in den Request-Fluss (siehe Kapitel 4.9); „Alle Prüfschritte der Simulation“ klappt die Einzelschritte auf.

**Hinweis:** Die Simulation prüft die WAF nur mit URL und User-Agent, weil Body und weitere Header nicht gespeichert werden. Ratelimits werden nicht mitgezählt, Fehler des Backends lassen sich nicht nachstellen. Die Zuordnung zu Site und Route gelingt nur, wenn Host und Port eindeutig sind.

Requests aus dem **Testmodus** tragen die Überschrift „Testmodus: …“ mit der Erklärung, dass die Regel nur protokolliert hat. Erster Lösungsvorschlag ist dann „Testmodus auswerten und scharf schalten“.

#### Request-Daten

Darunter stehen „Zeit“, „Caddy-Instanz“ (bei mehreren), „Host“, „URL“, „Status“, „Client“ (mit Land), „Netz“, „Benutzer“ (Site-Login), „User-Agent“, „Referer“, „Protokoll“, „Antwort“ (Größe und Dauer), „Policy“, „Aktion“, „Begründung“ (der konkrete Beleg, z. B. der passende Listeneintrag oder das Limit), „Referenz“ (siehe Kapitel 4.6) und „Anomalie-Score“. Bei WAF-Treffern folgt eine Tabelle „WAF-Treffer“ mit Regel, Meldung und den beanstandeten Daten.

Schaltflächen:

- „Im WAF-Tester öffnen“ übernimmt Methode, URL, User-Agent und Policy in den WAF-Tester (siehe Kapitel 5).
- „Als curl kopieren“ legt einen curl-Befehl mit Methode, User-Agent und URL in die Zwischenablage. Body und weitere Header sind nicht enthalten.

### 4.6 Fehleranalyse

*Fehleranalyse* (`#/failures`) beantwortet die Frage „Warum scheitern Anfragen?“. Fehlgeschlagen ist ein Request mit Status ab 400 oder mit einer blockierenden Sentinel-Aktion. Entscheidungen im Testmodus zählen nicht, weil der Request durchgelassen wurde.

#### Anfrage per Referenz finden

Blockiert Sentinel einen Besucher, zeigt die Fehlerseite unten „Referenz XXXX-XXXX“ mit Zeitpunkt und dem Satz „Wenn du glaubst, dass das ein Fehler ist, nenne dem Administrator diese Referenz.“ Die Referenz steht außerdem im Antwort-Header `X-Sentinel-Ref`.

1. Trage die Referenz in das Feld „Referenz von der Fehlerseite, z. B. K7QM-3XPA“ ein. Groß- und Kleinschreibung, Leerzeichen und ein fehlender Bindestrich spielen keine Rolle.
2. Klicke auf „Suchen“ oder drücke Enter.
3. Die Anfrage erscheint als Tabelle, ihre Details mit Diagnose öffnen sich sofort.

Die Suche durchsucht alle gespeicherten Requests unabhängig vom Zeitraum. Schneller geht es über die globale Suche (Strg+K) oder einen Link der Form `#/failures?ref=K7QM-3XPA`.

**Hinweis:** Gesucht wird in der gewählten Caddy-Instanz. Findet sich eine Referenz nicht, stelle die Instanz-Auswahl auf „Alle Caddy-Instanzen“. Nach Ablauf der Aufbewahrungsfrist (siehe Kapitel 4.1) ist der Request gelöscht.

#### Filter und Kennzahlen

Über der Liste wählst du den Host („Alle Hosts“) und den Verursacher („Alle“, „Sentinel“, „Caddy“, „Backend“, „Client“). Daneben steht die Leiste „Ansichten:“. Die Kacheln zeigen „Fehlgeschlagen“ insgesamt und den Anteil „durch Sentinel“, „durch Caddy“, „durch Backend“ und „durch Client“.

#### Verlauf und Änderungen

Das Diagramm zeigt „Blockiert (Sentinel)“, „Client-Fehler 4xx“ (ohne die von Sentinel blockierten) und „Server-Fehler 5xx“. Die Markierungen ◆ stehen für Änderungen an Policies, Regelsätzen, WAF-Ausnahmen, Feeds, Einstellungen, Instanzen und angewendeten Konfigurationen sowie Wiederherstellungen. Beim Überfahren erscheinen sie im Tooltip, ein Klick auf eine Markierung öffnet die Änderung. Darunter lässt sich die Liste „N Änderungen im Zeitraum“ aufklappen.

**Tipp:** Steigen die Fehler direkt nach einer Markierung an, ist die Änderung der wahrscheinlichste Auslöser.

#### Ursachen

Die Liste „Ursachen“ fasst gleichartige Fehler zusammen (bis zu 200 Gruppen): Sentinel-Entscheidungen nach Host, Policy, Aktion, Detail und Regel, alle übrigen Fehler nach Host und Status. Jede Zeile zeigt:

- eine Überschrift wie „Von der Web Application Firewall blockiert“ oder „Backend nicht erreichbar (502)“,
- den Verursacher, die Prüfstufe („an: WAF“), Host (mit Port, wenn er nicht 80 oder 443 ist), Policy und einen Beispielpfad („(+n weitere Pfade)“),
- bei Bedarf einen Lösungsvorschlag mit Link („→ …“),
- rechts die Anzahl, die Zahl der Clients und „zuletzt vor …“.

Ein Klick auf eine Gruppe öffnet rechts:

- Anzahl Anfragen, Clients und Pfade sowie den Zeitraum vom ersten bis zum letzten Auftreten,
- bei WAF-Blockaden die Schaltfläche „Fehlalarm-Assistent“ (siehe Kapitel 5),
- „Diagnose (letzte Anfrage dieser Gruppe)“ wie in Kapitel 4.5,
- „Beispiele“ mit bis zu 50 Requests und „Alle in den Analysen öffnen“.

#### Typischer Ablauf bei einer Störungsmeldung

1. Lass dir die Referenz von der Fehlerseite nennen und suche sie (Strg+K).
2. Lies Überschrift und Verursacher der Diagnose. Liegt es an Caddy oder dem Backend, prüfe Route und Backend (siehe Kapitel 8).
3. Liegt es an Sentinel, folge dem Lösungsvorschlag, z. B. Sperre aufheben, Pfad-Regel anpassen oder WAF-Ausnahme über den Fehlalarm-Assistenten.
4. Öffne die Request-Details erneut: „Mit der aktuellen Konfiguration“ sollte nun „Inzwischen behoben“ zeigen.

### 4.7 Sicherheit

*Sicherheit* (`#/security`) hat fünf Reiter: „Lage“, „Ereignisse“, „Sperren & Freigaben“, „Bedrohungs-Scores“ und „Audit-Log“. Der Reiter steht in der Adresse (`?tab=events`, `bans`, `scores`, `audit`).

#### 4.7.1 Lage

Der Reiter folgt dem Zeitraum. Läuft die Bedrohungserkennung im Testmodus oder ist sie ausgeschaltet, steht oben ein entsprechender Hinweis (siehe Kapitel 6).

| Kachel | Inhalt |
|---|---|
| „Aktive Sperren“ | derzeit gesperrte IPs und Netze |
| „Blockierte Requests“ | alle blockierten Requests im Zeitraum |
| „WAF blockiert“ / „WAF erkannt“ | Aktionen „WAF blockiert“ bzw. „WAF erkannt“ |
| „Honeypot“ | Aufrufe von Honeypot-Pfaden |
| „Ratelimit“ | „Ratelimit“ und „Ratelimit-Bann“ zusammen |
| „Geo & Feeds“ | „Geo-Sperre“ und „Threat-Feed“ zusammen |
| „Bot-Challenges“ | angezeigte Challenges, dazu „n gelöst“ |
| „Beobachtete IPs“ | Adressen, die die Bedrohungserkennung gerade verfolgt |

Darunter:

- „Blockierte Requests“ über die Zeit und „Eingriffe nach Art“ (alle Aktionen mit Anzahl).
- „Auffälligste Clients“: die zwölf IPs mit dem höchsten Bedrohungs-Score (Aufbau wie in Kapitel 4.7.4); „Alle“ öffnet den Reiter „Bedrohungs-Scores“.
- „Häufigste WAF-Regeln“ mit dem Link „ausnehmen“, der zu den Policies führt, um eine Regel bei Fehlalarmen auszunehmen (siehe Kapitel 5).
- „Angegriffene Pfade“ und „Angreifende IPs“: die zehn Pfade und Adressen mit den meisten blockierten Anfragen. Ein Klick auf einen Pfad öffnet die Analysen mit diesem Pfad und „Blockiert“, ein Klick auf eine IP die Seite „IP-Details“.

#### 4.7.2 Ereignisse

Der Reiter listet alle Ereignisse, neueste zuerst, unabhängig vom Zeitraum, je 100 Einträge („Ältere laden“). Neue Ereignisse erscheinen sofort.

Filter:

- Art: „Alle Arten“, „WAF“, „Honeypot“, „Sperren“ (Sperren und Aufhebungen), „Alarme“, „Ratelimit“, „User-Agent“, „Konfiguration“, „Agent“,
- Schwere: „Alle“, „ab Mittel“, „ab Hoch“,
- „Suche in Ereignissen …“.

Die Spalten sind „Zeit“, „Art“ (mit Schwere), „Ereignis“ und „Quelle“ (Instanz, IP, Host). Die Schwere hat fünf Stufen: „Info“, „Niedrig“, „Mittel“, „Hoch“, „Kritisch“.

Ein Klick öffnet das Ereignis mit „Zeit“, „Art“, „Schwere“, „IP“, „Host“, „Policy“, bei WAF-Ereignissen einer Tabelle der ausgelösten Regeln (die blockierenden mit „blockiert“) und den vollständigen Rohdaten.

Woher die Ereignisse stammen:

| Art | Ereignis | Schwere |
|---|---|---|
| WAF | „WAF blockiert: …“ | Mittel |
| WAF | „WAF-Treffer (Score n): …“ – nur bei einem Anomalie-Wert ab 5 | Niedrig |
| Honeypot | „Honeypot ausgelöst: …“ | Mittel |
| Ratelimit | „Ratelimit-Sperre: …“ | Mittel |
| User-Agent | „Gesperrter User-Agent“ | Niedrig |
| Sperre | „IP … gesperrt (Dauer): Grund“ | Hoch |
| Entsperrt | „Sperre aufgehoben: … (Benutzer)“ | Info |
| Alarm | „Fehlerrate …: x % 5xx in 5 Min.“ | Hoch |
| Alarm | „Traffic-Spitze …: n Req/Min (Ø m)“ | Mittel |
| Alarm | „Angriffswelle auf …: n blockierte Requests/Min“ | Kritisch |
| Alarm | „Anstieg: <Ursache> auf <Host> – n in 10 Min.“, gegebenenfalls mit „kurz nach: <Änderung>“ | Mittel, bei 5xx Hoch |
| Alarm | „Caddy-Agent … meldet sich nicht mehr“ | Kritisch |
| Alarm | „… ist nicht erreichbar“ / „… ist wieder erreichbar“ (Monitore) | Kritisch / Niedrig |
| Konfiguration | befristete Einträge, abgelaufene Pfad-Regeln und WAF-Ausnahmen, beendete Wartung und andere Änderungen | Info bis Niedrig |
| Agent | „Agent … meldet Policy-Fehler“ | Hoch |

Ereignisse aus Requests (WAF, Honeypot, Ratelimit, User-Agent) werden gedrosselt: höchstens eines je Art, IP und Host alle 20 Sekunden. Die Zahl der unterdrückten steht in den Rohdaten als `suppressed`. Jeder Alarm erscheint höchstens alle 30 Minuten, der Ursachen-Anstieg höchstens einmal pro Stunde und Ursache. Die Schwellen der Alarme stellst du unter *Einstellungen › Benachrichtigungen* ein (siehe Kapitel 11).

#### 4.7.3 Sperren & Freigaben

**„Aktive Sperren (N)“** listet alle gesperrten IPs und Netze mit „IP / Netz“, „Grund“ (mit Notiz und Autor), „Quelle“ („IDS“ oder „manuell“), „Seit“, „Dauer“ („noch …“ oder „dauerhaft“) und „Sperren gesamt“ (wie oft die Adresse schon gesperrt war). Gesperrte Adressen erhalten auf allen Sites mit Sentinel und auf allen Instanzen sofort 403.

Diese Aktionen stehen den Rollen Support, Bearbeiter und Administrator offen; Leser erhalten eine Fehlermeldung.

IP oder Netz sperren:

1. Klicke auf „IP sperren“.
2. Trage unter „IP oder CIDR“ die Adresse oder das Netz ein.
3. Wähle die „Dauer“: „1 Stunde“, „1 Tag“ (Standard), „7 Tage“, „30 Tage“ oder „dauerhaft“.
4. Gib einen „Grund“ an (leer: „manuell“; dein Benutzername wird angehängt) und optional eine „Notiz“, z. B. eine Ticketnummer.
5. Klicke auf „Sperren“.

Sperre aufheben: „Aufheben“ in der Zeile und Bestätigung. Die Adresse ist sofort wieder zugelassen, ihr Bedrohungs-Score und eine eventuelle Challenge-Pflicht werden zurückgesetzt. Auch eine lokale Sperre aus einem Ratelimit mit „429 + IP sperren“ hebt der Agent dann auf.

Notiz ergänzen: „+ Notiz“ bzw. „ändern“ in der Spalte „Grund“.

**„Befristete Freigaben und Sperren“** listet Einträge mit Enddatum. Sie laufen von selbst ab; Sentinel vermerkt das im Ereignisprotokoll.

| Liste | Gilt für | Wirkung | Wer darf eintragen |
|---|---|---|---|
| „Vertrauenswürdig“ | alle Sites (global) | alle Prüfungen werden übersprungen, auch Sperren | Administrator |
| „Nie sperren“ | alle Sites (global) | die Bedrohungserkennung sperrt die Adresse nicht automatisch | Support, Bearbeiter, Administrator |
| „Erlaubt-Liste“ | eine Policy | zählt im Modus „Nur Freigabeliste“ als freigegeben | Bearbeiter, Administrator |
| „Sperrliste“ | eine Policy | wird für diese Policy blockiert | Bearbeiter, Administrator |

Befristeten Eintrag anlegen:

1. Klicke auf „Befristet eintragen …“.
2. Trage unter „IP oder Netz“ die Adresse ein.
3. Wähle unter „Gilt für“ „alle Sites (global)“ oder eine Policy und dann die „Liste“. Es werden nur die Listen angeboten, die deine Rolle eintragen darf.
4. Lege unter „Endet“ das Ende fest: per Schnellwahl („1 Std.“, „Heute 18 Uhr“, „1 Tag“, „Freitag 18 Uhr“, „1 Woche“, „30 Tage“) oder mit Datum und Uhrzeit. Das Ende darf höchstens ein Jahr in der Zukunft liegen.
5. Begründe den Eintrag unter „Notiz (warum?)“, z. B. „Pentest der Firma X, Ticket #4711“.
6. Klicke auf „Eintragen“.

„Beenden“ entfernt einen Eintrag vorzeitig (globale Einträge: Support, Bearbeiter, Administrator; Policy-Einträge: Bearbeiter, Administrator).

**Tipp:** Für Pentests, Partnerzugänge oder Tests nach einer Änderung sind befristete Einträge sicherer als dauerhafte Listen, weil nichts aus Versehen offen bleibt. Dauerhafte Listen pflegst du in den Policies (siehe Kapitel 5) und unter *Einstellungen › Netz & Vertrauen*.

#### 4.7.4 Bedrohungs-Scores

Der Reiter zeigt bis zu 200 IP-Adressen mit einem Score ab 1. Der Text darüber nennt die aktuelle Halbwertszeit und die Sperrschwelle („Jedes verdächtige Signal erhöht den Score einer IP; er halbiert sich alle N Minuten. Ab M Punkten sperrt das IDS die IP automatisch.“).

Die Spalten sind „IP“, „Score“ (mit Balken im Verhältnis zur Sperrschwelle; rot ab 70 % der Schwelle), „Signale“ (die drei stärksten), „Requests“ und „Zuletzt“. Ein Klick öffnet die Seite „IP-Details“.

Die Signale heißen „WAF-Blocks“, „WAF-Treffer“, „Honeypot“, „404-Scans“, „Auth-Fehler“, „Fehlerhafte Requests“, „Scanner-Tool“, „Ratelimit“, „Gesperrter UA“, „Unerlaubte Methode“, „IP-Sperrliste“, „Request-Burst“, „Body zu groß“, „Geo-Sperre“, „Threat-Feed“, „Bot-Challenge“, „Pfad-Sperre“, „Falscher Suchmaschinen-Bot“ und „Crawler“. Gewichte, Schwellen und Sperrdauer beschreibt Kapitel 6.

**Hinweis:** Die Scores werden im Arbeitsspeicher des Panels geführt. Nach einem Neustart des Panels beginnen sie bei null; aktive Sperren bleiben erhalten.

#### 4.7.5 Audit-Log

Das „Audit-Log“ zeigt, wer wann was geändert hat, einschließlich An- und Abmeldungen und fehlgeschlagener Anmeldeversuche am Panel. Spalten: „Zeit“, „Aktion“ (sicherheitsrelevante Vorgänge mit „Warnung“), „Benutzer“, „IP“. Angezeigt werden die letzten 300 Einträge, unabhängig vom Zeitraum. Ältere Einträge findest du im Reiter „Ereignisse“ mit der Suche; aufbewahrt werden sie wie alle Ereignisse (Standard 90 Tage).

### 4.8 IP-Steckbrief und IP-Details

Zu jeder IP-Adresse gibt es zwei Darstellungen: den kompakten **IP-Steckbrief** als Seitenleiste und die Seite **„IP-Details“** (`#/ip/<Adresse>`).

Ein normaler Klick auf eine IP-Adresse in Request-Details, Ereignissen, Sperrlisten oder befristeten Einträgen öffnet den Steckbrief. Mit Strg-, ⌘- oder Umschalt-Klick, über „Ganze Seite“ im Steckbrief, über die Suche sowie aus Top-Listen und Score-Tabellen gelangst du direkt zur Seite „IP-Details“.

#### IP-Steckbrief

Der Steckbrief zeigt:

- Land, Netz (AS-Nummer und Betreiber), Reverse-DNS-Namen, „privat/lokal“ und Threat-Feeds, in denen die Adresse steht,
- eine aktive Sperre mit Restdauer, Grund und Notiz, befristete Einträge und dauerhafte Listen („Steht in: …“),
- „Bedrohungs-Score“ (mit „muss Challenge lösen“, falls zutreffend), „Anfragen“ („gespeichert · blockiert · Fehler“), „Gesehen“ (erstes und letztes Auftreten), „Caddy-Instanzen“, „Sperren bisher“, „Eingriffe“, „Hosts“, „Anmeldungen“,
- „Letzte Anfragen“ (die acht neuesten).

Schaltflächen:

| Schaltfläche | Wirkung | Rolle |
|---|---|---|
| „1 h sperren“ / „24 h sperren“ | sperrt sofort ohne Rückfrage, Grund „aus dem Steckbrief“ | Support, Bearbeiter, Administrator |
| „Sperre aufheben“ | hebt eine bestehende Sperre nach Rückfrage auf | Support, Bearbeiter, Administrator |
| „Dulden …“ | befristeter Eintrag; Administratoren ist „Vertrauenswürdig“ vorausgewählt, Support und Bearbeitern „Nie sperren“ | Support, Bearbeiter, Administrator |
| „Anfragen“ | Analysen, gefiltert auf diese Adresse | alle |
| „Simulieren“ | Request-Fluss mit dieser Client-IP (siehe Kapitel 4.9) | alle |
| „Kopieren“ | Adresse in die Zwischenablage | alle |
| „Ganze Seite“ | Seite „IP-Details“ | alle |

#### Seite „IP-Details“

Die Seite zeigt alle gespeicherten Daten der Adresse, unabhängig vom eingestellten Zeitraum.

Schaltflächen in der Kopfleiste: „IP kopieren“, „AbuseIPDB“ und „ipinfo“ (externe Auskunftsdienste in neuem Tab), „Befristet …“ (wie „Dulden …“, zusätzlich mit Policy-Listen), „Simulieren“ sowie „Sperren“ bzw. „Sperre aufheben“. Sperren, Aufheben und befristete Einträge sind wie oben den Rollen Support, Bearbeiter und Administrator vorbehalten.

Inhalt:

- Kennzeichen für Land, Netz (Klick: Analysen für dieses Netz), Threat-Feeds („in Liste: …“, Klick: Threat-Feeds) und „muss Bot-Challenge lösen (noch …)“.
- Hinweise zur Sperre (bei Sperre eines ganzen Netzes mit „(über Netz …)“), zu Reverse-DNS, zu dauerhaften Listen („Steht in: …“ – z. B. „Vertrauenswürdig (global)“, „IDS: nie sperren“, „Erlaubt-Liste von „…““, „Sperrliste von „…““, „ohne Anmeldung auf „…““, „trotz Wartung erlaubt auf „…““, „Pfad-Regel „…“ in „…““) und zu den Instanzen, auf denen die Adresse gesehen wurde.
- Bei privaten oder lokalen Adressen: „Private oder lokale Adresse. Steht Caddy hinter einem Proxy, prüfe `trusted_proxies` – sonst sehen alle Clients wie der Proxy aus.“
- Panel „Befristete Einträge“ (falls vorhanden).
- Kennzahlen „Bedrohungs-Score“, „Requests (gespeichert)“, „Fehler“, „Blockiert“, „Erstmals gesehen“, „Zuletzt gesehen“, „Sperren bisher“ (Sperren der letzten zwölf Monate).
- Panels „Signale“ (Punkte und Anzahl je Signal), „Aufgerufene Hosts“, „Sentinel-Aktionen“, „Pfade“, „User-Agents“, „Site-Anmeldungen von dieser IP“ (Konto, Ergebnis, Site, Details), „Ereignisse“ und „Letzte Requests“ (jeweils bis zu 100).

**Achtung:** Ist die Adresse über eine Netz-Sperre gesperrt, hebt „Sperre aufheben“ die Sperre des ganzen Netzes auf.

**Tipp:** Erscheinen viele Clients mit derselben privaten Adresse, steht ein Proxy oder Load Balancer vor Caddy, dessen Netz in Caddy nicht unter `trusted_proxies` eingetragen ist. Ohne diese Einstellung würde Sentinel den Proxy sperren.

### 4.9 Request-Fluss (Ablauf und Simulator)

*Request-Fluss* (`#/flow`) zeigt für jede Site, welche Stationen ein Request durchläuft, und simuliert einzelne Requests. Die Seite betrifft immer eine Caddy-Instanz (Leiste „Caddy-Instanz“, siehe Kapitel 3.5) und liest die laufende Caddy-Konfiguration. „Aktualisieren“ in der Kopfleiste liest sie neu ein. Ansehen und Simulieren dürfen alle Rollen.

#### Matrix „Alle Sites“

Die Tabelle zeigt je Site, welche Schutzfunktionen aktiv sind. Ein Klick auf eine Zeile wählt die Site für den Graphen.

| Spalte | Werte |
|---|---|
| „Site“ | Name und Adressen, auf denen Caddy lauscht |
| „Sentinel / Policy“ | „aktiv“, „teilweise“ (nur ein Teil der Routen geschützt) oder „ohne“; dazu die Policy |
| „TLS“ | „auto“, „intern“, „eigen“ oder „aus“ |
| „Regeln“ | Anzahl aktiver Pfad-Regeln |
| „Wartung“ | ● (rot) bei aktivem Wartungsmodus |
| „IP“, „Geo/Feeds“, „Filter“, „Bots“, „Limits“, „Challenge“ | ● aktiv, – aus |
| „Anmeldung“ | „AD“ oder „AD+2FA“ |
| „WAF“ | „block“, „erkennt“ oder „aus“ |
| „Ziele“ | Backends bzw. Ziele der Routen |

Der Tooltip einer Zelle zeigt die Zusammenfassung der Stufe und ihre Einträge.

#### Graph einer Site

Über „Site“ wählst du die Site, mit „↔ waagerecht“ bzw. „↕ senkrecht“ die Ausrichtung (auf schmalen Bildschirmen automatisch senkrecht; die Wahl bleibt im Browser gespeichert). Der Graph hat die Spalten:

1. „Client“,
2. „Eingang“: Ports, TLS-Art, Restlaufzeit des Zertifikats und die Hostnamen,
3. „Sentinel“: Policy (Link) und die Prüfstufen in dieser Reihenfolge: „Sperren & Vertrauen“, „Pfad-Regeln“ (mit Liste der Regeln, gegebenenfalls „(Zeitplan)“ oder „(bis …)“), „Wartung“, „IP-Regeln“, „Geo & Threat-Feeds“, „Filter“, „Bots & Crawler“, „Ratelimits“, „Bot-Challenge“, „Anmeldung“, „WAF“, „Sicherheits-Header“. Ist die Policy ausgeschaltet, steht hier „Policy aus – nur Messung – Sperren gelten weiter“.
4. „Caddy-Routen“: die Bedingungen der Routen (z. B. „Pfad /api/*“, „Methode …“, „Header …“, „Datei existiert“), Zwischenschritte als Kennzeichen und „ohne Sentinel“ für Routen, die Sentinel nicht durchlaufen,
5. „Ziele“: Reverse-Proxy mit Backends und Statuspunkt, PHP, Dateien, feste Antwort, Weiterleitung und andere.

Gestrichelte Linien laufen an Sentinel vorbei. Hinweise erscheinen, wenn auf der Site Sentinel gar nicht aktiv ist („Im Editor „Sentinel einfügen“ nutzen.“) oder nur einen Teil der Routen schützt.

#### Simulator

Der Simulator spielt einen gedachten Request in derselben Reihenfolge wie Sentinel durch. Änderungen an den Feldern starten die Simulation automatisch; „Simulieren“ startet sie von Hand.

| Feld | Bedeutung | Standard |
|---|---|---|
| „Methode“ | HTTP-Methode | GET |
| „Pfad“ | Pfad mit Query, z. B. `/admin/?x=1` | `/` |
| „Host“ | nur bei Sites mit mehreren Hostnamen; Platzhalter `*` wird zu `www` | erster Host |
| „Client-IP“ | Absenderadresse; Vorschläge für Internet, LAN, VPN, lokal | 203.0.113.10 |
| „Client“ | „Browser“, „Skript / API“, „KI-Crawler (GPTBot)“, „SEO-Crawler (AhrefsBot)“, „Googlebot“ – setzt User-Agent und Accept-Header | Browser |
| „Zeitpunkt“ | für Zeitpläne, Ablaufdaten und Wartungsfenster; leer = jetzt | leer |
| „Zugriffstoken“ | Site-Zugriffstoken (`sst_…`) | leer |
| „Angemeldet als“ | Site-Login-Benutzer | niemand |
| „Gruppen“ | Gruppen des Benutzers, durch Komma getrennt | leer |
| „Mit 2FA“ | „Code eingegeben“ | an |
| „API-Schlüssel“ | Wert für Pfad-Regeln mit API-Schlüssel | leer |
| „Bot-Challenge“ | „bereits gelöst“ | aus |
| „WAF“ | „Request wirklich prüfen“: führt die WAF-Prüfung von URL und User-Agent tatsächlich aus | aus |

Das **Ergebnis** zeigt Statuscode und Ausgang (z. B. „gesperrt (IPS)“, „durch Pfad-Regel gesperrt“, „Weiterleitung nach …“), die zuständige Pfad-Regel und alle Prüfschritte mit ✓ (ok), – (übersprungen), ✕ (blockiert), ⧗ (Challenge), 🔑 (Anmeldung), ↪ (Weiterleitung), i (Information) und ! (Warnung, z. B. Testmodus). Im Graphen wird der Weg hervorgehoben; endet der Request vorzeitig, erscheint die Spalte „Ergebnis“.

Die Simulation berücksichtigt vertrauenswürdige Adressen (alle Prüfungen übersprungen), aktive Sperren, befristete Einträge, Policies, die auf der Instanz nicht gelten (dann greift die Standard-Policy), ausgeschaltete Policies (nur Messung), Regeln im Testmodus sowie Zeitpläne und Ablaufdaten von Pfad-Regeln.

**Hinweis:** Ratelimits werden nur angezeigt, nicht gezählt. Caddy-Bedingungen wie „Datei existiert“ oder Ausdrücke lassen sich nicht auswerten; dann erscheint „… die gewählte Route ist eine Annahme.“

Der Simulator lässt sich vorbelegt öffnen: aus der Diagnose mit „Im Simulator öffnen“ (übernimmt den protokollierten Request) und aus dem IP-Steckbrief mit „Simulieren“ (übernimmt die IP). In diesen Fällen startet die Simulation sofort.

**Tipp:** Prüfe nach jeder Änderung an Pfad-Regeln oder IP-Listen mit dem Simulator, ob ein typischer Request aus dem LAN, aus dem Internet und mit einem Skript-Client das gewünschte Ergebnis liefert, bevor sich Benutzer melden.

### 4.10 Verfügbarkeit

*Verfügbarkeit* (`#/uptime`) überwacht Adressen mit regelmäßigen HTTP-Abrufen. Die Prüfungen führt der **Panel-Server** aus (nicht Caddy) mit einem GET-Request und dem User-Agent `caddy-sentinel-monitor/<Version>`; Weiterleitungen werden bis zu fünfmal verfolgt. Monitore gelten für das ganze Panel, nicht für eine einzelne Caddy-Instanz.

Monitore anlegen, ändern, löschen und testen dürfen Bearbeiter und Administratoren; die übrigen Rollen sehen die Seite nur.

#### Übersicht

Die Kacheln zeigen „Status“ („Alles erreichbar“ oder „N gestört“) und die Zahl der „Monitore“. Die Tabelle „Monitore“ enthält:

| Spalte | Inhalt |
|---|---|
| „Name“ | Name und URL |
| „Status“ | „erreichbar“, „gestört“, „pausiert“ oder „wartet“ (noch keine Prüfung seit dem Start des Panels), dazu „seit …“ und die letzte Fehlermeldung |
| „Letzte 90 Stunden“ | ein Balken je Stunde: grün ab 99,9 %, gelb ab 90 %, rot darunter, grau ohne Daten |
| „24 h“, „7 Tage“, „30 Tage“ | Verfügbarkeit in Prozent |
| „Antwortzeit“ | Verlauf der letzten 6 Stunden und Durchschnitt der letzten 24 Stunden |

Die Seite aktualisiert sich alle 20 Sekunden.

#### Monitore aus der Caddy-Konfiguration übernehmen

1. Klicke auf „Sites übernehmen“.
2. Der Dialog „Sites überwachen“ listet für jeden Hostnamen der laufenden Caddy-Konfiguration die Adresse `https://<host>/`. Platzhalter-Hosts, `localhost`, IP-Adressen und bereits überwachte Adressen fehlen.
3. Entferne die Haken bei Hosts, die nicht überwacht werden sollen.
4. Klicke auf „Überwachen“. Die Monitore werden mit 60 Sekunden Intervall und 10 Sekunden Timeout angelegt.

Grundlage ist die Konfiguration der gewählten Caddy-Instanz (bei „Alle“ die lokale).

#### Monitor anlegen oder bearbeiten

„Monitor hinzufügen“ bzw. „Bearbeiten“ öffnet den Dialog „Neuer Monitor“ bzw. „Monitor bearbeiten“.

| Feld | Bedeutung | Standard |
|---|---|---|
| „Name“ | Anzeigename | Hostname der URL |
| „URL“ | abzurufende Adresse, nur `http://` oder `https://` | – |
| „Intervall (s)“ | Abstand der Prüfungen, mindestens 15 Sekunden | 60 |
| „Timeout (s)“ | maximale Wartezeit, 1 bis 60 Sekunden | 10 |
| „Erwarteter Status“ | leer: jeder Status unter 400 gilt als erfolgreich; sonst ein Code (`200`), eine Klasse (`2xx`) oder mehrere durch Komma (`200,301`) | leer |
| „Muss enthalten“ | Text, der im Antworttext (erstes MiB) vorkommen muss | leer |
| „Zertifikat“ – „nicht prüfen“ | TLS-Zertifikat nicht prüfen (für interne Zertifikate) | aus |
| „Aktiv“ – „überwachen“ | Monitor eingeschaltet; ausgeschaltet erscheint er als „pausiert“ | an |

„Jetzt testen“ führt sofort eine Prüfung aus und zeigt „Erreichbar: Status … in … ms“ oder „Fehler: …“. „Löschen“ entfernt den Monitor samt Verlauf.

**Hinweis:** Das kürzeste Intervall ist 15 Sekunden; kleinere Werte setzt das Panel auf 15.

#### Wann ein Monitor als gestört gilt

- Eine Prüfung schlägt fehl bei Verbindungsfehler, Zeitüberschreitung, unerwartetem Status („unerwarteter Status …“) oder fehlendem Schlüsselwort („Schlüsselwort „…“ fehlt“).
- Der Monitor wechselt erst nach **zwei Fehlschlägen in Folge** auf „gestört“, damit einzelne Aussetzer keinen Alarm auslösen. Eine einzige erfolgreiche Prüfung meldet ihn wieder als „erreichbar“.
- Läuft das Zertifikat der Adresse in weniger als 7 Tagen ab, gilt die Prüfung als erfolgreich, zeigt aber den Hinweis „Zertifikat läuft in N Tagen ab“ in Gelb.

Beim Wechsel entstehen die Alarme „… ist nicht erreichbar: …“ (Kritisch) und „… ist wieder erreichbar (… ms)“, sofern die Benachrichtigung für Monitore unter *Einstellungen › Benachrichtigungen* eingeschaltet ist (Standard). Außerdem erscheint die Warnung „Nicht erreichbar: …“ in der Übersicht (siehe Kapitel 3.8). Der Verlauf wird 90 Tage aufbewahrt.

**Hinweis:** Der aktuelle Zustand der Monitore liegt im Arbeitsspeicher. Nach einem Neustart des Panels steht jeder Monitor bis zu seiner ersten Prüfung auf „wartet“.

**Tipp:** Überwache statt der Startseite eine Health-Check-Adresse des Backends (z. B. `/health`) und prüfe mit „Muss enthalten“ auf einen Text, der nur bei funktionierender Anwendung erscheint. So fällt auch eine Fehlerseite mit Status 200 auf.

---

## 5. Policies

Eine Policy legt fest, wie Sentinel die Anfragen an eine oder mehrere Sites schützt: IP-Regeln, Länder- und Netzregeln, Threat-Feeds, Filter, Bots, Ratelimits, Bot-Challenge, Anmeldung, Pfad-Regeln, WAF, Sicherheits-Header, Wartungsmodus und Anpassungen der Bedrohungserkennung. Das Caddy-Modul `sentinel` setzt die Policy bei jeder Anfrage durch. Nach dem Speichern meldet das Panel „… gespeichert – Caddy übernimmt die Änderung in Sekunden“.

Policies findest du unter *Konfiguration › Policies*. Ansehen dürfen alle Rollen; anlegen, ändern, löschen und als Standard festlegen dürfen nur Bearbeiter und Administratoren.

### 5.1 Überblick über die Policy-Seite

Links steht die Liste aller Policies. Jeder Eintrag zeigt den Namen und Kennzeichen:

- „Standard“ – die Standard-Policy (siehe 5.2),
- „aus“ – die Policy ist ausgeschaltet,
- „Wartung“ – der Wartungsmodus ist eingeschaltet,
- Instanz-Kennzeichen, wenn die Policy nur auf bestimmten Caddy-Instanzen gilt,
- darunter den WAF-Modus („WAF aus“, „WAF erkennt“, „WAF blockiert“) und die Hosts bzw. „alle übrigen Hosts“ (Standard-Policy) oder „keine Hosts“.

Mit „Neue Policy“ legst du eine Policy an; das Panel fragt nur den Namen ab.

Rechts stehen die Einstellungen der gewählten Policy in Tabs: „Allgemein“, „Zugriff“, „Ratelimits“, „Geo & Feeds“, „Bots“, „Bot-Challenge“, „Anmeldung“, „Pfad-Regeln“, „WAF“, „Header“, „IDS“. Ein „●“ am Tab zeigt, dass dort etwas Besonderes aktiv ist (Wartung, Bots, Anmeldung).

Die Aktionsleiste oben enthält:

| Knopf | Wirkung |
|---|---|
| „Auswirkung prüfen“ | Spielt die gespeicherten Anfragen der letzten 24 Stunden an diese Policy gegen den aktuellen Bearbeitungsstand nach (siehe 5.4). |
| „Testen“ | Öffnet den WAF-Tester mit dieser Policy (siehe 5.15). |
| „SecLang-Vorschau“ | Zeigt die erzeugte WAF-Konfiguration des gespeicherten Stands. |
| „Übertragen …“ | Übernimmt Bereiche dieser Policy in andere Policies (siehe 5.20). Nur sichtbar, wenn es mehr als eine Policy gibt. |
| „Als Standard“ | Macht diese Policy zur Standard-Policy. |
| „Löschen“ | Löscht die Policy (nicht bei der Standard-Policy). |
| „Speichern“ | Speichert die Änderungen. |

Ungespeicherte Änderungen meldet der Browser beim Verlassen der Seite.

#### Speichern und Prüfung beim Speichern

Beim Speichern prüft das Panel die Policy vollständig und lehnt sie mit einer Fehlermeldung ab, wenn etwas nicht stimmt, unter anderem:

- IP-Listen enthalten etwas anderes als eine IP-Adresse oder ein Netz in CIDR-Schreibweise,
- der Modus „Nur Freigabeliste zulassen“ ist gewählt, aber die Freigabeliste ist leer (das würde alle Besucher aussperren),
- ein Ratelimit hat einen ungültigen regulären Ausdruck,
- ein Ländercode hat nicht genau zwei Buchstaben (ISO 3166-1 alpha-2, z. B. DE),
- Geo-Regeln sind gesetzt, aber unter *Einstellungen › Netz & Vertrauen* ist keine GeoIP-Datenbank eingetragen,
- eine Feed-Regel verweist auf einen nicht vorhandenen Feed,
- eine Pfad-Regel ist fehlerhaft (Pfadmuster, Netze, Weiterleitungsziel, Header),
- eigene WAF-Regeln oder SecLang-Direktiven lassen sich nicht übersetzen („WAF-Konfiguration ungültig: …“).

Vor dem eigentlichen Speichern läuft automatisch die Auswirkungsprüfung (siehe 5.4). Ändert sich am gespeicherten Verkehr nichts, wird direkt gespeichert.

### 5.2 Welche Policy gilt für eine Anfrage?

#### Zuordnung über Hosts

Im Tab „Allgemein“ trägst du unter „Hosts“ die Hostnamen der Sites ein, eine Zeile pro Host. Sentinel wählt die Policy für jede Anfrage in dieser Reihenfolge:

1. **Feste Policy im Caddyfile.** Steht im Site-Block `sentinel <policy-id>` (oder `sentinel { policy <policy-id> }`), gilt diese Policy unabhängig vom Host – sofern sie auf dieser Caddy-Instanz vorhanden ist.
2. **Exakter Hostname** aus der Hostliste einer Policy. Groß-/Kleinschreibung und Port spielen keine Rolle.
3. **Wildcard** wie `*.example.com`. Sie passt auf jede Subdomain beliebiger Tiefe (`wiki.example.com`, `a.b.example.com`), aber nicht auf `example.com` selbst. Passen mehrere Wildcards, gewinnt die längste.
4. **Standard-Policy.**
5. Gibt es keine Standard-Policy, wird die Anfrage nicht geprüft; nur globale Sperren und vertrauenswürdige Quellen wirken.

Ist die im Caddyfile genannte Policy nicht vorhanden (gelöscht oder auf dieser Instanz nicht verteilt), fällt Sentinel auf die Schritte 2 bis 4 zurück.

**Achtung:** Trage einen Host nur in einer Policy ein. Steht derselbe Host in mehreren Policies, ist nicht eindeutig, welche gilt.

#### Die Standard-Policy

Die Standard-Policy gilt für alle Hosts, die keiner anderen Policy zugeordnet sind, und für `sentinel` ohne Policy-Angabe. Beim ersten Start legt Sentinel sie als „Standard“ (ID `default`) an:

| Bereich | Voreinstellung |
|---|---|
| Honeypot-Pfade | `/.env`, `/.git/`, `/.aws/`, `/.ssh/`, `/.svn/`, `/wp-config.php` |
| Ratelimit | „Allgemein pro IP“: 1200 Anfragen pro 60 Sekunden je Client-IP, danach 429 |
| WAF | „Erkennen (nur melden)“, OWASP CRS an, Paranoia-Level 1, Anomalie-Schwelle 5, Request-Body prüfen, Prüflimit 1 MiB |
| IP-Regeln | „Alle zulassen (außer Sperrliste)“ |
| Sicherheits-Header | aus (vorbelegt: nosniff, X-Frame-Options SAMEORIGIN, Referrer-Policy strict-origin-when-cross-origin) |

Pfade echter Anwendungen wie `/wp-login.php` oder `/phpmyadmin` sind bewusst keine Honeypots, weil die Standard-Policy für alle Sites ohne eigene Policy gilt. Installationen, deren Standard-Policy noch die älteren, unveränderten Werte enthielt, passt Sentinel einmalig an.

Die Standard-Policy kann nicht gelöscht werden; wähle vorher eine andere Policy mit „Als Standard“. Sie gilt immer auf allen Caddy-Instanzen. Fehlt die Standard-Policy oder ist sie ausgeschaltet, zeigt das Panel eine Warnung.

**Tipp:** Gib wichtigen Sites eine eigene Policy, statt sie über die Standard-Policy laufen zu lassen. Das gilt besonders für die Site des Panels selbst: Eine eigene Policy (z. B. mit Zugriff nur aus internen Netzen und ohne strenge Honeypots) verhindert, dass du dich durch eine Regel der Standard-Policy aussperrst.

#### Beschränkung auf Caddy-Instanzen

Gibt es mehrere Caddy-Instanzen (siehe Kapitel 9), erscheint im Tab „Allgemein“ das Feld „Gilt auf“. Wähle „allen Caddy-Instanzen“ oder einzelne Instanzen. Eine beschränkte Policy wird nur an diese Instanzen verteilt; auf den anderen gilt für ihre Hosts die Standard-Policy. Sind alle Instanzen ausgewählt, entspricht das „allen Caddy-Instanzen“.

### 5.3 Prüfreihenfolge pro Anfrage

Sentinel prüft jede Anfrage in fester Reihenfolge. Die erste Prüfung, die eine Anfrage ablehnt, beendet die Bearbeitung. Pfade werden vorher vereinheitlicht (`/a/../b`, `//b` und `/./b` werden zu `/b`); alle Pfadvergleiche beziehen sich auf diese Form.

| # | Prüfung | Antwort bei Treffer | Wird übersprungen durch |
|---|---|---|---|
| 1 | Vertrauenswürdige Quelle (*Einstellungen › Netz & Vertrauen* und befristete Einträge „Vertrauenswürdig“) | Anfrage geht ohne jede weitere Prüfung durch | – |
| 2 | Globale Sperren (IPS) | 403 | vertrauenswürdige Quelle |
| 3 | Lokale Ratelimit-Sperre der Caddy-Instanz | 403 | vertrauenswürdige Quelle |
| 4 | Policy ausgeschaltet oder keine Policy | Anfrage geht durch | – |
| 4a | Policy gesperrt, weil eine einschränkende Pfad-Regel oder die blockierende WAF auf dieser Instanz nicht übernommen werden konnte | 503 | – |
| 5 | Pfad-Regel (erste passende): „Nur aus Netzen erreichbar“, „Sperren“, „Weiterleiten“, API-Schlüssel | 403 / Weiterleitung / 401 | Testmodus der Regel |
| 6 | Wartungsmodus | 503 | „Trotzdem erreichbar für“, Pfad-Regel „Durchlassen“ oder „Wartungsmodus: trotzdem erreichbar“ |
| 7 | Sperrliste der Policy | 403 | Testmodus IP-Regeln |
| 8 | Freigabeliste (Modus „Nur Freigabeliste zulassen“) | 403 | „Durchlassen“, Testmodus IP-Regeln |
| 9 | Länder und Netze (ASN) | 403 oder Bot-Challenge | „Durchlassen“, Testmodus Geo |
| 10 | Threat-Feeds | 403, Bot-Challenge oder Markierung | „Durchlassen“, Testmodus Geo |
| 11 | Erlaubte Methoden | 405 | „Durchlassen“, Testmodus Filter |
| 12 | Gesperrte User-Agents | 403 | „Durchlassen“, Testmodus Filter |
| 13 | Honeypot-Pfade | 404 | „Durchlassen“, Testmodus Filter |
| 14 | Maximale Body-Größe | 413 | Testmodus Filter |
| 15 | Bots: gefälschte Suchmaschinen, KI- und SEO-Crawler | 403 bzw. 429 | „Durchlassen“, Testmodus Filter |
| 16 | Ratelimits (in der eingetragenen Reihenfolge) | 429, ggf. mit Sperre | „Durchlassen“, Pfad-Regel „Ratelimits: nicht anwenden“, Testmodus des Limits |
| 17 | Bot-Challenge | Challenge-Seite oder 403 | „Durchlassen“, Pfad-Regel „Bot-Challenge: nie“, ausgenommene Pfade, gültiges Challenge-Cookie |
| 18 | Anmeldung (Site-Login, siehe Kapitel 7) | Anmeldeseite, 401 oder 403 | „Durchlassen“, gültiger API-Schlüssel, Pfad-Regel „ohne Login“, Ausnahmen der Policy |
| 19 | WAF | Status der WAF-Regel (meist 403) bzw. nur Markierung | „Durchlassen“, Pfad-Regel „WAF: aus“ |
| 20 | Sicherheits-Header setzen, Anfrage an das Backend weitergeben | – | – |

Wichtige Folgerungen:

- Globale Sperren gelten auf allen Sites mit `sentinel`, auch wenn deren Policy ausgeschaltet ist.
- Eine lokale Ratelimit-Sperre gilt für alle Sites dieser Caddy-Instanz.
- Die Sperrliste der Policy und das Body-Größenlimit gelten auch bei einer Pfad-Regel „Durchlassen“.
- Ist eine Policy ausgeschaltet, greifen nur Schritte 1 bis 3; auch der Wartungsmodus wirkt dann nicht.

Den Weg einer konkreten Anfrage durch diese Schritte zeigt der Request-Fluss (siehe Kapitel 4).

#### Antwort bei Sperren

Browser erhalten bei Sperren eine kurze Fehlerseite mit einer Überschrift („Zugriff verweigert“, „Zu viele Anfragen“, „Wartungsarbeiten“, „Methode nicht erlaubt“, „Anfrage zu groß“, „Anmeldung erforderlich“), der „Referenz“ und dem Zeitpunkt. Die Seite nennt die auslösende Regel nicht. Andere Clients (APIs, Skripte) bekommen eine Textantwort mit Status, Meldung und `Ref: …`. Jede Sperrantwort trägt den Header `X-Sentinel-Ref`.

**Tipp:** Bitte Benutzer, bei Problemen die Referenz zu nennen. Über die Suche im Panel findest du damit die Anfrage samt Grund (siehe Kapitel 4).

### 5.4 Auswirkung prüfen

„Auswirkung prüfen“ spielt die gespeicherten Anfragen der letzten 24 Stunden an diese Policy gegen den aktuellen Bearbeitungsstand nach, bevor du speicherst. Das Ergebnis zeigt:

- „Neu blockiert“ (mit Zahl der Clients und Pfade),
- „Neu durchgelassen“,
- „Anderer Grund“ (weiterhin aufgehalten, aber durch eine andere Regel),
- Beispiele unter „Würden künftig aufgehalten“, „Würden künftig durchgelassen“ und „Weiterhin aufgehalten, aber anders“.

Geprüft werden höchstens die 3000 häufigsten Anfrageformen.

Beim „Speichern“ läuft diese Prüfung automatisch. Ändert sich etwas, erscheint der Dialog mit „Abbrechen“, „Als Testmodus speichern“ und „Speichern“ (bzw. „Trotzdem speichern“, wenn Anfragen neu blockiert würden). „Als Testmodus speichern“ schaltet den Testmodus für IP-Regeln, Geo & Feeds, Filter, alle Ratelimits und alle Pfad-Regeln mit Sperre, „Nur aus Netzen“ oder API-Schlüssel ein und speichert dann (siehe 5.5).

### 5.5 Testmodus

Mit dem Testmodus protokolliert Sentinel nur, was eine Regel blockiert hätte; die Anfrage geht durch. Im Protokoll erscheint die Aktion als „Test: …“.

| Bereich | Schalter | Umfasst |
|---|---|---|
| IP-Regeln | *Zugriff › IP-Regeln* „Testmodus“ | Sperrliste, Freigabeliste |
| Geo & Feeds | *Geo & Feeds › Länder* „Testmodus“ | Länder, Netze (ASN), Threat-Feeds |
| Filter | *Zugriff › Methoden & Clients* „Testmodus“ | Methoden, User-Agents, Honeypots, Body-Größe und alle Bot-Einstellungen |
| einzelnes Ratelimit | „Testmodus – nur protokollieren“ am Limit | dieses Limit einschließlich „429 + IP sperren“ |
| einzelne Pfad-Regel | „Testmodus – Sperren nur protokollieren“ | „Sperren“, „Nur aus Netzen erreichbar“ und API-Schlüssel dieser Regel |

Nicht über den Testmodus abgedeckt sind globale Sperren, Wartungsmodus, Bot-Challenge (außer über Geo/Feeds) und Anmeldung. Für die WAF verwendest du stattdessen den Modus „Erkennen (nur melden)“.

Treffer im Testmodus erhöhen den Bedrohungs-Score nicht (siehe Kapitel 6). Pro Anfrage wird nur die erste Test-Entscheidung festgehalten.

Ist ein Testmodus aktiv, zeigt die Policy oben „Testmodus aktiv: Einige Regeln dieser Policy protokollieren nur, statt zu blockieren.“ Im Tab „Allgemein“ steht dann das Panel „Testmodus – was wäre blockiert worden?“ mit der Auswertung der letzten 7 Tage („Wäre gewesen“, „Detail“, „Anfragen“, „Clients“, „Beispiel“, „Zuletzt“) und dem Zeitpunkt „Testmodus aktiv seit …“. Ein Klick auf eine Zeile öffnet die passenden Anfragen in den Analysen.

So schaltest du eine Regel scharf:

1. Öffne *Policies › <Policy> › Allgemein* und prüfe die Auswertung im Testmodus-Panel.
2. Stehen dort nur unerwünschte Anfragen, klicke unter „Scharf schalten:“ auf den betreffenden Bereich.
3. Klicke „Speichern“.

**Tipp:** Führe neue Sperrregeln immer zuerst im Testmodus ein und lass sie einige Tage laufen. „Erst scharf schalten, wenn in der Liste nur unerwünschte Anfragen stehen.“

### 5.6 Tab „Allgemein“

| Feld | Bedeutung | Standard |
|---|---|---|
| „Name“ | Anzeigename der Policy | – |
| „ID“ | Kennung aus dem Namen (Kleinbuchstaben, Umlaute umschrieben, Sonderzeichen als „-“). Nicht änderbar. Verwendbar als `sentinel <id>` im Caddyfile. | – |
| „Status“ | „Policy aktiv“ oder „Policy aus (nur Metriken, Bans gelten weiter)“ | aktiv |
| „Hosts“ | Hostnamen und Wildcards, einer pro Zeile (siehe 5.2) | leer |
| „Notizen“ | Freitext | leer |
| „Gilt auf“ | Beschränkung auf Caddy-Instanzen (siehe 5.2) | alle |

#### Wartungsmodus

Im Panel „Wartungsmodus“ schaltest du eine Wartungsseite für alle Sites der Policy ein.

| Feld | Bedeutung | Standard |
|---|---|---|
| „Wartung“ | „Besucher sehen eine Wartungsseite (503)“ | aus |
| „Meldung“ | Text der Wartungsseite. Mit geplantem Ende ergänzt Sentinel „Voraussichtlich wieder erreichbar ab … Uhr.“ | „Wartungsarbeiten – bitte später erneut versuchen.“ |
| „Beginn“ | Beginn des Zeitfensters; leer = sofort | leer |
| „Ende“ | Geplantes Ende; danach schaltet Sentinel die Wartung selbst aus | leer |
| „Trotzdem erreichbar für“ | IPs und Netze, die während der Wartung normal zugreifen (z. B. die IT). Der Link „Meine IP (…) eintragen“ fügt deine aktuelle Adresse hinzu. | leer |

Die Wartung wirkt nur, wenn der Schalter an ist und die aktuelle Zeit im Fenster aus Beginn und Ende liegt. Oben zeigt das Panel „Wartung ist aktiv“ oder „Wartung ist geplant“ mit Zeitraum. Sentinel antwortet mit 503 und dem Header `Retry-After` (Restzeit bis zum Ende, wenn diese unter 24 Stunden liegt, sonst 5 Minuten). Nach dem Ende schaltet das Panel die Wartung innerhalb von etwa 15 Sekunden ab und vermerkt das im Ereignisprotokoll.

Durch die Wartung kommen außerdem vertrauenswürdige Quellen sowie Pfade mit einer Pfad-Regel „Durchlassen“ oder „Wartungsmodus: trotzdem erreichbar“.

So planst du eine Wartung:

1. Öffne *Policies › <Policy> › Allgemein*.
2. Schalte „Wartung“ ein und trage „Beginn“ und „Ende“ ein.
3. Trage unter „Trotzdem erreichbar für“ das Netz der IT ein.
4. Klicke „Speichern“.

**Tipp:** Lege für Health-Checks eine Pfad-Regel mit der Vorlage „Health-Check frei“ an, damit Monitoring während der Wartung nicht Alarm schlägt.

#### Antwort bei Sperren

| Feld | Bedeutung | Standard |
|---|---|---|
| „Status-Code“ | Statuscode für Sperren (400–599). „0 = 403. WAF-Blocks nutzen den Status der Regel.“ | 0 |
| „Text“ | Meldung auf der Sperrseite | „Forbidden“ |

**Hinweis:** Status-Code und Text gelten nur für die 403-Sperren: globale Sperren, IP-Listen, „Nur aus Netzen“, Pfad-Regel-Sperren, Geo, Feeds, User-Agents, Bots und die Challenge-Ablehnung für Nicht-Browser. Der Text gilt außerdem für WAF-Blocks. Antworten mit 404 (Honeypot), 405 (Methode), 413 (Body), 429 (Ratelimit, Bot-Bremse), 503 (Wartung) und 401 (API-Schlüssel) bleiben unverändert.

### 5.7 Tab „Zugriff“

#### IP-Regeln

| Feld | Bedeutung | Standard |
|---|---|---|
| „Testmodus“ | Sperr- und Freigabeliste nur protokollieren | aus |
| „Modus“ | „Alle zulassen (außer Sperrliste)“ oder „Nur Freigabeliste zulassen“ | Alle zulassen |
| „Freigabeliste“ | IPs und Netze (IPv4/IPv6, CIDR). Nur im Modus „Nur Freigabeliste zulassen“ wirksam. | leer |
| „Sperrliste“ | IPs und Netze, die für diese Policy gesperrt sind (403). Globale Sperren verwaltest du unter *Schutz › Sicherheit*. | leer |

Die Sperrliste wird vor der Freigabeliste geprüft und gilt auch bei einer Pfad-Regel „Durchlassen“.

**Achtung:** Mit „Nur Freigabeliste zulassen“ erreicht niemand außerhalb der Liste die Site. Trage dein eigenes Netz ein, bevor du speicherst. Eine leere Freigabeliste lehnt das Panel ab.

#### Methoden & Clients

| Feld | Bedeutung | Standard |
|---|---|---|
| „Testmodus“ | Methoden, User-Agents, Honeypots, Body-Größe und Bot-Einstellungen nur protokollieren | aus |
| „Erlaubte Methoden“ | Auswahl aus GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, REPORT. Andere Methoden erhalten 405. Keine Auswahl = alle erlaubt. | alle |
| „Gesperrte User-Agents“ | Teilstrings, Groß-/Kleinschreibung egal; Treffer erhalten 403 | leer |
| „Honeypot-Pfade“ | Pfad-Präfixe, die echte Besucher nie aufrufen. Antwort 404; das IDS bewertet den Treffer sehr hoch (Standard: Sperre beim ersten Treffer). Groß-/Kleinschreibung zählt. | neue Policy: `/.env`, `/.git/`, `/.aws/`, `/.ssh/`, `/wp-config.php` |
| „Max. Request-Body“ | Grenze in MiB; größere Uploads erhalten 413. 0 = unbegrenzt. | 0 |

**Achtung:** Trage als Honeypot nur Pfade ein, die keine Anwendung hinter dieser Policy tatsächlich nutzt. Ein Honeypot auf `/wp-login.php` sperrt bei einer WordPress-Site die eigenen Redakteure.

#### Befristete Einträge

Hier siehst und erstellst du Freigaben und Sperren mit Enddatum für diese Policy, z. B. das Netz eines Dienstleisters bis Freitag. Sie gelten sofort, ohne dass du die Policy speicherst, und verschwinden von selbst. Details siehe 5.19.

### 5.8 Tab „Ratelimits“

Ratelimits begrenzen die Zahl der Anfragen pro Zeitfenster. Sentinel zählt mit einem gleitenden Fenster je Schlüssel. Alle passenden Limits werden der Reihe nach gezählt; das erste überschrittene greift.

| Feld | Bedeutung | Standard (neues Limit) |
|---|---|---|
| „Name“ | Bezeichnung; erscheint im Protokoll | „Neues Limit“ |
| „Pfad-Präfixe“ | Kommagetrennt; leer = alle Pfade | alle |
| „Requests“ | Erlaubte Anfragen pro Fenster | 120 |
| „pro Sek.“ | Fensterlänge in Sekunden | 60 |
| „Zählen pro“ | Schlüssel, siehe unten | „Client-IP“ |
| „Methoden“ | Leerzeichen- oder kommagetrennt; leer = alle | alle |
| „Bei Überschreitung“ | „429 senden“ oder „429 + IP sperren“ | „429 senden“ |
| „Sperre (Min.)“ | Dauer der Sperre bei „429 + IP sperren“ | 10 |
| „Testmodus“ | Limit nur protokollieren | aus |
| „Pfad-Regex (optional)“ | Zusätzliche Bedingung als regulärer Ausdruck auf den Pfad | leer |
| „Notiz“ | Begründung (Ticket, Vorfall); darunter stehen Autor und Zeitpunkt der letzten Änderung | leer |

Alle gesetzten Bedingungen (Methoden, Präfixe, Regex) müssen zutreffen. Ein Limit ohne Bedingungen gilt für alle Anfragen.

Schlüssel unter „Zählen pro“:

| Auswahl | Gezählt wird |
|---|---|
| „Client-IP“ | pro IPv4-Adresse bzw. pro IPv6-/64-Netz (ein Anschluss mit wechselnden IPv6-Adressen teilt sich einen Zähler) |
| „IP + Pfad“ | pro Client und Pfad |
| „alle zusammen“ | ein gemeinsamer Zähler für alle Clients |
| „angemeldeter Benutzer (Site-Login)“ | pro Benutzer der Site-Anmeldung oder des Zugriffstokens; ohne Anmeldung pro Client-IP |
| „Authorization-Header“, „X-Api-Key“ | pro Wert des Headers; fehlt der Header, pro Client-IP |

Bei Überschreitung antwortet Sentinel mit 429 und `Retry-After`. Mit „429 + IP sperren“ sperrt die Caddy-Instanz die Client-Adresse zusätzlich lokal für die eingestellte Dauer (auf allen ihren Sites); das Panel übernimmt die Sperre als globale Sperre, sofern die Bedrohungserkennung das zulässt (siehe Kapitel 6).

**Hinweis:** Bei „alle zusammen“ wird nie gesperrt, auch wenn „429 + IP sperren“ gewählt ist.

Bei IPv6 gilt auch die Sperre („429 + IP sperren“) für das ganze /64-Netz – so breit, wie die Einstellung „IPv6-Sperren für“ unter *Einstellungen › Bedrohungserkennung* es festlegt (Standard /64). Adressen unter „Nie sperren“ sperrt ein Ratelimit nie; sie bekommen nur 429.

**Hinweis:** Die lokale Sperre setzt die Caddy-Instanz selbst. Sie greift auch für Adressen unter „Nie automatisch sperren“ und im Testmodus der Bedrohungserkennung; ausgenommen sind nur vertrauenswürdige Quellen.

**Hinweis:** Header-Werte bestimmt der Client. Ein Angreifer kann bei „Authorization-Header“ oder „X-Api-Key“ durch wechselnde Werte eigene Zähler erzeugen. Kombiniere solche Limits mit einem Limit pro Client-IP.

Die Knöpfe unter der Liste:

- „Limit hinzufügen“ – neues Limit mit den Werten aus der Tabelle,
- „Vorlage: Login-Schutz“ – 10 POST-Anfragen pro 60 Sekunden je Client-IP auf `/login`, `/wp-login.php`, `/user/login`, `/api/auth`, danach 429 und Sperre für 30 Minuten.

**Tipp:** Verwende ein großzügiges Limit für alles (wie „Allgemein pro IP“ der Standard-Policy) und ein strenges für Login-Pfade. Büros hinter einer gemeinsamen IP und Sync-Clients erzeugen viele Anfragen.

### 5.9 Tab „Geo & Feeds“

Für Länder- und Netzregeln braucht Sentinel eine GeoIP-Datenbank (z. B. kostenlos von DB-IP oder MaxMind GeoLite2), die du unter *Einstellungen › Netz & Vertrauen* einträgst (siehe Kapitel 10). Fehlt sie, zeigt der Tab einen Hinweis und das Panel lehnt Geo-Regeln beim Speichern ab.

#### Länder

| Feld | Bedeutung | Standard |
|---|---|---|
| „Testmodus“ | Länder, Netze und Threat-Feeds nur protokollieren | aus |
| „Modus“ | „Aus“, „Ausgewählte Länder betreffen“ oder „Nur ausgewählte Länder zulassen“ | „Aus“ |
| „Aktion“ | „Blockieren“ (403) oder „Bot-Challenge“ | „Blockieren“ |
| „Unbekannte Herkunft zulassen“ | Anfragen, deren Land nicht bestimmbar ist, nicht als Treffer werten (nur im Modus „Nur ausgewählte Länder zulassen“ von Bedeutung) | aus |
| Länderliste | ISO-Ländercodes. Eingabe mit Leerzeichen oder Komma, „Hinzufügen“; Schnellauswahl „DACH“ und „EU“; „Leeren“ | leer |

Wirkung:

- „Ausgewählte Länder betreffen“: Anfragen aus den gelisteten Ländern erhalten die Aktion. Anfragen unbekannter Herkunft sind nie betroffen.
- „Nur ausgewählte Länder zulassen“: Anfragen aus allen anderen Ländern erhalten die Aktion; unbekannte Herkunft ebenfalls, außer „Unbekannte Herkunft zulassen“ ist an.

**Tipp:** Statt Länder hart zu blocken, ist „Nur ausgewählte Länder zulassen“ mit der Aktion „Bot-Challenge“ meist besser: Echte Besucher aus dem Urlaub kommen trotzdem durch.

#### Netze (ASN)

Unter „Betroffene Autonomous Systems“ trägst du AS-Nummern ein (z. B. `14061, 16276, 24940`; ein vorangestelltes „AS“ ist erlaubt). Anfragen aus diesen Netzen erhalten dieselbe Aktion wie die Länderregel – auch wenn der Länder-Modus „Aus“ ist. Das hilft gegen Bots aus Rechenzentren. Die AS-Nummern deiner Besucher siehst du in *Analysen › Netze*.

#### Threat-Feeds

Für jeden eingerichteten Feed (siehe 5.16) wählst du, was mit Anfragen von gelisteten IPs geschieht:

| Auswahl | Wirkung |
|---|---|
| „ignorieren“ | keine |
| „markieren“ | Anfrage geht durch, wird aber protokolliert und gekennzeichnet |
| „Challenge“ | Bot-Challenge (siehe 5.11) |
| „blockieren“ | 403 |

Feeds mit dem Kennzeichen „Liste aus“ sind abgeschaltet und wirken nicht.

### 5.10 Tab „Bots“

Sentinel erkennt bekannte Crawler am User-Agent. Echte Besucher sind nicht betroffen.

| Feld | Bedeutung | Standard |
|---|---|---|
| „KI-Crawler“ | „erlauben“, „bremsen“ oder „sperren“. Betrifft u. a. GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, PerplexityBot, CCBot, Bytespider, Amazonbot, Meta-Crawler, Applebot-Extended, Diffbot, cohere. | erlauben |
| „SEO-Crawler“ | „erlauben“, „bremsen“ oder „sperren“. Betrifft u. a. AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, DataForSeoBot, SISTRIX, Screaming Frog. | erlauben |
| „Anfragen pro Minute beim Bremsen“ | Grenze je Crawler und IP; darüber 429 | 10 |
| „Suchmaschinen prüfen“ | „falsche Googlebots, Bingbots … sperren“ | aus |

„Sperren“ beantwortet Crawler-Anfragen mit 403, „bremsen“ mit 429, sobald die Grenze pro Minute überschritten ist.

„Suchmaschinen prüfen“ verifiziert Anfragen, die sich als Googlebot, Bingbot, Applebot, YandexBot, Baiduspider, Yahoo Slurp oder PetalBot ausgeben: Sentinel löst die IP rückwärts auf (Reverse-DNS), prüft die Domain des Suchmaschinenbetreibers und macht die Gegenprobe. Fälschungen erhalten 403 und erhöhen den Bedrohungs-Score. Bestätigte Ergebnisse gelten 24 Stunden, Fälschungen 6 Stunden. Ist DNS gestört, lässt Sentinel die Anfrage durch. Die erste Anfrage einer neuen IP kann sich durch die Prüfung um bis zu etwa 2,5 Sekunden verzögern.

Ist der Testmodus für Filter aktiv, werden auch Bot-Sperren nur protokolliert.

**Tipp:** Ergänze eine `robots.txt`, die KI-Crawler höflich auslädt. Sentinel setzt die Entscheidung aber auch bei Crawlern durch, die `robots.txt` ignorieren.

### 5.11 Tab „Bot-Challenge“

Statt zu blockieren muss der Browser eine kurze Rechenaufgabe (Proof-of-Work, ca. 1 Sekunde) lösen. Echte Besucher merken kaum etwas; Skripte und einfache Bots ohne JavaScript kommen nicht durch.

| Feld | Bedeutung | Standard |
|---|---|---|
| „Modus“ | „Nur bei Geo-/Feed-Regeln“, „Auch für verdächtige IPs“ oder „Alle Besucher (Angriffsmodus)“ | „Nur bei Geo-/Feed-Regeln“ |
| „Schwierigkeit“ | 8 bis 24; „16 ≈ 1 Sekunde, jede Stufe mehr verdoppelt die Rechenzeit“ | 16 |
| „Gültigkeit (Stunden)“ | Solange gilt eine gelöste Challenge | 24 |
| „Ausgenommene Pfade“ | Pfad-Präfixe ohne Challenge, z. B. `/api/`, `/webhooks/` | leer |

Wann eine Challenge kommt:

- Eine Geo- oder Feed-Regel mit der Aktion „Bot-Challenge“ trifft (in jedem Modus),
- Modus „Auch für verdächtige IPs“: die IP hat den Bedrohungs-Score „Bot-Challenge ab Score“ erreicht, ist aber noch nicht gesperrt (siehe Kapitel 6),
- Modus „Alle Besucher (Angriffsmodus)“: jede Anfrage ohne gültiges Challenge-Cookie.

Pfad-Regeln können das übersteuern: „Bot-Challenge: nie“ schaltet jede Challenge für den Bereich ab (auch die aus Geo/Feeds), „immer“ erzwingt sie.

Nur Seitenaufrufe im Browser (GET oder HEAD, die HTML akzeptieren) erhalten die Seite „Kurze Sicherheitsprüfung“. Andere Anfragen auf geschützten Pfaden erhalten 403. Nach dem Lösen setzt Sentinel ein Cookie, das an die IP-Adresse des Besuchers gebunden ist. ACME-Pfade (`/.well-known/acme-challenge/`) sind immer ausgenommen.

**Achtung:** APIs, Webhooks und Apps können keine Challenge lösen. Trage deren Pfade unter „Ausgenommene Pfade“ ein oder lege eine Pfad-Regel mit „Bot-Challenge: nie“ an, bevor du den Angriffsmodus einschaltest.

**Hinweis:** Wechselt die IP-Adresse eines Besuchers (z. B. IPv6-Privacy-Adressen, Mobilfunk), muss er die Challenge erneut lösen.

### 5.12 Tab „Anmeldung“

Hier stellst du eine Anmeldung vor die Site: mit Domänenkonto (AD/LDAP), lokalem Zugangskonto oder einem OAuth/OIDC-Anbieter, optional mit zweitem Faktor. Die Felder („Anmeldemethoden“, „Anmeldung“, „Zweiter Faktor“, „Sitzungsdauer (Stunden)“, „Titel der Login-Seite“, „Erlaubte Gruppen“, „Zusätzlich erlaubte Benutzer“, Ausnahmen, „An IP binden“, „Header ans Backend“, „Single Sign-on“) beschreibt Kapitel 7. Die Anmeldung wird nach Ratelimits und Bot-Challenge und vor der WAF geprüft. Abweichungen für einzelne Bereiche (ohne Login, andere Gruppen, 2FA nur im Admin-Bereich, API-Schlüssel) regelst du mit Pfad-Regeln (siehe 5.13).

### 5.13 Tab „Pfad-Regeln“

Pfad-Regeln setzen für einzelne Bereiche einer Site abweichende Einstellungen: ein Admin-Bereich nur aus dem LAN und nur für eine Gruppe mit 2FA, ein öffentlicher Bereich ohne Anmeldung, Webhooks mit API-Schlüssel statt Login, eine Weiterleitung für eine alte URL.

**Die Regeln werden von oben nach unten geprüft; die erste passende Regel gilt.** Spätere Regeln werden für diese Anfrage nicht mehr betrachtet. Mit „↑“ und „↓“ änderst du die Reihenfolge. Stelle daher spezielle Regeln über allgemeine.

Jede Regel erscheint als Karte mit Schalter, Nummer und Name, Kennzeichen („Testmodus“, „bis …“ bzw. „abgelaufen“, Zeitplan), einer Zusammenfassung der Bedingungen und Wirkungen, der Notiz sowie Autor und Zeitpunkt der letzten Änderung. „Bearbeiten“ öffnet den Dialog, „Löschen“ entfernt die Regel. „Im Fluss-Simulator testen“ öffnet den Request-Fluss (siehe Kapitel 4).

#### Eine Pfad-Regel anlegen

1. Öffne *Policies › <Policy> › Pfad-Regeln*.
2. Klicke „Regel hinzufügen“ oder eine Vorlage.
3. Fülle im Dialog die Abschnitte aus (siehe unten) und klicke „Übernehmen“.
4. Bringe die Regel mit „↑“/„↓“ an die richtige Stelle.
5. Klicke „Speichern“.

#### Kopf der Regel

| Feld | Bedeutung | Standard |
|---|---|---|
| „Name“ | Bezeichnung | „Neue Regel“ |
| „Aktiv“ | „Regel anwenden“ | an |
| „Testmodus“ | „Sperren nur protokollieren“: „Sperren“, „Nur aus Netzen“ und API-Schlüssel greifen noch nicht | aus |
| „Notiz“ | Warum es die Regel gibt (Ticket, Ansprechpartner) | leer |

#### „Wann gilt die Regel?“

| Feld | Bedeutung | Standard |
|---|---|---|
| „Endet“ | Ab diesem Zeitpunkt gilt die Regel nicht mehr. Das Panel schaltet sie danach aus; sie bleibt sichtbar. | kein Ende |
| „Zeitplan“ | „immer“, „nur im Zeitfenster“ oder „nur außerhalb“ | „immer“ |
| „Tage“ | Wochentage; keine Auswahl = jeden Tag | Mo–Fr (beim Einschalten des Zeitplans) |
| „Von“ / „Bis“ | Uhrzeiten. „Bis“ vor „Von“ = über Mitternacht (der Teil nach Mitternacht gehört zum Starttag). | 07:00 / 19:00 |
| „Zeitzone“ | IANA-Zeitzone | Europe/Berlin |

Beispiel: Pfad `/admin` sperren „nur außerhalb Mo–Fr 07:00–19:00“ = Admin-Bereich nur zur Bürozeit erreichbar.

#### „Wenn …“ – Bedingungen

Alle gesetzten Bedingungen müssen zutreffen.

| Feld | Bedeutung |
|---|---|
| „Pfade“ | Eine Zeile pro Muster; eines muss passen. Leer = alle Pfade. Siehe Tabelle unten. |
| „Methoden“ | z. B. POST; leer = alle |
| „Client aus Netzen“ | Regel gilt nur für Clients aus diesen Netzen; leer = alle Clients |

Pfadmuster:

| Muster | Bedeutung | Beispiel |
|---|---|---|
| `/admin/` | beginnt mit | passt auf `/admin/users` |
| `=/login` | genau dieser Pfad | nur `/login` |
| `/files/*.pdf` | `*` = beliebige Zeichen innerhalb eines Pfadabschnitts, `?` = ein Zeichen | `/files/a.pdf`, nicht `/files/x/a.pdf` |
| `/**.bak` | `**` = beliebige Zeichen über Pfadabschnitte hinweg | jede Datei auf `.bak` |
| `~^/api/v[0-9]+/` | regulärer Ausdruck (nicht automatisch verankert) | `/api/v2/items` |

Groß-/Kleinschreibung zählt.

#### „… dann“ – Aktion

| Aktion | Wirkung |
|---|---|
| „Einstellungen anpassen“ | Es gelten nur die Abweichungen in den Abschnitten darunter. |
| „Durchlassen“ | Überspringt Geo-/Feed-Regeln, Methoden-, User-Agent- und Honeypot-Filter, IP-Freigabeliste, Ratelimits, Bot-Challenge, Anmeldung und WAF. Globale Sperren, die Sperrliste der Policy und „Nur aus Netzen“ gelten weiter. |
| „Sperren“ | 403; jeder Treffer erhöht den Bedrohungs-Score (Signal „Pfad-Sperre“). |
| „Weiterleiten“ | Weiterleitung auf „Ziel“ mit dem gewählten „Status“ |

**Hinweis:** „Durchlassen“ überspringt zusätzlich den Wartungsmodus und die Bot-Einstellungen; das Body-Größenlimit gilt dagegen weiter.

Für „Weiterleiten“:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Ziel“ | Beginnt mit `/` oder `http(s)://`. Platzhalter: `{path}`, `{query}`, `{uri}` (Pfad + Query), `{host}`. Beispiel: `https://neu.example.com{uri}` | – |
| „Status“ | „302 vorübergehend“, „301 dauerhaft“, „307 vorübergehend (Methode bleibt)“, „308 dauerhaft (Methode bleibt)“ | 302 |

Unabhängig von der Aktion:

| Feld | Bedeutung |
|---|---|
| „Nur aus Netzen erreichbar“ | Alle anderen Clients erhalten 403 – z. B. Admin-Bereiche nur intern. |

Der Unterschied: „Client aus Netzen“ ist eine Bedingung (die Regel betrifft nur diese Clients), „Nur aus Netzen erreichbar“ ist eine Einschränkung (alle anderen werden abgewiesen).

#### Anmeldung

| Feld | Bedeutung |
|---|---|
| „Login“ | „wie Policy“, „erforderlich“ oder „ohne Login“ |
| „Zweiter Faktor“ | „wie Policy“, „verlangen“ oder „nicht nötig“ |
| „Nur diese Gruppen“ | ersetzt die erlaubten Gruppen der Policy; leer = wie Policy |
| „Nur diese Benutzer“ | ersetzt zusammen mit den Gruppen die erlaubten Benutzer der Policy |
| „API-Schlüssel“ | Mit Schlüsseln ist der Bereich nur noch mit gültigem Schlüssel erreichbar – dafür ohne Login (Webhooks, Skripte, Monitoring). |

„Login: erforderlich“ setzt voraus, dass mindestens eine Anmeldemethode eingerichtet ist (siehe Kapitel 7).

So erzeugst du einen API-Schlüssel:

1. Klicke im Regel-Dialog unter „API-Schlüssel“ auf „Schlüssel erzeugen“.
2. Gib eine Bezeichnung ein (z. B. GitLab-Webhook).
3. Kopiere den angezeigten Schlüssel (`sk_…`). Er wird nur jetzt angezeigt; Sentinel speichert nur eine Prüfsumme.
4. Wähle unter „Header“, wie der Client ihn sendet: `X-API-Key` (Standard), „Authorization: Bearer …“, `X-Gitlab-Token` oder `X-Webhook-Token`.
5. Klicke „Übernehmen“ und speichere die Policy.

Fehlt der Schlüssel oder ist er falsch, antwortet Sentinel mit 401. Ein gültiger Schlüssel ersetzt die Anmeldung, auch wenn „Login: erforderlich“ gesetzt ist. In der Tabelle der Schlüssel siehst du Bezeichnung, Anfang des Schlüssels und Erstellungsdatum; „Entfernen“ widerruft ihn.

#### Schutz

| Feld | Bedeutung |
|---|---|
| „WAF“ | „wie Policy“, „aus“, „erkennen“ oder „blockieren“ |
| „Bot-Challenge“ | „wie Policy“, „nie“ oder „immer“ |
| „Ratelimits“ | „nicht anwenden“ |
| „Wartungsmodus“ | „trotzdem erreichbar“ |
| „Antwort-Header“ | Eine Zeile `Name: Wert` pro Header, z. B. `X-Robots-Tag: noindex`. Die Header werden auf alle Antworten für diesen Bereich gesetzt, auch auf Sperrantworten. |

#### Vorlagen

| Vorlage | Inhalt |
|---|---|
| „Admin-Bereich intern + Gruppe“ | `/admin/`, nur aus privaten Netzen (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7), Login erforderlich, 2FA, Gruppe IT-Admins, WAF blockieren |
| „Öffentlich ohne Login“ | `/public/`, `/assets/`, `=/favicon.ico`, ohne Login |
| „Webhook mit Schlüssel“ | `/hooks/`, POST, Header `X-Webhook-Token`, Challenge nie, WAF erkennen |
| „API mit Bearer-Token“ | `/api/`, Header Authorization, Challenge nie |
| „Health-Check frei“ | `=/health`, `=/healthz`, `=/status`, GET/HEAD, Durchlassen, auch bei Wartung |
| „Statische Dateien ohne WAF“ | `/static/`, `/assets/`, `/**.css`, `/**.js`, `/**.png`, `/**.svg`, `/**.woff2`, GET/HEAD, WAF aus, Challenge nie, `Cache-Control: public, max-age=86400` |
| „Alte URL umleiten“ | `/alt/` → `/neu{path}` mit 301 |
| „Pfad sperren“ | `/.git/`, `/backup/`, `/**.bak`, `/**.sql`, Sperren |
| „Nicht indexieren“ | `/intern/`, `X-Robots-Tag: noindex, nofollow` |

Passe Pfade, Netze und Gruppen nach dem Einfügen an.

#### Ablauf und Fehlerschutz

Eine Regel mit „Endet“ gilt ab dem Endzeitpunkt sofort nicht mehr; das Panel schaltet sie innerhalb von etwa 15 Sekunden aus und vermerkt das im Ereignisprotokoll. Speicherst du eine Regel, deren Ende schon vorbei ist, wird sie ausgeschaltet gespeichert.

Kann eine Caddy-Instanz eine aktive Regel mit „Sperren“, „Login: erforderlich“, „Nur aus Netzen erreichbar“ oder API-Schlüsseln nicht übernehmen (z. B. bei unterschiedlichen Versionen von Panel und Modul), behält sie die zuletzt funktionierenden Pfad-Regeln. Gibt es keine, antwortet die Policy mit 503, statt den Bereich ungeschützt zu öffnen.

**Tipp:** Halte Pfad-Regeln so eng wie möglich und dokumentiere sie in der „Notiz“. Prüfe neue Regeln im Request-Fluss und starte Sperren im Testmodus.

### 5.14 Tab „WAF“

Die Web Application Firewall (Coraza mit dem OWASP Core Rule Set 4) prüft URL, Header und – falls eingeschaltet – den Request-Body auf Angriffsmuster. Jede Regel, die anschlägt, erhöht einen Anomalie-Score; erreicht er die Schwelle, wird die Anfrage im Blockiermodus abgelehnt.

#### Web Application Firewall

| Feld | Bedeutung | Standard |
|---|---|---|
| „Modus“ | „Aus“, „Erkennen (nur melden)“ oder „Blockieren“ | neue Policy: Erkennen |
| „OWASP Core Rule Set“ | „CRS 4 aktiv“ | an |
| „Paranoia-Level“ | 1 bis 4; „1 = wenige Fehlalarme, 4 = sehr streng“ | 1 |
| „Anomalie-Schwelle“ | Ab diesem Score wird blockiert (CRS-Standard 5). Höher = toleranter. 1 bis 100. | 5 |
| „Request-Body prüfen“ | Formulare, JSON, XML, Uploads | an |
| „Body-Prüflimit (KiB)“ | Prüfgrenze für Anfrage-Bodies und – falls eingeschaltet – Antworten (mindestens 16) | 1024 |
| „Größere Bodies“ | „bis zum Limit prüfen, Rest durchlassen“ oder „ablehnen (413)“. Ablehnen schließt die Lücke hinter dem Limit, verhindert aber größere Uploads – nur für Sites ohne Uploads oder mit einer Pfad-Regel (WAF aus) für den Upload-Pfad. | bis zum Limit prüfen |
| „Antworten prüfen“ | „nur melden“: Text-Antworten (HTML, JSON, XML, Text) bis zum Limit gegen die Antwortregeln des CRS prüfen – Datenlecks wie SQL-Fehlermeldungen, Stacktraces, Verzeichnislisten. Die Antwort wird nie aufgehalten oder verändert; mit `encode` komprimierte Antworten (gzip, zstd) entpackt Sentinel für die Prüfung. Treffer erscheinen als „WAF-Treffer“ unter *Sicherheit*, zählen aber nicht für das IDS. Kostet etwas CPU pro Antwort. | aus |

Im Modus „Erkennen“ erscheinen Treffer unter *Schutz › Sicherheit* und fließen in die Bedrohungserkennung ein, Anfragen werden aber nicht blockiert. Im Modus „Blockieren“ antwortet Sentinel mit dem Status der auslösenden Regel (beim CRS 403).

Mit eingeschalteter Body-Prüfung liest die WAF JSON- und XML-Bodies strukturiert. Ein vollständig gelesener Body, der sich nicht verarbeiten lässt (z. B. kaputtes JSON), wird mit 400 abgelehnt. Bodies über dem Prüflimit werden nur teilweise geprüft. gRPC-Anfragen werden nicht im Body geprüft. Antworten des Backends prüft die WAF nicht.

**Tipp:** Starte jede WAF im Modus „Erkennen (nur melden)“. Beobachte die Treffer einige Tage unter *Schutz › Sicherheit*, beseitige Fehlalarme mit Ausnahmen (siehe unten) und stelle erst dann auf „Blockieren“. Erhöhe das Paranoia-Level nur schrittweise und wieder mit einer Erkennungsphase.

#### CRS-Regelgruppen

Bei eingeschaltetem CRS schaltest du hier ganze Regelgruppen ab (Häkchen entfernen):

| Gruppe | Name | Inhalt |
|---|---|---|
| 911 | „Methoden-Prüfung“ | Erlaubte HTTP-Methoden |
| 913 | „Scanner-Erkennung“ | Bekannte Security-Scanner anhand User-Agent und Headern |
| 920 | „Protokoll-Durchsetzung“ | Ungültige/anomale HTTP-Requests, Header-Limits, Content-Types |
| 921 | „Protokoll-Angriffe“ | Request Smuggling, Response Splitting, Header Injection |
| 922 | „Multipart-Angriffe“ | Manipulierte Multipart-Uploads |
| 930 | „Local File Inclusion“ | Path Traversal, Zugriff auf Systemdateien |
| 931 | „Remote File Inclusion“ | Einbinden entfernter Dateien über URLs |
| 932 | „Remote Code Execution“ | Shell-/Befehlsinjektion |
| 933 | „PHP-Angriffe“ | PHP-Injection, gefährliche Funktionen |
| 934 | „Generische Angriffe“ | Node.js, Ruby, SSRF, Prototype Pollution |
| 941 | „Cross-Site Scripting“ | XSS |
| 942 | „SQL-Injection“ | SQLi |
| 943 | „Session Fixation“ | Manipulation von Session-IDs |
| 944 | „Java-Angriffe“ | Java-Deserialisierung, Log4Shell, Spring |

Unter „Einzelne CRS-Regeln deaktivieren“ trägst du Regel-IDs oder Bereiche ein (z. B. `920350`, `942100-942199`). Das gilt für die ganze Policy.

**Tipp:** Schalte Regeln nicht global ab, wenn der Fehlalarm nur auf einem Pfad oder in einem Parameter auftritt. Verwende dafür eine Ausnahme oder eine eigene Regel mit der Aktion „CRS-Regeln ausnehmen“.

Von einem WAF-Treffer unter *Schutz › Sicherheit* aus kannst du eine CRS-Regel direkt für eine Policy deaktivieren: Policy auswählen, „Regel deaktivieren“.

#### Ausnahmen (Fehlalarme)

Ausnahmen schalten einzelne CRS-Regeln nur für einen Pfad – oder nur für einen Parameter – ab. Die Tabelle zeigt „Regeln“, „Pfade ab“ (oder „alle“), „Nur für“ (z. B. `ARGS:q` oder „alles“), „Gilt“ (Enddatum oder „dauerhaft“) und „Notiz“ mit Autor und Datum.

- „Befristen“ setzt oder ändert das Enddatum. Abgelaufene Ausnahmen entfernt das Panel selbst und vermerkt das im Ereignisprotokoll.
- „Entfernen“ löscht die Ausnahme (danach „Speichern“).

Neue Ausnahmen legst du mit dem Fehlalarm-Assistenten an („Fehlalarm-Assistent öffnen“).

#### Fehlalarm-Assistent

Der Assistent untersucht die WAF-Blockaden dieser Policy der letzten 7 Tage und schlägt die engste Ausnahme vor, die sie verhindert hätte. Du öffnest ihn im WAF-Tab oder aus der Sicherheits- und Fehleranalyse für einen bestimmten Host und Pfad.

Er zeigt:

- die Zahl der Blockaden, den betroffenen Bereich (Pfad-Präfix; über Knöpfe umschaltbar) und die Zahl der Clients,
- „Beteiligte Regeln“ mit Regel, Meldung, Treffern und „Gefunden in“ (z. B. `ARGS:comment`),
- Hinweise zur Einschätzung, z. B. „Vorsicht: … das sieht eher nach echten Angriffen als nach Fehlalarmen aus“ (viele Scanner/Skripte), „Alle Treffer kommen von sehr wenigen Clients – erst prüfen, ob es sich um einen Angriff handelt“ oder „… verschiedene Clients mit normalen Browsern – typisch für einen Fehlalarm“,
- „Vorschläge – vom engsten zum breitesten“, jeweils mit Risiko und „N von M verhindert“ (wie viele der Blockaden mit der Ausnahme unter der Schwelle geblieben wären).

| Vorschlag | Risiko | Wirkung |
|---|---|---|
| „Regel … nur für <Parameter> unter <Pfad> ignorieren“ | niedrig | Ausnahme nur für diesen Parameter; alles andere bleibt geschützt |
| „Regel … unter <Pfad> ausnehmen“ | mittel | Die Regel prüft in diesem Bereich nichts mehr |
| „WAF unter <Pfad> nur melden lassen“ | mittel | Neue Pfad-Regel mit WAF „erkennen“ ganz oben; auch echte Angriffe in diesem Bereich werden nicht mehr blockiert |
| „Regel … für die ganze Policy abschalten“ | hoch | Regel wird unter „Einzelne CRS-Regeln deaktivieren“ eingetragen |

„Anwenden“ (nur Bearbeiter und Administratoren) übernimmt den Vorschlag sofort in die Policy. Angewendete Ausnahmen stehen unter *WAF › Ausnahmen (Fehlalarme)* mit der Notiz „Fehlalarm-Assistent“.

Gilt für den Pfad schon eine Pfad-Regel, lehnt das Panel den Vorschlag „nur melden lassen“ ab, weil die neue Regel davor die Einschränkungen der bestehenden (Netze, Anmeldung, API-Schlüssel) aufheben würde. Wähle dann eine Ausnahme oder stelle in der bestehenden Pfad-Regel „WAF“ auf „erkennen“.

**Tipp:** Wähle möglichst den Vorschlag mit niedrigem Risiko und befriste breitere Ausnahmen.

#### Regelsätze

Hier aktivierst du Regelsätze (siehe 5.15) für diese Policy. Ein Klick auf einen Eintrag schaltet ihn an oder aus.

#### Eigene Regeln dieser Policy

Mit dem Regel-Builder legst du WAF-Regeln an, ohne SecLang zu schreiben:

1. Klicke „Regel hinzufügen“.
2. Gib der Regel einen Namen.
3. Lege die Bedingungen fest: Feld, ggf. „Name“ (z. B. Header- oder Parametername), „ist“/„ist nicht“, Operator und Wert. Mit „+ Bedingung (UND)“ fügst du weitere Bedingungen hinzu; alle müssen zutreffen. „t“ öffnet die Transformationen.
4. Wähle unter „Dann:“ die Aktion.
5. Speichere die Policy.

Fehler zeigt der Builder sofort an; „Erzeugtes SecLang anzeigen“ zeigt das Ergebnis. Regel-IDs vergibt Sentinel automatisch (ab 10000, eindeutig über alle Policies und Regelsätze).

Felder: „Pfad“, „URI (Pfad + Query)“, „Query-String“, „Methode“, „Host“, „Client-IP“, „User-Agent“, „Referer“, „Content-Type“, „Header“, „Header-Namen“, „Cookie“, „Parameter“, „Alle Parameter“, „Parameter-Namen“, „Query-Parameter“, „Request-Body“, „Dateiname“, „Protokoll“, „Upload-Dateinamen“.

Operatoren: „enthält“, „ist gleich“, „beginnt mit“, „endet mit“, „Regex“, „enthält eines der Wörter“ (durch Leerzeichen getrennt), „ist einer von“, „IP/CIDR in“ (Komma oder Leerzeichen), „= (Zahl)“, „> (Zahl)“, „< (Zahl)“, „existiert“, „SQL-Injection (libinjection)“, „XSS (libinjection)“, „Länge >“.

Transformationen (vor dem Vergleich angewendet, z. B. gegen Umgehungsversuche): lowercase, urlDecode, urlDecodeUni, trim, normalizePath, removeWhitespace, compressWhitespace, htmlEntityDecode, base64Decode, removeNulls, cmdLine, jsDecode.

| Aktion | Wirkung |
|---|---|
| „Blockieren“ | Lehnt die Anfrage ab (Status 400–599, Standard 403); Schwere wählbar |
| „Anomalie-Score erhöhen“ | Addiert Punkte (1–100, Standard 5) zum CRS-Score; blockiert wird erst bei Erreichen der Schwelle. Wirkt nur mit eingeschaltetem CRS. |
| „Nur protokollieren“ | Meldet den Treffer, ohne einzugreifen |
| „Erlauben (WAF überspringen)“ | Die übrigen WAF-Regeln prüfen die Anfrage nicht mehr |
| „CRS-Regeln ausnehmen“ | Schaltet CRS-Regeln für passende Anfragen ab. Angabe: ID, Bereich, `tag:…` oder `ID;ARGS:feld`, kommagetrennt. Nur mit Bedingungen auf Pfad, URI, Header, Methode, Host, IP u. ä., nicht mit Parametern oder Body. |

Für „Blockieren“, „Anomalie-Score erhöhen“ und „Nur protokollieren“ wählst du die Schwere (CRITICAL, ERROR, WARNING, NOTICE). Ein Notizfeld dokumentiert die Regel.

Im Blockiermodus der Policy wirkt „Blockieren“ sofort; im Erkennungsmodus wird nur gemeldet.

„SecLang-Regel hinzufügen“ legt eine Regel in Roh-SecLang (ModSecurity/Coraza) an. Vergib die IDs selbst, außerhalb des CRS-Bereichs 9xxxxx.

#### Erweitert: SecLang-Direktiven

Zwei Textfelder für Fortgeschrittene:

- „Vor dem CRS“ – Direktiven, die vor den CRS-Prüfungen laufen,
- „Nach dem CRS (z. B. SecRuleUpdateTargetById)“ – Direktiven nach dem CRS.

In beiden Feldern, in SecLang-Regeln des Builders und in Regelsätzen sind nur diese Direktiven erlaubt: `SecRule`, `SecAction`, `SecMarker`, `SecDefaultAction`, `SecRuleRemoveById`, `SecRuleRemoveByTag`, `SecRuleRemoveByMsg`, `SecRuleUpdateTargetById`, `SecRuleUpdateTargetByTag`, `SecRuleUpdateTargetByMsg`, `SecRuleUpdateActionById`. Der Operator `@inspectFile` ist verboten. Andere Direktiven lehnt das Panel beim Speichern ab („Direktive … ist in eigenen Regeln nicht erlaubt“).

#### Reihenfolge der WAF-Regeln

Mit CRS gilt diese Reihenfolge: CRS-Grundeinstellungen (Paranoia-Level, Schwelle) → Ausnahmen → Regelsätze (in der gewählten Reihenfolge) → eigene Regeln der Policy → „Vor dem CRS“ → CRS-Prüfungen → abgeschaltete Regeln und Gruppen → „Nach dem CRS“. Ohne CRS laufen nur Ausnahmen und eigene Regeln. Die erzeugte Konfiguration zeigt „SecLang-Vorschau“ (gespeicherter Stand). Fehler beim Erzeugen erscheinen oben in der Policy als „Fehler beim Erzeugen der WAF-Regeln: …“.

### 5.15 Regelsätze und WAF-Tester

#### Regelsätze

Regelsätze bündeln WAF-Regeln, die du in mehreren Policies verwendest – z. B. „WordPress-Härtung“ für alle WordPress-Sites. Du findest sie unter *Konfiguration › Regelsätze*. Bearbeiten dürfen Bearbeiter und Administratoren.

Die Übersicht zeigt „Name“, „Beschreibung“, „Regeln“ (aktiv/gesamt) und „Verwendet in“. Mit „Neuer Regelsatz“ legst du einen leeren Regelsatz an, unter „Vorlagen“ mit „Als Regelsatz anlegen“ einen vorbereiteten:

| Vorlage | Inhalt |
|---|---|
| „Exploit-Pfade & Scanner“ | Geheime Dateien (.env, .git, .aws …) und typische Exploit-Sonden (phpinfo.php, phpunit, cgi-bin, Router-Exploits, actuator, server-status …) mit 404 blockieren; Angriffstools am User-Agent blockieren; „Leerer User-Agent“ erhöht den Score (abgeschaltet) |
| „WordPress-Härtung“ | xmlrpc.php sperren, PHP in wp-content/uploads, Autoren-Enumeration (?author=), REST-Benutzerliste |
| „Admin nur aus internen Netzen“ | /admin außerhalb privater Netze sperren (Pfad und Netze anpassen) |
| „API: nur JSON“ | Schreibende Anfragen auf /api/ ohne JSON mit 415 ablehnen |
| „Nextcloud / WebDAV“ | Typische CRS-Fehlalarme für WebDAV-Methoden und Sync-Clients ausnehmen |
| „Login-Schutz“ | SQL-Injection in Login-Formularen blockieren; mit einem Ratelimit auf den Login-Pfad kombinieren |

Im Editor eines Regelsatzes bearbeitest du „Name“, „Beschreibung“ und die Regeln (gleicher Builder wie in 5.14). „Verwendet in“ zeigt die Policies. „Testen“ übergibt die Regeln an den WAF-Tester. Einen Regelsatz, den noch eine Policy verwendet, kannst du nicht löschen.

So setzt du einen Regelsatz ein:

1. Lege den Regelsatz an oder wähle eine Vorlage.
2. Prüfe ihn mit „Testen“ im WAF-Tester.
3. Aktiviere ihn unter *Policies › <Policy> › WAF › Regelsätze*.
4. Speichere die Policy.

Die Regeln eines Regelsatzes laufen nach der CRS-Initialisierung und vor den CRS-Prüfungen.

#### WAF-Tester

Unter *Schutz › WAF-Tester* schickst du eine Test-Anfrage durch die WAF einer Policy, ohne dass sie Caddy erreicht. Alle Rollen dürfen den Tester verwenden.

| Feld | Bedeutung | Standard |
|---|---|---|
| „Konfiguration“ | „Nur OWASP CRS (Paranoia 1, blockieren)“ oder „Policy: <Name>“ (gespeicherter Stand mit Regelsätzen und eigenen Regeln) | erste Policy |
| „Client-IP“ | Absender der Test-Anfrage | 203.0.113.10 |
| „Methode“ | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, PROPFIND | GET |
| „URL (Pfad und Query)“ | z. B. `/suche?q=test` | `/` |
| „Header (eine Zeile pro Header)“ | `Name: Wert` | leer |
| „Body“ | Formulardaten oder JSON | leer |

„Request prüfen“ startet den Test; Enter im URL-Feld ebenso. Die Knöpfe unter „Beispiele:“ („Harmlos“, „SQL-Injection“, „XSS“, „Path Traversal“, „Command Injection“, „Log4Shell“, „Scanner“, „JSON-SQLi“) füllen das Formular und prüfen sofort. Eine Policy mit WAF „Aus“ wird im Blockiermodus getestet.

Ergebnis:

- „Blockiert“ – mit Status und auslösender Regel,
- „Würde blockiert“ – die Policy ist im Erkennungsmodus, im Blockiermodus würde die Anfrage abgelehnt,
- „Treffer, aber durchgelassen“ – Anomalie-Score unter der Schwelle,
- „Durchgelassen“ – keine Regel hat angeschlagen.

Dazu „Anomalie-Score“, „Treffer“, „Prüfdauer“ und die Tabelle „Angeschlagene Regeln“. Der Tester prüft nur die WAF; den kompletten Weg einer Anfrage durch alle Prüfungen zeigt der Request-Fluss (siehe Kapitel 4).

**Tipp:** Prüfe mit dem WAF-Tester jede neue eigene Regel und jede Ausnahme mit einer harmlosen und einer bösartigen Beispielanfrage.

### 5.16 Threat-Feeds

Threat-Feeds sind IP-Listen bekannter Angreifer, Botnetze oder Anonymisierungsdienste. Sentinel lädt sie regelmäßig, verteilt sie an Caddy und prüft jede Anfrage dagegen. Was mit Treffern geschieht, legst du pro Policy fest (siehe 5.9). Feeds verwaltest du unter *Schutz › Threat-Feeds*; ändern dürfen Bearbeiter und Administratoren.

„Aktive Listen“ zeigt „Liste“, „Quelle“ (URL oder „manuell“), „Einträge“, „Aktualisiert“ (mit letztem Fehler), „Verwendet in“ und die Knöpfe „Jetzt laden“ und „Bearbeiten“.

Unter „Bekannte Listen“ aktivierst du vorbereitete Listen mit „Aktivieren“:

| Liste | Inhalt | Aktualisierung |
|---|---|---|
| FireHOL Level 1 | Bösartige Netze aus vielen Quellen, sehr wenige Fehlalarme. Gut als Blockliste. | alle 12 h |
| Spamhaus DROP | Gekaperte und von Kriminellen kontrollierte Netze (Don't Route Or Peer) | alle 12 h |
| abuse.ch Feodo Tracker | Botnetz-Command-and-Control-Server (Dridex, Emotet, QakBot …) | alle 6 h |
| blocklist.de (alle) | In den letzten 48 h gemeldete Angreifer (SSH, Mail, Web). Eher für Challenge statt Block. | alle 4 h |
| Emerging Threats: kompromittiert | Bekannte kompromittierte Hosts | alle 12 h |
| Tor-Exit-Knoten | Ausgangsknoten des Tor-Netzwerks. Eher für Challenge oder Protokollierung. | alle 2 h |

**Achtung:** Beachte die Nutzungsbedingungen der Anbieter (z. B. Spamhaus: nicht-kommerziell frei). Sentinel prüft sie nicht.

So legst du eine eigene Liste an:

1. Klicke „Eigene Liste anlegen“.
2. Trage „Name“ und „Beschreibung“ ein.
3. Trage entweder eine „Download-URL“ (http/https) ein oder lass sie leer und gib die IPs und Netze im Textfeld ein, eine pro Zeile (`#` leitet Kommentare ein).
4. Lege bei einer URL „Aktualisieren alle (Min.)“ fest (mindestens 15, Standard 360).
5. Lass „Aktiv – an Caddy verteilen“ eingeschaltet und klicke „Speichern“.
6. Wähle in den Policies unter *Geo & Feeds › Threat-Feeds* die Aktion für die Liste.

Liefert ein Download keine gültigen Adressen oder schlägt er fehl, bleibt die vorige Version in Kraft und der Fehler erscheint in der Übersicht. Ein fehlgeschlagener erster Download wird alle 10 Minuten wiederholt. Abgeschaltete Listen werden nicht an Caddy verteilt und wirken nicht. Eine Liste, die noch eine Policy verwendet, kannst du nicht löschen.

**Tipp:** Nutze Listen mit vielen dynamischen IPs (blocklist.de, Tor) für „Challenge“ oder „markieren“, nicht für harte Sperren. Für harte Sperren eignen sich FireHOL Level 1 und Spamhaus DROP.

### 5.17 Tab „Header“

Im Panel „Sicherheits-Header“ setzt Sentinel Sicherheits-Header auf alle durchgelassenen Antworten dieser Policy (nicht auf Sperrseiten).

| Feld | Bedeutung | Standard (neue Policy) |
|---|---|---|
| „Aktiv“ | Header setzen | aus |
| „HSTS“ | `Strict-Transport-Security: max-age=31536000; includeSubDomains`, nur bei HTTPS | an |
| „nosniff“ | `X-Content-Type-Options: nosniff` | an |
| „Server-Header“ | „entfernen“ | an |
| „X-Frame-Options“ | „nicht setzen“, DENY oder SAMEORIGIN | SAMEORIGIN |
| „Referrer-Policy“ | „nicht setzen“, no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin, no-referrer-when-downgrade | strict-origin-when-cross-origin |
| „Permissions-Policy“ | z. B. `camera=(), microphone=(), geolocation=()` | leer |
| „Content-Security-Policy“ | z. B. `default-src 'self'`. Leer lassen, wenn die Anwendung selbst eine CSP setzt. | leer |

**Achtung:** HSTS mit `includeSubDomains` zwingt Browser ein Jahr lang auf HTTPS – auch für alle Subdomains. Schalte HSTS nur ein, wenn alle Subdomains per HTTPS erreichbar sind.

### 5.18 Tab „IDS“

Hier passt du die Bedrohungserkennung für Anfragen an diese Policy an: „Automatische Sperren“ ein/aus, eigene „Sperr-Schwelle“ und eigene Gewichte pro Signal. Die Felder beschreibt Kapitel 6.7.

### 5.19 Befristete Einträge

Befristete Einträge sind Freigaben und Sperren mit Enddatum, z. B. „diese IP eine Stunde lang dulden“ oder „das Partnernetz bis Freitag zulassen“. Sie gelten sofort, ohne dass du eine Policy speicherst, und Sentinel entfernt sie nach Ablauf selbst. Du erstellst sie in *Policies › <Policy> › Zugriff › Befristete Einträge* („Befristet eintragen …“), unter *Schutz › Sicherheit* und im IP-Steckbrief (siehe Kapitel 4).

| Liste | Gilt für | Wirkung | Rolle |
|---|---|---|---|
| „Vertrauenswürdig“ | alle Sites (global) | alle Prüfungen werden übersprungen, auch Sperren | Administrator |
| „Nie sperren“ | alle Sites (global) | die Bedrohungserkennung sperrt die Adresse nicht automatisch | Support, Bearbeiter, Administrator |
| „Erlaubt-Liste“ | eine Policy | zählt im Modus „Nur Freigabeliste zulassen“ als freigegeben | Bearbeiter, Administrator |
| „Sperrliste“ | eine Policy | wird für diese Policy blockiert | Bearbeiter, Administrator |

Support und Bearbeiter sehen für „alle Sites (global)“ nur „Nie sperren“.

So legst du einen befristeten Eintrag an:

1. Klicke „Befristet eintragen …“.
2. Trage unter „IP oder Netz“ die Adresse ein (z. B. `203.0.113.7` oder `198.51.100.0/24`).
3. Wähle unter „Gilt für“ „alle Sites (global)“ oder eine Policy und dann die „Liste“.
4. Lege „Endet“ fest (Standard: in einer Stunde; höchstens ein Jahr).
5. Trage unter „Notiz (warum?)“ den Anlass ein (z. B. Pentest der Firma X, Ticket #4711).
6. Klicke „Eintragen“.

Die Tabelle zeigt „Adresse“, „Liste“, „Gilt für“, „Bis“ und „Notiz“ mit Autor und Zeitpunkt. „Beenden“ entfernt einen Eintrag vorzeitig. Anlegen, Ablauf und vorzeitiges Entfernen stehen im Ereignisprotokoll.

**Hinweis:** Einträge in der „Erlaubt-Liste“ wirken nur, wenn die Policy im Modus „Nur Freigabeliste zulassen“ steht.

**Tipp:** Verwende für Dienstleister, Pentests und vorübergehende Ausnahmen immer befristete Einträge statt der dauerhaften Listen. So bleibt nichts aus Versehen offen.

### 5.20 Policy-Bereiche übertragen

„Übertragen …“ übernimmt Bereiche der gespeicherten Policy in andere Policies. Wählbar sind: „IP-Listen“, „Geo & Threat-Feeds“, „Filter (Methoden, User-Agents, Honeypots, Größe)“, „Bots & Crawler“, „Ratelimits (gleiche Namen ersetzt, neue ergänzt)“, „Pfad-Regeln (gleiche Namen ersetzt, neue ergänzt)“, „WAF (Modus, CRS, Regelsätze, eigene Regeln, Ausnahmen)“, „Bot-Challenge“, „Anmeldung (ohne Seitentitel)“, „Sicherheits-Header“, „Sperrseite (Status, Meldung)“, „IDS-Anpassungen“, „Wartungsmodus“. Die Testmodus-Schalter wandern mit dem jeweiligen Bereich. Vor dem Übernehmen zeigt das Panel die Änderungen je Ziel-Policy. Die Vorschau sehen alle Rollen; übernehmen dürfen Bearbeiter und Administratoren.

**Achtung:** Beim Übertragen von Pfad-Regeln werden auch deren API-Schlüssel übernommen. Derselbe Schlüssel öffnet danach auch den Bereich in der Ziel-Policy.

### 5.21 Empfehlungen für den Einstieg

1. Ordne jede Site einer Policy zu; gib dem Panel selbst und wichtigen Anwendungen eigene Policies.
2. Lass die WAF zuerst im Modus „Erkennen (nur melden)“ laufen, beseitige Fehlalarme mit dem Fehlalarm-Assistenten und stelle dann auf „Blockieren“.
3. Trage dein Büro- oder IT-Netz unter *Einstellungen › Netz & Vertrauen › Nie automatisch sperren* ein (siehe Kapitel 6); vertrauenswürdig nur für Quellen, die wirklich alle Prüfungen umgehen sollen (z. B. Monitoring).
4. Setze ein großzügiges allgemeines Ratelimit und strenge Limits auf Login-Pfade.
5. Führe neue Sperren im Testmodus ein und prüfe vor dem Speichern „Auswirkung prüfen“.
6. Nimm APIs und Webhooks per Pfad-Regel von Challenge und Anmeldung aus (API-Schlüssel statt Login).
7. Steht Caddy hinter einem Proxy oder Cloudflare, trage dessen Netze in Caddy unter `trusted_proxies` ein; sonst sieht Sentinel nur die Proxy-Adresse und sperrt im Zweifel den Proxy.

## 6. Bedrohungserkennung (IDS)

Die Bedrohungserkennung (IDS) bewertet jede Client-IP anhand ihres Verhaltens. Jedes verdächtige Ereignis – ein WAF-Treffer, ein Honeypot-Aufruf, eine Folge von 404-Antworten, ein Ratelimit-Treffer – gibt Punkte. Der Punktestand (Bedrohungs-Score) sinkt mit der Zeit wieder. Erreicht eine IP die Challenge-Schwelle, muss sie auf entsprechend eingestellten Policies die Bot-Challenge lösen; erreicht sie die Sperr-Schwelle, sperrt Sentinel sie automatisch auf allen Sites (IPS).

Die globalen Einstellungen findest du unter *Einstellungen › Bedrohungserkennung*; ändern dürfen sie nur Administratoren. Anpassungen pro Policy machst du unter *Policies › <Policy> › IDS* (Bearbeiter und Administratoren). Die aktuell auffälligen IPs, Sperren und Ereignisse zeigt *Schutz › Sicherheit*, den Score einer einzelnen IP der IP-Steckbrief (siehe Kapitel 4).

### 6.1 Funktionsweise

1. Jede Caddy-Instanz meldet sicherheitsrelevante Anfragen an das Panel (Sperren, WAF-Treffer, 4xx/5xx-Antworten; normale Anfragen gemäß Stichprobenrate, siehe Kapitel 10).
2. Das Panel ordnet jedem Ereignis ein Signal zu und addiert dessen Gewicht zum Score der IP. Es gelten die Gewichte der Policy, über die die Anfrage lief.
3. Der Score halbiert sich in der eingestellten Halbwertszeit (Standard 15 Minuten). Wer nur gelegentlich auffällt, erreicht die Schwellen nie.
4. Ab „Bot-Challenge ab Score“ (Standard 40) und unter der Sperr-Schwelle setzt Sentinel die IP für die „Challenge-Dauer“ auf die Challenge-Liste. Sie wirkt auf Policies mit dem Challenge-Modus „Auch für verdächtige IPs“ (siehe Kapitel 5.11).
5. Ab der Sperr-Schwelle (Standard 100) sperrt Sentinel die IP auf allen Sites. Der Score wird danach zurückgesetzt.

Nicht gesperrt werden Adressen unter „Nie automatisch sperren“, vertrauenswürdige Quellen und befristete globale Einträge („Vertrauenswürdig“, „Nie sperren“). Ihr Score wird trotzdem angezeigt.

Anfragen, die im Testmodus einer Policy nur protokolliert werden („Test: …“), geben keine Punkte (siehe Kapitel 5.5). Erkannte Angriffstools und Request-Bursts zählen unabhängig davon.

### 6.2 Globale Einstellungen

Panel „Automatische Sperren (IPS)“:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Bedrohungserkennung aktiv“ | Schaltet die Bewertung insgesamt ein oder aus | an |
| „Testmodus (nur melden, nicht sperren)“ | Statt zu sperren erzeugt Sentinel das Ereignis „Testmodus: <IP> würde gesperrt (…)“ und setzt den Score zurück | aus |
| „Sperr-Schwelle (Punkte)“ | Ab diesem Score wird gesperrt | 100 |
| „Halbwertszeit des Scores (Min.)“ | So schnell „vergisst“ Sentinel verdächtiges Verhalten | 15 |
| „Erste Sperre (Min.)“ | Dauer der ersten automatischen Sperre | 60 |
| „Faktor je Wiederholung“ | Dauer = Erste Sperre × Faktor^(frühere Sperren) | 3 |
| „Maximale Sperre (Tage)“ | Obergrenze der Sperrdauer | 30 |
| „Dauerhaft ab Sperre Nr.“ | Ab der n-ten Sperre wird dauerhaft gesperrt; 0 = nie dauerhaft | 0 |
| „Burst: Requests“ | Mehr Anfragen einer IP im Fenster zählen als Signal „Request-Burst“; 0 = aus | 0 |
| „Burst: Fenster (s)“ | Fensterlänge für die Burst-Erkennung | 60 |
| „Bot-Challenge ab Score“ | Ab diesem Score müssen IPs auf Policies mit Challenge-Modus „Auch für verdächtige IPs“ die Bot-Challenge lösen; 0 = aus | 40 |
| „Challenge-Dauer (Min.)“ | So lange bleibt eine IP auf der Challenge-Liste (verlängert sich, solange weitere Anfragen der IP im Score-Bereich eintreffen) | 60 |
| „IPv6-Sperren für“ | Was eine Sperre bei IPv6 erfasst: „das /64-Netz des Clients“, /56, /48 oder „nur die einzelne Adresse“. Gilt für IDS-Sperren und Ratelimit-Sperren. | /64 |

Liegt die Challenge-Schwelle nicht unter der Sperr-Schwelle, greift die Challenge nie; das Panel zeigt dann eine Warnung.

Panel „Gewichtung der Signale“: Punkte pro Ereignis für jedes Signal (siehe 6.3). „Standardgewichte wiederherstellen“ setzt alle Gewichte zurück.

Panel „Angriffstools (User-Agent-Teilstrings)“: Liste von Teilstrings, an denen Sentinel Angriffswerkzeuge erkennt (Groß-/Kleinschreibung egal). Vorbelegt sind u. a. sqlmap, nikto, nmap, masscan, zgrab, nuclei, wpscan, dirbuster, gobuster, ffuf, feroxbuster, wfuzz, acunetix, netsparker, nessus, openvas, w3af, hydra, whatweb, commix, arachni, skipfish, xsstrike, censysinspect.

Unter *Einstellungen › Netz & Vertrauen* stehen außerdem:

- „Vertrauenswürdige Quellen“ – IPs und Netze, die alle Sentinel-Prüfungen umgehen (Sperren, WAF, Ratelimits),
- „Nie automatisch sperren“ – „Das IDS sperrt diese Adressen nie, Policies gelten aber weiter.“ Vorbelegt: `127.0.0.0/8`, `::1`.

**Tipp:** Trage die Netze deiner IT, deines Büros und deiner Monitoring-Systeme unter „Nie automatisch sperren“ ein. So sperrt ein Fehlalarm nicht die eigenen Leute aus, während Policy-Regeln weiter gelten. „Vertrauenswürdig“ ist dafür meist zu weitgehend, weil dann auch WAF und Anmeldung entfallen.

**Tipp:** Schalte nach der Installation zunächst den „Testmodus (nur melden, nicht sperren)“ ein, beobachte die Meldungen einige Tage und passe Gewichte an, bevor Sentinel wirklich sperrt.

### 6.3 Signale und Standardgewichte

| Signal | Anzeige in den Einstellungen | Gewicht | Ausgelöst durch |
|---|---|---|---|
| waf_block | „WAF-Block“ | 35 | Anfrage von der WAF blockiert |
| waf_detect | „WAF-Treffer (je 5 Score)“ | 8 | WAF-Treffer ohne Blockade (Erkennungsmodus oder unter der Schwelle) mit WAF-Score ab 5; Punkte = Gewicht × Score/5, höchstens das Vierfache |
| honeypot | „Honeypot-Treffer“ | 100 | Aufruf eines Honeypot-Pfads |
| not_found | „404-Antwort“ | 4 | 404 des Backends |
| auth_fail | „401/403 / Login fehlgeschlagen“ | 10 | fehlgeschlagene Anmeldung bei Sentinel, fehlender oder falscher API-Schlüssel, ungültiges Zugriffstoken, 401/403 des Backends |
| path_block | „Pfad-Sperre (Regel)“ | 15 | Pfad-Regel „Sperren“ |
| bad_request | „400-Antwort“ | 3 | 400 des Backends |
| scanner_ua | „Angriffstool erkannt“ | 60 | User-Agent aus der Liste der Angriffstools (höchstens einmal in 10 Minuten pro IP) |
| rate_limit | „Ratelimit überschritten“ | 10 | 429 eines Ratelimits |
| user_agent | „Gesperrter User-Agent“ | 30 | gesperrter User-Agent der Policy |
| method | „Unerlaubte Methode“ | 8 | 405 wegen nicht erlaubter Methode |
| ip_deny | „IP-Sperrliste“ | 2 | Sperr- oder Freigabeliste der Policy, „Nur aus Netzen erreichbar“ |
| burst | „Request-Burst“ | 50 | mehr Anfragen als „Burst: Requests“ im Fenster (höchstens einmal pro Fenster) |
| body_limit | „Body zu groß“ | 10 | 413 wegen Body-Größe |
| geo_block | „Geo-Sperre“ | 2 | Länder- oder Netzregel blockiert |
| feed_block | „Threat-Feed-Block“ | 20 | Threat-Feed blockiert |
| challenge | „Challenge ausgeliefert“ | 1 | Bot-Challenge ausgeliefert |
| bot_fake | „Gefälschter Suchmaschinen-Bot“ | 40 | angebliche Suchmaschine, Reverse-DNS passt nicht |
| bot | „Crawler gesperrt/gebremst“ | 0 | KI- oder SEO-Crawler gesperrt oder gebremst |

Keine Punkte geben: Wartungsseite, Weiterleitungen, Aufrufe ohne Anmeldung (Weiterleitung zur Anmeldeseite), erfolgreiche Anmeldungen, angemeldete Benutzer ohne Berechtigung, Feed-Markierungen und Test-Treffer.

Ein Gewicht von 0 schaltet ein Signal ab.

#### Mehrfachzählung wird begrenzt

Viele Anwendungen fragen dieselbe Adresse immer wieder ab (Sitzungsprüfung, fehlendes favicon, Polling). Damit dabei nicht die eigenen Besucher gesperrt werden, zählt Sentinel manche Signale nur einmal pro Zeitraum:

- 404, 400 und 401/403 des Backends bei GET, HEAD und OPTIONS sowie WAF-Treffer im Erkennungsmodus zählen je IP und Pfad nur einmal in 10 Minuten,
- Ratelimit-Treffer zählen je IP und Limit einmal pro Minute,
- fehlgeschlagene Anmeldungen (401/403 bei POST und anderen schreibenden Methoden) und Sentinels eigene Anmeldefehler zählen jedes Mal.

Ein Scanner, der viele verschiedene Pfade abfragt, sammelt dagegen schnell Punkte.

**Hinweis:** Die Burst-Erkennung zählt die an das Panel gemeldeten Anfragen. Ist unter *Einstellungen › Telemetrie & Speicher* eine Stichprobenrate unter 100 % eingestellt, erkennt sie Bursts entsprechend später.

### 6.4 Sperren und Eskalation

Erreicht eine IP die Sperr-Schwelle, legt Sentinel eine Sperre an. Sie gilt auf allen Sites aller Caddy-Instanzen mit `sentinel`, unabhängig von der Policy, und wird mit 403 beantwortet. Ausnahme: Stammen alle Punkte einer IP aus den Meldungen **einer einzigen entfernten Instanz**, gilt die Sperre nur dort (in der Liste „nur <Instanz>“). Ein übernommener Server kann so keine Adressen auf allen anderen Servern aussperren. Meldet eine zweite Instanz dieselbe IP, die lokale Instanz oder sperrst du von Hand, gilt die Sperre überall. Als Grund steht „Bedrohungs-Score: …“ mit den drei stärksten Signalen in der Sperre.

Die Sperrdauer wächst mit jeder Wiederholung:

Dauer = „Erste Sperre“ × „Faktor je Wiederholung“^(Anzahl früherer Sperren), höchstens „Maximale Sperre“. Als frühere Sperren zählen alle Sperren dieser IP – auch manuelle und Ratelimit-Sperren –, die weniger als 12 Monate zurückliegen.

Mit den Standardwerten: 1 Stunde, 3 Stunden, 9 Stunden, 27 Stunden, 81 Stunden … bis 30 Tage. Ist „Dauerhaft ab Sperre Nr.“ gesetzt, wird ab dieser Sperre dauerhaft gesperrt. Bei Wiederholung ergänzt Sentinel den Grund um „Wiederholungstäter (n. Sperre)“.

Jede Sperre erzeugt ein Ereignis und eine Benachrichtigung (siehe Kapitel 11). Abgelaufene Sperren entfernt Sentinel selbst und vermerkt „Sperre abgelaufen“. Hebst du eine Sperre auf, setzt Sentinel auch den Score der IP zurück und die Caddy-Instanzen heben eine zugehörige lokale Ratelimit-Sperre auf.

**Hinweis:** Sperrt ein Ratelimit („429 + IP sperren“) eine Adresse unter „Nie sperren“, übernimmt das Panel diese Sperre nicht; der Agent hält sie trotzdem bis zum Ablauf der Sperrdauer des Limits. Für solche Adressen das Limit auf „429“ stellen.

Sperren ansehen, manuell setzen und aufheben kannst du unter *Schutz › Sicherheit* und im IP-Steckbrief (siehe Kapitel 4). Das dürfen Support, Bearbeiter und Administratoren.

#### Sperren aus Ratelimits

Ein Ratelimit mit „429 + IP sperren“ (siehe Kapitel 5.8) sperrt die IP zuerst lokal auf der Caddy-Instanz. Das Panel übernimmt diese Sperre mit derselben Dauer (mindestens 1 Minute, höchstens „Maximale Sperre“, nie dauerhaft) als Sperre („Ratelimit überschritten: <Name>“) – für alle Instanzen, wenn sie von der lokalen Instanz kommt, sonst nur für die meldende Instanz – sofern die Bedrohungserkennung aktiv ist, nicht im Testmodus läuft, für die Policy nicht abgeschaltet ist und die IP nicht unter „Nie automatisch sperren“ fällt. Die Dauer einer solchen Sperre wird nicht eskaliert.

**Hinweis:** Die lokale Sperre auf der Caddy-Instanz greift in jedem Fall, auch für Adressen unter „Nie automatisch sperren“ und im Testmodus der Bedrohungserkennung. Nur vertrauenswürdige Quellen sind ausgenommen.

Bei IPv6 sperrt das IDS das ganze Netz des Clients, Standard /64 (Einstellung „IPv6-Sperren für“: /64, /56, /48 oder nur die einzelne Adresse). Ein /64 gehört praktisch immer zu einem Anschluss; wer nur die Adresse sperrt, lässt den Client mit der nächsten Adresse weitermachen. Liegt die Adresse in einem Netz unter „Nie sperren“, sperrt das IDS nichts.

### 6.5 Testmodus der Bedrohungserkennung

Mit „Testmodus (nur melden, nicht sperren)“ bewertet Sentinel weiter, sperrt aber nicht. Erreicht eine IP die Schwelle, entsteht das Ereignis „Testmodus: <IP> würde gesperrt (…)“ mit Score und Grund, und eine Benachrichtigung wird verschickt. Die Challenge-Liste bleibt aktiv.

So führst du die automatischen Sperren ein:

1. Schalte unter *Einstellungen › Bedrohungserkennung* den Testmodus ein und speichere.
2. Prüfe einige Tage lang die Ereignisse „würde gesperrt“ unter *Schutz › Sicherheit*.
3. Trifft es legitime Clients, trage deren Netze unter „Nie automatisch sperren“ ein oder senke die Gewichte der auslösenden Signale (global oder in der betroffenen Policy).
4. Schalte den Testmodus aus.

### 6.6 Typische Anpassungen

| Situation | Anpassung |
|---|---|
| API oder Single-Page-App mit vielen legitimen 404 | In der Policy das Gewicht „404“ auf 0 setzen |
| Interne Anwendung, Anmeldefehler sind normal | In der Policy das Gewicht „401/403 / Login fehlgeschlagen“ senken |
| Viele Fehlalarme im WAF-Erkennungsmodus | Fehlalarme mit Ausnahmen beheben (Kapitel 5.14); vorübergehend das Gewicht „WAF-Treffer“ senken |
| Crawler sollen nach Sperre auch gesperrt werden | Gewicht „Crawler gesperrt/gebremst“ erhöhen |
| Scanner werden zu spät gesperrt | „Request-Burst“ einschalten oder Sperr-Schwelle senken |
| Bekannte Angreifer erst testen, dann sperren | Challenge-Modus „Auch für verdächtige IPs“ in den Policies, Challenge-Schwelle deutlich unter der Sperr-Schwelle |

### 6.7 Anpassungen pro Policy

Unter *Policies › <Policy> › IDS* (Panel „IDS für diese Policy“) überschreibst du die globalen Werte für Anfragen, die über diese Policy laufen:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Automatische Sperren“ | „Bedrohungserkennung für Requests dieser Policy“. Aus = Anfragen dieser Policy werden gar nicht bewertet; auch Sperren aus Ratelimits werden nicht als globale Sperre übernommen. | an |
| „Sperr-Schwelle“ | Eigene Schwelle für diese Policy; 0 = global | 0 |
| Gewicht je Signal | „Punkte pro Ereignis“. Leeres Feld = globaler Wert (als Platzhalter angezeigt); 0 schaltet das Signal für diese Policy ab. | leer |

Die Signalnamen sind hier verkürzt („404“, „400“, „Honeypot“, „Scanner-Tool“, „Ratelimit“, „Gesperrter UA“ usw.), meinen aber dieselben Signale wie in 6.3.

Der Score einer IP ist global: Punkte aus allen Policies addieren sich. Die Policy bestimmt nur, wie viele Punkte ein Ereignis auf ihren Sites gibt und ab welchem Score eine Anfrage über diese Policy zur Sperre führt.

**Achtung:** „Automatische Sperren“ auszuschalten nimmt einer Site den Schutz durch das IPS. Senke stattdessen gezielt einzelne Gewichte.

**Tipp:** Für eine API mit vielen legitimen 404 setzt du das Gewicht „404“ der Policy auf 0, statt die Erkennung ganz abzuschalten.

## 7. Anmeldung und Zugriff

Caddy Sentinel kennt zwei voneinander getrennte Anmeldungen:

| | Site-Login | Panel-Anmeldung |
|---|---|---|
| Schützt | beliebige Sites hinter Caddy, pro Policy | das Sentinel-Panel selbst |
| Konten | Active-Directory-/LDAP-Konten, Zugangskonten (lokal in Sentinel), Konten von OAuth/OIDC-Anbietern | lokale Panel-Benutzer, optional AD-Konten und OAuth/OIDC-Konten |
| Zweiter Faktor | TOTP, pro Policy oder Pfad-Regel verlangt | TOTP für lokale Benutzer freiwillig, für AD-Konten per Schalter (Standard: verlangt) |
| Sitzung | signiertes Cookie, Prüfung direkt in Caddy | Sitzung auf dem Panel |
| Tokens | „Zugriffstokens“ `sst_…` für geschützte Sites | „API-Tokens“ `spt_…` für die Panel-API |

Den Site-Login verwaltest du unter *Site-Login & Konten* (Menügruppe „Schutz“) mit den Reitern „Übersicht“, „Konten“, „Zugriffstokens“, „Anmeldeprotokoll“, „Self-Service“, „OAuth / OIDC“, „Verzeichnis (AD)“ und „OIDC-Server“ (Sentinel als Anmeldedienst für Anwendungen, Kapitel 7.14). Ob eine Site eine Anmeldung verlangt, legst du in der Policy im Reiter „Anmeldung“ fest. Die Panel-Anmeldung steuern *Einstellungen › Benutzer*, *Einstellungen › Konto & Sicherheit* und *Einstellungen › API-Tokens*.

Einstellungen und Konten des Site-Logins darf nur ein Administrator ändern. Die anderen Rollen sehen die Übersicht, die Konten und das Anmeldeprotokoll nur lesend. Die Login-Einstellungen einer Policy darf dagegen jede Rolle mit Policy-Rechten ändern, also auch Bearbeiter (siehe Kapitel 12).

### 7.1 So funktioniert der Site-Login

1. Ein Besucher ruft eine geschützte Site ohne gültige Sitzung auf. Sentinel leitet ihn zur Anmeldeseite unter `/.sentinel/auth/login` weiter. Die Seite liegt auf der Adresse der Site selbst.
2. Jeden Anmeldeschritt reicht Sentinel an das Panel weiter. Das Panel fragt das Verzeichnis ab, prüft die Passwörter der Zugangskonten und verwaltet die TOTP-Schlüssel.
3. Nach erfolgreicher Anmeldung stellt das Panel die Sitzung aus und signiert sie mit seinem eigenen Schlüssel (Ed25519); Sentinel setzt sie als Cookie. Caddy prüft das Cookie bei jeder weiteren Anfrage selbst mit dem öffentlichen Schlüssel des Panels. Eine Caddy-Instanz kann Sitzungen also prüfen, aber keine ausstellen. Das Panel wird erst bei der nächsten Anmeldung oder beim Abmelden wieder gefragt.

Daraus folgt:

- Ist das Panel nicht erreichbar, sind keine neuen Anmeldungen möglich („Der Anmeldedienst ist gerade nicht erreichbar. Bitte später erneut versuchen.“). Wer schon angemeldet ist, arbeitet weiter.
- Hat Caddy noch nie einen Stand vom Panel erhalten (erster Start ohne Panel, keine Cache-Datei), lässt der Agent Anfragen ohne Anmeldung durch – mit der globalen Option `fail_closed` antwortet er stattdessen mit 503 (siehe Kapitel 1.2). Liegt ein Stand vor, fehlt aber das Signiergeheimnis, antwortet eine geschützte Site mit 503 („Anmeldung derzeit nicht möglich (keine Verbindung zum Sentinel-Panel).“).
- Ein Administrator kann Sitzungen widerrufen, etwa über „Abmelden“, „Sperren“, einen Passwortwechsel oder das Ablaufdatum eines Kontos. Der Widerruf erreicht alle Caddy-Server innerhalb weniger Sekunden.
- Die Sentinel-Cookies (`__sentinel_…`) und Zugriffstokens (`Authorization: Bearer sst_…`) entfernt Sentinel immer, bevor eine Anfrage ans Backend geht. Das gilt auch auf Pfaden ohne Anmeldung.

Auf jeder Site, deren Policy oder Pfad-Regeln eine Anmeldung verlangen, gibt es diese Adressen:

| Adresse | Zweck |
|---|---|
| `/.sentinel/auth/login` | Anmeldeseite |
| `/.sentinel/auth/logout` | Abmelden (ein Link zeigt eine Bestätigung, abgemeldet wird erst mit dem Knopf) |
| `/.sentinel/auth/me` | Kontoseite „Mein Konto“, mit `Accept: application/json` als JSON |
| `/.sentinel/auth/reset` | „Passwort vergessen“ |

**Achtung:** Global eingetragene „Vertrauenswürdige Quellen“ (siehe Kapitel 10) und ausgeschaltete Policies verlangen keine Anmeldung.

### 7.2 Anmeldemethoden einrichten

Eine Site lässt sich erst schützen, wenn mindestens eine Anmeldemethode existiert. Das kann ein verbundenes Active Directory sein, ein Zugangskonto oder ein aktiver OAuth-Anbieter mit Site-Login. Fehlt jede Methode, lehnt Sentinel das Speichern einer Policy mit aktivierter Anmeldung ab. Die „Übersicht“ zeigt dann den Hinweis „Noch keine Anmeldemethode“ und verlinkt die drei Wege.

#### 7.2.1 Active Directory / LDAP verbinden

1. Öffne *Site-Login & Konten › Verzeichnis (AD)*.
2. Fülle das Panel „Active Directory / LDAP“ aus:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Verzeichnis“ | schaltet die Anmeldung mit Domänenkonten ein | aus |
| „Server“ | ein Server pro Zeile, weitere Server dienen als Ausfallreserve; ohne Angabe des Schemas wird `ldaps://` ergänzt | – |
| „StartTLS“ | verschlüsselt Verbindungen über `ldap://` | aus |
| „Zertifikat“ – „nicht prüfen (nur zum Testen)“ | schaltet die Zertifikatsprüfung ab | aus |
| „CA-Zertifikat der Domänencontroller“ | PEM der internen Zertifizierungsstelle, wenn der Server ihr nicht vertraut | leer |
| „Dienstkonto (Bind-DN)“ | Lesekonto für die Benutzersuche, als DN oder `svc@firma.local` | leer (anonym) |
| „Passwort des Dienstkontos“ | leer lassen, um das gespeicherte zu behalten | – |
| „Base-DN“ | Startpunkt der Suche, Pflicht | – |
| „Benutzerfilter“ | `{user}` steht für den Namen ohne Domäne (aus `FIRMA\max` oder `max@firma.local`), `{input}` für die Eingabe, wie sie getippt wurde; „Standard wiederherstellen“ setzt den Standardfilter zurück | findet aktive AD-Konten über sAMAccountName oder UPN |
| „Attribut Benutzername“ | | `sAMAccountName` |
| „Attribut Anzeigename“ | | `displayName` |
| „Attribut E-Mail“ | | `mail` |
| „Gruppen“ – „verschachtelte Gruppen auflösen (AD)“ | berücksichtigt auch indirekte Mitgliedschaften | an |
| „Timeout (s)“ | 1–60 | 8 |

3. Prüfe die Einstellungen im Panel „Verbindung testen“. Der Test verwendet die Werte aus dem Formular, auch wenn sie noch nicht gespeichert sind:
   - „Verbindung & Dienstkonto prüfen“ testet die Verbindung, die Dienstkonto-Anmeldung und den Base-DN.
   - „Benutzer suchen“ zeigt zu einem Namen das Konto, den DN, die E-Mail-Adresse und die Gruppen an. Außerdem listet es, auf welche geschützten Policies das Konto zugreifen darf („Darf auf“) und auf welche nicht („Kein Zugriff“). Ist die Panel-Anmeldung mit AD aktiv, zeigt es auch die Panel-Rolle.
   - „Anmeldung testen“ macht dasselbe zusätzlich mit dem eingegebenen Passwort.
4. Klicke auf „Speichern“.

**Tipp:** Bevorzuge `ldaps://` (Port 636). Bei `ldap://` schalte immer „StartTLS“ ein.

**Hinweis:** Fehlgeschlagene AD-Anmeldungen zeigen dem Benutzer immer nur „Benutzername oder Passwort falsch“. Den genauen Grund, etwa „Passwort abgelaufen“, „Konto deaktiviert“, „Konto gesperrt“ oder „Passwort muss geändert werden“, findest du im „Anmeldeprotokoll“. Solche Fälle löst der Benutzer in Windows oder die IT im Active Directory.

AD-Konten erscheinen unter „Konten“ nach ihrer ersten erfolgreichen Anmeldung. Anzeigename, E-Mail-Adresse und Gruppen übernimmt Sentinel bei jeder Anmeldung aus dem Verzeichnis.

#### 7.2.2 Zugangskonten (lokal in Sentinel)

Zugangskonten sind für Personen ohne Domänenkonto gedacht, zum Beispiel externe Dienstleister oder Partner, und für Notfallzugänge oder Dienstkonten mit Zugriffstoken. Ihr Passwort und ihre Gruppen liegen in Sentinel.

1. Öffne *Site-Login & Konten › Konten* und klicke auf „Zugangskonto anlegen“ (Administrator).
2. Fülle den Dialog aus:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Benutzername“ | 2–64 Zeichen: Kleinbuchstaben, Ziffern und `. _ @ + -`, am Anfang ein Buchstabe oder eine Ziffer | – |
| „Anzeigename“ | z. B. „Max Partner (Agentur X)“ | – |
| „E-Mail“ | nötig für „Passwort vergessen“ | – |
| „Gruppen“ | frei wählbare Namen, die du in Policies wie AD-Gruppen verwendest | – |
| „Passwort“ | 10 bis 72 Zeichen; leer lassen, damit Sentinel ein sicheres Passwort erzeugt | leer |
| „Erste Anmeldung“ – „eigenes Passwort festlegen lassen“ | die Person muss bei der ersten Anmeldung ein eigenes Passwort wählen | an |
| „Zugang endet“ | danach ist keine Anmeldung mehr möglich, laufende Sitzungen enden | kein Ende |
| „Notiz“ | z. B. Firma, Vertragsende, Ansprechpartner | – |

3. Klicke auf „Anlegen“. Ein erzeugtes Passwort zeigt Sentinel genau einmal an. Kopiere es mit „Kopieren“ und gib es auf sicherem Weg weiter.

**Tipp:** Lass „eigenes Passwort festlegen lassen“ eingeschaltet. Dann kennt nur die Person selbst ihr endgültiges Passwort.

Bei der Anmeldung prüft Sentinel zuerst, ob es ein Zugangskonto mit genau dem eingegebenen Namen gibt. Erst wenn keines existiert, fragt es das Active Directory. Deshalb kann sich ein AD-Konto, dessen Name schon einem Zugangskonto gehört, nicht anmelden. Es erhält die Meldung „Dieses Konto kann sich hier nicht anmelden (Namenskonflikt)…“.

#### 7.2.3 OAuth / OpenID Connect einrichten

Sentinel unterstützt Microsoft Entra ID, Google, Keycloak, Authentik, GitLab, GitHub und jeden anderen Anbieter mit OpenID Connect Discovery. Das Panel tritt dabei als einziger OAuth-Client für alle Sites auf. Beim Anbieter trägst du deshalb nur eine Redirect-URI ein:

`<Öffentliche Panel-Adresse>/oauth/callback`

Bei einer Anmeldung über einen Anbieter sendet der Browser den Benutzer von der Site über das Panel zum Anbieter und wieder zurück zur Site. **Das Panel muss deshalb für die Browser aller Benutzer erreichbar sein.**

1. Öffne *Site-Login & Konten › OAuth / OIDC*.
2. Trage unter „Redirect-URI“ die „Öffentliche Panel-Adresse“ ein, z. B. `https://sentinel.firma.de`. Es ist dasselbe Feld wie „Panel-URL für Links“ unter *Einstellungen › Benachrichtigungen*. Ohne diese Adresse lässt sich kein aktiver Anbieter speichern.
3. Kopiere die angezeigte Redirect-URI mit „Kopieren“ und registriere beim Anbieter damit eine Anwendung. Notiere dir Client-ID und Client-Secret.
4. Klicke unter „Anbieter“ › „Hinzufügen:“ auf eine Vorlage: „Microsoft Entra ID“, „Google“, „Keycloak“, „Authentik“, „GitLab“, „GitHub“ oder „Anderer (OIDC)“.
5. Fülle die Karte aus:

| Feld | Bedeutung | Standard |
|---|---|---|
| Schalter und Name | Der Name erscheint auf dem Knopf „Mit <Name> anmelden“. | aktiv, Name aus der Vorlage |
| „Issuer-URL“ (OIDC) | Adresse, unter der `/.well-known/openid-configuration` liegt. Platzhalter wie `<TENANT-ID>` musst du ersetzen. | aus der Vorlage |
| „Autorisierungs-URL“, „Token-URL“, „Userinfo-URL“ | nur bei reinem OAuth2 (GitHub), alle drei Pflicht | aus der Vorlage |
| „Client-ID“ | Pflicht | – |
| „Client-Secret“ | leer lassen, um das gespeicherte zu behalten | – |
| „Scopes“ | durch Leerzeichen getrennt | `openid profile email` |
| „Claim für den Benutzernamen“ | Ist ein Claim eingetragen, gilt nur er: Fehlt er oder ist die E-Mail-Adresse unbestätigt (bei `email`), wird die Anmeldung abgelehnt – kein Ausweichen auf Claims, die Benutzer beim Anbieter selbst wählen können. Leer: der erste vorhandene Wert aus `preferred_username`, `email` (nur wenn bestätigt, siehe unten), `upn`, `login`, `sub`. Der Name wird kleingeschrieben. | je nach Vorlage |
| „Claim für Gruppen“ | Liste oder durch Komma/Leerzeichen getrennt; ein führendes `/` (Keycloak-Gruppenpfade) wird entfernt. Mit `roles` kommen bei Keycloak die Realm-Rollen hinzu. | `groups` |
| „Erlaubte E-Mail-Domains“ | nur Konten mit bestätigter E-Mail-Adresse dieser Domains; leer = alle. Als bestätigt gilt eine Adresse, wenn der Anbieter `email_verified: true` sendet; bei den Vorlagen Microsoft (Entra ID) und GitHub, die diesen Claim nicht senden, die gelieferte Adresse. | leer |
| „auf Anmeldeseiten geschützter Sites anbieten“ | Site-Login | an |
| „MFA beim Anbieter – kein eigener TOTP-Code“ | die Anmeldung zählt als zwei Faktoren, Sentinel fragt keinen eigenen Code ab | an bei Entra ID, sonst aus |
| „Anmeldung an diesem Panel erlauben“ | Panel-Anmeldung, siehe 7.12.3 | aus |

6. Klicke auf „Verbindung testen“. Der Test prüft nur, ob die Discovery erreichbar ist, und zeigt die gefundenen Endpunkte an.
7. Klicke auf „Speichern“.
8. Wähle den Anbieter in der Policy unter „Anmeldemethoden“ (siehe 7.3), falls die Policy die Methoden einschränkt.

Hinweise der Vorlagen:

- **Microsoft Entra ID:** Lege eine App-Registrierung an, trage die Redirect-URI als Plattform „Web“ ein und erzeuge ein Client-Secret. Für Gruppen fügst du unter „Tokenkonfiguration“ den Gruppenanspruch hinzu. Entra liefert die Gruppen als Objekt-IDs (GUIDs). Diese GUIDs trägst du in Policies und Panel-Rollengruppen ein.
- **Google:** OAuth-Client-ID vom Typ Webanwendung (Google Cloud Console › APIs & Dienste › Anmeldedaten). Google liefert keine Gruppen. Steuere den Zugriff über „Erlaubte E-Mail-Domains“ und „Zusätzlich erlaubte Benutzer“.
- **Keycloak:** Client vom Typ „OpenID Connect“ mit eingeschalteter Client-Authentifizierung. Für Gruppen legst du einen Mapper „Group Membership“ an (Token Claim Name `groups`, „Full group path“ aus).
- **Authentik:** Provider „OAuth2/OpenID“ mit der Redirect-URI. Die Gruppen stehen im Claim `groups`.
- **GitLab:** unter Applications mit den Scopes `openid profile email`. Benutzername aus `nickname`.
- **GitHub:** OAuth App unter Settings › Developer settings. Die Organisationen des Kontos gelten als Gruppen (Scope `read:org`).

OAuth-Konten erscheinen unter „Konten“ nach ihrer ersten Anmeldung mit der Herkunft „OAuth · <ID>“. Hat schon ein anderes Konto denselben Benutzernamen, schlägt die Anmeldung fehl. Fehler zeigt die Anmeldeseite der Site an, zum Beispiel „Die Anmeldung beim Anbieter ist fehlgeschlagen“.

**Öffentliche Anbieter.** Bei GitHub, Google, gitlab.com und den mandantenübergreifenden Microsoft-Endpunkten (`/common`, `/organizations`, `/consumers`) kann sich jeder ein Konto anlegen und Organisations- oder Gruppennamen frei wählen. Sentinel trennt diese Konten deshalb von Verzeichnis- und Zugangskonten:

- Benutzer- und Gruppennamen erhalten die Anbieter-ID als Präfix, z. B. `github:octocat` und `github:meine-org`. In Policies trägst du Organisationen entsprechend als `github:meine-org` ein (die ID steht in der Anbieterliste). Eine AD-Gruppe „IT-Admins“ passt also nie auf eine gleichnamige GitHub-Organisation, und niemand kann über GitHub den Namen eines AD-Benutzers belegen.
- Ohne „Erlaubte E-Mail-Domains“ öffnet ein öffentlicher Anbieter eine Site nur, wenn die Policy erlaubte Gruppen oder Benutzer festlegt oder den Anbieter unter „Anmeldemethoden“ ausdrücklich auswählt. Sonst erscheint er auf der Anmeldeseite nicht, und auch ein SSO-Cookie von einer anderen Site gilt dort nicht.
- Für die Panel-Anmeldung (Rollengruppen am Anbieter) gilt das Präfix nicht.

### 7.3 Eine Site mit Anmeldung schützen

Öffne *Policies › <Policy> › Anmeldung*. Ist die Anmeldung aktiv, heißt der Reiter „Anmeldung ●“.

Panel „Anmeldung vor der Site“:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Anmeldemethoden“ | Methoden, die die Anmeldeseite anbietet und akzeptiert: „Domänenkonten (AD/LDAP)“, „Zugangskonten (lokal in Sentinel)“ und jeder aktive OAuth-Anbieter mit Site-Login. Mindestens eine Methode muss markiert bleiben. | alle |
| „Anmeldung“ | „Login erforderlich“ oder „aus“ | aus |
| „Zweiter Faktor“ – „TOTP verlangen (Authenticator-App)“ | Code aus einer Authenticator-App; die App wird bei der ersten Anmeldung eingerichtet | an (neue Policy) |
| „Sitzungsdauer (Stunden)“ | Gültigkeit einer Anmeldung, 1–2160 (90 Tage) | 12 |
| „Titel der Login-Seite“ | Überschrift der Anmeldeseite | Hostname |
| „Erlaubte Gruppen“ | eine Gruppe pro Zeile: AD-Gruppe (Name oder voller DN), Gruppe eines Zugangskontos oder Gruppe/Rolle vom OAuth-Anbieter; leer = jedes Konto der erlaubten Methoden | leer |
| „Zusätzlich erlaubte Benutzer“ | Benutzernamen, die unabhängig von ihren Gruppen Zugriff haben | leer |

**Hinweis:** Sind alle Methoden markiert, gilt die Policy für alle Methoden, auch für OAuth-Anbieter, die du später hinzufügst. Soll eine Site nur bestimmte Methoden zulassen, entferne die Markierung bei den übrigen.

**Hinweis:** Wie ein Eintrag verglichen wird, hängt von seiner Form ab (Groß- und Kleinschreibung zählen nie):

- **Voller DN** (`CN=IT-Admins,OU=Gruppen,DC=firma,DC=local`): passt nur auf genau diese AD-Gruppe. Gruppen aus anderen OUs, von Zugangskonten oder OAuth-Anbietern erfüllen ihn nie. Für alles, was Rechte vergibt (Panel-Rollen, Admin-Bereiche), ist das die sichere Wahl – wer irgendwo im AD Gruppen anlegen darf, kann sich sonst über eine gleichnamige Gruppe Zugang verschaffen.
- **Reiner Name** (`IT-Admins`): passt auf jede gleichnamige Gruppe, egal in welcher OU und aus welcher Quelle.

Gruppen-DNs von AD-Konten kennt Sentinel aus deren letzter Anmeldung; nach dem Update auf v1.3.0 melden sich Konten daher einmal neu an, bevor DN-Einträge für sie greifen.

Panel „Ausnahmen“:

| Feld | Bedeutung |
|---|---|
| „Pfade ohne Anmeldung“ | Pfad-Präfixe, die mit `/` beginnen, z. B. für Webhooks oder öffentliche Dateien. `/.well-known/acme-challenge/` ist immer ausgenommen. |
| „Netze ohne Anmeldung“ | IP-Adressen oder Netze (CIDR), aus denen gar keine Anmeldung nötig ist |
| „Netze ohne 2FA“ | Aus diesen Netzen reicht das Passwort, z. B. aus dem Büro-LAN. Wechselt der Benutzer später in ein anderes Netz, muss er sich mit Code neu anmelden. |

**Achtung:** „Netze ohne Anmeldung“ öffnet die Site für jeden Client aus diesen Netzen. Solche Clients sind nicht angemeldet, das Backend erhält für sie keine Benutzer-Header. Steht Caddy hinter einem Proxy, muss Caddy die echte Client-IP kennen (siehe Kapitel 10).

Panel „Sitzung & Weitergabe“:

| Feld | Bedeutung | Standard |
|---|---|---|
| „An IP binden“ | Die Sitzung gilt nur von der IP-Adresse, mit der sich der Benutzer angemeldet hat. Wechselt die Adresse (Mobilfunk, IPv6-Privacy-Adressen), muss er sich neu anmelden. | aus |
| „Header ans Backend“ | gibt Benutzer, Name, E-Mail und Gruppen weiter (siehe 7.11) | an (neue Policy) |
| „Single Sign-on“ | Die Anmeldung gilt für alle SSO-Sites unter der SSO-Domain (siehe 7.5). Steht nur zur Wahl, wenn SSO eingerichtet ist. | aus |

#### 7.3.1 Anmeldung in Pfad-Regeln

Mit Pfad-Regeln legst du für einzelne Bereiche einer Site eigene Anmelde-Einstellungen fest (siehe Kapitel 5). Unter *Policies › <Policy> › Pfad-Regeln* stehen in jeder Regel im Abschnitt „Anmeldung“ diese Felder:

| Feld | Werte | Wirkung |
|---|---|---|
| „Login“ | „wie Policy“, „erforderlich“, „ohne Login“ | schaltet die Anmeldung für den Bereich ein oder aus; das geht auch, wenn die Policy selbst keine Anmeldung verlangt |
| „Zweiter Faktor“ | „wie Policy“, „verlangen“, „nicht nötig“ | TOTP für den Bereich |
| „Nur diese Gruppen“ | Liste | ersetzt die erlaubten Gruppen der Policy |
| „Nur diese Benutzer“ | Liste | ersetzt die erlaubten Benutzer der Policy |
| „API-Schlüssel“ | Schlüssel und Header | Mit Schlüsseln ist der Bereich nur noch mit gültigem Schlüssel erreichbar. Ein gültiger Schlüssel ersetzt die Anmeldung. |

**Achtung:** Sobald in einer Regel „Nur diese Gruppen“ oder „Nur diese Benutzer“ ausgefüllt ist, ersetzt die Regel beide Listen der Policy. Trägst du nur Benutzer ein, gelten in diesem Bereich keine Gruppen.

Die Aktion „Durchlassen“ überspringt die Anmeldung, außer „Login“ steht in der Regel auf „erforderlich“. Die Vorlage „Admin-Bereich intern + Gruppe“ zeigt eine typische Anwendung: `/admin/` nur aus dem LAN, Login erforderlich, zweiter Faktor verlangt, nur die Gruppe IT-Admins.

Beim Anmelden gilt die Pfad-Regel der Zieladresse. Wer direkt in einen Bereich mit strengeren Regeln will, muss deren Gruppen und den zweiten Faktor sofort erfüllen.

### 7.4 Zweiter Faktor und Schutz vor Fehlversuchen

Der zweite Faktor ist ein **Passkey** (Fingerabdruck, Gesichtserkennung oder Geräte-PIN, ein Smartphone oder ein Sicherheitsschlüssel wie YubiKey; siehe 7.7.1) oder ein sechsstelliger TOTP-Code aus einer Authenticator-App wie Microsoft Authenticator, Google Authenticator oder 2FAS. Ein Konto kann beides haben. Der Schlüssel gehört zum Konto, nicht zur Site. Ein Konto braucht also für alle Sites nur einen Eintrag in der App, und bei AD-Konten gilt derselbe Eintrag auch für das Panel. Sentinel akzeptiert eine Zeitabweichung von ±30 Sekunden, und jeder Code gilt nur einmal.

Als Ersatz für die App dienen zehn Wiederherstellungscodes im Format `xxxxx-xxxxx`. Jeder Code gilt einmal. Groß- und Kleinschreibung, Bindestrich und Leerzeichen spielen bei der Eingabe keine Rolle. Die Codes erzeugt der Benutzer selbst auf seiner Kontoseite (siehe 7.7).

Einstellungen unter *Site-Login & Konten › Verzeichnis (AD)*, Panel „Zweiter Faktor & Schutz“. Sie gelten für alle Kontoarten, nicht nur für AD:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Name in der Authenticator-App“ | Anzeigename des Eintrags in der App | Caddy Sentinel |
| „Sperre nach Fehlversuchen“ | Fehlversuche pro Konto im Zeitfenster; pro IP-Adresse gilt das Vierfache | 5 |
| „Sperrdauer (Minuten)“ | Zeitfenster und Dauer der Sperre | 15 |

Als Fehlversuch zählen falsche Passwörter, falsche Codes und falsche Bestätigungen auf der Kontoseite oder beim Zurücksetzen. Ein gesperrtes Konto sieht „Zu viele Fehlversuche – bitte 15 Minuten warten.“, und Sentinel meldet ein Ereignis „Site-Login: Konto … vorübergehend gesperrt“. Gesperrte Konten listet die „Übersicht“ unter „Vorübergehend gesperrte Konten“. Ein Administrator hebt die Sperre dort mit „Entsperren“ auf.

**Hinweis:** Die Sperren hält das Panel nur im Arbeitsspeicher. Ein Neustart des Panels hebt sie auf.

### 7.5 Single Sign-on (SSO)

Mit SSO meldet sich ein Benutzer einmal an und kann danach alle beteiligten Sites unter einer gemeinsamen Domain nutzen, zum Beispiel `wiki.firma.de` und `git.firma.de` unter `firma.de`.

1. Öffne *Site-Login & Konten › Verzeichnis (AD)*, Panel „Single Sign-on“.
2. Schalte „SSO“ ein und trage die „Domain“ ein, z. B. `firma.de`. Alle beteiligten Sites müssen unter dieser Domain liegen und HTTPS nutzen.
3. Klicke auf „Speichern“.
4. Schalte in jeder beteiligten Policy im Reiter „Anmeldung“ den Punkt „Single Sign-on“ ein.

Für SSO-Sites setzt Sentinel ein gemeinsames Cookie für die Domain und alle Subdomains. Jede Site prüft trotzdem selbst:

- ob die Gruppen oder Benutzer des Kontos passen,
- ob der zweite Faktor vorliegt (fehlt er, fragt Sentinel ihn nach einer erneuten Anmeldung ab),
- ob die Anmeldemethode erlaubt ist,
- ob „An IP binden“ verlangt ist.

Ein SSO-Cookie öffnet deshalb nur Sites, die SSO aktiviert haben und die Methode akzeptieren, mit der sich der Benutzer angemeldet hat. Wer sich zum Beispiel über Google angemeldet hat, kommt damit nicht auf eine SSO-Site, die nur Domänenkonten zulässt. Liegt der Host einer Site nicht unter der SSO-Domain, gilt dort weiter eine eigene Anmeldung.

Abmelden auf einer SSO-Site meldet den Browser von allen SSO-Sites der Domain ab.

Wie lange ein SSO-Cookie höchstens gilt und ob es an die IP gebunden ist, legt die Site fest, auf der sich der Benutzer angemeldet hat. Jede SSO-Site akzeptiert es aber nur so lange, wie ihre eigene „Sitzungsdauer“ erlaubt: Eine Site mit 1 Stunde verlangt nach einer Stunde eine neue Anmeldung, auch wenn das Cookie von einer Site mit 12 Stunden stammt.

**Tipp:** Wähle die SSO-Domain so eng wie möglich, z. B. `apps.firma.de` statt `firma.de`.

### 7.6 Anmeldung aus Sicht der Benutzer

#### 7.6.1 Verhalten ohne gültige Sitzung

- **Aufruf im Browser:** Sentinel leitet zur Anmeldeseite weiter und nach der Anmeldung zurück zur ursprünglich aufgerufenen Adresse.
- **Skripte und API-Aufrufe:** Sentinel antwortet mit HTTP 401 und dem Header `WWW-Authenticate: Sentinel realm="<host>", login="/.sentinel/auth/login"`. Für Skripte gibt es Zugriffstokens (siehe 7.10).
- **Angemeldet, aber ohne Berechtigung:** Es erscheint die Seite „Kein Zugriff“ (HTTP 403) mit den Links „Abmelden“ und „Mit anderem Konto anmelden“.
- **Angemeldet ohne Code, Bereich verlangt einen Code:** Sentinel fordert eine erneute Anmeldung mit Passwort und Code an („Für diesen Bereich ist zusätzlich ein Code aus der Authenticator-App nötig. Bitte erneut anmelden.“).

#### 7.6.2 Die Anmeldeseite

Die Seite zeigt die Felder „Benutzername“ und „Passwort“ und den Knopf „Anmelden“. Darunter stehen, je nach Einstellung, der Link „Passwort vergessen?“ (siehe 7.8) und für jeden OAuth-Anbieter ein Knopf „Mit <Name> anmelden“. Die Fußzeile sagt, welches Konto gemeint ist, zum Beispiel „Mit deinem Windows-/Domänenkonto oder Zugangskonto anmelden.“

Domänenkonten können sich als `max`, `FIRMA\max` oder `max@firma.local` anmelden.

#### 7.6.3 Erste Anmeldung mit Einrichtung des zweiten Faktors

1. Rufe die Site auf. Die Anmeldeseite erscheint.
2. Gib Benutzername und Passwort ein und klicke auf „Anmelden“. Bei OAuth klickst du stattdessen auf „Mit <Name> anmelden“ und meldest dich beim Anbieter an.
3. Nur bei Zugangskonten mit vorgegebenem Passwort erscheint jetzt „Neues Passwort festlegen“. Gib unter „Neues Passwort“ und „Neues Passwort wiederholen“ ein eigenes Passwort ein und klicke auf „Speichern und anmelden“. Das Passwort braucht 10 bis 72 Zeichen (Byte). Es darf nicht dem Benutzernamen, der E-Mail-Adresse oder dem bisherigen Passwort entsprechen.
4. Verlangt die Site einen zweiten Faktor und hat das Konto noch keinen, erscheint „Für diese Seite ist ein zweiter Faktor nötig. Richte ihn jetzt einmalig ein.“
   - **Mit Passkey** (nur über HTTPS): Klicke auf „Passkey einrichten und anmelden“ und bestätige im Dialog des Browsers mit Fingerabdruck, Gesichtserkennung, Geräte-PIN, Smartphone oder Sicherheitsschlüssel. Fertig – weiter mit Schritt 5.
   - **Mit Authenticator-App** (unter „oder Authenticator-App“):
   1. Öffne deine Authenticator-App.
   2. Scanne den QR-Code. Alternativ tippst du den angezeigten Schlüssel ab.
   3. Gib den sechsstelligen Code unter „Code aus der App“ ein und klicke auf „Einrichten und anmelden“.
5. Sentinel leitet dich zur aufgerufenen Seite weiter.
6. Öffne danach die Kontoseite `/.sentinel/auth/me`, erzeuge Wiederherstellungscodes und bewahre sie sicher auf (siehe 7.7).

Die Einrichtung muss innerhalb von 5 Minuten abgeschlossen sein. Nach 5 falschen Codes musst du dich neu anmelden. Lehnt Sentinel einen Code ab, prüfe die Uhrzeit des Geräts.

#### 7.6.4 Weitere Anmeldungen

1. Gib Benutzername und Passwort ein.
2. Mit Passkey: Klicke auf „Mit Passkey bestätigen“ und bestätige im Dialog des Browsers. Mit Authenticator-App: Gib unter „Code aus der Authenticator-App“ den aktuellen Code ein und klicke auf „Bestätigen“. Hat das Konto beides, zeigt die Seite beide Wege.

Ist das Gerät nicht zur Hand, klappe „Gerät nicht zur Hand?“ auf. Gib unter „Wiederherstellungscode“ einen der Codes ein und klicke auf „Mit Wiederherstellungscode anmelden“. Sentinel meldet die Verwendung eines Wiederherstellungscodes als Ereignis, weil sie auf ein verlorenes Gerät hindeuten kann. Richte danach auf der Kontoseite die App auf dem neuen Gerät ein.

#### 7.6.5 Abmelden

Klicke auf der Kontoseite auf „Abmelden“ oder rufe `/.sentinel/auth/logout` auf und bestätige dort mit „Abmelden“ (ein bloßer Link meldet nicht ab – sonst könnte jede fremde Seite Benutzer abmelden). Die Seite „Abgemeldet“ bestätigt „Du wurdest von dieser Seite abgemeldet.“, bei SSO „… von allen Seiten unter <Domain> abgemeldet.“

Abmelden beendet die Sitzung endgültig: Das Panel sperrt ihre Kennung, alle Caddy-Instanzen weisen innerhalb von Sekunden auch eine Kopie des Cookies ab. Um alle Sitzungen eines Kontos zu beenden, nutze „Auf allen Geräten abmelden“ auf der Kontoseite oder „Sitzungen beenden“ unter *Site-Login & Konten › Konten*.

### 7.7 Die Kontoseite „Mein Konto“

Jede geschützte Site hat eine Kontoseite unter `/.sentinel/auth/me`, zum Beispiel `https://wiki.firma.de/.sentinel/auth/me`. Wer nicht angemeldet ist, wird zuerst zur Anmeldung geleitet.

**Tipp:** Verlinke die Kontoseite im Intranet oder in der Anwendung als „Mein Konto“.

Die Seite zeigt:

- „Konto“, „Kontoart“ („Zugangskonto“, „Windows-/Domänenkonto“ oder „Anmeldung über <Anbieter>“),
- gegebenenfalls „Zugang bis“ und „E-Mail“,
- „Gruppen“,
- „Diese Sitzung“ (ein oder zwei Faktoren, seit wann, gültig bis wann),
- bei SSO die Domain, für die die Anmeldung gilt.

Darunter folgen die Abschnitte, in denen der Benutzer selbst etwas ändern kann. Vor Änderungen am zweiten Faktor verlangt die Seite eine Bestätigung. Ist eine Authenticator-App eingerichtet, ist das der aktuelle Code oder ein Wiederherstellungscode. Ohne App ist es das Passwort. Fehlversuche zählen für die Kontosperre.

#### 7.7.1 Anmeldung in zwei Schritten

**Authenticator-App zum ersten Mal einrichten** (wenn noch keine eingerichtet ist):

1. Klappe „Authenticator-App einrichten“ auf.
2. Gib das Passwort zur Bestätigung ein. Bei OAuth-Konten entfällt das.
3. Klicke auf „Weiter“.
4. Scanne den QR-Code, gib den Code unter „Code aus der neuen App“ ein und klicke auf „Einrichten“.
5. Sentinel zeigt zehn Wiederherstellungscodes an. Sichere sie mit „Als Textdatei speichern“ oder notiere sie und klicke auf „Gespeichert – zurück zum Konto“.

**Neues Handy oder andere App:**

1. Klappe „Neues Gerät oder andere App einrichten“ auf.
2. Gib einen aktuellen Code aus der alten App oder einen Wiederherstellungscode ein und klicke auf „Weiter“.
3. Scanne auf dem neuen Gerät den QR-Code und bestätige mit dem Code aus der neuen App über „Einrichten“. „Abbrechen – alte App bleibt gültig“ bricht den Umzug ab.
4. Das alte Gerät erzeugt ab sofort keine gültigen Codes mehr. Sentinel erzeugt dabei zehn neue Wiederherstellungscodes. Die bisherigen Codes werden ungültig.

**Hinweis:** „Neues Gerät oder andere App einrichten“ beendet keine anderen Sitzungen. Wurde das alte Gerät gestohlen, klicke danach auch auf „Auf allen Geräten abmelden“.

**Passkeys verwalten:** Der Abschnitt „Passkeys“ listet alle Passkeys des Kontos mit Einrichtungs- und letztem Nutzungsdatum.

- *Hinzufügen* (z. B. zweites Gerät oder Sicherheitsschlüssel als Reserve): „Passkey hinzufügen“ aufklappen, zur Bestätigung den Code aus der App bzw. das Passwort eingeben, „Weiter“, einen Namen vergeben (z. B. „Laptop“, „YubiKey“) und „Passkey erstellen“ klicken.
- *Entfernen* (z. B. Gerät verloren): bei dem Passkey „Entfernen“ aufklappen, Code bzw. Passwort eingeben und bestätigen. Bei Verdacht auf Missbrauch danach „Auf allen Geräten abmelden“.
- Konten, die nur Passkeys und keine Authenticator-App haben, erzeugen ihre Wiederherstellungscodes im selben Abschnitt.

Ein Passkey gilt für die Site, auf der er eingerichtet wurde – auf SSO-Sites für alle Sites unter der SSO-Domain. Passkeys funktionieren nur über HTTPS (Ausnahme: `localhost`); ohne HTTPS bietet Sentinel sie gar nicht an.

**Neue Wiederherstellungscodes:** Klappe „Neue Wiederherstellungscodes erzeugen“ auf. Gib den aktuellen Code aus der App ein und klicke auf „Codes erzeugen“. Die bisherigen Codes werden ungültig. Sind keine Codes mehr übrig, warnt die Kontoseite und zeigt diesen Abschnitt bereits aufgeklappt.

#### 7.7.2 Passwort

Nur Zugangskonten können ihr Passwort hier ändern:

1. Klappe „Passwort ändern“ auf.
2. Gib „Bisheriges Passwort“, „Neues Passwort“ und „Neues Passwort wiederholen“ ein. Das neue Passwort braucht 10 bis 72 Zeichen (Byte).
3. Klicke auf „Passwort ändern“.

Alle anderen Sitzungen des Kontos enden. Der aktuelle Browser bleibt angemeldet. AD- und OAuth-Konten ändern ihr Passwort in Windows bzw. beim Anbieter.

#### 7.7.3 Letzte Aktivität und Sitzungen

„Letzte Aktivität“ zeigt die letzten acht Einträge des Kontos: Anmeldungen, Fehlversuche und Änderungen, jeweils mit Site, IP-Adresse und Gerät. War ein Eintrag nicht der Benutzer selbst, sollte er das Passwort ändern, sich überall abmelden und die Administration informieren.

„Auf allen Geräten abmelden“ beendet sofort alle Sitzungen des Kontos auf allen Sites und Geräten. Zugriffstokens des Kontos bleiben gültig.

#### 7.7.4 Kontoinformationen als JSON

Anwendungen können die Kontoseite mit dem Header `Accept: application/json` abrufen. Bei bestehender Sitzung antwortet Sentinel so:

```json
{"authenticated": true, "user": "max", "name": "Max Mustermann", "email": "max@firma.de",
 "groups": ["Wiki-Benutzer"], "factors": 2, "issued": 1767225600, "expires": 1767268800, "sso": false}
```

Ohne Sitzung kommt HTTP 401 mit `{"authenticated": false}`.

### 7.8 Passwort vergessen (Zugangskonten)

Zugangskonten mit E-Mail-Adresse können ein vergessenes Passwort per E-Mail-Link zurücksetzen. AD-Konten setzt die IT im Active Directory zurück.

#### 7.8.1 Einrichten (Administrator)

1. Richte den E-Mail-Versand ein: *Einstellungen › Benachrichtigungen › SMTP*, mit Server und Absender (siehe Kapitel 11).
2. Öffne *Site-Login & Konten › Self-Service*.
3. Schalte im Panel „Passwort vergessen (Zugangskonten)“ den Punkt „Zurücksetzen per E-Mail“ ein.
4. Lege „Link gültig (Minuten)“ fest. Standard sind 30 Minuten, erlaubt sind 5 bis 1440.
5. Klicke auf „Speichern“.

Der Link „Passwort vergessen?“ erscheint auf einer Anmeldeseite nur, wenn alle diese Bedingungen erfüllt sind:

- „Zurücksetzen per E-Mail“ ist aktiv, und SMTP-Server und Absender sind eingetragen. Fehlt SMTP, warnt das Panel.
- Es gibt mindestens ein nicht gesperrtes Zugangskonto.
- Die Policy bzw. Pfad-Regel lässt die Methode „Zugangskonten“ zu.

Eine E-Mail verschickt Sentinel außerdem nur, wenn:

- das Konto eine E-Mail-Adresse hat und weder gesperrt noch abgelaufen ist,
- **die Site mit ihrem Hostnamen in der Caddy-Konfiguration steht**, als genauer Name oder über eine passende Wildcard `*.domain`.

Den Link baut Sentinel aus dem Hostnamen, den der Browser geschickt hat. Bei einer Site ohne Hostnamen (etwa nur `:443`) könnte dieser Name beliebig sein. Deshalb verschickt Sentinel dort keine E-Mail. Der Benutzer sieht trotzdem die übliche Bestätigung, und im Anmeldeprotokoll steht „Passwort-Reset abgelehnt – Host … ist keine konfigurierte Site“.

#### 7.8.2 Ablauf für Benutzer

1. Klicke auf der Anmeldeseite auf „Passwort vergessen?“.
2. Gib unter „Benutzername oder E-Mail“ deinen Benutzernamen oder deine E-Mail-Adresse ein und klicke auf „Link anfordern“.
3. Sentinel antwortet immer gleich: „Wenn es ein passendes Zugangskonto mit E-Mail-Adresse gibt, ist eine E-Mail mit einem Link unterwegs. Er gilt 30 Minuten.“
4. Öffne den Link aus der E-Mail mit dem Betreff „Passwort zurücksetzen – <Site>“.
5. Gib „Neues Passwort“ und „Neues Passwort wiederholen“ ein. Hat das Konto eine Authenticator-App, gib zusätzlich den aktuellen Code oder einen Wiederherstellungscode ein. Ein Zugriff auf das Postfach allein genügt also nicht.
6. Klicke auf „Passwort speichern“ und danach auf „Zur Anmeldung“.

Alle Sitzungen des Kontos enden. Der Link gilt nur einmal und nur auf der Site, auf der er angefordert wurde. Wird er eingelöst, verfallen auch alle anderen offenen Links des Kontos. Anfragen sind begrenzt auf drei pro Name in 15 Minuten, und pro Konto gehen höchstens drei E-Mails in 15 Minuten heraus. Die Antwort verrät nie, ob ein Konto existiert.

### 7.9 Konten verwalten

#### 7.9.1 Übersicht

*Site-Login & Konten › Übersicht* zeigt:

- die eingerichteten Anmeldemethoden,
- die Kennzahlen „Geschützte Policies“, „Konten“ (nach Herkunft, mit Anzahl der Konten mit 2FA), „Zugriffstokens“, „Anmeldungen 24 h“ und „Fehlversuche 24 h“,
- gesperrte Konten (siehe 7.4),
- die Tabelle „Geschützte Sites“ mit Hosts, Methoden, 2FA, erlaubten Gruppen und Benutzern, Sitzungsdauer und Ausnahmen,
- die letzten Anmeldeversuche.

#### 7.9.2 Konten

*Site-Login & Konten › Konten* listet alle Konten, die sich an geschützten Sites anmelden können. Filtern kannst du nach Name, E-Mail, Gruppe oder Notiz und nach Herkunft („Active Directory“, „Zugangskonten“, „OAuth/OIDC“). Die Spalte „2FA“ zeigt, ob eine App eingerichtet ist und wie viele Wiederherstellungscodes übrig sind. Das Badge „Passwort ändern“ heißt, dass das Konto bei der nächsten Anmeldung ein eigenes Passwort festlegen muss.

Aktionen (Administrator):

| Aktion | Wirkung |
|---|---|
| „Bearbeiten“ | Anzeigename, E-Mail, „Zugang endet“ und Notiz ändern; Gruppen nur bei Zugangskonten. Speichern beendet alle laufenden Sitzungen des Kontos, damit Änderungen sofort gelten. Bei AD- und OAuth-Konten überschreibt die nächste Anmeldung Anzeigename und E-Mail mit den Daten der Quelle. |
| „Passwort“ | nur Zugangskonten: erzeugt ein neues Passwort, das einmal angezeigt wird. Mit „bei der nächsten Anmeldung ein eigenes Passwort festlegen lassen“ (Standard an) muss die Person danach ein eigenes wählen. Laufende Sitzungen enden. |
| „Abmelden“ | beendet sofort alle Site-Sitzungen des Kontos; Zugriffstokens bleiben gültig |
| „2FA zurücksetzen“ | löscht Authenticator-App, Passkeys und alle Wiederherstellungscodes des Kontos und beendet die Sitzungen. Bei der nächsten Anmeldung richtet die Person eine neue App ein und erzeugt anschließend auf der Kontoseite neue Codes. Bei AD-Konten gilt das auch für das Panel. |
| „Sperren“ / „Entsperren“ | Ein gesperrtes Konto kann sich nicht mehr anmelden, auch nicht mit Zugriffstokens. Laufende Sitzungen enden sofort. |
| „Entfernen“ | löscht das Konto mit seinem TOTP-Schlüssel und seinen Zugriffstokens; laufende Sitzungen bleiben ungültig. Ein AD- oder OAuth-Konto legt Sentinel bei der nächsten Anmeldung neu an, dann ohne 2FA. |

**Tipp:** Hat jemand sein Gerät verloren und keine Wiederherstellungscodes mehr, setze unter „Konten“ die 2FA zurück.

#### 7.9.3 Anmeldeprotokoll

*Site-Login & Konten › Anmeldeprotokoll* zeigt die letzten 300 Anmeldeversuche. Filtern kannst du nach Benutzer und Ergebnis: „angemeldet“, „fehlgeschlagen“, „kein Zugriff“, „gesperrt“, „2FA-Einrichtung“, „Dienstfehler“, „Kontoänderung“, „Reset angefordert“. Die Spalte „Details“ nennt den Weg oder Grund, etwa „Passwort + 2FA“, „… (MFA beim Anbieter)“, „… + Wiederherstellungscode“, „nicht in den erlaubten Gruppen“ oder AD-Gründe wie „Passwort abgelaufen“. Ein Klick auf einen Benutzernamen filtert die Liste nach diesem Benutzer.

### 7.10 Zugriffstokens für Skripte und Dienste

Zugriffstokens öffnen eine geschützte Site ohne Anmeldeseite, etwa für Backup-Skripte oder Monitoring. Ein Token handelt im Namen eines Kontos. Die Gruppen des Kontos entscheiden, worauf das Token zugreifen darf. Anmeldung und zweiter Faktor entfallen.

1. Lege am besten für jeden Dienst ein eigenes Zugangskonto an, z. B. `svc-backup`, mit passenden Gruppen (siehe 7.2.2).
2. Öffne *Site-Login & Konten › Zugriffstokens* und klicke auf „Token erstellen“ (Administrator).
3. Fülle den Dialog aus:

| Feld | Bedeutung | Standard |
|---|---|---|
| „Konto“ | Konto, in dessen Namen das Token handelt | erstes Zugangskonto |
| „Name“ | wofür das Token gedacht ist, z. B. „Backup-Skript“ | – |
| „Nur für diese Sites“ | Policies, für die das Token gilt; keine Auswahl = alle Sites, auf die das Konto Zugriff hat | keine Auswahl |
| „Läuft ab“ | Ablaufdatum | in einem Jahr |
| „Notiz“ | wer das Token nutzt und wo es hinterlegt ist | – |

4. Klicke auf „Erstellen“. Sentinel zeigt das Token genau einmal an. Es beginnt mit `sst_`. Sentinel selbst speichert nur eine Prüfsumme.
5. Schicke das Token im Header mit:

```
curl -H "Authorization: Bearer sst_…" https://wiki.firma.de/…
```

Caddy kennt ein neues Token nach wenigen Sekunden und prüft es direkt, ohne Rückfrage beim Panel. Vor der Weitergabe ans Backend entfernt Sentinel den Header. Andere `Authorization`-Werte, die nicht mit `sst_` beginnen, gibt Sentinel unverändert weiter. Sie ersetzen aber keine Anmeldung.

Ein Token wird ungültig, wenn eines davon eintritt:

- es abläuft oder mit „Widerrufen“ zurückgezogen wird,
- sein Konto gesperrt, abgelaufen oder entfernt wird.

„Abmelden“ und „Auf allen Geräten abmelden“ wirken nicht auf Tokens. Antworten bei Fehlern:

- ungültiges oder abgelaufenes Token: 401 „Zugriffstoken ungültig oder abgelaufen.“
- Token für diese Site nicht freigegeben: 403 „Das Token ist für diese Site nicht freigegeben.“
- dem Konto fehlen die nötigen Gruppen: 403 „Das Konto des Tokens hat keinen Zugriff auf diesen Bereich.“

**Hinweis:** Tokens beachten die „Anmeldemethoden“ einer Policy nicht. Das Token eines Zugangskontos öffnet also auch eine Site, die nur Domänenkonten zulässt, sofern die Gruppen passen. Begrenze Tokens deshalb mit „Nur für diese Sites“.

Zum Vergleich: API-Schlüssel in Pfad-Regeln gehören zu keinem Konto und gelten nur für den Bereich ihrer Regel (siehe Kapitel 5). Panel-API-Tokens (`spt_…`) gelten nur für die Panel-API (siehe 7.13).

### 7.11 Benutzer-Header ans Backend

Ist in der Policy „Header ans Backend“ eingeschaltet, gibt Sentinel nach erfolgreicher Prüfung diese Header an die Anwendung weiter:

| Header | Inhalt |
|---|---|
| `Remote-User` | Benutzername in Kleinbuchstaben: bei AD der Wert von „Attribut Benutzername“, bei Zugangskonten der Kontoname, bei OAuth der zugeordnete Benutzername |
| `Remote-Name` | Anzeigename, falls vorhanden |
| `Remote-Email` | E-Mail-Adresse, falls vorhanden; bei Zugriffstokens nicht gesetzt |
| `Remote-Groups` | Gruppen durch Komma getrennt; bei AD nur die Gruppennamen (CN) |

Zusätzlich steht der Benutzer im Caddyfile als Platzhalter `{http.vars.sentinel.user}` bereit, auch ohne Header-Weitergabe. Damit kannst du ihn zum Beispiel ins Log schreiben.

Hat ein Benutzer ohne SSO mehr als 40 Gruppen, nimmt Sentinel nicht alle in die Sitzung auf. Die Gruppen, die die Policy und ihre Pfad-Regeln prüfen, bleiben immer erhalten. `Remote-Groups` kann dann unvollständig sein.

**Anmeldung über Header in der Anwendung:** Viele Anwendungen können einen vom Proxy gesetzten Benutzer übernehmen. Je nach Anwendung heißt das „Reverse-Proxy-Authentifizierung“, „Auth-Proxy“ oder „Remote-User“. So richtest du es ein:

1. Aktiviere in der Policy der Site „Anmeldung“ und „Header ans Backend“.
2. Stelle in der Anwendung die Header-Anmeldung ein und trage `Remote-User` als Header-Namen ein. Wenn die Anwendung es unterstützt, trage auch `Remote-Email`, `Remote-Name` und `Remote-Groups` ein. Die genauen Einstellungen stehen in der Dokumentation der Anwendung.
3. Sorge dafür, dass die Anwendung nur über Caddy erreichbar ist. Lass sie zum Beispiel nur auf `127.0.0.1` lauschen oder sperre ihren Port in der Firewall.

Gleichnamige Header, die ein Client selbst mitschickt, entfernt Sentinel auf jeder Site, deren Policy oder Pfad-Regeln eine Anmeldung nutzen. Das gilt auch für Clients, die keine Anmeldung brauchen. Fälschen lassen sich die Header so nicht.

**Achtung:** Bei Policies ganz ohne Anmeldung entfernt Sentinel diese Header nicht. Eine Anwendung darf `Remote-User` nur vertrauen, wenn sie ausschließlich über eine Site mit Sentinel-Anmeldung erreichbar ist. Aus „Netze ohne Anmeldung“, auf „Pfade ohne Anmeldung“ und für vertrauenswürdige Quellen kommt kein Benutzer-Header an. Die Anwendung muss damit umgehen können, etwa mit ihrer eigenen Anmeldung als Rückfallweg.

### 7.12 Anmeldung am Panel

#### 7.12.1 Lokale Panel-Benutzer

Beim ersten Aufruf erscheint die „Ersteinrichtung“. Hier legst du das erste Administratorkonto an: Benutzername mit mindestens 3 Zeichen (vorbelegt „admin“) und Passwort mit 10 bis 72 Zeichen. Weitere Benutzer legt ein Administrator an (siehe 7.12.4).

Die Anmeldung ist begrenzt auf 10 Fehlversuche pro IP-Adresse und 30 pro Konto in 15 Minuten. Fehlgeschlagene Anmeldungen protokolliert das Panel als Ereignis. Eine Sitzung gilt für lokale Benutzer 7 Tage, für AD- und OAuth-Konten 12 Stunden. Danach prüft Sentinel die Gruppen bei der nächsten Anmeldung neu.

Unter *Einstellungen › Konto & Sicherheit* verwalten lokale Benutzer ihr eigenes Konto:

- **„Passwort ändern“:** „Aktuelles Passwort“, „Neues Passwort“ (10 bis 72 Zeichen) und „Wiederholen“ eingeben. Alle anderen Sitzungen werden abgemeldet, eigene API-Tokens widerrufen (neu anlegen).
- **„Zwei-Faktor-Anmeldung“:**
  1. Klicke auf „2FA einrichten“.
  2. Scanne den QR-Code oder tippe den Schlüssel ab.
  3. Gib den angezeigten Code ein und klicke auf „Aktivieren“.

  Ab jetzt fragt das Panel nach dem Passwort einen sechsstelligen Code ab. „2FA deaktivieren“ verlangt das Passwort. Wiederherstellungscodes gibt es für das Panel nicht. Bei einem verlorenen Gerät setzt ein anderer Administrator die 2FA zurück.
- **„Aktive Sitzungen“:** Liste der Anmeldungen mit IP-Adresse und Browser. Mit „Beenden“ meldest du einzelne Sitzungen ab.
- **„Darstellung“:** „Farbschema“ „wie System“, „hell“ oder „dunkel“.

#### 7.12.2 Panel-Anmeldung mit Active Directory

Voraussetzung ist ein verbundenes Verzeichnis (siehe 7.2.1). Danach:

1. Öffne *Site-Login & Konten › Verzeichnis (AD)*, Panel „Panel-Anmeldung mit AD“.
2. Schalte „Panel-Login“ – „Verzeichniskonten zulassen“ ein.
3. Lass „2FA“ – „für AD-Konten verlangen“ eingeschaltet (Standard).
4. Trage die Gruppen für die Rollen ein: „Administratoren-Gruppen“, „Bearbeiter-Gruppen“, „Support-Gruppen“, „Leser-Gruppen“.
5. Klicke auf „Speichern“. Mit „Benutzer suchen“ im Panel „Verbindung testen“ siehst du, welche Panel-Rolle ein Konto bekäme.

Ablauf und Regeln:

- Gibt es einen lokalen Panel-Benutzer mit dem eingegebenen Namen, prüft das Panel lokal. Lokale Konten bleiben so als Notfallzugang erhalten. Sonst fragt es das Verzeichnis.
- Die Rolle ergibt sich bei jeder Anmeldung aus den Gruppen. Bei mehreren Treffern gilt die höchste Rolle: Administrator vor Bearbeiter vor Support vor Leser. Ohne passende Gruppe erscheint „Dein Verzeichniskonto hat keinen Zugriff auf das Panel“. Eine Rollenänderung unter *Einstellungen › Benutzer* überschreibt die nächste Anmeldung wieder.
- Konten, die unter *Site-Login & Konten › Konten* gesperrt sind oder deren „Zugang endet“ überschritten ist, können sich nicht am Panel anmelden.
- Der zweite Faktor ist derselbe Eintrag in der Authenticator-App wie beim Site-Login. Hat das Konto noch keinen, richtet es ihn bei der ersten Panel-Anmeldung ein („Zweiten Faktor einrichten“). Wiederherstellungscodes akzeptiert die Panel-Anmeldung nicht. Nutzt das Konto bisher nur Passkeys (oder hat es Wiederherstellungscodes), bietet das Panel keine Einrichtung an – sonst könnte, wer nur das Passwort kennt, eine eigene App eintragen. Die Authenticator-App wird dann auf der Kontoseite einer Site eingerichtet (`/.sentinel/auth/me`).
- Passwort und Gruppen verwaltet das Verzeichnis. *Einstellungen › Konto & Sicherheit* zeigt AD-Konten nur ihre Kontoart und die aktiven Sitzungen.

#### 7.12.3 Panel-Anmeldung mit OAuth/OIDC

1. Richte den Anbieter ein (siehe 7.2.3).
2. Schalte in seiner Karte „Anmeldung an diesem Panel erlauben“ ein.
3. Trage die „Administratoren-Gruppen“, „Bearbeiter-Gruppen“, „Support-Gruppen“ und „Leser-Gruppen“ ein. Bei Entra ID sind das die Objekt-IDs der Gruppen.
4. Klicke auf „Speichern“.

Die Panel-Anmeldeseite zeigt dann „Mit <Name> anmelden“. Die Rolle ergibt sich wie bei AD bei jeder Anmeldung aus den Gruppen. Ohne passende Gruppe erscheint „Dein Konto hat keinen Zugriff auf das Panel (keine passende Gruppe).“ OAuth-Konten haben kein lokales Passwort im Panel.

**Hinweis:** Bei der Panel-Anmeldung über OAuth fragt Sentinel den eigenen zweiten Faktor nur ab, wenn das Konto im Panel unter „Konto & Sicherheit“ 2FA eingerichtet hat. Ohne das zählt allein die Anmeldung beim Anbieter – erzwinge MFA deshalb dort, zum Beispiel mit Conditional Access in Entra ID.

#### 7.12.4 Panel-Benutzer verwalten (Administrator)

Unter *Einstellungen › Benutzer* siehst du alle Panel-Benutzer mit Rolle, 2FA-Status und letzter Anmeldung. AD-Konten tragen das Badge „AD“.

- „Benutzer anlegen“: „Benutzername“ (mindestens 3 Zeichen), „Passwort“ (mindestens 10 Zeichen) und „Rolle“ (Standard „Leser“).
- „Rolle“: direkt in der Liste ändern. Die eigene Rolle lässt sich nicht ändern, und mindestens ein Administrator muss bleiben.
- „Passwort setzen“: nur für lokale Benutzer. Beendet alle Sitzungen des Benutzers.
- „2FA zurücksetzen“: Der Benutzer muss die Zwei-Faktor-Anmeldung neu einrichten.
- „Löschen“: entfernt den Benutzer mit seinen Sitzungen, API-Tokens und privaten gespeicherten Ansichten. Sich selbst kann man nicht löschen.

Was die einzelnen Rollen dürfen, steht in Kapitel 12.

### 7.13 API-Tokens für das Panel

Skripte, Monitoring und Automatisierung sprechen die Panel-API mit einem API-Token statt mit einer Anmeldung an. Jede Rolle kann eigene Tokens anlegen.

1. Öffne *Einstellungen › API-Tokens* und klicke auf „Token erstellen“.
2. Fülle „Name“ (z. B. „Monitoring“) und „Rolle“ aus. Die Rolle darf höchstens deine eigene sein.
3. Wähle unter „Läuft ab“ ein Ablaufdatum. Vorbelegt sind 90 Tage.
4. Klicke auf „Erstellen“. Das Token beginnt mit `spt_` und wird nur einmal angezeigt.
5. Verwende es so:

```
curl -H "Authorization: Bearer spt_…" https://sentinel.firma.de/api/status
```

Ein Token handelt im Namen seines Kontos. Es hat die niedrigere der beiden Rollen: die des Tokens oder die aktuelle Rolle des Kontos. Mit dem Konto verliert auch das Token seine Rechte, und beim Löschen des Kontos verschwindet es. Ein neues Passwort, das Zurücksetzen der 2FA und das Löschen eines AD- bzw. OAuth-Kontos widerrufen seine Tokens ebenfalls; ist das Konto in Sentinel gesperrt oder seine Anmeldequelle abgeschaltet, gelten sie so lange nicht. Mit einem Token lassen sich keine weiteren Tokens erzeugen. Die Liste zeigt, wann und von welcher IP-Adresse ein Token zuletzt benutzt wurde. „Widerrufen“ macht es sofort ungültig. Administratoren sehen und widerrufen die Tokens aller Benutzer.

### 7.14 Sentinel als OIDC-Server für Anwendungen

Sentinel kann selbst Anmeldedienst (OpenID Provider) für Anwendungen sein, die OpenID Connect sprechen – etwa Grafana, Nextcloud, Gitea/Forgejo, Proxmox VE, Portainer, Jenkins oder Vaultwarden. Die Anwendung schickt ihre Benutzer zur Anmeldung an Sentinel und bekommt Name, E-Mail-Adresse und Gruppen zurück. Angemeldet wird mit denselben Konten wie beim Site-Login: Active Directory, Zugangskonten und – vermittelt – die eingerichteten OAuth-Anbieter. Zweiter Faktor (App oder Passkey), Sperren nach Fehlversuchen, „Überall abmelden“ und das Anmeldeprotokoll gelten auch hier.

Im Unterschied zum Site-Login (Kapitel 7.3), bei dem Sentinel vor der Anwendung steht und Benutzer-Header weiterreicht, kümmert sich hier die Anwendung selbst um Konten und Rechte; Sentinel bestätigt nur, wer sich anmeldet. Beides lässt sich kombinieren.

**So funktioniert es.** Die Anmeldung läuft über eine eigene Site in Caddy, die Anmelde-Adresse (Issuer), z. B. `https://sso.firma.de`. Dort zeigt der Agent die bekannte Anmeldeseite und reicht die Protokollaufrufe (Code gegen Token tauschen, Benutzerdaten, Schlüssel) an das Panel weiter. Das Panel hält Anwendungen, Signaturschlüssel und Tokens und muss für Benutzer und Anwendungen **nicht** erreichbar sein.

**Einrichten**

1. Lege in der Caddyfile die Site für die Anmelde-Adresse an:

   ```
   sso.firma.de {
   	sentinel
   	respond "Anmeldung" 200
   }
   ```

2. Ordne der Adresse eine Policy zu (Host `sso.firma.de` oder `sentinel <policy>` in der Site) und aktiviere dort den Reiter „Anmeldung“. Deren Einstellungen gelten für alle Anwendungen: Anmeldemethoden, zweiter Faktor, erlaubte Gruppen, „Netze ohne zweiten Faktor“, SSO. Auch Pfad-Regeln (z. B. „nur aus dem LAN“), Ratelimits, Geo- und IP-Regeln der Policy greifen. Die Bot-Challenge gilt für die Endpunkte nicht, weil Anwendungen den Token-Endpunkt direkt aufrufen.
3. Öffne *Site-Login & Konten › OIDC-Server*, schalte „OIDC-Server einschalten“ an, trage die Anmelde-Adresse ein und speichere. Die Adresse besteht nur aus Schema und Host (ohne Pfad) und muss mit `https://` beginnen; `http://` ist nur für `localhost`/`127.0.0.1` erlaubt. Der Kasten „Noch zu tun“ zeigt, was noch fehlt (Site, Policy, Anmeldung).
4. Klicke unter „Anwendungen“ auf „+ Anwendung“, trage Name und Redirect-URI ein und klicke auf „Anlegen“. Client-ID und Client-Secret werden **einmal** angezeigt.
5. Trage in der Anwendung Discovery-Adresse (bzw. Issuer), Client-ID und Client-Secret ein. Die Adressen aller Endpunkte stehen im Reiter zum Kopieren bereit.

**Einstellungen einer Anwendung**

| Einstellung | Bedeutung | Standard |
|---|---|---|
| „Redirect-URIs“ | Rücksprungadressen der Anwendung, eine pro Zeile, exakt wie gesendet (keine Platzhalter). `http://` nur für localhost, Mobil-Apps mit eigenem Schema in umgekehrter Domain-Schreibweise (`de.firma.app:/cb`) | – |
| „Adressen nach dem Abmelden“ | wohin Sentinel nach dem Abmelden über die Anwendung zurückleiten darf | leer |
| „Erlaubte Gruppen“ / „Erlaubte Benutzer“ | wer die Anwendung nutzen darf; leer = alle, die sich an der Anmelde-Adresse anmelden dürfen | leer |
| „Anmeldemethoden“ | `directory`, `local`, `oidc:<anbieter>`; leer = alle (öffentliche Anbieter wie GitHub nur mit Gruppen/Benutzern oder ausdrücklich) | leer |
| „Signaturverfahren“ | RS256 versteht jede Anwendung; ES256 ist kürzer | RS256 |
| „Öffentliche Anwendung“ | Single-Page- oder Mobil-App ohne Secret; dann ist PKCE Pflicht | aus |
| „PKCE verlangen“ | Schutz gegen abgefangene Codes. Nur abschalten, wenn die Anwendung kein PKCE kann (Sentinel zeigt dann einen Hinweis statt der Anmeldung) | an |
| „Zweiten Faktor verlangen“ | zweiter Faktor für diese Anwendung, auch wenn die Policy ihn nicht verlangt oder das Netz davon befreit ist | aus |
| „Zustimmung abfragen“ | Benutzer sehen beim ersten Mal, welche Angaben die Anwendung erhält, und bestätigen das | aus |
| „Refresh-Tokens ausgeben“ / „gültig … Tage“ | Die Anwendung kann sich neue Tokens holen, ohne den Benutzer erneut zur Anmeldung zu schicken. Jedes Refresh-Token gilt nur einmal (Rotation); taucht ein benutztes wieder auf, endet die ganze Freigabe. Spätestens 90 Tage nach der Anmeldung ist Schluss | aus, 30 Tage |

**Was die Anwendung erhält.** Scopes `openid` (Pflicht), `profile`, `email`, `groups` und `offline_access`. Claims: `sub` (feste Kennung des Kontos, z. B. `u-3f9c…`; ein später angelegtes Konto mit demselben Namen bekommt eine andere – Konten von vor v1.3.0 behalten ihren Namen als `sub`), `preferred_username` (Benutzername in Kleinbuchstaben), `name`, `email` mit `email_verified`, `groups` (Gruppennamen; bei GitHub & Co. mit Präfix wie `github:meine-org`), `amr` (`pwd`, `fed` für OAuth-Anbieter, `mfa` mit zweitem Faktor), `auth_time` und `sid`. Access- und ID-Token sind signierte JWTs (Access-Token mit `typ: at+jwt`) und gelten standardmäßig 60 Minuten („Gültigkeit von Access- und ID-Token“). Gruppen von AD-Konten stammen aus deren letzter Anmeldung.

**Beispiele**

- **Grafana** (`grafana.ini`, Abschnitt `[auth.generic_oauth]`): `enabled = true`, `client_id`, `client_secret`, `scopes = openid profile email groups`, `auth_url = <Issuer>/.sentinel/oidc/authorize`, `token_url = <Issuer>/.sentinel/oidc/token`, `api_url = <Issuer>/.sentinel/oidc/userinfo`, `use_pkce = true`, Rollen z. B. mit `role_attribute_path = contains(groups[*], 'Grafana-Admins') && 'Admin' || 'Viewer'`. Redirect-URI: `https://grafana.firma.de/login/generic_oauth`.
- **Nextcloud** (App „OpenID Connect user backend“): Discovery-Adresse `<Issuer>/.well-known/openid-configuration`, Client-ID und Secret; Redirect-URI `https://cloud.firma.de/apps/user_oidc/code`.
- **Gitea/Forgejo**: *Website-Administration › Authentifizierungsquellen › OAuth2 › OpenID Connect* mit der Discovery-Adresse; Redirect-URI `https://git.firma.de/user/oauth2/<Name der Quelle>/callback`.

**Abmelden.** Meldet sich jemand in der Anwendung ab und leitet die Anwendung zu `…/.sentinel/oidc/logout` weiter, endet auch die Sentinel-Sitzung (bei SSO auf allen Sites der Domain). Mit `id_token_hint` geschieht das sofort, ohne fragt Sentinel nach. Danach geht es zur eingetragenen „Adresse nach dem Abmelden“ zurück. Die Refresh-Tokens dieser Sitzung werden damit ungültig.

**Freigaben und Schlüssel.** „Aktive Freigaben“ listet die Refresh-Tokens pro Konto und Anwendung; „Widerrufen“ beendet eine Freigabe. Ein gesperrtes, abgelaufenes oder gelöschtes Konto und „Überall abmelden“ beenden alle Freigaben des Kontos beim nächsten Erneuern. „Schlüssel erneuern“ erzeugt neue Signaturschlüssel; die alten bleiben 7 Tage in der JWKS, Anwendungen laden die neuen selbst nach. In der Sicherung sind die Anwendungen enthalten (Secrets nur als Hash), die Schlüssel nicht – nach einer Wiederherstellung entstehen neue.

**Hinweise**

- Entfernen oder deaktivieren einer Anwendung beendet ihre Freigaben sofort; bereits ausgegebene Access-Tokens laufen bis zu ihrem Ablauf weiter.
- Bei jedem Erneuern und bei jeder Userinfo-Abfrage prüft Sentinel Konto, Policy der Anmelde-Adresse (auch eine Pfad-Regel für `/.sentinel/oidc/`) und die Regeln der Anwendung erneut. Wird der Zugriff eingeschränkt, endet er dort beim nächsten Erneuern.
- Falsche Client-Secrets sperren nur die Adresse, von der sie kommen (10 Versuche in 15 Minuten), nicht die Anwendung selbst.
- Unterstützt werden der Authorization-Code-Flow (mit PKCE) und Refresh-Tokens. Nicht unterstützt: Implicit Flow, `response_mode=form_post`, Client Credentials, SAML und LDAP-Proxy.
- Vertrauenswürdige Quellen (*Einstellungen › Netz & Vertrauen*) kommen an der Anmelde-Adresse wie alle anderen zur Anmeldeseite – für sie entfällt nur die Prüfung durch Sentinel vor Sites, nicht die Anmeldung an Anwendungen.

---

## 8. Caddyfile, Sites und Zertifikate

Dieses Kapitel beschreibt, wie du die Konfiguration von Caddy im Panel bearbeitest, neue Sites anlegst und Zertifikate überwachst. Alle Seiten dieses Kapitels arbeiten auf genau einer Caddy-Instanz. Sind mehrere Instanzen verbunden, zeigt ein farbiger Balken „Caddy-Instanz“ oben auf der Seite, welche gemeint ist; über „Wechseln:“ wählst du eine andere (siehe Kapitel 9).

### 8.1 Der Caddyfile-Editor

Aufruf: *Konfiguration › Caddyfile-Editor*.

#### Was bearbeitet werden kann

Der Editor zeigt die Haupt-Caddyfile (Umgebungsvariable `SENTINEL_CADDYFILE`, Standard `/etc/caddy/Caddyfile`) und alle Konfigurationsdateien im selben Verzeichnis und in bis zu drei Ebenen darunter:

- Dateien, deren Name mit `Caddyfile` beginnt,
- Dateien mit der Endung `.caddy`, `.caddyfile`, `.conf` oder `.snippet`.

Versteckte Ordner sowie `.git`, `node_modules`, `certificates`, `acme`, `locks`, `ocsp` und `pki` werden übergangen. Angezeigt werden höchstens 300 Dateien mit je bis zu 2 MB. Dateien, die das Panel nicht schreiben darf, tragen ein Schloss-Symbol.

Bei einer entfernten Instanz ist der Editor nur im Modus `remote full` verfügbar. Sonst erscheint der Hinweis „Die Caddyfile dieser Instanz ist im Panel nicht bearbeitbar.“ mit dem Block, der auf dem Server ergänzt werden muss (siehe Kapitel 9.3).

**Hinweis:** Lesen dürfen alle Rollen. Prüfen über Caddy, Übernehmen, „Sentinel einfügen“ und das Wiederherstellen von Versionen erfordern die Rolle Bearbeiter oder Administrator. Leser sehen in der Statuszeile „Prüfen über Caddy erfordert das Recht „Konfiguration““ – eine Prüfung durch Caddy könnte Umgebungsvariablen und lesbare Dateien preisgeben.

#### Aufbau der Seite

| Bereich | Inhalt |
|---|---|
| Links „Dateien“ | Dateiliste; ◆ markiert die Haupt-Caddyfile, ● eine geänderte Datei. „+ Neue Datei“ legt eine Datei an. |
| Links „Gliederung“ | Blöcke der aktuellen Datei: G = Globale Optionen, S = Site, ( ) = Snippet, & = benannte Route. Ein „!“ kennzeichnet eine Site ohne `sentinel`. ✎ öffnet die Site im Formular. |
| Werkzeugleiste | „Prüfen“, „Vollständig prüfen“, „Formatieren“, „Sentinel einfügen“, „Neue Site“, „Formular“, „Vorlage …“, „Suchen“, „Befehle“, „Änderungen“, „Löschen“, „Doku“ |
| Oben rechts | „Versionen“, „Verwerfen“, „Übernehmen“ (mit Anzahl geänderter Dateien, z. B. „Übernehmen (2)“) |
| Unter dem Editor | Liste der Fehler, Warnungen und Hinweise; ein Klick springt zur Stelle, auch in andere Dateien |
| Statusleiste | Prüfergebnis (z. B. „Gültig · 4 Sites“), Brotkrumen-Pfad, Zeile und Spalte, „F1: Befehle · ⌨ Kürzel“ |
| Rechts „Referenz“ (über „Doku“) | Beschreibung der Direktive am Cursor, Unterdirektiven zum Einfügen per Klick, „Beispiel einfügen“, „Offizielle Dokumentation öffnen“, Suchfeld „Direktive oder Option suchen …“ |

Der Editor verhält sich wie VS Code (Mehrfach-Cursor, Suchen und Ersetzen mit Regex, Einklappen, Gehe zu Definition, Matcher umbenennen). Die vollständige Liste zeigt „Tastenkürzel“ in der Statusleiste; die wichtigsten:

| Aktion | Kürzel |
|---|---|
| Befehlspalette | F1 oder Strg+Umschalt+P |
| Übernehmen | Strg+S |
| Vorschläge | Strg+Leertaste |
| Formatieren | Umschalt+Alt+F |
| Suchen / Ersetzen | Strg+F / Strg+H |
| Gehe zu Zeile | Strg+G |
| Gehe zu Definition (Matcher, Snippet) | F12 oder Strg+Klick |
| Matcher umbenennen | F2 |
| Nächster Hinweis / Hinweise-Liste | F8 / Strg+Umschalt+M |
| Weiteren Cursor setzen / nächstes Vorkommen markieren | Alt+Klick / Strg+D |

#### Prüfen

Der Editor prüft auf drei Ebenen:

1. **Beim Tippen** prüft er die Datei selbst und bietet Schnellkorrekturen an, etwa für Tippfehler („Unbekannte Direktive „…“ – meintest du „…“?“), doppelte Site-Adressen, veraltete Namen (`basicauth` → `basic_auth`), Transport-Optionen am falschen Ort, nie erreichbare Handler, unbekannte Snippets oder Policies, Klartext-Passwörter in `basic_auth` und Sites ohne `sentinel`.
2. **„Prüfen“** läuft automatisch etwa eine Sekunde nach jeder Änderung. Das Panel legt die geänderten Dateien in ein Prüfverzeichnis und lässt die Konfiguration von Caddy über die Admin-API übersetzen. Fehler erscheinen mit Zeilenangabe, auch in importierten Dateien. Zusätzlich meldet das Panel, wie viele Sites ohne `sentinel` laufen und ob `admin off` die Admin-API abschalten würde.
3. **„Vollständig prüfen“** führt `caddy validate` aus. Dabei richtet Caddy alle Module wirklich ein und findet so auch Fehler, die beim Übersetzen nicht auffallen: fehlende Zertifikatsdateien, ungültige Ausdrücke, unbekannte Plugins. Log-Dateien und Dateien, die nur Caddy lesen darf, öffnet die Prüfung nicht; sie stehen im Ergebnis unter „Nicht geprüft“. Bei „permission denied“ ergänzt das Panel einen Lösungshinweis. Die Prüfung dauert höchstens 60 Sekunden. Bei der lokalen Instanz nutzt das Panel das Programm aus `SENTINEL_CADDY_BIN`; ist die Variable leer gesetzt (Installation „nur Panel“), steht die vollständige Prüfung nicht zur Verfügung. Bei entfernten Instanzen führt der Agent die Prüfung mit seinem eigenen Caddy aus.

**Tipp:** Vor dem Übernehmen größerer Änderungen „Vollständig prüfen“ klicken. „Übernehmen“ selbst prüft nur auf Ebene 2; Fehler, die erst beim Laden auftreten, führen dann zwar zum automatischen Zurücksetzen (siehe unten), werden aber erst in diesem Moment sichtbar.

#### Formatieren, Sentinel einfügen, Vorlagen

- **„Formatieren“** bringt die geöffnete Datei in Caddys Standardformat (wie `caddy fmt`).
- **„Sentinel einfügen“** setzt `sentinel` als erste Zeile in jeden Site-Block der geöffneten Datei, dem die Direktive fehlt. Meldung: „sentinel in n Sites eingefügt“ oder „Alle Site-Blöcke dieser Datei enthalten bereits sentinel“. Für weitere Dateien die Aktion dort wiederholen.
- **„Vorlage …“** fügt einen Baustein am Cursor ein: Reverse Proxy, Statische Website, Single-Page-App, PHP (WordPress, Nextcloud …), Weiterleitung www → apex, API + Frontend getrennt, Load-Balancing mit Health-Check, Security-Header, Basic-Auth für Bereich, Nur interne Netze, Snippet definieren, Zugriffs-Log als JSON, Sentinel global konfigurieren, Hinter Cloudflare / Proxy.

Alle drei Aktionen ändern nur den Editor-Inhalt. Wirksam wird erst „Übernehmen“.

#### Dateien anlegen und löschen

1. „+ Neue Datei“ klicken und den Pfad relativ zum Caddyfile-Verzeichnis eingeben, z. B. `sites/blog.caddy`. Die Endung muss `.caddy`, `.caddyfile`, `.conf` oder `.snippet` sein.
2. Inhalt schreiben. Die Datei muss von der Caddyfile eingebunden werden (z. B. `import sites/*.caddy`), sonst wirkt sie nicht – das Panel erinnert daran.
3. „Übernehmen“ – erst jetzt entsteht die Datei.

Zum Löschen die Datei öffnen, „Löschen“ und „Zum Löschen vormerken“ wählen; gelöscht wird beim nächsten „Übernehmen“. Die Haupt-Caddyfile kann nicht gelöscht werden.

„Änderungen“ zeigt alle ausstehenden Änderungen als Diff. „Verwerfen“ setzt alle Dateien auf den gespeicherten Stand zurück.

**Achtung:** Ungespeicherte Änderungen existieren nur im geöffneten Browser-Tab. Beim Verlassen der Seite fragt das Panel nach; danach sind sie verloren.

### 8.2 Änderungen übernehmen

1. „Übernehmen“ klicken (oder Strg+S).
2. Der Dialog „Konfiguration übernehmen“ zeigt den Diff aller geänderten Dateien. Optional eine „Notiz zur Version“ eintragen, z. B. „Blog hinzugefügt“.
3. „Prüfen und übernehmen“ klicken.

Das Panel geht dann so vor:

1. Es prüft die Konfiguration (wie „Prüfen“). Ist sie ungültig, wird nichts geschrieben; die Fehler erscheinen im Editor.
2. Es merkt sich den bisherigen Stand aller Dateien.
3. Es schreibt die geänderten Dateien und löscht vorgemerkte Dateien.
4. Es lädt die neue Konfiguration über die Admin-API in Caddy – ohne Neustart, laufende Verbindungen bleiben bestehen.
5. Lehnt Caddy die Konfiguration ab, stellt das Panel die alten Dateien wieder her und entfernt neu angelegte. Meldung: „Nicht übernommen: …“; im Ereignisprotokoll steht „Konfiguration abgelehnt: …“.
6. Bei Erfolg speichert das Panel eine neue Version (Autor, Notiz; ohne Notiz „Änderung über Editor“) und meldet „Übernommen – Caddy läuft mit Version #n“. Das Ereignis „Konfiguration angewendet: …“ kann als Benachrichtigung verschickt werden (siehe Kapitel 11.1).

Schlägt das Schreiben fehl, lautet die Meldung „Speichern fehlgeschlagen: … (Schreibrechte für <Verzeichnis> prüfen)“.

**Gleichzeitiges Bearbeiten:** Hat jemand die Datei geändert, seit du sie geöffnet hast – im Panel oder von Hand auf dem Server –, übernimmt der Editor nichts und meldet „Datei inzwischen geändert“. Du kannst dann abbrechen, deine Änderungen kopieren und die Seite neu laden, oder mit „Trotzdem überschreiben“ deinen Stand durchsetzen; der andere Stand bleibt im Versionsverlauf.

Lehnt Caddy die Konfiguration ab, vermerkt das Audit-Log „Caddyfile übernommen – von Caddy abgelehnt, nichts geändert“.

### 8.3 Versionen, Vergleich und Zurückrollen

„Versionen“ öffnet die Liste der gespeicherten Stände dieser Instanz mit den Spalten „#“, „Zeit“, „Von“ und „Notiz“. Die oberste Zeile trägt „aktuell“. Angezeigt werden die letzten 100 Versionen, aufbewahrt die letzten 200 je Instanz.

Versionen entstehen

- bei jedem erfolgreichen Übernehmen (auch durch den Site-Assistenten und beim Wiederherstellen),
- beim ersten Start des Panels als „Initialer Import“ des vorhandenen Stands,
- automatisch als „Extern geändert (auf Platte erkannt)“, wenn du die Versionsliste öffnest und die Dateien inzwischen außerhalb des Panels geändert wurden.

**Eine frühere Version wiederherstellen:**

1. „Versionen“ öffnen.
2. Bei der gewünschten Version „Vergleichen“ klicken. Der Diff zeigt „Version #n → aktueller Stand“ (einschließlich noch nicht übernommener Editor-Änderungen).
3. „Wiederherstellen“ klicken und bestätigen.
4. Das Panel setzt alle Dateien auf diesen Stand – Dateien, die es damals nicht gab, werden gelöscht – und lädt Caddy neu. Es gilt derselbe Ablauf wie in 8.2 einschließlich automatischem Zurücksetzen. Die neue Version trägt die Notiz „Wiederhergestellt: Version #n“; der vorherige Stand bleibt als Version erhalten.

Lehnt Caddy die alte Version ab (etwa weil eine Zertifikatsdatei nicht mehr existiert), erscheint „Wiederherstellung abgelehnt: …“ und nichts ändert sich.

### 8.4 Sites im Formular bearbeiten

Für einzelne Site-Blöcke gibt es einen Formular-Modus, der ohne Caddyfile-Kenntnisse auskommt.

- **Bestehende Site:** Cursor in den Site-Block setzen und „Formular“ klicken, oder ✎ in der Gliederung.
- **Neue Site:** „Neue Site“ in der Werkzeugleiste.

| Abschnitt | Inhalt |
|---|---|
| „Adressen“ | Domains und Adressen der Site; bei neuen Sites zusätzlich die Umleitung der www-Variante |
| „Schutz durch Sentinel“ | „sentinel aktiv“; Policy fest wählen oder „Policy automatisch (nach Host)“ |
| „Ziel“ | Reverse Proxy, Statisch, Single-Page-App, Weiterleitung, Antwort oder Keins. Beim Reverse Proxy: „Upstreams“ (eins pro Zeile, mehrere = Lastverteilung), „Verteilung“, „Health-Check-Pfad“, „Intervall“, „HTTPS zum Backend“, „Zertifikat – nicht prüfen ⚠“, „Host-Header – Host des Backends senden“. Statisch: Verzeichnis, Verzeichnislisten. PHP-FPM-Adresse. Weiterleitung mit 301, 302 oder 308. |
| „Pfad-Routen“ | eigene Ziele für Pfade (Backend, Dateien, Antwort, Weiterleitung), optional „Präfix entfernen“ |
| „Matcher & Regeln“ | benannte Matcher (Pfad, Methode, Client-IP, Verbindungs-IP, Host, Header, Query, Protokoll, Pfad (Regex), Ausdruck (CEL)) und Regeln wie „Verbindung abbrechen“ |
| „TLS“ | Automatisch (Let’s Encrypt), Interne CA, ACME mit E-Mail, Eigenes Zertifikat („Zertifikat“, „Schlüssel“) |
| „Optionen“ | Kompression, Sicherheits-Header (HSTS, nosniff, Frame-Options, Referrer-Policy, ohne Server), eigene Header, X-Robots-Tag, Zugriffs-Log (optional JSON) |
| „Weitere Direktiven“ | Direktiven, die das Formular nicht abbildet |
| „Einfügen“ (nur neue Site) | „Neue Datei sites/<domain>.caddy“, „Ans Ende der Haupt-Caddyfile“ oder am Cursor |

Rechts zeigen die Reiter „Ergebnis“ (erzeugter Block), „Änderungen“ (Diff zum bisherigen Block) und „Prüfung“ (Hinweise) den Stand live. Teile des Blocks, die das Formular nicht versteht, bleiben unverändert erhalten.

„Übernehmen“ bzw. „Einfügen“ im Formular schreibt den Block nur in den Editor („Site aktualisiert – mit Strg+Z rückgängig“). Danach im Editor „Übernehmen“ klicken. Wird eine neue Datei unter `sites/` angelegt und fehlt `import sites/*.caddy` in der Caddyfile, ergänzt der Editor diese Zeile.

### 8.5 Die Seite „Sites“

Aufruf: *Sites*. Die Seite zeigt die Sites der **laufenden** Konfiguration – also das, was Caddy tatsächlich ausführt, nicht den Stand der Dateien. Sie funktioniert auch bei entfernten Instanzen im Modus `remote read`.

Fehlt in Sites die Direktive `sentinel`, erscheint oben: „n von m Sites laufen ohne die Direktive sentinel – dort gibt es keine Policies, Bans oder Metriken. Im Editor ergänzen.“

| Spalte | Inhalt |
|---|---|
| „Hosts“ | Hostnamen (Link zu den Analysen); `*` erscheint als „alle Hosts“ |
| „Listener“ | Ports bzw. Adressen |
| „Handler“ | Caddy-Handler, darunter Upstreams oder Verzeichnisse |
| „Sentinel / Policy“ | zuständige Policy oder „fehlt“ |
| „Requests 24 h“ | Verlauf und Anzahl |
| „5xx“, „Blockiert“, „Ø Zeit“ | Kennzahlen der letzten 24 Stunden |

In der Spalte „Sentinel / Policy“ gilt:

- Steht die Policy fest in der Direktive (`sentinel <policy-id>`), zeigt die Seite „aktiv“ mit dem Zusatz „(fest in der Direktive)“. Ändern nur im Editor.
- Sonst wählst du die Policy über das Auswahlfeld. Das Panel trägt den Host in die gewählte Policy ein und aus allen anderen aus. Die Standard-Policy ist mit „(Standard)“ markiert. Dafür ist die Rolle Bearbeiter oder Administrator nötig.

**Wartung per Schnellschalter** (Bearbeiter, Administrator):

1. Bei der Site „⚒ Wartung …“ klicken.
2. „Meldung“ eintragen, unter „Endet“ das Ende wählen (vorgeschlagen: in einer Stunde) und unter „Trotzdem erreichbar für“ IPs oder Netze eintragen, die weiter Zugriff haben sollen. Die eigene IP wird angezeigt.
3. „Wartung starten“. Zum vorzeitigen Beenden „⚒ Wartung aktiv – beenden“ klicken.

**Achtung:** Die Wartung gilt für die Policy, also für **alle** Hosts, die diese Policy nutzen. Details zum Wartungsmodus in Kapitel 5.

Unter „Upstreams“ listet die Seite alle Reverse-Proxy-Ziele mit „Aktive Requests“, „Fehler“ und „Zustand“ („ok“ oder „Fehler gemeldet“).

### 8.6 Neue Site mit dem Assistenten

Aufruf: *Sites › Neue Site …* (Bearbeiter, Administrator). Der Assistent legt eine Site in drei Schritten an und prüft vorher DNS und Konfiguration.

**Schritt 1 – Art wählen:** „Reverse Proxy“, „Statische Dateien“, „PHP-Anwendung“ oder „Weiterleitung“. Bei mehreren Instanzen nennt der Assistent die Instanz, auf der die Site entsteht.

**Schritt 2 – Angaben:**

| Feld | Bedeutung | Standard |
|---|---|---|
| „Domain(s)“ | eine oder mehrere Domains, durch Komma getrennt; Wildcards (`*.example.com`) und Ports (`:8443`) sind erlaubt | – |
| „Ziel“ (Reverse Proxy) | Adresse der Anwendung, z. B. `10.0.0.5:8080` oder `http://app:3000`; mehrere mit Leerzeichen = Lastverteilung | – |
| „Verzeichnis“ (Statisch, PHP) | absoluter Pfad ohne Leerzeichen, für den Benutzer `caddy` lesbar | `/srv/www/` |
| „PHP-FPM“ | Socket oder Adresse | `unix//run/php/php-fpm.sock` |
| „Ziel“ (Weiterleitung) | Adresse mit `http://` oder `https://`; Pfad und Query bleiben erhalten (301) | `https://` |
| „Policy“ | Standard-Policy oder eine bestimmte; die Domains werden der Policy zugeordnet | Standard-Policy |
| „www-Variante anlegen und auf die Domain umleiten“ | zusätzliche Site `www.<domain>` mit Umleitung | aus |
| „Zertifikat der internen CA (tls internal)“ | für interne Namen; der Assistent empfiehlt es bei `.local`, `.lan`, `.internal`, `.home.arpa`, `.intern` und Namen ohne Punkt | aus |
| „Komprimieren (zstd, gzip)“ | Kompression | an |
| „Verfügbarkeit überwachen (Monitor anlegen)“ | legt einen Monitor an (Intervall 60 s); nur mit Recht auf Policies | an |

„Weiter: prüfen“ klicken.

**Schritt 3 – Prüfen:**

- **DNS:** Für jede Domain zeigt der Assistent, wohin sie zeigt: „zeigt auf diesen Server“, „zeigt woandershin“, „kein DNS-Eintrag“, „nicht sicher prüfbar“ (etwa bei Servern hinter NAT) oder „Wildcard“ (Zertifikat nur per DNS-Challenge). Passt eine Domain nicht, kannst du die Site trotzdem anlegen; das Zertifikat klappt aber erst, wenn der DNS-Eintrag stimmt.
- **Vorschau:** der erzeugte Block. Bindet die Caddyfile `sites/*` ein, entsteht eine eigene Datei („Neue Datei sites/<domain>.caddy“), sonst wird der Block an die Caddyfile angehängt.
- **Prüfung durch Caddy:** „Caddy hat die Konfiguration geprüft – sie ist gültig.“ oder die Fehlermeldung. Bei einem Fehler ist „Site anlegen“ gesperrt.

„Site anlegen“ ordnet die Domains der gewählten Policy zu, übernimmt die Konfiguration wie in 8.2 (Version mit Notiz „Site-Assistent: <Domains>“) und legt bei Bedarf den Monitor an. Meldung: „<domain> ist angelegt – Caddy hat die Konfiguration geladen“.

Der Assistent bricht ab, wenn eine Domain schon in einer Datei eingerichtet ist („<domain> ist schon in <Datei> eingerichtet“) oder die Zieldatei bereits existiert. Solche Sites im Editor bearbeiten.

**Tipp:** Für Optionen, die der Assistent nicht kennt (Pfad-Routen, Header, eigene Zertifikate), im Editor „Neue Site“ verwenden (siehe 8.4).

### 8.7 Zertifikate

Aufruf: *Zertifikate*. Die Seite listet die Zertifikate, die Caddy automatisch verwaltet. Gelesen werden nur die öffentlichen `.crt`-Dateien aus `<Caddy-Datenverzeichnis>/certificates`.

- **Lokale Instanz:** Das Caddy-Datenverzeichnis stellst du unter *Einstellungen › Agent & Caddy › Zertifikats-Überwachung* ein (Paketinstallation: `/var/lib/caddy/.local/share/caddy`). Das Panel läuft als eigener Benutzer `caddy-sentinel` und darf das Verzeichnis nicht lesen – es enthält Caddys private Schlüssel. Die Zertifikate (ohne Schlüssel) holt es deshalb über den lokalen Sentinel-Agenten, wie bei entfernten Instanzen. Ist der Agent gerade nicht verbunden, zeigt die Seite den letzten bekannten Stand.
- **Entfernte Instanz:** Der Agent überträgt die Zertifikate (nie private Schlüssel). Das Panel hält eine Kopie und frischt sie im Hintergrund auf, wenn sie älter als zwei Minuten ist.

Oben stehen „Zertifikate“, „Handlungsbedarf“ und „Nächster Ablauf“. Die Tabelle zeigt „Domains“, „Aussteller“, „Status“, „Restlaufzeit“, „Gültig bis“ und „Schlüssel“.

| Status | Bedeutung |
|---|---|
| „gültig“ | alles in Ordnung |
| „Erneuerung fällig“ | im letzten Drittel der Laufzeit; Caddy erneuert in dieser Phase – normal |
| „läuft bald ab“ | Restlaufzeit unter der Warnschwelle (Standard 14 Tage; bei kurzlebigen Zertifikaten unter einem Sechstel der Laufzeit) – die Erneuerung hängt vermutlich |
| „abgelaufen“ | abgelaufen |

Ist „Zertifikate – vor Ablauf warnen“ eingeschaltet (Standard, siehe Kapitel 10.2), prüft das Panel stündlich und meldet „Zertifikat für … läuft in n Tagen ab – Caddy-Log prüfen (ACME-Erneuerung fehlgeschlagen?)“ (Schwere Hoch) bzw. „… ist abgelaufen“ (Kritisch), je Zertifikat höchstens einmal in 20 Stunden.

**Tipp:** Bei „läuft bald ab“ zuerst das Caddy-Log ansehen (`journalctl -u caddy`). Häufige Ursachen: DNS zeigt nicht auf den Server, Port 80/443 von außen nicht erreichbar, Ratelimit der Zertifizierungsstelle.

### 8.8 Interne CA

Aufruf: *Interne CA*. Nutzt eine Site `tls internal` oder `acme_server`, legt Caddy eine eigene Zertifizierungsstelle an. Die Seite liest dazu `<Caddy-Datenverzeichnis>/pki/authorities/*` (nur die Zertifikate) und die ACME-Datenbank `acme_server/<ca>/db` (nur lesend, als Kopie) – bei der lokalen Instanz über den Sentinel-Agenten (siehe 8.7). Gibt es keine CA, erscheint „Keine interne CA gefunden“.

Je CA zeigt die Seite:

- **Root-Zertifikat** und **aktives Intermediate** mit Laufzeit, Fingerabdruck (SHA-256), Schlüsseltyp, „PEM anzeigen“, „PEM kopieren“, „PEM herunterladen“. Das Root-Zertifikat verteilst du an Clients, die der CA vertrauen sollen.
- Abgleich mit der laufenden Instanz: Signiert Caddy gerade mit einem anderen Intermediate als im Speicher liegt, erscheint „Caddy nutzt anderes …“ – meist steht ein Neustart oder Reload aus.
- **Intermediate-Verlauf** mit der Zahl der damit ausgestellten Zertifikate.
- **ACME-Endpunkte** aus der laufenden Konfiguration („Directory-URL“, Laufzeit, Policy).
- **Ausgestellte Zertifikate** (per ACME an Clients und per `tls internal` an Caddy) mit Suche „Name, Seriennummer, Konto …“, Filtern nach Status („gültig“, „abgelaufen“, „widerrufen“), Quelle und Intermediate, Detailansicht und PEM-Download.

Status von Root und Intermediate: „gültig“, „Erneuerung fällig“, „überfällig“, „abgelaufen“. Mit eingeschalteter Zertifikatswarnung meldet das Panel ablaufende oder abgelaufene CA-Zertifikate und ein abweichendes Intermediate (jeweils höchstens alle sechs Stunden).

---

## 9. Mehrere Caddy-Server

Ein Panel kann beliebig viele Caddy-Server verwalten. Jeder Server ist eine **Instanz** mit Name, Farbe und eigenem Token.

### 9.1 Grundprinzip

- Die Instanz „local“ ist der Caddy auf dem Panel-Server. Sie wird automatisch angelegt (Name = Hostname, Kennzeichen „Panel-Server“) und kann nicht entfernt werden. Das Panel greift auf sie direkt zu: Admin-API und Caddyfile auf der Platte.
- Weitere Server verbinden sich über den Sentinel-Agent in ihrem Caddy mit dem Panel. Die Verbindung geht **immer vom Server zum Panel** (ausgehend, Long-Poll). Auf dem Caddy-Server muss kein Port geöffnet werden; das Panel muss aber von dort erreichbar sein.
- Jede Instanz hat ein eigenes Token. Das Panel speichert davon nur eine Prüfsumme und die ersten sechs Zeichen als Erkennungsmerkmal.

Pro Instanz getrennt sind Statistiken (über die Auswahl in der Kopfzeile auch gesammelt sichtbar), Caddyfile-Versionen, Request-Fluss, Sites, Zertifikate, Interne CA und Alarme. Für alle Instanzen gemeinsam gelten Policies (sofern nicht auf Instanzen beschränkt, siehe Kapitel 5), Sperren, Threat-Feeds und Einstellungen.

### 9.2 Die Seite „Caddy-Instanzen“

Aufruf: *Konfiguration › Caddy-Instanzen*. Anlegen, Bearbeiten, Token und Entfernen sind Administratoren vorbehalten; alle anderen Rollen sehen die Seite nur.

Jede Instanz erscheint als Karte:

| Angabe | Bedeutung |
|---|---|
| Status | „verbunden“ oder „offline“ |
| „ID“ | interne Kennung, aus dem Namen gebildet |
| „Zugriff“ | Zugriffsmodus (siehe 9.3) |
| „Caddyfile“ | Pfad der verwalteten Caddyfile (bei `remote full`) |
| „Zuletzt gemeldet“ | letzte Verbindung oder „noch nie“ |
| „Sentinel“ | Version des Agents |
| „Token“ | die ersten Zeichen des Tokens |
| Server-Liste | Hostname, Adresse und Caddy-Version jedes Servers, der dieses Token nutzt |

Knöpfe: „Bearbeiten“ (Name, Farbe, Beschreibung), „Token erneuern“ (lokal) bzw. „Neues Token“ (entfernt), „Entfernen“.

Eine Instanz gilt als verbunden, wenn ihr Agent in den letzten 30 Sekunden Daten geschickt hat. Für Zugriffe auf die Konfiguration muss der Agent zusätzlich in den letzten 70 Sekunden nach Aufträgen gefragt haben; sonst meldet das Panel „Caddy-Instanz nicht verbunden – läuft Caddy mit dem Sentinel-Agent und ist das Panel von dort erreichbar?“.

**Achtung:** Mehrere Server dürfen dasselbe Token nutzen; sie erscheinen dann als mehrere Server einer Instanz. Mit `remote full` gehen Änderungen an der Caddyfile aber an den Server, der zuerst antwortet. Für Fernverwaltung deshalb je Server eine eigene Instanz anlegen.

### 9.3 Zugriffsmodi

Was das Panel auf einem entfernten Server darf, entscheidet der Server selbst (Option `remote` in der Caddyfile oder Variable `SENTINEL_REMOTE`).

| Modus | Anzeige | Das Panel darf |
|---|---|---|
| `full` | „Fernverwaltung“ | zusätzlich zu `read`: Caddyfile und eingebundene Dateien lesen, bearbeiten, löschen (nie die Haupt-Caddyfile), prüfen (`caddy validate`) und laden – mit automatischem Zurücksetzen wie in Kapitel 8.2 |
| `read` | „Nur lesen“ | laufende Konfiguration **ohne Geheimnisse** (Tokens, Passwörter, Zugangsdaten in Headern und Ausdrücken schwärzt schon der Server), Backends, Caddy-Metriken, Zertifikate (ohne private Schlüssel), Interne CA |
| `off` | „Aus“ / „Keine Fernverwaltung“ | nichts an der Konfiguration; nur Schutz und Telemetrie |

Ohne Angabe gilt `read`. Das Installationsskript setzt im Agent-Modus standardmäßig `full`.

Für `full` braucht der Agent den Pfad der Caddyfile (Option `caddyfile`, sonst startet Caddy nicht) und der Benutzer, unter dem Caddy läuft, Schreibrechte auf das Konfigurationsverzeichnis. Unter systemd mit `ProtectSystem` zusätzlich `ReadWritePaths=/etc/caddy` – das Installationsskript setzt das.

**Hinweis:** Das Panel merkt sich den Modus einer entfernten Instanz bis zu zwei Minuten. Nach einer Umstellung (etwa von `read` auf `full`) kann der Editor also kurz noch „nicht bearbeitbar“ melden.

### 9.4 Einen weiteren Caddy-Server anbinden

Voraussetzung: Das Panel ist vom neuen Server aus erreichbar, in der Regel über HTTPS als eigene Site (siehe Kapitel 11.9). Trage die öffentliche Adresse unter *Einstellungen › Benachrichtigungen › Panel-URL für Links* ein; sie wird in den Installationsbefehl übernommen. Ohne Eintrag nimmt das Panel die Adresse, unter der du es gerade im Browser aufrufst.

1. *Caddy-Instanzen* › „Instanz hinzufügen“.
2. „Name“ (z. B. „Web-Server Rechenzentrum“), „Farbe“ und optional „Beschreibung“ eintragen, „Anlegen“.
3. Der Dialog „Token für „…““ zeigt das Token **nur dieses eine Mal** („Kopieren“). Unter „Zugriff des Panels auf diesen Caddy“ wählen: „Bearbeiten (remote full)“, „Nur lesen“ oder „Kein Zugriff“.
4. Den angezeigten Befehl kopieren („Befehl kopieren“) und auf dem neuen Server ausführen:

   ```bash
   SENTINEL_AGENT_TOKEN='<TOKEN>' bash <(wget -qO- https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh) \
     --agent --panel https://sentinel.example.com --remote full
   ```

   Läuft dort schon ein Caddy mit Sentinel-Modul, stattdessen den Block („Block kopieren“) in die globalen Optionen der Caddyfile einfügen und Caddy neu laden:

   ```caddyfile
   {
   	sentinel {
   		panel https://sentinel.example.com
   		token <TOKEN>
   		remote full
   		caddyfile /etc/caddy/Caddyfile
   	}
   }
   ```

5. Nach wenigen Sekunden zeigt die Karte „verbunden“.
6. In jede Site des neuen Servers, die geschützt werden soll, `sentinel` eintragen – bei `remote full` direkt im Editor mit „Sentinel einfügen“.

Das Installationsskript richtet im Agent-Modus Folgendes ein:

- Benutzer `caddy`, `/etc/caddy` mit Schreibrecht für die Gruppe `caddy`, `/etc/caddy/sites`, `/var/log/caddy`,
- `/usr/local/bin/caddy` mit Sentinel-Modul (ein vorhandenes fremdes Programm wird als `caddy.orig` gesichert),
- das Token in `/etc/caddy/sentinel-agent.token` (lesbar für Gruppe `caddy`),
- eine Ergänzung der Unit `caddy.service` mit `SENTINEL_PANEL`, `SENTINEL_TOKEN_FILE`, `SENTINEL_REMOTE` und `SENTINEL_CADDYFILE`,
- falls keine Caddyfile existiert, eine Start-Caddyfile mit einer `:80`-Site und `import sites/*.caddy`; enthält eine vorhandene Caddyfile kein `sentinel`, fragt es, ob die globale Option eingetragen werden soll (Sicherung als `/var/backups/caddy-sentinel/Caddyfile.vor-sentinel-<Zeit>`).

Ohne Optionen fragt das Skript interaktiv nach Panel-Adresse, Token und „Darf das Panel die Caddyfile bearbeiten? [J/n]“.

### 9.5 Token erneuern

**Entfernte Instanz:**

1. Auf der Karte „Neues Token“ klicken und bestätigen. Das alte Token ist sofort ungültig; der Agent wird abgewiesen.
2. Das neue Token aus dem Dialog kopieren.
3. Auf dem Server in die Token-Datei schreiben, bei einer Skript-Installation `/etc/caddy/sentinel-agent.token`. Der Agent liest die Datei nach einer Abweisung selbst neu ein (spätestens nach etwa zehn Sekunden) und verbindet sich wieder – ein Neuladen von Caddy ist nicht nötig.

Steht das Token direkt in der Caddyfile (`token …`) oder in der Variable `SENTINEL_TOKEN`, dort ändern und Caddy neu laden.

**Lokale Instanz:** „Token erneuern“ auf der Karte oder *Einstellungen › Agent & Caddy › Agent-Token › Erneuern*. Das Panel schreibt das neue Token in seine Token-Datei; der lokale Agent liest es beim nächsten abgewiesenen Abruf selbst und verbindet sich nach wenigen Sekunden neu. Andere Instanzen sind nicht betroffen.

Beide Vorgänge erscheinen im Ereignisprotokoll („Agent-Token erneuert“).

### 9.6 Instanz entfernen

„Entfernen“ weist den Agent sofort ab. Gespeicherte Statistiken bleiben bis zum Ende der Aufbewahrungsfrist erhalten. Policies, die auf diese Instanz beschränkt waren, verlieren den Eintrag; galt eine Policy **nur** dort, schaltet das Panel sie aus („Policy „…“ ausgeschaltet: sie galt nur auf der entfernten Instanz“).

Den Caddy auf dem Server selbst entfernt das nicht. Dafür dort `sudo caddy-sentinel-uninstall` ausführen (siehe Kapitel 11.7).

### 9.7 Der Agent im Betrieb

Der Agent ist Teil des Caddy-Programms und wird über die globale Option `sentinel` konfiguriert. Ohne Option gelten die Standardwerte – auf einem Server mit Panel und Caddy genügt das.

```caddyfile
{
	sentinel {
		panel         https://sentinel.example.com
		token_file    /etc/caddy/sentinel-agent.token
		cache_file    /var/lib/caddy/.local/share/caddy/sentinel-state.json
		fail_closed
		remote        full
		caddyfile     /etc/caddy/Caddyfile
		admin         http://localhost:2019
		geoip_country /var/lib/caddy-sentinel/geo/country.mmdb
		geoip_asn     /var/lib/caddy-sentinel/geo/asn.mmdb
	}
}
```

| Option | Bedeutung | Standard |
|---|---|---|
| `panel` | Adresse des Panels (auch als Argument: `sentinel <url>`) | `SENTINEL_PANEL`, sonst `http://127.0.0.1:7600` |
| `token` | Token direkt | `SENTINEL_TOKEN` |
| `token_file` | Datei mit dem Token, wenn kein `token` gesetzt ist | `SENTINEL_TOKEN_FILE`, sonst `/var/lib/caddy-sentinel/agent.token` |
| `cache_file` | Zwischenspeicher für den letzten Stand (Policies, Sperren) | `<Caddy-Datenverzeichnis>/sentinel-state.json` |
| `fail_closed` | ohne jeden bekannten Stand alle Anfragen mit 503 ablehnen | aus |
| `remote` | `off`, `read` oder `full` (siehe 9.3) | `SENTINEL_REMOTE`, sonst `read` |
| `caddyfile` | Caddyfile für `remote full` | `SENTINEL_CADDYFILE` |
| `admin` | Admin-API dieses Caddy für die Fernverwaltung (`http://host:port` oder `unix//pfad/zum.sock`) | Caddys eigene Vorgabe: `CADDY_ADMIN`, sonst `localhost:2019` |
| `geoip_country`, `geoip_asn` | eigene GeoIP-Datenbanken auf diesem Server (überschreiben die Panel-Einstellung) | – |

**Verhalten bei Ausfall des Panels:**

- Der Agent fragt das Panel per Long-Poll nach Änderungen; neue Policies und Sperren greifen in weniger als einer Sekunde.
- Jeden Stand speichert er im `cache_file`. Startet Caddy, während das Panel nicht erreichbar ist, lädt der Agent diesen Stand und schützt sofort.
- Fällt das Panel im Betrieb aus, gilt der letzte Stand weiter: Sperren, WAF, Ratelimits und bestehende Site-Anmeldungen funktionieren. Neue Site-Anmeldungen brauchen das Panel. Telemetrie puffert der Agent bis 20.000 Einträge und verwirft darüber hinaus (gezählt) – Caddy wartet nie auf das Panel.
- Ein fehlerhafter Stand vom Panel legt Caddy nicht lahm; der Agent behält den vorherigen. Lässt sich eine einschränkende Pfad-Regel oder eine blockierende WAF einer Policy nicht übernehmen und gibt es keine frühere funktionierende Fassung, antwortet diese Policy mit 503, statt ungeschützt zu öffnen.
- Kennt der Agent **gar keinen** Stand (erster Start, kein Cache, Panel nicht erreichbar), lässt er Anfragen standardmäßig ungeprüft durch. Mit `fail_closed` lehnt er sie stattdessen mit 503 ab.

**Tipp:** `fail_closed` lohnt sich für Sites, die ohne Anmeldung keinesfalls erreichbar sein dürfen. Dann aber darauf achten, dass der Cache auf dem Server erhalten bleibt.

---

## 10. Einstellungen

Aufruf: *Einstellungen*. Die Seite hat zehn Reiter. Administratoren sehen alle; die anderen Rollen nur „Konto & Sicherheit“, „API-Tokens“ und „Über & Lizenzen“.

Änderungen speichert der Knopf „Speichern“ oben rechts. Er wird aktiv, sobald etwas geändert wurde, und gilt für alle Reiter gemeinsam (nicht für Konto, API-Tokens und Über). Felder für Passwörter und Tokens bleiben leer; „•••••• gespeichert“ zeigt an, dass ein Wert hinterlegt ist. Leer lassen behält ihn.

Beim Speichern prüft das Panel IP-Adressen und Netze, Benachrichtigungskanäle und ob die Standard-Policy existiert. Unplausible Kombinationen (z. B. Wochenbericht ohne SMTP) meldet es als Warnung in der Seitenleiste (siehe Kapitel 3).

### 10.1 Bedrohungserkennung

Automatische Sperren, Gewichte der Signale und Angriffstools sind in Kapitel 6 beschrieben.

### 10.2 Benachrichtigungen

Dieser Reiter enthält die Alarme, den Wochenbericht, den E-Mail-Versand und die Benachrichtigungskanäle. Wie Kanäle eingerichtet und Nachrichten aufgebaut sind, beschreibt Kapitel 11.1; der Wochenbericht steht in Kapitel 11.2.

**Panel „Alarme“:**

| Feld | Bedeutung | Standard |
|---|---|---|
| „5xx-Quote ab (%)“ | Anteil der Serverfehler je Host über 5 Minuten; 0 = aus | 20 |
| „… bei mindestens Requests“ | Mindestzahl Anfragen in diesen 5 Minuten | 50 |
| „Traffic-Spitze ab Faktor“ | Anfragen pro Minute gegenüber dem Schnitt der letzten 30 Minuten; 0 = aus | 6 |
| „… bei mindestens Req/Min.“ | Mindestzahl Anfragen pro Minute | 300 |
| „Angriffswelle ab blockierten Req/Min.“ | blockierte Anfragen pro Minute je Host; 0 = aus | 200 |
| „Anstieg einer Fehlerursache“ | meldet, wenn eine Ursache (WAF-Regel, Ratelimit, 502 eines Backends …) sprunghaft steigt, mit Bezug zur letzten Änderung | an |
| „… ab Anfragen in 10 Min.“ | Mindestzahl | 30 |
| „… und ab Faktor“ | gegenüber dem Schnitt der Stunde davor | 5 |
| „Agent-Ausfall“ | „melden, wenn sich Caddy nicht mehr meldet“ (nach 30 Sekunden ohne Daten) | an |
| „Zertifikate“ | vor Ablauf warnen, auch für die Interne CA | an |
| „Verfügbarkeit“ | Ausfälle und Wiederherstellung der Monitore melden | an |
| „Panel-URL für Links“ | öffentliche Adresse des Panels, z. B. `https://sentinel.example.com` | leer |

Die Alarme werden jede Minute geprüft; derselbe Alarm kommt höchstens alle 30 Minuten (Anstieg einer Fehlerursache: alle 60 Minuten).

| Alarm | Titel (Beispiel) | Schwere |
|---|---|---|
| 5xx-Quote | „Fehlerrate app.example.com: 35 % 5xx in 5 Min. (…)“ | Hoch |
| Traffic-Spitze | „Traffic-Spitze app.example.com: 2400 Req/Min (Ø 300)“ | Mittel |
| Angriffswelle | „Angriffswelle auf app.example.com: 450 blockierte Requests/Min“ | Kritisch |
| Agent-Ausfall | „Caddy-Agent web1 meldet sich nicht mehr“ | Kritisch |
| Fehlerursache | „Anstieg: … auf app.example.com – 120 in 10 Min. (sonst ~4) · kurz nach: … (vor 6 Min.)“ | Mittel, bei 5xx Hoch |

Die „Panel-URL für Links“ wird an mehreren Stellen gebraucht: für die Knöpfe in Benachrichtigungen, den Link im Wochenbericht, den Installationsbefehl neuer Instanzen und die Redirect-URI für OAuth (Kapitel 7).

**Panel „E-Mail-Versand (SMTP)“:**

| Feld | Bedeutung | Standard |
|---|---|---|
| „Server“ | SMTP-Server | – |
| „Port“ | Port | 587 |
| „Verschlüsselung“ | „STARTTLS (587)“, „TLS (465)“ oder „keine (nur intern!)“ | STARTTLS |
| „Absender“ | Absenderadresse; erscheint als „Caddy Sentinel <Adresse>“ | – |
| „Benutzer“, „Passwort“ | Anmeldung am Server; ohne Benutzer wird nicht angemeldet | – |

SMTP wird für E-Mail-Benachrichtigungen, den Wochenbericht und den Passwort-Reset von Zugangskonten (Kapitel 7) genutzt. Ohne Server oder Absender lautet die Fehlermeldung „SMTP ist nicht konfiguriert (Einstellungen › Benachrichtigungen)“.

**Panel „Stummgeschaltet“:** Liste der Benachrichtigungen, die über den Knopf „24 h stummschalten“ in einer Nachricht stummgeschaltet wurden, mit „Bis“ und „Von“. „Wieder melden“ hebt die Stummschaltung auf (ab Rolle Support).

### 10.3 Netz & Vertrauen

| Panel | Bedeutung |
|---|---|
| „Vertrauenswürdige Quellen“ | IPs und Netze, die **alle** Sentinel-Prüfungen umgehen (Sperren, WAF, Ratelimits), z. B. Monitoring oder das eigene Büro. Eine Adresse oder ein Netz pro Zeile. |
| „Nie automatisch sperren“ | Adressen, die das IDS nie sperrt; Policies gelten weiter. Standard: `127.0.0.0/8`, `::1`. Siehe Kapitel 6. |
| „GeoIP-Datenbanken“ | Pfade zu „Länder-Datenbank“ und „ASN-Datenbank“ (`.mmdb`) |

**Achtung:** Vertrauenswürdige Quellen sind von jedem Schutz ausgenommen. Nur Netze eintragen, die du kontrollierst.

**GeoIP:** Geeignet sind z. B. „IP to Country Lite“ und „IP to ASN Lite“ von DB-IP (CC BY 4.0) oder MaxMind GeoLite2. Die Pfade gelten für das Panel **und** für alle Agents; die Dateien müssen also auf jedem Server unter diesem Pfad liegen. Auf einzelnen Servern lassen sie sich mit `geoip_country`/`geoip_asn` überschreiben (Kapitel 9.7). Unter Docker ein Verzeichnis in beide Container einhängen (Kapitel 11.8).

1. Verzeichnis anlegen: `sudo install -d -o caddy-sentinel -g caddy -m 2750 /var/lib/caddy-sentinel/geo`
2. Datenbanken herunterladen und als `country.mmdb` und `asn.mmdb` ablegen.
3. Pfade eintragen und „Speichern“. Die Zeile „Panel: …“ zeigt, ob das Panel die Dateien geladen hat.

Zum Aktualisieren die Dateien ersetzen und danach kurz einen anderen Pfad speichern oder Caddy neu laden. Ein monatliches Update genügt. Die Quellenangabe, die DB-IP und MaxMind verlangen, blendet das Panel automatisch ein.

Steht Caddy hinter einem weiteren Proxy oder Cloudflare, muss Caddy die echte Client-IP kennen, sonst würde Sentinel den Proxy sperren. Dafür in der Caddyfile `servers { trusted_proxies … }` setzen (README, Abschnitt „Caddyfile“).

### 10.4 Telemetrie & Speicher

**Panel „Telemetrie“:**

| Feld | Bedeutung | Standard |
|---|---|---|
| „Stichprobe normaler Requests (%)“ | Anteil unauffälliger Anfragen, die einzeln gespeichert werden. Fehler, WAF-Treffer und blockierte Anfragen werden immer übertragen; Zähler und Diagramme bleiben exakt. | 100 |
| „Query-Strings“ | „mitspeichern“ – hilfreich für Analysen. Werte sensibler Parameter (z. B. `token`, `password`, `secret`, `code`, `key`, `session`, `api_key`) speichert Sentinel immer als `***`, auf `/.sentinel/`-Seiten alle Werte. | an |

**Panel „Aufbewahrung“:**

| Feld | Bedeutung | Standard |
|---|---|---|
| „Einzelne Requests (Stunden)“ | Rohdaten für Request-Explorer, Live-Filter, Diagnose | 168 (7 Tage) |
| „Ereignisse (Tage)“ | Ereignisse und Audit-Log | 90 |
| „Minuten-Statistik (Tage)“ | Zähler für Übersicht und Diagramme | 90 |

Die Stunden-Zusammenfassungen für Top-Listen, Fehleranalyse und Wochenbericht bleiben mindestens acht Tage erhalten, auch wenn die Einzel-Requests kürzer aufbewahrt werden. Die aktuelle Größe der Datenbank steht unter „Datenbank“. Zum Speicherbedarf siehe Kapitel 11.10.

**Panel „Prometheus“:** siehe Kapitel 11.3.

### 10.5 Agent & Caddy

| Panel | Inhalt |
|---|---|
| „Verbundene Agenten“ | je Agent: „Agent“ (Hostname und Zugriffsmodus), „Status“ („verbunden“/„getrennt“, darunter gemeldete Policy-Fehler), „Version“, „Caddy“, „Handler“ (Sites mit `sentinel`), „WAF-Instanzen“, „Zuletzt“ |
| „Einrichtung“ | Beispiel für die globale Option und eine Site („Beispiel kopieren“); Zustand von „Caddy Admin-API“ („erreichbar“/„nicht erreichbar“), „Caddyfile“ („beschreibbar“/„schreibgeschützt“) und „Token-Datei“ der lokalen Instanz |
| „Zertifikats-Überwachung“ | „Caddy-Datenverzeichnis“ (enthält den Ordner `certificates`; Standard `/var/lib/caddy/.local/share/caddy`; ist es nicht lesbar – Normalfall, auch unter Docker –, kommen die Zertifikate über den Agenten) und „Warnen ab (Tage Restlaufzeit)“ (Standard 14) |
| „Agent-Token“ | Token der lokalen Instanz (beim Anklicken sichtbar), „Kopieren“, „Erneuern“ (siehe Kapitel 9.5) |

Meldet ein Agent Policy-Fehler (etwa eine eigene WAF-Regel, die er nicht übernehmen kann), erscheint das hier und als Ereignis „Agent … meldet Policy-Fehler“.

### 10.6 Benutzer

Panel-Benutzer und Rollen sind in Kapitel 7 beschrieben, die Rechte der Rollen in Kapitel 12.

### 10.7 Sicherung

Nur für Administratoren.

**Sicherung herunterladen:**

1. Unter „Passwort für die Sicherung“ ein Passwort mit mindestens 12 Zeichen eingeben und wiederholen.
2. „Sicherung herunterladen“ klicken. Die Datei `caddy-sentinel-backup-JJJJ-MM-TT.sentinel-backup` ist mit AES-256-GCM verschlüsselt (Schlüssel per scrypt aus dem Passwort).

**Achtung:** Ohne das Passwort lässt sich die Sicherung nicht einspielen; es gibt keine Wiederherstellung. Bewahre es getrennt von der Datei auf, z. B. im Passwortmanager.

Mit „Unverschlüsselt herunterladen“ entsteht stattdessen eine JSON-Datei mit allen Geheimnissen im Klartext. Für Skripte liefert `GET /api/backup` (Administrator-Token) ebenfalls die unverschlüsselte Fassung.

| Enthalten | Nicht enthalten |
|---|---|
| Einstellungen einschließlich aller Geheimnisse im Klartext (SMTP- und LDAP-Passwort, OAuth-Client-Secrets, Webhook- und Metrics-Token) | Panel-Benutzer und API-Tokens des Panels |
| Policies, Regelsätze | Statistiken, Requests, Ereignisse |
| Threat-Feeds (eigene Listen mit Inhalt), Monitore | aktive Sperren |
| befristete Einträge | Caddyfiles und deren Versionen |
| Zugangskonten des Site-Logins mit Passwort-Hash, 2FA-Schlüssel und Passkeys | Agent-Token, Instanzen |
| Site-Zugriffstokens (nur Prüfsummen) | |


**Sicherung einspielen:**

1. Unter „Sicherung einspielen“ die Datei wählen; bei einer verschlüsselten Sicherung das Passwort eingeben.
2. Optional „Auch globale Einstellungen übernehmen“ einschalten. Ohne den Schalter bleiben die Einstellungen des Zielsystems unverändert.
3. „Backup einspielen“ klicken.

Policies, Regelsätze, Feeds und Monitore mit derselben ID werden überschrieben, alle anderen bleiben erhalten. Zugangskonten, die es schon gibt, bleiben unverändert; nur fehlende werden angelegt. Befristete Einträge werden nur übernommen, wenn sie noch nicht abgelaufen sind. Die Meldung nennt die Zahl der eingespielten Policies, Regelsätze, Feeds und Monitore; Fehler einzelner Einträge listet der Dialog „Teilweise eingespielt“.

Die Sicherung eignet sich, um Regeln auf einen zweiten Server zu übertragen. Für eine vollständige Wiederherstellung nach einem Serverausfall siehe Kapitel 11.4.

### 10.8 Konto & Sicherheit, API-Tokens

Passwort, Zwei-Faktor-Anmeldung, Sitzungen und API-Tokens beschreibt Kapitel 7. Zusätzlich gibt es unter „Konto & Sicherheit“ das Panel „Darstellung“ mit „Farbschema“ („wie System“, „hell“, „dunkel“); die Wahl gilt nur im aktuellen Browser.

### 10.9 Über & Lizenzen

Zeigt die Version, die Lizenz (Apache License 2.0) und die NOTICE-Datei, die Pflicht-Quellenangaben der geladenen GeoIP-Datenbanken, einen Hinweis zu den Nutzungsbedingungen externer Datenquellen und unter „Enthaltene Software Dritter“ die Lizenzen aller enthaltenen Komponenten mit Suche („Komponente suchen …“) und Download „THIRD_PARTY_LICENSES.txt herunterladen“. In selbst gebauten Entwickler-Versionen ist diese Liste leer.

---

## 11. Betrieb

### 11.1 Benachrichtigungen einrichten

Benachrichtigungen verschickt das Panel an beliebig viele Kanäle. Einrichtung unter *Einstellungen › Benachrichtigungen* (Administrator).

1. Unter „Alarme“ die „Panel-URL für Links“ eintragen. Ohne sie enthalten Nachrichten keine Knöpfe.
2. Für E-Mail: das Panel „E-Mail-Versand (SMTP)“ ausfüllen und **zuerst speichern** – Test und Versand nutzen die gespeicherten SMTP-Daten.
3. Im Panel „Benachrichtigungen“ auf „Benachrichtigung hinzufügen“ klicken. Neu angelegt wird ein Eintrag mit Format Microsoft Teams, Mindest-Schwere „Mittel“ und den Arten `ban, alert, agent`.
4. „Name“, „Format“ und die Felder des Formats ausfüllen (Tabelle unten).
5. „Mindest-Schwere“ und „Arten“ wählen.
6. „Testen“ – das Panel schickt „Testnachricht von Caddy Sentinel“.
7. „Speichern“.

| Format | Feld „URL“ | Weitere Felder | Besonderheiten |
|---|---|---|---|
| „E-Mail“ | „Empfänger“, mehrere durch Komma | – | Betreff „[Sentinel] <Titel>“; Text mit Schwere, Art, Zeit, Host, IP, Instanz, Links und Details |
| „Microsoft Teams (Workflows)“ | Workflow-URL (`https://…logic.azure.com/workflows/…`) | – | Adaptive Card mit Knöpfen. Die alten Office-365-Connectoren werden nicht unterstützt. |
| „Matrix“ | „Homeserver“ (`https://matrix.example.org`) | „Raum-ID“ (`!abc:example.org`), „Access-Token“ eines Bot-Kontos, das im Raum ist | beides Pflicht; formatierte Nachricht mit Links |
| „ntfy (Handy)“ | Themen-URL, z. B. `https://ntfy.sh/mein-geheimes-thema` | Token optional (geschütztes Thema) | bis zu drei Knöpfe; Sperren/Stummschalten werden direkt ausgeführt |
| „Telegram“ | – | „Chat-ID“, „Bot-Token“ (von @BotFather) | beides Pflicht; Knöpfe unter der Nachricht |
| „Slack / Mattermost / Rocket.Chat“ | Incoming-Webhook-URL | – | Nachricht mit Knöpfen |
| „Discord“ | Webhook-URL | – | Links in der Nachricht |
| „Gotify“ | Adresse des Gotify-Servers | „App-Token“ | Markdown, Priorität nach Schwere |
| „Generisches JSON“ | beliebige URL | Token optional (als Bearer) | JSON mit Ereignis, Schwere und Aktions-Links – für eigene Skripte |

**Mindest-Schwere:** Info, Niedrig, Mittel, Hoch, Kritisch. Nachrichten unterhalb der gewählten Stufe gehen nicht an diesen Kanal.

**Arten** (leer = alle):

| Art | Ereignisse | typische Schwere |
|---|---|---|
| `ban` | IP gesperrt (automatisch oder manuell) | Hoch |
| `alert` | Alarme aus 10.2, Monitore, Zertifikate, Interne CA, Site-Login-Alarme, Fehler beim Wochenbericht | Niedrig bis Kritisch |
| `agent` | „Agent … meldet Policy-Fehler“ | Hoch |
| `config` | „Konfiguration angewendet: …“ | Info |
| `waf` | WAF-Blockaden | ab Mittel |
| `honeypot` | Zugriff auf einen Honeypot-Pfad | – |

Aufgehobene Sperren, Audit-Einträge und abgelehnte Konfigurationen werden nicht verschickt; sie stehen nur im Ereignisprotokoll.

**Knöpfe in Nachrichten:** Mit Panel-URL enthalten Nachrichten „IP 24 h sperren“ bzw. „Sperre aufheben“, „24 h stummschalten“ und „Im Panel öffnen“. Die Links sind 24 Stunden gültig, nur einmal verwendbar und zeigen vor der Aktion eine Bestätigungsseite – Link-Vorschauen in Chat-Programmen lösen also nichts aus. Bei ntfy führt der Knopf die Aktion direkt aus. Damit die Knöpfe von unterwegs funktionieren, muss `/act/*` des Panels erreichbar sein (siehe 11.9).

**Hinweis:** Das Panel stellt jede Nachricht genau einmal zu (Zeitlimit 10 Sekunden). Schlägt der Versand fehl, steht das nur im Log des Panels (`journalctl -u caddy-sentinel`, „webhook failed“); es gibt keine Wiederholung.

### 11.2 Wochenbericht

Der Wochenbericht fasst die letzten sieben Tage per E-Mail zusammen (HTML und Text). Einrichtung unter *Einstellungen › Benachrichtigungen › Wochenbericht per E-Mail* (Administrator):

1. SMTP einrichten und speichern (10.2).
2. „Bericht – wöchentlich senden“ einschalten.
3. „Wochentag“ (Standard Montag) und „Uhrzeit“ (Standard 07:00, Zeitzone des Panel-Servers) wählen.
4. „Empfänger“ eintragen, eine Adresse pro Zeile.
5. „Vorschau“ zeigt den Bericht mit aktuellen Daten; „Jetzt senden“ verschickt ihn sofort an die eingetragenen Empfänger.
6. „Speichern“.

Inhalt: Kennzahlen (Anfragen, Blockiert, Fehlerquote, Antwortzeit Ø / p95), bei mehreren Instanzen eine Tabelle je Instanz mit Status, „Häufigste Fehlerursachen“ (Top 10), „Am häufigsten blockierte Clients“, „Änderungen“, „Offene Hinweise“ (Zertifikate, Backends, Instanzen) und – mit Panel-URL – der Knopf „Im Panel ansehen“.

Der Bericht geht in der eingestellten Stunde raus, höchstens einmal in sechs Tagen. Scheitert der Versand, entsteht der Alarm „Wochenbericht konnte nicht gesendet werden: …“.

### 11.3 Prometheus

Das Panel stellt Kennzahlen im Prometheus-Format unter `/metrics` bereit.

1. *Einstellungen › Telemetrie & Speicher › Prometheus* öffnen.
2. Ein Token eintragen oder „Erzeugen“ klicken, dann „Speichern“.
3. Das angezeigte Beispiel in die Prometheus-Konfiguration übernehmen. Ist das Panel über HTTPS veröffentlicht, `scheme: https` ergänzen:

   ```yaml
   scrape_configs:
     - job_name: caddy-sentinel
       scheme: https
       authorization:
         credentials: <TOKEN>
       static_configs:
         - targets: ['sentinel.example.com']
   ```

Ohne Token antwortet `/metrics` mit 404, mit falschem Token mit 401. Der Pfad braucht keine Panel-Anmeldung.

| Metrik | Typ | Bedeutung |
|---|---|---|
| `sentinel_requests_total{host,code,action}` | Counter | Anfragen je Host, Statusklasse (z. B. `2xx`) und Aktion |
| `sentinel_response_bytes_total{host}` | Counter | ausgelieferte Bytes je Host |
| `sentinel_bans_active` | Gauge | aktive Sperren |
| `sentinel_ids_tracked_ips` | Gauge | vom IDS beobachtete IPs |
| `sentinel_agent_up{agent}` | Gauge | 1 = Agent verbunden; `agent` ist der Hostname des Servers |

Die Counter beginnen nach einem Neustart des Panels wieder bei null; Prometheus behandelt das als normalen Zähler-Reset.

### 11.4 Sicherung und Wiederherstellung

Es gibt drei Arten der Sicherung:

| Was | Wie | Wofür |
|---|---|---|
| Regeln und Einstellungen | *Einstellungen › Sicherung* (Kapitel 10.7) | Regeln auf einen anderen Server übertragen, Stand vor größeren Umbauten |
| Caddyfile | Versionen im Editor (Kapitel 8.3) | Konfigurationsänderungen zurücknehmen |
| Gesamtes System | Dateien auf dem Server | Wiederherstellung nach Ausfall |

Für eine vollständige Sicherung unter systemd gehören dazu:

- `/var/lib/caddy-sentinel/` (Datenbank `data/sentinel.db` mit `-wal` und `-shm`, Agent-Token, GeoIP-Dateien),
- `/etc/caddy/` (Caddyfile, eingebundene Dateien),
- `/etc/default/caddy-sentinel`,
- `/var/lib/caddy/.local/share/caddy/` (Zertifikate und Interne CA).

Die Datenbank konsistent sichern: Panel kurz stoppen, kopieren, wieder starten.

```bash
sudo systemctl stop caddy-sentinel
sudo tar czf /root/sentinel-$(date +%F).tgz /var/lib/caddy-sentinel /etc/caddy /etc/default/caddy-sentinel
sudo systemctl start caddy-sentinel
```

Caddy läuft währenddessen weiter und schützt mit dem zuletzt bekannten Stand.

**Wiederherstellen auf einem neuen Server:**

1. Caddy Sentinel installieren (docs/INSTALL.md), Dienste danach stoppen: `sudo systemctl stop caddy caddy-sentinel`.
2. Die gesicherten Verzeichnisse zurückspielen (`tar xzf … -C /`). Benutzer-IDs unterscheiden sich zwischen Servern; Besitz und Rechte setzt der nächste Schritt.
3. `sudo caddy-sentinel-update --force --yes` stellt Benutzer, Besitzer und Rechte wieder her (11.5, „Benutzer und Rechte“). Ein Archiv einer älteren Installation (Datenbank direkt in `/var/lib/caddy-sentinel`) stellt es dabei auf den eigenen Panel-Benutzer um.
4. `sudo systemctl start caddy-sentinel caddy`.

Unter Docker siehe docs/INSTALL.md, Abschnitt „Update mit Docker“ (Sicherung des Volumes `sentinel-data`); zusätzlich `caddy-etc` und `caddy-data` sichern.

### 11.5 Update

Das Panel zeigt unten in der Seitenleiste „Update vX.Y.Z“, sobald ein neues Release vorliegt (Abfrage bei GitHub alle sechs Stunden; abschaltbar mit `SENTINEL_UPDATE_CHECK=0`). Ein Klick zeigt den passenden Befehl. Das Panel aktualisiert sich nicht selbst, weil es bewusst ohne Root-Rechte läuft.

**systemd:**

```bash
sudo caddy-sentinel-update --check     # nur prüfen
sudo caddy-sentinel-update             # neueste Version
sudo caddy-sentinel-update --version v1.3.0
```

| Option | Bedeutung |
|---|---|
| `--check` | nur prüfen (ohne root möglich); Rückgabewert 0 = aktuell, 10 = Update verfügbar |
| `--version vX.Y.Z` | bestimmte Version |
| `--dir PFAD` | Programme aus einem Verzeichnis statt Download |
| `--force` | gleiche Version erneut einspielen |
| `--skip-validate` | Vorabprüfung der Caddyfile überspringen |
| `--rollback` | auf die vorherige Version zurück (siehe 11.6) |
| `--with-db` | beim Rollback auch die Datenbank zurückspielen |
| `--keep-config` | beim Rollback Caddyfile und `/etc/default/caddy-sentinel` nicht zurücksetzen |
| `--verify-attestation` | Herkunftsnachweis des Archivs mit `gh attestation verify` prüfen (auch `SENTINEL_VERIFY_ATTESTATION=1`; GitHub-CLI mit Anmeldung nötig) |
| `--skip-signature` | Signatur der Prüfsummen nicht prüfen – nur im Notfall bei vertrauenswürdiger Quelle (auch `SENTINEL_SKIP_SIGNATURE=1`) |
| `-y`, `--yes` | keine Rückfragen |

Ablauf auf dem Panel-Server:

1. Download, Prüfung der Signatur von `SHA256SUMS` (`SHA256SUMS.sig`, `ssh-keygen -Y verify` mit dem im Skript eingebauten bzw. bei der Installation gemerkten Schlüssel – Pflicht, sobald einer hinterlegt ist), dann der SHA-256-Prüfsumme (mit `--verify-attestation` zusätzlich des Herkunftsnachweises). Meldet die unsignierte `VERSION`-Datei eine ältere als die installierte Version, bricht das Update ab; ältere Versionen nur mit `--version`.
2. **Vorabprüfung:** Die vorhandene `/etc/caddy/Caddyfile` wird mit dem **neuen** Caddy geprüft. Ist sie ungültig (etwa weil eine neue Caddy-Version eine Option entfernt hat), bricht das Update ab, ohne etwas zu ändern.
3. Prüfung des freien Platzes, Panel stoppen.
4. Sicherung nach `/var/backups/caddy-sentinel/<Datum-Uhrzeit>-<alte Version>/`: Programme, Units, Umgebungsdatei, Caddyfile und Datenbank. Das Datenverzeichnis liest das Skript aus `/etc/default/caddy-sentinel`. Gelesen werden nur echte Dateien (ohne Symlinks zu folgen); die Sicherungen gehören `root` und sind nur für root lesbar.
5. Benutzer und Rechte herstellen (siehe unten) – bei jedem Update, damit verstellte Rechte wieder stimmen.
6. Panel tauschen, starten und prüfen.
7. Caddy tauschen und neu starten (Unterbrechung von etwa einer Sekunde), Stabilität prüfen.
8. Startet etwas nicht, spielt das Skript automatisch die vorherige Version zurück – einschließlich Benutzern, Rechten und Lage der Datenbank.

**Benutzer und Rechte.** Panel und Caddy laufen unter getrennten Systembenutzern:

| Benutzer | Dienst | Zugriff |
|---|---|---|
| `caddy` | Caddy | eigenes Datenverzeichnis `/var/lib/caddy/.local/share/caddy` (Zertifikate, private Schlüssel), `/var/log/caddy`; vom Panel nur Agent-Token und Prüf-Kopien (lesend, über die Gruppe `caddy`) |
| `caddy-sentinel` | Panel | eigene Datenbank; `/etc/caddy` schreiben (Zusatzgruppe `caddy`); Admin-API von Caddy über `/run/caddy/admin.sock` (Gruppe `caddy`); `caddy validate` – kein Login, keine Rechte auf Caddys Schlüssel |

| Pfad | Besitzer und Rechte |
|---|---|
| `/var/lib/caddy-sentinel/` | `caddy-sentinel:caddy`, `2750` |
| `/var/lib/caddy-sentinel/agent.token` | `caddy-sentinel:caddy`, `0640` |
| `/var/lib/caddy-sentinel/staging/`, `geo/` | `caddy-sentinel:caddy`, gruppenlesbar |
| `/var/lib/caddy-sentinel/data/` (Datenbank, Zertifikats-Spiegel) | `caddy-sentinel:caddy-sentinel`, `0700` |
| `/etc/caddy/` und Unterverzeichnisse | `root:caddy`, `2775` (setgid: neue Dateien gehören zur Gruppe `caddy`) |
| `/run/caddy/admin.sock` (in `/run/caddy`, `0750`) | `caddy:caddy`, `0660` – Admin-API, nur Caddy und Panel |

**Admin-API als Unix-Socket.** Die Ergänzung der Caddy-Unit setzt `CADDY_ADMIN=unix//run/caddy/admin.sock|0660` und `RuntimeDirectory=caddy`; `SENTINEL_CADDY_ADMIN` in `/etc/default/caddy-sentinel` zeigt auf den Socket. Port 2019 ist damit zu – vorher konnte jeder lokale Prozess Caddy über `localhost:2019` umkonfigurieren. `CADDY_ADMIN` gilt, solange die Caddyfile keine globale Option `admin` setzt; eine solche Zeile hat Vorrang (Installation und Update warnen und lassen sie stehen). Das Panel sollte eine Caddyfile, die die Admin-Adresse verlegt oder `admin off` setzt, nicht übernehmen, sonst verliert es die Verbindung. `systemctl reload caddy` und `caddy stop` in der Unit nutzen den Socket; von Hand als root: `caddy reload --config /etc/caddy/Caddyfile --address 'unix//run/caddy/admin.sock'`.

Folgen: Eine Caddyfile mit `file_server` auf `/var/lib/caddy-sentinel` liefert höchstens Token und Prüf-Kopien aus, die Datenbank nicht (403). Das Panel überwacht Zertifikate über den Sentinel-Agenten (öffentliche Teile, nie private Schlüssel; Kapitel 8.7), und „Vollständig prüfen“ läuft als `caddy-sentinel` ohne Caddys Log- und Schlüsseldateien zu öffnen (Kapitel 8).

**Umstellung älterer Installationen.** Lief Caddys Admin-API noch auf `localhost:2019`, stellt das Update sie auf den Socket um (Unit-Ergänzung, `SENTINEL_CADDY_ADMIN`, Neustart von Caddy – ein Reload genügt dafür nicht); auf Agent-Servern ebenso, außer der `sentinel`-Block nennt ein festes `admin http://…`. Lief das Panel bisher als `caddy` (Datenbank direkt in `/var/lib/caddy-sentinel`), stellt das Update außerdem um: Benutzer `caddy-sentinel` anlegen, Datenbank, Zertifikats-Spiegel und Prüfverzeichnis nach `data/` verschieben, Besitz und Rechte setzen, `SENTINEL_DATA`, `SENTINEL_TOKEN_FILE` und `SENTINEL_STAGING` in `/etc/default/caddy-sentinel` eintragen, Units aktualisieren, Dienste neu starten. Agent-Token, GeoIP-Dateien und eine `token_file`-Zeile in der Caddyfile bleiben gültig. Während der Umstellung gehört das Verzeichnis kurz `root`, damit kein anderer Prozess Einträge austauschen kann. Mehrfach ausgeführt ändert die Umstellung nichts mehr. Ein noch installiertes älteres `caddy-sentinel-update` tauscht zunächst nur die Programme; das Panel läuft dann weiter als `caddy` und warnt im Log („the panel runs as the same user as Caddy …“). Der nächste Aufruf von `sudo caddy-sentinel-update` stellt um, auch bei gleicher Version; `--check` zeigt an, ob die Umstellung aussteht.

Aufbewahrt werden die Programme der letzten fünf Updates, die Datenbank nur in den letzten zwei Sicherungen.

Auf **Agent-Servern** (Installation mit `--agent`) tauscht dasselbe Kommando nur Caddy, mit Sicherung und automatischem Zurücksetzen. Jeder Agent-Server wird einzeln aktualisiert. Panel und Agents sollten dieselbe Version haben; neue Funktionen brauchen auf jeder Instanz den aktuellen Agent.

Derselbe Installations-Einzeiler aus docs/INSTALL.md erkennt eine vorhandene Installation und ruft das Update auf. Automatische Updates per systemd-Timer: docs/INSTALL.md.

**Docker:** `docker compose pull && docker compose up -d`. Version festnageln mit `SENTINEL_VERSION` in einer `.env`-Datei (docs/INSTALL.md).

### 11.6 Rollback

```bash
sudo caddy-sentinel-update --rollback            # Programme der vorherigen Version
sudo caddy-sentinel-update --rollback --with-db  # zusätzlich die Datenbank von damals
```

Das Skript nimmt die neueste Sicherung einer **anderen** als der laufenden Version und spielt Programme, die Unit des Panels und die Caddy-Ergänzung zurück. Mit `--with-db` ersetzt es auch die Datenbank – alles, was seit dem Update gespeichert wurde (Statistiken, Policy-Änderungen, Sperren), geht dann verloren. Auf Agent-Servern spielt `--rollback` das Caddy-Programm der neuesten Sicherung zurück.

Auch Caddyfile und `/etc/default/caddy-sentinel` stellt der Rollback auf den Stand der Sicherung zurück. Haben sie sich seitdem geändert, legt das Skript die aktuelle Fassung unter `/var/backups/caddy-sentinel/vor-rollback-<Zeit>/` ab (nur root) – nicht neben die Datei, denn `/etc/caddy` ist für die Gruppe `caddy` beschreibbar, und ein dort untergeschobener Symlink könnte root sonst eine beliebige Datei überschreiben lassen. Ist die Caddyfile selbst ein Symlink, bleibt sie unverändert (Warnung). Mit `--keep-config` bleiben beide Dateien unverändert.

Geht der Rollback auf eine Version ohne eigenen Panel-Benutzer zurück, stellt er auch den alten Zustand her: Datenbank zurück nach `/var/lib/caddy-sentinel`, Besitzer `caddy`, Panel-Unit mit `User=caddy`, Benutzer `caddy-sentinel` entfernt. Ein späteres Update stellt wieder um.

### 11.7 Deinstallation

```bash
sudo caddy-sentinel-uninstall           # Programme entfernen, Daten behalten
sudo caddy-sentinel-uninstall --purge   # zusätzlich Datenbank, Sicherungen und Umgebungsdatei
```

Das Skript entfernt den Panel-Dienst, die Ergänzung der Caddy-Unit, die Programme und den Systembenutzer `caddy-sentinel`. Behaltene Daten gehören danach `root` und sind nur für root lesbar – ein später angelegter Benutzer mit derselben Nummer kann sie so nicht lesen; eine Neuinstallation übernimmt sie wieder. Dateien des Panels in `/etc/caddy` gehen an `root`. Ein gesichertes `caddy.orig` wird zurückgesetzt; ist ein Caddy aus dem Distributionspaket installiert, läuft danach wieder dieses. Sonst bleibt der Sentinel-Build, damit die Sites weiterlaufen. Caddyfile und Zertifikate bleiben immer erhalten.

**Achtung:** Vorher die Direktive `sentinel` (in den Sites und als globale Option) aus der Caddyfile entfernen, wenn danach ein Standard-Caddy laufen soll – sonst startet er nicht („Caddy startet nicht – vermutlich steht noch "sentinel" in der Caddyfile.“).

Auf Agent-Servern bleibt die Token-Datei `/etc/caddy/sentinel-agent.token` liegen; bei Bedarf von Hand löschen und die Instanz im Panel entfernen (Kapitel 9.6).

### 11.8 Docker

Aufbau, Volumes und Update stehen in docs/INSTALL.md. Ergänzend:

- Das Panel ist nur auf dem Docker-Host unter `127.0.0.1:7600` erreichbar. Zum Veröffentlichen in der Caddyfile `reverse_proxy panel:7600` verwenden.
- Caddy startet erst, wenn das Panel bereit ist.
- Die Admin-API läuft als Unix-Socket im Volume `caddy-admin` (`/run/caddy/admin.sock`); Caddy legt ihn an, das Panel hängt das Volume nur lesend ein (zum Verbinden reicht das). Die Zeile `admin unix//run/caddy/admin.sock` in der Caddyfile muss bleiben.
- Das Panel legt Prüf-Kopien der Konfiguration im eigenen Volume `sentinel-staging` ab (`SENTINEL_STAGING=/run/sentinel-staging/staging`). Caddy hängt es nur lesend ein, um eingebundene Dateien beim Prüfen zu lesen, und kann dort – wie in `/etc/caddy` (ebenfalls nur lesend) – nichts unterschieben. Ältere compose.yml legten die Prüf-Kopien in `caddy-admin` ab; neue compose.yml nur mit Images derselben Version verwenden.
- Das Volume `caddy-logs` (Log-Dateien aus `log { output file /var/log/caddy/… }`) und `caddy-data` (Zertifikate, private Schlüssel, interne CA) hängen nur im Caddy-Container. Zertifikate und interne CA zeigt das Panel über den Agenten, „Vollständig prüfen“ öffnet keine Log-Dateien.
- Caddy sieht nur das Agent-Token (Volume `sentinel-token`), nicht die Datenbank des Panels.
- Beide Container laufen ohne Linux-Capabilities (Caddy behält nur `NET_BIND_SERVICE` für die Ports 80/443), das Panel zusätzlich mit `no-new-privileges`.
- Die Container hängen in einem festen Netz `${SENTINEL_NET}.0/24` (Standard `172.31.77.0/24`; Panel `.2`, Caddy `.10`). Das Panel übernimmt `X-Forwarded-For` nur von Caddy (`.10`). Zugriffe über den veröffentlichten Port `127.0.0.1:7600` kommen vom Docker-Gateway (`.1`) und zählen mit dessen Adresse – über diesen Port lässt sich keine fremde Client-IP vortäuschen. (Ältere compose.yml vertrauten zusätzlich `.1` und hängten `caddy-data` und `caddy-logs` ins Panel; beim Update die neue compose.yml übernehmen.) Überschneidet sich das Netz mit einem eigenen, in der `.env` z. B. `SENTINEL_NET=10.99.77` setzen.
- GeoIP: ein Verzeichnis in **beide** Container einhängen (`./geo:/geo:ro`) und im Panel `/geo/country.mmdb` bzw. `/geo/asn.mmdb` eintragen.
- Zeitzone über `TZ` (Standard `Europe/Berlin`), Image-Version über `SENTINEL_VERSION`.

### 11.9 Panel über Caddy veröffentlichen

Das Panel lauscht standardmäßig nur auf `127.0.0.1:7600`. Für den Zugriff aus dem Netz eine eigene Site anlegen:

```caddyfile
sentinel.example.com {
	sentinel
	reverse_proxy 127.0.0.1:7600
}
```

Empfohlen:

1. Eine **eigene Policy** für diese Site anlegen (Kapitel 5), statt die Standard-Policy mitzunutzen. So lässt sich der Zugriff auf das Panel gezielt einschränken, ohne andere Sites zu berühren, und eine Wartung oder ein Testmodus anderer Sites wirkt nicht auf das Panel.
2. In dieser Policy eine IP-Freigabeliste setzen (nur Büro, VPN).
3. Pfade, die von außen erreichbar sein müssen, per Pfad-Regel ausnehmen: `/oauth/*` (Rückkehr vom OAuth-Anbieter, falls OAuth genutzt wird) und `/act/*` (Knöpfe in Benachrichtigungen von unterwegs).
4. Weitere Caddy-Server brauchen Zugriff auf `/api/agent/*`; ihre Adressen also ebenfalls freigeben.
5. Die öffentliche Adresse unter *Einstellungen › Benachrichtigungen › Panel-URL für Links* eintragen.

Das Panel übernimmt die echte Client-IP aus `X-Forwarded-For` nur von Proxys in `SENTINEL_TRUSTED_PROXIES` (Standard: localhost). Läuft der vorgeschaltete Caddy auf einem anderen Host, dessen Adresse dort eintragen – sonst gelten alle Anmeldeversuche als von einer IP und lösen gemeinsam die Anmeldesperre aus.

**Achtung:** Sperrt eine Policy-Regel oder das IDS deine eigene IP, sperrst du dich auch aus dem Panel aus, wenn es über Caddy veröffentlicht ist. Eigene Netze deshalb unter *Einstellungen › Netz & Vertrauen* bei „Nie automatisch sperren“ eintragen und den lokalen Zugang per SSH-Tunnel als Notweg kennen (11.11).

### 11.10 Datenmenge und Aufbewahrung

- Caddy wartet nie auf das Panel. Der Agent überträgt einmal pro Sekunde und puffert bis 20.000 Einträge.
- Das Panel speichert etwa 15.000–20.000 Einträge pro Sekunde. Der Speicherbedarf liegt bei rund 370 MB pro Million gespeicherter Anfragen.
- Einzel-Requests werden standardmäßig 168 Stunden aufbewahrt, Ereignisse und Minuten-Statistik 90 Tage (Kapitel 10.4). Stunden-Zusammenfassungen bleiben mindestens acht Tage.
- Bei sehr viel Verkehr die Aufbewahrung der Einzel-Requests kürzen oder eine Stichprobe unter 100 % setzen. Zähler und Diagramme bleiben exakt; nur die gespeicherten Einzelanfragen werden weniger. Die Burst-Erkennung des IDS sieht bei einer Stichprobe nur einen Teil des Verkehrs.

Weitere Messwerte stehen im README, Abschnitt „Hinweise“.

### 11.11 Fehlersuche

#### Logs

```bash
journalctl -u caddy-sentinel -f       # Panel
journalctl -u caddy -f                # Caddy und Agent
docker compose logs -f panel caddy    # Docker
```

Ausführlichere Panel-Logs: `SENTINEL_DEBUG=1` in `/etc/default/caddy-sentinel`, dann `sudo systemctl restart caddy-sentinel`. Fehlgeschlagene Verbindungsversuche des Agents protokolliert Caddy nur im Debug-Level (globale Option `debug` in der Caddyfile).

#### Caddy verbindet sich nicht mit dem Panel

Anzeichen: *Einstellungen › Agent & Caddy* zeigt „Kein Agent verbunden“, die Instanz steht auf „offline“ oder „noch nie verbunden“, es kommen keine Statistiken.

1. **Enthält die Caddyfile `sentinel`?** Caddy lädt den Agent nur, wenn `sentinel` als Direktive in einer Site oder als globale Option vorkommt.
2. **Läuft Caddy mit dem Sentinel-Build?** `caddy list-modules | grep sentinel` muss `http.handlers.sentinel` zeigen. Unter systemd prüfen, ob die Ergänzung `/etc/systemd/system/caddy.service.d/sentinel.conf` aktiv ist (`systemctl cat caddy`).
3. **Token vorhanden und lesbar?** Im Caddy-Log weist „no agent token yet“ auf eine fehlende oder unlesbare Token-Datei hin. Die Datei muss für den Benutzer `caddy` lesbar sein (lokal `/var/lib/caddy-sentinel/agent.token`, `caddy-sentinel:caddy` `0640` in einem Verzeichnis mit `2750`; Agent-Server `/etc/caddy/sentinel-agent.token`). Stimmen die Rechte nicht, setzt `sudo caddy-sentinel-update --force` sie neu. Nach einer Token-Erneuerung prüfen, ob das neue Token auf dem Server steht (Kapitel 9.5).
4. **Stimmt die Panel-Adresse?** Auf dem Panel-Server muss `SENTINEL_PANEL` in der Caddy-Ergänzung zur Adresse in `SENTINEL_LISTEN` passen; nach einer Änderung von `SENTINEL_LISTEN` die Ergänzung anpassen und `sudo systemctl daemon-reload && sudo systemctl restart caddy`.
5. **Ist das Panel erreichbar?** Vom Caddy-Server aus testen: `curl -sS https://sentinel.example.com/api/auth/state`. Antwortet nichts, Firewall, DNS und die Policy der Panel-Site prüfen (11.9). Auch Sentinel selbst kann die Adresse des Agent-Servers sperren, wenn das Panel über Caddy veröffentlicht ist – unter *Sicherheit › Sperren & Freigaben* nachsehen.
6. Verbindet sich der Agent, kann aber keine Konfiguration bearbeiten: Zugriffsmodus prüfen (Kapitel 9.3).

#### 502 hinter `reverse_proxy`

Ein 502 bedeutet, dass Caddy das Backend nicht erreicht.

1. In der Fehleranalyse oder im Request-Explorer die Anfrage öffnen. Die Diagnose zeigt, wer geantwortet hat; bei „Backend“ liegt das Problem hinter Caddy, nicht bei Sentinel.
2. *Sites › Upstreams* zeigt den Zustand der Ziele („Fehler gemeldet“).
3. Läuft die Anwendung, und lauscht sie auf der eingetragenen Adresse? Vom Caddy-Server aus `curl -v http://<ziel>` testen.
4. Unter Docker muss das Ziel im selben Netzwerk liegen und über den Servicenamen angesprochen werden (`reverse_proxy app:8080`, nicht `127.0.0.1`).
5. HTTPS-Backends brauchen `transport http { tls }` bzw. im Formular „HTTPS zum Backend“.
6. Wird das Panel selbst mit 502 beantwortet, läuft es nicht oder lauscht auf einer anderen Adresse: `systemctl status caddy-sentinel` und `SENTINEL_LISTEN` prüfen; unter Docker `reverse_proxy panel:7600`.

Steigt die Zahl der 502 sprunghaft, meldet das der Alarm „Anstieg einer Fehlerursache“ (10.2).

#### „permission denied“ bei /var/log/caddy

Anzeichen: Das Laden der Konfiguration („Übernehmen“) scheitert mit „permission denied“, meist bei `log { output file /var/log/caddy/… }`. Das Panel ergänzt dann „Caddy läuft als Benutzer caddy und darf das Log-Verzeichnis nicht anlegen oder beschreiben.“ „Vollständig prüfen“ öffnet Log-Dateien nicht (es läuft als `caddy-sentinel` und schreibt Logs in ein eigenes Arbeitsverzeichnis) und meldet sie unter „Nicht geprüft“; ein solcher Fehler zeigt sich daher erst beim Übernehmen. Meldet „Vollständig prüfen“ selbst „permission denied“, betrifft das eine Datei, die das Panel nicht lesen darf – Caddy prüft sie beim Übernehmen.

Abhilfe:

```bash
sudo install -d -o caddy -g caddy /var/log/caddy
```

Installations- und Update-Skript legen das Verzeichnis mit Besitzer `caddy` an; das Panel braucht dort keine Rechte. Liegen Log-Dateien woanders, dem Benutzer `caddy` dort Schreibrechte geben und unter systemd das Verzeichnis zusätzlich in `ReadWritePaths` der betroffenen Unit aufnehmen. Unter Docker muss das Verzeichnis im Volume `caddy-logs` liegen (Caddy-Container). Dasselbe gilt sinngemäß für Zertifikatsdateien und `root`-Verzeichnisse: Caddy braucht Leserechte.

#### Benutzer ausgesperrt

**Panel-Anmeldung:** Nach 10 Fehlversuchen pro IP oder 30 pro Konto innerhalb von 15 Minuten lehnt das Panel weitere Versuche ab („Zu viele Fehlversuche – bitte 15 Minuten warten“).

- 15 Minuten warten. Die Sperre liegt nur im Arbeitsspeicher; `sudo systemctl restart caddy-sentinel` hebt sie sofort auf.
- Passwort vergessen: Ein Administrator setzt es unter *Einstellungen › Benutzer › Passwort setzen*. 2FA-Gerät verloren: „2FA zurücksetzen“.
- Laufen alle Anmeldungen über einen Proxy auf einem anderen Host und ist dieser nicht in `SENTINEL_TRUSTED_PROXIES` eingetragen, zählen alle Fehlversuche für dieselbe IP – ein einzelner Nutzer kann so alle aussperren. Proxy eintragen (11.9).

**Site-Login (AD, Zugangskonten):** Nach der unter *Site-Login & Konten* eingestellten Zahl Fehlversuche (Standard 5 in 15 Minuten) meldet die Anmeldeseite „Zu viele Fehlversuche – bitte n Minuten warten.“ Ein Administrator hebt die Sperre auf der Übersicht von *Site-Login & Konten* unter „Vorübergehend gesperrte Konten“ mit „Entsperren“ auf. Ein von Hand gesperrtes Zugangskonto wird dort in der Kontenliste mit „Entsperren“ wieder freigegeben. Details in Kapitel 7.

**IP vom IDS gesperrt:** Die IP erhält auf allen Sites 403. Unter *Sicherheit › Sperren & Freigaben* bei der IP „Aufheben“ klicken; das setzt auch den Bedrohungs-Score zurück. Ist das Panel selbst nur über die gesperrte Site erreichbar, per SSH-Tunnel zugreifen:

```bash
ssh -L 7600:127.0.0.1:7600 benutzer@server
# dann http://127.0.0.1:7600 öffnen
```

**Vorbeugen:**

- Büro-, VPN- und Monitoring-Netze unter *Einstellungen › Netz & Vertrauen › Nie automatisch sperren* eintragen (Kapitel 6).
- Neue Regeln zuerst im Testmodus laufen lassen (Kapitel 5).
- Den SSH-Tunnel als Notzugang kennen.
- Für die Panel-Site eine eigene Policy verwenden (11.9).

#### Agent offline

Anzeichen: Alarm „Caddy-Agent <name> meldet sich nicht mehr“, Instanz auf „offline“.

1. Läuft Caddy auf dem Server? `systemctl status caddy`.
2. Ist das Panel vom Server aus erreichbar (siehe „Caddy verbindet sich nicht“, Schritte 3–5)? Wurde das Token erneuert?
3. Läuft das Panel? Bei einem Neustart des Panels melden sich alle Agents nach wenigen Sekunden von selbst wieder.

Solange der Agent offline ist, schützt Caddy mit dem zuletzt bekannten Stand weiter (Kapitel 9.7). Neue Sperren und Policy-Änderungen erreichen ihn erst nach der Wiederverbindung, und Statistiken dieser Zeit fehlen, soweit der Puffer von 20.000 Einträgen überlaufen ist.

#### Weitere typische Meldungen

| Meldung | Ursache / Abhilfe |
|---|---|
| „Die Caddyfile dieser Instanz ist im Panel nicht bearbeitbar.“ | entfernte Instanz nicht im Modus `remote full` (Kapitel 9.3) |
| „Speichern fehlgeschlagen: … (Schreibrechte für … prüfen)“ | Panel bzw. Agent darf nicht in das Konfigurationsverzeichnis schreiben; Gruppe `caddy` mit Schreibrecht und setgid (`sudo caddy-sentinel-update --force` setzt das für `/etc/caddy`), unter systemd `ReadWritePaths=/etc/caddy` |
| „Caddy-Instanz nicht verbunden – …“ | Agent pollt nicht; siehe „Agent offline“ |
| „Caddy Admin-API nicht erreichbar: … /run/caddy/admin.sock …“ | Caddy läuft nicht, die Ergänzung der Caddy-Unit fehlt (`systemctl cat caddy` muss `CADDY_ADMIN` und `RuntimeDirectory=caddy` zeigen) oder die Caddyfile setzt eine eigene globale Option `admin` – dann `SENTINEL_CADDY_ADMIN` anpassen oder die Zeile entfernen; `sudo caddy-sentinel-update --force` stellt die Ergänzung wieder her |
| Update/Installation bricht ab: „Signatur der Prüfsummen ist ungültig“ bzw. „hat keine Signatur“ | Archiv oder `SHA256SUMS` verändert, ein Spiegel liefert `SHA256SUMS.sig` nicht mit, oder das Release ist mit einem anderen Schlüssel signiert. Nicht einfach übergehen; nur bei sicher vertrauenswürdiger Quelle `--skip-signature` |
| „Zeitüberschreitung bei der Caddy-Instanz (…)“ | Agent verbunden, aber langsame Antwort; erneut versuchen, Caddy-Log prüfen |
| „SMTP ist nicht konfiguriert (Einstellungen › Benachrichtigungen)“ | Server oder Absender fehlen, oder SMTP-Daten nicht gespeichert |
| Zertifikat „läuft bald ab“ | Erneuerung scheitert; Caddy-Log, DNS, Ports 80/443 prüfen (Kapitel 8.7) |
| Seite „Zertifikate“ meldet „… ist für das Panel nicht lesbar … und der lokale Sentinel-Agent liefert keine Zertifikate“ | gewollt: das Panel liest Caddys Datenverzeichnis nicht selbst, sondern über den Agenten. Caddy läuft nicht, hat kein `sentinel` in der Caddyfile oder `remote off` – siehe „Caddy verbindet sich nicht mit dem Panel“ |
| Seite „Zertifikate“ meldet, das Verzeichnis sei nicht lesbar (ohne Hinweis auf den Agenten) | Caddy-Datenverzeichnis unter *Einstellungen › Agent & Caddy* falsch eingetragen |

---

## 12. Rollen und Rechte

Das Panel kennt vier Rollen:

- **Administrator:** alles, einschließlich Benutzer, Einstellungen und Caddy-Instanzen
- **Bearbeiter:** Caddyfile, Policies, Regelsätze, Feeds, Monitore und Sperren
- **Support:** alles sehen, Sperren setzen und aufheben
- **Leser:** nur lesen

Jede Rolle enthält die Rechte der darunterliegenden. Lokale Benutzer erhalten ihre Rolle unter *Einstellungen › Benutzer*. AD- und OAuth-Konten erhalten sie bei jeder Anmeldung aus ihren Gruppen (siehe Kapitel 7.12). API-Tokens haben höchstens die Rolle ihres Kontos (siehe Kapitel 7.13). Welche Aktionen auf einer Caddy-Instanz überhaupt möglich sind, hängt zusätzlich von deren Modus ab (siehe Kapitel 9).

Legende: ✓ = erlaubt, – = nicht erlaubt.

| Funktion | Administrator | Bearbeiter | Support | Leser |
|---|:-:|:-:|:-:|:-:|
| **Ansehen** | | | | |
| Übersicht, Live, Analysen, Anfragen, Fehleranalyse, Sicherheit, Ereignisse, IP-Steckbrief | ✓ | ✓ | ✓ | ✓ |
| Policies, Regelsätze, Threat-Feeds, Monitore, Zertifikate, Interne CA ansehen | ✓ | ✓ | ✓ | ✓ |
| Caddyfile, Versionen und laufende Caddy-Konfiguration ansehen | ✓ | ✓ | ✓² | ✓² |
| Site-Login: Übersicht, Konten, Anmeldeprotokoll, Einstellungen ansehen | ✓ | ✓ | ✓ | ✓ |
| Einstellungen ansehen (ohne Passwörter und Secrets) | ✓ | ✓¹ | ✓¹ | ✓¹ |
| **Werkzeuge** | | | | |
| WAF-Tester mit gespeicherten Policies, Fluss-Simulator, Regel-Prüfung, Erklärung einzelner Anfragen | ✓ | ✓ | ✓ | ✓ |
| WAF-Tester mit eigenen, nicht gespeicherten WAF-Einstellungen oder Regeln | ✓ | ✓ | – | – |
| Caddyfile formatieren, Gliederung anzeigen | ✓ | ✓ | ✓ | ✓ |
| Policy-Übertragung: Vorschau | ✓ | ✓ | ✓ | ✓ |
| Eigene gespeicherte Ansichten anlegen, ändern, löschen | ✓ | ✓ | ✓ | ✓ |
| **Eigenes Konto** | | | | |
| Eigenes Passwort ändern, eigene Panel-2FA, eigene Sitzungen beenden | ✓ | ✓ | ✓ | ✓ |
| Eigene API-Tokens erstellen und widerrufen (Rolle höchstens die eigene) | ✓ | ✓ | ✓ | ✓ |
| **Sperren** | | | | |
| IP-Adressen sperren und Sperren aufheben, Notiz zur Sperre | ✓ | ✓ | ✓³ | – |
| Befristet „Nie sperren“ (global) eintragen | ✓ | ✓ | ✓ | – |
| Befristete globale Einträge vorzeitig entfernen | ✓ | ✓ | ✓ | – |
| Stummschaltungen von Benachrichtigungen aufheben | ✓ | ✓ | ✓ | – |
| **Policies und Regeln** | | | | |
| Policies anlegen, ändern, löschen; Standard-Policy festlegen | ✓ | ✓ | – | – |
| Login-Einstellungen einer Policy (Reiter „Anmeldung“, Anmeldung in Pfad-Regeln) | ✓ | ✓ | – | – |
| API-Schlüssel für Pfad-Regeln erzeugen | ✓ | ✓ | – | – |
| WAF-Ausnahmen, Auswirkungsanalyse, Policy-Übertragung anwenden | ✓ | ✓ | – | – |
| Befristete Einträge in Erlaubt- oder Sperrlisten einer Policy, auch vorzeitig entfernen | ✓ | ✓ | – | – |
| Regelsätze, Threat-Feeds (auch aktualisieren), Monitore (auch testen) | ✓ | ✓ | – | – |
| **Caddy** | | | | |
| Caddyfile prüfen und übernehmen, Version wiederherstellen | ✓ | ✓ | – | – |
| Sentinel-Direktive einfügen, Site-Assistent | ✓ | ✓ | – | – |
| **Nur Administratoren** | | | | |
| Befristet „Vertrauenswürdig“ (global) eintragen | ✓ | – | – | – |
| Einstellungen speichern (alle Tabs, auch AD, SSO, OAuth, Self-Service, SMTP, Panel-URL) | ✓ | – | – | – |
| Zugangskonten anlegen und bearbeiten, Passwörter setzen | ✓ | – | – | – |
| Konto-Aktionen: Abmelden, 2FA zurücksetzen, Sperren, Entsperren, Entfernen, Lockout aufheben | ✓ | – | – | – |
| Zugriffstokens für Sites ansehen, erstellen, widerrufen | ✓ | – | – | – |
| Verzeichnis und OAuth-Anbieter testen | ✓ | – | – | – |
| OIDC-Server: einschalten, Anwendungen anlegen und ändern, Secrets und Schlüssel erneuern, Freigaben widerrufen (ansehen ohne Secrets: alle Rollen) | ✓ | – | – | – |
| Panel-Benutzer verwalten (anlegen, Rolle, Passwort, 2FA zurücksetzen, löschen) | ✓ | – | – | – |
| API-Tokens aller Benutzer sehen und widerrufen | ✓ | – | – | – |
| Caddy-Instanzen anlegen, ändern, entfernen; Instanz- und Agent-Token erneuern, Agent-Informationen | ✓ | – | – | – |
| Sicherung herunterladen und einspielen | ✓ | – | – | – |
| Wochenbericht: Vorschau und Versand, Benachrichtigungen testen | ✓ | – | – | – |

¹ Ohne Metrics-Token. Webhook-Adressen sind für Nicht-Administratoren gekürzt, weil die Adresse bei vielen Diensten selbst der Schlüssel ist. Nicht-Administratoren sehen unter *Einstellungen* nur „Konto & Sicherheit“, „API-Tokens“ und „Über & Lizenzen“.

² Ohne Geheimnisse: Werte von `token`, `api_token`, `secret`, `password` u. Ä., Zugangsdaten nach `dns <Anbieter>`, Passwort-Hashes aus `basic_auth` und Header wie `Authorization` oder `Cookie` erscheinen als `••••••`. Das ist ein Schutznetz, kein Tresor – Geheimnisse gehören in Umgebungsvariablen (`{$CF_API_TOKEN}`) bzw. Dateien (`token_file`).

³ Bearbeiter und Support sperren höchstens ein /16 (IPv4) bzw. /32 (IPv6), Administratoren höchstens ein /8 bzw. /16. Abgelehnt werden außerdem Sperren, die die eigene Adresse oder einen Eintrag aus „Nie sperren“ treffen.

Versucht jemand eine Aktion ohne die nötige Rolle, antwortet das Panel „Keine Berechtigung – diese Aktion erfordert die Rolle …“ bzw. „Nur für Administratoren“. Erfolgreiche Änderungen protokolliert das Panel als Audit-Ereignis mit Benutzer, IP-Adresse und Browser.

**Hinweis:** Bearbeiter können die Login-Einstellungen von Policies ändern, also erlaubte Gruppen, „Netze ohne Anmeldung“ und SSO-Schalter. Konten, Tokens und die globalen Anmeldemethoden verwaltet dagegen nur ein Administrator. Vergib die Rolle Bearbeiter deshalb nur an Personen, denen du den Zugriffsschutz der Sites anvertraust.

## 13. Bekannte Grenzen

Die früher hier aufgeführten Grenzen sind behoben: Sitzungen signiert nur noch das Panel (eine kompromittierte
Caddy-Instanz kann keine ausstellen), Abmelden widerruft die Sitzung überall, SSO-Cookies halten sich an die
Sitzungsdauer jeder Site, Cookies tragen hinter einem vertrauenswürdigen TLS-Proxy `Secure`, Passkeys sind als
zweiter Faktor da, IPv6-Sperren erfassen das /64-Netz, der Editor erkennt gleichzeitige Änderungen, der Rollback
stellt auch Caddyfile und Einstellungsdatei zurück, und Sicherungen sind verschlüsselt. Was bleibt:

**Anmeldung**
- Passkeys gibt es für den Site-Login. Am Panel selbst ist der zweite Faktor weiterhin die Authenticator-App (bzw.
  die MFA des OAuth-Anbieters).
- Das `Secure`-Flag hinter einem Load Balancer setzt Sentinel nur, wenn Caddy dem Proxy vertraut
  (`servers { trusted_proxies … }`) und dieser `X-Forwarded-Proto: https` mitschickt.
- Weitere Einschränkungen im Detail stehen als Hinweise in Kapitel 7 (Zugriffstokens und „Anmeldemethoden“,
  Panel-Anmeldung über OAuth, Gerätewechsel der Authenticator-App).

**WAF**
- Antworten prüft die WAF nur auf Wunsch und nur meldend; blockieren kann sie anhand einer Antwort nicht, denn
  dafür müsste jede Antwort vollständig zwischengespeichert werden.
- Bodies über der Prüfgrenze prüft die WAF standardmäßig nur bis zur Grenze. Wer das nicht will, stellt
  „Größere Bodies“ auf „ablehnen (413)“ – dann scheitern aber auch große Uploads.

**Betrieb**
- Panel (`caddy-sentinel`) und Caddy (`caddy`) laufen unter getrennten Benutzern (11.5). Die Trennung hat
  Grenzen: Beide teilen sich die Gruppe `caddy`. Wer den Caddy-Prozess übernimmt, liest das Agent-Token der
  lokalen Instanz (damit kann er Telemetrie im Namen dieser Instanz einliefern) und die Prüf-Kopien der
  Caddyfile; die Datenbank des Panels bleibt ihm verschlossen. Wer das Panel übernimmt, schreibt `/etc/caddy`
  und steuert damit (und über den Admin-Socket) Caddy, liest aber Caddys private Schlüssel nicht. Die Admin-API
  ist nur noch als Unix-Socket für Caddy und die Gruppe `caddy` erreichbar; setzt die Caddyfile selbst eine
  globale Option `admin` mit TCP-Adresse, ist sie wieder für alle lokalen Prozesse offen (Installation und
  Update warnen nur).
- „Vollständig prüfen“ läuft als Panel-Benutzer und öffnet nichts, was nur Caddy lesen darf: Log-Dateien
  schreiben während der Prüfung in ein Arbeitsverzeichnis, Caddys Speicher wird durch ein leeres ersetzt,
  Zertifikatsdateien mit für das Panel unlesbarem Schlüssel (`tls <cert> <key>`) werden nicht geladen. Das
  Ergebnis nennt diese Teile unter „Nicht geprüft“; Schreibrechte auf Log-Verzeichnisse und lesbare Schlüssel
  prüft erst Caddy beim Übernehmen (bei einem Fehler stellt das Panel die vorherige Fassung wieder her).
- Die Zertifikatsüberwachung der lokalen Instanz braucht einen verbundenen Agenten: Läuft Caddy nicht oder steht
  die Fernverwaltung auf `off`, zeigt das Panel die zuletzt gespiegelten Zertifikate bzw. eine Fehlermeldung. Der
  Agent liest Caddys Speicher – das Datenverzeichnis oder einen eigenen `storage` (Datenbank, S3 …) über dessen
  Schnittstelle, in beiden Fällen nur Zertifikate, nie Schlüssel.
- `SHA256SUMS` ist per SSH signiert, sobald der Repository-Inhaber den Schlüssel eingerichtet hat
  (docs/INSTALL.md); `install.sh` und `caddy-sentinel-update` prüfen die Signatur dann zwingend. Die Signatur
  schützt Updates, weil das schon installierte Skript mit seinem eingebauten Schlüssel prüft. Den allerersten
  Aufruf von `bash <(wget …/install.sh)` schützt sie nicht: Skript und Schlüssel kommen dann aus derselben
  Quelle – wer sichergehen will, lädt `install.sh` herunter und prüft es vorher mit
  `gh attestation verify install.sh --repo b1tk1ll3r/caddy-sentinel`. Wer den privaten Schlüssel (Secret
  `RELEASE_SIGNING_KEY`) erlangt, kann gültige Releases signieren. Docker-Images tragen noch keine Signatur, die
  Basis-Images sind nicht per Digest festgelegt (docs/INSTALL.md); zum Festschreiben `SENTINEL_VERSION` auf eine
  feste Version statt `latest` setzen.
- Monitore und Threat-Feeds dürfen interne Adressen abfragen (dafür sind sie da). Gesperrt sind nur link-lokale
  Ziele wie Cloud-Metadaten-Dienste (`169.254.169.254`, `fd00:ec2::254`). Bearbeiter können so also Dienste im
  internen Netz erreichen – die Rolle entsprechend vergeben.
- Wird ein AD-Konto aus den Panel-Gruppen entfernt oder im Verzeichnis gelöscht, verliert es spätestens nach
  30 Minuten Sitzungen und API-Tokens. Bei OAuth-Konten prüft das Panel die Gruppen nur bei der Anmeldung; ihre
  API-Tokens laufen deshalb nach höchstens 90 Tagen ab.

**Daten**
- Eine unverschlüsselte Sicherung („Unverschlüsselt herunterladen“ oder `GET /api/backup`) enthält weiterhin alle
  Geheimnisse im Klartext. Sie ist nur Administratoren zugänglich und gehört entsprechend geschützt abgelegt.
- Ein Rollback mit `--with-db` verwirft alles, was seit dem Update in der Datenbank gespeichert wurde.

## Anhang A: Aktionen im Anfrageprotokoll

Sentinel vermerkt bei jedem Request, bei dem es eingreift, eine Aktion. Requests ohne Aktion sind ohne Eingriff ausgeliefert worden (im Filter „Ohne Eingriff“). Die Spalte „Code“ ist der Wert, der im CSV-Export, in der Adresse (`?action=…`) und in den Rohdaten steht; „Anzeige“ ist die Beschriftung im Panel. Requests mit einer blockierenden Aktion zählen in allen Kennzahlen als „Blockiert“ und in der Fehleranalyse als fehlgeschlagen.

| Code | Anzeige | Blockierend | Bedeutung | Prüfstufe |
|---|---|---|---|---|
| `banned` | „Gebannt“ | ja | Die IP stand auf der Sperrliste (manuell oder durch die Bedrohungserkennung gesperrt). | Sperren |
| `path_block` | „Pfad-Sperre“ | ja | Eine Pfad-Regel sperrt den Pfad. | Pfad-Regeln |
| `redirect` | „Weitergeleitet“ | nein | Eine Pfad-Regel leitet weiter. | Pfad-Regeln |
| `api_key` | „API-Schlüssel fehlt“ | ja | Der von einer Pfad-Regel verlangte API-Schlüssel fehlt oder ist falsch. | Pfad-Regeln |
| `maintenance` | „Wartung“ | ja | Der Wartungsmodus ist aktiv (503). | Wartung |
| `ip_deny` | „IP-Sperre“ | ja | Die IP steht auf der Sperrliste der Policy, ist nicht freigegeben oder kommt nicht aus einem für die Pfad-Regel erlaubten Netz. | IP-Regeln (bzw. Pfad-Regeln) |
| `geo_block` | „Geo-Sperre“ | ja | Land oder Netz ist gesperrt. | Geo & Feeds |
| `feed_block` | „Threat-Feed“ | ja | Die IP steht in einem Threat-Feed mit Aktion Blockieren. | Geo & Feeds |
| `feed_match` | „Feed-Treffer“ | nein | Die IP steht in einem Threat-Feed, der nur markiert. | Geo & Feeds |
| `method` | „Methode“ | ja | Die HTTP-Methode ist nicht erlaubt. | Filter |
| `user_agent` | „User-Agent“ | ja | Der User-Agent ist gesperrt. | Filter |
| `honeypot` | „Honeypot“ | ja | Ein Honeypot-Pfad wurde aufgerufen. | Filter |
| `body_limit` | „Body-Limit“ | ja | Der Anfrage-Body ist zu groß. | Filter |
| `bot_block` | „Crawler gesperrt“ | ja | Ein KI- oder SEO-Crawler ist laut Bot-Einstellungen gesperrt. | Bots |
| `bot_limit` | „Crawler gebremst“ | ja | Ein Crawler hat sein Limit überschritten (429). | Bots |
| `bot_fake` | „Falscher Suchmaschinen-Bot“ | ja | Der Client gibt sich als Suchmaschine aus, ist aber keine. | Bots |
| `rate_limit` | „Ratelimit“ | ja | Ein Ratelimit wurde überschritten. | Ratelimits |
| `rate_ban` | „Ratelimit-Bann“ | ja | Ein Ratelimit mit Aktion „Bann“ hat die IP gesperrt. | Ratelimits |
| `challenge` | „Bot-Challenge“ | ja | Statt der Seite wurde die Bot-Challenge angezeigt. | Bot-Challenge |
| `challenge_pass` | „Challenge gelöst“ | nein | Der Client hat die Bot-Challenge gelöst. | Bot-Challenge |
| `auth_required` | „Anmeldung nötig“ | nein | Anmeldeseite angezeigt bzw. Request ohne Sitzung. | Anmeldung |
| `auth_login` | „Angemeldet“ | nein | Erfolgreiche Anmeldung am Site-Login. | Anmeldung |
| `auth_fail` | „Login fehlgeschlagen“ | ja | Falsche Zugangsdaten oder falscher Code. | Anmeldung |
| `auth_denied` | „Kein Zugriff“ | ja | Angemeldet, aber ohne Berechtigung (z. B. fehlende Gruppe). | Anmeldung |
| `auth_token` | „Token ungültig“ | ja | Das Site-Zugriffstoken ist ungültig oder abgelaufen. | Anmeldung |
| `waf_block` | „WAF blockiert“ | ja | Die Web Application Firewall hat blockiert. | WAF |
| `waf_detect` | „WAF erkannt“ | nein | Die WAF hat Treffer gemeldet, aber nicht blockiert (Erkennungsmodus oder unter der Schwelle). | WAF |
| `test:<code>` | „Test: <Anzeige>“ | nein | Eine Regel im Testmodus hätte so entschieden; der Request wurde durchgelassen. | wie `<code>` |

Die Prüfstufen sind in der Reihenfolge aufgeführt, in der Sentinel sie durchläuft (siehe Kapitel 5).

In der Tabellen-Darstellung des Panels sind die Aktionen farblich gekennzeichnet: rot für blockierende Aktionen, gelb für „WAF erkannt“, „Feed-Treffer“, „Bot-Challenge“ und „Kein Zugriff“, blau für „Wartung“, „Challenge gelöst“, „Anmeldung nötig“ und „Weitergeleitet“, grün für „Angemeldet“. Testmodus-Entscheidungen haben eine eigene Kennzeichnung mit dem Tooltip „Testmodus: wäre blockiert worden, wurde aber durchgelassen“.

## Anhang B: Umgebungsvariablen und Dateien

### B.1 Panel (`caddy-sentinel`)

Unter systemd in `/etc/default/caddy-sentinel`, unter Docker im Abschnitt `environment` der `compose.yml`. Nach Änderungen `sudo systemctl restart caddy-sentinel`. Jede Variable hat ein gleichwertiges Kommandozeilen-Flag (in Klammern).

| Variable | Bedeutung | Standard |
|---|---|---|
| `SENTINEL_LISTEN` (`-listen`) | Adresse und Port des Panels | `127.0.0.1:7600` (Docker: `0.0.0.0:7600`) |
| `SENTINEL_DATA` (`-data`) | Datenverzeichnis: Datenbank, Zertifikats-Spiegel, Arbeitsverzeichnisse; nur für das Panel lesbar (`0700`) | `/var/lib/caddy-sentinel` (Umgebungsdatei der systemd-Installation: `/var/lib/caddy-sentinel/data`) |
| `SENTINEL_CADDY_ADMIN` (`-caddy-admin`) | Admin-API des lokalen Caddy: `http://host:port` oder `unix//pfad/zum.sock` | `http://127.0.0.1:2019` (Umgebungsdatei und Docker: `unix//run/caddy/admin.sock`) |
| `SENTINEL_CADDYFILE` (`-caddyfile`) | Haupt-Caddyfile; Dateien im selben Verzeichnis sind im Editor bearbeitbar | `/etc/caddy/Caddyfile` |
| `SENTINEL_CADDY_BIN` (`-caddy-bin`) | Caddy-Programm für „Vollständig prüfen“; leer gesetzt = Funktion aus | `caddy` aus dem Suchpfad (Umgebungsdatei: `/usr/local/bin/caddy`; Installation „nur Panel“: leer) |
| `SENTINEL_STAGING` (`-staging`) | Verzeichnis für Prüf-Kopien der Konfiguration; Caddy muss es lesen können | `<SENTINEL_DATA>/staging` (Umgebungsdatei: `/var/lib/caddy-sentinel/staging`; Docker: `/run/sentinel-staging/staging`) |
| `SENTINEL_TOKEN_FILE` (`-token-file`) | Datei, in der das Panel das Token der lokalen Instanz ablegt; Caddy muss sie lesen können | `<SENTINEL_DATA>/agent.token` (Umgebungsdatei: `/var/lib/caddy-sentinel/agent.token`; Docker: `/run/sentinel-token/agent.token`) |
| `SENTINEL_TRUSTED_PROXIES` | Proxys, deren `X-Forwarded-For` das Panel übernimmt (Anmeldesperren, Protokoll); IPs oder Netze, durch Komma getrennt | `127.0.0.0/8,::1` (Docker: zusätzlich nur der Caddy-Container `.10`) |
| `SENTINEL_CADDY_DATA` | Vorgabe für das Caddy-Datenverzeichnis (Zertifikate, Interne CA). Ist es für das Panel nicht lesbar (Normalfall), kommen die öffentlichen Teile über den Agenten. Gesetzt zeigt der Update-Hinweis die Docker-Befehle | `/var/lib/caddy/.local/share/caddy` (Docker: `/caddy-data/caddy`, nicht eingehängt) |
| `SENTINEL_UPDATE_CHECK` | `0` oder `false` schaltet die Suche nach neuen Releases ab | an |
| `SENTINEL_DEBUG` (`-debug`) | ausführliches Log, wenn gesetzt | aus |
| `SENTINEL_WEB_DIR` | Oberfläche aus diesem Verzeichnis statt der eingebauten Dateien laden (Anpassung, Entwicklung) | – |

`caddy-sentinel -version` gibt die Version aus.

### B.2 Agent (Caddy-Prozess)

Unter systemd in der Ergänzung `/etc/systemd/system/caddy.service.d/sentinel.conf`, unter Docker im Caddy-Container. Optionen in der Caddyfile (Kapitel 9.7) haben Vorrang.

| Variable | Bedeutung | Standard |
|---|---|---|
| `SENTINEL_PANEL` | Adresse des Panels | `http://127.0.0.1:7600` (Docker: `http://panel:7600`) |
| `SENTINEL_TOKEN` | Token direkt | – |
| `SENTINEL_TOKEN_FILE` | Datei mit dem Token, wenn `SENTINEL_TOKEN` fehlt | `/var/lib/caddy-sentinel/agent.token` (steht so auch in der Ergänzung der Caddy-Unit; Agent-Installation: `/etc/caddy/sentinel-agent.token`) |
| `CADDY_ADMIN` | Caddys eigene Standard-Adresse der Admin-API (gilt ohne globale Option `admin`; auch für `caddy reload`/`caddy stop`); der Agent übernimmt sie | `localhost:2019` (Ergänzung der Caddy-Unit, auch Agent-Installation: `unix//run/caddy/admin.sock\|0660`) |
| `SENTINEL_REMOTE` | Zugriffsmodus `off`, `read`, `full` | `read` (Agent-Installation: `full`) |
| `SENTINEL_CADDYFILE` | Caddyfile für `remote full` | – (Agent-Installation: `/etc/caddy/Caddyfile`) |

### B.3 Skripte und Docker Compose

| Variable | Wo | Bedeutung |
|---|---|---|
| `SENTINEL_REPO` | Installation, Update | GitHub-Repository (Standard `b1tk1ll3r/caddy-sentinel`) |
| `SENTINEL_DOWNLOAD` | Installation, Update | Spiegel statt der GitHub-Releases; wird für spätere Updates gemerkt |
| `SENTINEL_DATA` | Update | Datenverzeichnis für die Sicherung; ohne Angabe aus `/etc/default/caddy-sentinel` |
| `GITHUB_TOKEN` | Update | optional, für Downloads bei GitHub |
| `SENTINEL_AGENT_TOKEN` | Installation (`--agent`) | Agent-Token; so steht es nicht in der Prozessliste (statt `--token`) |
| `SENTINEL_VERIFY_ATTESTATION` | Installation, Update | `1` = Herkunftsnachweis jedes Archivs mit `gh attestation verify` prüfen (wie `--verify-attestation`) |
| `GH_TOKEN` | Installation, Update (mit `--verify-attestation`) | Anmeldung der GitHub-CLI (alternativ `gh auth login` als root) |
| `SENTINEL_SKIP_SIGNATURE` | Installation, Update | `1` = Signatur der Prüfsummen nicht prüfen (wie `--skip-signature`; nur im Notfall) |
| `RELEASE_SIGNING_KEY` | GitHub-Secret (Release-Workflow) | privater SSH-Schlüssel, mit dem `SHA256SUMS` signiert wird (docs/INSTALL.md) |
| `SENTINEL_VERSION` | Docker Compose (`.env`) | Image-Version (Standard `latest`) |
| `SENTINEL_NET` | Docker Compose (`.env`) | die ersten drei Oktette des Container-Netzes (Standard `172.31.77`) |
| `TZ` | Docker Compose | Zeitzone (Standard `Europe/Berlin`) |

Optionen von `install.sh` stehen in docs/INSTALL.md, Optionen von `caddy-sentinel-update` in Kapitel 11.5.

### B.4 Dateien und Verzeichnisse (systemd-Installation)

| Pfad | Inhalt |
|---|---|
| `/etc/caddy/Caddyfile`, `/etc/caddy/sites/*.caddy` | Caddy-Konfiguration, im Panel bearbeitet (`root:caddy`, Verzeichnisse `2775` mit setgid) |
| `/etc/caddy/sentinel-agent.token` | Token auf Agent-Servern (`root:caddy`, `0640`) |
| `/etc/default/caddy-sentinel` | Umgebungsvariablen des Panels |
| `/var/lib/caddy-sentinel/` | gemeinsamer Teil für Panel und Caddy (`caddy-sentinel:caddy`, `2750`) |
| `/var/lib/caddy-sentinel/agent.token` | Token der lokalen Instanz (`caddy-sentinel:caddy`, `0640`) |
| `/var/lib/caddy-sentinel/staging/` | Prüf-Kopien der Konfiguration (Gruppe `caddy` lesend) |
| `/var/lib/caddy-sentinel/geo/` | GeoIP-Datenbanken (empfohlener Ort; Gruppe `caddy` lesend) |
| `/var/lib/caddy-sentinel/data/` | Datenverzeichnis des Panels (`caddy-sentinel:caddy-sentinel`, `0700`) |
| `/var/lib/caddy-sentinel/data/sentinel.db` (`-wal`, `-shm`) | Datenbank des Panels |
| `/var/lib/caddy-sentinel/data/mirror/<instanz>/` | Kopien der Zertifikate und CA-Daten (ohne Schlüssel), auch der lokalen Instanz (`local`) |
| `/var/lib/caddy-sentinel/data/validate-data/` | Arbeitsverzeichnis von „Vollständig prüfen“ |
| `/var/lib/caddy/.local/share/caddy/` | Caddy-Daten (nur Benutzer `caddy`): Zertifikate, private Schlüssel, Interne CA (`pki/`), Zwischenspeicher des Agents `sentinel-state.json`, bei `remote full` das Prüfverzeichnis `sentinel-staging/` |
| `/var/log/caddy/` | Log-Dateien von Caddy (Besitzer `caddy`) |
| `/run/caddy/admin.sock` | Admin-API von Caddy (`caddy:caddy`, `0660`; Verzeichnis von systemd über `RuntimeDirectory=caddy` angelegt) |
| `/var/backups/caddy-sentinel/` | Sicherungen der Updates; `Caddyfile.vor-sentinel-<Zeit>` (Sicherung, falls das Installationsskript die globale Option `sentinel` eingetragen hat); `vor-rollback-<Zeit>/` (beim Rollback ersetzte Fassungen) – alles nur für root |
| `/usr/local/bin/caddy-sentinel` | Panel |
| `/usr/local/bin/caddy` | Caddy mit Sentinel-Modul; ein vorher vorhandenes Programm als `caddy.orig` |
| `/usr/local/sbin/caddy-sentinel-update`, `/usr/local/sbin/caddy-sentinel-uninstall` | Update und Deinstallation |
| `/usr/local/share/caddy-sentinel/` | installierte Version, Repository, Spiegel, Installationsart, gemerkter Signaturschlüssel `release-signing.pub` |
| `/usr/local/share/doc/caddy-sentinel/` | Lizenz, NOTICE, Lizenzen Dritter |
| `/etc/systemd/system/caddy-sentinel.service` | Unit des Panels (`User=caddy-sentinel`, `SupplementaryGroups=caddy`) |
| `/etc/systemd/system/caddy.service.d/sentinel.conf` | Ergänzung der Caddy-Unit (Sentinel-Build, Panel-Adresse, Token-Datei, Admin-Socket über `CADDY_ADMIN` und `RuntimeDirectory`) |

### B.5 Docker-Volumes

| Volume | Caddy | Panel | Inhalt |
|---|---|---|---|
| `caddy-etc` | `/etc/caddy` (nur lesend) | `/etc/caddy` | Caddyfile und eingebundene Dateien |
| `caddy-admin` | `/run/caddy` | `/run/caddy` (nur lesend) | Admin-API-Socket |
| `sentinel-staging` | `/run/sentinel-staging` (nur lesend) | `/run/sentinel-staging` | Prüf-Kopien der Konfiguration (`staging`) |
| `caddy-data` | `/data` | – | Zertifikate, private Schlüssel, Interne CA (öffentliche Teile bekommt das Panel über den Agenten) |
| `caddy-config` | `/config` | – | Caddys automatisch gespeicherte Konfiguration |
| `caddy-logs` | `/var/log/caddy` | – | Log-Dateien |
| `sentinel-data` | – | `/var/lib/caddy-sentinel` | Datenbank des Panels |
| `sentinel-token` | `/run/sentinel-token` (nur lesend) | `/run/sentinel-token` | nur das Agent-Token |
