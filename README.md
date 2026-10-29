# Caddy Sentinel

Steuerzentrale für Caddy: Live-Editor für das Caddyfile, Metriken und Analysen,
Bedrohungserkennung mit automatischen Sperren (IDS/IPS), eine Web Application
Firewall mit eigenen Regelsätzen und Limits pro Site.

```
                ┌──────────────────────────── Caddy (eigener Build) ─────────────────────────┐
 Request ──────▶│ sentinel-Handler: Bans → Pfad-Regeln → Wartung → IP/Geo/Feeds → Filter      │──▶ reverse_proxy / file_server …
                │   → Ratelimits → Bot-Challenge → Anmeldung (AD + 2FA) → Coraza-WAF (CRS)    │
                └───────┬──────────────────────────────────────────────▲───────────────────────┘
                        │ Telemetrie (Zähler + Requests, 1×/s)          │ Policies & Bans (Long-Poll, < 1 s)
                ┌───────▼──────────────────────────────────────────────┴───────────────────────┐
                │ Sentinel-Panel: SQLite · IDS-Engine · Alarme/Webhooks · Web-UI · /metrics      │
                │                 Caddy Admin-API (adapt/load) · Caddyfile-Versionen             │
                └───────────────────────────────────────────────────────────────────────────────┘
```

## Funktionen

**Caddyfile-Editor** (CodeMirror 6, mitgeliefert – keine externen Abhängigkeiten zur Laufzeit)
- Bedienung wie in VS Code: Mehrfach-Cursor (Alt+Klick, Strg+D, Strg+Umschalt+L), Block-Auswahl, Zeilen verschieben/duplizieren, Klammer-Paare, Blöcke einklappen, Suchen & Ersetzen mit Regex, Gehe zu Zeile, Befehlspalette (F1 / Strg+Umschalt+P), eigener Undo-Verlauf pro Datei, Brotkrumen-Navigation in der Statusleiste
- Gehe zu Definition (F12 / Strg+Klick) für benannte Matcher und Snippets – auch in anderen Dateien –, Matcher umbenennen (F2)
- Kontextabhängige Vorschläge: globale Optionen, Direktiven mit Vorlagen, Unterdirektiven je Block, erlaubte Werte (z. B. `lb_policy`, `redir`-Codes, `encode`), Header-Namen, Statuscodes, Platzhalter, Matcher, vorhandene Snippets, importierbare Dateien, Sentinel-Policies, Upstreams aus der Datei
- Eigene Prüfung schon beim Tippen (zusätzlich zur Caddy-Validierung) mit Schnellkorrekturen: Tippfehler mit „Meinten Sie …?“, Unterdirektiven am falschen Ort (z. B. Transport-Optionen direkt in `reverse_proxy`), veraltete Namen (`basicauth`), doppelte Site-Adressen, undefinierte oder unbenutzte Matcher, unbekannte Snippets und Policies, Klartext-Passwörter in `basic_auth`, überflüssige `header_up X-Forwarded-*`, nie erreichbare Handler, Sites ohne `sentinel`, `file_server` ohne `root`
- **Formular-Modus pro Site**: jeden Site-Block (Knopf „Formular“ oder ✎ in der Gliederung) als Formular bearbeiten – Adressen, Sentinel/Policy, Ziel (Reverse Proxy mit Lastverteilung/Health-Check/HTTPS-Backend, statisch, SPA, PHP, Weiterleitung, Antwort), Pfad-Routen, benannte Matcher mit Regeln, TLS, Kompression, Sicherheits-Header, Logging. Nicht abbildbare Teile bleiben unverändert erhalten; Vorschau, Diff und Prüfung live daneben. „Neue Site“ legt Blöcke als eigene Datei, in der Caddyfile oder am Cursor an
- Live-Validierung über die Caddy-Admin-API (`/adapt`) mit Fehlerzeile direkt im Editor – auch für importierte Dateien; „Vollständig prüfen“ mit `caddy validate`
- Mehrere Dateien (Caddyfile + `import`ierte `*.caddy`), Gliederung, Formatieren (`caddy fmt`, Umschalt+Alt+F), Vorlagen, „Sentinel einfügen“
- Übernehmen ohne Neustart; lehnt Caddy die Konfiguration ab, werden die alten Dateien automatisch wiederhergestellt
- Versionsverlauf mit Diff und Wiederherstellung, Erkennung externer Änderungen

**Fehleranalyse – woran scheitert eine Anfrage?**
- Jede Anfrage im Request-Explorer, Live-Traffic und auf der IP-Seite hat eine Diagnose: wer geantwortet hat (Sentinel, Caddy, Backend oder Client), an welcher Stelle der Prüfkette sie hängen blieb, die konkrete Ursache mit Beleg (passender Sperrlisten-Eintrag, Ratelimit mit Grenze, WAF-Treffer, Geo-Treffer, fehlende Gruppe beim Site-Login, nicht erreichbares Backend …) und direkte Wege zur Lösung (Policy-Abschnitt, Pfad-Regel, Sperre aufheben, WAF-Regel ausnehmen)
- „Mit der aktuellen Konfiguration“: Die Anfrage wird gegen die heutige Konfiguration nachgespielt – so sieht man sofort, ob eine Änderung das Problem behebt. Ein Klick öffnet sie vorausgefüllt im Simulator des Request-Flusses
- Seite **Fehleranalyse**: fehlgeschlagene und blockierte Anfragen nach Ursache gruppiert, mit Anzahl, betroffenen Clients und Pfaden, gefiltert nach Sentinel / Caddy / Backend / Client
- Blockierte Browser sehen eine neutrale Fehlerseite mit **Referenz** (z. B. `K7QM-3XPA`, auch im Header `X-Sentinel-Ref`); über die Referenz findet man im Panel genau diese Anfrage samt Begründung. Die Seite nennt keine Regel-Details

- Zeitverlauf der Fehler mit **Markierungen für Änderungen** (Policies, Regelsätze, Caddyfile, WAF-Ausnahmen) – sichtbar, ob ein Anstieg mit einer Änderung zusammenfällt
- **Hinweise von sich aus**: steigt eine Fehlerursache sprunghaft an (z. B. eine WAF-Regel, ein Ratelimit, 502 eines Backends), kommt eine Meldung über die eingerichteten Kanäle – mit Bezug zur Änderung kurz davor
- **Fehlalarm-Assistent für die WAF**: schlägt anhand echter Blockaden die engste Ausnahme vor (Regel nur für einen Parameter unter einem Pfad → Regel unter einem Pfad → WAF dort nur melden → Regel ganz aus), jeweils mit der Zahl der Blockaden, die sie verhindert hätte, und einem Hinweis, wenn es eher nach echtem Angriff aussieht
- Dashboard „Was Aufmerksamkeit braucht“: ablaufende Zertifikate, ausfallende Backends, offline Caddy-Instanzen, fehlerhafte Policies, Monitore, Testmodus, aktuelle Anstiege

**Änderungen sicher einführen**
- **Vorschau vor dem Speichern**: Beim Speichern einer Policy wird der gespeicherte Verkehr der letzten 24 Stunden gegen den Entwurf nachgespielt – „neu blockiert“, „neu durchgelassen“ mit Beispielen. Ohne Auswirkung wird direkt gespeichert
- **Testmodus** für IP-Regeln, Geo & Feeds, Filter, einzelne Ratelimits und Pfad-Regeln: Treffer werden als „Test: …“ protokolliert, die Anfrage geht durch. Auswertung „was wäre blockiert worden“ mit Knöpfen zum Scharfschalten

**Mehrere Caddy-Server – ein Panel**
- Weitere Caddy-Instanzen verbinden sich über ihren Sentinel-Agent mit eigenem Token – nur ausgehend, ohne offenen Port auf dem Server. Installation per `install.sh --agent --panel URL --token TOKEN`
- Zugriff je Server wählbar: `remote read` (Konfiguration, Backends, Zertifikate lesen) oder `remote full` (Caddyfile im Panel bearbeiten, prüfen und laden, mit automatischem Zurückrollen)
- Jede Instanz hat Name und Farbe. Statistiken pro Instanz oder gesammelt (Auswahl in der Kopfzeile); Editor, Request-Fluss, Sites, Zertifikate und interne CA zeigen immer genau eine Instanz – mit farbigem Balken oben und Umschalter. Tabellen und Meldungen tragen die Instanz als farbiges Kennzeichen
- Versionsverlauf, Zertifikatswarnungen und Alarme getrennt je Instanz; Policies, Sperren und Feeds gelten für alle

**Rollen und Berichte**
- Rollen Administrator, Bearbeiter (Caddyfile, Policies, Regelsätze, Feeds, Monitore, Sperren), Support (alles sehen, Sperren setzen/aufheben) und Leser – auch über AD-Gruppen
- **Wochenbericht per E-Mail** (HTML + Text): Kennzahlen je Instanz, häufigste Fehlerursachen, blockierte Clients, Änderungen, offene Hinweise; mit Vorschau und Sofortversand

**Metriken & Analysen**
- Exakte Zähler pro Host/Status/Aktion (unabhängig von der Stichprobe), Latenz-Histogramm mit p50/p95/p99
- Dashboard, Live-Traffic (pro Sekunde + Request-Stream), Top-Listen (Pfade, Clients, User-Agents, Referer, Status, Methoden, Aktionen), Request-Explorer mit Filtern und CSV-Export
- Sites-Übersicht aus der laufenden Konfiguration inkl. Upstream-Status, Caddy-Prozessdaten
- Prometheus-Endpunkt `/metrics` (mit Token)

**IDS / IPS**
- Bedrohungs-Score pro IP aus Signalen: WAF-Blocks/-Treffer, Honeypots, 404-Scans, 401/403-Serien, Angriffstools, Ratelimits, Bursts …
- Score zerfällt exponentiell; ab der Schwelle automatische Sperre – mit Eskalation für Wiederholungstäter und optional dauerhaft
- Sperren greifen innerhalb von Millisekunden auf allen Sites, bleiben bei Panel-Ausfall aktiv (lokaler Cache im Agent)
- Testmodus, Ausnahmelisten, manuelle Sperren (IP/CIDR), IP-Detailseite mit Verlauf
- Alarme für Fehlerquoten, Traffic-Spitzen, Angriffswellen und Agent-Ausfall; Webhooks für Discord, Slack/Mattermost, Teams, ntfy, Gotify, JSON

**WAF**
- Coraza mit OWASP CRS 4, Modus Aus/Erkennen/Blockieren, Paranoia-Level, Anomalie-Schwelle, Body-Prüfung
- CRS-Gruppen einzeln abschaltbar, Regeln global oder gezielt pro Pfad ausnehmen
- Regel-Builder ohne SecLang-Kenntnisse (Felder, Operatoren, Transformationen, Aktionen: blockieren, Score erhöhen, protokollieren, erlauben, CRS-Regeln ausnehmen) – oder rohes SecLang
- Wiederverwendbare Regelsätze mit Vorlagen (Exploit-Pfade, WordPress, Admin nur intern, API nur JSON, Nextcloud, Login-Schutz)
- WAF-Tester: Requests gegen eine Policy prüfen, ohne Caddy zu berühren

**Geo, Netze & Threat-Feeds**
- Länder- und ASN-Regeln pro Policy (sperren oder Bot-Challenge), z. B. „nur DACH, Rest muss sich ausweisen“ oder „Rechenzentren-Netze challengen“
- Länder- und Netz-Analysen (Top-Listen, Filter, Flaggen in allen Request-Listen)
- Threat-Feeds: FireHOL Level 1, Spamhaus DROP, abuse.ch Feodo, blocklist.de, Emerging Threats, Tor-Exit-Knoten – oder eigene Listen; automatische Aktualisierung, Abgleich in O(log n) im Agent

**Bot-Challenge**
- JavaScript-Proof-of-Work-Interstitial statt harter Sperre: echte Browser lösen es in ca. einer Sekunde, Skripte ohne JavaScript nicht
- Auslöser: Geo-/Feed-Regel, verdächtige IPs (IDS-Score über der Challenge-Schwelle) oder „Angriffsmodus“ für alle Besucher
- Signiertes, IP-gebundenes Cookie, ausgenommene Pfade für APIs/Webhooks, funktioniert auch auf reinen HTTP-Seiten

**Interne CA (Caddy als Zertifizierungsstelle)**
- Root und **aktives Intermediate** jeder Caddy-CA mit Laufzeit, Fingerabdruck, Schlüsseltyp und PEM-Download; Abgleich mit der laufenden Instanz über die Admin-API (`/pki/ca/<id>`) – zeigt, wenn Caddy mit einem anderen Intermediate signiert als im Speicher liegt
- Intermediate-Verlauf: alle bisherigen Intermediates (aus der ACME-Datenbank und den Zertifikatsketten) mit Anzahl der damit ausgestellten Zertifikate
- **Alle ausgestellten Zertifikate**: über `acme_server` an Clients (aus der step-ca-Datenbank von Caddy, inkl. ACME-Konto, Provisioner, Widerruf mit Grund) und per `tls internal` an Caddy selbst; Suche, Filter (gültig/abgelaufen/widerrufen, Quelle, Intermediate, nur neuestes je Name), Detailansicht und PEM-Download
- ACME-Endpunkte aus der laufenden Konfiguration (Directory-URL, Laufzeit, Policy) und Alarm, wenn Root oder Intermediate ablaufen bzw. nicht erneuert wurden

**Site-Login mit Active Directory + 2FA**
- Beliebige Sites hinter Caddy pro Policy mit einer Anmeldung schützen: Domänenkonto (AD/LDAP, auch `FIRMA\name` oder UPN) plus TOTP-Code; den Authenticator richten Benutzer beim ersten Login selbst per QR-Code ein
- Zugriff über AD-Gruppen (verschachtelt) oder einzelne Konten, Sitzungsdauer, Pfad- und Netz-Ausnahmen, „ohne 2FA aus dem Büro-LAN“, optional an die IP gebunden
- Weitergabe an das Backend als `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups` (Client-Header werden entfernt) und als Platzhalter `{http.vars.sentinel.user}`
- Sperre nach Fehlversuchen, Replay-Schutz für Codes, Fehlversuche fließen ins IDS; Benutzerliste mit 2FA-Reset, „überall abmelden“ und Sperren; Anmeldeprotokoll
- Auch das Panel selbst akzeptiert auf Wunsch AD-Konten (Rolle aus Gruppen, 2FA Pflicht) – lokale Konten bleiben als Notfallzugang

**Request-Fluss (grafisch)**
- Matrix aller Sites: TLS, Sentinel/Policy, Pfad-Regeln, Wartung, IP, Geo/Feeds, Filter, Limits, Challenge, Anmeldung, WAF und Ziele auf einen Blick
- Fluss-Diagramm pro Site von links nach rechts (oder von oben nach unten): Client → Eingang (Port, TLS, Zertifikat) → Sentinel mit allen Stufen der Policy und den Pfad-Regeln → Caddy-Routen (Matcher, Middleware wie Header/Kompression/Rewrite) → Ziele (Upstreams mit Status, Dateien, Antworten, Weiterleitungen) – Routen ohne Sentinel sind gestrichelt
- Simulator: Methode, Pfad, Client-IP, Browser/API, angemeldeter Benutzer mit Gruppen und 2FA, API-Schlüssel – der Weg des Requests wird im Diagramm hervorgehoben, inklusive Grund für eine Sperre und optionaler echter WAF-Prüfung

**Pfad-Regeln (Ausnahmen pro Bereich)**
- Pro Policy beliebig viele Regeln nach Pfad (Präfix, exakt, Platzhalter, Regex), Methode und Client-Netz – die erste passende gilt
- Aktionen: durchlassen, sperren, weiterleiten (mit Platzhaltern) oder Einstellungen anpassen
- Bereiche mit und ohne Anmeldung, eigene AD-Gruppen/Benutzer und 2FA nur für bestimmte Pfade (z. B. `/admin/` mit 2FA und Gruppe *IT-Admins*, Rest ohne 2FA); fehlt der zweite Faktor, fragt Sentinel ihn nach (Step-up)
- „Nur aus Netzen“ (Admin nur aus dem LAN), API-Schlüssel statt Login für Webhooks und Skripte (nur als Hash gespeichert, auch als `Authorization: Bearer`), WAF/Challenge/Ratelimits/Wartung je Bereich abweichend, Antwort-Header (z. B. `X-Robots-Tag`)
- Vorlagen: Admin-Bereich, öffentlicher Bereich, Webhook, API mit Bearer-Token, Health-Check, statische Dateien, Weiterleitung, Pfad sperren, nicht indexieren
- **Single Sign-on**: einmal anmelden, alle Sites unter einer Domain nutzen (Domain-Cookie, Abmelden überall), Gruppen und 2FA weiter pro Site geprüft
- Kontoseite `/.sentinel/auth/me` (auch als JSON für Apps), Ratelimits pro angemeldetem Benutzer

**Betrieb**
- Verfügbarkeits-Monitore mit Statusbalken, Uptime (24 h/7 T/30 T), Antwortzeit, Schlüsselwort- und Statusprüfung; Alarm bei Ausfall und Wiederherstellung
- Zertifikats-Übersicht aus dem Caddy-Speicher mit Warnung, wenn eine Erneuerung hängt
- Benutzer mit Rollen (Administrator/Leser), Zwei-Faktor-Anmeldung (TOTP mit QR-Code), Sitzungsverwaltung, Audit-Log aller Änderungen und Anmeldungen
- E-Mail-Benachrichtigungen per SMTP (zusätzlich zu Discord, Slack, Teams, ntfy, Gotify, JSON)
- Backup/Import von Einstellungen, Policies, Regelsätzen, Feeds und Monitoren (auch zum Übertragen auf einen zweiten Server)

**Pro Site (Policy)**
Hosts → Policy-Zuordnung (oder fest per `sentinel <policy>`), je Policy: Wartungsmodus, Länder-/ASN-Regeln, Threat-Feed-Aktionen, Bot-Challenge, IP-Frei-/Sperrlisten, erlaubte Methoden, gesperrte User-Agents, Honeypot-Pfade, Body-Limit, beliebig viele Ratelimits (pro IP, IP+Pfad, global, Header) mit 429 oder Sperre, WAF-Einstellungen, Sicherheits-Header, eigene IDS-Schwellen und -Gewichte.

## Aufbau

| Verzeichnis | Inhalt |
|---|---|
| `sentinel/` | Caddy-Modul (`http.handlers.sentinel`, App `sentinel`), Protokoll, WAF-Konfiguration |
| `caddy/` | `main.go` für den Caddy-Build mit Sentinel-Modul (entspricht xcaddy) |
| `panel/` | Panel (Go, SQLite) mit eingebetteter Web-UI (`web/static`, reines JavaScript ohne Build-Schritt; der Editor nutzt ein mitgeliefertes CodeMirror-Bündel in `web/static/vendor/`, neu erzeugbar mit `scripts/build-codemirror.sh`) |
| `deploy/` | systemd-Units, Umgebungsdatei, Installationsskript |

## Installation

Kurzfassung – alle Wege (systemd, Docker Compose, selbst bauen, Updates, Rollback, Releases) stehen ausführlich in **[docs/INSTALL.md](docs/INSTALL.md)**.

**Server mit systemd** (amd64, arm64, armv7):

```bash
curl -fsSL https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh | sudo bash
sudo caddy-sentinel-update --check     # später: Update prüfen
sudo caddy-sentinel-update             # aktualisieren (mit Vorabprüfung, Sicherung, automatischem Rollback)
```

**Docker Compose** (Images auf ghcr.io):

```bash
curl -fsSLO https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/deploy/docker/compose.yml
docker compose up -d                   # Update: docker compose pull && docker compose up -d
```

**Selbst bauen:** `./build.sh` (Ergebnis in `dist/`), danach `sudo ./deploy/install.sh`. Statische Release-Archive wie in der CI: `./scripts/build-release.sh`.

Danach `http://127.0.0.1:7600` öffnen (z. B. `ssh -L 7600:127.0.0.1:7600 server`) und das Admin-Konto anlegen. Konfiguration des Panels: `/etc/default/caddy-sentinel`.

**GitHub Actions:** Pushes und Pull Requests laufen durch Tests und einen Test-Build (`ci.yml`). Ein Tag `v1.2.3` baut alle Binaries, erstellt das Release mit Prüfsummen und veröffentlicht beide Docker-Images (`release.yml`).

### Caddyfile

```caddy
{
	# optional – das sind die Standardwerte
	sentinel {
		panel http://127.0.0.1:7600
		token_file /var/lib/caddy-sentinel/agent.token
	}
}

example.com {
	sentinel                # Policy über den Host (oder: sentinel <policy-id>)
	reverse_proxy 127.0.0.1:8080
}
```

Jede Site, die geschützt und gemessen werden soll, braucht die Direktive `sentinel` – der Editor fügt sie auf Knopfdruck überall ein. Sie läuft automatisch vor allen anderen Handlern.

**Hinter einem Proxy / Cloudflare** muss Caddy die echte Client-IP kennen, sonst würde Sentinel den Proxy sperren:

```caddy
{
	servers {
		trusted_proxies static 173.245.48.0/20 103.21.244.0/22   # Netze des Proxys
		client_ip_headers CF-Connecting-IP X-Forwarded-For
	}
}
```

### Panel über Caddy veröffentlichen

```caddy
sentinel.example.com {
	sentinel
	reverse_proxy 127.0.0.1:7600
}
```

Das Panel hat eine eigene Anmeldung mit Brute-Force-Schutz. Zusätzlich empfiehlt sich eine IP-Freigabeliste in der Policy dieser Site.

### GeoIP-Datenbanken

Für Länder/ASN werden `.mmdb`-Dateien benötigt, z. B. kostenlos von DB-IP („IP to Country Lite“, „IP to ASN Lite“, CC BY 4.0) oder MaxMind GeoLite2 (kostenloses Konto):

```bash
sudo install -d -o caddy -g caddy /var/lib/caddy-sentinel/geo
# Dateien herunterladen und entpacken, z. B. nach
#   /var/lib/caddy-sentinel/geo/country.mmdb und /var/lib/caddy-sentinel/geo/asn.mmdb
```

Pfade unter *Einstellungen › Netz & Vertrauen* eintragen – sie gelten für Panel und Caddy. Auf einem separaten Caddy-Host lassen sie sich mit `geoip_country`/`geoip_asn` in der globalen `sentinel`-Option überschreiben. Ein monatliches Update per Cronjob genügt.

### Zertifikate

Unter *Einstellungen › Agent & Caddy* das Caddy-Datenverzeichnis angeben (Paketinstallation: `/var/lib/caddy/.local/share/caddy`). Das Panel liest nur die `.crt`-Dateien.

### Interne CA

Die Seite *Interne CA* liest `<Caddy-Datenverzeichnis>/pki/authorities/*` und die ACME-Datenbank `acme_server/<ca>/db`. Caddy hält die Datenbank geöffnet; das Panel liest deshalb eine Kopie (nur lesend). Beides funktioniert, wenn das Panel als Benutzer `caddy` läuft (Standard der mitgelieferten Unit). Typische Konfiguration einer internen CA:

```caddyfile
ca.firma.local {
	tls internal
	acme_server {
		lifetime 7d
	}
}
```

### Site-Login (Active Directory + TOTP)

1. *Site-Login › Verzeichnis*: Server (`ldaps://dc1.firma.local`), Dienstkonto mit Leserechten, Base-DN eintragen, ggf. das CA-Zertifikat der Domänencontroller einfügen – mit „Verbindung prüfen“ und „Anmeldung testen“ kontrollieren.
2. In der Policy der Site (Reiter *Anmeldung*) den Login einschalten, erlaubte Gruppen eintragen, 2FA an/aus.
3. Die Site muss die `sentinel`-Direktive haben. Login: `/.sentinel/auth/login`, Abmelden: `/.sentinel/auth/logout`.

Passwörter werden nicht gespeichert; das Panel prüft sie bei jeder Anmeldung direkt am AD (Bind als Benutzer) und liest die Gruppen mit dem Dienstkonto. Gespeichert werden nur TOTP-Schlüssel und Anmeldedaten. Die Sitzung ist ein signiertes Cookie, das der Agent lokal prüft – das Panel wird nur beim Anmelden gebraucht. Ein 2FA-Reset, Sperren oder „Abmelden“ wirkt innerhalb von Sekunden auf allen Caddy-Instanzen.

## Erste Schritte

1. **Editor**: `sentinel` in alle Sites einfügen und übernehmen.
2. **Policies › Standard**: Die WAF startet im Modus *Erkennen*. Ein paar Tage Treffer unter *Sicherheit* beobachten, Fehlalarme ausnehmen (Link „ausnehmen“ bei den Regeln), dann auf *Blockieren* stellen.
3. **Ratelimits**: Vorlage „Login-Schutz“ für Login-Pfade.
4. **Einstellungen › Bedrohungserkennung**: Schwelle und Gewichte prüfen, eigene Netze unter *Netz & Vertrauen* eintragen.
5. **Einstellungen › Benachrichtigungen**: Webhook oder E-Mail für Sperren und Alarme.
6. **Verfügbarkeit**: „Sites übernehmen“ legt Monitore für alle Hosts an.
7. **Einstellungen › Konto & Sicherheit**: Zwei-Faktor-Anmeldung einrichten.
8. **Site-Login**: Active Directory verbinden und interne Sites per Policy schützen.

## Hinweise

- Die WAF prüft Requests (URI, Header, Body). Antworten werden nicht inspiziert, damit Streaming und große Downloads unverändert bleiben.
- Stichprobe < 100 % reduziert gespeicherte Einzel-Requests; Fehler, WAF-Treffer und Eingriffe werden immer übertragen, Diagramme und Zähler bleiben exakt. Die Burst-Erkennung des IDS sieht bei einer Stichprobe nur einen Teil des Traffics.
- Alle Agent-Daten laufen über `POST /api/agent/ingest`, `GET /api/agent/state` und (Site-Login) `POST /api/agent/auth` mit Bearer-Token. Mehrere Caddy-Instanzen können dasselbe Panel nutzen.
- UI anpassen ohne neu zu bauen: `SENTINEL_WEB_DIR=/pfad/zu/panel/web/static` setzt die Dateien von der Platte ein.
- Gespeicherte Geheimnisse (SMTP-, LDAP-Dienstkonto-Passwort) gibt die API nicht mehr aus; leere Felder behalten den gespeicherten Wert.
- Das Panel zeigt in der Seitenleiste neue Releases an (GitHub, alle 6 Stunden; `SENTINEL_UPDATE_CHECK=0` schaltet das ab).
- Getestet in dieser Umgebung mit Caddy 2.10.0, Coraza 3.3.3 und CRS 4.25 (Go 1.24); `build.sh` baut standardmäßig gegen die neuesten Versionen.
