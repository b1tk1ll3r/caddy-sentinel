# Änderungen

Format: je Version ein Abschnitt `## vX.Y.Z`; der Release-Workflow übernimmt ihn als Release-Notizen.

## v1.3.0

Sicherheitsrelease nach einem vollständigen Audit (Modul, Panel, Anmeldung, Oberfläche, Betrieb): 51 Funde,
davon 8 hoch, keiner kritisch – alle behoben oder entschärft. **Allen Installationen wird das Update empfohlen.**

### Wichtig beim Update

- **Eigener Benutzer für das Panel (systemd).** Das Panel läuft als `caddy-sentinel` (Zusatzgruppe `caddy`), die
  Datenbank liegt in `/var/lib/caddy-sentinel/data` (0700). Caddy kann sie nicht mehr lesen, auch nicht über eine
  Caddyfile mit `file_server`. Agent-Token, Prüf-Kopien und GeoIP bleiben am bisherigen Ort; die Caddyfile muss
  nicht geändert werden. `caddy-sentinel-update` stellt automatisch um (ein Update mit dem alten Skript braucht
  dafür zwei Aufrufe, der Installationsbefehl einen); `--rollback` stellt auch das alte Layout wieder her.
  Zertifikate und Interne CA liest das Panel jetzt über den lokalen Agenten (ohne private Schlüssel);
  „Vollständig prüfen“ öffnet keine Log- und Schlüsseldateien mehr und nennt sie unter „Nicht geprüft“.
- Sicherungen, die die Skripte anlegen (`Caddyfile.vor-sentinel-<Zeit>`, `vor-rollback-<Zeit>/`), liegen jetzt in
  `/var/backups/caddy-sentinel/` (nur root). Die systemd-Units liegen im Quellbaum unter `deploy/systemd/`.
- **Caddys Admin-API nur noch als Unix-Socket (systemd).** `/run/caddy/admin.sock` (0660, Gruppe `caddy`) über
  `CADDY_ADMIN` in der Caddy-Unit; `localhost:2019` ist zu. Das Update stellt um und startet Caddy neu; die
  Caddyfile bleibt unverändert. Eigene Skripte, die `localhost:2019` nutzen, brauchen
  `caddy reload --address unix//run/caddy/admin.sock` bzw. `curl --unix-socket /run/caddy/admin.sock`. Eine
  globale Option `admin` in der Caddyfile hat Vorrang (die Skripte warnen); das Panel lehnt Konfigurationen ab, die
  die Admin-API dorthin verlegen, wo es Caddy nicht mehr erreicht. Agent-Server ebenso, außer bei
  `admin http://…` im `sentinel`-Block.
- **Docker:** neue `compose.yml` und Images gemeinsam übernehmen – das Docker-Gateway gilt nicht mehr als
  vertrauenswürdiger Proxy, das Panel hängt Caddys Daten- und Log-Volume nicht mehr ein, Caddy bekommt das
  Konfigurationsvolume nur lesend, die Prüf-Kopien liegen im neuen Volume `sentinel-staging` (für Caddy nur lesend).
- **Signierte Releases:** `SHA256SUMS` wird per SSH signiert (`SHA256SUMS.sig`). Ist ein Schlüssel eingebaut,
  prüfen install.sh und `caddy-sentinel-update` die Signatur zwingend (Notausgang `--skip-signature`); Spiegel
  müssen `SHA256SUMS.sig` mit ausliefern. Einrichtung des Schlüssels: `docs/INSTALL.md`.
- `caddy-sentinel-update` geht über die `VERSION`-Datei nicht mehr auf eine ältere Version zurück; dafür ist
  `--version` nötig.
- Neu: `--verify-attestation` (bzw. `SENTINEL_VERIFY_ATTESTATION=1`) prüft bei Installation und Update die
  Herkunft des Release-Archivs mit `gh attestation verify`.
- **Gruppen als voller DN** (`CN=…,OU=…,DC=…`) in Policies, Pfadregeln, OIDC-Anwendungen und Panel-Rollen
  passen jetzt nur noch auf genau diese AD-Gruppe, nicht mehr auf jede gleichnamige Gruppe. Ein reiner Name
  (`IT-Admins`) passt wie bisher auf jede gleichnamige Gruppe. Site-Sitzungen von vor dem Update tragen nur
  Gruppennamen: Wer auf einer Seite mit DN-Einträgen „kein Zugriff“ sieht, meldet sich einmal neu an. Dasselbe
  gilt für Zugangstokens und OIDC-Anwendungen von AD-Konten: Die DNs kennt Sentinel erst nach der nächsten
  Anmeldung des Kontos.
- **OAuth-Anbieter mit eingestelltem Benutzernamen-Claim** weichen nicht mehr auf andere Claims aus. Fehlt der
  Claim oder ist die E-Mail-Adresse unbestätigt, wird die Anmeldung abgelehnt.
- **OIDC-Server:** `sub` ist jetzt eine feste, zufällige Kennung je Konto. Bestehende Konten behalten ihren
  Namen als `sub`; neu angelegte Konten bekommen eine neue Kennung, auch wenn ein früheres Konto gleich hieß.
- Passwörter dürfen höchstens 72 Byte lang sein (Grenze von bcrypt); längere wurden bisher unbrauchbar gespeichert.
- Ein neues Panel-Passwort und das Zurücksetzen der 2FA beenden auch die API-Tokens des Kontos.

### Sicherheit

- **Caddy-Modul:** `@inspectFile` ließ sich per Zeilenfortsetzung einschleusen (Programmausführung) und
  `setenv` änderte Caddys Umgebung – beides wird abgewiesen. Pfadregeln, Ratelimits und Honeypots prüfen
  kanonische Pfade (Groß/Klein, Pfad-Parameter wie `/;x/admin`); WAF-„block“- und Challenge-„always“-Regeln
  gelten als verschärfend. `NeverBan` gilt auch für lokale Ratelimit-Sperren. Challenge-Token und
  Pass-Cookie sind an Policy, Host und Schwierigkeit gebunden. Offene Weiterleitung über `{path}`,
  Cache-Control auf dem Login-Redirect, WAF-Umgehung per `Content-Type: application/grpc` und große
  PUT-Formulare auf Login-Seiten behoben. Warnung bei unverschlüsselter Verbindung zu einem entfernten Panel.
- **Panel und Agents:** Zeitraum-Abfragen und Telemetrie sind begrenzt (kein Speicherüberlauf durch Leser
  oder ein Agent-Token). Hintergrundaufgaben fangen Abstürze ab (präparierte ACME-Datenbank einer
  Fern-Instanz). Telemetrie eines Agents wird bereinigt: Sperrdauer höchstens `MaxBanSeconds`, nie dauerhaft;
  Zeitstempel im Aufbewahrungsfenster; Feldlängen, Aktionen, Agent-Liste und Host-Listen begrenzt;
  Steuerzeichen werden als `%XX` gespeichert.
- **Benachrichtigungen:** Pfade und Hosts aus Anfragen werden für Discord, Slack, Teams und Gotify maskiert,
  Discord löst keine Erwähnungen mehr auf. Drosselung je IP statt je Host; Alarme ab Schwere „Hoch“ haben eine
  eigene Warteschlange.
- **Leser:** Header-Matcher (`@api header X-Api-Key …`), Zugangsdaten in CEL-Ausdrücken und in Monitor-/Feed-URLs
  werden geschwärzt (Fluss-Ansicht, Caddyfile, Suche). Geteilte Ansichten erst ab Bearbeiter; „CRS-Regel
  ausnehmen“ per Link nur für eine einzelne Regel-ID. Die Übertragungs-Vorschau ist begrenzt.
- **Backup-Restore:** Zugangstokens nur für Konten, die der Restore anlegt; befristete Einträge mit denselben
  Prüfungen wie in der Oberfläche, globale Listen nur zusammen mit den Einstellungen; scrypt-Parameter
  begrenzt; nur ein Restore gleichzeitig.
- **Anmeldung:** Passkey-Einrichtung mit einem alten Ticket, nachdem der Inhaber einen zweiten Faktor
  eingerichtet hat, wird abgewiesen. Fehlversuche bei Codes werden vor der Prüfung gezählt (keine parallelen
  Versuche über das Limit). Das Kontolimit gilt für `DOMÄNE\name` und `name@…` gemeinsam, das Adresslimit für
  IPv6 je /64. Abmelden beendet auch die OIDC-Refresh-Tokens der Sitzung. Gesperrte und gelöschte
  Verzeichniskonten sowie abgeschaltete Anmeldequellen verlieren den Panel-Zugriff (auch API-Tokens).
  Namenskonflikte zwischen AD und anderen Quellen werden beim Panel-Login abgewiesen. Benutzte
  Aktionslinks bleiben nach einem Neustart benutzt. Die Ersteinrichtung liest nach Abschluss keine Anfragen mehr.
- **Sperren aus der Telemetrie entfernter Instanzen** gelten nur auf der meldenden Instanz, solange keine zweite
  Instanz (oder die lokale) dieselbe IP meldet; manuelle Sperren gelten wie bisher überall. Die Liste der Sperren
  zeigt den Geltungsbereich.
- **Fernverwaltung „read“:** Der Agent schwärzt Geheimnisse der laufenden Konfiguration, bevor sie den Server
  verlassen – ein übernommenes Panel erfährt keine DNS-Tokens oder Zugangsdaten. Der Agent spricht die Admin-API
  auch über einen Unix-Socket und folgt ohne eigene Angabe Caddys `CADDY_ADMIN`.
- **Abmelden** auf Site-Logins nur noch per Formular mit Token; ein bloßer Link (auch von fremden Seiten) zeigt
  eine Bestätigung.
- Die Zertifikatsüberwachung liest auch Zertifikate aus einem eigenen `storage` (Datenbank, S3 …), nie Schlüssel.
- **Feeds** hinter einem HTTP-Proxy: link-lokale Ziele (Metadaten-Dienste) bleiben gesperrt.
- **„Als curl kopieren“** kodiert Steuerzeichen, die beim Einfügen im Terminal Befehle auslösen konnten.
- **Skripte:** install.sh und update.sh schreiben als root nie mehr durch Symlinks in Verzeichnisse, die Caddy
  beschreiben kann (Rollback, Eintragen von `sentinel`, Agent-Token). Das Panel schreibt Caddyfiles und
  Prüf-Kopien ebenfalls nur über neu angelegte Dateien.
- **Lieferkette:** `govulncheck` in CI und vor jedem Release (Abbruch bei erreichbaren Schwachstellen); lokale und
  Docker-Builds verwenden standardmäßig die aktuellen Caddy-/Coraza-Versionen statt der in `go.mod`; der
  CodeMirror-Build ist auf Commit-Hashes festgelegt.
- Dashboard-Warnung, solange das Panel noch als `caddy` läuft oder sein Datenverzeichnis für andere lesbar ist.

### Behoben

- Mit Caddy ab 2.11 lehnte die Admin-API über einen Unix-Socket (Docker, neue systemd-Installation) alle
  Anfragen des Panels ab („client is not allowed to access from origin 'http://caddy-admin'“). Das Panel schickt
  über Sockets keinen Origin-Header mehr.

## v1.2.0

### Neu

- **Sentinel als OIDC-Server** (OpenID Provider) für Anwendungen, die OpenID Connect sprechen (Grafana, Nextcloud,
  Gitea/Forgejo, Proxmox, Portainer …). Anmeldung mit AD, Zugangskonten und den eingerichteten OAuth-Anbietern,
  mit zweitem Faktor (App oder Passkey), Sperren und Anmeldeprotokoll wie beim Site-Login.
  - Authorization-Code-Flow mit PKCE (S256), Discovery, JWKS, Userinfo, Token-Widerruf und Abmelden
    (RP-initiated Logout); Signatur RS256 oder ES256, Schlüsselrotation.
  - Pro Anwendung: exakte Redirect-URIs, erlaubte Gruppen/Benutzer und Anmeldemethoden, zweiter Faktor,
    Zustimmungsseite, Refresh-Tokens mit Rotation und Widerruf der ganzen Freigabe bei Wiederverwendung.
  - Die Endpunkte liegen auf einer eigenen Caddy-Site (Anmelde-Adresse); deren Policy bestimmt Anmeldemethoden,
    Netze und Ratelimits. Das Panel muss für Benutzer und Anwendungen nicht erreichbar sein.
  - Einrichtung unter *Site-Login & Konten › OIDC-Server*, Handbuch Kapitel 7.14.

### Verbessert

- Vertrauenswürdige Quellen erreichen Sentinels eigene Seiten (Anmeldung, Kontoseite, OIDC) statt des Backends.
- Wird ein OAuth-Anbieter abgeschaltet oder entfernt, enden die Site-Sitzungen seiner Konten sofort.

## v1.1.0

Produktionsreifer Stand mit umfassender Sicherheitsprüfung und überarbeiteten Diagrammen.

### Wichtig beim Update

- **Alle Site-Benutzer melden sich einmal neu an.** Sitzungen signiert jetzt das Panel (Ed25519); ältere
  Sitzungs-Cookies gelten nicht mehr. Auch Panel-Sitzungen werden nur noch als Hash gespeichert.
- **Mehrere Server: zuerst das Panel aktualisieren, dann die Agents.** Neue Agents erwarten vom Panel signierte
  Sitzungen.
- **Docker:** neue `compose.yml` übernehmen. Sie bringt ein festes Netz (`SENTINEL_NET`, Standard `172.31.77`),
  ein eigenes Volume für das Agent-Token und eines für `/var/log/caddy`. Danach beide Container neu starten.
- **Sicherungen** sind jetzt mit Passwort verschlüsselt; ältere unverschlüsselte Sicherungen lassen sich weiter
  einspielen.
- Unveränderte Werte der automatisch angelegten Standard-Policy werden einmalig angepasst (Honeypots,
  Ratelimit 1200/min). Eigene Änderungen bleiben.
- **GitHub, Google, gitlab.com, Microsoft „common“:** Benutzer- und Gruppennamen dieser Anbieter tragen jetzt die
  Anbieter-ID als Präfix (`github:meine-org`). Erlaubte Gruppen in Policies entsprechend anpassen. Ohne erlaubte
  E-Mail-Domains öffnen diese Anbieter nur noch Sites, die Gruppen/Benutzer festlegen oder den Anbieter ausdrücklich
  als Anmeldemethode auswählen. Bestehende Konten dieser Anbieter entstehen beim nächsten Login neu (2FA neu einrichten).
- Pfade mit `..;`-Segmenten, Backslash oder NUL beantwortet Sentinel mit 400.
- Leser und Support sehen Caddyfile und Konfiguration ohne Geheimnisse; eigene WAF-Einstellungen im WAF-Tester nur
  noch für Bearbeiter. Fernverwaltung „read“ kann keine Caddyfiles mehr adaptieren.

### Sicherheit

- Pfade werden vor allen Regeln normalisiert (`/a/../b`, `//b`) – Login und Pfad-Regeln lassen sich nicht mehr
  über solche Pfade umgehen.
- Eigene WAF-Regeln (auch „Nach dem CRS“) dürfen nur Regel-Direktiven enthalten; `@inspectFile` ist in Release-Builds
  nicht enthalten.
- Rollen: Leser können Caddyfiles nicht mehr über Caddy prüfen lassen; globale „vertrauenswürdige“ Einträge nur
  durch Administratoren.
- Site-Sitzungen signiert nur das Panel; jede Caddy-Instanz hat ein eigenes Geheimnis für Challenge-Cookies und
  OAuth-Starts; Benachrichtigungs-Links signiert ein Schlüssel, der das Panel nie verlässt.
- „Abmelden“ widerruft die Sitzung auf allen Instanzen; SSO-Cookies gelten höchstens so lange wie die Sitzungsdauer
  jeder einzelnen Site.
- Sentinel-Cookies und `sst_`-Zugriffstokens erreichen nie das Backend.
- Query-Strings im Protokoll werden geschwärzt (Tokens, Passwörter, OAuth-Codes, Signaturen; Reset-Links).
- „2FA zurücksetzen“ entfernt auch Wiederherstellungscodes und Passkeys; abgelaufene Konten können sich weder am
  Panel anmelden noch ihr Passwort zurücksetzen; kein lokales Passwort für OIDC-Konten.
- OIDC: E-Mail-Adressen zählen nur bestätigt (`email_verified`) als Identität bzw. für erlaubte Domains.
- Fail-closed: Lässt sich eine einschränkende Pfad-Regel oder eine blockierende WAF nicht übernehmen, antwortet die
  Policy mit 503 statt ungeschützt zu öffnen.
- Panel hinter einem Proxy: Client-IP nur aus `SENTINEL_TRUSTED_PROXIES`; Login-Sperre pro IP und pro Konto.
- Passwort-Reset-Mails nur für Hosts, die als Site in Caddy stehen (kein Host-Header-Missbrauch).
- „Als curl kopieren“ quotet alle Werte des Requests – ein präparierter Pfad wird beim Einfügen ins Terminal nicht
  mehr als Befehl ausgeführt.
- CSV-Export schützt vor Formel-Injection in Tabellenprogrammen.
- Strengere Content-Security-Policy (`base-uri`, `form-action`, `object-src`); zusätzliche systemd-Härtung des Panels.
- `update.sh` sichert und restauriert keine symbolischen Links (Schutz vor untergeschobenen Links in `/etc/caddy`)
  und schickt `GITHUB_TOKEN` nur an GitHub.
- Agent-Token für `install.sh` per `SENTINEL_AGENT_TOKEN` statt als sichtbares Argument.
- Docker: Container ohne Linux-Capabilities (Caddy nur `NET_BIND_SERVICE`), Panel mit `no-new-privileges`;
  das Panel vertraut `X-Forwarded-For` nur noch dem eigenen Caddy.
- Releases: GitHub-Actions auf Commit-SHAs festgelegt, signierter Herkunftsnachweis der Archive,
  Installationsskript aus dem Release statt aus dem Hauptzweig.
- Pfad-Regeln lassen sich nicht mehr über abweichende Auflösung im Backend umgehen: `..;` (Tomcat/Jetty), `\`
  (Windows) und NUL werden abgelehnt; einschränkende Regeln greifen auch bei anderer Groß-/Kleinschreibung und mit
  Pfad-Parametern; die ACME-Ausnahme gilt nur für echte Challenge-Token.
- Eine API-Schlüssel-Regel im Testmodus schaltet den Login nicht mehr ab.
- Identitäts-Header werden auf allen Sites und in jeder Schreibweise entfernt (`Remote_User` → FastCGI).
- Anmeldeseite folgt „nur aus freigegebenen Netzen“ und Sperren ihres Ziels; Login-CSRF über `Origin: null`
  abgewehrt; OAuth-Fehler nur als feste Texte; API-Schlüssel der Pfad-Regeln erreichen das Backend nicht;
  Referer ohne Query im Protokoll (mit Query-Bericht geschwärzt).
- WAF-Regeltext wird genau wie von Coraza zerlegt – eine Kommentarzeile mit `\` am Ende kann keine
  Engine-Direktive (z. B. `SecAuditLog`) mehr einschleusen.
- Zweiter Faktor: Konten mit Passkey oder Wiederherstellungscodes bekommen nirgends eine neue App-Einrichtung
  angeboten; Panel-2FA gilt auch bei OAuth-Anmeldung; Self-Service von OAuth-Konten nur nach frischer Anmeldung.
- Fehlversuche werden vor der Passwortprüfung gezählt (keine parallelen Rateversuche über das Limit), Login-Anfragen
  sind in Größe und Namenslänge begrenzt, unbekannte Benutzernamen kosten dieselbe Zeit.
- AD-Panelkonten verlieren Sitzungen und API-Tokens, wenn sie gesperrt oder aus den Panel-Gruppen entfernt werden
  (Prüfung alle 30 Minuten); API-Tokens externer Konten laufen nach höchstens 90 Tagen ab.
- Manuelle Sperren: höchstens /16 bzw. /32 für Nicht-Administratoren, nie die eigene Adresse oder „Nie sperren“.
- Wiederangelegte Zugangskonten erben keine alten Sitzungen; OAuth-Anmeldungen lassen sich nicht mehr durch
  massenhaft gestartete Flows abbrechen; Monitore und Feeds erreichen keine Cloud-Metadaten-Dienste.
- Die WAF hält große geprüfte Bodys nicht mehr vollständig im Speicher.

### Neu

- **Passkeys (WebAuthn)** als zweiter Faktor im Site-Login – Einrichtung beim ersten Login oder auf der Kontoseite.
- **Verschlüsselte Sicherung** (AES-256-GCM, Schlüssel per scrypt).
- **Konfliktschutz im Editor**: Übernehmen einer inzwischen geänderten Datei wird gemeldet statt überschrieben.
- **Antwortprüfung der WAF** (optional, nur melden; auch gzip/zstd) und wahlweise Ablehnung zu großer Bodys (413).
- **IPv6-Sperren** für das /64-Netz (einstellbar); „Nie sperren“ gilt auch für lokale Ratelimit-Sperren.
- **Plausibilitätswarnungen** für Einstellungen, die gespeichert sind, aber nicht wirken können.
- **Handbuch** (`docs/HANDBUCH.md`) für alle Funktionen.
- Lizenzdateien (Apache-2.0), `THIRD_PARTY_LICENSES.txt` im Release, im Docker-Image und im Panel.

### Verbessert

- Bedrohungserkennung: 404, 400, 401/403 bei GET und WAF-Treffer im Erkennungsmodus zählen je Pfad einmal in
  10 Minuten, Ratelimit-Treffer einmal pro Minute – Seiten, die dieselbe Adresse abfragen, sperren ihre Besucher
  nicht mehr.
- Standard-Policy: keine Honeypots auf Pfaden echter Anwendungen (`/wp-login.php`, `/phpmyadmin`); allgemeines
  Ratelimit 1200 Anfragen/Minute.
- Aufbewahrung der Einzel-Requests 7 Tage (vorher 3), Stunden-Aggregate mindestens 8 Tage.
- Diagramme: eine Farbe pro Bedeutung auf allen Seiten (für Farbfehlsichtigkeit geprüft, hell und dunkel),
  runde Achsenwerte, Balken mit Abstand, gebündelte Änderungs-Markierungen, Hinweis bei leerem Zeitraum.
- Übersicht: gleiche Warnungen zusammengefasst und eingeklappt, Eingriffe nach blockierend/nicht blockierend
  unterschieden, keine leeren Flächen neben Diagrammen; Sperr-Meldungen bei Angriffswellen gebündelt.
- Rollback stellt auch Caddyfile und `/etc/default/caddy-sentinel` wieder her (`--keep-config` verhindert das).
- Telemetrie: Stapel mit ID, keine Doppelzählung bei Wiederholung, begrenzte Stapelgröße.
- Installation legt `/var/log/caddy` an und verbindet Caddy automatisch mit dem Panel.

### Behoben

- 502 bei Logins hinter `reverse_proxy` (Request-Body wurde von der WAF verbraucht).
- Prüflimit der WAF unter 128 KiB ließ sich nicht speichern.
- Panel-Shutdown dauerte bis zu 15 Sekunden.
- Zahlreiche Anzeige- und Rechtefehler in der Oberfläche (Knöpfe ohne Berechtigung, falsche Links, Texte).
