# Installation & Update

Caddy Sentinel besteht aus zwei Programmen:

| Datei | Aufgabe |
|---|---|
| `caddy` | Caddy mit eingebautem Sentinel-Modul (Agent): setzt Regeln, Sperren, WAF und Anmeldung durch |
| `caddy-sentinel` | Panel: Weboberfläche, Datenbank, IDS, Verbindung zum Active Directory |

Es gibt drei Wege: **systemd** (empfohlen für Server), **Docker Compose** und **selbst bauen**.

---

## 1. systemd (Debian, Ubuntu, RHEL, Raspberry Pi OS …)

### Installation

```bash
bash <(wget -qO- https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh)
```

oder mit curl: `bash <(curl -fsSL https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh)`. Ohne root startet sich das Skript selbst mit `sudo` neu. Ohne Optionen fragt es, was installiert werden soll (alles, nur Panel, nur Caddy mit Agent) und unter welcher Adresse das Panel erreichbar sein soll.

**Derselbe Befehl aktualisiert:** Ist Caddy Sentinel schon installiert, vergleicht das Skript die Version und spielt – falls nötig – das Update über `caddy-sentinel-update` ein (Vorabprüfung, Sicherung, automatischer Rollback). Ist alles aktuell, endet es mit „aktuell“.

Woher kommen die Dateien? Jedes Release enthält neben den versionierten Archiven auch welche mit festem Namen (`caddy-sentinel_linux_amd64.tar.gz` usw.), eine `VERSION`-Datei, `SHA256SUMS` und deren Signatur `SHA256SUMS.sig`. Das Skript lädt direkt `https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/caddy-sentinel_linux_<arch>.tar.gz`, prüft Signatur und Prüfsumme und entpackt es mit `tar` – ohne GitHub-API und ohne deren Abfragelimit.

**Signierte Prüfsummen:** Die Release-Action signiert `SHA256SUMS` mit einem SSH-Schlüssel (`ssh-keygen -Y sign`). `install.sh` und `caddy-sentinel-update` enthalten den öffentlichen Schlüssel (`RELEASE_SIGNING_PUBKEY`) und prüfen mit `ssh-keygen -Y verify` – OpenSSH ist auf praktisch jedem Server vorhanden, weitere Werkzeuge braucht es nicht. Ist ein Schlüssel hinterlegt, ist eine gültige Signatur **Pflicht**: fehlt `SHA256SUMS.sig` oder passt sie nicht, bricht das Skript ab (auch bei einem Spiegel über `SENTINEL_DOWNLOAD` – der muss `SHA256SUMS.sig` mit ausliefern). Nur in einem Notfall und bei vertrauenswürdiger Quelle: `--skip-signature` bzw. `SENTINEL_SKIP_SIGNATURE=1`. Den Schlüssel merkt sich die Installation zusätzlich in `/usr/local/share/caddy-sentinel/release-signing.pub`; so bleibt die Prüfung Pflicht, auch wenn später ein Skript ohne Schlüssel auftaucht. Meldet die `VERSION`-Datei (unsigniert) eine ältere als die installierte Version, bricht `caddy-sentinel-update` ab – ein älteres, gültig signiertes Release lässt sich so nicht unterschieben; zurück nur mit ausdrücklichem `--version`. Was die Signatur nicht abdeckt: Den ersten Aufruf von `bash <(wget …/install.sh)` schützt sie nur, wenn du `install.sh` vorher selbst prüfst (siehe „Herkunft prüfen“); Updates prüft das bereits installierte `caddy-sentinel-update` mit seinem eingebauten Schlüssel.

> **Eigene Domain:** Soll der Befehl `bash <(wget -qO- https://example.com/install.sh)` lauten, genügt auf dem eigenen Webserver eine Weiterleitung, z. B. in Caddy:
> `redir /install.sh https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh` – das Skript kommt so immer aus dem neuesten Release und passt zur veröffentlichten Version.
>
> **Herkunft prüfen:** Jedes Release enthält `SHA256SUMS` und einen signierten Herkunftsnachweis (GitHub Artifact Attestation). `SHA256SUMS` liegt neben den Archiven und schützt nur vor Übertragungsfehlern, nicht vor einem ausgetauschten Release oder Spiegel. Wer sichergehen will, lädt das Skript herunter und prüft es vor dem Ausführen: `gh attestation verify install.sh --repo b1tk1ll3r/caddy-sentinel`. Mit `--verify-attestation` (oder `SENTINEL_VERIFY_ATTESTATION=1`) prüfen `install.sh` und `caddy-sentinel-update` zusätzlich jedes heruntergeladene Archiv mit `gh attestation verify` und brechen ab, wenn der Nachweis fehlt oder nicht passt – auch beim Download über einen Spiegel (`SENTINEL_DOWNLOAD`). Voraussetzung: die GitHub-CLI `gh` mit Anmeldung (`gh auth login` oder `GH_TOKEN`, bei `sudo` als root).

Bei einer Neuinstallation

1. lädt das passende Release (amd64, arm64 oder armv7) und prüft die SHA-256-Prüfsumme,
2. legt die Systembenutzer `caddy` (für Caddy, falls nicht vorhanden) und `caddy-sentinel` (für das Panel, ohne Login, Zusatzgruppe `caddy`) an, dazu `/var/lib/caddy-sentinel` (siehe [Benutzer und Rechte](#benutzer-und-rechte)) und bei Bedarf eine Start-Caddyfile,
3. installiert `caddy` und `caddy-sentinel` nach `/usr/local/bin` (ein vorhandenes, fremdes `/usr/local/bin/caddy` wird als `caddy.orig` gesichert),
4. richtet `caddy-sentinel.service` ein und hängt einen Override an `caddy.service` an, damit Caddy mit dem Sentinel-Build startet – ein Caddy aus dem Distributionspaket bleibt installiert und wird beim Deinstallieren wieder aktiv,
5. startet Panel und Caddy und prüft, ob beide laufen.

Optionen werden hinten angehängt, z. B. `bash <(wget -qO- …/install.sh) --version v1.2.0`:

| Option | Bedeutung |
|---|---|
| `--version v1.2.0` | bestimmte Version |
| `--listen 0.0.0.0:7600` | Adresse des Panels (Standard `127.0.0.1:7600`) |
| `--panel-only` | nur das Panel (Caddy läuft auf einem anderen Host) |
| `--dir PFAD` | Binaries aus einem Verzeichnis statt Download |
| `--agent --panel URL` (Token in `SENTINEL_AGENT_TOKEN`, alternativ `--token T`) | nur Caddy mit Agent für ein bestehendes Panel (siehe unten) |
| `--reinstall` | trotz vorhandener Installation neu einrichten statt aktualisieren |
| `--force` | dieselbe Version erneut einspielen |
| `--no-start` | nur installieren |
| `--verify-attestation` | Herkunftsnachweis des Archivs mit `gh` prüfen (siehe oben) |
| `--skip-signature` | Signatur der Prüfsummen nicht prüfen – nur im Notfall (siehe oben) |
| `-y` | keine Rückfragen |

Ohne Internetzugang: Release-Archiv `caddy-sentinel_<version>_linux_<arch>.tar.gz` herunterladen, auf den Server kopieren, entpacken und darin `sudo ./install.sh` ausführen.

### Panel aufrufen

Das Panel lauscht standardmäßig nur lokal. Vom eigenen Rechner per SSH-Tunnel:

```bash
ssh -L 7600:127.0.0.1:7600 benutzer@server
# dann http://127.0.0.1:7600 öffnen
```

Dauerhaft über HTTPS veröffentlichen – eine Site in der Caddyfile genügt, das Panel hat eine eigene Anmeldung (auf Wunsch mit AD und 2FA):

```caddyfile
sentinel.example.com {
	sentinel
	reverse_proxy 127.0.0.1:7600
}
```

Beim ersten Aufruf legst du das Administratorkonto an.

### Benutzer und Rechte

Panel und Caddy laufen unter **getrennten Systembenutzern**. Caddy verarbeitet Verkehr aus dem Internet; wer Caddy übernimmt – oder als Bearbeiter im Panel eine Caddyfile mit `file_server` auf das Panel-Verzeichnis schreibt –, kommt trotzdem nicht an die Datenbank des Panels (Passwort-Hashes, TOTP-Geheimnisse, Sitzungen, API-Tokens, SMTP-/LDAP-/OAuth-Geheimnisse, Tokens aller Instanzen). Umgekehrt kann das Panel Caddys private Schlüssel nicht lesen.

| Benutzer | Dienst | Darf |
|---|---|---|
| `caddy` | `caddy.service` | eigenes Datenverzeichnis (Zertifikate, Schlüssel), `/var/log/caddy`; vom Panel nur Agent-Token und Prüf-Kopien lesen |
| `caddy-sentinel` (ohne Login, Zusatzgruppe `caddy`) | `caddy-sentinel.service` | eigene Datenbank; `/etc/caddy` schreiben (über die Gruppe); Admin-API von Caddy über `/run/caddy/admin.sock` (Gruppe); `caddy validate` |

| Pfad | Besitzer, Rechte | Inhalt |
|---|---|---|
| `/var/lib/caddy-sentinel/` | `caddy-sentinel:caddy` `2750` | gemeinsamer Teil, für Caddy lesbar |
| `…/agent.token` | `caddy-sentinel:caddy` `0640` | Token der lokalen Instanz (`SENTINEL_TOKEN_FILE`); Caddy findet es ohne Angabe |
| `…/staging/` | `caddy-sentinel:caddy` `2750` | Prüf-Kopien beim Bearbeiten (`SENTINEL_STAGING`), Caddy liest eingebundene Dateien beim Prüfen |
| `…/geo/` (optional) | `caddy-sentinel:caddy`, gruppenlesbar | GeoIP-Datenbanken, liest auch Caddy |
| `…/data/` | `caddy-sentinel:caddy-sentinel` `0700` | **Datenbank** `sentinel.db`, Zertifikats-Spiegel (`SENTINEL_DATA`) – nur das Panel |
| `/etc/caddy/` | `root:caddy` `2775` (setgid) | Caddyfile und Imports; das Panel schreibt über die Gruppe, neue Dateien gehören zur Gruppe `caddy` |
| `/var/lib/caddy/.local/share/caddy` | `caddy`, `0700` | Zertifikate, private Schlüssel, interne CA – nur Caddy |
| `/run/caddy/admin.sock` | `caddy:caddy` `0660` in `/run/caddy` (`0750`) | Admin-API von Caddy – nur Caddy und das Panel |

**Admin-API nur als Unix-Socket.** Standardmäßig lauscht Caddys Admin-API auf `localhost:2019` – dort könnte jeder lokale Prozess (jeder Benutzer, jeder Dienst) Caddy eine neue Konfiguration geben, etwa eine, die Dateien ausliefert. Die Ergänzung der Caddy-Unit setzt deshalb `CADDY_ADMIN=unix//run/caddy/admin.sock|0660` und `RuntimeDirectory=caddy` (`0750`): Die API ist nur noch für Caddy und die Gruppe `caddy` (also das Panel) erreichbar, Port 2019 ist zu. `CADDY_ADMIN` gilt, solange die Caddyfile keine globale Option `admin` setzt; steht dort eine, hat sie Vorrang – Installation und Update lassen sie stehen, warnen und belassen `SENTINEL_CADDY_ADMIN` (bitte selbst passend halten oder die Zeile entfernen). `systemctl reload caddy` (`caddy reload` als Benutzer `caddy`) und `caddy stop` in der Unit nutzen den Socket automatisch. Von Hand als root:

```bash
caddy reload --config /etc/caddy/Caddyfile --address 'unix//run/caddy/admin.sock'
curl --unix-socket /run/caddy/admin.sock http://localhost/config/
```

Ältere Installationen stellt das Update um (Ergänzung der Unit, `SENTINEL_CADDY_ADMIN=unix//run/caddy/admin.sock`, Neustart von Caddy); ein Rollback stellt `localhost:2019` wieder her. Auf Agent-Servern (`--agent`) gilt dasselbe ohne Panel; steht im `sentinel`-Block der Caddyfile ein festes `admin http://…`, bleibt die API auf TCP (Warnung), damit die Fernverwaltung weiter funktioniert – die Zeile entfernen, dann übernimmt der Agent Caddys Admin-Adresse selbst.

**Zertifikatsüberwachung** und die Ansicht der internen CA lesen Caddys Datenverzeichnis deshalb nicht direkt: Der Sentinel-Agent in Caddy liefert die öffentlichen Teile (Zertifikate, CA-Zertifikate, ACME-Datenbank – nie private Schlüssel) an das Panel, das sie in `data/mirror/local` spiegelt – derselbe Weg wie bei weiteren Caddy-Servern. Kann das Panel das unter *Einstellungen › Zertifikate* eingestellte Verzeichnis selbst lesen (Docker mit eingehängtem Volume, ältere Installationen), liest es direkt.

**„Vollständig prüfen“** (`caddy validate`) läuft als `caddy-sentinel` mit der von Caddy übersetzten Konfiguration. Was nur Caddy öffnen darf, lässt die Prüfung aus und nennt es im Ergebnis: Log-Dateien (`log { output file … }`) schreiben in ein Arbeitsverzeichnis des Panels, der Speicher (`storage file_system`) ebenso, und Zertifikatsdateien, deren Schlüssel das Panel nicht lesen darf (`tls cert.pem key.pem`), werden nicht geladen. Fehlende Dateien meldet die Prüfung weiterhin. Beim Übernehmen prüft Caddy diese Teile selbst; schlägt das Laden fehl, stellt das Panel die vorherige Fassung wieder her.

Ältere Installationen (Panel und Caddy beide als `caddy`, Datenbank direkt in `/var/lib/caddy-sentinel`) stellt `caddy-sentinel-update` bzw. der Installationsbefehl automatisch um, siehe [Update](#update).

### Wichtige Pfade

| Pfad | Inhalt |
|---|---|
| `/etc/caddy/Caddyfile`, `/etc/caddy/sites/*.caddy` | Caddy-Konfiguration (vom Panel bearbeitet) |
| `/var/lib/caddy-sentinel/data/` | Datenbank `sentinel.db` (nur für das Panel lesbar) |
| `/var/lib/caddy-sentinel/agent.token` | Agent-Token der lokalen Instanz |
| `/etc/default/caddy-sentinel` | Einstellungen des Panels (Adresse, Pfade) |
| `/var/lib/caddy/.local/share/caddy` | Zertifikate und interne CA von Caddy (nur für Caddy lesbar) |
| `/var/backups/caddy-sentinel/` | Sicherungen der letzten 5 Updates (Programme, Caddyfile, Einstellungen; die Datenbank nur in den letzten 2), dazu `Caddyfile.vor-sentinel-<Zeit>` und `vor-rollback-<Zeit>/` – nur für root |

### Update

```bash
sudo caddy-sentinel-update --check   # nur prüfen
sudo caddy-sentinel-update           # auf die neueste Version
sudo caddy-sentinel-update --version v1.3.0
```

Ablauf:

1. Download und Prüfsumme,
2. **Vorabprüfung**: die vorhandene Caddyfile wird mit dem *neuen* Caddy validiert – ist sie ungültig (z. B. wegen einer entfernten Option in einer neuen Caddy-Version), bricht das Update ab, ohne etwas zu ändern,
3. Sicherung von Binaries, Datenbank, Units und Caddyfile nach `/var/backups/caddy-sentinel/<datum>-<version>/`,
4. Benutzer, Verzeichnisse und Rechte prüfen und bei Bedarf umstellen (siehe unten),
5. Panel tauschen und prüfen, dann Caddy tauschen und neu starten (kurze Unterbrechung von etwa einer Sekunde),
6. startet etwas nicht, wird **automatisch** die vorherige Version zurückgespielt – samt Benutzern, Rechten und Lage der Datenbank.

**Umstellung älterer Installationen auf den eigenen Panel-Benutzer** (einmalig, automatisch): Läuft das Panel noch als `caddy`, legt das Update den Benutzer `caddy-sentinel` an, verschiebt die Datenbank nach `/var/lib/caddy-sentinel/data/` (`0700`), setzt Besitz und Rechte (Token und Prüf-Kopien für die Gruppe `caddy` lesbar, `/etc/caddy` setgid), trägt `SENTINEL_DATA`, `SENTINEL_TOKEN_FILE` und `SENTINEL_STAGING` in `/etc/default/caddy-sentinel` ein und aktualisiert die Units. Agent-Token und GeoIP-Dateien bleiben, wo sie sind; Caddyfiles mit `token_file /var/lib/caddy-sentinel/agent.token` gelten unverändert. Die Umstellung ist idempotent – jedes Update prüft die Rechte erneut. `--rollback` auf eine ältere Version stellt den alten Zustand wieder her (Datenbank zurück, Panel wieder als `caddy`, Benutzer `caddy-sentinel` entfernt).

> Wer noch ein älteres `caddy-sentinel-update` hat, aktualisiert damit zunächst nur die Programme (das Panel läuft weiter als `caddy` und schreibt eine Warnung ins Log). Ein zweiter Aufruf von `sudo caddy-sentinel-update` – dann bereits das neue Skript – stellt um, auch wenn die Version schon aktuell ist. Der Installationsbefehl (`bash <(wget …/install.sh)`) stellt sofort um. `sudo caddy-sentinel-update --check` zeigt an, ob die Umstellung noch aussteht.

Manuell zurück:

```bash
sudo caddy-sentinel-update --rollback            # Programme der vorherigen Version
sudo caddy-sentinel-update --rollback --with-db  # zusätzlich die Datenbank von damals
```

Das Panel zeigt unten in der Seitenleiste an, wenn ein neues Release verfügbar ist (Abfrage bei GitHub alle 6 Stunden, abschaltbar mit `SENTINEL_UPDATE_CHECK=0` in `/etc/default/caddy-sentinel`). Aktualisieren muss trotzdem root – das Panel läuft bewusst ohne Rechte.

Automatische Updates (z. B. jeden Sonntag 4 Uhr) per systemd-Timer:

```ini
# /etc/systemd/system/caddy-sentinel-update.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/caddy-sentinel-update --yes

# /etc/systemd/system/caddy-sentinel-update.timer
[Timer]
OnCalendar=Sun *-*-* 04:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now caddy-sentinel-update.timer
```

### Deinstallation

```bash
sudo caddy-sentinel-uninstall           # Programme weg, Daten bleiben
sudo caddy-sentinel-uninstall --purge   # auch Datenbank und Sicherungen
```

Der Benutzer `caddy-sentinel` wird entfernt; behaltene Daten gehören danach `root` (nur root lesbar), eine spätere Neuinstallation übernimmt sie wieder. Caddyfile und Zertifikate bleiben immer erhalten. Vorher die Direktive `sentinel` aus der Caddyfile entfernen, wenn danach ein Standard-Caddy laufen soll.

### Weitere Caddy-Server anbinden

Ein Panel kann mehrere Caddy-Server verwalten. Im Panel unter **Caddy-Instanzen › Instanz hinzufügen** Name und Farbe wählen, dann auf dem neuen Server:

```bash
SENTINEL_AGENT_TOKEN='<TOKEN>' bash <(wget -qO- https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh) \
  --agent --panel https://sentinel.example.com --remote full
```

Das installiert nur Caddy mit Sentinel-Modul (kein Panel, kein Benutzer `caddy-sentinel`), legt das Token in `/etc/caddy/sentinel-agent.token` ab (`root:caddy`, `0640`) und verbindet den Server mit dem Panel. Die Verbindung geht immer vom Server zum Panel – dort muss kein Port offen sein, das Panel muss aber vom Server erreichbar sein.

| `--remote` | Was das Panel darf |
|---|---|
| `full` (Standard) | Caddyfile lesen, bearbeiten, prüfen (`caddy validate`) und laden; laufende Konfiguration, Backends, Zertifikate (ohne private Schlüssel) |
| `read` | nur lesen: laufende Konfiguration, Backends, Zertifikate |
| `off` | nur Schutz und Telemetrie, kein Zugriff auf die Konfiguration |

Bei einem vorhandenen Caddy mit Sentinel-Modul reicht stattdessen ein Block in den globalen Optionen:

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

Für `remote full` braucht der Benutzer, unter dem Caddy läuft, Schreibrechte auf das Konfigurationsverzeichnis (bei systemd mit `ProtectSystem` zusätzlich `ReadWritePaths=/etc/caddy`; das Installationsskript setzt das).

---

## 2. Docker Compose

Zwei Images auf GitHub Container Registry (amd64, arm64, armv7):

- `ghcr.io/b1tk1ll3r/caddy-sentinel` – Caddy mit Sentinel-Modul
- `ghcr.io/b1tk1ll3r/caddy-sentinel-panel` – Panel (enthält zusätzlich `caddy` für „Vollständig prüfen“)

Panel und Caddy laufen in getrennten Containern und sehen nur die Volumes, die sie brauchen (Tabelle unten): Caddy sieht weder die Datenbank noch das Panel-Volume, das Panel weder Caddys Zertifikats-Volume (private Schlüssel) noch die Logs.

```bash
mkdir caddy-sentinel && cd caddy-sentinel
curl -fsSLO https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/deploy/docker/compose.yml
docker compose up -d
```

Panel: `http://127.0.0.1:7600` (nur auf dem Docker-Host; per SSH-Tunnel oder als Site in der Caddyfile veröffentlichen, siehe oben – im Container heißt das Ziel `reverse_proxy panel:7600`).

Aufbau:

| Volume | Caddy | Panel | Zweck |
|---|---|---|---|
| `caddy-etc` | `/etc/caddy` (nur lesend) | `/etc/caddy` | Caddyfile, vom Panel bearbeitet |
| `caddy-admin` | `/run/caddy` | `/run/caddy` (nur lesend) | Admin-API als Unix-Socket – kein offener Port; das Panel verbindet sich nur |
| `sentinel-staging` | `/run/sentinel-staging` (nur lesend) | `/run/sentinel-staging` | Prüf-Kopien beim Bearbeiten (`SENTINEL_STAGING`) – nur das Panel schreibt |
| `caddy-data` | `/data` | – | Zertifikate, private Schlüssel, interne CA (das Panel bekommt die öffentlichen Teile über den Agenten) |
| `caddy-logs` | `/var/log/caddy` | – | Zugriffs-Logs aus `log { output file … }` |
| `sentinel-data` | – | `/var/lib/caddy-sentinel` | Datenbank des Panels |
| `sentinel-token` | `/run/sentinel-token` (nur lesend) | `/run/sentinel-token` | nur das Agent-Token – Caddy sieht die Datenbank nicht |

Beide Container laufen als Benutzer `1000:1000`, Caddy darf trotzdem Port 80/443 öffnen (`cap_net_bind_service`). Das Panel übernimmt `X-Forwarded-For` nur von Caddy (`.10` im festen Netz); Zugriffe über den veröffentlichten Port `127.0.0.1:7600` zählen mit der Adresse des Docker-Gateways – so kann niemand über diesen Port eine fremde Client-IP vortäuschen und die Anmeldesperre pro IP umgehen.

Beim ersten Start wird eine Standard-Caddyfile angelegt; sie enthält `admin unix//run/caddy/admin.sock` – diese Zeile muss bleiben, damit das Panel Caddy steuern kann.

Ein übernommener Caddy-Container kann dem Panel nichts unterschieben: Caddyfile (`caddy-etc`) und Prüf-Kopien (`sentinel-staging`) hängen bei Caddy nur lesend, das Panel sieht das Admin-Socket-Volume nur lesend und weder Caddys Zertifikate noch dessen Logs.

> **Ältere compose.yml:** Bis v1.2 hängte das Panel `caddy-data` (nur lesend) und `caddy-logs` ein, vertraute zusätzlich dem Gateway `.1` und legte die Prüf-Kopien in `caddy-admin` ab (für Caddy beschreibbar). Beim Update die neue compose.yml übernehmen – zusammen mit Images derselben Version (das Verzeichnis `/run/sentinel-staging` legen erst die neuen Images an); die Volumes bleiben erhalten.

> **Basis-Images:** Die Dockerfiles nutzen `golang:<version>-alpine` und `alpine:3.22` über Tags, nicht über Digests (`@sha256:…`). Digests lassen sich nur mit Zugriff auf die Registry ermitteln und müssten bei jedem Alpine-Sicherheitsupdate nachgezogen werden (sonst bleiben behobene Lücken im Image); dafür wäre ein automatisches Update (z. B. Dependabot/Renovate für Dockerfiles) nötig. Wer reproduzierbar bauen will, setzt die Digests selbst ein und aktualisiert sie regelmäßig. Die eigenen Images tragen noch keine Signatur – zum Festschreiben `SENTINEL_VERSION` auf eine feste Version setzen.

Upstreams in anderen Containern erreichst du über deren Servicenamen, z. B. `reverse_proxy nextcloud:80` – dafür die Container ins selbe Netzwerk hängen (`networks:` in der compose.yml).

GeoIP-Datenbanken: Verzeichnis einhängen (`./geo:/geo:ro` bei **beiden** Diensten) und im Panel `/geo/country.mmdb` bzw. `/geo/asn.mmdb` eintragen.

### Update mit Docker

```bash
docker compose pull
docker compose up -d
```

Version festnageln: in einer `.env` neben der compose.yml `SENTINEL_VERSION=1.2.0` setzen. Zurück auf eine ältere Version: Tag dort ändern und `docker compose up -d`. Vor größeren Sprüngen sichern:

```bash
docker compose stop panel
docker run --rm -v caddy-sentinel_sentinel-data:/d -v "$PWD":/b alpine tar czf /b/sentinel-data.tgz -C /d .
docker compose start panel
```

### Images selbst bauen

```bash
git clone https://github.com/b1tk1ll3r/caddy-sentinel && cd caddy-sentinel
docker build -f deploy/docker/Dockerfile --target caddy -t caddy-sentinel .
docker build -f deploy/docker/Dockerfile --target panel -t caddy-sentinel-panel .
# Argumente: --build-arg VERSION=v1.2.0
#   Standard: CADDY_VERSION=latest und UPGRADE_WAF=1 (neueste Caddy-, Coraza- und CRS-Version);
#   exakt aus go.mod: --build-arg CADDY_VERSION= --build-arg UPGRADE_WAF=0
```

Standard sind die neuesten Versionen, weil die in `go.mod` hinterlegte Caddy-Version (v2.10.0) bekannte Schwachstellen hat. Panel und Caddy bekommen dabei immer dieselben Versionen.

In der compose.yml dann `image:` durch die eigenen Namen ersetzen (oder die auskommentierten `build:`-Zeilen nutzen).

---

## 3. Selbst bauen

Voraussetzung: Go (für aktuelles Caddy mindestens die Version, die Caddy verlangt), gcc (das Panel nutzt SQLite über CGO).

```bash
./build.sh                       # dist/caddy + dist/caddy-sentinel, neueste Caddy-Version
PINNED=1 ./build.sh              # exakt die Versionen aus go.mod
sudo ./deploy/install.sh         # installiert den lokalen Build
```

Statische Release-Archive wie in der CI:

```bash
./scripts/build-release.sh                                   # aktuelle Architektur
ARCH=arm64 CC=aarch64-linux-gnu-gcc ./scripts/build-release.sh
ARCH=armv7 CC=arm-linux-gnueabihf-gcc ./scripts/build-release.sh
```

Nur das Caddy-Modul in einen eigenen Build (z. B. mit weiteren Plugins) – mit [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/b1tk1ll3r/caddy-sentinel/sentinel
```

---

## 4. Releases veröffentlichen (GitHub Actions)

- **CI** (`.github/workflows/ci.yml`): bei jedem Push und Pull Request – Formatierung, `go vet`, Tests (mit Race-Detector), JavaScript-Syntax, Shell-Skripte und ein Test-Build; dazu `govulncheck` für `sentinel`, `caddy` und `panel` mit den neuesten Caddy-/Coraza-/CRS-Versionen (scheitert bei erreichbaren bekannten Schwachstellen) und als Hinweis mit den Versionen aus `go.mod`.
- **Release** (`.github/workflows/release.yml`): der Job `resolve` löst die Versionen auf, testet und prüft sie mit `govulncheck` – meldet es eine erreichbare Schwachstelle, wird nichts gebaut und nichts veröffentlicht. Danach startet der Build für amd64, arm64 und armv7 (statische Binaries, Cross-Compiler für das Panel), erstellt das GitHub-Release mit Archiven, `SHA256SUMS` und – mit dem Secret `RELEASE_SIGNING_KEY` – `SHA256SUMS.sig` und veröffentlicht beide Docker-Images (Tags `1.2.3`, `1.2`, `latest`; Pre-Releases wie `v1.3.0-rc.1` ohne `latest`).

```bash
git tag v1.2.0
git push origin v1.2.0
```

Standardmäßig baut das Release gegen die **neueste Caddy-Version** und die neuesten Coraza/CRS-Versionen. Anpassen:

- dauerhaft: Repository-Variable `CADDY_VERSION` (Settings › Secrets and variables › Actions › Variables), z. B. `v2.11.2`,
- einmalig: Actions › Release › „Run workflow“ mit Tag und gewünschter Caddy-Version – praktisch, um nach einem Caddy-Sicherheitsupdate neu zu bauen.

Einmalig nach dem ersten Release: unter *Packages* die beiden Images auf **Public** stellen, sonst brauchen Docker-Hosts ein Login für ghcr.io.

### Signaturschlüssel für Releases einrichten (einmalig)

Ohne Schlüssel bleiben Releases unsigniert und die Skripte prüfen nur die Prüfsumme. So richtest du die Signatur ein (als Repository-Inhaber `b1tk1ll3r`, auf einem vertrauenswürdigen Rechner):

```bash
# 1. Schlüsselpaar erzeugen (ed25519, ohne Passphrase – die Action signiert unbeaufsichtigt)
ssh-keygen -t ed25519 -N '' -C caddy-sentinel-release -f caddy-sentinel-release

# 2. privaten Schlüssel als Actions-Secret hinterlegen (oder im Browser: Settings › Secrets and
#    variables › Actions › New repository secret, Name RELEASE_SIGNING_KEY, Inhalt der Datei)
gh secret set RELEASE_SIGNING_KEY --repo b1tk1ll3r/caddy-sentinel < caddy-sentinel-release

# 3. öffentlichen Schlüssel ins Repository und in beide Skripte eintragen
cp caddy-sentinel-release.pub scripts/release-signing.pub
key=$(cat scripts/release-signing.pub)
sed -i "s|^RELEASE_SIGNING_PUBKEY=.*|RELEASE_SIGNING_PUBKEY='$key'|" scripts/install.sh scripts/update.sh
git add scripts/release-signing.pub scripts/install.sh scripts/update.sh && git commit -m "Release-Signaturschlüssel"

# 4. privaten Schlüssel offline sichern (z. B. Passwort-Manager) und hier löschen
shred -u caddy-sentinel-release
```

Ab dem nächsten Tag signiert die Release-Action `SHA256SUMS` und prüft die Signatur gleich gegen den Schlüssel in `update.sh`. Fehlt das Secret, obwohl die Skripte einen Schlüssel enthalten, bricht das Release ab – sonst würden alle Updates an der fehlenden Signatur scheitern. Die CI prüft, dass `install.sh`, `update.sh` und `scripts/release-signing.pub` denselben Schlüssel enthalten.

Selbst prüfen: `printf 'caddy-sentinel-release namespaces="caddy-sentinel-release" %s\n' "$(cat scripts/release-signing.pub)" > allowed_signers` und `ssh-keygen -Y verify -f allowed_signers -I caddy-sentinel-release -n caddy-sentinel-release -s SHA256SUMS.sig < SHA256SUMS`.

**Schlüssel wechseln:** Updates prüft immer das bereits installierte Skript. Deshalb erst ein Release mit **beiden** öffentlichen Schlüsseln veröffentlichen (je eine Zeile in `RELEASE_SIGNING_PUBKEY` und `scripts/release-signing.pub`, noch mit dem alten Schlüssel signiert), danach das Secret auf den neuen Schlüssel umstellen und den alten aus den Skripten entfernen. Ist der private Schlüssel kompromittiert: Secret sofort ersetzen, neues Release mit nur dem neuen Schlüssel – bestehende Installationen müssen dann einmal mit dem neuen `install.sh` (vorher mit `gh attestation verify` geprüft) aktualisiert werden.

