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
bash <(wget -qO- https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh)
```

oder mit curl: `bash <(curl -fsSL https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh)`. Ohne root startet sich das Skript selbst mit `sudo` neu. Ohne Optionen fragt es, was installiert werden soll (alles, nur Panel, nur Caddy mit Agent) und unter welcher Adresse das Panel erreichbar sein soll.

**Derselbe Befehl aktualisiert:** Ist Caddy Sentinel schon installiert, vergleicht das Skript die Version und spielt – falls nötig – das Update über `caddy-sentinel-update` ein (Vorabprüfung, Sicherung, automatischer Rollback). Ist alles aktuell, endet es mit „aktuell“.

Woher kommen die Dateien? Jedes Release enthält neben den versionierten Archiven auch welche mit festem Namen (`caddy-sentinel_linux_amd64.tar.gz` usw.), eine `VERSION`-Datei und `SHA256SUMS`. Das Skript lädt direkt `https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/caddy-sentinel_linux_<arch>.tar.gz`, prüft die Prüfsumme und entpackt es mit `tar` – ohne GitHub-API und ohne deren Abfragelimit.

> **Eigene Domain:** Soll der Befehl `bash <(wget -qO- https://example.com/install.sh)` lauten, genügt auf dem eigenen Webserver eine Weiterleitung, z. B. in Caddy:
> `redir /install.sh https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh` – oder auf die Kopie im neuesten Release: `https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh` (passt immer zur veröffentlichten Version).

Bei einer Neuinstallation

1. lädt das passende Release (amd64, arm64 oder armv7) und prüft die SHA-256-Prüfsumme,
2. legt den Benutzer `caddy` an (falls nicht vorhanden), `/var/lib/caddy-sentinel` und bei Bedarf eine Start-Caddyfile,
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
| `--agent --panel URL --token T` | nur Caddy mit Agent für ein bestehendes Panel (siehe unten) |
| `--reinstall` | trotz vorhandener Installation neu einrichten statt aktualisieren |
| `--force` | dieselbe Version erneut einspielen |
| `--no-start` | nur installieren |
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

### Wichtige Pfade

| Pfad | Inhalt |
|---|---|
| `/etc/caddy/Caddyfile`, `/etc/caddy/sites/*.caddy` | Caddy-Konfiguration (vom Panel bearbeitet) |
| `/var/lib/caddy-sentinel/` | Datenbank `sentinel.db`, Agent-Token |
| `/etc/default/caddy-sentinel` | Einstellungen des Panels (Adresse, Pfade) |
| `/var/lib/caddy/.local/share/caddy` | Zertifikate und interne CA von Caddy |
| `/var/backups/caddy-sentinel/` | Sicherungen der letzten 5 Updates |

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
4. Panel tauschen und prüfen, dann Caddy tauschen und neu starten (kurze Unterbrechung von etwa einer Sekunde),
5. startet etwas nicht, wird **automatisch** die vorherige Version zurückgespielt.

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

Caddyfile und Zertifikate bleiben immer erhalten. Vorher die Direktive `sentinel` aus der Caddyfile entfernen, wenn danach ein Standard-Caddy laufen soll.

### Weitere Caddy-Server anbinden

Ein Panel kann mehrere Caddy-Server verwalten. Im Panel unter **Caddy-Instanzen › Instanz hinzufügen** Name und Farbe wählen, dann auf dem neuen Server:

```bash
bash <(wget -qO- https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh) \
  --agent --panel https://sentinel.example.com --token <TOKEN> --remote full
```

Das installiert nur Caddy mit Sentinel-Modul, legt das Token in `/etc/caddy/sentinel-agent.token` ab und verbindet den Server mit dem Panel. Die Verbindung geht immer vom Server zum Panel – dort muss kein Port offen sein, das Panel muss aber vom Server erreichbar sein.

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
- `ghcr.io/b1tk1ll3r/caddy-sentinel-panel` – Panel (enthält zusätzlich `caddy` für „Vollständig prüfen“ und „Formatieren“)

```bash
mkdir caddy-sentinel && cd caddy-sentinel
curl -fsSLO https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/deploy/docker/compose.yml
docker compose up -d
```

Panel: `http://127.0.0.1:7600` (nur auf dem Docker-Host; per SSH-Tunnel oder als Site in der Caddyfile veröffentlichen, siehe oben – im Container heißt das Ziel `reverse_proxy panel:7600`).

Aufbau:

| Volume | Caddy | Panel | Zweck |
|---|---|---|---|
| `caddy-etc` | `/etc/caddy` | `/etc/caddy` | Caddyfile, vom Panel bearbeitet |
| `caddy-admin` | `/run/caddy` | `/run/caddy` | Admin-API als Unix-Socket – kein offener Port |
| `caddy-data` | `/data` | `/caddy-data` (nur lesend) | Zertifikate, interne CA |
| `sentinel-data` | – | `/var/lib/caddy-sentinel` | Datenbank des Panels |
| `sentinel-token` | `/run/sentinel-token` (nur lesend) | `/run/sentinel-token` | nur das Agent-Token – Caddy sieht die Datenbank nicht |

Beide Container laufen als Benutzer `1000:1000`, Caddy darf trotzdem Port 80/443 öffnen (`cap_net_bind_service`). Beim ersten Start wird eine Standard-Caddyfile angelegt; sie enthält `admin unix//run/caddy/admin.sock` – diese Zeile muss bleiben, damit das Panel Caddy steuern kann.

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
# Argumente: --build-arg CADDY_VERSION=latest --build-arg UPGRADE_WAF=1 --build-arg VERSION=v1.2.0
```

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

- **CI** (`.github/workflows/ci.yml`): bei jedem Push und Pull Request – Formatierung, `go vet`, Tests (mit Race-Detector), JavaScript-Syntax, Shell-Skripte und ein Test-Build.
- **Release** (`.github/workflows/release.yml`): ein Tag `v*` startet den Build für amd64, arm64 und armv7 (statische Binaries, Cross-Compiler für das Panel), erstellt das GitHub-Release mit Archiven und `SHA256SUMS` und veröffentlicht beide Docker-Images (Tags `1.2.3`, `1.2`, `latest`; Pre-Releases wie `v1.3.0-rc.1` ohne `latest`).

```bash
git tag v1.2.0
git push origin v1.2.0
```

Standardmäßig baut das Release gegen die **neueste Caddy-Version** und die neuesten Coraza/CRS-Versionen. Anpassen:

- dauerhaft: Repository-Variable `CADDY_VERSION` (Settings › Secrets and variables › Actions › Variables), z. B. `v2.11.2`,
- einmalig: Actions › Release › „Run workflow“ mit Tag und gewünschter Caddy-Version – praktisch, um nach einem Caddy-Sicherheitsupdate neu zu bauen.

Einmalig nach dem ersten Release: unter *Packages* die beiden Images auf **Public** stellen, sonst brauchen Docker-Hosts ein Login für ghcr.io.
