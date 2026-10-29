// Caddyfile knowledge base used for autocomplete, hover docs and the reference panel.
// Format: name -> { s: syntax, d: description, sub: { name: [syntax, description] }, snip: snippet }
// ${1:x} in snippets marks tab stops (the editor jumps to the first one).

const D = 'https://caddyserver.com/docs/caddyfile/directives/';
const G = 'https://caddyserver.com/docs/caddyfile/options';

export const GLOBAL = {
  debug: { s: 'debug', d: 'Aktiviert Debug-Logging für den Standard-Logger.' },
  http_port: { s: 'http_port <port>', d: 'Port für HTTP (Standard 80). Für automatische HTTP→HTTPS-Weiterleitungen relevant.' },
  https_port: { s: 'https_port <port>', d: 'Port für HTTPS (Standard 443).' },
  default_bind: { s: 'default_bind <hosts...>', d: 'Standard-Bind-Adresse(n) für alle Sites, z. B. nur IPv4 oder eine bestimmte Schnittstelle.' },
  order: { s: 'order <dir1> first|last|[before|after <dir2>]', d: 'Ändert die Reihenfolge, in der Handler-Direktiven ausgeführt werden (z. B. für Plugins).' },
  storage: { s: 'storage <module> { ... }', d: 'Speichermodul für Zertifikate und andere Assets (Standard: file_system).', sub: { root: ['root <path>', 'Wurzelverzeichnis für file_system-Storage'] } },
  storage_clean_interval: { s: 'storage_clean_interval <duration>', d: 'Wie oft der Speicher von abgelaufenen Assets bereinigt wird (Standard 24h).' },
  renew_interval: { s: 'renew_interval <duration>', d: 'Wie oft Zertifikate auf Erneuerung geprüft werden (Standard 10m).' },
  ocsp_interval: { s: 'ocsp_interval <duration>', d: 'Wie oft OCSP-Staples geprüft werden.' },
  admin: { s: 'admin off|<addr> { origins … enforce_origin }', d: 'Konfiguriert die Admin-API (Standard localhost:2019). ⚠ `admin off` trennt das Sentinel-Panel von Caddy.', sub: { origins: ['origins <origins...>', 'Erlaubte Origins für Admin-Anfragen'], enforce_origin: ['enforce_origin', 'Origin-Header erzwingen'] } },
  persist_config: { s: 'persist_config off', d: 'Verhindert, dass Caddy die aktive Konfiguration nach autosave.json schreibt.' },
  log: { s: 'log [name] { output … format … level … include … exclude … }', d: 'Konfiguriert einen benannten Logger (Standard: default).', sub: { output: ['output <writer> …', 'Ausgabe: stdout, stderr, discard, file <path>, net <addr>'], format: ['format <encoder> …', 'Format: console, json, filter, …'], level: ['level <level>', 'DEBUG, INFO, WARN, ERROR'], include: ['include <names...>', 'Nur diese Logger'], exclude: ['exclude <names...>', 'Diese Logger ausschließen'], sampling: ['sampling { interval first thereafter }', 'Log-Sampling'] } },
  grace_period: { s: 'grace_period <duration>', d: 'Wie lange beim Neuladen/Beenden auf laufende Verbindungen gewartet wird.' },
  shutdown_delay: { s: 'shutdown_delay <duration>', d: 'Verzögerung vor dem Grace Period beim Herunterfahren ({http.shutting_down} ist dann true).' },
  metrics: { s: 'metrics { per_host }', d: 'Aktiviert Prometheus-Metriken (unter /metrics der Admin-API).', sub: { per_host: ['per_host', 'Metriken zusätzlich pro Host labeln'] } },
  auto_https: { s: 'auto_https off|disable_redirects|ignore_loaded_certs|disable_certs', d: 'Steuert automatisches HTTPS.' },
  email: { s: 'email <email>', d: 'Kontakt-E-Mail für ACME-Konten.' },
  default_sni: { s: 'default_sni <name>', d: 'Standard-SNI, wenn Clients keinen Servernamen senden.' },
  fallback_sni: { s: 'fallback_sni <name>', d: 'SNI, wenn kein Zertifikat zum angefragten Namen passt.' },
  local_certs: { s: 'local_certs', d: 'Alle Zertifikate von der lokalen Caddy-CA ausstellen (für Entwicklung/intern).' },
  skip_install_trust: { s: 'skip_install_trust', d: 'Die lokale CA nicht in Vertrauensspeicher installieren.' },
  acme_ca: { s: 'acme_ca <directory_url>', d: 'ACME-CA-Verzeichnis (z. B. Let’s Encrypt Staging).' },
  acme_ca_root: { s: 'acme_ca_root <pem_file>', d: 'Vertrauenswürdiges Root-Zertifikat für die ACME-CA.' },
  acme_eab: { s: 'acme_eab { key_id <id> mac_key <key> }', d: 'External Account Binding für die ACME-CA.' },
  acme_dns: { s: 'acme_dns <provider> …', d: 'DNS-Provider für die DNS-01-Challenge (benötigt Plugin).' },
  on_demand_tls: { s: 'on_demand_tls { ask <endpoint> | permission <module> }', d: 'Konfiguriert On-Demand-TLS (Zertifikate beim ersten Handshake).', sub: { ask: ['ask <endpoint>', 'URL, die erlaubte Domains bestätigt'], permission: ['permission <module>', 'Berechtigungsmodul'] } },
  key_type: { s: 'key_type ed25519|p256|p384|rsa2048|rsa4096', d: 'Schlüsseltyp für neue Zertifikate.' },
  cert_issuer: { s: 'cert_issuer <name> …', d: 'Zertifikatsaussteller (acme, zerossl, internal). Mehrfach angebbar als Fallback.' },
  cert_lifetime: { s: 'cert_lifetime <duration>', d: 'Gewünschte Laufzeit interner Zertifikate.' },
  ocsp_stapling: { s: 'ocsp_stapling off', d: 'Deaktiviert OCSP-Stapling.' },
  preferred_chains: { s: 'preferred_chains smallest|{ root_common_name … any_common_name … }', d: 'Bevorzugte Zertifikatskette.' },
  servers: {
    s: 'servers [<listener_address>] { … }', d: 'Optionen für HTTP-Server (alle oder einen bestimmten Listener).',
    sub: {
      name: ['name <name>', 'Name für Logs/Metriken'],
      listener_wrappers: ['listener_wrappers { … }', 'Listener-Wrapper, z. B. proxy_protocol, http_redirect, tls'],
      timeouts: ['timeouts { read_body read_header write idle }', 'Verbindungs-Timeouts'],
      trusted_proxies: ['trusted_proxies static <ranges...>|private_ranges', 'Vertrauenswürdige Proxies → echte Client-IP aus Headern (wichtig für Sentinel-Bans hinter Cloudflare/Load-Balancern)'],
      trusted_proxies_strict: ['trusted_proxies_strict', 'Client-IP von rechts nach links aus X-Forwarded-For bestimmen'],
      client_ip_headers: ['client_ip_headers <headers...>', 'Header für die Client-IP (Standard X-Forwarded-For)'],
      metrics: ['metrics', 'Metriken für diesen Server'],
      max_header_size: ['max_header_size <size>', 'Maximale Header-Größe'],
      enable_full_duplex: ['enable_full_duplex', 'HTTP/1 Full-Duplex aktivieren'],
      log_credentials: ['log_credentials', 'Authorization/Cookies nicht aus Logs entfernen'],
      protocols: ['protocols h1|h2|h2c|h3', 'Erlaubte HTTP-Protokolle'],
      strict_sni_host: ['strict_sni_host [on|insecure_off]', 'SNI muss zum Host-Header passen'],
      keepalive_interval: ['keepalive_interval <duration>', 'TCP-Keepalive-Intervall'],
      trusted_proxies_unix: ['trusted_proxies_unix', 'Unix-Socket-Verbindungen als vertrauenswürdig behandeln'],
    },
  },
  pki: { s: 'pki { ca [<id>] { name root_cn intermediate_cn … } }', d: 'Konfiguriert die interne PKI/CA.' },
  events: { s: 'events { on <event> <handler…> }', d: 'Reagiert auf Caddy-Events (z. B. cert_obtained).' },
  filesystem: { s: 'filesystem <name> <module> …', d: 'Registriert ein virtuelles Dateisystem für fs/file_server.' },
  sentinel: {
    s: 'sentinel [<panel-url>] { panel token token_file cache_file fail_closed }',
    d: 'Verbindung des Sentinel-Moduls zum Panel. Ohne Angabe: http://127.0.0.1:7600 und /var/lib/caddy-sentinel/agent.token.',
    sub: { panel: ['panel <url>', 'URL des Sentinel-Panels'], token: ['token <token>', 'Agent-Token (besser token_file)'], token_file: ['token_file <path>', 'Datei mit dem Agent-Token'], cache_file: ['cache_file <path>', 'Zwischenspeicher für den letzten Stand (Policies, Bans)'], fail_closed: ['fail_closed', 'Ohne bekannten Stand alle Requests mit 503 ablehnen'], remote: ['remote read|full|off', 'Zugriff des Panels auf diesen Caddy: read = Konfiguration/Zertifikate lesen, full = Caddyfile bearbeiten'], caddyfile: ['caddyfile <path>', 'Caddyfile, die das Panel bei remote full bearbeitet'], admin: ['admin <url>', 'Admin-API dieses Caddy (Standard http://localhost:2019)'], geoip_country: ['geoip_country <path>', 'Eigene Länder-Datenbank'], geoip_asn: ['geoip_asn <path>', 'Eigene ASN-Datenbank'] },
  },
};

const REVERSE_PROXY_SUB = {
  to: ['to <upstreams...>', 'Upstream-Adressen (zusätzlich zu den Argumenten)'],
  dynamic: ['dynamic <module> …', 'Dynamische Upstreams (a, srv, multi)'],
  lb_policy: ['lb_policy random|round_robin|least_conn|ip_hash|client_ip_hash|uri_hash|header|cookie|first|weighted_round_robin|query', 'Lastverteilungs-Strategie'],
  lb_retries: ['lb_retries <n>', 'Wiederholungen bei Fehlern'],
  lb_try_duration: ['lb_try_duration <duration>', 'Wie lange ein verfügbarer Upstream gesucht wird'],
  lb_try_interval: ['lb_try_interval <interval>', 'Pause zwischen Versuchen'],
  lb_retry_match: ['lb_retry_match <matcher>', 'Welche Requests wiederholt werden dürfen'],
  health_uri: ['health_uri <uri>', 'Pfad für aktive Health-Checks'],
  health_port: ['health_port <port>', 'Port für Health-Checks'],
  health_interval: ['health_interval <interval>', 'Intervall aktiver Health-Checks'],
  health_passes: ['health_passes <n>', 'Erfolge bis „gesund“'],
  health_fails: ['health_fails <n>', 'Fehlschläge bis „ungesund“'],
  health_timeout: ['health_timeout <duration>', 'Timeout des Health-Checks'],
  health_status: ['health_status <status>', 'Erwarteter Status (z. B. 2xx)'],
  health_body: ['health_body <regexp>', 'Erwarteter Body (Regex)'],
  health_headers: ['health_headers { <field> <value> }', 'Header für Health-Checks'],
  health_method: ['health_method <method>', 'HTTP-Methode für Health-Checks'],
  fail_duration: ['fail_duration <duration>', 'Passive Health-Checks: wie lange ein Fehler zählt'],
  max_fails: ['max_fails <n>', 'Passive Fehler bis ein Upstream als down gilt'],
  unhealthy_status: ['unhealthy_status <status...>', 'Status-Codes, die als Fehler zählen'],
  unhealthy_latency: ['unhealthy_latency <duration>', 'Latenz, die als Fehler zählt'],
  unhealthy_request_count: ['unhealthy_request_count <n>', 'Max. gleichzeitige Requests pro Upstream'],
  flush_interval: ['flush_interval <interval>', 'Puffer-Flush (-1 = sofort, z. B. für SSE)'],
  request_buffers: ['request_buffers <size>', 'Request-Body puffern'],
  response_buffers: ['response_buffers <size>', 'Response-Body puffern'],
  stream_timeout: ['stream_timeout <duration>', 'Max. Dauer von Streams (WebSockets)'],
  stream_close_delay: ['stream_close_delay <duration>', 'Streams beim Neuladen verzögert schließen'],
  header_up: ['header_up [+|-]<field> [<value>|<find> <replace>]', 'Header zum Upstream setzen/entfernen'],
  header_down: ['header_down [+|-]<field> [<value>|<find> <replace>]', 'Header der Antwort setzen/entfernen'],
  method: ['method <method>', 'Methode für den Upstream-Request ändern'],
  rewrite: ['rewrite <to>', 'URI für den Upstream umschreiben'],
  transport: ['transport http|fastcgi { … }', 'Transport-Optionen (TLS zum Upstream, Timeouts, Keepalive …)'],
  handle_response: ['handle_response [<matcher>] { … }', 'Antworten des Upstreams abfangen und behandeln'],
  replace_status: ['replace_status [<matcher>] <status>', 'Status der Upstream-Antwort ersetzen'],
  trusted_proxies: ['trusted_proxies <ranges...>', 'Veraltet – global unter servers setzen'],
  verbose_logs: ['verbose_logs', 'Ausführlichere Logs'],
};

const TRANSPORT_SUB = {
  tls: ['tls', 'HTTPS zum Upstream'],
  tls_insecure_skip_verify: ['tls_insecure_skip_verify', '⚠ Zertifikat des Upstreams nicht prüfen'],
  tls_server_name: ['tls_server_name <name>', 'SNI zum Upstream'],
  tls_trust_pool: ['tls_trust_pool <module> …', 'Vertrauenswürdige CAs'],
  dial_timeout: ['dial_timeout <duration>', 'Verbindungsaufbau-Timeout'],
  response_header_timeout: ['response_header_timeout <duration>', 'Timeout bis zu den Antwort-Headern'],
  read_timeout: ['read_timeout <duration>', 'Lese-Timeout'],
  write_timeout: ['write_timeout <duration>', 'Schreib-Timeout'],
  keepalive: ['keepalive off|<duration>', 'Keepalive zu Upstreams'],
  keepalive_idle_conns: ['keepalive_idle_conns <n>', 'Max. Leerlauf-Verbindungen'],
  versions: ['versions 1.1|2|h2c|3', 'HTTP-Versionen zum Upstream'],
  compression: ['compression off', 'Keine Kompression vom Upstream anfordern'],
  max_conns_per_host: ['max_conns_per_host <n>', 'Max. Verbindungen pro Upstream'],
  root: ['root <path>', 'FastCGI: Dokumenten-Root'],
  split: ['split <at>', 'FastCGI: PATH_INFO-Trennung (.php)'],
  env: ['env <key> <value>', 'FastCGI: Umgebungsvariable'],
};

const HEADER_SUB = {};

export const DIRECTIVES = {
  abort: { s: 'abort [<matcher>]', d: 'Bricht die Verbindung ohne Antwort ab.' },
  acme_server: { s: 'acme_server [<matcher>] { ca lifetime resolvers challenges allow deny }', d: 'Macht Caddy zu einem ACME-Server für die interne CA.' },
  basic_auth: { s: 'basic_auth [<matcher>] [<hash_algorithm>] { <user> <hashed_password> }', d: 'HTTP Basic Authentication. Hash mit `caddy hash-password` erzeugen.', snip: 'basic_auth ${1:/admin/*} {\n\t${2:admin} ${3:$2a$14$...}\n}' },
  bind: { s: 'bind <hosts...> [{ protocols … }]', d: 'Bindet die Site an bestimmte Netzwerkadressen.' },
  encode: { s: 'encode [<matcher>] <formats...> { gzip zstd minimum_length match }', d: 'Komprimiert Antworten (zstd, gzip).', sub: { gzip: ['gzip [<level>]', 'Gzip-Kompression'], zstd: ['zstd [<level>]', 'Zstandard-Kompression'], minimum_length: ['minimum_length <length>', 'Mindestgröße zum Komprimieren'], match: ['match { status header }', 'Welche Antworten komprimiert werden'] }, snip: 'encode zstd gzip' },
  error: { s: 'error [<matcher>] <status>|<message> [<status>]', d: 'Löst einen Fehler aus, der von handle_errors behandelt wird.' },
  file_server: { s: 'file_server [<matcher>] [browse] { fs root hide index browse precompressed status disable_canonical_uris pass_thru etag_file_extensions }', d: 'Liefert statische Dateien aus.', sub: { fs: ['fs <filesystem>', 'Virtuelles Dateisystem'], root: ['root <path>', 'Wurzelverzeichnis'], hide: ['hide <files...>', 'Dateien verstecken'], index: ['index <filenames...>', 'Index-Dateien'], browse: ['browse [<template>] { reveal_symlinks sort file_limit }', 'Verzeichnislisten anzeigen'], precompressed: ['precompressed <formats...>', 'Vorkomprimierte Dateien (.br, .gz, .zst) nutzen'], status: ['status <status>', 'Status-Code überschreiben'], disable_canonical_uris: ['disable_canonical_uris', 'Keine Weiterleitung auf / am Ende'], pass_thru: ['pass_thru', 'Bei 404 zum nächsten Handler'], etag_file_extensions: ['etag_file_extensions <ext...>', 'ETag aus Begleitdateien'] }, snip: 'root * ${1:/var/www/html}\nfile_server' },
  forward_auth: { s: 'forward_auth [<matcher>] <upstreams...> { uri copy_headers … }', d: 'Delegiert die Authentifizierung an einen externen Dienst (Authelia, Authentik …).', sub: { uri: ['uri <to>', 'Pfad des Auth-Endpunkts'], copy_headers: ['copy_headers <fields...>', 'Header der Auth-Antwort übernehmen'], ...REVERSE_PROXY_SUB }, snip: 'forward_auth ${1:authelia:9091} {\n\turi /api/authz/forward-auth\n\tcopy_headers Remote-User Remote-Groups Remote-Email Remote-Name\n}' },
  fs: { s: 'fs <filesystem>', d: 'Setzt das Dateisystem für nachfolgende Handler.' },
  handle: { s: 'handle [<matcher>] { … }', d: 'Gruppiert Direktiven; nur der erste passende handle-Block wird ausgeführt (sich gegenseitig ausschließend).', snip: 'handle ${1:/api/*} {\n\t$0\n}' },
  handle_errors: { s: 'handle_errors [<status_codes...>] { … }', d: 'Behandelt Fehler ({err.status_code}, {err.message}).', snip: 'handle_errors {\n\trespond "{err.status_code} {err.status_text}"\n}' },
  handle_path: { s: 'handle_path <path_matcher> { … }', d: 'Wie handle, entfernt aber das Pfad-Präfix.', snip: 'handle_path ${1:/static/*} {\n\t$0\n}' },
  header: { s: 'header [<matcher>] [[+|-|?|>]<field> [<value>|<find>] [<replace>]] { defer }', d: 'Setzt, ergänzt oder entfernt Antwort-Header. `-Server` entfernt den Header, `?` setzt nur, wenn nicht vorhanden.', sub: { defer: ['defer', 'Header erst beim Schreiben der Antwort anwenden'], match: ['match …', 'Nur bei passender Antwort'] }, snip: 'header {\n\tStrict-Transport-Security "max-age=31536000; includeSubDomains"\n\tX-Content-Type-Options nosniff\n\tReferrer-Policy strict-origin-when-cross-origin\n\t-Server\n}' },
  import: { s: 'import <pattern> [<args...>]', d: 'Importiert Dateien (Glob erlaubt) oder Snippets. Argumente als {args[0]} usw.' },
  intercept: { s: 'intercept [<matcher>] { @name status … handle_response … replace_status }', d: 'Fängt Antworten beliebiger Handler ab.' },
  invoke: { s: 'invoke <name>', d: 'Ruft eine benannte Route (&(name)) auf.' },
  log: { s: 'log [<logger_name>] { hostnames output format level no_hostname }', d: 'Aktiviert Zugriffs-Logs für diese Site.', sub: { output: ['output stdout|stderr|discard|file <path> { roll_size roll_keep roll_keep_for }|net <addr>', 'Ziel'], format: ['format console|json|filter …', 'Format'], level: ['level <level>', 'Level'], hostnames: ['hostnames <hostnames...>', 'Nur diese Hostnamen'], no_hostname: ['no_hostname', 'Keine Hostnamen-Zuordnung'] }, snip: 'log {\n\toutput file /var/log/caddy/${1:access}.log {\n\t\troll_size 50MiB\n\t\troll_keep 5\n\t}\n\tformat json\n}' },
  log_append: { s: 'log_append [<matcher>] <key> <value>', d: 'Fügt dem Zugriffs-Log ein Feld hinzu.' },
  log_skip: { s: 'log_skip [<matcher>]', d: 'Diese Requests nicht loggen.' },
  log_name: { s: 'log_name [<matcher>] <names...>', d: 'Logger für passende Requests wählen.' },
  map: { s: 'map [<matcher>] <source> <destinations...> { <input> <outputs...> default … }', d: 'Bildet einen Eingabewert auf Variablen ab.' },
  method: { s: 'method [<matcher>] <method>', d: 'Ändert die HTTP-Methode intern.' },
  metrics: { s: 'metrics [<matcher>] { disable_openmetrics }', d: 'Stellt Prometheus-Metriken unter dieser Route bereit.' },
  php_fastcgi: { s: 'php_fastcgi [<matcher>] <php-fpm_gateways...> { root split env index try_files resolve_root_symlink dial_timeout read_timeout write_timeout capture_stderr }', d: 'PHP über FastCGI (PHP-FPM) mit sinnvollen Standards.', sub: { ...TRANSPORT_SUB, index: ['index <filename>|off', 'Index-Datei'], try_files: ['try_files <files...>', 'Dateien für try_files'], resolve_root_symlink: ['resolve_root_symlink', 'Symlinks im Root auflösen'], capture_stderr: ['capture_stderr', 'stderr von PHP loggen'] }, snip: 'root * ${1:/var/www/html}\nphp_fastcgi ${2:unix//run/php/php-fpm.sock}\nfile_server' },
  push: { s: 'push [<matcher>] [<resource>] { [GET|HEAD] <resource> headers }', d: 'HTTP/2 Server Push (veraltet in Browsern).' },
  redir: { s: 'redir [<matcher>] <to> [<code>]', d: 'Weiterleitung. code: temporary (302), permanent (301), html, oder Status.', snip: 'redir ${1:https://example.com{uri}} ${2:permanent}' },
  request_body: { s: 'request_body [<matcher>] { max_size }', d: 'Begrenzt die Request-Body-Größe.', sub: { max_size: ['max_size <size>', 'z. B. 10MB'] } },
  request_header: { s: 'request_header [<matcher>] [[+|-]<field> [<value>|<find>] [<replace>]]', d: 'Ändert Request-Header vor der Weitergabe.' },
  respond: { s: 'respond [<matcher>] <status>|<body> [<status>] { body close }', d: 'Antwortet direkt mit Status und optionalem Body.', sub: { body: ['body <text>', 'Antwort-Body'], close: ['close', 'Verbindung danach schließen'] }, snip: 'respond ${1:"OK"} ${2:200}' },
  reverse_proxy: { s: 'reverse_proxy [<matcher>] [<upstreams...>] { … }', d: 'Leitet Requests an Backend-Server weiter – mit Lastverteilung, Health-Checks und Header-Manipulation.', sub: REVERSE_PROXY_SUB, snip: 'reverse_proxy ${1:localhost:8080}' },
  rewrite: { s: 'rewrite [<matcher>] <to>', d: 'Schreibt die URI intern um.' },
  root: { s: 'root [<matcher>] <path>', d: 'Setzt das Wurzelverzeichnis für file_server, php_fastcgi, templates usw.', snip: 'root * ${1:/var/www/html}' },
  route: { s: 'route [<matcher>] { … }', d: 'Führt die Direktiven exakt in der angegebenen Reihenfolge aus.' },
  sentinel: { s: 'sentinel [<policy-id>]', d: 'Caddy Sentinel: setzt Policies (WAF, Ratelimits, IP-Regeln, Bans) durch und sendet Metriken ans Panel. Ohne Argument wird die Policy über den Host gewählt.', snip: 'sentinel' },
  templates: { s: 'templates [<matcher>] { mime between root extensions }', d: 'Wertet Go-Templates in Antworten aus.' },
  tls: { s: 'tls internal|<email>|<cert_file> <key_file> { … }', d: 'TLS-Einstellungen der Site.', sub: { protocols: ['protocols <min> [<max>]', 'z. B. tls1.2 tls1.3'], ciphers: ['ciphers <suites...>', 'Cipher-Suites'], curves: ['curves <curves...>', 'Elliptische Kurven'], alpn: ['alpn <values...>', 'ALPN-Protokolle'], load: ['load <paths...>', 'Zertifikate aus Ordnern laden'], ca: ['ca <ca_dir_url>', 'ACME-CA'], ca_root: ['ca_root <pem_file>', 'Root-Zertifikat der CA'], key_type: ['key_type <type>', 'Schlüsseltyp'], dns: ['dns <provider> …', 'DNS-01-Challenge'], propagation_timeout: ['propagation_timeout <duration>', 'DNS-Propagation abwarten'], resolvers: ['resolvers <resolvers...>', 'DNS-Resolver'], eab: ['eab <key_id> <mac_key>', 'External Account Binding'], on_demand: ['on_demand', 'On-Demand-TLS'], client_auth: ['client_auth { mode trusted_ca_cert_file … }', 'mTLS: Client-Zertifikate verlangen'], issuer: ['issuer <issuer_name> …', 'Aussteller'], get_certificate: ['get_certificate <manager> …', 'Zertifikat von externem Manager'] } },
  tracing: { s: 'tracing { span }', d: 'OpenTelemetry-Tracing.' },
  try_files: { s: 'try_files <files...> { policy }', d: 'Probiert Dateien der Reihe nach und schreibt auf die erste existierende um (SPA: try_files {path} /index.html).', snip: 'try_files {path} /index.html' },
  uri: { s: 'uri [<matcher>] strip_prefix|strip_suffix|replace|path_regexp|query <args>', d: 'Manipuliert die URI (Präfix entfernen, ersetzen, Query ändern).' },
  vars: { s: 'vars [<matcher>] [<name> <value>] { <name> <value> }', d: 'Setzt Variablen ({vars.name}).' },
};

export const MATCHERS = {
  client_ip: ['client_ip <ranges...>', 'Client-IP (berücksichtigt trusted_proxies)'],
  remote_ip: ['remote_ip <ranges...>', 'IP der direkten Verbindung'],
  expression: ['expression <cel…>', 'CEL-Ausdruck, z. B. {method} == "POST"'],
  file: ['file { root try_files try_policy split_path }', 'Datei existiert'],
  header: ['header <field> [<value>]', 'Request-Header (Wildcards erlaubt)'],
  header_regexp: ['header_regexp [<name>] <field> <regexp>', 'Header per Regex'],
  host: ['host <hosts...>', 'Hostname'],
  method: ['method <verbs...>', 'HTTP-Methode'],
  not: ['not <matcher>', 'Negation'],
  path: ['path <paths...>', 'Pfad (mit * Wildcards)'],
  path_regexp: ['path_regexp [<name>] <regexp>', 'Pfad per Regex ({re.name.1})'],
  protocol: ['protocol http|https|grpc|http/<version>', 'Protokoll'],
  query: ['query <key>=<val>…', 'Query-Parameter'],
  vars: ['vars <variable> <values...>', 'Variable'],
  vars_regexp: ['vars_regexp [<name>] <variable> <regexp>', 'Variable per Regex'],
};

export const PLACEHOLDERS = [
  ['{host}', 'Host des Requests'], ['{hostport}', 'Host und Port'], ['{uri}', 'URI inkl. Query'], ['{path}', 'Pfad'],
  ['{query}', 'Query-String'], ['{method}', 'HTTP-Methode'], ['{scheme}', 'http/https'], ['{remote_host}', 'Client-IP (Verbindung)'],
  ['{client_ip}', 'Client-IP (trusted_proxies)'], ['{remote_port}', 'Client-Port'], ['{tls_version}', 'TLS-Version'],
  ['{file}', 'Dateiname des Pfads'], ['{dir}', 'Verzeichnis des Pfads'], ['{labels.0}', 'Host-Label (von rechts)'],
  ['{path.0}', 'Pfad-Segment'], ['{query.<key>}', 'Query-Parameter'], ['{header.<Name>}', 'Request-Header'],
  ['{cookie.<name>}', 'Cookie'], ['{env.<VAR>}', 'Umgebungsvariable (Laufzeit)'], ['{$VAR}', 'Umgebungsvariable (beim Parsen)'],
  ['{vars.<name>}', 'Variable'], ['{re.<name>.<n>}', 'Regex-Gruppe'], ['{err.status_code}', 'Fehlerstatus'], ['{err.message}', 'Fehlermeldung'],
  ['{upstream_hostport}', 'Gewählter Upstream'], ['{http.request.uuid}', 'Request-ID'], ['{system.hostname}', 'Hostname des Servers'],
  ['{time.now.unix}', 'Unix-Zeit'],
];

export const SNIPPETS = [
  { label: 'Reverse Proxy', text: '${1:app.example.com} {\n\tsentinel\n\tencode zstd gzip\n\treverse_proxy ${2:127.0.0.1:8080}\n}\n' },
  { label: 'Statische Website', text: '${1:www.example.com} {\n\tsentinel\n\troot * ${2:/var/www/html}\n\tencode zstd gzip\n\tfile_server\n}\n' },
  { label: 'Single-Page-App', text: '${1:app.example.com} {\n\tsentinel\n\troot * ${2:/var/www/app}\n\tencode zstd gzip\n\ttry_files {path} /index.html\n\tfile_server\n}\n' },
  { label: 'PHP (WordPress, Nextcloud …)', text: '${1:blog.example.com} {\n\tsentinel\n\troot * ${2:/var/www/wordpress}\n\tencode zstd gzip\n\tphp_fastcgi ${3:unix//run/php/php-fpm.sock}\n\tfile_server\n}\n' },
  { label: 'Weiterleitung www → apex', text: 'www.${1:example.com} {\n\tredir https://${1:example.com}{uri} permanent\n}\n' },
  { label: 'API + Frontend getrennt', text: '${1:example.com} {\n\tsentinel\n\thandle /api/* {\n\t\treverse_proxy ${2:127.0.0.1:3000}\n\t}\n\thandle {\n\t\troot * ${3:/var/www/frontend}\n\t\ttry_files {path} /index.html\n\t\tfile_server\n\t}\n}\n' },
  { label: 'Load-Balancing mit Health-Check', text: 'reverse_proxy ${1:10.0.0.11:8080 10.0.0.12:8080} {\n\tlb_policy least_conn\n\thealth_uri /health\n\thealth_interval 10s\n\tfail_duration 30s\n}\n' },
  { label: 'Security-Header', text: 'header {\n\tStrict-Transport-Security "max-age=31536000; includeSubDomains"\n\tX-Content-Type-Options nosniff\n\tX-Frame-Options SAMEORIGIN\n\tReferrer-Policy strict-origin-when-cross-origin\n\t-Server\n}\n' },
  { label: 'Basic-Auth für Bereich', text: 'basic_auth ${1:/admin/*} {\n\t${2:admin} ${3:<hash von caddy hash-password>}\n}\n' },
  { label: 'Nur interne Netze', text: '@extern not client_ip private_ranges\nrespond @extern "Forbidden" 403\n' },
  { label: 'Snippet definieren', text: '(${1:common}) {\n\tencode zstd gzip\n\theader -Server\n}\n' },
  { label: 'Zugriffs-Log als JSON', text: 'log {\n\toutput file /var/log/caddy/${1:site}.log {\n\t\troll_size 50MiB\n\t\troll_keep 5\n\t}\n\tformat json\n}\n' },
  { label: 'Sentinel global konfigurieren', text: '{\n\tsentinel {\n\t\tpanel http://127.0.0.1:7600\n\t\ttoken_file /var/lib/caddy-sentinel/agent.token\n\t}\n}\n' },
  { label: 'Hinter Cloudflare / Proxy', text: '{\n\tservers {\n\t\ttrusted_proxies static ${1:173.245.48.0/20 103.21.244.0/22}\n\t\tclient_ip_headers CF-Connecting-IP X-Forwarded-For\n\t}\n}\n' },
];

export const DOC_LINK = (name, global) => global ? G + '#' + name.replace(/_/g, '-') : D + name;

export const SUBS = { transport: TRANSPORT_SUB, header: HEADER_SUB };

// ---------------------------------------------------------------- additions (value hints, extra entries)

Object.assign(DIRECTIVES, {
  copy_response: { s: 'copy_response [<matcher>] [<status>] { status }', d: 'Nur in handle_response: kopiert die Upstream-Antwort zum Client.' },
  copy_response_headers: { s: 'copy_response_headers [<matcher>] { include exclude }', d: 'Nur in handle_response: kopiert Header der Upstream-Antwort.' },
});
DIRECTIVES.acme_server.sub = {
  ca: ['ca <id>', 'ID der internen CA (Standard local)'],
  lifetime: ['lifetime <duration>', 'Laufzeit ausgestellter Zertifikate (Standard 12h)'],
  resolvers: ['resolvers <resolvers...>', 'DNS-Resolver für die Validierung'],
  challenges: ['challenges <challenges...>', 'Erlaubte Challenges: http-01, tls-alpn-01, dns-01'],
  allow: ['allow { domains ip_ranges }', 'Nur diese Namen/Netze ausstellen'],
  deny: ['deny { domains ip_ranges }', 'Diese Namen/Netze nie ausstellen'],
  sign_with_root: ['sign_with_root', 'Direkt mit dem Root signieren (ohne Intermediate)'],
};
GLOBAL.pki.sub = {
  ca: ['ca [<id>] { … }', 'Eine CA konfigurieren (Standard: local)'],
  name: ['name <name>', 'Anzeigename der CA'],
  root_cn: ['root_cn <name>', 'Common Name des Root-Zertifikats'],
  intermediate_cn: ['intermediate_cn <name>', 'Common Name des Intermediate'],
  intermediate_lifetime: ['intermediate_lifetime <duration>', 'Laufzeit des Intermediate (Standard 7d)'],
  root: ['root { cert key format }', 'Eigenes Root-Zertifikat verwenden'],
  intermediate: ['intermediate { cert key format }', 'Eigenes Intermediate verwenden'],
};

// Value suggestions for arguments: directive or subdirective -> [value, description]
export const VALUES = {
  redir: [['permanent', '301 dauerhaft'], ['temporary', '302 vorübergehend'], ['html', 'Weiterleitung per HTML-Seite'], ['301', ''], ['302', ''], ['307', ''], ['308', '']],
  lb_policy: [['round_robin', 'reihum'], ['least_conn', 'wenigste Verbindungen'], ['random', 'zufällig'], ['first', 'erster verfügbarer (Failover)'], ['ip_hash', 'nach Verbindungs-IP'], ['client_ip_hash', 'nach Client-IP (Sticky)'], ['uri_hash', 'nach URI'], ['header', 'nach Header'], ['cookie', 'Sticky-Cookie'], ['weighted_round_robin', 'gewichtet'], ['query', 'nach Query-Parameter']],
  encode: [['zstd', 'Zstandard'], ['gzip', 'Gzip']],
  tls: [['internal', 'interne CA (tls internal)'], ['{$ACME_EMAIL}', 'E-Mail für ACME']],
  auto_https: [['off', 'aus'], ['disable_redirects', 'keine HTTP→HTTPS-Weiterleitung'], ['ignore_loaded_certs', 'geladene Zertifikate ignorieren'], ['disable_certs', 'keine Zertifikate beziehen']],
  transport: [['http', 'HTTP(S) zum Upstream'], ['fastcgi', 'FastCGI (PHP-FPM)']],
  protocols: [['tls1.2', 'TLS 1.2'], ['tls1.3', 'TLS 1.3'], ['h1', 'HTTP/1.1'], ['h2', 'HTTP/2'], ['h2c', 'HTTP/2 cleartext'], ['h3', 'HTTP/3']],
  key_type: [['ed25519', ''], ['p256', ''], ['p384', ''], ['rsa2048', ''], ['rsa4096', '']],
  output: [['stdout', ''], ['stderr', ''], ['discard', ''], ['file', 'file <pfad> { roll_size … }'], ['net', 'net <adresse>']],
  format: [['json', ''], ['console', ''], ['filter', 'Felder filtern/maskieren'], ['transform', 'eigene Vorlage (Plugin)']],
  level: [['DEBUG', ''], ['INFO', ''], ['WARN', ''], ['ERROR', '']],
  versions: [['1.1', ''], ['2', ''], ['h2c', ''], ['3', '']],
  keepalive: [['off', ''], ['2m', '']],
  health_status: [['2xx', ''], ['200', '']],
  health_method: [['GET', ''], ['HEAD', '']],
  method: [['GET', ''], ['POST', ''], ['PUT', ''], ['PATCH', ''], ['DELETE', ''], ['HEAD', ''], ['OPTIONS', '']],
  protocol: [['https', ''], ['http', ''], ['grpc', ''], ['http/2', ''], ['http/3', '']],
  client_ip: [['private_ranges', 'alle privaten Netze'], ['192.168.0.0/16', ''], ['10.0.0.0/8', '']],
  remote_ip: [['private_ranges', 'alle privaten Netze']],
  trusted_proxies: [['static', 'static <ranges…>'], ['private_ranges', 'alle privaten Netze']],
  strict_sni_host: [['on', ''], ['insecure_off', '']],
  ocsp_stapling: [['off', '']],
  persist_config: [['off', '']],
  admin: [['off', '⚠ trennt das Panel von Caddy'], ['localhost:2019', ''], ['unix//run/caddy/admin.sock', 'Unix-Socket']],
  challenges: [['http-01', ''], ['tls-alpn-01', ''], ['dns-01', '']],
  compression: [['off', '']],
  index: [['index.html', ''], ['off', '']],
  precompressed: [['zstd', ''], ['br', ''], ['gzip', '']],
  try_files: [['{path}', 'angefragter Pfad'], ['{path}/', 'als Verzeichnis'], ['/index.html', 'SPA-Fallback'], ['{path}.html', 'ohne .html-Endung']],
  file_server: [['browse', 'Verzeichnislisten anzeigen']],
  uri: [['strip_prefix', ''], ['strip_suffix', ''], ['replace', ''], ['path_regexp', ''], ['query', '']],
  log_skip: [],
};

// common HTTP status codes
export const STATUS = [['200', 'OK'], ['201', 'Created'], ['204', 'No Content'], ['301', 'Moved Permanently'], ['302', 'Found'], ['304', 'Not Modified'], ['307', 'Temporary Redirect'], ['308', 'Permanent Redirect'], ['400', 'Bad Request'], ['401', 'Unauthorized'], ['403', 'Forbidden'], ['404', 'Not Found'], ['405', 'Method Not Allowed'], ['410', 'Gone'], ['418', "I'm a teapot"], ['429', 'Too Many Requests'], ['500', 'Internal Server Error'], ['502', 'Bad Gateway'], ['503', 'Service Unavailable'], ['504', 'Gateway Timeout']];
export const STATUS_DIRECTIVES = new Set(['respond', 'error', 'replace_status', 'status', 'health_status', 'redir']);

// header names (with typical values) for header/header_up/header_down/request_header
export const HEADERS = [
  ['Strict-Transport-Security', '"max-age=31536000; includeSubDomains"'],
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'SAMEORIGIN'],
  ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  ['Content-Security-Policy', `"default-src 'self'"`],
  ['Permissions-Policy', '"geolocation=(), microphone=(), camera=()"'],
  ['Cross-Origin-Opener-Policy', 'same-origin'],
  ['Cross-Origin-Resource-Policy', 'same-origin'],
  ['Cache-Control', '"public, max-age=3600"'],
  ['X-Robots-Tag', '"noindex, nofollow"'],
  ['Access-Control-Allow-Origin', '*'],
  ['Access-Control-Allow-Methods', '"GET, POST, OPTIONS"'],
  ['Access-Control-Allow-Headers', '*'],
  ['-Server', ''],
  ['-X-Powered-By', ''],
  ['Host', '{upstream_hostport}'],
  ['X-Real-IP', '{client_ip}'],
  ['Authorization', ''],
];
export const HEADER_DIRECTIVES = new Set(['header', 'header_up', 'header_down', 'request_header', 'health_headers']);

// directives whose block content is fully described by `sub` (unknown names get a warning)
export const STRICT_SUBS = new Set(['reverse_proxy', 'file_server', 'encode', 'log', 'tls', 'request_body', 'acme_server', 'transport', 'php_fastcgi', 'forward_auth', 'servers', 'sentinel', 'on_demand_tls', 'metrics']);
// directives that only make sense inside other blocks
export const NESTED_ONLY = new Set(['copy_response', 'copy_response_headers']);
// terminal handlers (write the response)
export const TERMINAL = new Set(['respond', 'reverse_proxy', 'file_server', 'redir', 'php_fastcgi', 'error', 'abort', 'acme_server', 'static_response']);
Object.assign(GLOBAL.sentinel.sub, {
  geoip_country: ['geoip_country <path.mmdb>', 'GeoIP-Länderdatenbank auf diesem Caddy-Host'],
  geoip_asn: ['geoip_asn <path.mmdb>', 'GeoIP-ASN-Datenbank auf diesem Caddy-Host'],
});
// Caddy's default directive order (which unmatched handler wins)
export const DIRECTIVE_ORDER = ['tracing', 'map', 'vars', 'fs', 'root', 'log_append', 'log_skip', 'log_name', 'header', 'copy_response_headers', 'request_body', 'redir', 'method', 'rewrite', 'uri', 'try_files', 'basic_auth', 'forward_auth', 'request_header', 'encode', 'push', 'intercept', 'templates', 'invoke', 'handle', 'handle_path', 'route', 'abort', 'error', 'copy_response', 'respond', 'metrics', 'reverse_proxy', 'php_fastcgi', 'file_server', 'acme_server'];
export const DEPRECATED = { basicauth: 'basic_auth', skip_log: 'log_skip' };
