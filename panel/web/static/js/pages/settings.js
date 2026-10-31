import { del, el, mount, get, post, put, panel, tabs, field, toggle, select, linesInput, toast, errToast, confirmDialog, copy, fmtBytes, fmtAgo, empty, ROLES, roleLabel, modal, untilInput, fmtUnix, fmtUntil, can } from '../ui.js';
import { setActions } from '../app.js';

const SIGNALS = { waf_block: 'WAF-Block', waf_detect: 'WAF-Treffer (je 5 Score)', honeypot: 'Honeypot-Treffer', not_found: '404-Antwort', auth_fail: '401/403 / Login fehlgeschlagen', path_block: 'Pfad-Sperre (Regel)', bad_request: '400-Antwort', scanner_ua: 'Angriffstool erkannt', rate_limit: 'Ratelimit überschritten', user_agent: 'Gesperrter User-Agent', method: 'Unerlaubte Methode', ip_deny: 'IP-Sperrliste', burst: 'Request-Burst', body_limit: 'Body zu groß', geo_block: 'Geo-Sperre', feed_block: 'Threat-Feed-Block', challenge: 'Challenge ausgeliefert', bot_fake: 'Gefälschter Suchmaschinen-Bot', bot: 'Crawler gesperrt/gebremst' };

export async function render(root, _p, scope, q) {
  const data = await get('/settings', scope.signal);
  const s = data.settings;
  s.webhooks ??= []; s.trusted ??= []; s.ids.never_ban ??= []; s.ids.scanner_uas ??= [];
  s.geoip ??= { country_db: '', asn_db: '' }; s.smtp ??= { port: 587, security: 'starttls' }; s.certs ??= { storage_path: '', warn_days: 14 };
  const me = (window.__status || {}).user || {};
  const isAdmin = me.role === 'admin';
  let tab = q.get('tab') || 'ids';
  let dirty = false;
  const saveBtn = el('button.btn.primary', { disabled: true, onclick: save }, 'Speichern');
  const markDirty = () => { dirty = true; saveBtn.disabled = false; };
  setActions(saveBtn);
  async function save() {
    saveBtn.disabled = true;
    try { await put('/settings', s); dirty = false; toast('Einstellungen gespeichert', 'ok'); } catch (e) { saveBtn.disabled = false; errToast(e); }
  }
  const body = el('div.stack');
  const draw = () => {
    history.replaceState(null, '', '#/settings?tab=' + tab);
    const tabList = [['ids', 'Bedrohungserkennung'], ['alerts', 'Benachrichtigungen'], ['network', 'Netz & Vertrauen'], ['data', 'Telemetrie & Speicher'], ['agent', 'Agent & Caddy'], ['users', 'Benutzer'], ['backup', 'Sicherung'], ['account', 'Konto & Sicherheit'], ['tokens', 'API-Tokens'], ['about', 'Über & Lizenzen']]
      .filter(([k]) => isAdmin || ['account', 'tokens', 'about'].includes(k));
    if (!isAdmin && !['tokens', 'about'].includes(tab)) tab = 'account';
    mount(root, tabs(tabList, tab, (t) => { tab = t; draw(); }), body);
    setActions(['account', 'tokens', 'about'].includes(tab) ? null : saveBtn);
    ({ ids, alerts, network, dataTab, agent, users, backup, account, tokens, about })[tab === 'data' ? 'dataTab' : tab]();
  };

  const num = (obj, key, attrs = {}) => el('input', { type: 'number', value: obj[key] ?? 0, ...attrs, oninput: (e) => { obj[key] = attrs.float ? parseFloat(e.target.value) : +e.target.value; markDirty(); } });

  function ids() {
    const c = s.ids;
    mount(body,
      panel('Automatische Sperren (IPS)', el('div.stack', null,
        el('div.row', null, toggle(c.enabled, (v) => { c.enabled = v; markDirty(); }, 'Bedrohungserkennung aktiv'), toggle(c.dry_run, (v) => { c.dry_run = v; markDirty(); }, 'Testmodus (nur melden, nicht sperren)')),
        el('div.fields', null,
          field('Sperr-Schwelle (Punkte)', num(c, 'ban_threshold', { min: 1 })),
          field('Halbwertszeit des Scores (Min.)', el('input', { type: 'number', min: 1, value: Math.round(c.half_life_seconds / 60), oninput: (e) => { c.half_life_seconds = +e.target.value * 60; markDirty(); } }), 'So schnell „vergisst“ Sentinel verdächtiges Verhalten.'),
          field('Erste Sperre (Min.)', el('input', { type: 'number', min: 1, value: Math.round(c.ban_seconds / 60), oninput: (e) => { c.ban_seconds = +e.target.value * 60; markDirty(); } })),
          field('Faktor je Wiederholung', num(c, 'escalation', { min: 1, step: 0.5, float: true }), 'Dauer = Erste Sperre × Faktor^(frühere Sperren)'),
          field('Maximale Sperre (Tage)', el('input', { type: 'number', min: 1, value: Math.round(c.max_ban_seconds / 86400), oninput: (e) => { c.max_ban_seconds = +e.target.value * 86400; markDirty(); } })),
          field('Dauerhaft ab Sperre Nr.', num(c, 'permanent_after', { min: 0 }), '0 = nie dauerhaft'),
          field('Burst: Requests', num(c, 'burst_requests', { min: 0 }), '0 = aus. Mehr Requests einer IP im Fenster zählen als Signal.'),
          field('Burst: Fenster (s)', num(c, 'burst_window_seconds', { min: 1 })),
          field('Bot-Challenge ab Score', num(c, 'challenge_threshold', { min: 0 }), 'IPs ab diesem Score müssen auf Policies mit Challenge-Modus „verdächtig“ die Bot-Challenge lösen. 0 = aus.'),
          field('Challenge-Dauer (Min.)', el('input', { type: 'number', min: 1, value: Math.round((c.challenge_seconds || 3600) / 60), oninput: (e) => { c.challenge_seconds = +e.target.value * 60; markDirty(); } })),
          field('IPv6-Sperren für', select([['64', 'das /64-Netz des Clients'], ['56', 'das /56-Netz'], ['48', 'das /48-Netz'], ['128', 'nur die einzelne Adresse']], String(c.ipv6_prefix || 64), (v) => { c.ipv6_prefix = +v; markDirty(); }), 'Ein /64 gehört meist einem Anschluss. Wer nur die Adresse sperrt, lässt den Client mit der nächsten Adresse weitermachen.')))),
      panel('Gewichtung der Signale', el('div.stack', null,
        el('p.muted', null, 'Punkte, die eine IP pro Ereignis erhält. Policies können diese Werte überschreiben. 404, 400, 401/403 des Backends bei GET und WAF-Treffer im Erkennungsmodus zählen je Pfad nur einmal in 10 Minuten, Ratelimit-Treffer einmal pro Minute – so sperrt eine Seite, die dieselbe Adresse abfragt, ihre Besucher nicht. Fehlgeschlagene Anmeldungen (POST) zählen jedes Mal.'),
        el('div.fields', null, Object.keys(SIGNALS).map(k => field(SIGNALS[k], el('input', { type: 'number', min: 0, value: c.weights[k] ?? 0, oninput: (e) => { c.weights[k] = +e.target.value; markDirty(); } })))),
        el('div.row', null, el('button.btn.ghost', { onclick: () => { c.weights = { ...data.defaults.ids.weights }; markDirty(); ids(); } }, 'Standardgewichte wiederherstellen')))),
      panel('Angriffstools (User-Agent-Teilstrings)', linesInput(c.scanner_uas, (v) => { c.scanner_uas = v; markDirty(); }, { rows: 6 })));
  }

  function alerts() {
    const a = s.alerts;
    s.report ??= { enabled: false, weekday: 1, hour: 7, recipients: [] };
    s.report.recipients ??= [];
    const rp = s.report;
    const reportPanel = panel('Wochenbericht per E-Mail', el('div.stack', null,
      el('p.muted', { style: { margin: 0 } }, 'Zusammenfassung der letzten 7 Tage: Anfragen, Blockaden, häufigste Fehlerursachen, blockierte Clients, Änderungen, Zertifikate und offene Hinweise – bei mehreren Caddy-Servern auch je Instanz.'),
      el('div.fields', null,
        el('div.field', null, el('span', null, 'Bericht'), toggle(rp.enabled, (v) => { rp.enabled = v; markDirty(); }, 'wöchentlich senden')),
        field('Wochentag', select([[1, 'Montag'], [2, 'Dienstag'], [3, 'Mittwoch'], [4, 'Donnerstag'], [5, 'Freitag'], [6, 'Samstag'], [0, 'Sonntag']], rp.weekday, (v) => { rp.weekday = +v; markDirty(); })),
        field('Uhrzeit', select(Array.from({ length: 24 }, (_, h) => [h, String(h).padStart(2, '0') + ':00']), rp.hour, (v) => { rp.hour = +v; markDirty(); }), 'Zeitzone des Panel-Servers'),
        el('div.field.wide', null, el('span', null, 'Empfänger'), linesInput(rp.recipients, (v) => { rp.recipients = v; markDirty(); }, { rows: 2, placeholder: 'it-sicherheit@example.com' }))),
      el('div.row', null,
        el('button.btn', { onclick: async () => {
          try {
            const r = await get('/report/preview');
            const frame = el('iframe', { sandbox: '', title: 'Vorschau Wochenbericht', style: { width: '100%', height: '70vh', border: '1px solid var(--line)', borderRadius: '6px', background: '#fff' } });
            frame.srcdoc = r.html;
            modal(r.subject, frame, { wide: true });
          } catch (e) { errToast(e); }
        } }, 'Vorschau'),
        el('button.btn', { onclick: async (e) => {
          const b = e.currentTarget; b.disabled = true;
          try { const r = await post('/report/send', { to: rp.recipients.join(',') }); toast('Bericht gesendet an ' + r.to.join(', '), 'ok', 5000); } catch (err) { errToast(err); } finally { b.disabled = false; }
        } }, 'Jetzt senden'),
        el('small.muted', null, 'Versand über die SMTP-Einstellungen darunter.'))));
    const hooks = el('div.stack');
    const drawHooks = () => mount(hooks, s.webhooks.length ? s.webhooks.map((w, i) => el('div.rule', null,
      el('div.rule-head', null, toggle(w.enabled, (v) => { w.enabled = v; markDirty(); }),
        el('input.name', { value: w.name, placeholder: 'Name', oninput: (e) => { w.name = e.target.value; markDirty(); } }),
        el('button.btn.sm', { onclick: async () => { try { await post('/settings/webhooks/test', w); toast('Testnachricht gesendet', 'ok'); } catch (e) { errToast(e); } } }, 'Testen'),
        el('button.icon-btn', { onclick: () => { s.webhooks.splice(i, 1); markDirty(); drawHooks(); } }, '✕')),
      el('div.rule-body', null, el('div.fields', null,
        field('Format', select([['email', 'E-Mail'], ['teams', 'Microsoft Teams (Workflows)'], ['matrix', 'Matrix'], ['ntfy', 'ntfy (Handy)'], ['telegram', 'Telegram'], ['slack', 'Slack / Mattermost / Rocket.Chat'], ['discord', 'Discord'], ['gotify', 'Gotify'], ['json', 'Generisches JSON']], w.format, (v) => { w.format = v; markDirty(); drawHooks(); })),
        w.format === 'telegram' ? null : el('div.field', { style: { gridColumn: 'span 2' } }, el('span', null, { email: 'Empfänger', matrix: 'Homeserver' }[w.format] || 'URL'), el('input.mono', { value: w.url, placeholder: { email: 'admin@example.com, it@example.com', matrix: 'https://matrix.example.org', ntfy: 'https://ntfy.sh/mein-geheimes-thema', teams: 'https://…logic.azure.com/workflows/…' }[w.format] || 'https://…', oninput: (e) => { w.url = e.target.value; markDirty(); } })),
        w.format === 'matrix' || w.format === 'telegram' ? field(w.format === 'matrix' ? 'Raum-ID' : 'Chat-ID', el('input.mono', { value: w.room || '', placeholder: w.format === 'matrix' ? '!abcdef:example.org' : '-1001234567890', oninput: (e) => { w.room = e.target.value.trim(); markDirty(); } })) : null,
        w.format === 'email' ? null : field({ matrix: 'Access-Token', telegram: 'Bot-Token', gotify: 'App-Token' }[w.format] || 'Token (optional)', el('input', { value: w.token || '', type: 'password', autocomplete: 'off', placeholder: data.secrets_set?.['webhook_' + w.id] ? '•••••• gespeichert' : '', oninput: (e) => { w.token = e.target.value; markDirty(); } }), { ntfy: 'Bearer-Token, falls das Thema geschützt ist', json: 'wird als Bearer gesendet', matrix: 'Token eines Bot-Kontos, das im Raum ist', telegram: 'von @BotFather' }[w.format] || ''),
        field('Mindest-Schwere', select([[0, 'Info'], [1, 'Niedrig'], [2, 'Mittel'], [3, 'Hoch'], [4, 'Kritisch']], w.min_severity, (v) => { w.min_severity = +v; markDirty(); })),
        field('Arten', el('input', { value: (w.types || []).join(', '), placeholder: 'alle (z. B. ban, alert, waf, config)', oninput: (e) => { w.types = e.target.value.split(',').map(x => x.trim()).filter(Boolean); markDirty(); } })))))) : el('p.muted', null, 'Noch keine Benachrichtigungen eingerichtet.'));
    drawHooks();
    mount(body,
      panel('Alarme', el('div.fields', null,
        field('5xx-Quote ab (%)', el('input', { type: 'number', min: 0, max: 100, value: Math.round(a.error_rate * 100), oninput: (e) => { a.error_rate = +e.target.value / 100; markDirty(); } }), '0 = aus · über 5 Minuten je Host'),
        field('… bei mindestens Requests', num(a, 'error_min_requests', { min: 1 })),
        field('Traffic-Spitze ab Faktor', num(a, 'spike_factor', { min: 0, step: 0.5, float: true }), 'Requests/Min. gegenüber dem 30-Minuten-Schnitt, 0 = aus'),
        field('… bei mindestens Req/Min.', num(a, 'spike_min_requests', { min: 1 })),
        field('Angriffswelle ab blockierten Req/Min.', num(a, 'attack_per_minute', { min: 0 }), '0 = aus'),
        el('div.field', null, el('span', null, 'Anstieg einer Fehlerursache'), toggle(a.cause_spike !== false, (v) => { a.cause_spike = v; markDirty(); }, 'melden – mit Bezug zu vorherigen Änderungen'),
          el('small', null, 'z. B. plötzlich viele WAF-Blockaden einer Regel, 502 von einem Backend oder ein greifendes Ratelimit.')),
        field('… ab Anfragen in 10 Min.', num(a, 'cause_min', { min: 1 })),
        field('… und ab Faktor', num(a, 'cause_factor', { min: 1, step: 0.5, float: true }), 'gegenüber dem Schnitt der Stunde davor'),
        el('div.field', null, el('span', null, 'Agent-Ausfall'), toggle(a.agent_offline, (v) => { a.agent_offline = v; markDirty(); }, 'melden, wenn sich Caddy nicht mehr meldet')),
        el('div.field', null, el('span', null, 'Zertifikate'), toggle(a.cert_expiry, (v) => { a.cert_expiry = v; markDirty(); }, 'vor Ablauf warnen')),
        el('div.field', null, el('span', null, 'Verfügbarkeit'), toggle(a.monitor_down, (v) => { a.monitor_down = v; markDirty(); }, 'Ausfälle und Wiederherstellung melden')),
        field('Panel-URL für Links', el('input', { value: s.panel_url || '', placeholder: 'https://sentinel.example.com', oninput: (e) => { s.panel_url = e.target.value; markDirty(); } })))),
      reportPanel,
      panel('E-Mail-Versand (SMTP)', el('div.fields', null,
        field('Server', el('input', { value: s.smtp.host || '', placeholder: 'smtp.example.com', oninput: (e) => { s.smtp.host = e.target.value; markDirty(); } })),
        field('Port', num(s.smtp, 'port', { min: 1, max: 65535 })),
        field('Verschlüsselung', select([['starttls', 'STARTTLS (587)'], ['tls', 'TLS (465)'], ['none', 'keine (nur intern!)']], s.smtp.security || 'starttls', (v) => { s.smtp.security = v; markDirty(); })),
        field('Absender', el('input', { value: s.smtp.from || '', placeholder: 'sentinel@example.com', oninput: (e) => { s.smtp.from = e.target.value; markDirty(); } })),
        field('Benutzer', el('input', { value: s.smtp.username || '', autocomplete: 'off', oninput: (e) => { s.smtp.username = e.target.value; markDirty(); } })),
        field('Passwort', el('input', { type: 'password', value: '', placeholder: data.secrets_set?.smtp_password ? '•••••• gespeichert – leer lassen zum Beibehalten' : '', autocomplete: 'new-password', oninput: (e) => { s.smtp.password = e.target.value; markDirty(); } })))),
      panel('Benachrichtigungen', el('div.stack', null,
        el('p.muted', { style: { margin: 0 } }, 'Mit eingetragener Panel-URL enthalten Nachrichten Knöpfe: „IP 24 h sperren“ bzw. „Sperre aufheben“, „24 h stummschalten“ und „Im Panel öffnen“. Die Links sind 24 Stunden gültig, nur einmal verwendbar und fragen vor der Aktion nach (Link-Vorschauen lösen nichts aus). Bei ntfy führen die Knöpfe die Aktion direkt aus.'),
        !s.panel_url ? el('div.callout.warn', null, 'Ohne Panel-URL (oben unter Alarme) gibt es keine Knöpfe in den Nachrichten.') : null,
        hooks,
        el('div.row', null, el('button.btn', { onclick: () => { s.webhooks.push({ id: '', name: 'Neue Benachrichtigung', url: '', format: 'teams', min_severity: 2, types: ['ban', 'alert', 'agent'], enabled: true }); markDirty(); drawHooks(); } }, 'Benachrichtigung hinzufügen')))),
      panel('Stummgeschaltet', mutesBox()));
  }

  function mutesBox() {
    const box = el('div');
    const load = () => get('/mutes').then(list => mount(box, list.length ? el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Benachrichtigung'), el('th', null, 'Bis'), el('th', null, 'Von'), el('th'))),
      el('tbody', null, list.map(m => el('tr', null, el('td', null, m.title || m.key), el('td.nowrap', { title: fmtUnix(m.until) }, fmtUntil(m.until)), el('td.muted', null, m.author),
        el('td.right', null, can('bans') ? el('button.btn.sm', { onclick: async () => { try { await del('/mutes/' + encodeURIComponent(m.key)); load(); } catch (e) { errToast(e); } } }, 'Wieder melden') : null)))))
      : el('p.muted', null, 'Nichts stummgeschaltet. Stummschalten geht über den Knopf in einer Benachrichtigung.'))).catch(e => mount(box, el('div.callout.bad', null, e.message)));
    load();
    return box;
  }

  function network() {
    mount(body,
      panel('Vertrauenswürdige Quellen', el('div.stack', null,
        el('p.muted', null, 'Diese IPs und Netze umgehen alle Sentinel-Prüfungen (Sperren, WAF, Ratelimits) – z. B. Monitoring oder das eigene Büro.'),
        linesInput(s.trusted, (v) => { s.trusted = v; markDirty(); }, { rows: 5, placeholder: '10.0.0.0/8\n192.168.178.0/24' }))),
      panel('Nie automatisch sperren', el('div.stack', null,
        el('p.muted', null, 'Das IDS sperrt diese Adressen nie, Policies gelten aber weiter.'),
        linesInput(s.ids.never_ban, (v) => { s.ids.never_ban = v; markDirty(); }, { rows: 4 }))),
      panel('GeoIP-Datenbanken', el('div.stack', null,
        el('p.muted', null, 'Für Länder-/Netz-Analysen und Geo-Regeln. Unterstützt werden .mmdb-Dateien, z. B. kostenlos „IP to Country Lite“ und „IP to ASN Lite“ von DB-IP (CC BY 4.0) oder MaxMind GeoLite2 (Konto nötig). Die Pfade gelten auf dem Caddy-Host.'),
        el('div.fields', null,
          el('div.field.wide', null, el('span', null, 'Länder-Datenbank'), el('input.mono', { value: s.geoip.country_db || '', placeholder: '/var/lib/caddy-sentinel/dbip-country-lite.mmdb', oninput: (e) => { s.geoip.country_db = e.target.value.trim(); markDirty(); } })),
          el('div.field.wide', null, el('span', null, 'ASN-Datenbank'), el('input.mono', { value: s.geoip.asn_db || '', placeholder: '/var/lib/caddy-sentinel/dbip-asn-lite.mmdb', oninput: (e) => { s.geoip.asn_db = e.target.value.trim(); markDirty(); } }))),
        (window.__status || {}).geoip ? el('small', null, 'Panel: ', window.__status.geoip) : null,
        el('small', null, 'Aktualisieren: Datei ersetzen und hier kurz einen anderen Pfad speichern oder Caddy neu laden. Ein monatliches Update per Cronjob genügt.'))),
      el('div.callout', null, 'Steht Caddy hinter einem Proxy oder Cloudflare, muss Caddy die echte Client-IP kennen – sonst würde Sentinel den Proxy sperren. Dafür im Caddyfile unter ', el('code', null, 'servers { trusted_proxies … }'), ' die Proxy-Netze eintragen.'));
  }

  async function dataTab() {
    const st = await get('/status');
    const t = s.telemetry;
    mount(body,
      panel('Telemetrie', el('div.fields', null,
        field('Stichprobe normaler Requests (%)', el('input', { type: 'number', min: 0, max: 100, value: Math.round(t.sample_rate * 100), oninput: (e) => { t.sample_rate = +e.target.value / 100; markDirty(); } }),
          'Fehler, Treffer und blockierte Requests werden immer übertragen. Zähler und Diagramme sind immer exakt.'),
        el('div.field', null, el('span', null, 'Query-Strings'), toggle(t.report_query, (v) => { t.report_query = v; markDirty(); }, 'mitspeichern (hilfreich für Analysen, kann personenbezogene Daten enthalten)')))),
      panel('Aufbewahrung', el('div.fields', null,
        field('Einzelne Requests (Stunden)', num(s.retention, 'requests_hours', { min: 1 })),
        field('Ereignisse (Tage)', num(s.retention, 'events_days', { min: 1 })),
        field('Minuten-Statistik (Tage)', num(s.retention, 'rollup_days', { min: 1 })),
        el('div.field', null, el('span', null, 'Datenbank'), el('span', null, fmtBytes(st.db_size))))),
      panel('Prometheus', el('div.stack', null,
        el('p.muted', null, 'Sentinel stellt Kennzahlen unter /metrics bereit, sobald ein Token gesetzt ist.'),
        el('div.row', null, field('Token', el('input.mono', { value: s.metrics_token || '', style: { width: '360px' }, oninput: (e) => { s.metrics_token = e.target.value; markDirty(); } })),
          el('button.btn', { onclick: () => { s.metrics_token = crypto.getRandomValues(new Uint8Array(20)).reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''); markDirty(); dataTab(); } }, 'Erzeugen')),
        s.metrics_token ? el('pre.block', null, `scrape_configs:\n  - job_name: caddy-sentinel\n    authorization:\n      credentials: ${s.metrics_token}\n    static_configs:\n      - targets: ['${location.host}']`) : null)));
  }

  async function agent() {
    const info = await get('/settings/agent');
    const st = await get('/status');
    const snippet = `{\n\tsentinel {\n\t\tpanel ${info.panel_url}\n\t\ttoken_file ${info.token_file}\n\t}\n}\n\nexample.com {\n\tsentinel\n\treverse_proxy 127.0.0.1:8080\n}`;
    mount(body,
      panel('Verbundene Agenten', info.agents.length ? el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Agent'), el('th', null, 'Status'), el('th', null, 'Version'), el('th', null, 'Caddy'), el('th', null, 'Handler'), el('th', null, 'WAF-Instanzen'), el('th', null, 'Zuletzt'))),
        el('tbody', null, info.agents.map(a => el('tr', null,
          el('td', null, el('b', null, a.id), el('small', null, ' ' + a.remote)),
          el('td', null, a.online ? el('span.badge.ok', null, 'verbunden') : el('span.badge.bad', null, 'getrennt'),
            a.errors && Object.keys(a.errors).length ? el('div', null, Object.entries(a.errors).map(([p, e]) => el('small', { style: { color: 'var(--bad)', display: 'block' } }, `${p}: ${e}`))) : null),
          el('td', null, a.version), el('td', null, a.caddy_version), el('td', null, (a.sites || []).join(', ')), el('td', null, a.waf_instances),
          el('td', null, fmtAgo(a.last_seen * 1000)))))) : empty('Kein Agent verbunden', 'Siehe Einrichtung unten.')),
      panel('Einrichtung', el('div.stack', null,
        el('p', null, 'Caddy braucht das Sentinel-Modul (eigener Build, siehe README) und liest das Agent-Token aus der Token-Datei. Die globale Option ist optional, wenn Panel und Caddy auf demselben Host mit Standardpfaden laufen.'),
        el('pre.block', null, snippet),
        el('div.row', null, el('button.btn', { onclick: () => copy(snippet) }, 'Beispiel kopieren')),
        el('dl.kv', null,
          el('dt', null, 'Caddy Admin-API'), el('dd.mono', null, st.caddy_admin, ' ', st.caddy_ok ? el('span.badge.ok', null, 'erreichbar') : el('span.badge.bad', null, 'nicht erreichbar')),
          el('dt', null, 'Caddyfile'), el('dd.mono', null, st.caddyfile, ' ', st.caddyfile_writable ? el('span.badge.ok', null, 'beschreibbar') : el('span.badge.warn', null, 'schreibgeschützt')),
          el('dt', null, 'Token-Datei'), el('dd.mono', null, info.token_file)))),
      panel('Zertifikats-Überwachung', el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'Caddy-Datenverzeichnis'), el('input.mono', { value: s.certs.storage_path || '', placeholder: '/var/lib/caddy/.local/share/caddy', oninput: (e) => { s.certs.storage_path = e.target.value.trim(); markDirty(); } }), el('small', null, 'Enthält den Ordner „certificates“. Ist er für das Panel nicht lesbar (Standard seit dem eigenen Benutzer caddy-sentinel), kommen die Zertifikate ohne Schlüssel über den lokalen Agenten.')),
        field('Warnen ab (Tage Restlaufzeit)', num(s.certs, 'warn_days', { min: 1 })))),
      panel('Agent-Token', el('div.stack', null,
        el('div.row', null, el('input.mono', { value: info.token, readonly: true, style: { flex: 1, minWidth: '280px' }, type: 'password', onfocus: (e) => { e.target.type = 'text'; }, onblur: (e) => { e.target.type = 'password'; } }),
          el('button.btn', { onclick: () => copy(info.token) }, 'Kopieren'),
          el('button.btn.danger', {
            onclick: async () => {
              if (!await confirmDialog('Token erneuern', 'Der Agent liest das neue Token beim nächsten abgewiesenen Abruf selbst aus der Datei und verbindet sich nach wenigen Sekunden neu. Agents auf anderen Servern mit eigenem Token sind nicht betroffen.', 'Erneuern')) return;
              try { await post('/settings/agent/rotate'); toast('Neues Token erzeugt', 'ok'); agent(); } catch (e) { errToast(e); }
            },
          }, 'Erneuern')))));
  }

  async function about() {
    const l = await get('/legal');
    const tp = l.third_party || '';
    const filter = el('input', { type: 'search', placeholder: 'Komponente suchen …', style: { maxWidth: '320px' } });
    const pre = el('pre.block', { style: { maxHeight: '60vh', overflow: 'auto', whiteSpace: 'pre-wrap' } }, tp);
    filter.oninput = () => {
      const q = filter.value.trim().toLowerCase();
      if (!q) { pre.textContent = tp; return; }
      // nur die Abschnitte zeigen, die den Suchbegriff enthalten
      const parts = tp.split(/\n(?======)/);
      pre.textContent = parts.filter(p => p.toLowerCase().includes(q)).join('\n') || 'Nichts gefunden.';
    };
    const dl = (name, text) => {
      const a = el('a.btn', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name }, name + ' herunterladen');
      return a;
    };
    mount(body,
      panel('Caddy Sentinel', el('div.stack', null,
        el('p', null, 'Version ', el('b', null, l.version || '?'), ' · Lizenz: ', el('a', { href: 'https://www.apache.org/licenses/LICENSE-2.0', target: '_blank', rel: 'noopener' }, 'Apache License 2.0')),
        el('pre.block', { style: { whiteSpace: 'pre-wrap' } }, l.notice || ''))),
      (l.geo_credits || []).length ? panel('GeoIP-Daten', el('div.stack', null,
        el('p.muted', null, 'Die eingebundenen GeoIP-Datenbanken verlangen diese Quellenangabe. Sie wird auch in der Seitenleiste angezeigt.'),
        el('ul', null, l.geo_credits.map(c => el('li', null, el('a', { href: c.url, target: '_blank', rel: 'noopener' }, c.text)))))) : null,
      panel('Externe Datenquellen', el('p.muted', null,
        'Threat-Feeds (Spamhaus, abuse.ch, blocklist.de, FireHOL, Emerging Threats, Tor-Projekt) und GeoIP-Datenbanken werden nicht mitgeliefert, sondern vom Betreiber geladen. Für sie gelten die Nutzungsbedingungen der jeweiligen Anbieter – vor allem bei kommerzieller Nutzung vorher prüfen.')),
      panel('Enthaltene Software Dritter', tp
        ? el('div.stack', null, el('div.row', null, filter, dl('THIRD_PARTY_LICENSES.txt', tp)), pre)
        : el('p.muted', null, 'In diesem Entwickler-Build ist die Liste nicht enthalten. Sie wird beim Release-Build erzeugt (tools/licenses) und liegt jedem Release-Archiv bei.')));
  }

  async function users() {
    const list = await get('/users');
    const box = el('div');
    const reload = () => users();
    mount(body, panel('Benutzer', el('div.stack', null,
      el('p.muted', null, 'Administratoren dürfen alles. Bearbeiter ändern Caddyfile, Policies, Regelsätze, Feeds und Monitore und setzen Sperren. Support sieht alles und setzt oder hebt Sperren auf. Leser sehen alle Daten, können aber nichts ändern.'),
      el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Benutzer'), el('th', null, 'Rolle'), el('th', null, '2FA'), el('th', null, 'Letzte Anmeldung'), el('th', null, ''))),
        el('tbody', null, list.map(u => el('tr', null,
          el('td', null, el('b', null, u.username), u.id === me.id ? el('small', null, ' (du)') : null, u.source === 'ldap' ? el('span.badge.info', { style: { marginLeft: '6px' }, title: 'Anmeldung über Active Directory; Rolle wird bei jedem Login aus den Gruppen bestimmt' }, 'AD') : null, u.display ? el('div', null, el('small.muted', null, u.display)) : null),
          el('td', null, select(ROLES.map(([k, l]) => [k, l]), u.role, async (v) => { try { await put('/users/' + u.id, { role: v }); toast('Rolle geändert', 'ok'); } catch (e) { errToast(e); reload(); } }, { disabled: u.id === me.id })),
          el('td', null, u.source === 'ldap' ? el('a', { href: '#/access?tab=users' }, 'über Site-Login') : u.totp_enabled ? el('span.badge.ok', null, 'aktiv') : el('span.badge', null, 'aus')),
          el('td', null, u.last_login ? fmtAgo(u.last_login * 1000) : '–'),
          el('td.nowrap', null,
            (u.source && u.source !== 'local') ? null : el('button.btn.sm', { onclick: async () => { const pw = await promptPw(u.username); if (!pw) return; try { await put('/users/' + u.id, { password: pw }); toast('Passwort gesetzt', 'ok'); } catch (e) { errToast(e); } } }, 'Passwort setzen'), ' ',
            u.totp_enabled ? el('button.btn.sm', { onclick: async () => { if (!await confirmDialog('2FA zurücksetzen', `${u.username} muss die Zwei-Faktor-Anmeldung danach neu einrichten.`, 'Zurücksetzen')) return; await put('/users/' + u.id, { reset_totp: true }); reload(); } }, '2FA zurücksetzen') : null, ' ',
            u.id !== me.id ? el('button.btn.sm.danger', { onclick: async () => { if (!await confirmDialog('Benutzer löschen', `${u.username} löschen?`, 'Löschen')) return; try { await del('/users/' + u.id); reload(); } catch (e) { errToast(e); } } }, 'Löschen') : null)))))),
      el('div.row', null, el('button.btn.primary', { onclick: createUser }, 'Benutzer anlegen')))));
    async function createUser() {
      let n, pw, role = 'viewer';
      modal('Benutzer anlegen', [
        field('Benutzername', n = el('input', { autocomplete: 'off' })),
        field('Passwort', pw = el('input', { type: 'password', autocomplete: 'new-password' }), 'mindestens 10 Zeichen'),
        field('Rolle', select(ROLES.map(([k, l]) => [k, l]), role, (v) => { role = v; }), ROLES.map(([, l, d]) => l + ': ' + d).join(' · ')),
      ], { actions: [{ label: 'Abbrechen' }, { label: 'Anlegen', kind: 'primary', onClick: async () => { await post('/users', { username: n.value, password: pw.value, role }); toast('Benutzer angelegt', 'ok'); reload(); } }] });
    }
    function promptPw(name) {
      return new Promise((resolve) => {
        let pw, done = false;
        modal('Neues Passwort für ' + name, field('Passwort', pw = el('input', { type: 'password', autocomplete: 'new-password' }), 'mindestens 10 Zeichen; alle Sitzungen werden beendet'), {
          actions: [{ label: 'Abbrechen' }, { label: 'Setzen', kind: 'primary', onClick: () => { done = true; resolve(pw.value); } }],
          onClose: () => { if (!done) resolve(null); },
        });
      });
    }
    void box;
  }

  function backup() {
    let fileIn, withSettings, pw1, pw2, plain, pwIn;
    const download = async () => {
      const unencrypted = plain.checked;
      if (!unencrypted) {
        if (pw1.value.length < 12) return toast('Das Passwort muss mindestens 12 Zeichen haben', 'bad');
        if (pw1.value !== pw2.value) return toast('Die Passwörter stimmen nicht überein', 'bad');
      }
      try {
        const data = await post('/backup', unencrypted ? { plain: true } : { password: pw1.value });
        const name = `caddy-sentinel-backup-${new Date().toISOString().slice(0, 10)}${unencrypted ? '.json' : '.sentinel-backup'}`;
        const a = el('a', { href: URL.createObjectURL(new Blob([JSON.stringify(data)], { type: 'application/json' })), download: name });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 10000);
        pw1.value = pw2.value = '';
        toast(unencrypted ? 'Unverschlüsselte Sicherung erstellt – sicher aufbewahren' : 'Verschlüsselte Sicherung erstellt', 'ok');
      } catch (e) { errToast(e); }
    };
    mount(body,
      panel('Sicherung herunterladen', el('div.stack', null,
        el('p.muted', null, 'Exportiert Einstellungen, Policies, Regelsätze, Threat-Feeds, Monitore, befristete Einträge, Zugangskonten und Site-Zugriffstokens. Panel-Benutzer, Statistiken und das Agent-Token sind nicht enthalten. Die Sicherung enthält Geheimnisse (SMTP-, LDAP-Passwort, OAuth-Secrets, Webhook- und Metrics-Token) sowie Passwort-Hashes und 2FA-Schlüssel der Zugangskonten. Sie wird deshalb mit einem Passwort verschlüsselt (AES-256-GCM). Ohne das Passwort lässt sie sich nicht einspielen – es gibt keine Wiederherstellung.'),
        el('div.fields', null,
          field('Passwort für die Sicherung', pw1 = el('input', { type: 'password', autocomplete: 'new-password', minlength: 12 }), 'mindestens 12 Zeichen'),
          field('Passwort wiederholen', pw2 = el('input', { type: 'password', autocomplete: 'new-password' }))),
        el('label.toggle', null, plain = el('input', { type: 'checkbox', onchange: () => { pw1.disabled = pw2.disabled = plain.checked; } }), el('span.track', null, el('span.thumb')), el('span', null, 'Unverschlüsselt herunterladen (Geheimnisse im Klartext)')),
        el('div', null, el('button.btn.primary', { onclick: download }, 'Sicherung herunterladen')))),
      panel('Sicherung einspielen', el('div.stack', null,
        el('p.muted', null, 'Policies, Regelsätze, Feeds und Monitore mit derselben ID werden überschrieben, andere bleiben erhalten. Vorhandene Zugangskonten bleiben unverändert. Geeignet auch zum Übertragen der Regeln auf einen zweiten Server.'),
        fileIn = el('input', { type: 'file', accept: 'application/json,.json,.sentinel-backup' }),
        field('Passwort (bei verschlüsselter Sicherung)', pwIn = el('input', { type: 'password', autocomplete: 'off' })),
        el('label.toggle', null, withSettings = el('input', { type: 'checkbox' }), el('span.track', null, el('span.thumb')), el('span', null, 'Auch globale Einstellungen übernehmen')),
        el('div', null, el('button.btn', {
          onclick: async () => {
            const f = fileIn.files[0];
            if (!f) return toast('Bitte eine Backup-Datei wählen', 'bad');
            try {
              const data = JSON.parse(await f.text());
              const enc = data.format === 'caddy-sentinel-backup-encrypted';
              if (enc && !pwIn.value) return toast('Die Sicherung ist verschlüsselt – bitte das Passwort eingeben', 'bad');
              const r = await post('/backup/restore', enc ? { encrypted: data, password: pwIn.value, settings: withSettings.checked } : { backup: data, settings: withSettings.checked });
              pwIn.value = '';
              const n = r.imported;
              toast(`Eingespielt: ${n.policies || 0} Policies, ${n.rulesets || 0} Regelsätze, ${n.feeds || 0} Feeds, ${n.monitors || 0} Monitore`, r.errors.length ? 'bad' : 'ok', 8000);
              if (r.errors.length) modal('Teilweise eingespielt', el('ul', null, r.errors.map(e => el('li', null, e))));
            } catch (e) { errToast(e); }
          },
        }, 'Backup einspielen')))));
  }

  function account() {
    let cur, n1, n2;
    const theme = localStorage.getItem('sentinel.theme') || 'auto';
    if (me.source && me.source !== 'local') {
      mount(body,
        panel('Verzeichniskonto', el('div.stack', null,
          me.source === 'ldap'
            ? el('p', null, 'Du bist mit deinem Active-Directory-Konto ', el('b', null, me.username), ' angemeldet. Passwort und Gruppen verwaltest du im Verzeichnis; der zweite Faktor ist derselbe wie bei der Site-Anmeldung.')
            : el('p', null, 'Du bist über ', el('b', null, me.source.replace(/^oidc:/, '')), ' (OAuth/OIDC) als ', el('b', null, me.username), ' angemeldet. Passwort und zweiter Faktor liegen beim Anbieter.'),
          el('p.muted', null, 'Deine Rolle (', roleLabel(me.role), ') ergibt sich bei jeder Anmeldung aus den Gruppen.'))),
        panel('Aktive Sitzungen', sessionsBox()));
      return;
    }
    mount(body,
      panel('Passwort ändern', el('form.stack', {
        style: { maxWidth: '420px' }, onsubmit: async (e) => {
          e.preventDefault();
          if (n1.value !== n2.value) return toast('Die neuen Passwörter stimmen nicht überein', 'bad');
          try { await post('/auth/password', { current: cur.value, new: n1.value }); toast('Passwort geändert – andere Sitzungen wurden abgemeldet', 'ok'); e.target.reset(); } catch (err) { errToast(err); }
        },
      }, field('Aktuelles Passwort', cur = el('input', { type: 'password', autocomplete: 'current-password', required: true })),
        field('Neues Passwort', n1 = el('input', { type: 'password', autocomplete: 'new-password', minlength: 10, required: true })),
        field('Wiederholen', n2 = el('input', { type: 'password', autocomplete: 'new-password', required: true })),
        el('div', null, el('button.btn.primary', { type: 'submit' }, 'Passwort ändern')))),
      panel('Zwei-Faktor-Anmeldung', twofa()),
      panel('Aktive Sitzungen', sessionsBox()),
      panel('Darstellung', field('Farbschema', select([['auto', 'wie System'], ['light', 'hell'], ['dark', 'dunkel']], theme, (v) => {
        localStorage.setItem('sentinel.theme', v);
        if (v === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', v);
      }))));
  }

  function twofa() {
    const box = el('div.stack');
    const drawBox = async () => {
      const st = await get('/auth/state');
      const u = st.user;
      if (u.totp_enabled) {
        let pw;
        mount(box, el('p', null, el('span.badge.ok', null, 'aktiv'), ' Beim Anmelden wird zusätzlich ein Code aus deiner Authenticator-App abgefragt.'),
          el('div.row', null, pw = el('input', { type: 'password', placeholder: 'Passwort zur Bestätigung', autocomplete: 'current-password' }),
            el('button.btn.danger', { onclick: async () => { try { await post('/auth/totp/disable', { password: pw.value }); toast('2FA deaktiviert', 'ok'); drawBox(); } catch (e) { errToast(e); } } }, '2FA deaktivieren')));
      } else {
        mount(box, el('p.muted', null, 'Schützt das Panel zusätzlich mit einem Einmalcode (TOTP, z. B. Aegis, Google Authenticator, 1Password, Bitwarden).'),
          el('div', null, el('button.btn.primary', {
            onclick: async () => {
              try {
                const r = await post('/auth/totp/setup');
                let code;
                mount(box,
                  el('div.row', { style: { alignItems: 'flex-start', gap: '20px' } }, el('img.qr', { src: r.qr, alt: 'QR-Code für die Authenticator-App' }),
                    el('div.stack', null, el('p', null, '1. QR-Code mit der Authenticator-App scannen oder den Schlüssel manuell eingeben:'),
                      el('code', { style: { wordBreak: 'break-all' } }, r.secret.replace(/(.{4})/g, '$1 ').trim()),
                      el('p', null, '2. Angezeigten Code eingeben:'),
                      el('div.row', null, code = el('input', { inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 7, style: { width: '120px', letterSpacing: '4px' } }),
                        el('button.btn.primary', { onclick: async () => { try { await post('/auth/totp/enable', { code: code.value }); toast('2FA aktiviert', 'ok'); drawBox(); } catch (e) { errToast(e); } } }, 'Aktivieren')))));
              } catch (e) { errToast(e); }
            },
          }, '2FA einrichten')));
      }
    };
    drawBox();
    return box;
  }

  function tokens() {
    const box = el('div');
    const load = () => get('/tokens' + (isAdmin ? '?all=1' : '')).then(list => mount(box, list.length ? el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Name'), isAdmin ? el('th', null, 'Konto') : null, el('th', null, 'Rolle'), el('th', null, 'Token'), el('th', null, 'Läuft ab'), el('th', null, 'Zuletzt benutzt'), el('th'))),
      el('tbody', null, list.map(t => el('tr', null, el('td', null, el('b', null, t.name)), isAdmin ? el('td', null, t.username) : null, el('td', null, roleLabel(t.role)),
        el('td.mono', null, t.prefix + '…'), el('td.nowrap', null, t.expires ? fmtUntil(t.expires) : 'nie'),
        el('td.nowrap', null, t.last_used ? [fmtAgo(t.last_used * 1000), el('div', null, el('small.muted', null, t.last_ip))] : 'noch nie'),
        el('td.right', null, el('button.btn.sm.danger', { onclick: async () => { if (!await confirmDialog('Token widerrufen', `„${t.name}“ ist sofort ungültig.`, 'Widerrufen')) return; try { await del('/tokens/' + t.id); load(); } catch (e) { errToast(e); } } }, 'Widerrufen'))))))) :
      el('p.muted', null, 'Noch keine API-Tokens.'))).catch(e => mount(box, el('div.callout.bad', null, e.message)));
    load();
    const create = () => {
      const st = { name: '', role: 'viewer', expires: Math.floor(Date.now() / 1000) + 90 * 86400 };
      const myRank = { viewer: 1, support: 2, editor: 3, admin: 4 }[me.role] || 1;
      modal('API-Token erstellen', el('div.stack', null,
        field('Name', el('input', { placeholder: 'z. B. Monitoring, Ansible, Ticketsystem', oninput: (e) => { st.name = e.target.value; } })),
        field('Rolle', select(ROLES.filter(([r]) => ({ viewer: 1, support: 2, editor: 3, admin: 4 }[r] <= myRank)).map(([r, l, d]) => [r, `${l} – ${d}`]), st.role, (v) => { st.role = v; }), 'Höchstens deine eigene Rolle. Das Token verliert Rechte mit deinem Konto.'),
        el('label.field', null, el('span', null, 'Läuft ab'), untilInput(st.expires, (v) => { st.expires = v; }))), {
        actions: [{ label: 'Abbrechen' }, {
          label: 'Erstellen', kind: 'primary', onClick: async () => {
            const r = await post('/tokens', st);
            load();
            modal('API-Token erstellt', el('div.stack', null,
              el('p', null, 'Das Token wird nur jetzt angezeigt – Sentinel speichert nur eine Prüfsumme.'),
              el('pre.mono', { style: { userSelect: 'all', whiteSpace: 'pre-wrap' } }, r.token),
              el('p.muted', null, 'Verwendung:'),
              el('pre.mono', { style: { whiteSpace: 'pre-wrap' } }, `curl -H "Authorization: Bearer ${r.token}" ${location.origin}/api/status`)), {
              actions: [{ label: 'Kopieren', onClick: () => { copy(r.token); return false; } }, { label: 'Fertig', kind: 'primary' }],
            });
          },
        }],
      });
    };
    mount(body, panel('API-Tokens für das Panel', el('div.stack', null,
      el('p.muted', { style: { margin: 0 } }, 'Für Skripte, Monitoring und Automatisierung: Anfragen an die Panel-API mit „Authorization: Bearer spt_…“ statt Anmeldung. Ein Token handelt im Namen seines Kontos mit der gewählten Rolle (höchstens der eigenen). Für den Zugriff auf geschützte Sites gibt es eigene Zugriffstokens unter Site-Login.'),
      box, el('div.row', null, el('button.btn.primary', { onclick: create }, 'Token erstellen')))));
  }

  function sessionsBox() {
    const box = el('div');
    const drawS = async () => {
      const r = await get('/auth/sessions');
      mount(box, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Angemeldet'), el('th', null, 'IP'), el('th', null, 'Browser'), el('th', null, ''))),
        el('tbody', null, r.sessions.map(x => el('tr', null,
          el('td.nowrap', null, fmtAgo(x.created * 1000)), el('td.mono', null, x.ip), el('td', null, el('span.trunc', { title: x.ua }, x.ua)),
          el('td', null, x.id === r.current ? el('span.badge.ok', null, 'diese Sitzung') : el('button.btn.sm', { onclick: async () => { await del('/auth/sessions/' + x.id); drawS(); } }, 'Beenden')))))));
    };
    drawS();
    return box;
  }

  draw();
  scope.listen(window, 'beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
}
