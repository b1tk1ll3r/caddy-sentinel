import { el, mount, get, post, put, del, panel, tabs, field, toggle, select, linesInput, toast, errToast, confirmDialog, prompt, modal, empty, countryLabel, fmtInt, fmtAgo, fmtDateTime, instChip, actionLabel, instState, untilInput, toLocalInput, fromLocalInput, fmtUnix, fmtUntil, stampLine, can } from '../ui.js';
import { tempPanelBody, tempDialog } from '../temp.js';
import { openTransfer } from '../transfer.js';

const fmtIntSafe = (n) => fmtInt(n || 0);
import { seg } from '../widgets.js';
import { ruleBuilder, wafMeta } from '../rulebuilder.js';
import { setActions } from '../app.js';
import { openWafAssistant } from '../waffp.js';

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'REPORT'];

function blankPolicy(name) {
  return {
    id: '', name, enabled: true, hosts: [], rulesets: [], rules: [], disabled_groups: [], notes: '',
    maintenance: false, maintenance_message: '', ip: { mode: 'off', allow: [], deny: [] }, allowed_methods: [], blocked_user_agents: [],
    honeypot_paths: ['/.env', '/.git/', '/.aws/', '/.ssh/', '/wp-config.php'], max_body_bytes: 0, rate_limits: [],
    waf: { mode: 'detect', crs: true, paranoia: 1, inbound_threshold: 5, remove_rules: [], directives: '', post_directives: '', inspect_body: true, body_limit: 1048576 },
    security_headers: { enabled: false, hsts: true, frame_options: 'SAMEORIGIN', no_sniff: true, referrer_policy: 'strict-origin-when-cross-origin', permissions_policy: '', content_security_policy: '', hide_server: true },
    block_status: 0, block_message: '', ids_overrides: { disabled: false, ban_threshold: 0, weights: {} },
  };
}

export async function render(root, [id], scope, q) {
  const [list, meta, rs, settings, feedData] = await Promise.all([get('/policies', scope.signal), wafMeta(), get('/rulesets', scope.signal), get('/settings', scope.signal), get('/feeds', scope.signal)]);
  const policies = list.policies;
  const exclude = q.get('exclude');

  if (!id) {
    const target = policies.find(p => p.id === list.default) || policies[0];
    // only a single CRS rule ID (six digits): a shared link must not prepare
    // the removal of whole ranges
    if (exclude && /^\d{6}$/.test(exclude)) return excludeFlow(root, policies, exclude, list.default);
    if (target) { location.replace('#/policies/' + target.id); return; }
  }
  const sideList = el('div.policy-list', null, policies.map(p => el('a' + (p.id === id ? '.active' : ''), { href: '#/policies/' + p.id },
    el('b', null, p.name), p.id === list.default ? el('span.badge.primary', { style: { marginLeft: '6px' } }, 'Standard') : null,
    !p.enabled ? el('span.badge', { style: { marginLeft: '6px' } }, 'aus') : null,
    p.maintenance ? el('span.badge.warn', { style: { marginLeft: '6px' } }, 'Wartung') : null,
    (p.instances || []).map(i => el('span', { style: { marginLeft: '4px' } }, instChip(i))),
    el('small', null, wafLabel(p.waf.mode), ' · ', p.hosts?.length ? p.hosts.join(', ') : (p.id === list.default ? 'alle übrigen Hosts' : 'keine Hosts')))),
    el('div', { style: { padding: '10px 14px' } }, el('button.btn', { onclick: create }, 'Neue Policy')));

  async function create() {
    const name = await prompt('Neue Policy', 'Name', 'Meine Website');
    if (!name) return;
    try {
      const p = await post('/policies', blankPolicy(name));
      location.hash = '#/policies/' + p.id;
    } catch (e) { errToast(e); }
  }

  const pol = policies.find(p => p.id === id);
  if (!pol) { mount(root, el('div.grid', { style: { gridTemplateColumns: '260px 1fr' } }, panel('Policies', sideList), panel(null, empty('Policy nicht gefunden')))); return; }
  const p = structuredClone(pol);
  p.ip ??= { mode: 'off', allow: [], deny: [] };
  p.ids_overrides ??= { weights: {} };
  p.ids_overrides.weights ??= {};
  p.rules ??= []; p.rulesets ??= []; p.disabled_groups ??= []; p.rate_limits ??= []; p.hosts ??= [];
  p.waf.remove_rules ??= [];
  p.geo ??= { mode: 'off', countries: [], asns: [], action: 'block', allow_unknown: true };
  p.geo.countries ??= []; p.geo.asns ??= [];
  p.feed_rules ??= [];
  p.challenge ??= { mode: 'off', difficulty: 16, ttl_seconds: 86400, exempt_paths: [] };
  p.challenge.exempt_paths ??= [];
  p.auth ??= { enabled: false, require_totp: true, allowed_groups: [], allowed_users: [], session_hours: 12, exempt_paths: [], bypass_networks: [], totp_skip_networks: [], bind_ip: false, pass_headers: true, title: '' };
  for (const k of ['allowed_groups', 'allowed_users', 'exempt_paths', 'bypass_networks', 'totp_skip_networks']) p.auth[k] ??= [];
  p.path_rules ??= [];
  p.test ??= { ip: false, geo: false, filters: false };
  p.instances ??= [];
  p.maintenance_allow ??= [];
  p.bots ??= {};
  p.auth.sources ??= [];
  for (const r of p.path_rules) r.schedule ??= {};
  let dirty = false;
  const saveBtn = el('button.btn.primary', { disabled: true, onclick: save }, 'Speichern');
  const markDirty = () => { dirty = true; saveBtn.disabled = false; };
  const errBox = el('div');

  // impact preview: replay the stored traffic against the edited policy
  async function impact(showAlways) {
    const res = await post(`/policies/${p.id}/impact?hours=24`, p);
    const changes = res.newly_blocked + res.newly_allowed + res.changed;
    if (!showAlways && !changes) return true;
    return new Promise((resolve) => {
      const ex = (list, cls) => list.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Anfrage'), el('th', null, 'Client'), el('th.num', null, 'Anzahl'), el('th', null, 'Bisher'), el('th', null, 'Neu'))),
        el('tbody', null, list.map(x => el('tr', null,
          el('td', null, instChip(x.inst), ' ', el('span.mono', null, `${x.method} ${x.host}${x.path}`)),
          el('td.mono', null, x.ip), el('td.num', null, fmtInt(x.count)),
          el('td.muted', null, x.before), el('td', { style: { color: cls } }, x.after)))))) : null;
      const m = modal('Auswirkung der Änderung', el('div.stack', null,
        el('p', { style: { margin: 0 } }, `Nachgespielt: ${fmtInt(res.requests)} gespeicherte Anfragen der letzten ${res.hours} Stunden an diese Policy (${fmtInt(res.distinct)} verschiedene).`),
        el('div.kpis', null,
          el('div.kpi' + (res.newly_blocked ? '.bad' : ''), null, el('div.label', null, 'Neu blockiert'), el('div.value', null, fmtInt(res.newly_blocked)), el('div', null, el('span.muted', null, `${res.clients_blocked} Clients · ${res.paths_blocked} Pfade`))),
          el('div.kpi', null, el('div.label', null, 'Neu durchgelassen'), el('div.value', null, fmtInt(res.newly_allowed))),
          el('div.kpi', null, el('div.label', null, 'Anderer Grund'), el('div.value', null, fmtInt(res.changed)))),
        !changes ? el('div.callout.ok', null, 'Die Änderung wirkt sich auf den gespeicherten Verkehr nicht aus.') : null,
        res.block_examples.length ? [el('h4', { style: { margin: '4px 0 0' } }, 'Würden künftig aufgehalten'), ex(res.block_examples, 'var(--bad)')] : null,
        res.allow_examples.length ? [el('h4', { style: { margin: '4px 0 0' } }, 'Würden künftig durchgelassen'), ex(res.allow_examples, 'var(--ok)')] : null,
        res.other_examples.length ? [el('h4', { style: { margin: '4px 0 0' } }, 'Weiterhin aufgehalten, aber anders'), ex(res.other_examples, 'var(--warn)')] : null,
        el('ul.diag-notes', null, res.notes.map(n => el('li', null, n)), res.truncated ? el('li', null, 'Nur die 3000 häufigsten Anfrageformen wurden geprüft.') : null)),
      {
        wide: true, onClose: () => resolve(false),
        actions: showAlways ? [{ label: 'Schließen' }] : [
          { label: 'Abbrechen' },
          { label: 'Als Testmodus speichern', onClick: () => { setTestEverywhere(); resolve(true); } },
          { label: res.newly_blocked ? 'Trotzdem speichern' : 'Speichern', kind: res.newly_blocked ? 'danger' : 'primary', onClick: () => { resolve(true); } },
        ],
      });
      m.box.querySelector('footer button:nth-child(2)')?.setAttribute('title', 'Neue Sperren nur protokollieren, bis die Auswertung passt');
    });
  }
  function setTestEverywhere() {
    p.test.ip = p.test.geo = p.test.filters = true;
    p.rate_limits.forEach(r => { r.test = true; });
    p.path_rules.forEach(r => { if (r.action === 'block' || r.only_networks?.length || r.api_keys?.length) r.test = true; });
  }

  async function save() {
    saveBtn.disabled = true;
    try {
      const ok = await impact(false).catch((e) => { toast('Auswirkung nicht prüfbar: ' + e.message, 'info', 5000); return true; });
      if (!ok) { saveBtn.disabled = false; return; }
      const res = await put('/policies/' + p.id, p);
      Object.assign(p, res);
      dirty = false;
      mount(errBox);
      toast(`„${p.name}“ gespeichert – Caddy übernimmt die Änderung in Sekunden`, 'ok');
      render(root, [p.id], scope, q);
    } catch (e) {
      saveBtn.disabled = false;
      mount(errBox, el('div.callout.bad', null, e.message));
      errToast(e);
    }
  }

  let tab = q.get('tab') || sessionStorage.getItem('policy.tab') || 'general';
  const tabBody = el('div.stack');
  const drawTab = () => {
    sessionStorage.setItem('policy.tab', tab);
    const botsOn = (p.bots.ai && p.bots.ai !== 'allow') || (p.bots.seo && p.bots.seo !== 'allow') || p.bots.verify_search;
    mount(tabHost, tabs([['general', p.maintenance ? 'Allgemein ●' : 'Allgemein'], ['access', 'Zugriff'], ['rate', `Ratelimits (${p.rate_limits.length})`], ['geo', 'Geo & Feeds'], ['bots', botsOn ? 'Bots ●' : 'Bots'], ['challenge', 'Bot-Challenge'], ['login', p.auth.enabled ? 'Anmeldung ●' : 'Anmeldung'], ['rules', `Pfad-Regeln (${p.path_rules.length})`], ['waf', 'WAF'], ['headers', 'Header'], ['ids', 'IDS']], tab, (t) => { tab = t; q.delete('tab'); drawTab(); }), tabBody);
    ({ general, access, rate, geo, bots, challenge, login, rules, waf, headers, ids })[tab]();
  };
  const tabHost = el('div.stack');

  // test mode switch shown at the top of a section
  function testToggle(key, what) {
    return el('div.field.wide.test-toggle', null, el('span', null, 'Testmodus'),
      toggle(!!p.test[key], (v) => { p.test[key] = v; markDirty(); }, 'nur protokollieren, nicht blockieren'),
      el('small', null, `${what}: Treffer werden als „Test: …“ erfasst, die Anfrage geht durch. Auswertung unter Allgemein.`));
  }
  const anyTest = () => p.test.ip || p.test.geo || p.test.filters || p.rate_limits.some(r => r.test) || p.path_rules.some(r => r.test && r.enabled);

  function testPanel() {
    const box = el('div', null, el('div.diag-skel', null, 'Lade Auswertung …'));
    get(`/policies/${p.id}/testmode?hours=168`).then(({ groups }) => {
      const total = groups.reduce((a, g) => a + g.count, 0);
      const parts = [
        p.test.ip ? ['ip', 'IP-Regeln'] : null, p.test.geo ? ['geo', 'Geo & Feeds'] : null, p.test.filters ? ['filters', 'Filter'] : null,
        ...p.rate_limits.filter(r => r.test).map(r => ['rl:' + r.id, 'Ratelimit „' + r.name + '“']),
        ...p.path_rules.filter(r => r.test && r.enabled).map(r => ['pr:' + r.id, 'Pfad-Regel „' + r.name + '“']),
      ].filter(Boolean);
      const arm = (k) => {
        if (k === 'ip' || k === 'geo' || k === 'filters') p.test[k] = false;
        else if (k.startsWith('rl:')) p.rate_limits.find(r => r.id === k.slice(3)).test = false;
        else if (k.startsWith('pr:')) p.path_rules.find(r => r.id === k.slice(3)).test = false;
        markDirty(); drawTab(); toast('Scharf geschaltet – zum Übernehmen speichern', 'info');
      };
      mount(box, el('div.stack', null,
        el('p', { style: { margin: 0 } }, p.test.since ? `Testmodus aktiv seit ${fmtDateTime(p.test.since * 1000)}. ` : '', total ? `In den letzten 7 Tagen wären ${fmtInt(total)} Anfragen aufgehalten worden:` : 'In den letzten 7 Tagen hätte keine Regel im Testmodus etwas blockiert.'),
        groups.length ? el('div.table-wrap', null, el('table', null,
          el('thead', null, el('tr', null, el('th', null, 'Wäre gewesen'), el('th', null, 'Detail'), el('th.num', null, 'Anfragen'), el('th.num', null, 'Clients'), el('th', null, 'Beispiel'), el('th', null, 'Zuletzt'))),
          el('tbody', null, groups.map(g => el('tr.clickable', { onclick: () => { location.hash = '#/analytics?action=' + encodeURIComponent(g.action) + '&policy=' + encodeURIComponent(p.id); } },
            el('td', null, actionLabel(g.action)), el('td.mono', null, g.detail || '–'), el('td.num', null, fmtInt(g.count)), el('td.num', null, fmtInt(g.ips)),
            el('td.mono.muted', null, g.example), el('td.muted', null, fmtAgo(g.last))))))) : null,
        parts.length ? el('div.row', null, el('b', null, 'Scharf schalten:'), parts.map(([k, l]) => el('button.btn.sm', { onclick: () => arm(k) }, l))) : null,
        el('small.muted', null, 'Erst scharf schalten, wenn in der Liste nur unerwünschte Anfragen stehen. „Auswirkung prüfen“ zeigt vor dem Speichern, was sich ändert.')));
    }).catch(e => mount(box, el('div.callout.bad', null, e.message)));
    return panel('Testmodus – was wäre blockiert worden?', box);
  }

  // ---------------- tabs
  function general() {
    mount(tabBody, anyTest() ? testPanel() : null, panel(null, el('div.fields', null,
      field('Name', el('input', { value: p.name, oninput: (e) => { p.name = e.target.value; markDirty(); } })),
      field('ID', el('input.mono', { value: p.id, disabled: true }), 'Verwendbar als `sentinel ' + p.id + '` im Caddyfile'),
      el('div.field', null, el('span', null, 'Status'), toggle(p.enabled, (v) => { p.enabled = v; markDirty(); }, p.enabled ? 'Policy aktiv' : 'Policy aus (nur Metriken, Bans gelten weiter)')),
      el('div.field.wide', null, el('span', null, 'Hosts'), linesInput(p.hosts, (v) => { p.hosts = v; markDirty(); }, { rows: 3, placeholder: 'example.com\n*.example.com' }),
        el('small', null, p.id === list.default ? 'Standard-Policy: gilt zusätzlich für alle Hosts, die keiner anderen Policy zugeordnet sind.' : 'Requests an diese Hosts nutzen diese Policy (sofern die Direktive keine Policy fest vorgibt). Wildcards wie *.example.com sind erlaubt.')),
      el('div.field.wide', null, el('span', null, 'Notizen'), el('textarea', { rows: 2, value: p.notes || '', oninput: (e) => { p.notes = e.target.value; markDirty(); } })),
      instState.multi() ? instanceScope() : null,
    )), maintenancePanel(), panel('Antwort bei Sperren', el('div.fields', null,
      field('Status-Code', el('input', { type: 'number', min: 0, max: 599, value: p.block_status || 0, oninput: (e) => { p.block_status = +e.target.value; markDirty(); } }), '0 = 403. WAF-Blocks nutzen den Status der Regel.'),
      field('Text', el('input', { value: p.block_message || '', placeholder: 'Forbidden', oninput: (e) => { p.block_message = e.target.value; markDirty(); } })),
    )));
  }

  function instanceScope() {
    const all = !p.instances.length;
    const isDef = p.id === list.default;
    return el('div.field.wide', null, el('span', null, 'Gilt auf'),
      el('div.chips', null,
        el('span.chip' + (all ? '.on' : ''), { role: 'checkbox', 'aria-checked': all ? 'true' : 'false', tabindex: 0, onclick: () => { p.instances = []; markDirty(); general(); } }, 'allen Caddy-Instanzen'),
        isDef ? null : instState.list.map(i => {
          const on = p.instances.includes(i.id);
          return el('span.chip' + (on ? '.on' : ''), { role: 'checkbox', 'aria-checked': on ? 'true' : 'false', tabindex: 0, onclick: () => { p.instances = on ? p.instances.filter(x => x !== i.id) : [...p.instances, i.id]; markDirty(); general(); } }, on ? '✓ ' : '', i.name);
        })),
      el('small', null, isDef ? 'Die Standard-Policy gilt immer überall.' : all ? 'Die Policy wird an alle Caddy-Server verteilt.' : 'Nur diese Server erhalten die Policy. Auf den anderen greift für ihre Hosts die Standard-Policy.'));
  }

  function maintenancePanel() {
    const now = Math.floor(Date.now() / 1000);
    const active = p.maintenance && (!p.maintenance_from || p.maintenance_from <= now) && (!p.maintenance_until || p.maintenance_until > now);
    const myIP = window.__status?.client_ip;
    return panel('Wartungsmodus', el('div.stack', null,
      p.maintenance ? el('div.callout.' + (active ? 'warn' : 'info'), null, active ? 'Wartung ist aktiv' : 'Wartung ist geplant', p.maintenance_from > now ? ' ab ' + fmtUnix(p.maintenance_from) : '', p.maintenance_until ? ' bis ' + fmtUnix(p.maintenance_until) + ' – danach schaltet Sentinel sie selbst aus.' : ' – ohne geplantes Ende.') : null,
      el('div.fields', null,
        el('div.field', null, el('span', null, 'Wartung'), toggle(p.maintenance, (v) => { p.maintenance = v; markDirty(); general(); }, 'Besucher sehen eine Wartungsseite (503)')),
        field('Meldung', el('input', { value: p.maintenance_message || '', placeholder: 'Wartungsarbeiten – bitte später erneut versuchen.', oninput: (e) => { p.maintenance_message = e.target.value; markDirty(); } }), 'Mit geplantem Ende nennt die Seite die Uhrzeit, ab der es weitergeht.'),
        field('Beginn', el('input', { type: 'datetime-local', value: toLocalInput(p.maintenance_from), onchange: (e) => { p.maintenance_from = fromLocalInput(e.target.value); markDirty(); } }), 'leer = sofort'),
        el('label.field', null, el('span', null, 'Ende'), untilInput(p.maintenance_until || 0, (v) => { p.maintenance_until = v; markDirty(); })),
        el('div.field.wide', null, el('span', null, 'Trotzdem erreichbar für'), linesInput(p.maintenance_allow, (v) => { p.maintenance_allow = v; markDirty(); }, { rows: 2, placeholder: '192.168.10.0/24' }),
          el('small', null, 'Netze, die während der Wartung normal zugreifen – z. B. die IT zum Testen. Vertrauenswürdige IPs und Pfad-Regeln mit „auch bei Wartung“ kommen ebenfalls durch. ',
            myIP ? el('a', { href: '#', onclick: (e) => { e.preventDefault(); if (!p.maintenance_allow.includes(myIP)) p.maintenance_allow.push(myIP); markDirty(); general(); } }, 'Meine IP (' + myIP + ') eintragen') : null)))));
  }

  function access() {
    const polById = Object.fromEntries(policies.map(x => [x.id, x.name]));
    const temp = tempPanelBody(p.id, polById);
    mount(tabBody,
      panel('IP-Regeln', el('div.fields', null,
        testToggle('ip', 'IP-Freigabe- und Sperrliste'),
        el('div.field.wide', null, el('span', null, 'Modus'), seg([['off', 'Alle zulassen (außer Sperrliste)'], ['allowlist', 'Nur Freigabeliste zulassen', 'warn']], p.ip.mode, (v) => { p.ip.mode = v; markDirty(); })),
        field('Freigabeliste', linesInput(p.ip.allow, (v) => { p.ip.allow = v; markDirty(); }, { placeholder: '192.168.0.0/16\n2001:db8::/32' }), 'Nur im Modus „Nur Freigabeliste“ wirksam.'),
        field('Sperrliste', linesInput(p.ip.deny, (v) => { p.ip.deny = v; markDirty(); }, { placeholder: '203.0.113.0/24' }), 'Gilt nur für diese Policy. Globale Sperren unter Sicherheit.'))),
      panel('Methoden & Clients', el('div.fields', null,
        testToggle('filters', 'Methoden, User-Agents, Honeypots und Body-Größe'),
        el('div.field.wide', null, el('span', null, 'Erlaubte Methoden'), el('div.chips', null, METHODS.map(m => {
          const on = p.allowed_methods.includes(m);
          return el('span.chip' + (on ? '.on' : ''), {
            role: 'checkbox', 'aria-checked': on ? 'true' : 'false', tabindex: 0,
            onclick: (e) => { p.allowed_methods = on ? p.allowed_methods.filter(x => x !== m) : [...p.allowed_methods, m]; markDirty(); access(); },
          }, m);
        })), el('small', null, p.allowed_methods.length ? 'Andere Methoden erhalten 405.' : 'Keine Auswahl = alle Methoden erlaubt.')),
        field('Gesperrte User-Agents', linesInput(p.blocked_user_agents, (v) => { p.blocked_user_agents = v; markDirty(); }, { placeholder: 'python-requests\nGPTBot' }), 'Teilstring, Groß-/Kleinschreibung egal.'),
        field('Honeypot-Pfade', linesInput(p.honeypot_paths, (v) => { p.honeypot_paths = v; markDirty(); }, { placeholder: '/.env\n/wp-login.php' }), 'Pfad-Präfixe, die echte Besucher nie aufrufen. Antwort 404, das IDS bewertet den Treffer hoch.'),
        field('Max. Request-Body', el('div.row', null, el('input', { type: 'number', min: 0, value: p.max_body_bytes ? Math.round(p.max_body_bytes / 1048576) : 0, oninput: (e) => { p.max_body_bytes = Math.round(+e.target.value * 1048576); markDirty(); } }), 'MiB'), '0 = unbegrenzt. Größere Uploads erhalten 413.'))),
      panel('Befristete Einträge', el('div.stack', null,
        el('p.muted', { style: { margin: 0 } }, 'Freigaben oder Sperren mit Enddatum, z. B. das Netz eines Dienstleisters bis Freitag. Sie gelten sofort (ohne Speichern) und verschwinden von selbst.'),
        temp,
        can('policy') ? el('div.row', null, el('button.btn', { onclick: () => tempDialog({ scope: p.id, list: p.ip.mode === 'allowlist' ? 'allow' : 'deny', policies, onDone: () => temp.reload() }, modal) }, 'Befristet eintragen …'),
          p.ip.mode !== 'allowlist' ? el('small.muted', null, 'Hinweis: Einträge in der Erlaubt-Liste wirken nur im Modus „Nur Freigabeliste“.') : null) : null)));
  }

  function bots() {
    const b = p.bots;
    const act = (k) => seg([['', 'erlauben'], ['limit', 'bremsen', 'warn'], ['block', 'sperren', 'bad']], b[k] || '', (v) => { b[k] = v; markDirty(); bots(); });
    mount(tabBody, panel('Bots & Crawler', el('div.stack', null,
      el('p.muted', { style: { margin: 0 } }, 'Sentinel erkennt bekannte Crawler am User-Agent. Echte Besucher sind nicht betroffen. „Bremsen“ erlaubt einem Crawler pro IP nur eine bestimmte Zahl Anfragen pro Minute, danach 429 – seriöse Crawler halten sich daran.'),
      p.test.filters ? el('div.callout.warn', null, 'Testmodus für Filter ist aktiv: Bot-Sperren werden nur protokolliert.') : null,
      el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'KI-Crawler'), act('ai'), el('small', null, 'GPTBot, ChatGPT-User, ClaudeBot, PerplexityBot, CCBot (Common Crawl), Bytespider, Amazonbot, Meta, Applebot-Extended, Diffbot, cohere … – sammeln Inhalte für KI-Modelle und KI-Suche.')),
        el('div.field.wide', null, el('span', null, 'SEO-Crawler'), act('seo'), el('small', null, 'AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, DataForSeoBot … – erzeugen viel Last, nützen meist nur Dritten.')),
        field('Anfragen pro Minute beim Bremsen', el('input', { type: 'number', min: 1, max: 10000, value: b.limit_per_minute || 10, oninput: (e) => { b.limit_per_minute = +e.target.value; markDirty(); } }), 'je Crawler und IP'),
        el('div.field.wide', null, el('span', null, 'Suchmaschinen prüfen'), toggle(!!b.verify_search, (v) => { b.verify_search = v; markDirty(); }, 'falsche Googlebots, Bingbots … sperren'),
          el('small', null, 'Echte Suchmaschinen bleiben erlaubt. Wer sich als Googlebot, Bingbot, Applebot, YandexBot, Baiduspider oder PetalBot ausgibt, wird per Reverse-DNS und Gegenprobe geprüft (Ergebnis 24 h gecacht). Fälschungen erhalten 403 und erhöhen den Bedrohungs-Score. Ist DNS gestört, lässt Sentinel die Anfrage durch.'))),
      el('div.callout', null, 'Tipp: Ergänzend kann eine robots.txt die KI-Crawler höflich ausladen – Sentinel setzt die Entscheidung aber auch bei Crawlern durch, die robots.txt ignorieren.'))));
  }

  function rate() {
    const rows = el('div');
    const draw = () => mount(rows, p.rate_limits.length ? p.rate_limits.map((r, i) => el('div.rl-row', null,
      field('Name', el('input', { value: r.name, oninput: (e) => { r.name = e.target.value; markDirty(); } })),
      field('Pfad-Präfixe', el('input', { value: (r.path_prefixes || []).join(', '), placeholder: 'alle', oninput: (e) => { r.path_prefixes = e.target.value.split(',').map(s => s.trim()).filter(Boolean); markDirty(); } })),
      field('Requests', el('input', { type: 'number', min: 1, value: r.requests, style: { width: '80px' }, oninput: (e) => { r.requests = +e.target.value; markDirty(); } })),
      field('pro Sek.', el('input', { type: 'number', min: 1, value: r.window_seconds, style: { width: '90px' }, oninput: (e) => { r.window_seconds = +e.target.value; markDirty(); } })),
      field('Zählen pro', select([['ip', 'Client-IP'], ['ip_path', 'IP + Pfad'], ['global', 'alle zusammen'], ['user', 'angemeldeter Benutzer (Site-Login)'], ['header:Authorization', 'Authorization-Header'], ['header:X-Api-Key', 'X-Api-Key']], r.key || 'ip', (v) => { r.key = v; markDirty(); })),
      field('Methoden', el('input', { value: (r.methods || []).join(' '), placeholder: 'alle', oninput: (e) => { r.methods = e.target.value.toUpperCase().split(/[\s,]+/).filter(Boolean); markDirty(); } })),
      field('Bei Überschreitung', select([['reject', '429 senden'], ['ban', '429 + IP sperren']], r.action || 'reject', (v) => { r.action = v; markDirty(); draw(); })),
      el('div.row', { style: { gap: '4px' } },
        r.action === 'ban' ? field('Sperre (Min.)', el('input', { type: 'number', min: 1, value: Math.round((r.ban_seconds || 600) / 60), style: { width: '80px' }, oninput: (e) => { r.ban_seconds = +e.target.value * 60; markDirty(); } })) : null,
        el('button.icon-btn', { title: 'Entfernen', onclick: () => { p.rate_limits.splice(i, 1); markDirty(); draw(); } }, '✕')),
      el('div.field', null, el('span', null, 'Testmodus'), toggle(!!r.test, (v) => { r.test = v; markDirty(); }, 'nur protokollieren')),
      el('div', { style: { gridColumn: '1 / -1' } }, field('Pfad-Regex (optional)', el('input.mono', { value: r.path_regex || '', placeholder: '^/api/v[0-9]+/login$', oninput: (e) => { r.path_regex = e.target.value; markDirty(); } }))),
      el('div', { style: { gridColumn: '1 / -1' } }, field('Notiz', el('input', { value: r.note || '', placeholder: 'Warum gibt es das Limit? (z. B. Ticket, Vorfall)', oninput: (e) => { r.note = e.target.value; markDirty(); } })), stampLine(r)),
    )) : el('p.muted', null, 'Keine Ratelimits.'));
    draw();
    mount(tabBody, panel('Ratelimits', el('div.stack', null,
      el('p.muted', null, 'Gleitendes Fenster pro Schlüssel. Die erste passende Regel, deren Limit überschritten ist, greift. Typisch: großzügiges Limit für alles, strenges für Login-Pfade.'),
      rows,
      el('div.row', null,
        el('button.btn', { onclick: () => { p.rate_limits.push({ id: '', name: 'Neues Limit', key: 'ip', requests: 120, window_seconds: 60, action: 'reject', path_prefixes: [], methods: [] }); markDirty(); draw(); } }, 'Limit hinzufügen'),
        el('button.btn.ghost', { onclick: () => { p.rate_limits.push({ id: '', name: 'Login-Schutz', key: 'ip', requests: 10, window_seconds: 60, action: 'ban', ban_seconds: 1800, path_prefixes: ['/login', '/wp-login.php', '/user/login', '/api/auth'], methods: ['POST'] }); markDirty(); draw(); } }, 'Vorlage: Login-Schutz')))));
  }

  function geo() {
    const g = p.geo;
    const hasGeo = !!(settings.settings.geoip?.country_db || settings.settings.geoip?.asn_db);
    const chips = el('div.chips');
    const drawChips = () => mount(chips, g.countries.length ? g.countries.map(cc => el('span.chip.on', { title: 'Entfernen', onclick: () => { g.countries = g.countries.filter(x => x !== cc); markDirty(); drawChips(); } }, countryLabel(cc), ' ✕')) : el('small', null, 'Keine Länder ausgewählt'));
    drawChips();
    const addInput = el('input', {
      placeholder: 'Ländercodes, z. B. DE AT CH', style: { width: '240px' },
      onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); addCodes(e.target.value); e.target.value = ''; } },
    });
    const addCodes = (txt) => {
      const codes = txt.toUpperCase().split(/[\s,;]+/).filter(c => /^[A-Z]{2}$/.test(c));
      g.countries = [...new Set([...g.countries, ...codes])];
      markDirty(); drawChips();
    };
    const preset = (label, codes) => el('button.btn.sm.ghost', { onclick: () => addCodes(codes) }, label);
    const feedRows = el('div.stack', { style: { gap: '6px' } });
    const drawFeeds = () => mount(feedRows, feedData.feeds.length ? feedData.feeds.map(f => {
      const rule = p.feed_rules.find(r => r.feed === f.id);
      return el('div.row', { style: { justifyContent: 'space-between', borderBottom: '1px solid var(--line-2)', paddingBottom: '6px' } },
        el('div', null, el('b', null, f.name), el('small', null, ` · ${fmtIntSafe(f.count)} Einträge`), !f.enabled ? el('span.badge', { style: { marginLeft: '6px' } }, 'Liste aus') : null),
        seg([['', 'ignorieren'], ['log', 'markieren', 'warn'], ['challenge', 'Challenge', 'warn'], ['block', 'blockieren', 'bad']], rule?.action || '', (v) => {
          p.feed_rules = p.feed_rules.filter(r => r.feed !== f.id);
          if (v) p.feed_rules.push({ feed: f.id, action: v });
          markDirty();
        }));
    }) : el('p.muted', null, 'Noch keine Threat-Feeds. ', el('a', { href: '#/feeds' }, 'Feeds einrichten')));
    drawFeeds();
    mount(tabBody,
      !hasGeo ? el('div.callout.warn', null, 'Für Länder- und Netzregeln braucht Sentinel eine GeoIP-Datenbank (z. B. kostenlos von DB-IP oder MaxMind GeoLite2). Pfad unter ', el('a', { href: '#/settings?tab=network' }, 'Einstellungen › Netz & Vertrauen'), ' eintragen.') : null,
      panel('Länder', el('div.stack', null,
        testToggle('geo', 'Länder, Netze und Threat-Feeds'),
        el('div.row', null, el('b', null, 'Modus'), seg([['off', 'Aus'], ['deny', 'Ausgewählte Länder betreffen', 'warn'], ['allow', 'Nur ausgewählte Länder zulassen', 'warn']], g.mode, (v) => { g.mode = v; markDirty(); })),
        el('div.row', null, el('b', null, 'Aktion'), seg([['block', 'Blockieren', 'bad'], ['challenge', 'Bot-Challenge', 'warn']], g.action || 'block', (v) => { g.action = v; markDirty(); }),
          toggle(g.allow_unknown, (v) => { g.allow_unknown = v; markDirty(); }, 'Unbekannte Herkunft zulassen')),
        chips,
        el('div.row', null, addInput, el('button.btn.sm', { onclick: () => { addCodes(addInput.value); addInput.value = ''; } }, 'Hinzufügen'),
          el('span.muted', null, 'Schnellauswahl:'), preset('DACH', 'DE AT CH'), preset('EU', 'AT BE BG CY CZ DE DK EE ES FI FR GR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK'),
          el('button.btn.sm.ghost', { onclick: () => { g.countries = []; markDirty(); drawChips(); } }, 'Leeren')),
        el('small', null, 'Beispiel: Nur DACH zulassen und den Rest per Challenge prüfen – echte Besucher aus dem Urlaub kommen so trotzdem durch.'))),
      panel('Netze (ASN)', el('div.stack', null,
        field('Betroffene Autonomous Systems', el('input', { value: g.asns.join(', '), placeholder: 'z. B. 14061, 16276, 24940 (Hosting-Provider)', oninput: (e) => { g.asns = e.target.value.split(/[\s,;]+/).map(x => parseInt(x.replace(/^AS/i, ''), 10)).filter(Boolean); markDirty(); } }),
          'Requests aus diesen Netzen bekommen dieselbe Aktion wie die Länderregel. Nützlich gegen Bots aus Rechenzentren. Die ASN siehst du in Analysen › Netze.'))),
      panel('Threat-Feeds', el('div.stack', null, el('p.muted', null, 'Was soll mit Requests von IPs passieren, die in einer Liste stehen?'), feedRows)));
  }

  function login() {
    const a = p.auth;
    const dir = settings.settings.directory || {};
    const provs = (settings.settings.oauth || []).filter(x => x.enabled && x.site_login);
    const hostHint = p.hosts?.length ? p.hosts[0] : 'deine-site';
    const srcs = [['directory', 'Domänenkonten (AD/LDAP)', dir.enabled ? '' : 'nicht eingerichtet'], ['local', 'Zugangskonten (lokal in Sentinel)', ''], ...provs.map(x => ['oidc:' + x.id, x.name + ' (OAuth/OIDC)', ''])];
    const srcBox = el('div.chips', null, srcs.map(([k, l, warn]) => {
      const on = !a.sources.length || a.sources.includes(k);
      return el('span.chip' + (on ? '.on' : ''), {
        role: 'checkbox', 'aria-checked': on ? 'true' : 'false', tabindex: 0, title: warn,
        onclick: () => {
          let cur = a.sources.length ? [...a.sources] : srcs.map(x => x[0]);
          cur = on ? cur.filter(x => x !== k) : [...cur, k];
          if (!cur.length) { toast('Mindestens eine Anmeldemethode muss bleiben', 'bad'); return; }
          a.sources = cur.length === srcs.length ? [] : cur;
          markDirty(); login();
        },
      }, on ? '✓ ' : '', l, warn ? el('small', null, ' – ' + warn) : null);
    }));
    mount(tabBody,
      panel('Anmeldung vor der Site', el('div.stack', null,
        el('p.muted', null, 'Besucher müssen sich anmelden, bevor Caddy die Site ausliefert – mit Domänenkonto (AD), lokalem Zugangskonto oder über einen OAuth-Anbieter wie Microsoft Entra ID oder Google, optional mit zweitem Faktor (TOTP). Skripte und Dienste weisen sich mit einem Zugriffstoken aus (Authorization: Bearer sst_…). Danach gilt ein signiertes Sitzungs-Cookie.'),
        el('div.field', null, el('span', null, 'Anmeldemethoden'), srcBox, el('small', null, 'Alle markierten werden auf der Anmeldeseite angeboten. ', el('a', { href: '#/access' }, 'Konten, Tokens und Anbieter verwalten'))),
        el('div.fields', null,
          el('div.field', null, el('span', null, 'Anmeldung'), toggle(a.enabled, (v) => { a.enabled = v; markDirty(); drawTab(); }, a.enabled ? 'Login erforderlich' : 'aus')),
          el('div.field', null, el('span', null, 'Zweiter Faktor'), toggle(a.require_totp, (v) => { a.require_totp = v; markDirty(); }, 'TOTP verlangen (Authenticator-App)'), el('small', null, 'Anbieter mit „MFA beim Anbieter“ zählen als zwei Faktoren; Zugriffstokens ersetzen Login und Code.')),
          field('Sitzungsdauer (Stunden)', el('input', { type: 'number', min: 1, max: 2160, value: a.session_hours || 12, oninput: (e) => { a.session_hours = +e.target.value; markDirty(); } }), 'Danach ist eine neue Anmeldung nötig.'),
          field('Titel der Login-Seite', el('input', { value: a.title || '', placeholder: hostHint, oninput: (e) => { a.title = e.target.value; markDirty(); } })),
          el('div.field.wide', null, el('span', null, 'Erlaubte Gruppen'), linesInput(a.allowed_groups, (v) => { a.allowed_groups = v; markDirty(); }, { rows: 3, placeholder: 'Wiki-Benutzer\nCN=IT-Admins,OU=Gruppen,DC=firma,DC=local' }),
            el('small', null, 'AD-Gruppe, Gruppe eines Zugangskontos oder Gruppe/Rolle vom OAuth-Anbieter – eine pro Zeile. Ein voller DN (CN=…,OU=…) passt nur auf genau diese AD-Gruppe; ein reiner Name auf jede gleichnamige Gruppe aus jeder Quelle. Leer = jedes Konto der erlaubten Anmeldemethoden.')),
          el('div.field.wide', null, el('span', null, 'Zusätzlich erlaubte Benutzer'), linesInput(a.allowed_users, (v) => { a.allowed_users = v; markDirty(); }, { rows: 2, placeholder: 'max.mustermann' }), el('small', null, 'Benutzername, unabhängig von den Gruppen.'))))),
      panel('Ausnahmen', el('div.fields', null,
        field('Pfade ohne Anmeldung', linesInput(a.exempt_paths, (v) => { a.exempt_paths = v; markDirty(); }, { placeholder: '/public/\n/api/webhook' }), 'Pfad-Präfixe, z. B. für Webhooks oder öffentliche Dateien.'),
        field('Netze ohne Anmeldung', linesInput(a.bypass_networks, (v) => { a.bypass_networks = v; markDirty(); }, { placeholder: '10.10.0.0/16' }), 'Clients aus diesen Netzen brauchen gar keinen Login (Vorsicht).'),
        field('Netze ohne 2FA', linesInput(a.totp_skip_networks, (v) => { a.totp_skip_networks = v; markDirty(); }, { placeholder: '192.168.10.0/24' }), 'Hier reicht das Passwort, z. B. im Büro-LAN.'))),
      panel('Sitzung & Weitergabe', el('div.stack', null,
        el('div.fields', null,
          el('div.field', null, el('span', null, 'An IP binden'), toggle(a.bind_ip, (v) => { a.bind_ip = v; markDirty(); }, 'Cookie nur von derselben IP gültig')),
          el('div.field', null, el('span', null, 'Header ans Backend'), toggle(a.pass_headers, (v) => { a.pass_headers = v; markDirty(); }, 'Remote-User, Remote-Name, Remote-Email, Remote-Groups')),
          el('div.field', null, el('span', null, 'Single Sign-on'), settings.settings.sso?.enabled
            ? toggle(a.sso, (v) => { a.sso = v; markDirty(); }, `Anmeldung gilt für alle SSO-Sites unter ${settings.settings.sso.domain}`)
            : el('small', null, 'nicht eingerichtet – ', el('a', { href: '#/access?tab=directory' }, 'Site-Login › Verzeichnis')))),
        el('div.callout', null, 'Login-Seite: ', el('code', null, '/.sentinel/auth/login'), ' · Konto: ', el('code', null, '/.sentinel/auth/me'), ' (auch als JSON) · Abmelden: ', el('code', null, '/.sentinel/auth/logout'), '. Einzelne Bereiche (ohne Login, andere Gruppen, 2FA nur für den Admin-Bereich, API-Schlüssel) regelst du unter „Pfad-Regeln“. Anfragen ohne Sitzung leitet Sentinel im Browser zur Anmeldung um, API-Clients erhalten 401. Gleichnamige Header vom Client werden immer entfernt; im Caddyfile steht der Benutzer als ', el('code', null, '{http.vars.sentinel.user}'), ' bereit (z. B. für Logs).'))));
  }

  function rules() {
    const list = el('div.stack');
    const drawList = () => mount(list, p.path_rules.length ? p.path_rules.map((r, i) => ruleCard(r, i)) :
      empty('Keine Pfad-Regeln', 'Alle Requests werden nach den Einstellungen der Policy behandelt. Vorlagen oben fügen typische Ausnahmen hinzu.'));
    const add = (r) => { p.path_rules.push(r); markDirty(); drawList(); editRule(r, true); };
    mount(tabBody,
      panel('Pfad-Regeln', el('div.stack', null,
        el('p.muted', null, 'Ausnahmen und abweichende Einstellungen für einzelne Bereiche der Site – z. B. ein Admin-Bereich nur aus dem LAN und nur für eine AD-Gruppe mit 2FA, ein öffentlicher Bereich ohne Anmeldung, Webhooks mit API-Schlüssel statt Login oder eine alte URL, die weiterleitet. Die Regeln werden von oben nach unten geprüft, die erste passende gilt.'),
        el('div.row', null, el('b', null, 'Vorlagen:'), ...RULE_PRESETS.map(([label, mk]) => el('button.btn.sm', { onclick: () => add(Object.assign(blankRule(), mk())) }, label))),
        list,
        el('div.row', null, el('button.btn.primary', { onclick: () => add(blankRule()) }, 'Regel hinzufügen'),
          el('a.btn.ghost', { href: '#/flow?policy=' + encodeURIComponent(p.id) }, 'Im Fluss-Simulator testen')))));
    drawList();

    function ruleCard(r, i) {
      const chips = ruleSummary(r);
      return el('div.rule' + (r.enabled ? '' : '.off'), null,
        el('div.rule-head', null,
          toggle(r.enabled, (v) => { r.enabled = v; markDirty(); drawList(); }),
          el('b', null, `${i + 1}. ${r.name}`),
          r.test ? el('span.badge.test', { title: 'Sperren dieser Regel werden nur protokolliert' }, 'Testmodus') : null,
          r.until ? el('span.badge.' + (r.until * 1000 < Date.now() ? 'bad' : 'warn'), { title: 'Endet ' + fmtUnix(r.until) }, r.until * 1000 < Date.now() ? 'abgelaufen' : 'bis ' + fmtUnix(r.until)) : null,
          r.schedule?.mode ? el('span.badge.info', { title: 'Zeitplan' }, scheduleLabel(r.schedule)) : null,
          el('span.grow'),
          el('button.icon-btn', { title: 'nach oben', disabled: i === 0, onclick: () => { [p.path_rules[i - 1], p.path_rules[i]] = [p.path_rules[i], p.path_rules[i - 1]]; markDirty(); drawList(); } }, '↑'),
          el('button.icon-btn', { title: 'nach unten', disabled: i === p.path_rules.length - 1, onclick: () => { [p.path_rules[i + 1], p.path_rules[i]] = [p.path_rules[i], p.path_rules[i + 1]]; markDirty(); drawList(); } }, '↓'),
          el('button.btn.sm', { onclick: () => editRule(r) }, 'Bearbeiten'),
          el('button.btn.sm.danger', { onclick: async () => { if (!await confirmDialog('Regel löschen', `„${r.name}“ löschen?`, 'Löschen')) return; p.path_rules.splice(i, 1); markDirty(); drawList(); } }, 'Löschen')),
        el('div.rule-body', null, el('div.chips', null, chips.when.map(c => el('span.chip', null, c))), el('div.chips', { style: { marginTop: '6px' } }, chips.then.map(([c, k]) => el('span.chip' + (k ? '.' + k : ''), null, c))),
          r.note ? el('div.rule-note', null, '📝 ', r.note) : null, stampLine(r)));
    }

    function editRule(orig, isNew) {
      const r = structuredClone(orig);
      r.response_headers ??= {};
      let hdrText = Object.entries(r.response_headers).map(([k, v]) => `${k}: ${v}`).join('\n');
      const keysBox = el('div.stack', { style: { gap: '6px' } });
      const drawKeys = () => mount(keysBox, r.api_keys.length ? el('table', null, el('tbody', null, r.api_keys.map((k, ki) => el('tr', null,
        el('td', null, el('b', null, k.name || 'Schlüssel')), el('td.mono', null, k.prefix + '…'), el('td', null, k.created ? new Date(k.created * 1000).toLocaleDateString('de-DE') : ''),
        el('td.right', null, el('button.btn.sm.danger', { onclick: () => { r.api_keys.splice(ki, 1); drawKeys(); } }, 'Entfernen')))))) : el('span.muted', null, 'Kein Schlüssel – der Bereich ist ohne Schlüssel erreichbar.'),
        el('div.row', null, el('button.btn.sm', {
          onclick: async () => {
            const name = await prompt('Neuer API-Schlüssel', 'Bezeichnung (z. B. GitLab-Webhook)', '');
            if (name === null) return;
            const k = await post('/apikey', { name });
            r.api_keys.push(k.api_key); drawKeys();
            modal('API-Schlüssel erstellt', [el('p', null, 'Der Schlüssel wird nur jetzt angezeigt – Sentinel speichert nur eine Prüfsumme.'), el('pre.mono', { style: { userSelect: 'all', whiteSpace: 'pre-wrap' } }, k.key),
              el('p.muted', null, (r.api_key_header || 'X-API-Key') === 'Authorization' ? 'Senden als: Authorization: Bearer <Schlüssel>' : `Senden als Header ${r.api_key_header || 'X-API-Key'}: <Schlüssel>`)],
            { actions: [{ label: 'Kopieren', onClick: () => { navigator.clipboard?.writeText(k.key); toast('Kopiert', 'ok'); return false; } }, { label: 'Fertig', kind: 'primary' }] });
          },
        }, 'Schlüssel erzeugen'), field('Header', select([['', 'X-API-Key'], ['Authorization', 'Authorization: Bearer …'], ['X-Gitlab-Token', 'X-Gitlab-Token'], ['X-Webhook-Token', 'X-Webhook-Token']], r.api_key_header || '', (v) => { r.api_key_header = v; }))));
      const actionExtra = el('div');
      const drawAction = () => mount(actionExtra, r.action === 'redirect' ? el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'Ziel'), el('input.mono', { value: r.redirect_url || '', placeholder: 'https://neu.example.com{uri} oder /neu{path}', oninput: (e) => { r.redirect_url = e.target.value; } }), el('small', null, 'Platzhalter: {path}, {query}, {uri} (Pfad + Query), {host}')),
        field('Status', select([[302, '302 vorübergehend'], [301, '301 dauerhaft'], [307, '307 vorübergehend (Methode bleibt)'], [308, '308 dauerhaft (Methode bleibt)']], r.redirect_status || 302, (v) => { r.redirect_status = +v; }))) :
        r.action === 'allow' ? el('div.callout.warn', null, 'Durchlassen überspringt Geo-/Feed-Regeln, Methoden-, User-Agent- und Honeypot-Filter, IP-Freigabeliste, Ratelimits, Bot-Challenge, Anmeldung und WAF. Sperren, die Sperrliste der Policy und „Nur aus Netzen“ gelten weiter.') :
        r.action === 'block' ? el('p.muted', null, 'Passende Requests erhalten 403. Treffer erhöhen den Bedrohungs-Score (Signal „Pfad-Sperre“).') : null);
      drawAction();
      modal(isNew ? 'Neue Pfad-Regel' : 'Pfad-Regel bearbeiten', [
        el('div.fields', null,
          field('Name', el('input', { value: r.name, oninput: (e) => { r.name = e.target.value; } })),
          el('div.field', null, el('span', null, 'Aktiv'), toggle(r.enabled, (v) => { r.enabled = v; }, 'Regel anwenden')),
          el('div.field', null, el('span', null, 'Testmodus'), toggle(!!r.test, (v) => { r.test = v; }, 'Sperren nur protokollieren'), el('small', null, 'Sperre, „Nur aus Netzen“ und API-Schlüssel greifen noch nicht – sichtbar in Analysen und Fehleranalyse als „Test: …“.')),
          el('div.field.wide', null, el('span', null, 'Notiz'), el('input', { value: r.note || '', placeholder: 'Warum gibt es die Regel? (Ticket, Ansprechpartner …)', oninput: (e) => { r.note = e.target.value; } }))),
        el('h4', null, 'Wann gilt die Regel?'),
        scheduleEditor(r),
        el('h4', null, 'Wenn …'),
        el('div.fields', null,
          el('div.field.wide', null, el('span', null, 'Pfade'), linesInput(r.paths, (v) => { r.paths = v; }, { rows: 3, placeholder: '/admin/\n=/login\n/files/*.pdf\n~^/api/v[0-9]+/' }),
            el('small', null, '/admin/ = beginnt mit · =/login = genau · * und ** = Platzhalter · ~… = regulärer Ausdruck · leer = alle Pfade')),
          field('Methoden', linesInput(r.methods, (v) => { r.methods = v.map(x => x.toUpperCase()); }, { rows: 2, placeholder: 'POST' }), 'leer = alle'),
          field('Client aus Netzen', linesInput(r.networks, (v) => { r.networks = v; }, { rows: 2, placeholder: '10.0.0.0/8' }), 'leer = alle Clients')),
        el('h4', null, '… dann'),
        el('div.row', null, seg([['', 'Einstellungen anpassen'], ['allow', 'Durchlassen', 'warn'], ['block', 'Sperren', 'bad'], ['redirect', 'Weiterleiten']], r.action || '', (v) => { r.action = v; drawAction(); })),
        actionExtra,
        el('div.fields', null,
          field('Nur aus Netzen erreichbar', linesInput(r.only_networks, (v) => { r.only_networks = v; }, { rows: 2, placeholder: '192.168.0.0/16\n10.0.0.0/8' }), 'Andere Clients erhalten 403 – z. B. Admin-Bereiche nur intern.')),
        el('h4', null, 'Anmeldung'),
        el('div.fields', null,
          el('div.field', null, el('span', null, 'Login'), seg([['', 'wie Policy'], ['on', 'erforderlich'], ['off', 'ohne Login', 'warn']], r.auth || '', (v) => { r.auth = v; })),
          el('div.field', null, el('span', null, 'Zweiter Faktor'), seg([['', 'wie Policy'], ['on', 'verlangen'], ['off', 'nicht nötig']], r.totp || '', (v) => { r.totp = v; })),
          field('Nur diese Gruppen', linesInput(r.auth_groups, (v) => { r.auth_groups = v; }, { rows: 2, placeholder: 'IT-Admins' }), 'ersetzt die Gruppen der Policy; leer = wie Policy'),
          field('Nur diese Benutzer', linesInput(r.auth_users, (v) => { r.auth_users = v; }, { rows: 2, placeholder: 'max.mustermann' }))),
        el('div.field', null, el('span', null, 'API-Schlüssel'), el('small.muted', null, 'Mit Schlüsseln ist der Bereich nur noch mit gültigem Schlüssel erreichbar – dafür ohne Login (für Webhooks, Skripte, Monitoring).'), keysBox),
        el('h4', null, 'Schutz'),
        el('div.fields', null,
          el('div.field', null, el('span', null, 'WAF'), seg([['', 'wie Policy'], ['off', 'aus'], ['detect', 'erkennen'], ['block', 'blockieren', 'bad']], r.waf || '', (v) => { r.waf = v; })),
          el('div.field', null, el('span', null, 'Bot-Challenge'), seg([['', 'wie Policy'], ['off', 'nie'], ['always', 'immer', 'warn']], r.challenge || '', (v) => { r.challenge = v; })),
          el('div.field', null, el('span', null, 'Ratelimits'), toggle(r.skip_rate_limits, (v) => { r.skip_rate_limits = v; }, 'nicht anwenden')),
          el('div.field', null, el('span', null, 'Wartungsmodus'), toggle(r.skip_maintenance, (v) => { r.skip_maintenance = v; }, 'trotzdem erreichbar'))),
        el('div.field', null, el('span', null, 'Antwort-Header'), el('textarea.mono', { rows: 2, placeholder: 'X-Robots-Tag: noindex\nCache-Control: no-store', value: hdrText, oninput: (e) => { hdrText = e.target.value; } })),
      ], {
        wide: true,
        actions: [{ label: 'Abbrechen', onClick: () => { if (isNew) { p.path_rules.splice(p.path_rules.indexOf(orig), 1); drawList(); } } }, {
          label: 'Übernehmen', kind: 'primary', onClick: () => {
            r.response_headers = {};
            for (const line of hdrText.split('\n')) { const i = line.indexOf(':'); if (i > 0) r.response_headers[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
            Object.assign(orig, r); markDirty(); drawList(); drawTab();
          },
        }],
      });
    }
  }

  function challenge() {
    const c = p.challenge;
    mount(tabBody, panel('Bot-Challenge', el('div.stack', null,
      el('p.muted', null, 'Statt zu blockieren muss der Browser eine kurze Rechenaufgabe (Proof-of-Work, ca. 1 Sekunde) lösen. Echte Besucher merken kaum etwas, Skripte und einfache Bots ohne JavaScript kommen nicht durch. Ein gelöstes Rätsel gilt per Cookie für die eingestellte Dauer.'),
      el('div.row', null, el('b', null, 'Modus'), seg([['off', 'Nur bei Geo-/Feed-Regeln'], ['suspicious', 'Auch für verdächtige IPs', 'warn'], ['always', 'Alle Besucher (Angriffsmodus)', 'bad']], c.mode, (v) => { c.mode = v; markDirty(); })),
      el('div.fields', null,
        field('Schwierigkeit', el('input', { type: 'number', min: 8, max: 24, value: c.difficulty || 16, oninput: (e) => { c.difficulty = +e.target.value; markDirty(); } }), '16 ≈ 1 Sekunde, jede Stufe mehr verdoppelt die Rechenzeit'),
        field('Gültigkeit (Stunden)', el('input', { type: 'number', min: 1, value: Math.round((c.ttl_seconds || 86400) / 3600), oninput: (e) => { c.ttl_seconds = +e.target.value * 3600; markDirty(); } })),
        el('div.field.wide', null, el('span', null, 'Ausgenommene Pfade'), linesInput(c.exempt_paths, (v) => { c.exempt_paths = v; markDirty(); }, { rows: 3, placeholder: '/api/\n/webhooks/\n/.well-known/' }), el('small', null, 'APIs, Webhooks und Apps können keine Challenge lösen – diese Pfade auslassen. Nicht-Browser-Requests auf geschützten Pfaden erhalten 403.'))),
      el('div.callout', null, '„Verdächtig“ sind IPs, deren Bedrohungs-Score die Challenge-Schwelle (Einstellungen › Bedrohungserkennung, aktuell ', String(settings.settings.ids.challenge_threshold || 0), ') erreicht, aber noch nicht gesperrt sind.'))));
  }

  function waf() {
    const w = p.waf;
    const groupBox = el('div.group-grid', null, meta.groups.map(g => {
      const disabled = p.disabled_groups.includes(g.id);
      return el('label.group' + (disabled ? '.disabled' : ''), null,
        el('input', { type: 'checkbox', checked: !disabled, onchange: (e) => { p.disabled_groups = e.target.checked ? p.disabled_groups.filter(x => x !== g.id) : [...p.disabled_groups, g.id]; markDirty(); waf(); } }),
        el('div', null, el('b', null, g.name), el('small', null, `${g.id}xxx · ${g.desc}`)));
    }));
    const rsChips = el('div.chips', null, rs.rulesets.length ? rs.rulesets.map(r => {
      const on = p.rulesets.includes(r.id);
      return el('span.chip' + (on ? '.on' : ''), { onclick: () => { p.rulesets = on ? p.rulesets.filter(x => x !== r.id) : [...p.rulesets, r.id]; markDirty(); waf(); }, title: r.description }, on ? '✓ ' : '', r.name, el('small', null, ` (${r.rules.length})`));
    }) : el('span.muted', null, 'Noch keine Regelsätze. ', el('a', { href: '#/rulesets' }, 'Regelsatz anlegen')));
    mount(tabBody,
      panel('Web Application Firewall', el('div.stack', null,
        el('div.row', null, el('b', null, 'Modus'), seg([['off', 'Aus'], ['detect', 'Erkennen (nur melden)', 'warn'], ['block', 'Blockieren', 'bad']], w.mode, (v) => { w.mode = v; markDirty(); })),
        el('div.fields', null,
          el('div.field', null, el('span', null, 'OWASP Core Rule Set'), toggle(w.crs, (v) => { w.crs = v; markDirty(); waf(); }, 'CRS 4 aktiv')),
          field('Paranoia-Level', seg([[1, '1'], [2, '2'], [3, '3'], [4, '4']], w.paranoia || 1, (v) => { w.paranoia = v; markDirty(); }), '1 = wenige Fehlalarme, 4 = sehr streng'),
          field('Anomalie-Schwelle', el('input', { type: 'number', min: 1, max: 100, value: w.inbound_threshold || 5, oninput: (e) => { w.inbound_threshold = +e.target.value; markDirty(); } }), 'Ab diesem Score wird blockiert (CRS-Standard 5). Höher = toleranter.'),
          el('div.field', null, el('span', null, 'Request-Body prüfen'), toggle(w.inspect_body, (v) => { w.inspect_body = v; markDirty(); }, 'Formulare, JSON, XML, Uploads')),
          field('Body-Prüflimit (KiB)', el('input', { type: 'number', min: 16, value: Math.round((w.body_limit || 1048576) / 1024), oninput: (e) => { w.body_limit = +e.target.value * 1024; markDirty(); } }), 'Gilt für Anfragen und – falls eingeschaltet – Antworten.'),
          field('Größere Bodies', select([['partial', 'bis zum Limit prüfen, Rest durchlassen'], ['reject', 'ablehnen (413)']], w.body_limit_action || 'partial', (v) => { w.body_limit_action = v === 'partial' ? '' : v; markDirty(); }), 'Ablehnen schließt die Lücke hinter dem Limit, verhindert aber größere Uploads – nur für Sites ohne Uploads oder mit eigener Pfad-Regel dafür.'),
          el('div.field', null, el('span', null, 'Antworten prüfen'), toggle(w.inspect_response, (v) => { w.inspect_response = v; markDirty(); }, 'nur melden'), el('small', null, 'Prüft Text-Antworten (HTML, JSON, XML) bis zum Limit auf Datenlecks wie SQL-Fehlermeldungen, Stacktraces oder Verzeichnislisten. Die Antwort wird nie aufgehalten oder verändert; Treffer erscheinen unter Sicherheit. Kostet etwas CPU pro Antwort.'))),
        w.mode === 'detect' ? el('div.callout.warn', null, 'Erkennungsmodus: Treffer erscheinen unter Sicherheit und fließen in die IDS-Scores ein, Requests werden aber nicht blockiert. Gut zum Einlernen vor dem Scharfschalten.') : null)),
      w.crs ? panel('CRS-Regelgruppen', el('div.stack', null, groupBox,
        field('Einzelne CRS-Regeln deaktivieren', linesInput(w.remove_rules, (v) => { w.remove_rules = v; markDirty(); }, { rows: 3, placeholder: '920350\n942100-942199' }), 'Global für diese Policy. Für gezielte Ausnahmen (nur bestimmte Pfade) besser eine Regel mit Aktion „CRS-Regeln ausnehmen“ verwenden.'))) : null,
      panel('Ausnahmen (Fehlalarme)', el('div.stack', null,
        el('p.muted', { style: { margin: 0 } }, 'Schalten einzelne CRS-Regeln nur für einen Pfad – oder nur für einen Parameter – ab. Der Fehlalarm-Assistent schlägt passende Ausnahmen anhand echter Blockaden vor.'),
        (w.exclusions || []).length ? el('div.table-wrap', null, el('table', null,
          el('thead', null, el('tr', null, el('th', null, 'Regeln'), el('th', null, 'Pfade ab'), el('th', null, 'Nur für'), el('th', null, 'Gilt'), el('th', null, 'Notiz'), el('th'))),
          el('tbody', null, w.exclusions.map((x, i) => el('tr', null,
            el('td.mono', null, x.rules.join(', ')), el('td.mono', null, x.path_prefix || 'alle'), el('td.mono', null, x.target || 'alles'),
            el('td.nowrap', null, x.until ? el('span', { title: fmtUnix(x.until) }, fmtUntil(x.until)) : 'dauerhaft'),
            el('td.muted', null, [x.note, x.author, x.created ? new Date(x.created * 1000).toLocaleDateString('de-DE') : ''].filter(Boolean).join(' · ')),
            el('td.right.nowrap', null,
              el('button.btn.sm', { onclick: () => { let u = x.until || 0; modal('Ausnahme befristen', el('label.field', null, el('span', null, 'Endet'), untilInput(u, (v) => { u = v; })), { actions: [{ label: 'Abbrechen' }, { label: 'Übernehmen', kind: 'primary', onClick: () => { x.until = u; markDirty(); waf(); } }] }); } }, 'Befristen'), ' ',
              el('button.btn.sm.danger', { onclick: () => { w.exclusions.splice(i, 1); markDirty(); waf(); } }, 'Entfernen'))))))) : el('span.muted', null, 'Keine Ausnahmen.'),
        el('div.row', null, el('button.btn', { onclick: () => openWafAssistant({ policy: p.id }) }, 'Fehlalarm-Assistent öffnen')))),
      panel('Regelsätze', rsChips),
      panel('Eigene Regeln dieser Policy', ruleBuilder(p.rules, meta, markDirty)),
      panel('Erweitert: SecLang-Direktiven', el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'Vor dem CRS'), el('textarea.code', { rows: 4, value: w.directives || '', spellcheck: 'false', oninput: (e) => { w.directives = e.target.value; markDirty(); } })),
        el('div.field.wide', null, el('span', null, 'Nach dem CRS (z. B. SecRuleUpdateTargetById)'), el('textarea.code', { rows: 3, value: w.post_directives || '', spellcheck: 'false', oninput: (e) => { w.post_directives = e.target.value; markDirty(); } })))),
    );
  }

  function headers() {
    const s = p.security_headers;
    mount(tabBody, panel('Sicherheits-Header', el('div.fields', null,
      el('div.field.wide', null, el('span', null, 'Aktiv'), toggle(s.enabled, (v) => { s.enabled = v; markDirty(); }, 'Header auf alle Antworten dieser Policy setzen')),
      el('div.field', null, el('span', null, 'HSTS'), toggle(s.hsts, (v) => { s.hsts = v; markDirty(); }, 'Strict-Transport-Security (1 Jahr, nur HTTPS)')),
      el('div.field', null, el('span', null, 'nosniff'), toggle(s.no_sniff, (v) => { s.no_sniff = v; markDirty(); }, 'X-Content-Type-Options')),
      el('div.field', null, el('span', null, 'Server-Header'), toggle(s.hide_server, (v) => { s.hide_server = v; markDirty(); }, 'entfernen')),
      field('X-Frame-Options', select([['', 'nicht setzen'], 'DENY', 'SAMEORIGIN'], s.frame_options, (v) => { s.frame_options = v; markDirty(); })),
      field('Referrer-Policy', select([['', 'nicht setzen'], 'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'], s.referrer_policy, (v) => { s.referrer_policy = v; markDirty(); })),
      field('Permissions-Policy', el('input', { value: s.permissions_policy, placeholder: 'camera=(), microphone=(), geolocation=()', oninput: (e) => { s.permissions_policy = e.target.value; markDirty(); } })),
      el('div.field.wide', null, el('span', null, 'Content-Security-Policy'), el('input.mono', { value: s.content_security_policy, placeholder: "default-src 'self'", oninput: (e) => { s.content_security_policy = e.target.value; markDirty(); } }), el('small', null, 'Leer lassen, wenn die Anwendung selbst eine CSP setzt.')))));
  }

  function ids() {
    const o = p.ids_overrides;
    const g = settings.settings.ids;
    mount(tabBody, panel('IDS für diese Policy', el('div.stack', null,
      el('div.field', null, el('span', null, 'Automatische Sperren'), toggle(!o.disabled, (v) => { o.disabled = !v; markDirty(); }, 'Bedrohungserkennung für Requests dieser Policy')),
      el('div.fields', null,
        field('Sperr-Schwelle', el('input', { type: 'number', min: 0, value: o.ban_threshold || 0, oninput: (e) => { o.ban_threshold = +e.target.value; markDirty(); } }), `0 = global (${g.ban_threshold})`),
        ...settings.signals.map(sig => field(signalLabel(sig), el('input', {
          type: 'number', min: 0, value: o.weights[sig] ?? '', placeholder: String(g.weights[sig] ?? 0),
          oninput: (e) => { if (e.target.value === '') delete o.weights[sig]; else o.weights[sig] = +e.target.value; markDirty(); },
        }), 'Punkte pro Ereignis'))),
      el('small', null, 'Leere Felder übernehmen die globalen Gewichte aus den Einstellungen. Beispiel: Für eine API mit vielen legitimen 404 das Gewicht „404-Scans“ auf 0 setzen.'))));
  }

  setActions(
    el('button.btn', { onclick: () => impact(true).catch(errToast), title: 'Gespeicherten Verkehr der letzten 24 h gegen den aktuellen Bearbeitungsstand nachspielen' }, 'Auswirkung prüfen'),
    el('a.btn', { href: '#/waf?policy=' + p.id }, 'Testen'),
    el('button.btn', { onclick: preview }, 'SecLang-Vorschau'),
    policies.length > 1 ? el('button.btn', { onclick: () => { if (dirty) toast('Übertragen wird der gespeicherte Stand', 'info'); openTransfer(pol, policies); }, title: 'Bereiche dieser Policy in andere Policies übernehmen' }, 'Übertragen …') : null,
    p.id !== list.default ? el('button.btn', { onclick: makeDefault }, 'Als Standard') : null,
    p.id !== list.default ? el('button.btn.danger', { onclick: remove }, 'Löschen') : null,
    saveBtn);

  async function preview() {
    if (dirty) toast('Vorschau zeigt den gespeicherten Stand', 'info');
    const r = await get(`/policies/${p.id}/preview`);
    modal('Erzeugte WAF-Konfiguration', [r.errors?.length ? el('div.callout.bad', null, r.errors.join('; ')) : null, el('pre.block', { style: { maxHeight: '60vh' } }, r.directives)], { wide: true, actions: [{ label: 'Schließen' }] });
  }
  async function makeDefault() {
    try { await post(`/policies/${p.id}/default`); toast(`„${p.name}“ ist jetzt die Standard-Policy`, 'ok'); render(root, [p.id], scope, q); } catch (e) { errToast(e); }
  }
  async function remove() {
    if (!await confirmDialog('Policy löschen', `„${p.name}“ wird gelöscht. Sites mit „sentinel ${p.id}“ fallen auf die Standard-Policy zurück.`, 'Löschen')) return;
    try { await del('/policies/' + p.id); location.hash = '#/policies'; } catch (e) { errToast(e); }
  }

  const errs = list.errors?.[p.id];
  mount(root, el('div.grid', { style: { gridTemplateColumns: 'minmax(220px, 260px) minmax(0, 1fr)', alignItems: 'start' } },
    panel('Policies', sideList),
    el('div.stack', null,
      errs?.length ? el('div.callout.bad', null, 'Fehler beim Erzeugen der WAF-Regeln: ', errs.join('; ')) : null,
      errBox,
      anyTest() ? el('div.callout.warn', null, el('b', null, 'Testmodus aktiv: '), 'Einige Regeln dieser Policy protokollieren nur, statt zu blockieren. ', el('a', { href: '#', onclick: (e) => { e.preventDefault(); tab = 'general'; drawTab(); } }, 'Auswertung ansehen')) : null,
      tabHost)));
  drawTab();
  scope.listen(window, 'beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
}

function blankRule() {
  return { id: '', name: 'Neue Regel', enabled: true, paths: [], methods: [], networks: [], action: '', redirect_url: '', redirect_status: 302, only_networks: [], auth: '', auth_groups: [], auth_users: [], totp: '', api_keys: [], api_key_header: '', waf: '', challenge: '', skip_rate_limits: false, skip_maintenance: false, response_headers: {}, until: 0, schedule: {}, note: '' };
}

const DAYS = [[1, 'Mo'], [2, 'Di'], [3, 'Mi'], [4, 'Do'], [5, 'Fr'], [6, 'Sa'], [7, 'So']];
function scheduleLabel(s) {
  if (!s?.mode) return '';
  const days = (s.days || []).length ? (s.days.join(',') === '1,2,3,4,5' ? 'Mo–Fr' : s.days.map(d => DAYS[d - 1][1]).join(', ')) : 'täglich';
  return (s.mode === 'inside' ? 'nur ' : 'außer ') + days + ' ' + (s.from || '00:00') + '–' + (s.to || '24:00');
}

function scheduleEditor(r) {
  r.schedule ??= {};
  const s = r.schedule;
  const box = el('div.stack', { style: { gap: '8px' } });
  const draw = () => mount(box,
    el('div.fields', null,
      el('label.field', null, el('span', null, 'Endet'), untilInput(r.until || 0, (v) => { r.until = v; }), el('small', null, 'Danach schaltet Sentinel die Regel aus (sie bleibt sichtbar).')),
      el('div.field', null, el('span', null, 'Zeitplan'), seg([['', 'immer'], ['inside', 'nur im Zeitfenster'], ['outside', 'nur außerhalb']], s.mode || '', (v) => { s.mode = v; if (v && !s.from) { s.from = '07:00'; s.to = '19:00'; s.days = [1, 2, 3, 4, 5]; } draw(); }))),
    s.mode ? el('div.fields', null,
      el('div.field.wide', null, el('span', null, 'Tage'), el('div.chips', null, DAYS.map(([d, l]) => {
        const on = (s.days || []).includes(d);
        return el('span.chip' + (on ? '.on' : ''), { role: 'checkbox', 'aria-checked': on ? 'true' : 'false', tabindex: 0, onclick: () => { s.days = on ? s.days.filter(x => x !== d) : [...(s.days || []), d].sort(); draw(); } }, l);
      })), el('small', null, 'Keine Auswahl = jeden Tag')),
      field('Von', el('input', { type: 'time', value: s.from || '', onchange: (e) => { s.from = e.target.value; draw(); } })),
      field('Bis', el('input', { type: 'time', value: s.to || '', onchange: (e) => { s.to = e.target.value; draw(); } }), 'Bis vor Von = über Mitternacht'),
      field('Zeitzone', el('input', { value: s.tz || '', placeholder: 'Europe/Berlin', oninput: (e) => { s.tz = e.target.value.trim(); } })),
      el('div.callout', { style: { gridColumn: '1 / -1' } }, 'Die Regel gilt ', el('b', null, scheduleLabel(s)), '. Beispiel: Pfad /admin sperren „nur außerhalb Mo–Fr 07:00–19:00“ = Admin-Bereich nur zur Bürozeit erreichbar.')) : null);
  draw();
  return box;
}

const LAN = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'];
const RULE_PRESETS = [
  ['Admin-Bereich intern + Gruppe', () => ({ name: 'Admin-Bereich', paths: ['/admin/'], only_networks: LAN, auth: 'on', totp: 'on', auth_groups: ['IT-Admins'], waf: 'block' })],
  ['Öffentlich ohne Login', () => ({ name: 'Öffentlicher Bereich', paths: ['/public/', '/assets/', '=/favicon.ico'], auth: 'off' })],
  ['Webhook mit Schlüssel', () => ({ name: 'Webhooks', paths: ['/hooks/'], methods: ['POST'], api_key_header: 'X-Webhook-Token', challenge: 'off', waf: 'detect', skip_rate_limits: false })],
  ['API mit Bearer-Token', () => ({ name: 'API', paths: ['/api/'], api_key_header: 'Authorization', challenge: 'off' })],
  ['Health-Check frei', () => ({ name: 'Health-Check', paths: ['=/health', '=/healthz', '=/status'], methods: ['GET', 'HEAD'], action: 'allow', skip_maintenance: true })],
  ['Statische Dateien ohne WAF', () => ({ name: 'Statische Dateien', paths: ['/static/', '/assets/', '/**.css', '/**.js', '/**.png', '/**.svg', '/**.woff2'], methods: ['GET', 'HEAD'], waf: 'off', challenge: 'off', response_headers: { 'Cache-Control': 'public, max-age=86400' } })],
  ['Alte URL umleiten', () => ({ name: 'Weiterleitung', paths: ['/alt/'], action: 'redirect', redirect_url: '/neu{path}', redirect_status: 301 })],
  ['Pfad sperren', () => ({ name: 'Gesperrt', paths: ['/.git/', '/backup/', '/**.bak', '/**.sql'], action: 'block' })],
  ['Nicht indexieren', () => ({ name: 'Nicht indexieren', paths: ['/intern/'], response_headers: { 'X-Robots-Tag': 'noindex, nofollow' } })],
];

function ruleSummary(r) {
  const when = [];
  when.push(r.paths?.length ? r.paths.join(', ') : 'alle Pfade');
  if (r.methods?.length) when.push(r.methods.join('/'));
  if (r.networks?.length) when.push('von ' + r.networks.join(', '));
  const then = [];
  if (r.action === 'allow') then.push(['durchlassen', 'warn']);
  if (r.action === 'block') then.push(['sperren', 'off-red']);
  if (r.action === 'redirect') then.push(['→ ' + r.redirect_url + ' (' + (r.redirect_status || 302) + ')']);
  if (r.only_networks?.length) then.push(['nur ' + r.only_networks.join(', '), 'on']);
  if (r.auth === 'on') then.push(['Login', 'on']);
  if (r.auth === 'off') then.push(['ohne Login', 'warn']);
  if (r.totp === 'on') then.push(['2FA', 'on']);
  if (r.totp === 'off') then.push(['ohne 2FA']);
  if (r.auth_groups?.length) then.push(['Gruppen: ' + r.auth_groups.join(', '), 'on']);
  if (r.auth_users?.length) then.push(['Benutzer: ' + r.auth_users.join(', '), 'on']);
  if (r.api_keys?.length) then.push([`${r.api_keys.length} API-Schlüssel (${r.api_key_header || 'X-API-Key'})`, 'on']);
  if (r.waf) then.push(['WAF ' + ({ off: 'aus', detect: 'erkennt', block: 'blockiert' })[r.waf]]);
  if (r.challenge) then.push(['Challenge ' + ({ off: 'nie', always: 'immer' })[r.challenge]]);
  if (r.skip_rate_limits) then.push(['ohne Ratelimits']);
  if (r.skip_maintenance) then.push(['auch bei Wartung']);
  if (r.schedule?.mode) when.push(scheduleLabel(r.schedule));
  for (const k of Object.keys(r.response_headers || {})) then.push(['Header ' + k]);
  if (!then.length) then.push(['keine Änderung']);
  return { when, then };
}

function wafLabel(m) { return { off: 'WAF aus', detect: 'WAF erkennt', block: 'WAF blockiert' }[m] || m; }

function signalLabel(s) {
  return { geo_block: 'Geo-Sperre', feed_block: 'Threat-Feed-Block', challenge: 'Challenge ausgeliefert', waf_block: 'WAF-Block', waf_detect: 'WAF-Treffer (je 5 Score)', honeypot: 'Honeypot', not_found: '404', auth_fail: '401/403 / Login fehlgeschlagen', path_block: 'Pfad-Sperre (Regel)', bad_request: '400', scanner_ua: 'Scanner-Tool', rate_limit: 'Ratelimit', user_agent: 'Gesperrter UA', method: 'Unerlaubte Methode', ip_deny: 'IP-Sperrliste', burst: 'Request-Burst', body_limit: 'Body zu groß', bot_fake: 'Gefälschter Suchmaschinen-Bot', bot: 'Crawler gesperrt/gebremst' }[s] || s;
}

function excludeFlow(root, policies, ruleId, def) {
  let sel;
  mount(root, panel(`CRS-Regel ${ruleId} ausnehmen`, el('div.stack', null,
    el('p', null, 'Löst eine CRS-Regel Fehlalarme aus, kannst du sie für eine Policy deaktivieren. Für eine gezielte Ausnahme (nur bestimmte Pfade oder Parameter) lege in der Policy stattdessen eine Regel mit der Aktion „CRS-Regeln ausnehmen“ an.'),
    field('Policy', sel = select(policies.map(p => [p.id, p.name]), def, () => { })),
    el('div.row', null, el('button.btn.primary', {
      onclick: async () => {
        const p = policies.find(x => x.id === sel.value);
        p.waf.remove_rules = [...new Set([...(p.waf.remove_rules || []), String(ruleId)])];
        try { await put('/policies/' + p.id, p); toast(`Regel ${ruleId} in „${p.name}“ deaktiviert`, 'ok'); location.hash = '#/policies/' + p.id; } catch (e) { errToast(e); }
      },
    }, 'Regel deaktivieren'), el('a.btn', { href: '#/security' }, 'Abbrechen')))));
}
