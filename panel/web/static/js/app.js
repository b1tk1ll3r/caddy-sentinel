import { el, mount, get, post, api, toast, errToast, Scope, fmtInt, rangePicker, rangeState, modal, instState, select, roleLabel } from './ui.js';
import { canLeave } from './instancebar.js';
import { installIPDrawer } from './ipdrawer.js';
import { openSearch, installSearchKey } from './search.js';

try { const th = localStorage.getItem('sentinel.theme'); if (th && th !== 'auto') document.documentElement.setAttribute('data-theme', th); } catch { }

const ICONS = {
  dashboard: 'M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z',
  live: 'M2 12h4l3-8 4 16 3-8h6',
  analytics: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
  failures: 'M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15zM21 21l-5.2-5.2M10.5 7v4.5M10.5 14h.01',
  sites: 'M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01',
  editor: 'M8 6l-6 6 6 6M16 6l6 6-6 6',
  security: 'M12 2 4 5v6c0 5.2 3.4 9.8 8 11 4.6-1.2 8-5.8 8-11V5z',
  policies: 'M4 6h16M4 12h10M4 18h6M18 14l2 2 3-4',
  rulesets: 'M4 4h16v4H4zM4 10h16v4H4zM4 16h16v4H4z',
  waf: 'M12 3v4M12 17v4M3 12h4M17 12h4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
  uptime: 'M3 12h4l2-6 4 12 2-6h6M3 4v16h18',
  certs: 'M7 3h10v7l-5 3-5-3zM9 13l-2 8 5-3 5 3-2-8',
  flow: 'M3 6h4v4H3zM17 3h4v4h-4zM17 10h4v4h-4zM17 17h4v4h-4zM7 8h4l2-3h4M11 8l2 4h4M11 8l2 11h4',
  instances: 'M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01M11 7h6M11 17h6',
  pki: 'M14 4a6 6 0 1 1-5.6 8.2L3 17.6V21h3.4v-2.2h2.2v-2.2h2.2l1.2-1.2A6 6 0 0 1 14 4zM16 8h.01',
  access: 'M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM3 21a7 7 0 0 1 10.5-6M15 16h6v5h-6zM16.5 16v-2a1.5 1.5 0 0 1 3 0v2',
  feeds: 'M5 5a14 14 0 0 1 14 14M5 11a8 8 0 0 1 8 8M6 18h.01',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
};

export function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  p.setAttribute('d', ICONS[name] || '');
  svg.append(p);
  return svg;
}

function logo(size = 26) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 32 32');
  svg.setAttribute('width', size); svg.setAttribute('height', size);
  svg.innerHTML = '<path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--primary)"/><path d="M9 17h3l2-5 4 9 2-4h3" fill="none" stroke="var(--primary-ink)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>';
  return svg;
}

const NAV = [
  [null, [['/', 'dashboard', 'Übersicht'], ['/live', 'live', 'Live-Traffic'], ['/analytics', 'analytics', 'Analysen'], ['/failures', 'failures', 'Fehleranalyse'], ['/sites', 'sites', 'Sites'], ['/flow', 'flow', 'Request-Fluss'], ['/uptime', 'uptime', 'Verfügbarkeit'], ['/certs', 'certs', 'Zertifikate'], ['/pki', 'pki', 'Interne CA']]],
  ['Konfiguration', [['/instances', 'instances', 'Caddy-Instanzen'], ['/editor', 'editor', 'Caddyfile-Editor'], ['/policies', 'policies', 'Policies'], ['/rulesets', 'rulesets', 'Regelsätze']]],
  ['Schutz', [['/security', 'security', 'Sicherheit'], ['/access', 'access', 'Site-Login & Konten'], ['/feeds', 'feeds', 'Threat-Feeds'], ['/waf', 'waf', 'WAF-Tester']]],
  [null, [['/settings', 'settings', 'Einstellungen']]],
];

const ROUTES = [
  [/^\/$/, 'dashboard', 'Übersicht', true],
  [/^\/live$/, 'live', 'Live-Traffic'],
  [/^\/analytics$/, 'analytics', 'Analysen', true],
  [/^\/failures$/, 'failures', 'Fehleranalyse', true],
  [/^\/sites$/, 'sites', 'Sites'],
  [/^\/editor$/, 'config', 'Caddyfile-Editor'],
  [/^\/security$/, 'security', 'Sicherheit', true],
  [/^\/policies(?:\/([\w-]+))?$/, 'policies', 'Policies'],
  [/^\/rulesets(?:\/([\w-]+))?$/, 'rulesets', 'Regelsätze'],
  [/^\/waf$/, 'waftest', 'WAF-Tester'],
  [/^\/settings$/, 'settings', 'Einstellungen'],
  [/^\/uptime$/, 'uptime', 'Verfügbarkeit'],
  [/^\/certs$/, 'certs', 'Zertifikate'],
  [/^\/feeds$/, 'feeds', 'Threat-Feeds'],
  [/^\/pki$/, 'pki', 'Interne CA'],
  [/^\/flow$/, 'flow', 'Request-Fluss'],
  [/^\/instances$/, 'instances', 'Caddy-Instanzen'],
  [/^\/access$/, 'access', 'Site-Login & Konten'],
  [/^\/ip\/(.+)$/, 'ip', 'IP-Details', true],
];

// --------------------------------------------------------------- live bus

export const bus = new EventTarget();
let es;
function connectStream() {
  if (es) es.close();
  es = new EventSource('/api/stream' + (instState.value !== 'all' ? '?inst=' + encodeURIComponent(instState.value) : ''));
  for (const t of ['requests', 'event', 'tick', 'monitor']) {
    es.addEventListener(t, (m) => bus.dispatchEvent(new CustomEvent(t, { detail: JSON.parse(m.data) })));
  }
  es.onerror = () => { /* EventSource reconnects automatically */ };
}

// --------------------------------------------------------------- pulse ribbon

function pulse() {
  const N = 90;
  const bars = el('div.pulse-bars', { 'aria-hidden': 'true' });
  const num = el('div.pulse-num', { 'aria-live': 'off' });
  const data = [];
  const draw = () => {
    const max = Math.max(5, ...data.map(d => d.req));
    bars.replaceChildren(...Array.from({ length: N }, (_, i) => {
      const d = data[data.length - N + i];
      if (!d) return el('i', { style: { height: '1px', opacity: .35 } });
      const h = Math.max(1, (d.req / max) * 28);
      const bh = d.req ? (d.blocked / d.req) * h : 0;
      return el('i', { style: { height: h + 'px' }, title: `${d.req} Req/s, ${d.blocked} blockiert` }, bh ? el('b', { style: { height: bh + 'px' } }) : null);
    }));
    const last = data.slice(-5);
    const rps = last.length ? last.reduce((a, d) => a + d.req, 0) / last.length : 0;
    const blk = last.reduce((a, d) => a + d.blocked, 0);
    num.replaceChildren(el('strong', null, rps.toFixed(rps < 10 ? 1 : 0) + ' Req/s'), blk ? el('span', { style: { color: 'var(--bad)' } }, `${blk} blockiert`) : 'live');
  };
  get('/stats/live?n=' + N).then(pts => { data.push(...pts); draw(); }).catch(() => { });
  bus.addEventListener('tick', (e) => {
    const p = e.detail;
    if (data.length && data[data.length - 1].t >= p.t) return;
    data.push(p);
    if (data.length > N * 2) data.splice(0, data.length - N);
    draw();
  });
  return el('div.pulse', { title: 'Requests pro Sekunde (rot: blockiert)' }, bars, num);
}

// --------------------------------------------------------------- auth screens

function loginScreen(setup) {
  let user, pw, pw2, errEl;
  const submit = async (e) => {
    e.preventDefault();
    errEl.textContent = '';
    try {
      if (setup) {
        if (pw.value !== pw2.value) throw new Error('Die Passwörter stimmen nicht überein');
        await post('/auth/setup', { username: user.value, password: pw.value });
      } else {
        const r = await post('/auth/login', { username: user.value, password: pw.value });
        if (r.totp_required) return totpScreen(r.ticket, r.totp_enroll ? r : null);
      }
      start();
    } catch (err) { errEl.textContent = err.message; }
  };
  const providers = el('div.stack', { style: { gap: '8px' } });
  mount(document.getElementById('app'), el('div.login', null, el('form.login-box', { onsubmit: submit },
    el('div.brand', null, logo(30), el('span', null, 'Caddy Sentinel', el('small', null, setup ? 'Ersteinrichtung' : 'Anmelden'))),
    setup ? el('p.muted', null, 'Lege das Administratorkonto an. Das Panel ist danach nur mit diesem Login erreichbar.') : null,
    el('label.field', null, el('span', null, 'Benutzername'), user = el('input', { autocomplete: 'username', required: true, value: setup ? 'admin' : '' })),
    el('label.field', null, el('span', null, 'Passwort'), pw = el('input', { type: 'password', autocomplete: setup ? 'new-password' : 'current-password', required: true, minlength: setup ? 10 : null })),
    setup ? el('label.field', null, el('span', null, 'Passwort wiederholen'), pw2 = el('input', { type: 'password', autocomplete: 'new-password', required: true })) : null,
    errEl = el('div.err', { role: 'alert' }),
    el('button.btn.primary', { type: 'submit' }, setup ? 'Konto anlegen' : 'Anmelden'),
    providers)));
  if (!setup) {
    fetch('/api/auth/providers').then(r => r.ok ? r.json() : []).then(list => {
      if (list.length) mount(providers, el('div.or', null, el('span', null, 'oder')), list.map(p => el('a.btn', { href: p.href }, 'Mit ' + p.name + ' anmelden')));
    }).catch(() => { });
  }
  setTimeout(() => (setup ? pw : user).focus(), 30);
}

function totpScreen(ticket, enroll) {
  let code, errEl;
  mount(document.getElementById('app'), el('div.login', null, el('form.login-box', {
    onsubmit: async (e) => {
      e.preventDefault();
      errEl.textContent = '';
      const res = await fetch('/api/auth/totp', { method: 'POST', headers: { 'X-Sentinel': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ ticket, code: code.value }) });
      const data = await res.json().catch(() => ({}));
      if (res.ok) return start();
      if (data.ticket) ticket = data.ticket;
      errEl.textContent = data.error || 'Anmeldung fehlgeschlagen';
      code.value = '';
      code.focus();
      if (!data.ticket) setTimeout(() => loginScreen(false), 1500);
    },
  },
    el('div.brand', null, logo(30), el('span', null, 'Caddy Sentinel', el('small', null, enroll ? 'Zweiten Faktor einrichten' : 'Zwei-Faktor-Anmeldung'))),
    enroll ? [
      el('p.muted', null, 'Für Verzeichniskonten ist ein zweiter Faktor Pflicht. Scanne den QR-Code mit deiner Authenticator-App (z. B. Microsoft Authenticator, 2FAS) und gib den angezeigten Code ein. Derselbe Eintrag gilt auch für die Site-Anmeldung.'),
      el('img.qr', { src: enroll.qr, alt: 'QR-Code für die Authenticator-App', style: { width: '180px', height: '180px', alignSelf: 'center' } }),
      el('code', { style: { textAlign: 'center', userSelect: 'all', wordBreak: 'break-all' } }, enroll.secret.replace(/(.{4})/g, '$1 ').trim()),
    ] : el('p.muted', null, 'Gib den 6-stelligen Code aus deiner Authenticator-App ein.'),
    el('label.field', null, el('span', null, 'Code'), code = el('input', { inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9 ]{6,7}', maxlength: 7, required: true, style: { fontSize: '22px', letterSpacing: '6px', textAlign: 'center' } })),
    errEl = el('div.err', { role: 'alert' }),
    el('button.btn.primary', { type: 'submit' }, 'Bestätigen'),
    el('button.btn.ghost', { type: 'button', onclick: () => loginScreen(false) }, 'Zurück'))));
  setTimeout(() => code.focus(), 30);
}

// --------------------------------------------------------------- update hint

async function updateHint() {
  try {
    const u = await get('/update');
    const row = document.getElementById('version-row');
    if (!row || !u.available) return;
    row.append(el('a.badge.info', {
      href: '#', style: { marginLeft: '6px' }, title: 'Neue Version verfügbar',
      onclick: (e) => {
        e.preventDefault();
        modal('Update auf ' + u.latest, [
          el('p', null, 'Installiert ist ', el('b', null, u.current), ', verfügbar ist ', el('b', null, u.latest), '. ', el('a', { href: u.url, target: '_blank', rel: 'noopener' }, 'Änderungen ansehen')),
          u.docker
            ? [el('p', null, 'Docker Compose (im Verzeichnis mit der compose.yml):'), el('pre.mono', null, 'docker compose pull\ndocker compose up -d')]
            : [el('p', null, 'Auf dem Server (prüft die Konfiguration vorab, sichert und rollt bei Fehlern automatisch zurück):'), el('pre.mono', null, 'sudo caddy-sentinel-update')],
        ]);
      },
    }, 'Update ' + u.latest));
  } catch { /* offline – kein Hinweis */ }
}

// --------------------------------------------------------------- shell

let scope = new Scope();
let shellEls = null;
const pageCache = {};

async function loadPage(name) {
  if (!pageCache[name]) pageCache[name] = await import(`./pages/${name}.js`);
  return pageCache[name];
}

function buildShell(status) {
  const navLinks = [];
  const navCount = el('span.count', { hidden: true });
  const nav = el('nav.nav', { 'aria-label': 'Hauptnavigation' },
    el('a.brand', { href: '#/' }, logo(), el('span', null, 'Caddy Sentinel', el('small.muted', null, 'Caddy-Steuerzentrale'))),
    el('ul.nav-list', null, NAV.map(([group, items]) => [
      group ? el('li.nav-group', null, group) : null,
      items.map(([path, ic, label]) => {
        const a = el('a', { href: '#' + path, 'data-path': path }, icon(ic), label, path === '/security' ? navCount : null);
        navLinks.push(a);
        return el('li', null, a);
      }),
    ])),
    el('div.nav-foot', null,
      el('div.row', null, el('span.dot#caddy-dot'), el('span#caddy-label', null, 'Caddy')),
      el('div.row', null, el('span.dot#agent-dot'), el('span#agent-label', null, 'Agent')),
      el('div.row#version-row', null, el('small.muted', null, 'Version ' + (status.version || '?'))),
      el('div.row', null, el('span.muted', null, status.user?.username || ''), status.user?.role && status.user.role !== 'admin' ? el('span.badge', { title: 'Rolle im Panel' }, roleLabel(status.user.role)) : null, el('button.icon-btn', {
        style: { marginLeft: 'auto' }, title: 'Abmelden', onclick: async () => { await post('/auth/logout'); location.hash = '#/'; start(); },
      }, 'Abmelden'))));
  const title = el('h1');
  const actions = el('div.actions');
  const instBox = el('div.inst-picker-box');
  const content = el('main.content', { id: 'content', tabindex: '-1' });
  const shell = el('div.shell', null, nav, el('div.main', null,
    el('header.topbar', null,
      el('button.btn.ghost.menu-btn', { 'aria-label': 'Menü', onclick: () => shell.classList.toggle('nav-open') }, '☰'),
      title, el('button.search-btn', { onclick: openSearch, title: 'Suche (Strg+K oder /)' }, el('span', null, '⌕'), el('span.lbl', null, 'Suchen'), el('kbd', null, navigator.platform?.includes('Mac') ? '⌘K' : 'Strg K')), pulse(), instBox, actions),
    content));
  mount(document.getElementById('app'), shell);
  shellEls = { shell, title, actions, content, navLinks, navCount, instBox };
  drawInstPicker();
  updateStatus(status);
}

export function setActions(...nodes) { mount(shellEls.actions, ...nodes); }

// global instance selection (only shown with more than one Caddy)
function drawInstPicker() {
  if (!shellEls) return;
  if (!instState.multi()) { mount(shellEls.instBox); return; }
  const cur = instState.byId(instState.value);
  mount(shellEls.instBox, el('label.inst-picker', { style: { '--ic': cur?.color || 'var(--line)' }, title: 'Welche Caddy-Instanz angezeigt wird' },
    select([['all', 'Alle Caddy-Instanzen'], ...instState.list.map(i => [i.id, i.name + (i.online ? '' : ' (offline)')])], instState.value, (v, ev) => {
      if (!canLeave()) { ev.target.value = instState.value; return; }
      instState.set(v);
    }, { 'aria-label': 'Caddy-Instanz' })));
}
instState.listeners.add(() => {
  drawInstPicker();
  connectStream();
  get('/status').then(updateStatus).catch(() => { });
  route(true);
});

function updateStatus(st) {
  const cd = document.getElementById('caddy-dot');
  if (!cd) return;
  const hadMulti = instState.multi();
  const before = JSON.stringify(instState.list.map(i => [i.id, i.name, i.color, i.online]));
  if (st.instances) instState.setList(st.instances);
  if (before !== JSON.stringify(instState.list.map(i => [i.id, i.name, i.color, i.online])) || hadMulti !== instState.multi()) drawInstPicker();
  const insts = instState.list;
  if (insts.length > 1 && instState.value === 'all') {
    const on = insts.filter(i => i.online).length;
    cd.className = 'dot ' + (on === insts.length ? 'ok' : on ? 'warn' : 'bad');
    document.getElementById('caddy-label').textContent = `${on} von ${insts.length} Caddy-Instanzen verbunden`;
    document.getElementById('caddy-label').title = insts.filter(i => !i.online).map(i => i.name + ' offline').join(', ') || 'alle verbunden';
  } else {
    const name = insts.length > 1 ? (instState.byId(instState.effective())?.name || 'Caddy') : 'Caddy';
    cd.className = 'dot ' + (st.caddy_ok ? 'ok' : 'bad');
    document.getElementById('caddy-label').textContent = name + (st.caddy_ok ? ' erreichbar' : ' nicht erreichbar');
    document.getElementById('caddy-label').title = st.caddy_error || st.caddy_admin;
  }
  const online = (st.agents || []).filter(a => a.online);
  const ad = document.getElementById('agent-dot');
  const errs = (st.agents || []).some(a => a.errors && Object.keys(a.errors).length);
  ad.className = 'dot ' + (online.length ? (errs ? 'warn' : 'ok') : 'bad');
  document.getElementById('agent-label').textContent = online.length ? `${online.length} Agent${online.length > 1 ? 'en' : ''} verbunden` : 'Kein Agent verbunden';
  shellEls.navCount.hidden = !st.bans;
  shellEls.navCount.textContent = st.bans;
  shellEls.navCount.title = `${st.bans} aktive Sperren`;
  window.__status = st;
}

let lastRoutePath = '';
async function route(keepInstance) {
  if (!shellEls) return;
  const path = location.hash.replace(/^#/, '') || '/';
  // an instance pinned by an instance page stays while the user only switches it
  if (keepInstance !== true && path.split('?')[0] !== lastRoutePath) instState.page = null;
  lastRoutePath = path.split('?')[0];
  const qInst = new URLSearchParams(path.split('?')[1] || '').get('inst');
  if (qInst && instState.value === 'all') instState.page = qInst;
  const match = ROUTES.find(([re]) => re.test(path.split('?')[0]));
  scope.dispose();
  scope = new Scope();
  document.querySelectorAll('.modal-wrap, .drawer').forEach(n => n.remove());
  shellEls.shell.classList.remove('nav-open');
  for (const a of shellEls.navLinks) {
    const p = a.dataset.path;
    a.classList.toggle('active', p === '/' ? path === '/' : path.startsWith(p));
    if (a.classList.contains('active')) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  }
  if (!match) { shellEls.title.textContent = 'Nicht gefunden'; mount(shellEls.content, el('div.empty', null, 'Seite nicht gefunden')); return; }
  const [re, mod, title, ranged] = match;
  const params = path.split('?')[0].match(re).slice(1).map(x => x && decodeURIComponent(x));
  shellEls.title.textContent = title;
  document.title = title + ' · Caddy Sentinel';
  mount(shellEls.actions, ranged ? rangePicker() : null);
  mount(shellEls.content, el('div.spinner'));
  try {
    const page = await loadPage(mod);
    const q = new URLSearchParams(path.split('?')[1] || '');
    const thisScope = scope;
    await page.render(shellEls.content, params, scope, q);
    if (thisScope !== scope) return;
  } catch (e) {
    console.error(e);
    mount(shellEls.content, el('div.callout.bad', null, 'Fehler beim Laden: ' + e.message));
  }
}

export function setTitle(t) { if (shellEls) { shellEls.title.textContent = t; document.title = t + ' · Caddy Sentinel'; } }

async function start() {
  let st;
  try { st = await get('/auth/state'); } catch (e) { mount(document.getElementById('app'), el('div.boot', null, e.message)); return; }
  if (st.setup_required) return loginScreen(true);
  if (!st.user) return loginScreen(false);
  const status = await get('/status');
  instState.setList(status.instances);
  buildShell(status);
  updateHint();
  connectStream();
  route();
}

window.addEventListener('hashchange', () => route());
installIPDrawer();
installSearchKey();
window.addEventListener('sentinel:unauthorized', () => { if (shellEls) { shellEls = null; es?.close(); loginScreen(false); } });
setInterval(() => { if (shellEls && !document.hidden) get('/status').then(updateStatus).catch(() => { }); }, 15000);
bus.addEventListener('event', (e) => {
  const ev = e.detail;
  if (ev.type === 'ban') { toast(ev.title, 'bad', 6000); get('/status').then(updateStatus).catch(() => { }); }
  if (ev.type === 'alert' && ev.severity >= 3) toast(ev.title, 'bad', 8000);
});
start();
