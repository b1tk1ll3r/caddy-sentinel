// Small DOM + API toolkit for the Sentinel UI (no dependencies).

export function el(tag, props, ...children) {
  let id = null;
  const hash = tag.indexOf('#');
  if (hash >= 0) { id = tag.slice(hash + 1); tag = tag.slice(0, hash); }
  const [name, ...classes] = tag.split('.');
  const node = document.createElementNS(
    name === 'svg' || props?.svg ? 'http://www.w3.org/2000/svg' : 'http://www.w3.org/1999/xhtml',
    name || 'div');
  if (classes.length) node.setAttribute('class', classes.join(' '));
  if (id) node.id = id;
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false || k === 'svg') continue;
      if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'class') node.setAttribute('class', [node.getAttribute('class'), v].filter(Boolean).join(' '));
      else if (k === 'style' && typeof v === 'object') { for (const [sk, sv] of Object.entries(v)) { if (sk.startsWith('--')) { if (sv != null) node.style.setProperty(sk, sv); } else node.style[sk] = sv; } }
      else if (k === 'value' || k === 'checked' || k === 'selected' || k === 'disabled' || k === 'indeterminate') node[k] = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k === 'ref') v(node);
      else node.setAttribute(k, v === true ? '' : v);
    }
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false || c === true) continue;
    node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function mount(node, ...children) {
  node.replaceChildren();
  append(node, children);
  return node;
}

export const $ = (sel, root = document) => root.querySelector(sel);

// ---------------------------------------------------------------- API

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export async function api(path, { method = 'GET', body, signal, inst } = {}) {
  const opts = { method, headers: { 'X-Sentinel': '1' }, signal, credentials: 'same-origin' };
  const useInst = inst ?? instState.effective();
  if (useInst) opts.headers['X-Sentinel-Instance'] = useInst;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch('/api' + path, opts);
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError(0, 'Panel nicht erreichbar');
  }
  if (res.status === 401 && !path.startsWith('/auth/')) {
    window.dispatchEvent(new CustomEvent('sentinel:unauthorized'));
  }
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || res.statusText);
  return data;
}

export const get = (p, signal) => api(p, { signal });
export const post = (p, body) => api(p, { method: 'POST', body: body ?? {} });
export const put = (p, body) => api(p, { method: 'PUT', body });
export const del = (p) => api(p, { method: 'DELETE' });

export function qs(obj) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) if (v !== '' && v != null) p.set(k, v);
  const s = p.toString();
  return s ? '?' + s : '';
}

// ---------------------------------------------------------------- feedback

let toastHost;
export function toast(msg, kind = 'info', ms = 4000) {
  if (!toastHost) { toastHost = el('div.toasts', { role: 'status', 'aria-live': 'polite' }); document.body.append(toastHost); }
  const t = el('div.toast.' + kind, null, msg);
  toastHost.append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, ms);
}

export function errToast(e) { toast(e.message || String(e), 'bad', 7000); }

export function modal(title, body, { actions = [], wide = false, onClose } = {}) {
  const prev = document.activeElement;
  const close = () => { wrap.remove(); document.removeEventListener('keydown', onKey); prev?.focus?.(); onClose?.(); };
  // only the topmost dialog reacts to Escape (dialogs can be stacked)
  const onKey = (e) => { if (e.key === 'Escape' && [...document.querySelectorAll('.modal-wrap')].pop() === wrap) close(); };
  const box = el('div.modal' + (wide ? '.wide' : ''), { role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    el('header', null, el('h2', null, title), el('button.icon-btn', { onclick: close, 'aria-label': 'Schließen', title: 'Schließen' }, '✕')),
    el('div.modal-body', null, body),
    actions.length ? el('footer', null, actions.map(a => el('button.btn' + (a.kind ? '.' + a.kind : ''), {
      onclick: async (e) => {
        if (!a.onClick) return close();
        const btn = e.currentTarget;
        btn.disabled = true;
        try { if ((await a.onClick()) !== false) close(); } catch (err) { errToast(err); } finally { btn.disabled = false; }
      },
    }, a.label))) : null);
  const wrap = el('div.modal-wrap', { onmousedown: (e) => { if (e.target === wrap) close(); } }, box);
  document.body.append(wrap);
  document.addEventListener('keydown', onKey);
  setTimeout(() => (box.querySelector('input,textarea,select,button.primary') || box.querySelector('button'))?.focus(), 30);
  return { close, box };
}

export function confirmDialog(title, text, label = 'Bestätigen', kind = 'danger') {
  return new Promise((resolve) => {
    let done = false;
    modal(title, el('p', null, text), {
      actions: [
        { label: 'Abbrechen' },
        { label, kind, onClick: () => { done = true; resolve(true); } },
      ],
      onClose: () => { if (!done) resolve(false); },
    });
  });
}

export function prompt(title, label, value = '') {
  return new Promise((resolve) => {
    let input; let done = false;
    const m = modal(title, el('label.field', null, el('span', null, label), input = el('input', { value, onkeydown: (e) => { if (e.key === 'Enter') { done = true; resolve(input.value); m.close(); } } })), {
      actions: [{ label: 'Abbrechen' }, { label: 'OK', kind: 'primary', onClick: () => { done = true; resolve(input.value); } }],
      onClose: () => { if (!done) resolve(null); },
    });
  });
}

// ---------------------------------------------------------------- formatting

const nf = new Intl.NumberFormat('de-DE');
const nf1 = new Intl.NumberFormat('de-DE', { maximumFractionDigits: 1 });
export const fmtInt = (n) => nf.format(Math.round(n || 0));
export const fmt1 = (n) => nf1.format(n || 0);

export function fmtCompact(n) {
  n = n || 0;
  if (Math.abs(n) >= 1e9) return nf1.format(n / 1e9) + ' Mrd.';
  if (Math.abs(n) >= 1e6) return nf1.format(n / 1e6) + ' Mio.';
  if (Math.abs(n) >= 1e4) return nf1.format(n / 1e3) + ' Tsd.';
  return nf.format(Math.round(n));
}

export function fmtBytes(b) {
  b = b || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return nf1.format(b) + ' ' + u[i];
}

export function fmtMs(ms) {
  if (ms == null) return '–';
  if (ms >= 1000) return nf1.format(ms / 1000) + ' s';
  if (ms >= 10) return nf.format(Math.round(ms)) + ' ms';
  return nf1.format(ms) + ' ms';
}

export function fmtPct(x) { return nf1.format((x || 0) * 100) + ' %'; }

const dtf = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const tf = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
export const fmtTime = (ms) => tf.format(new Date(ms));
export const fmtDateTime = (ms) => dtf.format(new Date(ms));

export function fmtAgo(ms) {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 5) return 'gerade eben';
  if (s < 60) return `vor ${s} s`;
  if (s < 3600) return `vor ${Math.round(s / 60)} Min.`;
  if (s < 86400) return `vor ${Math.round(s / 3600)} Std.`;
  return `vor ${Math.round(s / 86400)} Tagen`;
}

export function fmtDuration(sec) {
  if (!sec) return 'dauerhaft';
  if (sec < 120) return `${sec} s`;
  if (sec < 7200) return `${Math.round(sec / 60)} Min.`;
  if (sec < 172800) return `${Math.round(sec / 3600)} Std.`;
  return `${Math.round(sec / 86400)} Tage`;
}

export function fmtUntil(unix) {
  if (!unix) return 'dauerhaft';
  const s = unix - Date.now() / 1000;
  if (s <= 0) return 'abgelaufen';
  return 'noch ' + fmtDuration(Math.round(s));
}

export const ACTIONS = {
  banned: 'Gebannt',
  ip_deny: 'IP-Sperre',
  maintenance: 'Wartung',
  method: 'Methode',
  user_agent: 'User-Agent',
  honeypot: 'Honeypot',
  body_limit: 'Body-Limit',
  rate_limit: 'Ratelimit',
  rate_ban: 'Ratelimit-Bann',
  waf_block: 'WAF blockiert',
  waf_detect: 'WAF erkannt',
  geo_block: 'Geo-Sperre',
  feed_block: 'Threat-Feed',
  feed_match: 'Feed-Treffer',
  challenge: 'Bot-Challenge',
  challenge_pass: 'Challenge gelöst',
  auth_required: 'Anmeldung nötig',
  auth_fail: 'Login fehlgeschlagen',
  auth_denied: 'Kein Zugriff',
  auth_login: 'Angemeldet',
  path_block: 'Pfad-Sperre',
  redirect: 'Weitergeleitet',
  api_key: 'API-Schlüssel fehlt',
  bot_block: 'Crawler gesperrt',
  bot_limit: 'Crawler gebremst',
  bot_fake: 'Falscher Suchmaschinen-Bot',
  auth_token: 'Token ungültig',
};

// actions after which the request was still served; "test:…" are decisions
// of rules in test mode (would have blocked, but let through)
class NonBlocking extends Set {
  has(a) { return super.has(a) || (typeof a === 'string' && a.startsWith('test:')); }
}
export const NON_BLOCKING = new NonBlocking(['waf_detect', 'feed_match', 'challenge_pass', 'auth_login', 'auth_required', 'redirect']);
export const isTest = (a) => typeof a === 'string' && a.startsWith('test:');
export const actionLabel = (a) => isTest(a) ? 'Test: ' + (ACTIONS[a.slice(5)] || a.slice(5)) : (ACTIONS[a] || a);

// Country code -> flag emoji + German name
const regionNames = (() => { try { return new Intl.DisplayNames(['de'], { type: 'region' }); } catch { return null; } })();
export function countryName(cc) {
  if (!cc) return 'Unbekannt';
  try { return regionNames?.of(cc) || cc; } catch { return cc; }
}
export function flag(cc) {
  if (!cc || cc.length !== 2) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}
export function countryLabel(cc) {
  return cc ? `${flag(cc)} ${countryName(cc)}` : 'Unbekannt';
}

export function actionBadge(a) {
  if (!a) return null;
  if (isTest(a)) {
    const base = a.slice(5);
    return el('span.badge.test', { title: 'Testmodus: wäre blockiert worden, wurde aber durchgelassen' }, 'Test: ' + (ACTIONS[base] || base));
  }
  const kind = a === 'waf_detect' || a === 'feed_match' || a === 'challenge' || a === 'auth_denied' ? 'warn' : a === 'maintenance' || a === 'challenge_pass' || a === 'auth_required' || a === 'redirect' ? 'info' : a === 'auth_login' ? 'ok' : 'bad';
  return el('span.badge.' + kind, null, ACTIONS[a] || a);
}

export function statusBadge(s) {
  const k = s >= 500 ? 'bad' : s >= 400 ? 'warn' : s >= 300 ? 'info' : 'ok';
  return el('span.status.' + k, null, s);
}

export const SEVERITY = ['Info', 'Niedrig', 'Mittel', 'Hoch', 'Kritisch'];
export function sevBadge(s) {
  const k = ['muted', 'info', 'warn', 'bad', 'crit'][s] || 'muted';
  return el('span.badge.' + k, null, SEVERITY[s] ?? s);
}

// ---------------------------------------------------------------- small components

export function spinner() { return el('div.spinner', { 'aria-label': 'Lädt' }); }

export function empty(title, text, action) {
  return el('div.empty', null, el('strong', null, title), text ? el('p', null, text) : null, action || null);
}

export function tabs(items, active, onChange) {
  return el('div.tabs', { role: 'tablist' }, items.map(([key, label]) =>
    el('button.tab' + (key === active ? '.active' : ''), { role: 'tab', 'aria-selected': key === active ? 'true' : 'false', onclick: () => onChange(key) }, label)));
}

export function field(label, input, hint) {
  return el('label.field', null, el('span', null, label), input, hint ? el('small', null, hint) : null);
}

export function toggle(checked, onChange, label) {
  return el('label.toggle', null,
    el('input', { type: 'checkbox', checked, onchange: (e) => onChange(e.target.checked) }),
    el('span.track', null, el('span.thumb')), label ? el('span', null, label) : null);
}

export function select(options, value, onChange, attrs = {}) {
  return el('select', { ...attrs, onchange: (e) => onChange(e.target.value, e) },
    options.map(o => {
      const [v, l] = Array.isArray(o) ? o : [o, o];
      return el('option', { value: v, selected: String(v) === String(value) }, l);
    }));
}

// list editor: one entry per line
export function linesInput(arr, onChange, attrs = {}) {
  return el('textarea.lines', {
    rows: attrs.rows || 4, placeholder: attrs.placeholder || '', spellcheck: 'false',
    value: (arr || []).join('\n'),
    oninput: (e) => onChange(e.target.value.split('\n').map(s => s.trim()).filter(Boolean)),
  });
}

export function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function copy(text) {
  navigator.clipboard?.writeText(text).then(() => toast('In die Zwischenablage kopiert', 'ok', 1800), () => toast('Kopieren nicht möglich', 'bad'));
}

export function ipLink(ip) {
  return el('a.mono.iplink', { href: '#/ip/' + encodeURIComponent(ip), 'data-ip': ip, title: 'Klick: Steckbrief · Strg+Klick: ganze Seite' }, ip);
}

// ---------------------------------------------------------------- dates

const pad = (n) => String(n).padStart(2, '0');
/** unix seconds -> value for <input type=datetime-local> */
export function toLocalInput(unix) {
  if (!unix) return '';
  const d = new Date(unix * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
export function fromLocalInput(v) {
  if (!v) return 0;
  const t = new Date(v).getTime();
  return Number.isFinite(t) ? Math.round(t / 1000) : 0;
}
const udf = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
export function fmtUnix(unix) { return unix ? udf.format(new Date(unix * 1000)) : '–'; }

/**
 * End-date picker: quick choices plus free date/time. value = unix seconds
 * (0 = no end). opts.required hides "unbefristet".
 */
export function untilInput(value, onChange, opts = {}) {
  const input = el('input', { type: 'datetime-local', value: toLocalInput(value), min: toLocalInput(Math.floor(Date.now() / 1000)), onchange: (e) => { onChange(fromLocalInput(e.target.value)); } });
  const set = (unix) => { input.value = toLocalInput(unix); onChange(unix); };
  const now = () => Math.floor(Date.now() / 1000);
  const friday = () => { const d = new Date(); d.setDate(d.getDate() + ((5 - d.getDay() + 7) % 7 || 7)); d.setHours(18, 0, 0, 0); return Math.floor(d / 1000); };
  const quick = [['1 Std.', () => now() + 3600], ['Heute 18 Uhr', () => { const d = new Date(); d.setHours(18, 0, 0, 0); return d < new Date() ? now() + 3600 : Math.floor(d / 1000); }], ['1 Tag', () => now() + 86400], ['Freitag 18 Uhr', friday], ['1 Woche', () => now() + 7 * 86400], ['30 Tage', () => now() + 30 * 86400]];
  return el('div.until', null,
    el('div.row', { style: { gap: '4px', flexWrap: 'wrap' } },
      opts.required ? null : el('button.btn.sm' + (!value ? '.on' : ''), { type: 'button', onclick: () => set(0) }, 'unbefristet'),
      quick.map(([l, f]) => el('button.btn.sm', { type: 'button', onclick: () => set(f()) }, l))),
    input);
}

/** "geändert von admin am 01.02. 12:00 · Notiz" */
export function stampLine(o) {
  const parts = [];
  if (o?.author) parts.push(o.author);
  if (o?.updated || o?.created) parts.push(fmtUnix(o.updated || o.created));
  return parts.length ? el('small.muted.stamp', null, '✎ ' + parts.join(' · ')) : null;
}

// simple card wrapper
export function panel(title, body, extra) {
  return el('section.panel', null,
    title ? el('header.panel-head', null, el('h3', null, title), extra || null) : null,
    el('div.panel-body', null, body));
}

// ---------------------------------------------------------------- range state

const RANGES = [['15m', '15 Min.'], ['1h', '1 Std.'], ['6h', '6 Std.'], ['24h', '24 Std.'], ['7d', '7 Tage'], ['30d', '30 Tage']];
export const rangeState = {
  value: localStorage.getItem('sentinel.range') || '1h',
  host: '',
  listeners: new Set(),
  set(v) { this.value = v; try { localStorage.setItem('sentinel.range', v); } catch { } this.listeners.forEach(f => f()); },
  setHost(h) { this.host = h; this.listeners.forEach(f => f()); },
};

// Caddy instances: the global selection (value: "all" or an ID) filters
// statistics; pages about one Caddy (editor, flow, sites, certificates) pin
// a concrete instance in `page` while "all" is selected.
let storedInst = 'all';
try { storedInst = localStorage.getItem('sentinel.inst') || 'all'; } catch { }
export const instState = {
  value: storedInst,
  page: null,
  lastPage: null, // last instance chosen on an instance page (kept across pages)
  list: [],
  listeners: new Set(),
  set(v) {
    this.value = v || 'all';
    try { localStorage.setItem('sentinel.inst', this.value); } catch { }
    this.listeners.forEach(f => f(this.value));
  },
  setList(list) {
    this.list = list || [];
    if (this.value !== 'all' && !this.list.find(i => i.id === this.value)) this.value = 'all';
  },
  effective() { return this.value !== 'all' ? this.value : (this.page || ''); },
  byId(id) { return this.list.find(i => i.id === (id || 'local')); },
  multi() { return this.list.length > 1; },
};

/** Small coloured label of an instance (only when several exist). */
export function instChip(id, { always = false } = {}) {
  if (!always && !instState.multi()) return null;
  const i = instState.byId(id);
  if (!i) return id ? el('span.inst-chip', null, id) : null;
  return el('span.inst-chip', { style: { '--ic': i.color || 'var(--muted)' }, title: 'Caddy-Instanz ' + i.name }, i.name);
}

export function rangePicker() {
  const s = select(RANGES, rangeState.value, (v) => rangeState.set(v), { 'aria-label': 'Zeitraum', class: 'range-select' });
  return s;
}

// lifecycle helper: pages register cleanup functions
export class Scope {
  constructor() { this.fns = []; this.ctrl = new AbortController(); }
  on(fn) { this.fns.push(fn); }
  interval(fn, ms) { const t = setInterval(fn, ms); this.on(() => clearInterval(t)); }
  listen(target, ev, fn) { target.addEventListener(ev, fn); this.on(() => target.removeEventListener(ev, fn)); }
  get signal() { return this.ctrl.signal; }
  dispose() { this.ctrl.abort(); this.fns.forEach(f => { try { f(); } catch { } }); this.fns = []; }
}

// ---------------------------------------------------------------- roles
export const ROLES = [
  ['admin', 'Administrator', 'alles, inkl. Benutzer, Einstellungen und Caddy-Instanzen'],
  ['editor', 'Bearbeiter', 'Caddyfile, Policies, Regelsätze, Feeds, Monitore und Sperren'],
  ['support', 'Support', 'alles sehen, Sperren aufheben und setzen'],
  ['viewer', 'Leser', 'nur lesen'],
];
export const roleLabel = (r) => (ROLES.find(x => x[0] === r) || [r, r])[1];
const CAPS = { admin: ['config', 'policy', 'bans', 'admin'], editor: ['config', 'policy', 'bans'], support: ['bans'], viewer: [] };
/** Whether the logged-in user may do something (config | policy | bans | admin). */
export function can(cap) {
  const role = window.__status?.user?.role || 'viewer';
  return (CAPS[role] || []).includes(cap);
}
