// Bar at the top of pages that work on exactly one Caddy (editor, request
// flow, sites, certificates, internal CA). It makes unmistakable which Caddy
// is meant and lets the user switch. With a single instance nothing is shown.
import { el, mount, instState, select, fmtAgo } from './ui.js';

const MODE = {
  local: ['Lokal', 'Caddy auf dem Panel-Server – volle Verwaltung'],
  full: ['Fernverwaltung', 'Caddyfile über den Agent bearbeitbar'],
  read: ['Nur lesen', 'Konfiguration, Backends und Zertifikate sichtbar; Caddyfile nicht bearbeitbar'],
  off: ['Keine Fernverwaltung', 'Der Agent erlaubt keinen Zugriff auf die Konfiguration'],
};

/** Returns the instance this page works on and pins it for API calls. */
export function pageInstance({ preferEditable = false } = {}) {
  if (instState.value !== 'all') return instState.value;
  const list = instState.list;
  let id = instState.page || instState.lastPage;
  if (!id || !instState.byId(id)) {
    const pick = preferEditable ? list.find(i => i.editable && i.online) : null;
    id = (pick || list.find(i => i.local) || list[0] || { id: 'local' }).id;
  }
  instState.page = instState.lastPage = id;
  return id;
}

export function instanceBar(id, { note } = {}) {
  if (!instState.multi()) return null;
  const i = instState.byId(id) || { id, name: id };
  const mode = MODE[i.remote] || ['Unbekannt', 'Agent hat sich noch nicht gemeldet'];
  return el('div.inst-bar', { style: { '--ic': i.color || 'var(--primary)' }, role: 'region', 'aria-label': 'Caddy-Instanz' },
    el('div', null,
      el('div.muted', { style: { fontSize: '11.5px', textTransform: 'uppercase', letterSpacing: '.05em' } }, 'Caddy-Instanz'),
      el('div.inst-name', null, i.name)),
    el('div.inst-meta', null,
      el('span', null, el('span.dot.' + (i.online ? 'ok' : 'bad')), ' ', i.online ? 'verbunden' : (i.last_seen ? 'offline seit ' + fmtAgo(i.last_seen * 1000) : 'noch nie verbunden')),
      el('span', { title: mode[1] }, mode[0]),
      i.nodes?.length ? el('span', null, i.nodes.map(n => n.id).join(', ')) : null,
      i.caddyfile ? el('span.mono', null, i.caddyfile) : null,
      note ? el('span', null, note) : null),
    el('span.grow'),
    el('label.row', { style: { gap: '6px' } }, el('span.muted', { style: { fontSize: '12.5px' } }, 'Wechseln:'),
      select(instState.list.map(x => [x.id, x.name + (x.online ? '' : ' (offline)')]), id, (v, ev) => {
        if (!canLeave()) { if (ev?.target) ev.target.value = id; return; }
        if (instState.value !== 'all') instState.set(v); else { instState.page = instState.lastPage = v; instState.listeners.forEach(f => f(instState.value)); }
      }, { 'aria-label': 'Caddy-Instanz wechseln' })));
}

/** Asks before leaving a page with unsaved changes (editor). */
export function canLeave() {
  try { return !window.__leaveGuard?.() || window.confirm('Ungespeicherte Änderungen verwerfen?'); } catch { return true; }
}

/** Pins the page instance and puts the bar above the page content. */
export function withInstance(root, opts = {}) {
  const inst = pageInstance(opts);
  const bar = instanceBar(inst, opts);
  if (!bar) return { root, inst };
  const inner = el('div');
  mount(root, bar, inner);
  return { root: inner, inst };
}
