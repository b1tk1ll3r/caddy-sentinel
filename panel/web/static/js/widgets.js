import { diagnosisBox } from './diagnosis.js';
import { instChip, instState, NON_BLOCKING, flag, countryName, countryLabel, el, mount, fmtInt, fmtMs, fmtBytes, fmtTime, fmtDateTime, fmtAgo, actionBadge, statusBadge, sevBadge, ipLink, copy, empty } from './ui.js';

export function topTable(entries, { label = 'Wert', render, onPick, showErrors = true, showBlocked = true } = {}) {
  if (!entries?.length) return empty('Keine Daten im Zeitraum');
  const max = Math.max(...entries.map(e => e.count), 1);
  return el('div.table-wrap', null, el('table', null,
    el('thead', null, el('tr', null, el('th', null, label), el('th.num', null, 'Requests'),
      showErrors ? el('th.num', null, 'Fehler') : null, showBlocked ? el('th.num', null, 'Blockiert') : null, el('th.num', null, 'Ø Zeit'))),
    el('tbody', null, entries.map(e => el('tr' + (onPick ? '.clickable' : ''), { onclick: onPick ? () => onPick(e.key) : null },
      el('td.bar-cell', null, el('i.bar', { style: { width: (e.count / max * 100).toFixed(1) + '%' } }),
        el('span.trunc', { title: e.key }, render ? render(e.key) : (e.key || '–'))),
      el('td.num', null, fmtInt(e.count)),
      showErrors ? el('td.num', { style: { color: e.errors ? 'var(--warn)' : null } }, fmtInt(e.errors)) : null,
      showBlocked ? el('td.num', { style: { color: e.blocked ? 'var(--bad)' : null } }, fmtInt(e.blocked)) : null,
      el('td.num.muted', null, fmtMs(e.avg_ms)))))));
}

const EVENT_TYPES = { audit: 'Audit', waf: 'WAF', honeypot: 'Honeypot', ban: 'Sperre', unban: 'Entsperrt', alert: 'Alarm', config: 'Konfiguration', agent: 'Agent', ratelimit: 'Ratelimit', useragent: 'User-Agent' };
export const eventTypeLabel = (t) => EVENT_TYPES[t] || t;

export function eventList(events, { compact = false } = {}) {
  if (!events?.length) return empty('Keine Ereignisse', 'Sobald Sentinel etwas erkennt, erscheint es hier.');
  return el('div.table-wrap', null, el('table', null,
    el('thead', null, el('tr', null, el('th', null, 'Zeit'), el('th', null, 'Art'), el('th', null, 'Ereignis'), compact ? null : el('th', null, 'Quelle'))),
    el('tbody', null, events.map(e => el('tr.clickable', { onclick: () => eventDrawer(e) },
      el('td.nowrap.muted', { title: fmtDateTime(e.ts) }, compact ? fmtAgo(e.ts) : fmtDateTime(e.ts)),
      el('td.nowrap', null, sevBadge(e.severity), ' ', el('span.muted', null, eventTypeLabel(e.type))),
      el('td', null, el('span.trunc', { title: e.title }, e.title)),
      compact ? null : el('td.nowrap', null, e.inst && instState.value === 'all' ? instChip(e.inst) : null, e.ip ? ipLink(e.ip) : '', e.host ? el('span.muted', null, ' ' + e.host) : ''))))));
}

export function eventDrawer(e) {
  let d = e.detail;
  const body = [
    el('dl.kv', null,
      el('dt', null, 'Zeit'), el('dd', null, fmtDateTime(e.ts)),
      el('dt', null, 'Art'), el('dd', null, eventTypeLabel(e.type)),
      el('dt', null, 'Schwere'), el('dd', null, sevBadge(e.severity)),
      e.ip ? [el('dt', null, 'IP'), el('dd', null, ipLink(e.ip))] : null,
      e.host ? [el('dt', null, 'Host'), el('dd', null, e.host)] : null,
      e.policy ? [el('dt', null, 'Policy'), el('dd', null, el('a', { href: '#/policies/' + e.policy }, e.policy))] : null),
  ];
  if (d && d.hits?.length) body.push(hitsTable(d.hits));
  if (d) body.push(el('pre.block', null, JSON.stringify(d, null, 2)));
  drawer(e.title, body);
}

export function hitsTable(hits) {
  return el('div.table-wrap', null, el('table', null,
    el('thead', null, el('tr', null, el('th', null, 'Regel'), el('th', null, 'Meldung'), el('th', null, 'Daten'))),
    el('tbody', null, hits.map(h => el('tr', null,
      el('td.mono.nowrap', null, h.id, h.dis ? el('span.badge.bad', { style: { marginLeft: '6px' } }, 'blockiert') : null),
      el('td', null, h.msg, h.tags?.length ? el('div', null, h.tags.map(t => el('span.badge', { style: { marginRight: '4px' } }, t))) : null),
      el('td.mono', null, el('span.trunc', { title: h.data || '' }, h.data || '')))))));
}

let openDrawer;
export function drawer(title, body, actions) {
  openDrawer?.remove();
  const close = () => { d.remove(); document.removeEventListener('keydown', onKey); openDrawer = null; };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const d = el('aside.drawer', { role: 'dialog', 'aria-label': title },
    el('header', null, el('h2', { style: { fontSize: '15px' } }, title), el('div.row', { style: { marginLeft: 'auto' } }, actions || null, el('button.icon-btn', { onclick: close, 'aria-label': 'Schließen' }, '✕'))),
    el('div.drawer-body', null, body));
  document.body.append(d);
  document.addEventListener('keydown', onKey);
  openDrawer = d;
  d.querySelector('button')?.focus();
  return { close };
}

export function requestRows(rows, { onPick, showHost = true } = {}) {
  return rows.map(r => el('tr.clickable' + (r.a && !NON_BLOCKING.has(r.a) ? '.blocked' : r.a ? '.detected' : ''), { onclick: () => (onPick || requestDrawer)(r) },
    el('td.nowrap.muted', { title: fmtDateTime(r.t) }, fmtTime(r.t)),
    el('td', null, statusBadge(r.s)),
    el('td.nowrap', null, r.m),
    showHost ? el('td.nowrap.muted', null, instState.value === 'all' ? instChip(r.inst) : null, instState.value === 'all' && instState.multi() ? ' ' : null, r.host) : null,
    el('td', null, el('span.trunc', { title: r.p + (r.q ? '?' + r.q : '') }, r.p, r.q ? el('span.muted', null, '?' + r.q) : null)),
    el('td.nowrap.mono', { title: r.cc ? countryName(r.cc) + (r.asn ? ` · AS${r.asn} ${r.aso || ''}` : '') : '' }, r.cc ? flag(r.cc) + ' ' : '', r.ip),
    el('td.num.muted', null, fmtMs(r.d)),
    el('td', null, el('span.nowrap', null, actionBadge(r.a), r.ws ? el('span.muted', null, ' Score ' + r.ws) : null),
      r.a && !NON_BLOCKING.has(r.a) && (r.why || r.det) ? el('small.muted.trunc', { style: { display: 'block', maxWidth: '240px' }, title: [r.det, r.why].filter(Boolean).join(' · ') }, r.why || r.det) : null)));
}

export function requestTable(rows, opts = {}) {
  if (!rows?.length) return empty('Keine Requests', opts.emptyText || 'Für die gewählten Filter liegen keine Requests vor.');
  return el('div.table-wrap', null, el('table', null,
    el('thead', null, el('tr', null, el('th', null, 'Zeit'), el('th', null, 'Status'), el('th', null, 'Methode'),
      opts.showHost !== false ? el('th', null, 'Host') : null, el('th', null, 'Pfad'), el('th', null, 'Client'), el('th.num', null, 'Dauer'), el('th', null, 'Aktion'))),
    el('tbody', null, requestRows(rows, opts))));
}

export function requestDrawer(r) {
  const url = r.p + (r.q ? '?' + r.q : '');
  drawer(`${r.m} ${r.p}`, [
    diagnosisBox(r, { onUnban: () => requestDrawer(r) }),
    el('h3', { style: { margin: '4px 0 0', fontSize: '13px' } }, 'Request-Daten'),
    el('dl.kv', null,
      el('dt', null, 'Zeit'), el('dd', null, fmtDateTime(r.t)),
      instState.multi() ? [el('dt', null, 'Caddy-Instanz'), el('dd', null, instChip(r.inst, { always: true }))] : null,
      el('dt', null, 'Host'), el('dd', null, r.host),
      el('dt', null, 'URL'), el('dd.mono', null, url),
      el('dt', null, 'Status'), el('dd', null, statusBadge(r.s)),
      el('dt', null, 'Client'), el('dd', null, ipLink(r.ip), r.cc ? el('span.muted', null, ' ' + countryLabel(r.cc)) : null),
      r.asn ? [el('dt', null, 'Netz'), el('dd', null, `AS${r.asn} ${r.aso || ''}`)] : null,
      r.usr ? [el('dt', null, 'Benutzer'), el('dd', null, r.usr, el('span.muted', null, ' (Site-Login)'))] : null,
      el('dt', null, 'User-Agent'), el('dd', null, r.ua || '–'),
      r.ref ? [el('dt', null, 'Referer'), el('dd', null, r.ref)] : null,
      el('dt', null, 'Protokoll'), el('dd', null, r.proto || '–'),
      el('dt', null, 'Antwort'), el('dd', null, fmtBytes(r.b) + ' in ' + fmtMs(r.d)),
      el('dt', null, 'Policy'), el('dd', null, r.pol ? el('a', { href: '#/policies/' + r.pol }, r.pol) : '–'),
      r.a ? [el('dt', null, 'Aktion'), el('dd', null, actionBadge(r.a), r.det ? el('span.muted', null, ' ' + r.det) : null)] : null,
      r.why ? [el('dt', null, 'Begründung'), el('dd', null, r.why)] : null,
      r.sref ? [el('dt', null, 'Referenz'), el('dd.mono', null, r.sref)] : null,
      r.ws ? [el('dt', null, 'Anomalie-Score'), el('dd', null, r.ws)] : null),
    r.hits?.length ? el('div', null, el('h3', { style: { margin: '6px 0' } }, 'WAF-Treffer'), hitsTable(r.hits)) : null,
    el('div.row', null,
      el('a.btn', { href: `#/waf?method=${encodeURIComponent(r.m)}&url=${encodeURIComponent(url)}&ua=${encodeURIComponent(r.ua || '')}&policy=${encodeURIComponent(r.pol || '')}` }, 'Im WAF-Tester öffnen'),
      el('button.btn', { onclick: () => copy(`curl -i -X ${r.m} -H 'User-Agent: ${(r.ua || '').replace(/'/g, '')}' 'http://${r.host}${url}'`) }, 'Als curl kopieren')),
  ]);
}

export function kpi(label, value, { trend, kind, sub, title } = {}) {
  return el('div.kpi' + (kind ? '.' + kind : ''), { title },
    el('div.label', null, label),
    el('div.value', null, value),
    trend || sub ? el('div', null, trend || null, sub ? el('span.muted', { style: { fontSize: '12px' } }, sub) : null) : null);
}

export function trend(cur, prev, { goodUp = false } = {}) {
  if (prev == null) return null;
  if (!prev && !cur) return el('span.trend.flat', null, '±0 %');
  if (!prev) return el('span.trend.flat', null, 'neu');
  const d = (cur - prev) / prev;
  const cls = Math.abs(d) < 0.02 ? 'flat' : d > 0 ? 'up' : 'down';
  const arrow = cls === 'flat' ? '±' : d > 0 ? '▲ ' : '▼ ';
  return el('span.trend.' + cls + (goodUp ? '.good-up' : ''), { title: 'gegenüber dem vorherigen Zeitraum' }, arrow + Math.abs(d * 100).toFixed(0) + ' %');
}

export function seg(options, value, onChange) {
  const wrap = el('div.seg', { role: 'group' });
  const draw = (v) => mount(wrap, options.map(([k, label, kind]) => el('button' + (k === v ? '.active' + (kind ? '.' + kind : '') : ''), {
    type: 'button', 'aria-pressed': k === v ? 'true' : 'false', onclick: () => { draw(k); onChange(k); },
  }, label)));
  draw(value);
  return wrap;
}
