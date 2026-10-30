import { countryLabel, el, mount, get, qs, fmtInt, fmtCompact, fmtMs, fmtBytes, fmtPct, rangeState, panel, select, debounce, ACTIONS, statusBadge, actionLabel } from '../ui.js';
import { timeChart, legend } from '../charts.js';
import { topTable, requestTable, kpi, seg } from '../widgets.js';
import { viewsBar } from '../views.js';

export async function render(root, _p, scope, q) {
  const f = {
    host: q.get('host') || '', status: q.get('status') || '', method: q.get('method') || '', action: q.get('action') || '',
    path: q.get('path') || '', ip: q.get('ip') || '', ua: q.get('ua') || '', q: q.get('q') || '', policy: q.get('policy') || '',
    country: q.get('country') || '', asn: q.get('asn') || '',
  };
  const ov = await get('/stats/overview?range=30d', scope.signal);
  const hosts = (ov.current.hosts || []).map(h => h.host);
  const pols = (await get('/policies', scope.signal)).policies;

  const series = [
    { label: 'Requests', color: 'var(--series-1)', values: [] },
    { label: 'Fehler (4xx/5xx)', color: 'var(--series-3)', values: [] },
    { label: 'Blockiert', color: 'var(--series-4)', values: [] },
  ];
  const chart = timeChart({ series, t: [], kind: 'area', height: 200, yFormat: fmtCompact });
  const kpis = el('div.kpis');
  const tops = {};
  const dims = [['path', 'Pfade', 'Pfad'], ['ip', 'Clients', 'IP'], ['ua', 'User-Agents', 'User-Agent'], ['status', 'Statuscodes', 'Status'],
    ['country', 'Länder', 'Land'], ['asn', 'Netze (ASN)', 'Netz'],
    ['referer', 'Referer', 'Referer'], ['method', 'Methoden', 'Methode'], ['action', 'Sentinel-Aktionen', 'Aktion'], ['host', 'Hosts', 'Host']];
  for (const [d] of dims) tops[d] = el('div');
  const reqBox = el('div');
  const moreBtn = el('button.btn', { onclick: () => loadRequests(true) }, 'Weitere laden');
  let lastID = 0;
  let reqRows = [];

  const setF = (k, v) => { f[k] = v; syncURL(); reload(); };
  const syncURL = () => {
    const s = qs(f);
    history.replaceState(null, '', '#/analytics' + s);
  };
  const input = (k, ph, w = 150) => el('input', { type: 'search', value: f[k], placeholder: ph, style: { width: w + 'px' }, oninput: debounce((e) => setF(k, e.target.value.trim()), 350) });

  const filterBar = el('div.row', null,
    select([['', 'Alle Hosts'], ...hosts.map(h => [h, h])], f.host, (v) => setF('host', v), { 'aria-label': 'Host' }),
    select([['', 'Alle Policies'], ...pols.map(p => [p.id, p.name])], f.policy, (v) => setF('policy', v), { 'aria-label': 'Policy' }),
    select([['', 'Alle Status'], ['2xx', '2xx Erfolg'], ['3xx', '3xx Umleitung'], ['4xx', '4xx Client-Fehler'], ['5xx', '5xx Server-Fehler'], ['404', '404'], ['403', '403'], ['429', '429'], ['500', '500'], ['502', '502']], f.status, (v) => setF('status', v), { 'aria-label': 'Status' }),
    select([['', 'Alle Methoden'], 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], f.method, (v) => setF('method', v), { 'aria-label': 'Methode' }),
    select([['', 'Alle Aktionen'], ['none', 'Ohne Eingriff'], ['any', 'Mit Eingriff'], ['blocked', 'Blockiert'], ...Object.entries(ACTIONS)], f.action, (v) => setF('action', v), { 'aria-label': 'Aktion' }),
    input('country', 'Land (DE)', 90), input('asn', 'ASN', 80),
    input('path', 'Pfad enthält …'), input('ip', 'IP (Präfix mit *)', 140), input('ua', 'User-Agent …'), input('q', 'Volltext …', 160),
    el('button.btn.ghost', { onclick: () => { Object.keys(f).forEach(k => f[k] = ''); syncURL(); render(root, _p, scope, new URLSearchParams()); } }, 'Zurücksetzen'));

  mount(root,
    panel('Filter', el('div.stack', { style: { gap: '8px' } }, filterBar, viewsBar('analytics', scope))),
    kpis,
    panel(null, el('div.stack', null, chart, legend(series, () => chart.update({})))),
    el('div.grid.g2', null, dims.map(([d, title]) => panel(title, tops[d]))),
    panel('Request-Explorer', el('div.stack', null, reqBox, el('div.row', null, moreBtn,
      el('button.btn.ghost', { onclick: exportCSV }, 'Als CSV exportieren')))),
  );

  async function reload() {
    const base = { range: rangeState.value, ...f };
    const [ovr, top] = await Promise.all([
      get('/stats/overview' + qs({ range: rangeState.value, host: f.host, policy: f.policy }), scope.signal),
      get('/stats/top' + qs({ ...base, dim: dims.map(d => d[0]).join(','), limit: 12 }), scope.signal),
    ]);
    const c = ovr.current;
    const s = c.series;
    series[0].values = s.map(x => x.req);
    series[1].values = s.map(x => x.s4 + x.s5);
    series[2].values = s.map(x => x.blocked);
    chart.update({ t: s.map(x => x.t) });
    const filtered = Object.values(f).some(Boolean) && !(Object.entries(f).every(([k, v]) => !v || k === 'host' || k === 'policy'));
    mount(kpis,
      kpi('Requests', fmtCompact(c.requests)),
      kpi('Fehlerquote', fmtPct(c.requests ? (c.errors_4xx + c.errors_5xx) / c.requests : 0)),
      kpi('Blockiert', fmtCompact(c.blocked), { kind: c.blocked ? 'bad' : '' }),
      kpi('Ø Antwortzeit', fmtMs(c.avg_ms), { sub: ' p95 ' + fmtMs(c.p95_ms) }),
      kpi('Datenvolumen', fmtBytes(c.bytes)),
      filtered ? kpi('Gefiltert', 'Rohdaten', { sub: 'Diagramm zeigt alle Requests des Hosts' }) : null);
    for (const [d, , label] of dims) {
      const pick = (v) => {
        const map = { path: 'path', ip: 'ip', ua: 'ua', status: 'status', method: 'method', action: 'action', host: 'host', country: 'country' };
        if (d === 'ip') { location.hash = '#/ip/' + encodeURIComponent(v); return; }
        if (d === 'country') { setF('country', v || '-'); return; }
        if (d === 'asn') { const m = /^AS(\d+)/.exec(v); if (m) setF('asn', m[1]); return; }
        if (map[d]) setF(map[d], v);
      };
      const render = d === 'status' ? (v) => statusBadge(+v) : d === 'action' ? (v) => v ? (actionLabel(v)) : 'ohne Eingriff'
        : d === 'country' ? (v) => countryLabel(v) : d === 'asn' ? (v) => v || 'unbekannt' : null;
      mount(tops[d], topTable(top[d], { label, onPick: d === 'referer' ? null : pick, render }));
    }
    await loadRequests(false);
  }

  async function loadRequests(more) {
    const rows = await get('/requests' + qs({ range: rangeState.value, ...f, limit: 100, before: more ? lastID : '' }), scope.signal);
    reqRows = more ? reqRows.concat(rows) : rows;
    lastID = rows.length ? rows[rows.length - 1].id : lastID;
    moreBtn.hidden = rows.length < 100;
    mount(reqBox, requestTable(reqRows));
  }

  function exportCSV() {
    const head = ['zeit', 'host', 'methode', 'pfad', 'query', 'status', 'ip', 'land', 'asn', 'dauer_ms', 'bytes', 'aktion', 'policy', 'user_agent'];
    const esc = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const lines = [head.join(';')].concat(reqRows.map(r => [new Date(r.t).toISOString(), r.host, r.m, r.p, r.q, r.s, r.ip, r.cc, r.asn ? 'AS' + r.asn + ' ' + (r.aso || '') : '', r.d, r.b, r.a, r.pol, r.ua].map(esc).join(';')));
    const blob = new Blob(['﻿' + lines.join('\n')], { type: 'text/csv;charset=utf-8' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `sentinel-requests-${Date.now()}.csv` });
    document.body.append(a); a.click(); a.remove();
  }

  const onRange = () => reload();
  rangeState.listeners.add(onRange);
  scope.on(() => rangeState.listeners.delete(onRange));
  await reload();
}
