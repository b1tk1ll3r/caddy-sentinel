import { el, mount, get, fmtInt, fmt1, panel, debounce, NON_BLOCKING, instState, qs, select, ACTIONS } from '../ui.js';
import { viewsBar } from '../views.js';
import { timeChart, legend } from '../charts.js';
import { requestRows, seg } from '../widgets.js';
import { bus } from '../app.js';

export async function render(root, _p, scope, q) {
  const N = 300;
  const series = [
    { label: 'Requests/s', color: 'var(--c-requests)', values: [] },
    { label: '5xx/s', color: 'var(--c-5xx)', values: [] },
    { label: 'Blockiert/s', color: 'var(--c-blocked)', values: [] },
  ];
  const chart = timeChart({ series, t: [], kind: 'line', height: 190, yFormat: (v) => fmt1(v), fractional: true, label: 'Live-Traffic pro Sekunde' });
  let pts = await get('/stats/live?n=' + N, scope.signal);
  const redraw = () => {
    series[0].values = pts.map(p => p.req);
    series[1].values = pts.map(p => p.err);
    series[2].values = pts.map(p => p.blocked);
    chart.update({ t: pts.map(p => p.t) });
  };
  redraw();

  let mode = q?.get('mode') || 'all', paused = false, filter = q?.get('q') || '';
  const f = { host: q?.get('host') || '', status: q?.get('status') || '', action: q?.get('action') || '', ip: q?.get('ip') || '' };
  const sync = () => history.replaceState(null, '', '#/live' + qs({ mode: mode === 'all' ? '' : mode, q: filter, ...f }));
  let hoverPause = false;
  const rows = [];
  const pending = [];
  const tbody = el('tbody');
  const counter = el('span.muted');
  const pauseBtn = el('button.btn', { onclick: () => { paused = !paused; pauseBtn.textContent = paused ? 'Fortsetzen' : 'Anhalten'; } }, 'Anhalten');
  const search = el('input', { type: 'search', value: filter, placeholder: 'Volltext: Pfad, User-Agent, Benutzer …', style: { minWidth: '220px' }, oninput: debounce((e) => { filter = e.target.value.toLowerCase(); sync(); draw(); }, 150) });
  const hostSel = el('span');
  const knownHosts = new Set();
  const drawHostSel = () => mount(hostSel, select([['', 'Alle Hosts'], ...[...knownHosts].sort().map(h => [h, h])], f.host, (v) => { f.host = v; sync(); draw(); }, { 'aria-label': 'Host' }));
  drawHostSel();
  const statusSel = select([['', 'Alle Status'], ['2', '2xx'], ['3', '3xx'], ['4', '4xx'], ['5', '5xx'], ['401', '401'], ['403', '403'], ['404', '404'], ['429', '429'], ['502', '502'], ['503', '503']], f.status, (v) => { f.status = v; sync(); draw(); }, { 'aria-label': 'Status' });
  const actionSel = select([['', 'Alle Aktionen'], ...Object.entries(ACTIONS)], f.action, (v) => { f.action = v; sync(); draw(); }, { 'aria-label': 'Aktion' });
  const ipIn = el('input', { type: 'search', value: f.ip, placeholder: 'IP / Präfix', style: { width: '130px' }, oninput: debounce((e) => { f.ip = e.target.value.trim(); sync(); draw(); }, 200) });

  const matches = (r) => {
    if (instState.value !== 'all' && (r.inst || 'local') !== instState.value) return false;
    if (mode === 'blocked' && !(r.a && !NON_BLOCKING.has(r.a))) return false;
    if (mode === 'security' && !r.a) return false;
    if (mode === 'errors' && r.s < 400) return false;
    if (f.host && r.host !== f.host) return false;
    if (f.status && !(f.status.length === 1 ? String(r.s).startsWith(f.status) : String(r.s) === f.status)) return false;
    if (f.action && r.a !== f.action && r.a !== 'test:' + f.action) return false;
    if (f.ip && !r.ip.startsWith(f.ip.replace(/\*$/, ''))) return false;
    if (filter && !`${r.host} ${r.p} ${r.q || ''} ${r.ip} ${r.usr || ''} ${r.ua || ''} ${r.s} ${r.m}`.toLowerCase().includes(filter)) return false;
    return true;
  };
  const draw = () => {
    let added = false;
    for (const r of rows) if (r.host && !knownHosts.has(r.host)) { knownHosts.add(r.host); added = true; }
    if (added) drawHostSel();
    const vis = rows.filter(matches).slice(0, 250);
    mount(tbody, requestRows(vis));
    counter.textContent = `${fmtInt(vis.length)} von ${fmtInt(rows.length)} Requests im Puffer`;
  };

  // seed with recent requests
  const recent = await get('/requests?range=15m&limit=150', scope.signal);
  rows.push(...recent);
  draw();

  scope.listen(bus, 'requests', (e) => {
    if (paused || hoverPause) { if (!paused) pending.push(...e.detail); return; }
    if (pending.length) { e = { detail: [...pending, ...e.detail] }; pending.length = 0; }
    const incoming = e.detail.slice().reverse();
    rows.unshift(...incoming);
    if (rows.length > 2000) rows.length = 2000;
    draw();
    for (let i = 0; i < Math.min(incoming.length, tbody.children.length); i++) tbody.children[i].classList.add('new');
  });
  scope.listen(bus, 'tick', (e) => {
    pts.push(e.detail);
    if (pts.length > N) pts = pts.slice(-N);
    redraw();
  });

  mount(root,
    panel('Requests pro Sekunde (letzte 5 Minuten)', el('div.stack', null, chart, legend(series, () => chart.update({})))),
    panel('Request-Stream', el('div.stack', null,
      el('div.row', null,
        seg([['all', 'Alle'], ['security', 'Sicherheitsrelevant'], ['blocked', 'Blockiert', 'bad'], ['errors', 'Fehler', 'warn']], mode, (m) => { mode = m; sync(); draw(); }),
        hostSel, statusSel, actionSel, ipIn, search, el('span.grow'), counter, pauseBtn),
      viewsBar('live', scope),
      el('div.table-wrap', { style: { maxHeight: 'calc(100vh - 500px)', minHeight: '300px', overflow: 'auto' }, title: 'Beim Überfahren mit der Maus hält der Stream kurz an', onmouseenter: () => { hoverPause = true; }, onmouseleave: () => { hoverPause = false; } },
        el('table.stream', null,
          el('thead', null, el('tr', null, el('th', null, 'Zeit'), el('th', null, 'Status'), el('th', null, 'Methode'), el('th', null, 'Host'), el('th', null, 'Pfad'), el('th', null, 'Client'), el('th.num', null, 'Dauer'), el('th', null, 'Aktion'))),
          tbody)),
      el('small', null, 'Bei einer Telemetrie-Stichprobe unter 100 % zeigt der Stream nur die Stichprobe – sicherheitsrelevante Requests und Fehler werden immer übertragen.'))));
}
