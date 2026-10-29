import { el, mount, get, fmtInt, fmt1, panel, debounce, NON_BLOCKING, instState } from '../ui.js';
import { timeChart, legend } from '../charts.js';
import { requestRows, seg } from '../widgets.js';
import { bus } from '../app.js';

export async function render(root, _p, scope) {
  const N = 300;
  const series = [
    { label: 'Requests/s', color: 'var(--series-1)', values: [] },
    { label: '5xx/s', color: 'var(--series-3)', values: [] },
    { label: 'Blockiert/s', color: 'var(--series-4)', values: [] },
  ];
  const chart = timeChart({ series, t: [], kind: 'line', height: 190, yFormat: (v) => fmt1(v), label: 'Live-Traffic pro Sekunde' });
  let pts = await get('/stats/live?n=' + N, scope.signal);
  const redraw = () => {
    series[0].values = pts.map(p => p.req);
    series[1].values = pts.map(p => p.err);
    series[2].values = pts.map(p => p.blocked);
    chart.update({ t: pts.map(p => p.t) });
  };
  redraw();

  let mode = 'all', paused = false, filter = '';
  const rows = [];
  const tbody = el('tbody');
  const counter = el('span.muted');
  const pauseBtn = el('button.btn', { onclick: () => { paused = !paused; pauseBtn.textContent = paused ? 'Fortsetzen' : 'Anhalten'; } }, 'Anhalten');
  const search = el('input', { type: 'search', placeholder: 'Filtern nach Host, Pfad, IP, User-Agent …', style: { minWidth: '280px' }, oninput: debounce((e) => { filter = e.target.value.toLowerCase(); draw(); }, 150) });

  const matches = (r) => {
    if (instState.value !== 'all' && (r.inst || 'local') !== instState.value) return false;
    if (mode === 'blocked' && !(r.a && !NON_BLOCKING.has(r.a))) return false;
    if (mode === 'security' && !r.a) return false;
    if (mode === 'errors' && r.s < 400) return false;
    if (filter && !`${r.host} ${r.p} ${r.q || ''} ${r.ip} ${r.usr || ''} ${r.ua || ''} ${r.s} ${r.m}`.toLowerCase().includes(filter)) return false;
    return true;
  };
  const draw = () => {
    const vis = rows.filter(matches).slice(0, 250);
    mount(tbody, requestRows(vis));
    counter.textContent = `${fmtInt(vis.length)} von ${fmtInt(rows.length)} Requests im Puffer`;
  };

  // seed with recent requests
  const recent = await get('/requests?range=15m&limit=150', scope.signal);
  rows.push(...recent);
  draw();

  scope.listen(bus, 'requests', (e) => {
    if (paused) return;
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
        seg([['all', 'Alle'], ['security', 'Sicherheitsrelevant'], ['blocked', 'Blockiert', 'bad'], ['errors', 'Fehler', 'warn']], mode, (m) => { mode = m; draw(); }),
        search, el('span.grow'), counter, pauseBtn),
      el('div.table-wrap', { style: { maxHeight: 'calc(100vh - 470px)', minHeight: '300px', overflow: 'auto' } },
        el('table.stream', null,
          el('thead', null, el('tr', null, el('th', null, 'Zeit'), el('th', null, 'Status'), el('th', null, 'Methode'), el('th', null, 'Host'), el('th', null, 'Pfad'), el('th', null, 'Client'), el('th.num', null, 'Dauer'), el('th', null, 'Aktion'))),
          tbody)),
      el('small', null, 'Bei einer Telemetrie-Stichprobe unter 100 % zeigt der Stream nur die Stichprobe – sicherheitsrelevante Requests und Fehler werden immer übertragen.'))));
}
