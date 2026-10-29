import { el, mount, get, qs, fmtInt, fmtCompact, fmtMs, fmtBytes, fmtPct, fmt1, rangeState, panel, empty, ACTIONS, fmtAgo, actionLabel, instState, instChip } from '../ui.js';
import { timeChart, legend, barChart } from '../charts.js';
import { kpi, trend, eventList, topTable } from '../widgets.js';
import { bus } from '../app.js';

export async function render(root, _params, scope) {
  const kpis = el('div.kpis');
  const trafficSeries = [
    { label: '2xx', color: 'var(--series-2)', values: [] },
    { label: '3xx', color: 'var(--series-6)', values: [] },
    { label: '4xx', color: 'var(--series-3)', values: [] },
    { label: '5xx', color: 'var(--series-4)', values: [] },
  ];
  const traffic = timeChart({ series: trafficSeries, t: [], stacked: true, kind: 'area', height: 230, yFormat: fmtCompact, label: 'Requests nach Status' });
  const latSeries = [
    { label: 'Ø', color: 'var(--series-1)', values: [] },
    { label: 'p95', color: 'var(--series-5)', values: [], dashed: true },
  ];
  const latency = timeChart({ series: latSeries, t: [], kind: 'line', height: 170, yFormat: fmtMs, label: 'Antwortzeit' });
  const blockedSeries = [{ label: 'Blockiert', color: 'var(--series-4)', values: [] }];
  const blocked = timeChart({ series: blockedSeries, t: [], kind: 'bar', height: 120, yFormat: fmtCompact, label: 'Blockierte Requests' });
  const actionsBox = el('div');
  const eventsBox = el('div');
  const hostsBox = el('div');
  const histBox = el('div');
  const rulesBox = el('div');
  const healthBox = el('div');
  const banner = el('div');
  const warnBox = el('div');
  const instBox = el('div');

  mount(root,
    warnBox,
    instBox,
    banner,
    kpis,
    el('div.grid.g-main', null,
      panel('Traffic', el('div.stack', null, traffic, legend(trafficSeries, () => traffic.update({})))),
      panel('Schutzmaßnahmen', el('div.stack', null, blocked, actionsBox))),
    el('div.grid.g-main', null,
      panel('Antwortzeit', el('div.stack', null, latency, legend(latSeries, () => latency.update({})))),
      panel('Latenzverteilung', histBox)),
    el('div.grid.g-main', null,
      panel('Sites', hostsBox, el('a', { href: '#/sites' }, 'Alle Sites')),
      panel('Neueste Sicherheitsereignisse', eventsBox, el('a', { href: '#/security' }, 'Sicherheit'))),
    el('div.grid.g2', null,
      panel('Meistgetroffene WAF-Regeln', rulesBox),
      panel('Caddy-Prozess', healthBox)),
  );

  const SEV = { 4: ['bad', 'Kritisch'], 3: ['bad', 'Problem'], 2: ['warn', 'Warnung'], 1: ['info', 'Hinweis'] };
  const loadWarnings = async () => {
    const { warnings } = await get('/warnings', scope.signal);
    mount(warnBox, warnings.length ? panel(`Was Aufmerksamkeit braucht (${warnings.length})`, el('ul.warn-list', null, warnings.slice(0, 12).map(w => el('li.' + (SEV[w.severity]?.[0] || 'info'), null,
      el('span.badge.' + (SEV[w.severity]?.[0] || 'info'), null, SEV[w.severity]?.[1] || 'Hinweis'),
      el('div', null, el('div', null, instChip(w.inst), instChip(w.inst) ? ' ' : null, w.href ? el('a', { href: w.href }, w.title) : el('b', null, w.title)), w.detail ? el('small.muted', null, w.detail) : null)))),
      warnings.length > 12 ? el('small.muted', null, `… und ${warnings.length - 12} weitere`) : null) : null);
    // instance overview (only with several Caddy servers and "all" selected)
    if (instState.multi() && instState.value === 'all') {
      mount(instBox, el('div.inst-strip', null, instState.list.map(i => el('a.inst-tile', { href: '#', style: { '--ic': i.color }, onclick: (e) => { e.preventDefault(); instState.set(i.id); } },
        el('b', null, i.name), el('span', null, el('span.dot.' + (i.online ? 'ok' : 'bad')), i.online ? ' verbunden' : ' offline'), el('small.muted', null, i.remote === 'local' ? 'Panel-Server' : i.remote === 'full' ? 'Fernverwaltung' : i.remote === 'read' ? 'nur lesen' : '')))));
    } else mount(instBox);
  };
  loadWarnings().catch(() => { });
  const wt = setInterval(() => { if (!document.hidden) loadWarnings().catch(() => { }); }, 60000);
  scope.on(() => clearInterval(wt));

  const load = async () => {
    const q = qs({ range: rangeState.value, host: rangeState.host });
    const [ov, evs, rules] = await Promise.all([
      get('/stats/overview' + q, scope.signal),
      get('/events?limit=12&type=waf,honeypot,ban,alert,ratelimit,agent', scope.signal),
      get('/stats/rules' + q + '&limit=8', scope.signal),
    ]);
    const c = ov.current, p = ov.previous || {};
    const span = ov.to - ov.from;
    const rps = c.requests / Math.max(span, 1);
    const err5 = c.requests ? c.errors_5xx / c.requests : 0;
    const perr5 = p.requests ? p.errors_5xx / p.requests : 0;
    const st = window.__status || {};
    mount(kpis,
      kpi('Requests', fmtCompact(c.requests), { trend: trend(c.requests, p.requests, { goodUp: true }), sub: ' · ' + fmt1(rps) + '/s' }),
      kpi('Server-Fehler (5xx)', fmtPct(err5), { kind: err5 > 0.05 ? 'bad' : err5 > 0.01 ? 'warn' : '', trend: trend(err5, perr5), title: fmtInt(c.errors_5xx) + ' Requests' }),
      kpi('Client-Fehler (4xx)', fmtCompact(c.errors_4xx), { trend: trend(c.errors_4xx, p.errors_4xx) }),
      kpi('Blockiert', fmtCompact(c.blocked), { kind: c.blocked ? 'bad' : '', trend: trend(c.blocked, p.blocked) }),
      kpi('Antwortzeit p95', fmtMs(c.p95_ms), { trend: trend(c.p95_ms, p.p95_ms), sub: ' Ø ' + fmtMs(c.avg_ms) }),
      kpi('Datenvolumen', fmtBytes(c.bytes), { trend: trend(c.bytes, p.bytes, { goodUp: true }) }),
      kpi('Aktive Sperren', fmtInt(st.bans || 0), { kind: st.bans ? 'warn' : '', sub: st.tracked_ips ? `${fmtInt(st.tracked_ips)} IPs beobachtet` : '' }),
    );
    const t = c.series.map(x => x.t);
    trafficSeries[0].values = c.series.map(x => x.s2);
    trafficSeries[1].values = c.series.map(x => x.s3);
    trafficSeries[2].values = c.series.map(x => x.s4);
    trafficSeries[3].values = c.series.map(x => x.s5);
    traffic.update({ t });
    latSeries[0].values = c.series.map(x => x.avg);
    latSeries[1].values = c.series.map(x => x.p95);
    latency.update({ t });
    blockedSeries[0].values = c.series.map(x => x.blocked);
    blocked.update({ t });

    const acts = Object.entries(c.by_action || {}).sort((a, b) => b[1] - a[1]);
    mount(actionsBox, acts.length ? el('table', null, el('tbody', null, acts.map(([a, n]) => el('tr', null,
      el('td', null, el('span.badge.' + (a === 'waf_detect' ? 'warn' : 'bad'), null, actionLabel(a))),
      el('td.num', null, fmtInt(n)))))) : empty('Nichts blockiert', 'Im Zeitraum musste Sentinel nicht eingreifen.'));

    const labels = c.hist_bounds.map(b => b >= 1000 ? String(b / 1000).replace('.', ',') + ' s' : String(b)).concat(['mehr']);
    mount(histBox, c.requests ? el('div.stack', null,
      barChart(labels, c.histogram, { height: 170, format: fmtInt }),
      el('div.row.muted', { style: { fontSize: '12px' } }, el('span', null, 'Obergrenzen in ms'), el('span.grow'), el('span', null, `p50 ${fmtMs(c.p50_ms)}`), el('span', null, `p95 ${fmtMs(c.p95_ms)}`), el('span', null, `p99 ${fmtMs(c.p99_ms)}`), el('span', null, `max ${fmtMs(c.max_ms)}`))) : empty('Noch keine Requests'));

    mount(hostsBox, c.hosts?.length ? topTable(c.hosts.slice(0, 10).map(h => ({ key: h.host, count: h.requests, errors: h.errors, blocked: h.blocked, avg_ms: h.avg_ms })),
      { label: 'Host', onPick: (h) => { location.hash = '#/analytics?host=' + encodeURIComponent(h); } }) : noTraffic());
    mount(eventsBox, eventList(evs, { compact: true }));
    mount(rulesBox, rules.length ? el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Regel'), el('th', null, 'Beschreibung'), el('th.num', null, 'Treffer'), el('th.num', null, 'Blockiert'))),
      el('tbody', null, rules.map(r => el('tr', null, el('td.mono', null, r.id), el('td', null, el('span.trunc', null, r.msg)), el('td.num', null, fmtInt(r.count)), el('td.num', null, fmtInt(r.blocked))))))) : empty('Keine WAF-Treffer im Zeitraum'));

    if (!st.caddy_ok) mount(banner, el('div.callout.bad', null, 'Caddy ist nicht erreichbar: ', st.caddy_error || '', '. Prüfe, ob Caddy läuft und die Admin-API unter ', el('code', null, st.caddy_admin), ' erreichbar ist.'));
    else if (!(st.agents || []).some(a => a.online)) mount(banner, el('div.callout.warn', null, 'Es ist noch kein Sentinel-Agent verbunden. Caddy muss mit dem Sentinel-Modul gebaut sein und mindestens eine Site die Direktive ', el('code', null, 'sentinel'), ' enthalten. Details unter ', el('a', { href: '#/settings' }, 'Einstellungen › Agent'), '.'));
    else mount(banner);
  };

  const loadHealth = async () => {
    try {
      const m = await get('/caddy/metrics', scope.signal);
      const up = m.start_time ? fmtAgo(m.start_time * 1000).replace('vor ', '') : '–';
      const ups = (m.upstreams || []);
      mount(healthBox, el('dl.kv', null,
        el('dt', null, 'Laufzeit'), el('dd', null, up),
        el('dt', null, 'Speicher (RSS)'), el('dd', null, fmtBytes(m.memory_rss)),
        el('dt', null, 'Goroutinen'), el('dd', null, fmtInt(m.goroutines)),
        el('dt', null, 'CPU-Zeit'), el('dd', null, fmt1(m.cpu_seconds) + ' s'),
        el('dt', null, 'Letzter Reload'), el('dd', null, m.config_reloaded ? fmtAgo(m.config_reloaded * 1000) + (m.config_success ? ' · erfolgreich' : ' · fehlgeschlagen') : '–'),
        el('dt', null, 'Upstreams'), el('dd', null, ups.length ? ups.map(u => el('div', null, el('span.dot.' + (u.value ? 'ok' : 'bad')), ' ', u.labels?.upstream || '?')) : 'keine Health-Checks konfiguriert')));
    } catch (e) {
      mount(healthBox, el('p.muted', null, 'Prozess-Metriken nicht verfügbar: ', e.message, '. Für Upstream-Status in Caddy ', el('code', null, 'metrics'), ' als globale Option aktivieren.'));
    }
  };

  await load();
  loadHealth();
  scope.interval(() => { if (!document.hidden) load().catch(() => { }); }, 30000);
  scope.interval(() => { if (!document.hidden) loadHealth(); }, 60000);
  const onRange = () => load();
  rangeState.listeners.add(onRange);
  scope.on(() => rangeState.listeners.delete(onRange));
  scope.listen(bus, 'event', () => get('/events?limit=12&type=waf,honeypot,ban,alert,ratelimit,agent').then(evs => mount(eventsBox, eventList(evs, { compact: true }))).catch(() => { }));
}

function noTraffic() {
  return empty('Noch kein Traffic', 'Sobald Caddy mit Sentinel Requests verarbeitet, erscheinen hier die Sites.');
}
