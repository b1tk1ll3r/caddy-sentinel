// Failure analysis: why do requests fail? Groups failed requests by cause,
// shows who answered (Sentinel, Caddy, backend, client) and leads to a
// diagnosis with fixes. Also finds a request by the reference shown on
// Sentinel's error page.
import { el, mount, get, qs, fmtInt, fmtAgo, fmtDateTime, rangeState, panel, select, empty, ACTIONS, statusBadge, errToast, instChip, instState, actionLabel } from '../ui.js';
import { viewsBar } from '../views.js';
import { requestTable, requestDrawer, drawer, kpi, seg, eventDrawer } from '../widgets.js';
import { timeChart, legend } from '../charts.js';
import { diagnosisBox } from '../diagnosis.js';
import { openWafAssistant } from '../waffp.js';

const hostLabel = (g) => g.host + (g.port && g.port !== 80 && g.port !== 443 ? ':' + g.port : '');

const WHO = [['', 'Alle'], ['sentinel', 'Sentinel'], ['caddy', 'Caddy'], ['backend', 'Backend'], ['client', 'Client']];
const WHO_HELP = {
  sentinel: 'Sentinel hat entschieden – Policy, Pfad-Regel, IP-/Geo-Sperre, WAF …',
  caddy: 'Caddy selbst – keine Route, Datei fehlt, Backend nicht erreichbar',
  backend: 'Das Backend hat mit einem Fehler geantwortet',
  client: 'Liegt am Client – Anmeldung, API-Schlüssel, zu viele Anfragen',
};

export async function render(root, _p, scope, q) {
  let host = q.get('host') || '';
  let who = q.get('who') || '';
  let groups = [];
  const ov = await get('/stats/overview?range=30d', scope.signal);
  const hosts = (ov.current.hosts || []).map(h => h.host);

  const kpis = el('div.kpis');
  const series = [
    { label: 'Blockiert (Sentinel)', color: 'var(--c-blocked)', values: [] },
    { label: 'Client-Fehler 4xx', color: 'var(--c-4xx)', values: [] },
    { label: 'Server-Fehler 5xx', color: 'var(--c-5xx)', values: [] },
  ];
  const chart = timeChart({ series, t: [], kind: 'area', height: 180, label: 'Fehlgeschlagene Anfragen über die Zeit', onMarker: (m) => eventDrawer(m.ev) });
  const changesBox = el('div.change-list');
  const listBox = el('div');
  const whoSeg = el('div');
  const refInput = el('input', {
    type: 'search', placeholder: 'Referenz von der Fehlerseite, z. B. K7QM-3XPA', 'aria-label': 'Referenz suchen',
    onkeydown: (e) => { if (e.key === 'Enter') findRef(); },
  });
  const refResult = el('div');

  const sync = () => history.replaceState(null, '', '#/failures' + qs({ host, who }));

  mount(root,
    el('p.muted', null, 'Warum scheitern Anfragen? Fehlgeschlagene und blockierte Requests sind hier nach Ursache gruppiert – mit der Stelle, an der sie hängen bleiben, und einem Weg zur Lösung.'),
    panel('Anfrage per Referenz finden', el('div.stack', null,
      el('p.muted', { style: { margin: 0, fontSize: '13px' } }, 'Blockierte Besucher sehen auf der Fehlerseite eine Referenz. Hier eingeben, um genau diese Anfrage mit Begründung zu öffnen.'),
      el('div.ref-search', null, refInput, el('button.btn.primary', { onclick: findRef }, 'Suchen')),
      refResult)),
    el('div.row', null,
      select([['', 'Alle Hosts'], ...hosts.map(h => [h, h])], host, (v) => { host = v; sync(); load(); }, { 'aria-label': 'Host' }),
      whoSeg, el('span.grow'), viewsBar('failures', scope)),
    kpis,
    panel('Verlauf und Änderungen', el('div.stack', null, chart, legend(series, () => chart.update({})),
      el('small.muted', null, '◆ markiert Änderungen an Konfiguration, Policies und Regeln – so ist sichtbar, ob ein Anstieg mit einer Änderung zusammenfällt. Klick auf eine Markierung zeigt Details.'),
      changesBox)),
    panel('Ursachen', listBox));

  async function findRef() {
    const v = refInput.value.trim();
    if (!v) return;
    try {
      const rows = await get('/requests' + qs({ ref: v, limit: 5 }), scope.signal);
      if (!rows.length) {
        mount(refResult, el('div.callout.warn', null, `Keine Anfrage mit Referenz „${v}“ gefunden. Ältere Einträge werden nach der Aufbewahrungsfrist gelöscht; Referenzen gibt es erst ab dieser Version.`));
        return;
      }
      mount(refResult, requestTable(rows));
      requestDrawer(rows[0]);
    } catch (e) { errToast(e); }
  }

  const CHANGE_RE = /Policy|Regelsatz|WAF-Ausnahme|Feed|Einstellungen|Standard-Policy|Backup|Instanz|Konfiguration angewendet|wiederhergestellt/;
  async function loadTimeline() {
    const [ov, evs] = await Promise.all([
      get('/stats/overview' + qs({ range: rangeState.value, host }), scope.signal),
      get('/events' + qs({ type: 'audit,config', range: rangeState.value, limit: 300 }), scope.signal),
    ]);
    const sp = ov.current.series;
    series[0].values = sp.map(x => x.blocked);
    series[1].values = sp.map(x => Math.max(0, x.s4 - x.blocked));
    series[2].values = sp.map(x => x.s5);
    const changes = evs.filter(e => CHANGE_RE.test(e.title) && !/Caddyfile übernommen/.test(e.title));
    chart.update({ t: sp.map(x => x.t), markers: changes.map(e => ({ t: Math.floor(e.ts / 1000), label: fmtDateTime(e.ts) + ' – ' + e.title, ev: e, color: 'var(--ink-2)' })) });
    mount(changesBox, changes.length ? el('details', null, el('summary', null, `${changes.length} Änderung${changes.length === 1 ? '' : 'en'} im Zeitraum`),
      el('ul', null, changes.slice(0, 30).map(e => el('li', null, el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); eventDrawer(e); } }, fmtDateTime(e.ts)), ' ', instChip(e.inst), ' ', e.title)))) : el('small.muted', null, 'Keine Änderungen im Zeitraum.'));
  }

  async function load() {
    loadTimeline().catch(() => { });
    mount(listBox, el('div.diag-skel', null, 'Lade …'));
    const res = await get('/failures' + qs({ range: rangeState.value, host }), scope.signal);
    groups = res.groups || [];
    draw();
  }

  function draw() {
    const sum = (w) => groups.filter(g => !w || g.who === w).reduce((a, g) => a + g.count, 0);
    const total = sum();
    mount(kpis,
      kpi('Fehlgeschlagen', fmtInt(total), { kind: total ? 'bad' : '' }),
      ...WHO.slice(1).map(([k, l]) => kpi('durch ' + l, fmtInt(sum(k)), { title: WHO_HELP[k], sub: total ? ' ' + Math.round(sum(k) / total * 100) + ' %' : '' })));
    mount(whoSeg, seg(WHO, who, (v) => { who = v; sync(); draw(); }));
    const vis = groups.filter(g => !who || g.who === who);
    if (!vis.length) {
      mount(listBox, empty(total ? 'Keine Ursachen in dieser Kategorie' : 'Keine fehlgeschlagenen Anfragen', total ? 'Andere Kategorie wählen.' : 'Im gewählten Zeitraum ist nichts blockiert worden und kein Request mit Fehler geendet.'));
      return;
    }
    mount(listBox, el('div.stack', null,
      el('div.who-legend', null, WHO.slice(1).map(([k, l]) => el('span', null, el('span.who-chip.' + k, null, l), ' ', WHO_HELP[k]))),
      el('div.fail-list', { role: 'list' }, vis.map(g => el('div.fail-row', {
        role: 'listitem', tabindex: 0, onclick: () => openGroup(g), onkeydown: (e) => { if (e.key === 'Enter') openGroup(g); },
      },
        el('span.accent.' + g.who),
        el('div.fail-main', null,
          el('b', null, g.headline || (g.action ? actionLabel(g.action) : 'Status ' + g.status)),
          el('div.fail-meta', null,
            instState.value === 'all' ? instChip(g.inst) : null,
            el('span.who-chip.' + g.who, null, g.who_label),
            g.stage_label ? el('span', null, 'an: ', el('b', null, g.stage_label)) : null,
            el('span', null, hostLabel(g)),
            g.policy_name ? el('span', null, 'Policy ' + g.policy_name) : null,
            g.example ? el('span.mono', { title: g.example }, g.example + (g.paths > 1 ? ` (+${g.paths - 1} weitere Pfade)` : '')) : null),
          g.fix ? el('div.fail-meta', null, '→ ', g.fix.href ? el('a', { href: g.fix.href, onclick: (e) => e.stopPropagation() }, g.fix.label) : g.fix.label) : null),
        el('div.fail-count', null, el('b', null, fmtInt(g.count)),
          el('small', { title: fmtDateTime(g.last) }, `${fmtInt(g.ips)} Client${g.ips === 1 ? '' : 's'} · zuletzt ${fmtAgo(g.last)}`)))))));
  }

  async function openGroup(g) {
    const exBox = el('div', null, el('div.diag-skel', null, 'Lade Beispiele …'));
    drawer(g.headline || 'Ursache', [
      el('div.row', { style: { gap: '18px' } },
        el('span', null, el('b', null, fmtInt(g.count)), ' Anfragen'),
        el('span', null, el('b', null, fmtInt(g.ips)), ' Clients'),
        el('span', null, el('b', null, fmtInt(g.paths)), ' Pfade'),
        el('span.muted', null, `${fmtDateTime(g.first)} – ${fmtDateTime(g.last)}`)),
      g.action === 'waf_block' ? el('div.row', null, el('button.btn.primary', { onclick: () => openWafAssistant({ policy: g.policy, host: g.host, inst: g.inst }) }, 'Fehlalarm-Assistent'), el('span.muted', null, 'schlägt die engste Ausnahme vor')) : null,
      el('h3', { style: { margin: '4px 0 0', fontSize: '13px' } }, 'Diagnose (letzte Anfrage dieser Gruppe)'),
      diagnosisBox({ id: g.sample_id }),
      el('h3', { style: { margin: '4px 0 0', fontSize: '13px' } }, 'Beispiele'),
      exBox,
    ]);
    const f = { range: rangeState.value, host: g.host, port: g.port || '', policy: g.policy, limit: 50, errors: 1, inst: g.inst };
    if (g.action && !g.status) { f.action = g.action; f.detail = g.detail; if (g.rule) f.rule = g.rule; }
    else { f.status = String(g.status); f.action = g.action || 'none'; }
    try {
      const rows = await get('/requests' + qs(f), scope.signal);
      mount(exBox, requestTable(rows, { showHost: false }),
        el('a.btn.sm', { href: '#/analytics' + qs({ host: g.host, action: f.action === 'none' ? 'none' : f.action, status: f.status || '' }), style: { marginTop: '8px' } }, 'Alle in den Analysen öffnen'));
    } catch (e) { mount(exBox, el('div.callout.bad', null, e.message)); }
  }

  if (q.get('ref')) { refInput.value = q.get('ref'); findRef(); }
  const onRange = () => load();
  rangeState.listeners.add(onRange);
  scope.on(() => rangeState.listeners.delete(onRange));
  await load();
}
