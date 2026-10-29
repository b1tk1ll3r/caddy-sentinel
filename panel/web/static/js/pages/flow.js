import { el, mount, get, post, panel, select, toggle, debounce, errToast, empty } from '../ui.js';
import { withInstance } from '../instancebar.js';
import { seg } from '../widgets.js';
import { setActions } from '../app.js';

// Request flow: client → entry (listener/TLS) → Sentinel (policy stages,
// path rules) → Caddy routes → endpoints. Plus a simulator that highlights
// the path a concrete request takes.

const STAGE_ICON = { bans: '⛨', rules: '⑂', maintenance: '⚒', ip: '⌂', geo: '◍', filters: '⚑', rate: '⏱', challenge: '⧗', auth: '🔑', waf: '⛊', headers: '≡', policy: '⏻' };
const RESULT_ICON = { pass: '✓', skip: '–', block: '✕', challenge: '⧗', login: '🔑', redirect: '↪', info: 'i', warn: '!' };
const MATRIX = [
  ['tls', 'TLS'], ['rules', 'Regeln'], ['maintenance', 'Wartung'], ['ip', 'IP'], ['geo', 'Geo/Feeds'], ['filters', 'Filter'],
  ['rate', 'Limits'], ['challenge', 'Challenge'], ['auth', 'Anmeldung'], ['waf', 'WAF'],
];
const EP_ICON = { proxy: '⇄', php: '⟨⟩', files: '🗀', respond: '↩', redirect: '↪', acme: '🔏', error: '⚠', other: '◇' };

export async function render(root, _p, scope, q) {
  ({ root } = withInstance(root));
  let data;
  let siteId = q.get('site') || '';
  const wantPolicy = q.get('policy') || '';
  let vertical = (() => { try { return localStorage.getItem('sentinel.flow.vertical') === '1' || window.innerWidth < 900; } catch { return window.innerWidth < 900; } })();
  let trace = null;
  const sim = { method: 'GET', path: '/', ip: '203.0.113.10', client: 'browser', user: '', groups: '', factors: 2, api_key: '', challenge_solved: false, check_waf: false, host: '' };
  // prefilled from a logged request ("Im Simulator nachstellen")
  let autoRun = false;
  for (const k of ['method', 'path', 'ip', 'host', 'client', 'user']) if (q.get(k)) { sim[k] = q.get(k); autoRun = true; }
  if (q.get('waf') === '1') sim.check_waf = true;
  if (q.get('solved') === '1') sim.challenge_solved = true;

  setActions(el('button.btn', { onclick: () => load(true) }, 'Aktualisieren'));

  async function load(keepTrace) {
    data = await get('/flow', scope.signal);
    if (!keepTrace) trace = null;
    if (!data.sites.find(s => s.id === siteId)) {
      const byPol = wantPolicy && data.sites.find(s => s.policy === wantPolicy);
      siteId = (byPol || data.sites.find(s => s.sentinel !== 'none') || data.sites[0] || {}).id || '';
    }
    draw();
  }

  const graphHost = el('div');
  const simHost = el('div');
  const resultHost = el('div');

  function draw() {
    if (!data.sites.length) {
      mount(root, data.error ? el('div.callout.bad', null, data.error) : null,
        empty('Keine Sites', 'In der laufenden Caddy-Konfiguration gibt es keine HTTP-Sites.'));
      return;
    }
    const site = data.sites.find(s => s.id === siteId);
    mount(root,
      el('p.muted', null, 'Was greift für welche Site? Von links nach rechts: Client → Eingang (Port, TLS) → Sentinel mit Policy und Pfad-Regeln → Caddy-Routen → Ziel. Mit dem Simulator unten siehst du, welchen Weg ein bestimmter Request nimmt.'),
      panel('Alle Sites', matrix()),
      panel(null, el('div.stack', null,
        el('div.row', null,
          el('b', null, 'Site'),
          select(data.sites.map(s => [s.id, s.label + (s.policy_name ? ` · ${s.policy_name}` : '')]), siteId, (v) => { siteId = v; trace = null; sim.host = ''; history.replaceState(null, '', '#/flow?site=' + encodeURIComponent(v)); draw(); }, { 'aria-label': 'Site' }),
          el('span.grow'),
          seg([['h', '↔ waagerecht'], ['v', '↕ senkrecht']], vertical ? 'v' : 'h', (v) => { vertical = v === 'v'; try { localStorage.setItem('sentinel.flow.vertical', vertical ? '1' : '0'); } catch { } drawGraph(site); })),
        site.sentinel === 'none' ? el('div.callout.warn', null, 'Auf dieser Site ist Sentinel nicht aktiv – keine Policy, keine WAF, kein IDS. Im Editor „Sentinel einfügen“ nutzen.') : null,
        site.sentinel === 'partial' ? el('div.callout.warn', null, 'Sentinel schützt nur einen Teil der Routen dieser Site (gestrichelte Linien laufen an Sentinel vorbei).') : null,
        graphHost)),
      el('div.grid.g-main', null, panel('Simulator', simHost), panel('Ergebnis', resultHost)));
    drawGraph(site);
    drawSim(site);
    if (autoRun && site) {
      autoRun = false;
      simulate(site).then(() => simHost.scrollIntoView({ behavior: 'smooth', block: 'start' }));
    }
    drawResult();
  }

  // ------------------------------------------------------------ matrix
  function matrix() {
    const cell = (s, key) => {
      if (key === 'tls') {
        const k = s.tls === 'off' ? 'warn' : s.tls === 'internal' ? 'info' : 'on';
        return el('span.fm.' + k, { title: s.tls_detail }, { off: 'aus', internal: 'intern', auto: 'auto', custom: 'eigen' }[s.tls] || s.tls);
      }
      if (s.sentinel === 'none') return el('span.fm', null, '–');
      const st = s.stages.find(x => x.key === key);
      if (!st) return el('span.fm', null, '–');
      const cls = !st.active ? '' : key === 'maintenance' ? 'bad' : key === 'auth' ? 'info' : 'on';
      let txt = st.active ? '●' : '–';
      if (key === 'rules' && st.items?.length) txt = String(st.items.length);
      if (key === 'waf') txt = st.active ? (st.summary.startsWith('blockiert') ? 'block' : 'erkennt') : 'aus';
      if (key === 'auth' && st.active) txt = st.summary.includes('2FA') ? 'AD+2FA' : 'AD';
      return el('span.fm' + (cls ? '.' + cls : ''), { title: st.summary + (st.items?.length ? '\n' + st.items.join('\n') : '') }, txt);
    };
    return el('div.table-wrap', null, el('table.flow-matrix', null,
      el('thead', null, el('tr', null, el('th', null, 'Site'), el('th', null, 'Sentinel / Policy'), ...MATRIX.map(([, l]) => el('th', null, l)), el('th', null, 'Ziele'))),
      el('tbody', null, data.sites.map(s => el('tr.clickable' + (s.id === siteId ? '.sel' : ''), { onclick: () => { siteId = s.id; trace = null; sim.host = ''; history.replaceState(null, '', '#/flow?site=' + encodeURIComponent(s.id)); draw(); } },
        el('td', null, el('b', null, s.label), el('div', null, el('small.muted', null, s.listen.join(', ')))),
        el('td', null, s.sentinel === 'none' ? el('span.fm.bad', null, 'ohne') : el('span', null, el('span.fm.' + (s.sentinel === 'all' ? 'on' : 'warn'), null, s.sentinel === 'all' ? 'aktiv' : 'teilweise'), ' ', el('small', null, s.policy_name || s.policy || ''))),
        ...MATRIX.map(([k]) => el('td', null, cell(s, k))),
        el('td', { style: { textAlign: 'left' } }, el('small', null, [...new Set(s.branches.map(b => b.endpoint?.label))].filter(Boolean).join(', ') || '–')))))));
  }

  // ------------------------------------------------------------ graph
  function drawGraph(site) {
    const t = trace && trace.site === site.id ? trace : null;
    const stepBy = {};
    for (const s of t?.steps || []) stepBy[s.key] = s;
    const stopped = t && ['block', 'login', 'challenge', 'redirect'].includes(t.outcome?.kind);
    const nodes = {};
    const node = (id, cls, ...children) => (nodes[id] = el('div.fnode' + cls, { 'data-node': id }, ...children));

    const client = node('client', t ? '.hot' : '', el('div.t', null, '👤 Client'),
      el('div.d', null, t ? `${sim.method} ${sim.path}` : 'Browser, App, Skript …'),
      t ? el('div.d', null, sim.ip + (t.country ? ' · ' + t.country : '')) : null);
    const entry = node('entry', t ? '.hot' : '', el('div.t', null, site.tls === 'off' ? '🔓' : '🔒', ' Eingang'),
      el('div.d', null, site.listen.join(', ')),
      el('div.d', null, site.tls_detail, site.cert_days_left != null ? ` · Zertifikat noch ${site.cert_days_left} Tage` : ''),
      site.hosts.length ? el('div.chips', null, site.hosts.slice(0, 6).map(h => el('span.chip', null, h))) : null);

    let sentinel = null;
    if (site.sentinel !== 'none') {
      const stages = site.stages.map(st => {
        const r = stepBy[st.key];
        const cls = '.fstage' + (st.active ? '.on' : '.off') + (r ? '.r-' + r.result : '');
        const icon = r ? RESULT_ICON[r.result] || '·' : STAGE_ICON[st.key] || '·';
        let extra = null;
        if (st.key === 'rules' && site.rules.length) {
          extra = el('ul.frules', null, site.rules.map(rule => el('li' + (t?.rule === rule.id ? '.hit' : ''), { title: (rule.paths || []).join(', ') }, (rule.enabled ? '' : '(aus) ') + rule.name)));
        }
        return el('li' + cls, null, el('span.ic', null, icon),
          el('span', null, st.label, el('span.s', null, st.summary), r?.detail ? el('span.why', null, r.detail) : null, extra));
      });
      const hot = t && (stepBy.bans || stepBy.sentinel);
      sentinel = node('sentinel', '.fsent' + (hot ? (t.outcome?.kind === 'block' || t.outcome?.kind === 'login' || t.outcome?.kind === 'challenge' ? '.stop' : '.hot') : ''),
        el('div.t', null, '⛨ Sentinel', el('a', { href: '#/policies/' + site.policy, style: { marginLeft: 'auto', fontWeight: 500, fontSize: '12px' } }, site.policy_name || site.policy)),
        el('ul.fstages', null, stages));
    }

    const branchNodes = site.branches.map(b => node(b.id, (t ? (t.branch === b.id && !stopped ? '.hot' : '.dim') : ''),
      el('div.t', null, '⑂ ', b.match.length ? b.match.join(' · ') : 'alle übrigen Requests'),
      b.middleware.length ? el('div.chips', null, b.middleware.map(m => el('span.chip', { title: (m.detail || '') + (m.cond ? ' – nur wenn ' + m.cond : '') }, m.label + (m.detail && m.kind === 'root' ? ' ' + m.detail : '')))) : null,
      !b.sentinel ? el('div.d', { style: { color: 'var(--warn)' } }, 'ohne Sentinel') : b.policy ? el('div.d', null, 'Policy fest: ' + b.policy) : null));

    const epNodes = site.branches.filter(b => b.endpoint).map(b => {
      const ep = b.endpoint;
      return node(ep.id, (t ? (t.endpoint === ep.id && !stopped ? '.hot' : '.dim') : ''),
        el('div.t', null, EP_ICON[ep.kind] || '◇', ' ', ep.label),
        ep.detail ? el('div.d.mono', null, ep.detail) : null,
        ep.upstreams?.length ? el('div.ups', null, ep.upstreams.map(u => el('span', { title: u.known ? `${u.requests} aktive Requests, ${u.fails} Fehler` : 'kein Status bekannt' }, el('i.updot' + (!u.known ? '' : u.fails > 0 ? '.bad' : '.ok')), u.addr))) : null);
    });

    // outcome node for blocked/redirected simulations
    let outcomeNode = null;
    if (stopped) {
      outcomeNode = node('outcome', '.stop', el('div.t', null, RESULT_ICON[t.outcome.kind === 'redirect' ? 'redirect' : t.outcome.kind] || '✕', ' ', String(t.outcome.status)), el('div.d', null, t.outcome.text));
    }

    const col = (title, ...items) => el('div.flow-col', null, el('h4', null, title), ...items);
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.classList.add('flow-svg');
    const flow = el('div.flow' + (vertical ? '.vertical' : ''), null,
      svg,
      col('Client', client),
      col('Eingang', entry),
      sentinel ? col('Sentinel', sentinel) : null,
      col('Caddy-Routen', ...(branchNodes.length ? branchNodes : [el('div.fnode.dim', null, 'keine Route')])),
      col(stopped ? 'Ergebnis' : 'Ziele', ...(stopped ? [outcomeNode] : epNodes.length ? epNodes : [el('div.fnode.dim', null, 'kein Ziel')])));
    const wrap = el('div.flow-wrap', null, flow);
    mount(graphHost, wrap);

    // edges
    const edges = [];
    edges.push(['client', 'entry', t ? 'hot' : '']);
    if (sentinel) {
      edges.push(['entry', 'sentinel', t && stepBy.bans ? 'hot' : '']);
    }
    for (const b of site.branches) {
      const from = b.sentinel && sentinel ? 'sentinel' : 'entry';
      const isHot = t && t.branch === b.id && !stopped;
      edges.push([from, b.id, (isHot ? 'hot' : t ? 'dim' : '') + (b.sentinel ? '' : ' bypass')]);
      if (b.endpoint && !stopped) edges.push([b.id, b.endpoint.id, isHot ? 'hot' : t ? 'dim' : '']);
    }
    if (stopped) {
      const lastStage = sentinel ? 'sentinel' : 'entry';
      edges.push([t.outcome.kind === 'redirect' && !sentinel ? 'entry' : lastStage, 'outcome', 'hot']);
    }
    const drawEdges = () => {
      const box = flow.getBoundingClientRect();
      svg.setAttribute('width', flow.scrollWidth);
      svg.setAttribute('height', flow.scrollHeight);
      svg.replaceChildren();
      for (const [a, b, cls] of edges) {
        const A = nodes[a], B = nodes[b];
        if (!A || !B) continue;
        const ra = A.getBoundingClientRect(), rb = B.getBoundingClientRect();
        let x1, y1, x2, y2, d;
        if (vertical) {
          x1 = ra.left + ra.width / 2 - box.left; y1 = ra.bottom - box.top;
          x2 = rb.left + rb.width / 2 - box.left; y2 = rb.top - box.top;
          const my = (y1 + y2) / 2;
          d = `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
        } else {
          x1 = ra.right - box.left; y1 = ra.top + Math.min(ra.height / 2, 28) - box.top;
          x2 = rb.left - box.left; y2 = rb.top + Math.min(rb.height / 2, 28) - box.top;
          const mx = (x1 + x2) / 2;
          d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
        }
        const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        p.setAttribute('d', d);
        if (cls.trim()) p.setAttribute('class', cls.trim());
        svg.append(p);
        // arrow head
        const ah = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        ah.setAttribute('d', vertical ? `M${x2 - 4},${y2 - 6} L${x2},${y2} L${x2 + 4},${y2 - 6}` : `M${x2 - 6},${y2 - 4} L${x2},${y2} L${x2 - 6},${y2 + 4}`);
        if (cls.trim()) ah.setAttribute('class', cls.trim());
        svg.append(ah);
      }
    };
    requestAnimationFrame(drawEdges);
    const ro = new ResizeObserver(() => drawEdges());
    ro.observe(flow);
    scope.on(() => ro.disconnect());
  }

  // ------------------------------------------------------------ simulator
  function drawSim(site) {
    if (!sim.host) sim.host = (site.hosts[0] || '').replace('*', 'www');
    const run = debounce(() => simulate(site), 250);
    const inp = (k, attrs = {}) => el('input', { value: sim[k] ?? '', ...attrs, oninput: (e) => { sim[k] = e.target.value; run(); } });
    mount(simHost, el('div.stack', null,
      el('div.fields', null,
        el('label.field', null, el('span', null, 'Methode'), select(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], sim.method, (v) => { sim.method = v; run(); })),
        el('label.field.wide', null, el('span', null, 'Pfad'), inp('path', { class: 'mono', placeholder: '/admin/?x=1' })),
        site.hosts.length > 1 ? el('label.field', null, el('span', null, 'Host'), select(site.hosts.map(h => h.replace('*', 'www')), sim.host, (v) => { sim.host = v; run(); })) : null,
        el('label.field', null, el('span', null, 'Client-IP'), inp('ip', { class: 'mono', list: 'flow-ips' }),
          el('datalist#flow-ips', null, [['203.0.113.10', 'Internet'], ['192.168.1.20', 'LAN'], ['10.0.0.5', 'VPN'], ['127.0.0.1', 'lokal']].map(([v, l]) => el('option', { value: v }, l)))),
        el('div.field', null, el('span', null, 'Client'), seg([['browser', 'Browser'], ['api', 'Skript / API']], sim.client, (v) => { sim.client = v; run(); })),
        el('label.field', null, el('span', null, 'Angemeldet als'), inp('user', { placeholder: 'niemand' })),
        el('label.field', null, el('span', null, 'Gruppen'), inp('groups', { placeholder: 'Wiki-Users, IT-Admins' })),
        el('div.field', null, el('span', null, 'Mit 2FA'), toggle(sim.factors >= 2, (v) => { sim.factors = v ? 2 : 1; run(); }, 'Code eingegeben')),
        el('label.field', null, el('span', null, 'API-Schlüssel'), inp('api_key', { placeholder: 'optional', class: 'mono' })),
        el('div.field', null, el('span', null, 'Bot-Challenge'), toggle(sim.challenge_solved, (v) => { sim.challenge_solved = v; run(); }, 'bereits gelöst')),
        el('div.field', null, el('span', null, 'WAF'), toggle(sim.check_waf, (v) => { sim.check_waf = v; run(); }, 'Request wirklich prüfen'))),
      el('div.row', null, el('button.btn.primary', { onclick: () => simulate(site) }, 'Simulieren'),
        el('small.muted', null, 'Die Simulation nutzt dieselbe Reihenfolge wie Sentinel. Ratelimits werden nur angezeigt, nicht gezählt.'))));
  }

  async function simulate(site) {
    try {
      trace = await post('/flow/trace', {
        site: site.id, host: sim.host, method: sim.method, path: sim.path, ip: sim.ip,
        ua: sim.client === 'api' ? 'curl/8.5.0' : '', accept: sim.client === 'api' ? 'application/json' : '',
        user: sim.user.trim(), groups: sim.groups.split(',').map(s => s.trim()).filter(Boolean), factors: sim.factors,
        api_key: sim.api_key.trim(), challenge_solved: sim.challenge_solved, check_waf: sim.check_waf,
      });
      drawGraph(site);
      drawResult();
    } catch (e) { errToast(e); }
  }

  function drawResult() {
    if (!trace) return mount(resultHost, el('p.muted', null, 'Noch keine Simulation – Pfad und Client einstellen, dann „Simulieren“.'));
    const o = trace.outcome || {};
    mount(resultHost, el('div.stack', null,
      el('div.outcome.' + (o.kind || ''), null, el('span.code', null, o.status || '–'), el('div', null, el('b', null, o.text), trace.rule_name ? el('div', null, el('small.muted', null, 'Pfad-Regel: ' + trace.rule_name)) : null)),
      trace.uncertain ? el('div.callout.warn', null, 'Ein Teil der Caddy-Matcher (z. B. „Datei existiert“ oder Ausdrücke) lässt sich nicht simulieren – die gewählte Route ist eine Annahme.') : null,
      el('ul.tsteps', null, trace.steps.map(s => el('li.' + s.result, null, el('span.ic', null, RESULT_ICON[s.result] || '·'), el('b', null, s.label), el('span', null, s.detail || ({ pass: 'ok', skip: 'übersprungen' })[s.result] || ''))))));
  }

  await load();
}
