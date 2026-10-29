import { el, mount, get, put, panel, fmtInt, fmtMs, empty, select, toast, errToast } from '../ui.js';
import { withInstance } from '../instancebar.js';
import { spark } from '../charts.js';

export async function render(root, _p, scope) {
  ({ root } = withInstance(root));
  let sites, pols, ups = null;
  try {
    [sites, pols] = await Promise.all([get('/caddy/sites', scope.signal), get('/policies', scope.signal)]);
  } catch (e) {
    mount(root, el('div.callout.bad', null, e.message));
    return;
  }
  try { ups = await get('/caddy/upstreams', scope.signal); } catch { }
  const policies = pols.policies;

  const assign = async (host, policyId) => {
    try {
      for (const p of policies) {
        const had = (p.hosts || []).includes(host);
        const want = p.id === policyId;
        if (had === want) continue;
        p.hosts = want ? [...(p.hosts || []), host] : p.hosts.filter(h => h !== host);
        await put('/policies/' + p.id, p);
      }
      toast(`${host} nutzt jetzt „${policies.find(p => p.id === policyId)?.name || 'Standard'}“`, 'ok');
      render(root, _p, scope);
    } catch (e) { errToast(e); }
  };

  const missing = sites.filter(s => !s.sentinel).length;
  mount(root,
    missing ? el('div.callout.warn', null, `${missing} von ${sites.length} Sites laufen ohne die Direktive `, el('code', null, 'sentinel'),
      ' – dort gibt es keine Policies, Bans oder Metriken. ', el('a', { href: '#/editor' }, 'Im Editor ergänzen'), '.') : null,
    panel(`Sites (${sites.length})`, sites.length ? el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Hosts'), el('th', null, 'Listener'), el('th', null, 'Handler'), el('th', null, 'Sentinel / Policy'),
        el('th', null, 'Requests 24 h'), el('th.num', null, '5xx'), el('th.num', null, 'Blockiert'), el('th.num', null, 'Ø Zeit'))),
      el('tbody', null, sites.map(s => {
        const host = s.hosts[0];
        const hostKey = host === '*' ? '' : host;
        return el('tr', null,
          el('td', null, s.hosts.map(h => el('div', null, el('a', { href: '#/analytics?host=' + encodeURIComponent(h === '*' ? '' : h) }, h === '*' ? 'alle Hosts' : h)))),
          el('td.mono.muted', null, (s.listen || []).join(' ')),
          el('td', null, el('div', null, s.handlers.filter(h => h !== 'sentinel').map(h => el('span.badge', { style: { marginRight: '4px' } }, h))),
            s.upstreams?.length ? el('small.mono', null, '→ ' + s.upstreams.join(', ')) : null,
            s.roots?.length ? el('small.mono', null, s.roots.join(', ')) : null),
          el('td', null, s.sentinel
            ? (s.policy_source === 'directive'
              ? el('span', null, el('span.badge.ok', null, 'aktiv'), ' ', el('a', { href: '#/policies/' + s.policy }, s.policy_name || s.policy), el('small', null, ' (fest in der Direktive)'))
              : el('div.row', { style: { gap: '6px' } }, el('span.badge.ok', null, 'aktiv'),
                hostKey ? select(policies.map(p => [p.id, p.name + (p.id === pols.default ? ' (Standard)' : '')]), s.policy, (v) => assign(hostKey, v), { 'aria-label': 'Policy für ' + host })
                  : el('a', { href: '#/policies/' + s.policy }, s.policy_name)))
            : el('span.badge.warn', null, 'fehlt')),
          el('td', null, spark(s.spark || [], { width: 140 }), el('small', null, fmtInt(s.requests))),
          el('td.num', { style: { color: s.errors ? 'var(--bad)' : null } }, fmtInt(s.errors)),
          el('td.num', null, fmtInt(s.blocked)),
          el('td.num.muted', null, fmtMs(s.avg_ms)));
      })))) : empty('Keine Sites', 'Die laufende Caddy-Konfiguration enthält keine HTTP-Server.'), el('a', { href: '#/editor' }, 'Caddyfile bearbeiten')),
    panel('Upstreams', ups && ups.length ? el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Adresse'), el('th.num', null, 'Aktive Requests'), el('th.num', null, 'Fehler'), el('th', null, 'Zustand'))),
      el('tbody', null, ups.map(u => el('tr', null, el('td.mono', null, u.address), el('td.num', null, u.num_requests), el('td.num', null, u.fails),
        el('td', null, u.fails > 0 ? el('span.badge.warn', null, 'Fehler gemeldet') : el('span.badge.ok', null, 'ok')))))) : empty('Keine Upstreams', 'Reverse-Proxy-Ziele erscheinen hier mit ihrem Health-Status.')),
  );
}
