import { el, mount, get, put, panel, fmtInt, fmtMs, empty, select, toast, errToast, modal, field, untilInput, fmtUnix, can, linesInput } from '../ui.js';
import { setActions } from '../app.js';
import { openSiteWizard } from '../sitewizard.js';
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
  setActions(can('config') ? el('button.btn.primary', { onclick: () => openSiteWizard({ onDone: () => render(root, _p, scope) }) }, 'Neue Site …') : null);
  const now = Date.now() / 1000;
  const maintOn = (p) => p && p.maintenance && (!p.maintenance_from || p.maintenance_from <= now) && (!p.maintenance_until || p.maintenance_until > now);
  const maintenance = (pid) => {
    const p = policies.find(x => x.id === pid);
    if (!p) return;
    if (maintOn(p)) {
      put('/policies/' + p.id, { ...p, maintenance: false, maintenance_from: 0, maintenance_until: 0 }).then(() => { toast(`Wartung für „${p.name}“ beendet`, 'ok'); render(root, _p, scope); }).catch(errToast);
      return;
    }
    const st = { msg: p.maintenance_message || '', until: Math.floor(now) + 3600, allow: [...(p.maintenance_allow || [])] };
    const myIP = window.__status?.client_ip;
    modal(`Wartung: „${p.name}“`, el('div.stack', null,
      el('p.muted', { style: { margin: 0 } }, 'Alle Sites dieser Policy (' + ((p.hosts || []).join(', ') || 'Standard') + ') zeigen eine Wartungsseite. Nach dem Ende schaltet Sentinel sie selbst wieder frei.'),
      field('Meldung', el('input', { value: st.msg, placeholder: 'Wartungsarbeiten – bitte später erneut versuchen.', oninput: (e) => { st.msg = e.target.value; } })),
      el('label.field', null, el('span', null, 'Endet'), untilInput(st.until, (v) => { st.until = v; })),
      field('Trotzdem erreichbar für', linesInput(st.allow, (v) => { st.allow = v; }, { rows: 2, placeholder: myIP || '192.168.10.0/24' }), myIP ? 'Deine IP: ' + myIP : '')), {
      actions: [{ label: 'Abbrechen' }, {
        label: 'Wartung starten', kind: 'danger', onClick: async () => {
          await put('/policies/' + p.id, { ...p, maintenance: true, maintenance_message: st.msg, maintenance_from: 0, maintenance_until: st.until, maintenance_allow: st.allow });
          toast('Wartungsmodus aktiv' + (st.until ? ' bis ' + fmtUnix(st.until) : ''), 'ok');
          render(root, _p, scope);
        },
      }],
    });
  };

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
            : el('span.badge.warn', null, 'fehlt'),
            s.sentinel && can('policy') ? el('div', { style: { marginTop: '4px' } }, maintOn(policies.find(x => x.id === s.policy))
              ? el('button.btn.sm.danger', { onclick: () => maintenance(s.policy), title: 'Wartung beenden' }, '⚒ Wartung aktiv – beenden')
              : el('button.btn.sm.ghost', { onclick: () => maintenance(s.policy) }, '⚒ Wartung …')) : null),
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
