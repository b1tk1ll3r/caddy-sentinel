import { countryLabel, el, mount, get, del, panel, empty, fmtInt, fmtAgo, fmtDateTime, fmtUntil, toast, errToast, confirmDialog, copy, ACTIONS, actionLabel, modal, can, instChip, fmtUnix } from '../ui.js';
import { tempDialog, tempTable } from '../temp.js';
import { requestTable, eventList, topTable, kpi } from '../widgets.js';
import { setActions, setTitle } from '../app.js';
import { banDialog } from './security.js';

const SIGNAL_LABEL = {
  waf_block: 'WAF-Blocks', waf_detect: 'WAF-Treffer', honeypot: 'Honeypot', not_found: '404-Scans', auth_fail: 'Auth-Fehler', bad_request: 'Fehlerhafte Requests',
  scanner_ua: 'Scanner-Tool', rate_limit: 'Ratelimit', user_agent: 'Gesperrter UA', method: 'Unerlaubte Methode', ip_deny: 'IP-Sperrliste', burst: 'Request-Burst', body_limit: 'Body zu groß', geo_block: 'Geo-Sperre', feed_block: 'Threat-Feed', challenge: 'Bot-Challenge',
};

export async function render(root, [ip], scope) {
  const [d, x] = await Promise.all([get('/ip/' + encodeURIComponent(ip), scope.signal), get('/ip/' + encodeURIComponent(ip) + '/extra', scope.signal).catch(() => ({}))]);
  const pols = await get('/policies', scope.signal).then(r => r.policies).catch(() => []);
  setTitle('IP ' + ip);
  const s = d.summary;
  const reload = () => render(root, [ip], scope);
  setActions(
    el('button.btn', { onclick: () => copy(ip) }, 'IP kopieren'),
    el('a.btn', { href: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`, target: '_blank', rel: 'noopener noreferrer' }, 'AbuseIPDB'),
    el('a.btn', { href: `https://ipinfo.io/${encodeURIComponent(ip)}`, target: '_blank', rel: 'noopener noreferrer' }, 'ipinfo'),
    can('bans') ? el('button.btn', { onclick: () => tempDialog({ value: ip, scope: 'global', list: 'trusted', policies: pols, onDone: reload }, modal), title: 'Befristet freigeben oder sperren' }, 'Befristet …') : null,
    el('a.btn', { href: '#/flow?ip=' + encodeURIComponent(ip) }, 'Simulieren'),
    d.ban ? el('button.btn.primary', {
      onclick: async () => {
        if (!await confirmDialog('Sperre aufheben', `${d.ban.ip} wird wieder zugelassen.`, 'Aufheben', 'primary')) return;
        try { await del('/bans/' + encodeURIComponent(d.ban.ip)); toast('Entsperrt', 'ok'); reload(); } catch (e) { errToast(e); }
      },
    }, 'Sperre aufheben') : el('button.btn.danger', { onclick: () => banDialog(reload, ip) }, 'Sperren'));

  const score = d.score;
  const g = d.geo || {};
  mount(root,
    (g.Country || g.ASN || (d.feeds || []).length || d.challenged_until) ? el('div.row', { style: { gap: '8px' } },
      g.Country ? el('span.badge.primary', null, countryLabel(g.Country)) : null,
      g.ASN ? el('a.badge', { href: '#/analytics?asn=' + g.ASN }, `AS${g.ASN} ${g.ASOrg || ''}`) : null,
      (d.feeds || []).map(f => el('a.badge.bad', { href: '#/feeds' }, 'in Liste: ' + f)),
      d.challenged_until ? el('span.badge.warn', null, 'muss Bot-Challenge lösen (' + fmtUntil(d.challenged_until) + ')') : null) : null,
    d.ban ? el('div.callout.bad', null, el('b', null, 'Gesperrt '), fmtUntil(d.ban.until), ' – ', d.ban.reason, d.ban.ip !== ip ? ` (über Netz ${d.ban.ip})` : '', d.ban.note ? el('div', null, '📝 ', d.ban.note, d.ban.author ? ' (' + d.ban.author + ')' : '') : null) : null,
    (x.rdns || []).length || (x.lists || []).length || (x.instances || []).length > 1 ? el('div.callout', null,
      (x.rdns || []).length ? el('div', null, el('b', null, 'Reverse-DNS: '), el('span.mono', null, x.rdns.join(', '))) : null,
      (x.lists || []).length ? el('div', null, el('b', null, 'Steht in: '), x.lists.join(' · ')) : null,
      (x.instances || []).length > 1 ? el('div', null, el('b', null, 'Gesehen auf: '), x.instances.map(i => el('span', { style: { marginRight: '10px' } }, instChip(i.inst, { always: true }), ' ', fmtInt(i.count), ' Anfragen'))) : null) : null,
    (x.temp || []).length ? panel('Befristete Einträge', tempTable(x.temp, { onChange: reload, policies: Object.fromEntries(pols.map(p => [p.id, p.name])) })) : null,
    d.private ? el('div.callout', null, 'Private oder lokale Adresse. Steht Caddy hinter einem Proxy, prüfe ', el('code', null, 'trusted_proxies'), ' – sonst sehen alle Clients wie der Proxy aus.') : null,
    el('div.kpis', null,
      kpi('Bedrohungs-Score', score ? Math.round(score.score) : '0', { kind: score?.score > 50 ? 'bad' : score?.score > 10 ? 'warn' : 'ok' }),
      kpi('Requests (gespeichert)', fmtInt(s.requests)),
      kpi('Fehler', fmtInt(s.errors)),
      kpi('Blockiert', fmtInt(s.blocked), { kind: s.blocked ? 'bad' : '' }),
      kpi('Erstmals gesehen', s.first_seen ? fmtAgo(s.first_seen) : '–', { title: s.first_seen ? fmtDateTime(s.first_seen) : '' }),
      kpi('Zuletzt gesehen', s.last_seen ? fmtAgo(s.last_seen) : '–'),
      kpi('Sperren bisher', fmtInt(d.offender_bans))),
    el('div.grid.g3', null,
      panel('Signale', score && Object.keys(score.signals).length ? el('table', null, el('tbody', null,
        Object.entries(score.signals).sort((a, b) => b[1] - a[1]).map(([k, v]) => el('tr', null, el('td', null, SIGNAL_LABEL[k] || k), el('td.num', null, Math.round(v) + ' Pkt.'), el('td.num.muted', null, (score.counts[k] || 0) + '×')))))
        : empty('Keine aktuellen Signale')),
      panel('Aufgerufene Hosts', topTable(s.hosts, { label: 'Host', showErrors: false })),
      panel('Sentinel-Aktionen', Object.keys(s.actions).length ? el('table', null, el('tbody', null, Object.entries(s.actions).map(([a, n]) => el('tr', null, el('td', null, actionLabel(a)), el('td.num', null, fmtInt(n)))))) : empty('Keine Eingriffe'))),
    el('div.grid.g2', null,
      panel('Pfade', topTable(s.paths, { label: 'Pfad' })),
      panel('User-Agents', topTable(s.uas, { label: 'User-Agent', showBlocked: false }))),
    (x.logins || []).length ? panel('Site-Anmeldungen von dieser IP', el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Zeit'), el('th', null, 'Konto'), el('th', null, 'Ergebnis'), el('th', null, 'Site'), el('th', null, 'Details'))),
      el('tbody', null, x.logins.map(l => el('tr', null, el('td.nowrap', { title: fmtDateTime(l.ts) }, fmtAgo(l.ts)), el('td', null, l.user || '–'), el('td', null, l.result), el('td.mono', null, l.host), el('td', null, l.detail))))))) : null,
    panel('Ereignisse', eventList(d.events)),
    panel('Letzte Requests', requestTable(d.requests)));
}
