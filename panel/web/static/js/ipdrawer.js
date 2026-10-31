// IP profile as a drawer: opens from every IP link (Ctrl/Cmd-click or the
// middle button still open the full page) with the key facts and the
// actions block, lift, tolerate.
import { el, mount, get, post, del, toast, errToast, confirmDialog, modal, countryLabel, fmtInt, fmtAgo, fmtDateTime, fmtUntil, fmtUnix, actionLabel, can, instChip, copy } from './ui.js';
import { drawer } from './widgets.js';
import { tempDialog, TEMP_LISTS } from './temp.js';

export function openIPDrawer(ip) {
  const body = el('div.stack', null, el('div.diag-skel', null, 'Lade Steckbrief …'));
  const d = drawer('IP ' + ip, body, el('a.btn.sm', { href: '#/ip/' + encodeURIComponent(ip), onclick: () => d.close() }, 'Ganze Seite'));
  const load = async () => {
    try {
      const [b, x] = await Promise.all([get('/ip/' + encodeURIComponent(ip)), get('/ip/' + encodeURIComponent(ip) + '/extra')]);
      draw(b, x);
    } catch (e) { mount(body, el('div.callout.bad', null, e.message)); }
  };
  function draw(b, x) {
    const s = b.summary || {};
    const g = b.geo || {};
    const score = b.score?.score ? Math.round(b.score.score) : 0;
    const acts = Object.entries(s.actions || {}).sort((a, c) => c[1] - a[1]).slice(0, 5);
    mount(body,
      el('div.row', { style: { gap: '6px', flexWrap: 'wrap' } },
        g.Country ? el('span.badge.primary', null, countryLabel(g.Country)) : null,
        g.ASN ? el('span.badge', null, `AS${g.ASN} ${g.ASOrg || ''}`) : null,
        (x.rdns || []).map(n => el('span.badge', { title: 'Reverse-DNS' }, n)),
        b.private ? el('span.badge', null, 'privat/lokal') : null,
        (b.feeds || []).map(f => el('span.badge.bad', null, 'Feed: ' + f))),
      b.ban ? el('div.callout.bad', null, el('b', null, 'Gesperrt '), fmtUntil(b.ban.until), ' – ', b.ban.reason, b.ban.note ? el('div', null, el('small', null, '📝 ' + b.ban.note)) : null) : null,
      (x.temp || []).map(t => el('div.callout.' + (t.list === 'deny' ? 'bad' : 'warn'), null, el('b', null, TEMP_LISTS[t.list]?.[0] || t.list), ` (befristet, ${fmtUntil(t.until)})`, t.note ? ' – ' + t.note : '')),
      (x.lists || []).length ? el('div.callout', null, el('b', null, 'Steht in: '), x.lists.join(' · ')) : null,
      el('dl.kv', null,
        el('dt', null, 'Bedrohungs-Score'), el('dd', null, el('b', { style: { color: score > 50 ? 'var(--bad)' : score > 10 ? 'var(--warn)' : '' } }, String(score)), b.challenged_until ? el('span.badge.warn', { style: { marginLeft: '6px' } }, 'muss Challenge lösen') : null),
        el('dt', null, 'Anfragen'), el('dd', null, `${fmtInt(s.requests)} gespeichert · ${fmtInt(s.blocked)} blockiert · ${fmtInt(s.errors)} Fehler`),
        el('dt', null, 'Gesehen'), el('dd', null, s.first_seen ? `${fmtAgo(s.first_seen)} bis ${fmtAgo(s.last_seen)}` : '–'),
        (x.instances || []).length ? [el('dt', null, 'Caddy-Instanzen'), el('dd', null, x.instances.map(i => el('span', { style: { marginRight: '8px' } }, instChip(i.inst, { always: true }), ' ', fmtInt(i.count))))] : null,
        el('dt', null, 'Sperren bisher'), el('dd', null, fmtInt(b.offender_bans)),
        acts.length ? [el('dt', null, 'Eingriffe'), el('dd', null, acts.map(([a, n]) => `${actionLabel(a)} ${fmtInt(n)}×`).join(', '))] : null,
        (s.hosts || []).length ? [el('dt', null, 'Hosts'), el('dd', null, s.hosts.slice(0, 4).map(h => h.key).join(', '))] : null,
        (x.logins || []).length ? [el('dt', null, 'Anmeldungen'), el('dd', null, x.logins.slice(0, 4).map(l => el('div', null, `${l.user || '?'} – ${l.result} · ${l.host} · ${fmtAgo(l.ts)}`)))] : null),
      el('div.row', { style: { flexWrap: 'wrap', gap: '6px' } },
        can('bans') ? (b.ban
          ? el('button.btn.primary', { onclick: async () => { if (!await confirmDialog('Sperre aufheben', `${b.ban.ip} wird wieder zugelassen.`, 'Aufheben', 'primary')) return; try { await del('/bans/' + encodeURIComponent(b.ban.ip)); toast('Entsperrt', 'ok'); load(); } catch (e) { errToast(e); } } }, 'Sperre aufheben')
          : [el('button.btn.danger', { onclick: () => quickBan(ip, 3600, load) }, '1 h sperren'), el('button.btn.danger', { onclick: () => quickBan(ip, 86400, load) }, '24 h sperren')]) : null,
        can('bans') ? el('button.btn', { onclick: () => tempDialog({ value: ip, scope: 'global', list: can('admin') ? 'trusted' : 'never_ban', onDone: load }, modal), title: can('admin') ? 'Befristet als vertrauenswürdig eintragen – alle Prüfungen werden übersprungen' : 'Befristet vor IDS-Sperren schützen' }, 'Dulden …') : null,
        el('a.btn', { href: '#/analytics?ip=' + encodeURIComponent(ip) }, 'Anfragen'),
        el('a.btn', { href: '#/flow?ip=' + encodeURIComponent(ip) }, 'Simulieren'),
        el('button.btn.ghost', { onclick: () => copy(ip) }, 'Kopieren')),
      b.requests?.length ? el('div', null, el('h4', { style: { margin: '6px 0' } }, 'Letzte Anfragen'),
        el('table.compact', null, el('tbody', null, b.requests.slice(0, 8).map(r => el('tr', null,
          el('td.muted.nowrap', { title: fmtDateTime(r.t) }, fmtAgo(r.t)), el('td', null, String(r.s)), el('td.mono.trunc', { title: r.host + r.p }, r.host + r.p), el('td', null, r.a ? actionLabel(r.a) : '')))))) : null);
  }
  load();
}

async function quickBan(ip, secs, done) {
  try { await post('/bans', { ip, seconds: secs, reason: 'aus dem Steckbrief' }); toast(`${ip} gesperrt`, 'ok'); done(); } catch (e) { errToast(e); }
}

/** Delegated handler: plain clicks on IP links open the drawer. */
export function installIPDrawer() {
  document.addEventListener('click', (e) => {
    const a = e.target.closest?.('a.iplink[data-ip]');
    if (!a || e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    openIPDrawer(a.dataset.ip);
  });
}

export { fmtUnix };
