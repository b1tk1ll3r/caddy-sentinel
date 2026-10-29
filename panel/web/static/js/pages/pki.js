import { el, mount, get, qs, panel, empty, modal, select, toggle, copy, debounce, fmtInt, fmtDateTime, fmtAgo } from '../ui.js';
import { withInstance } from '../instancebar.js';
import { setActions } from '../app.js';

const CA_STATUS = {
  ok: ['ok', 'gültig'],
  renew: ['info', 'Erneuerung fällig'],
  warn: ['warn', 'überfällig'],
  expired: ['bad', 'abgelaufen'],
};
const ISSUED_STATUS = {
  valid: ['ok', 'gültig'],
  expired: ['', 'abgelaufen'],
  revoked: ['bad', 'widerrufen'],
};

function left(unix) {
  const s = unix - Date.now() / 1000;
  if (s <= 0) return 'abgelaufen';
  const d = s / 86400;
  if (d >= 730) return Math.floor(d / 365) + ' Jahre';
  if (d >= 2) return Math.floor(d) + ' Tage';
  const h = s / 3600;
  return h >= 1 ? Math.floor(h) + ' Std.' : Math.max(1, Math.floor(s / 60)) + ' Min.';
}

const shortFp = (fp) => fp ? fp.slice(0, 16).replace(/(..)(?=.)/g, '$1:').toUpperCase() + '…' : '';
const fullFp = (fp) => fp.replace(/(..)(?=.)/g, '$1:').toUpperCase();

function download(name, text) {
  const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' })), download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

function lifebar(c) {
  const total = Math.max(1, c.not_after - c.not_before);
  const rest = Math.max(0, Math.min(1, (c.not_after - Date.now() / 1000) / total));
  const [k] = CA_STATUS[c.status] || ['ok'];
  return el('div.sharebar', { title: `${Math.round(rest * 100)} % der Laufzeit übrig` },
    el('span', { style: { width: Math.max(2, rest * 100) + '%', background: `var(--${k === 'info' ? 'ok' : k})` } }));
}

function dl(rows) {
  return el('dl.kv', null, rows.filter(Boolean).flatMap(([k, v]) => [el('dt', null, k), el('dd', null, v)]));
}

function certCard(title, c, extra, filename) {
  if (!c) return panel(title, el('p.muted', null, 'Nicht gefunden.'));
  const [k, label] = CA_STATUS[c.status] || ['', c.status];
  return panel(title, el('div.stack', null,
    el('div.row', null, el('b', null, c.subject), el('span.badge.' + k, null, label), extra || null),
    lifebar(c),
    dl([
      ['Gültig', `${fmtDateTime(c.not_before * 1000)} – ${fmtDateTime(c.not_after * 1000)}`],
      ['Restlaufzeit', left(c.not_after)],
      ['Ausgestellt von', c.issuer],
      ['Seriennummer', el('span.mono.wrap', null, c.serial)],
      ['Schlüssel', c.key_type],
      ['SHA-256', el('span.mono.wrap', { title: 'Klicken zum Kopieren', style: { cursor: 'copy' }, onclick: () => copy(fullFp(c.fingerprint)) }, fullFp(c.fingerprint))],
    ])),
    el('button.btn.sm', { onclick: () => download(filename, c.pem) }, 'PEM herunterladen'));
}

export async function render(root, _p, scope, q) {
  ({ root } = withInstance(root));
  let data;
  let caId = q.get('ca') || '';
  const f = { q: '', status: '', source: '', intermediate: '', latest: false, offset: 0 };
  const LIMIT = 50;

  setActions(el('button.btn', { onclick: () => load() }, 'Aktualisieren'));

  async function load() {
    data = await get('/pki', scope.signal);
    draw();
  }

  function draw() {
    const cas = data.authorities;
    if (!cas.length) {
      mount(root,
        data.error ? el('div.callout.warn', null, data.error, '. Den Pfad stellst du unter ', el('a', { href: '#/settings?tab=agent' }, 'Einstellungen › Agent & Caddy'), ' ein.') : null,
        empty('Keine interne CA gefunden', `Caddy legt seine CA unter ${data.storage}/pki/authorities an, sobald eine Site „tls internal“ oder „acme_server“ nutzt.`));
      return;
    }
    if (!cas.find(a => a.id === caId)) caId = cas[0].id;
    const a = cas.find(x => x.id === caId);
    const active = a.intermediates.find(i => i.active) || a.live_intermediate || a.intermediate;
    const live = a.live === 'match'
      ? el('span.badge.ok', { title: 'Die laufende Caddy-Instanz meldet genau dieses Intermediate über die Admin-API.' }, 'von Caddy bestätigt')
      : a.live === 'mismatch'
        ? el('span.badge.warn', { title: 'Caddy nutzt ein anderes Intermediate als im Speicher liegt – meist nach einer Erneuerung bis zum nächsten Reload.' }, 'Caddy nutzt anderes')
        : el('span.badge', { title: a.live_error || '' }, 'Admin-API nicht erreichbar');
    const issuedBody = el('div');

    mount(root,
      el('p.muted', null, 'Caddys eingebaute Zertifizierungsstelle: Root und aktives Intermediate, die ACME-Endpunkte sowie alle ausgestellten Zertifikate – über ', el('code', null, 'acme_server'), ' an Clients und per ', el('code', null, 'tls internal'), ' an Caddy selbst.'),
      cas.length > 1 ? el('div.row', null, el('span.muted', null, 'CA:'), select(cas.map(x => [x.id, `${x.name} (${x.id})`]), caId, (v) => { caId = v; f.intermediate = ''; f.offset = 0; history.replaceState(null, '', '#/pki?ca=' + v); draw(); })) : null,
      a.errors?.length ? el('div.callout.warn', null, a.errors.join(' · ')) : null,
      a.db_error ? el('div.callout.warn', null, 'ACME-Datenbank: ', a.db_error) : null,
      a.live === 'mismatch' ? el('div.callout.warn', null, 'Caddy signiert gerade mit einem anderen Intermediate (', shortFp(a.live_intermediate.fingerprint), ') als im Speicher liegt (', shortFp(a.intermediate.fingerprint), '). Das passiert nach einer Erneuerung durch eine andere Instanz oder bis zum nächsten Reload.') : null,
      el('div.kpis', null,
        el('div.kpi.' + ((CA_STATUS[active?.status] || ['ok'])[0] === 'ok' ? 'ok' : (CA_STATUS[active?.status] || [''])[0]), null, el('div.label', null, 'Aktives Intermediate'), el('div.value', null, active ? left(active.not_after) : '–'), el('div.muted', null, active ? 'bis ' + fmtDateTime(active.not_after * 1000) : '')),
        el('div.kpi', null, el('div.label', null, 'Root gültig'), el('div.value', null, a.root ? left(a.root.not_after) : '–'), el('div.muted', null, a.root ? 'bis ' + fmtDateTime(a.root.not_after * 1000) : '')),
        el('div.kpi', null, el('div.label', null, 'Ausgestellt'), el('div.value', null, fmtInt(a.stats.total || 0)), el('div.muted', null, `${fmtInt(a.stats.valid || 0)} gültig · ${fmtInt(a.stats.revoked || 0)} widerrufen`)),
        el('div.kpi', null, el('div.label', null, 'Intermediates'), el('div.value', null, a.intermediates.length), el('div.muted', null, a.intermediate_lifetime ? 'Laufzeit ' + a.intermediate_lifetime : 'Laufzeit 7d (Standard)'))),
      el('div.grid.g2', null,
        certCard('Aktives Intermediate', active, live, `${a.id}-intermediate.crt`),
        certCard('Root-Zertifikat', a.root, el('span.muted', null, 'Diese Datei verteilen Clients als vertrauenswürdige CA.'), `${a.id}-root.crt`)),
      panel('ACME-Endpunkte', a.acme.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Directory-URL'), el('th', null, 'Hosts'), el('th', null, 'Zertifikatslaufzeit'), el('th', null, 'Signiert mit'), el('th', null, 'Policy'))),
        el('tbody', null, a.acme.map(e => el('tr', null,
          el('td', null, el('span.mono', { style: { cursor: 'copy' }, title: 'Klicken zum Kopieren', onclick: () => copy(e.directory) }, e.directory)),
          el('td', null, (e.hosts || []).join(', ') || el('span.muted', null, 'alle')),
          el('td', null, e.lifetime),
          el('td', null, e.sign_with_root ? 'Root' : 'Intermediate'),
          el('td', null, e.policy ? el('code', null, JSON.stringify(e.policy)) : el('span.muted', null, 'keine Einschränkung'))))))) :
        el('p.muted', null, 'Diese CA stellt keine Zertifikate per ACME aus (kein ', el('code', null, 'acme_server'), ' in der laufenden Konfiguration). Zertifikate aus ', el('code', null, 'tls internal'), ' erscheinen trotzdem unten.')),
      panel('Intermediate-Verlauf', el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Intermediate'), el('th', null, 'Status'), el('th', null, 'Gültig von'), el('th', null, 'Gültig bis'), el('th.num', null, 'Ausgestellt'), el('th', null, ''))),
        el('tbody', null, a.intermediates.map(i => {
          const [k, label] = CA_STATUS[i.status] || ['', i.status];
          return el('tr', null,
            el('td', null, el('div', null, i.subject, i.active ? el('span.badge.ok', { style: { marginLeft: '8px' } }, 'aktiv') : null), el('small.mono', null, shortFp(i.fingerprint))),
            el('td', null, i.active || i.status === 'expired' ? el('span.badge.' + k, null, label) : el('span.badge', { title: 'Noch gültig, Caddy signiert aber nicht mehr damit' }, 'abgelöst')),
            el('td.nowrap', null, fmtDateTime(i.not_before * 1000)),
            el('td.nowrap', null, fmtDateTime(i.not_after * 1000)),
            el('td.num', null, i.issued ? el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); f.intermediate = i.fingerprint; f.offset = 0; loadIssued(); issuedBody.scrollIntoView({ behavior: 'smooth' }); } }, fmtInt(i.issued)) : '0'),
            el('td', null, el('button.btn.sm', { onclick: () => download(`${a.id}-intermediate-${i.fingerprint.slice(0, 8)}.crt`, i.pem) }, 'PEM')));
        }))))),
      issuedBody);

    async function loadIssued() {
      const r = await get(`/pki/${encodeURIComponent(a.id)}/issued` + qs({ q: f.q, status: f.status, source: f.source, intermediate: f.intermediate, latest: f.latest ? 1 : '', limit: LIMIT, offset: f.offset }), scope.signal);
      const search = el('input', { type: 'search', placeholder: 'Name, Seriennummer, Konto …', value: f.q, style: { minWidth: '240px' }, oninput: debounce((e) => { f.q = e.target.value; f.offset = 0; loadIssued(); }, 250) });
      const inter = f.intermediate ? a.intermediates.find(i => i.fingerprint === f.intermediate) : null;
      const pages = Math.ceil(r.total / LIMIT);
      const page = Math.floor(f.offset / LIMIT) + 1;
      mount(issuedBody, panel('Ausgestellte Zertifikate', el('div.stack', null,
        el('div.row', null, search,
          select([['', 'Alle Status'], ['valid', 'Gültig'], ['expired', 'Abgelaufen'], ['revoked', 'Widerrufen']], f.status, (v) => { f.status = v; f.offset = 0; loadIssued(); }, { 'aria-label': 'Status' }),
          select([['', 'Alle Quellen'], ['acme', 'ACME-Clients'], ['internal', 'tls internal']], f.source, (v) => { f.source = v; f.offset = 0; loadIssued(); }, { 'aria-label': 'Quelle' }),
          toggle(f.latest, (v) => { f.latest = v; f.offset = 0; loadIssued(); }, 'nur neuestes je Name'),
          inter ? el('span.chip.on', { onclick: () => { f.intermediate = ''; loadIssued(); }, title: 'Filter entfernen' }, 'Intermediate ' + shortFp(inter.fingerprint) + ' ✕') : null,
          el('span.grow'), el('span.muted', null, `${fmtInt(r.total)} Treffer · ${fmtInt(r.active_subjects)} Namen mit gültigem Zertifikat`)),
        r.items.length ? el('div.table-wrap', null, el('table', null,
          el('thead', null, el('tr', null, el('th', null, 'Namen'), el('th', null, 'Status'), el('th', null, 'Quelle'), el('th', null, 'Ausgestellt'), el('th', null, 'Gültig bis'), el('th', null, 'Signiert von'), el('th', null, 'Seriennummer'))),
          el('tbody', null, r.items.map(c => {
            const [k, label] = ISSUED_STATUS[c.status] || ['', c.status];
            const i = a.intermediates.find(x => x.fingerprint === c.intermediate);
            return el('tr.clickable', { onclick: () => detail(a, c), title: 'Details anzeigen' },
              el('td', null, c.names.slice(0, 3).map(n => el('div.mono', null, n)), c.names.length > 3 ? el('small.muted', null, `+${c.names.length - 3} weitere`) : null),
              el('td', null, el('span.badge.' + k, null, label), c.status === 'valid' ? el('div', null, el('small', null, 'noch ' + left(c.not_after))) : null),
              el('td', null, c.source === 'acme' ? 'ACME' : 'tls internal', c.account ? el('div', null, el('small', null, c.account)) : null),
              el('td.nowrap', { title: fmtDateTime(c.not_before * 1000) }, fmtAgo(c.not_before * 1000)),
              el('td.nowrap', null, fmtDateTime(c.not_after * 1000)),
              el('td', null, i ? el('span', null, i.active ? 'aktives' : 'früheres', ' Intermediate', el('div', null, el('small.mono', null, shortFp(i.fingerprint)))) : (c.signed_by || el('span.muted', null, 'unbekannt'))),
              el('td', null, el('small.mono', null, c.serial.length > 23 ? c.serial.slice(0, 23) + '…' : c.serial)));
          })))) : empty('Keine Zertifikate', f.q || f.status || f.source || f.intermediate ? 'Für diese Filter gibt es keine Treffer.' : 'Diese CA hat noch keine Zertifikate ausgestellt.'),
        pages > 1 ? el('div.row', null,
          el('button.btn.sm', { disabled: page <= 1, onclick: () => { f.offset -= LIMIT; loadIssued(); } }, '‹ Zurück'),
          el('span.muted', null, `Seite ${page} von ${pages}`),
          el('button.btn.sm', { disabled: page >= pages, onclick: () => { f.offset += LIMIT; loadIssued(); } }, 'Weiter ›')) : null)));
    }
    loadIssued();
  }

  async function detail(a, c) {
    const d = await get(`/pki/${encodeURIComponent(a.id)}/issued/${encodeURIComponent(c.serial)}`);
    const [k, label] = ISSUED_STATUS[c.status] || ['', c.status];
    modal('Zertifikat ' + (c.names[0] || c.serial), [
      el('div.row', null, el('span.badge.' + k, null, label), c.status === 'revoked' ? el('span.muted', null, `am ${fmtDateTime(c.revoked_at * 1000)}${c.revoke_reason ? ' – ' + c.revoke_reason : ''}`) : null),
      dl([
        ['Namen (SAN)', el('div', null, c.names.map(n => el('div.mono', null, n)))],
        ['Subject', d.subject],
        ['Gültig', `${fmtDateTime(c.not_before * 1000)} – ${fmtDateTime(c.not_after * 1000)} (${d.lifetime_hours} Std.)`],
        ['Kette', d.chain.join(' → ')],
        ['Quelle', c.source === 'acme' ? 'ACME' + (c.provisioner ? ' · Provisioner ' + c.provisioner : '') : 'tls internal (Caddy selbst)'],
        c.account ? ['ACME-Konto', c.account] : null,
        c.order ? ['Order-ID', el('span.mono', null, c.order)] : null,
        ['Verwendung', (d.ext_key_usage || []).join(', ') || '–'],
        ['Schlüssel', c.key_type + ' · ' + d.signature_algorithm],
        ['Seriennummer', el('span.mono.wrap', null, c.serial)],
        ['SHA-256', el('span.mono.wrap', { style: { cursor: 'copy' }, onclick: () => copy(fullFp(d.fingerprint)) }, fullFp(d.fingerprint))],
      ]),
      el('details', null, el('summary', null, 'PEM anzeigen'), el('pre.mono', { style: { whiteSpace: 'pre-wrap', fontSize: '11.5px' } }, d.pem)),
    ], {
      wide: true,
      actions: [
        { label: 'PEM kopieren', onClick: () => { copy(d.pem); return false; } },
        { label: 'Herunterladen', kind: 'primary', onClick: () => { download((c.names[0] || 'cert').replace(/[*/:]/g, '_') + '.crt', d.pem); return false; } },
        { label: 'Schließen' },
      ],
    });
  }

  await load();
  scope.interval(() => { if (!document.hidden && !document.querySelector('.modal-wrap')) load().catch(() => { }); }, 60000);
}
