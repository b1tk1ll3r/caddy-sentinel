import { el, mount, get, panel, empty, fmtDateTime } from '../ui.js';
import { withInstance } from '../instancebar.js';

const STATUS = {
  ok: ['ok', 'gültig'],
  renew: ['info', 'Erneuerung fällig'],
  warn: ['warn', 'läuft bald ab'],
  expired: ['bad', 'abgelaufen'],
};

const left = (c) => c.days_left >= 2 ? c.days_left + ' Tage' : Math.max(0, c.hours_left) + ' Std.';

export async function render(root, _p, scope) {
  ({ root } = withInstance(root));
  const d = await get('/certs', scope.signal);
  const certs = d.certs;
  const bad = certs.filter(c => c.status === 'warn' || c.status === 'expired').length;
  mount(root,
    el('p.muted', null, 'Zertifikate, die Caddy automatisch verwaltet (aus ', el('code', null, d.storage + '/certificates'), '). Caddy erneuert sie im letzten Drittel ihrer Laufzeit; läuft eines trotzdem bald ab, schlägt die Erneuerung fehl – dann sendet Sentinel einen Alarm.'),
    d.error ? el('div.callout.warn', null, d.error, '. Den Pfad zum Caddy-Datenverzeichnis stellst du unter ', el('a', { href: '#/settings?tab=agent' }, 'Einstellungen › Agent & Caddy'), ' ein. Das Panel braucht Leserechte.') : null,
    certs.length ? el('div.kpis', null,
      el('div.kpi', null, el('div.label', null, 'Zertifikate'), el('div.value', null, certs.length)),
      el('div.kpi.' + (bad ? 'bad' : 'ok'), null, el('div.label', null, 'Handlungsbedarf'), el('div.value', null, bad || 'keiner')),
      el('div.kpi', null, el('div.label', null, 'Nächster Ablauf'), el('div.value', null, left(certs[0])), el('div.muted', null, certs[0].names[0]))) : null,
    panel('Zertifikate', certs.length ? el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Domains'), el('th', null, 'Aussteller'), el('th', null, 'Status'), el('th', null, 'Restlaufzeit'), el('th', null, 'Gültig bis'), el('th', null, 'Schlüssel'))),
      el('tbody', null, certs.map(c => {
        const [k, label] = STATUS[c.status] || ['', c.status];
        return el('tr', null,
          el('td', null, c.names.map(n => el('div.mono', null, n))),
          el('td', null, c.issuer, el('div', null, el('small', null, c.ca))),
          el('td', null, el('span.badge.' + k, null, label)),
          el('td', { style: { minWidth: '160px' } }, el('div.sharebar', { title: `${c.days_left} Tage` }, el('span', { style: { width: Math.max(2, Math.min(100, (c.hours_left / 24) / Math.max(1, (c.not_after - c.not_before) / 86400) * 100)) + '%', background: `var(--${k === 'ok' || k === 'info' ? 'ok' : k})` } })), el('small', null, left(c))),
          el('td.nowrap', null, fmtDateTime(c.not_after * 1000)),
          el('td', null, c.key_type));
      })))) : empty('Keine Zertifikate gefunden', 'Sobald Caddy Zertifikate bezieht (öffentliche Domains oder „tls internal“), erscheinen sie hier.')));
}
