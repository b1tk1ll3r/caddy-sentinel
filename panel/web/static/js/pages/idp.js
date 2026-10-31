// Site-Login › OIDC-Server: Sentinel as OpenID Provider for applications.
import { el, mount, get, post, put, del, panel, field, toggle, select, linesInput, toast, errToast, confirmDialog, modal, copy, fmtUnix, fmtAgo } from '../ui.js';
import { setActions } from '../app.js';

const SCOPE_HINT = 'Scopes: openid (Pflicht), profile, email, groups, offline_access';

// examples for common applications (redirect URI patterns)
const EXAMPLES = [
  ['Grafana', 'https://grafana.firma.de/login/generic_oauth'],
  ['Nextcloud (user_oidc)', 'https://cloud.firma.de/apps/user_oidc/code'],
  ['Gitea / Forgejo', 'https://git.firma.de/user/oauth2/<Name>/callback'],
  ['Portainer', 'https://portainer.firma.de/'],
  ['Proxmox VE', 'https://pve.firma.de:8006'],
];

export async function idpTab(body, scope, isAdmin) {
  const data = await get('/oidc', scope.signal);
  let cfg = { enabled: data.enabled, issuer: data.issuer || '', access_minutes: data.access_minutes || 60 };
  const saveBtn = el('button.btn.primary', { disabled: true, onclick: save }, 'Speichern');
  const markDirty = () => { saveBtn.disabled = !isAdmin; };
  setActions(saveBtn);
  async function save() {
    saveBtn.disabled = true;
    try { await put('/oidc/settings', cfg); toast('Gespeichert', 'ok'); idpTab(body, scope, isAdmin); } catch (e) { saveBtn.disabled = false; errToast(e); }
  }
  const ep = data.endpoints || {};
  const endpointRow = (label, v) => v ? el('tr', null, el('td', { style: { whiteSpace: 'nowrap', paddingRight: '16px' } }, label), el('td.mono', { style: { wordBreak: 'break-all' } }, v), el('td', null, el('button.btn.sm', { onclick: () => copy(v) }, 'Kopieren'))) : null;
  const clients = data.clients || [];
  const grants = data.grants || [];
  const byClient = Object.fromEntries(clients.map(c => [c.id, c.name]));

  mount(body,
    el('p.muted', null, 'Sentinel kann selbst Anmeldedienst (OpenID Provider) für Anwendungen sein, die OpenID Connect sprechen – Grafana, Nextcloud, Gitea, Proxmox, Portainer und viele mehr. Angemeldet wird mit denselben Konten wie beim Site-Login (Active Directory, Zugangskonten, OAuth-Anbieter), mit zweitem Faktor, Sperren bei Fehlversuchen und Anmeldeprotokoll. Das Panel selbst muss dafür nicht erreichbar sein: Die Anmeldung läuft über eine eigene Site in Caddy.'),
    (data.warnings || []).length ? el('div.callout.warn', null, el('b', null, 'Noch zu tun: '), el('ul', { style: { margin: '4px 0 0 18px', padding: 0 } }, data.warnings.map(w => el('li', null, w)))) : null,
    panel('Anmeldedienst', el('div.stack', null,
      toggle(cfg.enabled, (v) => { cfg.enabled = v; markDirty(); }, 'OIDC-Server einschalten'),
      el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'Anmelde-Adresse (Issuer)'),
          el('input.mono', { value: cfg.issuer, placeholder: 'https://sso.firma.de', oninput: (e) => { cfg.issuer = e.target.value.trim(); markDirty(); } }),
          el('small', null, 'Eine eigene Site in Caddy mit der Direktive „sentinel“, z. B. ', el('code', null, 'sso.firma.de { sentinel; respond "Anmeldung" }'), '. Ihre Policy muss die Anmeldung aktivieren – deren Anmeldemethoden, zweiter Faktor, Netze und Ratelimits gelten auch hier.')),
        field('Gültigkeit von Access- und ID-Token (Minuten)', el('input', { type: 'number', min: 5, max: 1440, value: cfg.access_minutes, oninput: (e) => { cfg.access_minutes = +e.target.value; markDirty(); } }))),
      data.policy ? el('div.callout' + (data.policy.login ? '' : '.warn'), null, 'Policy der Anmelde-Adresse: ', el('a', { href: '#/policies/' + data.policy.id + '?tab=login' }, data.policy.name), data.policy.login ? (data.policy.require_totp ? ' · Anmeldung mit zweitem Faktor' : ' · Anmeldung aktiv') : ' · Anmeldung nicht aktiviert') : null,
      data.discovery ? el('div.table-wrap', null, el('table', { style: { width: 'auto', tableLayout: 'auto' } }, el('tbody', null,
        endpointRow('Discovery', data.discovery),
        endpointRow('Issuer', ep.issuer),
        endpointRow('Autorisierung', ep.authorization_endpoint),
        endpointRow('Token', ep.token_endpoint),
        endpointRow('Userinfo', ep.userinfo_endpoint),
        endpointRow('Schlüssel (JWKS)', ep.jwks_uri),
        endpointRow('Abmelden', ep.end_session_endpoint)))) : null)),
    panel('Anwendungen', el('div.stack', null,
      clients.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, ['Name', 'Client-ID', 'Art', 'Zugriff', 'Optionen', ''].map(h => el('th', null, h)))),
        el('tbody', null, clients.map(c => el('tr', null,
          el('td', null, c.name, !c.enabled ? el('span.badge', { style: { marginLeft: '6px' } }, 'aus') : null),
          el('td.mono', null, c.id),
          el('td', null, c.public ? el('span.badge.info', { title: 'ohne Secret, nur mit PKCE' }, 'öffentlich') : el('span.badge', null, 'vertraulich')),
          el('td', null, [...(c.allowed_groups || []), ...(c.allowed_users || [])].join(', ') || el('span.muted', null, 'alle')),
          el('td', null, [c.require_2fa ? '2FA' : null, c.require_pkce ? 'PKCE' : null, c.consent ? 'Zustimmung' : null, c.refresh ? 'Refresh ' + c.refresh_days + ' T.' : null, c.alg !== 'RS256' ? c.alg : null].filter(Boolean).join(' · ')),
          el('td', { style: { textAlign: 'right', whiteSpace: 'nowrap' } },
            el('button.btn.sm', { onclick: () => editClient(c) }, isAdmin ? 'Bearbeiten' : 'Ansehen')))))))
        : el('p.muted', null, 'Noch keine Anwendung.'),
      isAdmin ? el('div.row', null, el('button.btn', { onclick: () => editClient(null) }, '+ Anwendung')) : null)),
    panel('Aktive Freigaben (Refresh-Tokens)', grants.length ? el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, ['Konto', 'Anwendung', 'Angemeldet', 'Zuletzt erneuert', 'Läuft ab', ''].map(h => el('th', null, h)))),
      el('tbody', null, grants.map(g => el('tr', null,
        el('td', null, g.username), el('td', null, byClient[g.client] || g.client),
        el('td', null, fmtUnix(g.auth_time)), el('td', null, fmtAgo(g.last_used * 1000)), el('td', null, fmtUnix(g.expires)),
        el('td', { style: { textAlign: 'right' } }, isAdmin ? el('button.btn.sm.danger', {
          onclick: async () => {
            if (!(await confirmDialog('Freigabe widerrufen?', `${g.username} muss sich bei „${byClient[g.client] || g.client}“ neu anmelden, sobald das aktuelle Access-Token abläuft.`, 'Widerrufen'))) return;
            try { await del('/oidc/grants/' + encodeURIComponent(g.family)); toast('Widerrufen', 'ok'); idpTab(body, scope, isAdmin); } catch (e) { errToast(e); }
          },
        }, 'Widerrufen') : null))))))
      : el('p.muted', null, 'Keine – Refresh-Tokens gibt es nur für Anwendungen, bei denen sie eingeschaltet sind.')),
    panel('Signaturschlüssel', el('div.stack', null,
      (data.keys || []).length ? el('div.table-wrap', null, el('table.fit', null,
        el('thead', null, el('tr', null, ['Kennung', 'Verfahren', 'Erzeugt', 'Status'].map(h => el('th', null, h)))),
        el('tbody', null, data.keys.map(k => el('tr', null, el('td.mono', { style: { whiteSpace: 'nowrap' } }, k.kid), el('td', null, k.alg), el('td', null, fmtUnix(k.created)),
          el('td', null, k.retired ? el('span.badge', null, 'ausgemustert ' + fmtUnix(k.retired)) : el('span.badge.ok', null, 'aktiv')))))))
        : el('p.muted', null, 'Werden beim Einschalten erzeugt.'),
      el('small.muted', null, 'RS256 versteht jede Anwendung, ES256 ist kürzer. Nach dem Erneuern bleiben die alten öffentlichen Schlüssel 7 Tage veröffentlicht; Anwendungen laden die neuen selbst nach.'),
      isAdmin && (data.keys || []).length ? el('div.row', null, el('button.btn', {
        onclick: async () => {
          if (!(await confirmDialog('Schlüssel erneuern?', 'Neue Tokens werden ab sofort mit neuen Schlüsseln signiert. Anwendungen, die Schlüssel fest hinterlegt haben (statt sie über JWKS zu laden), müssen angepasst werden.', 'Erneuern', 'primary'))) return;
          try { await post('/oidc/keys/rotate'); toast('Neue Schlüssel aktiv', 'ok'); idpTab(body, scope, isAdmin); } catch (e) { errToast(e); }
        },
      }, 'Schlüssel erneuern')) : null)));

  function showSecret(c, secret) {
    modal('Client-Secret für „' + c.name + '“', el('div.stack', null,
      el('div.callout.warn', null, 'Das Secret wird nur jetzt angezeigt. Trage es in der Anwendung ein.'),
      el('div.table-wrap', null, el('table.fit', null, el('tbody', null,
        el('tr', null, el('td', null, 'Client-ID'), el('td.mono', null, c.id), el('td', null, el('button.btn.sm', { onclick: () => copy(c.id) }, 'Kopieren'))),
        el('tr', null, el('td', null, 'Client-Secret'), el('td.mono', { style: { wordBreak: 'break-all' } }, secret), el('td', null, el('button.btn.sm', { onclick: () => copy(secret) }, 'Kopieren'))),
        data.discovery ? el('tr', null, el('td', null, 'Discovery'), el('td.mono', null, data.discovery), el('td', null, el('button.btn.sm', { onclick: () => copy(data.discovery) }, 'Kopieren'))) : null)))),
    { actions: [{ label: 'Fertig', kind: 'primary' }], wide: true, onClose: () => idpTab(body, scope, isAdmin) });
  }

  function editClient(orig) {
    const isNew = !orig;
    const c = orig ? JSON.parse(JSON.stringify(orig)) : { id: '', name: '', enabled: true, public: false, redirect_uris: [], post_logout_uris: [], allowed_groups: [], allowed_users: [], sources: [], require_2fa: false, require_pkce: true, consent: false, refresh: false, refresh_days: 30, alg: 'RS256' };
    const ro = !isAdmin;
    const inp = (k, attrs = {}) => el('input' + (attrs.mono ? '.mono' : ''), { value: c[k] || '', placeholder: attrs.placeholder || '', disabled: ro || attrs.disabled, oninput: (e) => { c[k] = e.target.value.trim(); } });
    const lines = (k, ph) => { const t = linesInput(c[k] || [], (v) => { c[k] = v; }, { rows: 2, placeholder: ph }); t.disabled = ro; return t; };
    const tg = (k, label, after) => { const t = toggle(!!c[k], (v) => { c[k] = v; after?.(); }, label); t.querySelector('input').disabled = ro; return t; };
    const pkceBox = el('span');
    const drawPKCE = () => mount(pkceBox, c.public ? el('small.muted', null, 'Öffentliche Anwendungen verwenden immer PKCE.') : tg('require_pkce', 'PKCE verlangen (empfohlen; nur abschalten, wenn die Anwendung es nicht kann)'));
    drawPKCE();
    const m = modal(isNew ? 'Anwendung hinzufügen' : 'Anwendung „' + c.name + '“', el('div.stack', null,
      el('div.fields', null,
        field('Name', inp('name', { placeholder: 'Grafana' })),
        field('Client-ID', inp('id', { mono: true, placeholder: 'leer = aus dem Namen', disabled: !isNew }), isNew ? 'Kann später nicht geändert werden.' : null),
        el('div.field.wide', null, el('span', null, 'Redirect-URIs'), lines('redirect_uris', 'https://grafana.firma.de/login/generic_oauth'),
          el('small', null, 'Eine pro Zeile, exakt wie die Anwendung sie sendet (keine Platzhalter). Beispiele: ', EXAMPLES.map(([n, u], i) => [i ? ' · ' : '', el('span', { title: u }, n)]))),
        el('div.field.wide', null, el('span', null, 'Adressen nach dem Abmelden (optional)'), lines('post_logout_uris', 'https://grafana.firma.de/login'))),
      el('div.fields', null,
        el('div.field', null, el('span', null, 'Erlaubte Gruppen'), lines('allowed_groups', 'Grafana-Users'), el('small', null, 'leer = alle, die sich an der Anmelde-Adresse anmelden dürfen')),
        el('div.field', null, el('span', null, 'Erlaubte Benutzer'), lines('allowed_users', 'erika')),
        el('div.field', null, el('span', null, 'Anmeldemethoden'), lines('sources', 'directory\nlocal'), el('small', null, 'leer = alle (öffentliche Anbieter wie GitHub nur mit Gruppen/Benutzern oder ausdrücklich)')),
        field('Signaturverfahren', select([['RS256', 'RS256 (Standard)'], ['ES256', 'ES256']], c.alg || 'RS256', (v) => { c.alg = v; }, { disabled: ro }))),
      el('div.stack', { style: { gap: '8px' } },
        tg('enabled', 'Aktiv'),
        tg('public', 'Öffentliche Anwendung (Single-Page- oder Mobil-App ohne Secret)', drawPKCE),
        pkceBox,
        tg('require_2fa', 'Zweiten Faktor verlangen (auch wenn die Policy ihn nicht verlangt)'),
        tg('consent', 'Zustimmung abfragen (Benutzer sehen, welche Angaben die Anwendung erhält)'),
        el('div.row', { style: { gap: '10px' } }, tg('refresh', 'Refresh-Tokens ausgeben'),
          el('label.row', { style: { gap: '6px' } }, 'gültig', el('input', { type: 'number', min: 1, max: 90, value: c.refresh_days || 30, style: { width: '70px' }, disabled: ro, oninput: (e) => { c.refresh_days = +e.target.value; } }), 'Tage'))),
      el('small.muted', null, SCOPE_HINT + '. Claims: sub und preferred_username = Benutzername, name, email, groups (Gruppennamen, bei GitHub & Co. mit Präfix).')),
    {
      wide: true,
      actions: ro ? [{ label: 'Schließen' }] : [
        !isNew ? { label: 'Entfernen', kind: 'danger', onClick: async () => {
          if (!(await confirmDialog('Anwendung entfernen?', `„${c.name}“ kann danach keine Anmeldungen mehr anfordern; ihre Refresh-Tokens werden ungültig.`, 'Entfernen'))) return false;
          await del('/oidc/clients/' + encodeURIComponent(c.id)); toast('Entfernt', 'ok'); idpTab(body, scope, isAdmin);
        } } : null,
        !isNew && !c.public ? { label: 'Secret erneuern', onClick: async () => {
          if (!(await confirmDialog('Neues Client-Secret?', 'Das alte Secret gilt sofort nicht mehr; die Anwendung braucht das neue.', 'Erneuern', 'primary'))) return false;
          const r = await post('/oidc/clients/' + encodeURIComponent(c.id) + '/secret'); showSecret(c, r.secret);
        } } : null,
        { label: 'Abbrechen' },
        { label: isNew ? 'Anlegen' : 'Speichern', kind: 'primary', onClick: async () => {
          if (isNew) {
            const r = await post('/oidc/clients', c);
            if (r.secret) showSecret(r.client, r.secret); else { toast('Angelegt', 'ok'); idpTab(body, scope, isAdmin); }
          } else {
            await put('/oidc/clients/' + encodeURIComponent(c.id), c); toast('Gespeichert', 'ok'); idpTab(body, scope, isAdmin);
          }
        } },
      ].filter(Boolean),
    });
    return m;
  }
}
