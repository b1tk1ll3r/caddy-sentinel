import { el, mount, get, post, put, del, qs, panel, tabs, field, toggle, select, linesInput, toast, errToast, confirmDialog, empty, fmtInt, fmtAgo, fmtDateTime, ipLink, roleLabel, modal, copy, untilInput, fmtUnix, fmtUntil, debounce } from '../ui.js';
import { setActions } from '../app.js';

const RESULT = {
  ok: ['ok', 'angemeldet'],
  fail: ['bad', 'fehlgeschlagen'],
  denied: ['warn', 'kein Zugriff'],
  locked: ['bad', 'gesperrt'],
  enroll: ['info', '2FA-Einrichtung'],
  error: ['bad', 'Dienstfehler'],
  change: ['info', 'Kontoänderung'],
  reset: ['', 'Reset angefordert'],
};
const resultBadge = (r) => { const [k, l] = RESULT[r] || ['', r]; return el('span.badge.' + k, null, l); };

export function sourceBadge(src) {
  if (src === 'local') return el('span.badge.info', { title: 'Passwort liegt in Sentinel' }, 'Zugangskonto');
  if (src?.startsWith('oidc:')) return el('span.badge.primary', { title: 'Anmeldung über OAuth/OIDC' }, 'OAuth · ' + src.slice(5));
  return el('span.badge', { title: 'Active Directory / LDAP' }, 'AD');
}

const PRESETS = {
  entra: { name: 'Microsoft', kind: 'oidc', issuer: 'https://login.microsoftonline.com/<TENANT-ID>/v2.0', scopes: ['openid', 'profile', 'email'], username_claim: 'preferred_username', groups_claim: 'groups', hint: 'App-Registrierung in Entra ID: Redirect-URI (Web) eintragen, Client-Secret erzeugen. Gruppen: unter „Tokenkonfiguration“ den Gruppenanspruch hinzufügen – Entra liefert Objekt-IDs (GUIDs), die du in den Policies als Gruppe einträgst.' },
  google: { name: 'Google', kind: 'oidc', issuer: 'https://accounts.google.com', scopes: ['openid', 'profile', 'email'], username_claim: 'email', groups_claim: '', hint: 'Google Cloud Console › APIs & Dienste › Anmeldedaten › OAuth-Client-ID (Webanwendung). Google liefert keine Gruppen – Zugriff über „Erlaubte Domains“ und „Zusätzlich erlaubte Benutzer“ steuern.' },
  keycloak: { name: 'Keycloak', kind: 'oidc', issuer: 'https://keycloak.example.com/realms/<REALM>', scopes: ['openid', 'profile', 'email'], username_claim: 'preferred_username', groups_claim: 'groups', hint: 'Client vom Typ „OpenID Connect“, Client-Authentifizierung an. Für Gruppen einen Mapper „Group Membership“ (Token Claim Name: groups, Full group path aus) anlegen.' },
  authentik: { name: 'Authentik', kind: 'oidc', issuer: 'https://authentik.example.com/application/o/<SLUG>/', scopes: ['openid', 'profile', 'email'], username_claim: 'preferred_username', groups_claim: 'groups', hint: 'Provider „OAuth2/OpenID“, Redirect-URI eintragen. Gruppen liefert Authentik im Claim „groups“.' },
  gitlab: { name: 'GitLab', kind: 'oidc', issuer: 'https://gitlab.com', scopes: ['openid', 'profile', 'email'], username_claim: 'nickname', groups_claim: 'groups', hint: 'Benutzer- oder Gruppen-Einstellungen › Applications, Scopes openid, profile, email.' },
  github: { name: 'GitHub', kind: 'oauth2', auth_url: 'https://github.com/login/oauth/authorize', token_url: 'https://github.com/login/oauth/access_token', userinfo_url: 'https://api.github.com/user', scopes: ['read:user', 'user:email', 'read:org'], username_claim: 'login', groups_claim: 'orgs', hint: 'Settings › Developer settings › OAuth Apps. Als Gruppen gelten die Organisationen des Kontos.' },
  generic: { name: 'OIDC-Anbieter', kind: 'oidc', issuer: '', scopes: ['openid', 'profile', 'email'], username_claim: 'preferred_username', groups_claim: 'groups', hint: 'Jeder Anbieter mit OpenID Connect Discovery (/.well-known/openid-configuration).' },
};

export async function render(root, _p, scope, q) {
  let tab = q.get('tab') || 'overview';
  let userQuery = q.get('q') || '';
  const me = (window.__status || {}).user || {};
  const isAdmin = me.role === 'admin';
  const body = el('div.stack');
  const draw = () => {
    history.replaceState(null, '', '#/access' + (tab === 'overview' ? '' : '?tab=' + tab));
    setActions();
    mount(root, tabs([['overview', 'Übersicht'], ['users', 'Konten'], ['tokens', 'Zugriffstokens'], ['log', 'Anmeldeprotokoll'], ['selfservice', 'Self-Service'], ['oauth', 'OAuth / OIDC'], ['directory', 'Verzeichnis (AD)']], tab, (t) => { tab = t; draw(); }), body);
    ({ overview, users, tokens, log, selfservice, oauth, directory })[tab]().catch(errToast);
  };
  const goto = (t) => (e) => { e?.preventDefault?.(); tab = t; draw(); };

  async function overview() {
    const [ov, recent] = await Promise.all([get('/access/overview', scope.signal), get('/access/log?limit=12', scope.signal)]);
    const st = ov.stats_24h || {};
    const locked = Object.entries(ov.locked || {});
    const bs = ov.by_source || {};
    const methods = [
      ov.directory.enabled ? 'Active Directory' : null,
      (ov.sources || []).includes('local') ? 'Zugangskonten' : null,
      ...(ov.providers || []).filter(p => p.enabled && p.site_login).map(p => p.name),
    ].filter(Boolean);
    mount(body,
      el('p.muted', null, 'Schützt beliebige Sites hinter Caddy mit einer Anmeldung – über Active Directory, lokale Zugangskonten (z. B. für externe Partner) oder OAuth/OIDC-Anbieter wie Microsoft Entra ID, Google oder Keycloak, optional mit zweitem Faktor. Skripte und Dienste nutzen Zugriffstokens. Welche Site eine Anmeldung verlangt, legst du pro Policy im Reiter „Anmeldung“ fest.'),
      !methods.length ? el('div.callout.warn', null, 'Noch keine Anmeldemethode: ', el('a', { href: '#', onclick: goto('directory') }, 'Active Directory verbinden'), ', ', el('a', { href: '#', onclick: goto('users') }, 'ein Zugangskonto anlegen'), ' oder ', el('a', { href: '#', onclick: goto('oauth') }, 'einen OAuth-Anbieter einrichten'), '.')
        : el('div.callout', null, el('b', null, 'Anmeldemethoden: '), methods.join(' · ')),
      el('div.kpis', null,
        el('div.kpi', null, el('div.label', null, 'Geschützte Policies'), el('div.value', null, ov.sites.length)),
        el('div.kpi', null, el('div.label', null, 'Konten'), el('div.value', null, fmtInt(ov.users)), el('div.muted', null, [bs.ldap ? `${bs.ldap} AD` : null, bs.local ? `${bs.local} lokal` : null, bs.oauth ? `${bs.oauth} OAuth` : null].filter(Boolean).join(' · ') || '–', ` · ${fmtInt(ov.enrolled)} mit 2FA`)),
        el('div.kpi', null, el('div.label', null, 'Zugriffstokens'), el('div.value', null, fmtInt(ov.tokens))),
        el('div.kpi.ok', null, el('div.label', null, 'Anmeldungen 24 h'), el('div.value', null, fmtInt(st.ok || 0))),
        el('div.kpi.' + ((st.fail || 0) + (st.locked || 0) ? 'bad' : ''), null, el('div.label', null, 'Fehlversuche 24 h'), el('div.value', null, fmtInt((st.fail || 0) + (st.locked || 0))), el('div.muted', null, `${fmtInt(st.denied || 0)} ohne Berechtigung`))),
      locked.length ? panel('Vorübergehend gesperrte Konten', el('div.table-wrap', null, el('table', null,
        el('tbody', null, locked.map(([u, n]) => el('tr', null, el('td', null, el('b', null, u)), el('td', null, `${n} Fehlversuche`),
          el('td.right', null, isAdmin ? el('button.btn.sm', { onclick: async () => { await post(`/access/users/${encodeURIComponent(u)}/unlock`); toast('Entsperrt', 'ok'); overview(); } }, 'Entsperren') : null))))))) : null,
      panel('Geschützte Sites', ov.sites.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Policy'), el('th', null, 'Hosts'), el('th', null, 'Anmeldung mit'), el('th', null, '2FA'), el('th', null, 'Erlaubt'), el('th', null, 'Sitzung'), el('th', null, 'Ausnahmen'))),
        el('tbody', null, ov.sites.map(x => el('tr', null,
          el('td', null, el('a', { href: '#/policies/' + x.policy + '?tab=login' }, x.name), !x.auth.enabled ? el('div', null, el('small.muted', null, 'Login nur über Pfad-Regeln')) : null, x.auth.sso ? el('span.badge.info', { style: { marginLeft: '6px' } }, 'SSO') : null,
            x.rules?.length ? el('div', null, el('small.muted', null, 'Regeln: ' + x.rules.join(', '))) : null),
          el('td', null, x.hosts?.length ? x.hosts.map(h => el('div.mono', null, h)) : el('span.muted', null, x.default ? 'alle übrigen Hosts' : 'per Direktive „sentinel ' + x.policy + '“')),
          el('td', null, (x.auth.sources || []).length ? x.auth.sources.map(s => el('div', null, sourceLabel(s, ov.providers))) : el('span.muted', null, 'allen Methoden')),
          el('td', null, x.auth.require_totp ? el('span.badge.ok', null, 'Pflicht') : el('span.badge.warn', null, 'nur Passwort'), x.auth.totp_skip_networks?.length ? el('div', null, el('small', null, 'außer ' + x.auth.totp_skip_networks.join(', '))) : null),
          el('td', null, (x.auth.allowed_groups.length || x.auth.allowed_users.length) ? [...x.auth.allowed_groups.map(g => el('span.chip', { style: { margin: '1px' } }, g.replace(/^CN=([^,]+).*/i, '$1'))), ...x.auth.allowed_users.map(u => el('span.chip', { style: { margin: '1px' } }, '👤 ' + u))] : el('span.muted', null, 'alle Konten')),
          el('td', null, x.auth.session_hours + ' h', x.auth.bind_ip ? el('div', null, el('small', null, 'an IP gebunden')) : null),
          el('td', null, [...x.auth.exempt_paths.map(p => el('div.mono', null, p)), ...x.auth.bypass_networks.map(n => el('div.mono', null, n + ' (Netz)'))].length ? [...x.auth.exempt_paths.map(p => el('div.mono', null, p)), ...x.auth.bypass_networks.map(n => el('div.mono', null, n + ' (Netz)'))] : el('span.muted', null, '–'))))))) :
        empty('Noch keine Site geschützt', 'Öffne eine Policy und aktiviere im Reiter „Anmeldung“ den Login.', el('a.btn', { href: '#/policies' }, 'Zu den Policies'))),
      panel('Letzte Anmeldeversuche', logTable(recent), el('button.btn.sm', { onclick: goto('log') }, 'Alle anzeigen')));
  }

  function sourceLabel(s, provs) {
    if (s === 'directory') return 'Active Directory';
    if (s === 'local') return 'Zugangskonten';
    const p = (provs || []).find(x => 'oidc:' + x.id === s);
    return p ? p.name : s;
  }

  function logTable(entries) {
    if (!entries.length) return empty('Noch keine Anmeldeversuche');
    return el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Zeit'), el('th', null, 'Benutzer'), el('th', null, 'Ergebnis'), el('th', null, 'Site'), el('th', null, 'IP'), el('th', null, 'Details'))),
      el('tbody', null, entries.map(e => el('tr', null,
        el('td.nowrap', { title: fmtDateTime(e.ts) }, fmtAgo(e.ts)),
        el('td', null, e.user ? el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); logFilter.user = e.user; tab = 'log'; draw(); } }, e.user) : '–'),
        el('td', null, resultBadge(e.result)),
        el('td', null, el('span.mono', null, e.host), e.policy ? el('div', null, el('small.muted', null, e.policy)) : null),
        el('td', null, e.ip ? ipLink(e.ip) : '–'),
        el('td', null, el('span', { title: e.ua }, e.detail)))))));
  }

  const logFilter = { user: '', result: '' };
  async function log() {
    const entries = await get('/access/log' + qs({ user: logFilter.user, result: logFilter.result, limit: 300 }), scope.signal);
    mount(body, panel('Anmeldeprotokoll', el('div.stack', null,
      el('div.row', null,
        el('input', { type: 'search', placeholder: 'Benutzer', value: logFilter.user, onchange: (e) => { logFilter.user = e.target.value.trim(); log(); } }),
        el('select', { onchange: (e) => { logFilter.result = e.target.value; log(); } }, [['', 'Alle Ergebnisse'], ...Object.entries(RESULT).map(([k, [, l]]) => [k, l])].map(([v, l]) => el('option', { value: v, selected: v === logFilter.result }, l))),
        el('span.grow'), el('span.muted', null, `${entries.length} Einträge`)),
      logTable(entries))));
  }

  // ------------------------------------------------------------ accounts

  function showPassword(user, pw) {
    modal('Passwort für ' + user, el('div.stack', null,
      el('p', null, 'Das Passwort wird nur jetzt angezeigt. Gib es auf sicherem Weg weiter (nicht per unverschlüsselter E-Mail).'),
      el('pre.mono', { style: { fontSize: '18px', textAlign: 'center', userSelect: 'all' } }, pw),
      el('small.muted', null, 'Beim ersten Login richtet das Konto den zweiten Faktor ein, wenn die Site ihn verlangt. Eigenes Passwort, neues Handy und Wiederherstellungscodes verwaltet die Person danach selbst unter /.sentinel/auth/me.')), {
      actions: [{ label: 'Kopieren', onClick: () => { copy(pw); return false; } }, { label: 'Fertig', kind: 'primary' }],
    });
  }

  function accountDialog(u, onDone) {
    const isNew = !u;
    const a = u ? { ...u, groups: [...(u.groups || [])] } : { username: '', display: '', email: '', groups: [], expires: 0, note: '', password: '', must_change: true };
    const local = isNew || a.source === 'local';
    modal(isNew ? 'Zugangskonto anlegen' : 'Konto bearbeiten: ' + a.username, el('div.stack', null,
      isNew ? el('p.muted', { style: { margin: 0 } }, 'Lokale Konten für Personen ohne Domänenkonto – z. B. externe Dienstleister, Partner oder Notfallzugänge. Sie melden sich auf der Anmeldeseite mit Benutzername und Passwort an; der zweite Faktor funktioniert wie bei AD-Konten.') : null,
      el('div.fields', null,
        isNew ? field('Benutzername', el('input', { autocapitalize: 'none', spellcheck: 'false', placeholder: 'max.partner', oninput: (e) => { a.username = e.target.value.trim().toLowerCase(); } })) : null,
        field('Anzeigename', el('input', { value: a.display || '', placeholder: 'Max Partner (Agentur X)', oninput: (e) => { a.display = e.target.value; } })),
        field('E-Mail', el('input', { type: 'email', value: a.email || '', oninput: (e) => { a.email = e.target.value; } })),
        local ? el('div.field.wide', null, el('span', null, 'Gruppen'), linesInput(a.groups, (v) => { a.groups = v; }, { rows: 2, placeholder: 'partner\nwiki-leser' }), el('small', null, 'Frei wählbare Namen – in den Policies unter „Erlaubte Gruppen“ verwendbar, genau wie AD-Gruppen.'))
          : el('div.field.wide', null, el('span', null, 'Gruppen'), el('div', null, (a.groups || []).map(g => el('span.chip', { style: { margin: '1px' } }, g)), el('small', null, ' (kommen aus ' + (a.source === 'ldap' ? 'dem Verzeichnis' : 'dem OAuth-Anbieter') + ')'))),
        isNew ? field('Passwort', el('input', { type: 'password', autocomplete: 'new-password', placeholder: 'leer = sicheres Passwort erzeugen', oninput: (e) => { a.password = e.target.value; } }), 'mindestens 10 Zeichen') : null,
        isNew ? el('div.field', null, el('span', null, 'Erste Anmeldung'), toggle(a.must_change, (v) => { a.must_change = v; }, 'eigenes Passwort festlegen lassen'), el('small', null, 'Empfohlen: dann kennt nur die Person selbst ihr Passwort.')) : null,
        el('label.field', null, el('span', null, 'Zugang endet'), untilInput(a.expires || 0, (v) => { a.expires = v; }), el('small', null, 'Danach kann sich das Konto nicht mehr anmelden, laufende Sitzungen enden.')),
        el('div.field.wide', null, el('span', null, 'Notiz'), el('input', { value: a.note || '', placeholder: 'z. B. Agentur X, Vertrag bis Ende Q4, Ansprechpartner …', oninput: (e) => { a.note = e.target.value; } })))), {
      wide: true,
      actions: [{ label: 'Abbrechen' }, {
        label: isNew ? 'Anlegen' : 'Speichern', kind: 'primary', onClick: async () => {
          if (isNew) {
            const r = await post('/access/accounts', a);
            if (r.password) showPassword(r.username, r.password);
            toast('Konto angelegt', 'ok');
          } else {
            await put('/access/users/' + encodeURIComponent(a.username), a);
            toast('Gespeichert – laufende Sitzungen des Kontos wurden beendet', 'ok');
          }
          onDone();
        },
      }],
    });
  }

  async function users() {
    const [list, toks] = await Promise.all([get('/access/users', scope.signal), isAdmin ? get('/access/tokens', scope.signal) : Promise.resolve([])]);
    const tokCount = {};
    for (const t of toks) tokCount[t.user] = (tokCount[t.user] || 0) + 1;
    let filter = userQuery, src = '';
    const tableBox = el('div');
    const act = async (u, action, title, text, label) => {
      if (title && !await confirmDialog(title, text, label)) return;
      try { await post(`/access/users/${encodeURIComponent(u.username)}/${action}`); toast('Erledigt', 'ok'); users(); } catch (e) { errToast(e); }
    };
    const now = Date.now() / 1000;
    const drawTable = () => {
      const f = filter.toLowerCase();
      const rows = list.filter(u => (!f || `${u.username} ${u.display} ${u.email} ${u.groups.join(' ')} ${u.note || ''}`.toLowerCase().includes(f)) &&
        (!src || (src === 'oauth' ? u.source?.startsWith('oidc:') : (u.source || 'ldap') === src)));
      mount(tableBox, rows.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Konto'), el('th', null, 'Herkunft'), el('th', null, 'Gruppen'), el('th', null, '2FA'), el('th', null, 'Letzte Anmeldung'), el('th.num', null, 'Logins'), isAdmin ? el('th', null, '') : null)),
        el('tbody', null, rows.map(u => el('tr', null,
          el('td', null, el('b', null, u.display || u.username),
            u.disabled ? el('span.badge.bad', { style: { marginLeft: '6px' } }, 'gesperrt') : null,
            u.expires ? el('span.badge.' + (u.expires < now ? 'bad' : 'warn'), { style: { marginLeft: '6px' }, title: 'Zugang endet ' + fmtUnix(u.expires) }, u.expires < now ? 'abgelaufen' : 'bis ' + fmtUnix(u.expires).slice(0, 10)) : null,
            tokCount[u.username] ? el('a.badge', { href: '#', style: { marginLeft: '6px' }, onclick: goto('tokens') }, `${tokCount[u.username]} Token`) : null,
            el('div', null, el('small.mono', null, u.username), u.email ? el('small.muted', null, ' · ' + u.email) : null),
            u.note ? el('div', null, el('small.muted', null, '📝 ' + u.note + (u.created_by ? ' (' + u.created_by + ')' : ''))) : null),
          el('td', null, sourceBadge(u.source)),
          el('td', { style: { maxWidth: '300px' } }, u.groups.slice(0, 5).map(g => el('span.chip', { style: { margin: '1px' } }, g)), u.groups.length > 5 ? el('small.muted', { title: u.groups.join('\n') }, ` +${u.groups.length - 5}`) : null),
          el('td', null, u.totp_enabled ? el('span.badge.ok', null, 'eingerichtet') : el('span.badge', null, 'nicht eingerichtet'),
            u.totp_enabled ? el('div', null, el('small' + (u.recovery_left ? '.muted' : '.warn-text'), { title: 'Wiederherstellungscodes erzeugt die Person auf ihrer Kontoseite' }, u.recovery_left ? `${u.recovery_left} Ersatzcodes` : 'keine Ersatzcodes')) : null,
            u.must_change ? el('div', null, el('span.badge.warn', { title: 'Muss bei der nächsten Anmeldung ein eigenes Passwort festlegen' }, 'Passwort ändern')) : null),
          el('td.nowrap', null, u.last_login ? [fmtAgo(u.last_login * 1000), el('div', null, el('small.muted', null, `${u.last_host} · ${u.last_ip}`))] : '–'),
          el('td.num', null, fmtInt(u.logins)),
          isAdmin ? el('td.nowrap', null,
            el('button.btn.sm', { onclick: () => accountDialog(u, users) }, 'Bearbeiten'), ' ',
            u.source === 'local' ? [el('button.btn.sm', {
              onclick: async () => {
                const o = { must_change: true };
                modal('Neues Passwort für ' + u.username, el('div.stack', null,
                  el('p', { style: { margin: 0 } }, 'Sentinel erzeugt ein neues Passwort. Laufende Sitzungen des Kontos enden.'),
                  toggle(o.must_change, (v) => { o.must_change = v; }, 'bei der nächsten Anmeldung ein eigenes Passwort festlegen lassen'),
                  u.email ? el('small.muted', null, 'Tipp: Ist „Passwort vergessen“ unter Self-Service aktiv, kann ' + u.username + ' das auch selbst per E-Mail erledigen.') : null), {
                  actions: [{ label: 'Abbrechen' }, {
                    label: 'Erzeugen', kind: 'primary', onClick: async () => {
                      const r = await post(`/access/users/${encodeURIComponent(u.username)}/password`, o);
                      showPassword(u.username, r.password); users();
                    },
                  }],
                });
              },
            }, 'Passwort'), ' '] : null,
            el('button.btn.sm', { onclick: () => act(u, 'revoke', 'Sitzungen beenden', `Alle Site-Anmeldungen von ${u.username} werden sofort ungültig.`, 'Beenden') }, 'Abmelden'), ' ',
            u.totp_enabled ? el('button.btn.sm', { onclick: () => act(u, 'reset-totp', '2FA zurücksetzen', `${u.username} richtet beim nächsten Login einen neuen Authenticator ein (z. B. nach Handywechsel). Bestehende Sitzungen enden.`, 'Zurücksetzen') }, '2FA zurücksetzen') : null, ' ',
            u.disabled ? el('button.btn.sm', { onclick: () => act(u, 'enable') }, 'Entsperren') : el('button.btn.sm.danger', { onclick: () => act(u, 'disable', 'Konto sperren', `${u.username} kann sich nicht mehr an geschützten Sites anmelden, auch nicht mit Tokens. Laufende Sitzungen enden sofort.`, 'Sperren') }, 'Sperren'), ' ',
            el('button.btn.sm', {
              onclick: async () => {
                if (!await confirmDialog('Konto entfernen', `${u.username} aus Sentinel entfernen? TOTP-Schlüssel und Zugriffstokens werden gelöscht, laufende Sitzungen enden.` + (u.source === 'local' ? ' Das Zugangskonto ist danach weg.' : ' Beim nächsten Login wird das Konto neu angelegt.'), 'Entfernen')) return;
                try { await del('/access/users/' + encodeURIComponent(u.username)); users(); } catch (e) { errToast(e); }
              },
            }, 'Entfernen')) : null))))) : empty(list.length ? 'Kein Konto passt zum Filter' : 'Noch keine Konten', list.length ? '' : 'AD- und OAuth-Konten erscheinen nach der ersten Anmeldung. Zugangskonten legst du hier an.'));
    };
    drawTable();
    setActions(isAdmin ? el('button.btn.primary', { onclick: () => accountDialog(null, users) }, 'Zugangskonto anlegen') : null);
    mount(body, panel('Konten', el('div.stack', null,
      el('p.muted', { style: { margin: 0 } }, 'Alle Konten, die sich an geschützten Sites anmelden können: AD-Konten (Passwort und Gruppen im Verzeichnis), Zugangskonten (Passwort und Gruppen in Sentinel) und Konten von OAuth-Anbietern. Sentinel speichert dazu den TOTP-Schlüssel und die letzten Anmeldedaten.'),
      el('div.row', null,
        el('input', { type: 'search', placeholder: 'Name, E-Mail, Gruppe, Notiz …', value: filter, style: { minWidth: '240px' }, oninput: debounce((e) => { filter = e.target.value.trim(); userQuery = filter; drawTable(); }, 150) }),
        select([['', 'Alle Herkünfte'], ['ldap', 'Active Directory'], ['local', 'Zugangskonten'], ['oauth', 'OAuth/OIDC']], src, (v) => { src = v; drawTable(); }),
        el('span.grow'), el('span.muted', null, `${list.length} Konten`)),
      tableBox)));
  }

  // ------------------------------------------------------------ self-service

  async function selfservice() {
    const data = await get('/settings', scope.signal);
    const s = data.settings;
    s.self_service ??= { password_reset: false, reset_minutes: 30 };
    const ss = s.self_service;
    const smtpOK = !!(s.smtp?.host && s.smtp?.from);
    let dirty = false;
    const saveBtn = el('button.btn.primary', { disabled: true, onclick: save }, 'Speichern');
    const markDirty = () => { dirty = true; saveBtn.disabled = !isAdmin; };
    setActions(saveBtn);
    async function save() {
      saveBtn.disabled = true;
      try { await put('/settings', s); dirty = false; toast('Self-Service gespeichert', 'ok'); } catch (e) { saveBtn.disabled = false; errToast(e); }
    }
    const li = (t, d) => el('li', null, el('b', null, t), ' – ', d);
    mount(body, el('div.grid.g-main', null,
      el('div.stack', null,
        panel('Kontoseite', el('div.stack', null,
          el('p', { style: { margin: 0 } }, 'Jede geschützte Site hat eine Kontoseite unter ', el('code', null, '/.sentinel/auth/me'), ' (z. B. ', el('span.mono', null, 'https://wiki.firma.de/.sentinel/auth/me'), '). Angemeldete Personen erledigen dort selbst:'),
          el('ul', { style: { margin: 0, paddingLeft: '18px', lineHeight: 1.7 } },
            li('Neues Handy', 'Authenticator-App neu einrichten, bestätigt mit dem aktuellen Code oder einem Wiederherstellungscode'),
            li('Wiederherstellungscodes', 'zehn Einmal-Codes für den Fall, dass das Gerät weg ist; auf der Anmeldeseite unter „Gerät nicht zur Hand?“ nutzbar'),
            li('Passwort ändern', 'nur Zugangskonten; AD-Konten ändern ihr Passwort wie gewohnt in Windows'),
            li('Überall abmelden', 'beendet alle Sitzungen auf allen Geräten und Sites'),
            li('Letzte Aktivität', 'Anmeldungen, Fehlversuche und Änderungen mit IP und Gerät')),
          el('p.muted', { style: { margin: 0 } }, 'Tipp: Verlinke die Kontoseite im Intranet oder in der Anwendung („Mein Konto“). Für Anwendungen gibt es dieselbe Adresse als JSON (Accept: application/json).'))),
        panel('Passwort vergessen (Zugangskonten)', el('div.stack', null,
          el('p.muted', { style: { margin: 0 } }, 'Zeigt auf der Anmeldeseite „Passwort vergessen?“. Zugangskonten mit E-Mail-Adresse bekommen einen Link, der einmal und nur kurz gilt. Ist 2FA eingerichtet, verlangt der Link zusätzlich den Code aus der App – ein Postfach allein reicht also nicht. Danach enden alle Sitzungen des Kontos.'),
          !smtpOK ? el('div.callout.warn', null, 'Dafür muss der E-Mail-Versand eingerichtet sein: ', el('a', { href: '#/settings?tab=alerts' }, 'Einstellungen › Benachrichtigungen › SMTP'), '.') : null,
          el('div.fields', null,
            el('div.field', null, el('span', null, 'Zurücksetzen per E-Mail'), toggle(ss.password_reset, (v) => { ss.password_reset = v; markDirty(); }, ss.password_reset ? 'aktiv' : 'aus')),
            field('Link gültig (Minuten)', el('input', { type: 'number', min: 5, max: 1440, value: ss.reset_minutes || 30, oninput: (e) => { ss.reset_minutes = +e.target.value; markDirty(); } }))),
          el('small.muted', null, 'Die Antwort verrät nie, ob es ein Konto gibt. Pro Konto und IP höchstens drei Anfragen in 15 Minuten.')))),
      el('div.stack', null,
        panel('Was die Administration noch tun muss', el('ul', { style: { margin: 0, paddingLeft: '18px', lineHeight: 1.6 } },
          el('li', null, 'Gerät verloren und keine Wiederherstellungscodes: unter „Konten“ die 2FA zurücksetzen.'),
          el('li', null, 'AD-Konto vergessen: Passwort im Active Directory zurücksetzen.'),
          el('li', null, 'Neue Zugangskonten: mit „eigenes Passwort festlegen lassen“ anlegen – dann kennt die Administration das endgültige Passwort nicht.'))),
        panel('Einstieg für Nutzer', el('ol', { style: { margin: 0, paddingLeft: '18px', lineHeight: 1.6 } },
          el('li', null, 'Erste Anmeldung: Passwort, ggf. eigenes Passwort festlegen, QR-Code scannen.'),
          el('li', null, 'Danach auf der Kontoseite Wiederherstellungscodes erzeugen und sicher ablegen.'),
          el('li', null, 'Handywechsel: Kontoseite › „Neues Gerät oder andere App einrichten“.'))))));
    scope.listen(window, 'beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  }

  // ------------------------------------------------------------ tokens

  async function tokens() {
    const [list, accounts, pols] = await Promise.all([get('/access/tokens', scope.signal), get('/access/users', scope.signal), get('/policies', scope.signal)]);
    const polName = Object.fromEntries(pols.policies.map(p => [p.id, p.name]));
    const now = Date.now() / 1000;
    const create = () => {
      const t = { user: accounts.find(a => a.source === 'local')?.username || accounts[0]?.username || '', name: '', policies: [], expires: Math.floor(now) + 365 * 86400, note: '' };
      const polBox = el('div.chips');
      const drawPols = () => mount(polBox, pols.policies.filter(p => p.auth?.enabled || (p.path_rules || []).some(r => r.auth === 'on')).map(p => {
        const on = t.policies.includes(p.id);
        return el('span.chip' + (on ? '.on' : ''), { role: 'checkbox', tabindex: 0, 'aria-checked': on ? 'true' : 'false', onclick: () => { t.policies = on ? t.policies.filter(x => x !== p.id) : [...t.policies, p.id]; drawPols(); } }, on ? '✓ ' : '', p.name);
      }));
      drawPols();
      modal('Zugriffstoken erstellen', el('div.stack', null,
        el('p.muted', { style: { margin: 0 } }, 'Für Skripte, Monitoring oder andere Dienste, die eine geschützte Site ohne Anmeldeseite erreichen müssen. Das Token handelt im Namen eines Kontos: dessen Gruppen entscheiden über den Zugriff, ein gesperrtes oder abgelaufenes Konto macht auch das Token ungültig. Login und zweiter Faktor entfallen.'),
        el('div.fields', null,
          field('Konto', select(accounts.map(a => [a.username, `${a.display || a.username} (${a.username})`]), t.user, (v) => { t.user = v; }), accounts.length ? 'Tipp: ein eigenes Zugangskonto pro Dienst, z. B. „svc-backup“' : 'Erst ein Konto anlegen'),
          field('Name', el('input', { placeholder: 'z. B. Backup-Skript, Uptime-Kuma', oninput: (e) => { t.name = e.target.value; } })),
          el('div.field.wide', null, el('span', null, 'Nur für diese Sites'), polBox, el('small', null, 'Keine Auswahl = alle Sites, auf die das Konto Zugriff hat.')),
          el('label.field', null, el('span', null, 'Läuft ab'), untilInput(t.expires, (v) => { t.expires = v; })),
          field('Notiz', el('input', { placeholder: 'Wer nutzt das Token, wo ist es hinterlegt?', oninput: (e) => { t.note = e.target.value; } })))), {
        wide: true,
        actions: [{ label: 'Abbrechen' }, {
          label: 'Erstellen', kind: 'primary', onClick: async () => {
            const r = await post('/access/tokens', t);
            tokens();
            modal('Zugriffstoken erstellt', el('div.stack', null,
              el('p', null, 'Das Token wird nur jetzt angezeigt – Sentinel speichert nur eine Prüfsumme. Caddy kennt es in wenigen Sekunden.'),
              el('pre.mono', { style: { userSelect: 'all', whiteSpace: 'pre-wrap' } }, r.token),
              el('p.muted', null, 'So verwenden:'),
              el('pre.mono', { style: { whiteSpace: 'pre-wrap' } }, `curl -H "Authorization: Bearer ${r.token}" https://<site>/…`)), {
              actions: [{ label: 'Kopieren', onClick: () => { copy(r.token); return false; } }, { label: 'Fertig', kind: 'primary' }],
            });
          },
        }],
      });
    };
    setActions(isAdmin ? el('button.btn.primary', { onclick: create, disabled: !accounts.length }, 'Token erstellen') : null);
    mount(body, panel('Zugriffstokens für geschützte Sites', el('div.stack', null,
      el('p.muted', { style: { margin: 0 } }, 'Ein Token wird als „Authorization: Bearer sst_…“ an die Site geschickt. Sentinel prüft es direkt in Caddy (ohne Umweg über das Panel) und entfernt den Header, bevor die Anfrage weitergeht. Andere Bearer-Header der Anwendung bleiben unberührt.'),
      list.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Name'), el('th', null, 'Konto'), el('th', null, 'Token'), el('th', null, 'Sites'), el('th', null, 'Läuft ab'), el('th', null, 'Erstellt'), el('th'))),
        el('tbody', null, list.map(t => el('tr', null,
          el('td', null, el('b', null, t.name), t.note ? el('div', null, el('small.muted', null, '📝 ' + t.note)) : null),
          el('td', null, t.user),
          el('td.mono', null, t.prefix + '…'),
          el('td', null, t.policies.length ? t.policies.map(p => el('span.chip', { style: { margin: '1px' } }, polName[p] || p)) : el('span.muted', null, 'alle erlaubten')),
          el('td.nowrap', null, t.expires ? el('span' + (t.expires < now ? '.bad-text' : ''), { title: fmtUnix(t.expires) }, fmtUntil(t.expires)) : 'nie'),
          el('td.nowrap.muted', null, fmtUnix(t.created), el('div', null, el('small', null, t.created_by))),
          el('td.right', null, isAdmin ? el('button.btn.sm.danger', { onclick: async () => { if (!await confirmDialog('Token widerrufen', `„${t.name}“ ist in wenigen Sekunden auf allen Caddy-Servern ungültig.`, 'Widerrufen')) return; try { await del('/access/tokens/' + t.id); tokens(); } catch (e) { errToast(e); } } }, 'Widerrufen') : null)))))) :
        empty('Noch keine Zugriffstokens', 'Tokens gehören immer zu einem Konto – lege dafür am besten ein Zugangskonto pro Dienst an.'))));
  }

  // ------------------------------------------------------------ OAuth / OIDC

  async function oauth() {
    const data = await get('/settings', scope.signal);
    const s = data.settings;
    s.oauth ??= [];
    let dirty = false;
    const saveBtn = el('button.btn.primary', { disabled: true, onclick: save }, 'Speichern');
    const markDirty = () => { dirty = true; saveBtn.disabled = !isAdmin; };
    setActions(saveBtn);
    async function save() {
      saveBtn.disabled = true;
      try { await put('/settings', s); dirty = false; toast('Anbieter gespeichert', 'ok'); oauth(); } catch (e) { saveBtn.disabled = false; errToast(e); }
    }
    const redirect = () => (s.panel_url || '').replace(/\/$/, '') + '/oauth/callback';
    const list = el('div.stack');
    const card = (p, i) => {
      const pre = PRESETS[p.preset] || PRESETS.generic;
      const inp = (k, attrs = {}) => el('input' + (attrs.mono ? '.mono' : ''), { value: p[k] || '', placeholder: attrs.placeholder || '', oninput: (e) => { p[k] = e.target.value.trim(); markDirty(); } });
      const lines = (k, ph) => linesInput(p[k] || [], (v) => { p[k] = v; markDirty(); }, { rows: 2, placeholder: ph });
      const testOut = el('div');
      return el('div.rule', null,
        el('div.rule-head', null, toggle(p.enabled, (v) => { p.enabled = v; markDirty(); }),
          el('input.name', { value: p.name, oninput: (e) => { p.name = e.target.value; markDirty(); } }),
          p.id ? el('small.mono.muted', null, p.id) : null, el('span.grow'),
          el('button.btn.sm', {
            onclick: async () => {
              mount(testOut, el('span.muted', null, 'Prüfe …'));
              try {
                const r = await post('/access/oauth/test', p);
                mount(testOut, r.ok ? el('div.callout.ok', null, 'Erreichbar. Anmeldung: ', el('code', null, r.endpoints.authorization_endpoint), ' · Token: ', el('code', null, r.endpoints.token_endpoint)) : el('div.callout.bad', null, r.error));
              } catch (e) { mount(testOut, el('div.callout.bad', null, e.message)); }
            },
          }, 'Verbindung testen'),
          el('button.icon-btn', { title: 'Entfernen', onclick: () => { s.oauth.splice(i, 1); markDirty(); drawList(); } }, '✕')),
        el('div.rule-body', null, el('div.stack', null,
          el('small.muted', null, pre.hint),
          el('div.fields', null,
            p.kind === 'oauth2'
              ? [field('Autorisierungs-URL', inp('auth_url', { mono: true })), field('Token-URL', inp('token_url', { mono: true })), field('Userinfo-URL', inp('userinfo_url', { mono: true }))]
              : el('div.field.wide', null, el('span', null, 'Issuer-URL'), inp('issuer', { mono: true, placeholder: pre.issuer }), el('small', null, 'Die Adresse, unter der /.well-known/openid-configuration liegt.')),
            field('Client-ID', inp('client_id', { mono: true })),
            field('Client-Secret', el('input', { type: 'password', autocomplete: 'new-password', placeholder: data.secrets_set?.['oauth_' + p.id] ? '•••••• gespeichert – leer lassen zum Beibehalten' : '', oninput: (e) => { p.client_secret = e.target.value; markDirty(); } })),
            field('Scopes', el('input.mono', { value: (p.scopes || []).join(' '), oninput: (e) => { p.scopes = e.target.value.split(/\s+/).filter(Boolean); markDirty(); } })),
            field('Claim für den Benutzernamen', inp('username_claim', { mono: true, placeholder: 'preferred_username' })),
            field('Claim für Gruppen', inp('groups_claim', { mono: true, placeholder: 'groups' })),
            el('div.field', null, el('span', null, 'Erlaubte E-Mail-Domains'), lines('allowed_domains', 'firma.de'), el('small', null, 'leer = alle'))),
          el('div.row', { style: { gap: '18px', flexWrap: 'wrap' } },
            toggle(p.site_login, (v) => { p.site_login = v; markDirty(); }, 'auf Anmeldeseiten geschützter Sites anbieten'),
            toggle(p.trust_mfa, (v) => { p.trust_mfa = v; markDirty(); }, 'MFA beim Anbieter – kein eigener TOTP-Code'),
            toggle(p.panel_login, (v) => { p.panel_login = v; markDirty(); drawList(); }, 'Anmeldung an diesem Panel erlauben')),
          p.panel_login ? el('div.fields', null,
            field('Administratoren-Gruppen', lines('panel_admin_groups', 'it-admins')),
            field('Bearbeiter-Gruppen', lines('panel_editor_groups', 'web-team')),
            field('Support-Gruppen', lines('panel_support_groups', 'it-support')),
            field('Leser-Gruppen', lines('panel_viewer_groups', 'it-leitung'))) : null,
          testOut)));
    };
    const drawList = () => mount(list, s.oauth.length ? s.oauth.map(card) : el('p.muted', null, 'Noch kein Anbieter.'));
    drawList();
    const addPreset = (k) => { const pr = PRESETS[k]; s.oauth.push({ id: '', name: pr.name, enabled: true, preset: k, kind: pr.kind, issuer: pr.issuer || '', auth_url: pr.auth_url || '', token_url: pr.token_url || '', userinfo_url: pr.userinfo_url || '', client_id: '', scopes: pr.scopes, username_claim: pr.username_claim, groups_claim: pr.groups_claim, allowed_domains: [], site_login: true, panel_login: false, trust_mfa: k === 'entra', panel_admin_groups: [], panel_editor_groups: [], panel_support_groups: [], panel_viewer_groups: [] }); markDirty(); drawList(); };
    mount(body,
      panel('Redirect-URI', el('div.stack', null,
        el('p.muted', { style: { margin: 0 } }, 'Das Panel ist der OAuth-Client für alle Sites – beim Anbieter muss nur diese eine Adresse als Redirect-URI eingetragen werden. Der Browser kommt nach der Anmeldung über das Panel zur Site zurück; das Panel muss dafür von den Benutzern erreichbar sein.'),
        el('div.fields', null,
          el('div.field.wide', null, el('span', null, 'Öffentliche Panel-Adresse'), el('input.mono', { value: s.panel_url || '', placeholder: 'https://sentinel.firma.de', oninput: (e) => { s.panel_url = e.target.value.trim(); markDirty(); mount(ru, redirect()); } }), el('small', null, 'Wird auch für Links und Knöpfe in Benachrichtigungen verwendet.'))),
        el('div.row', null, el('b', null, 'Redirect-URI:'), el('code'), el('button.btn.sm', { onclick: () => copy(redirect()) }, 'Kopieren')))),
      panel('Anbieter', el('div.stack', null, list,
        el('div.row', null, el('b', null, 'Hinzufügen:'), Object.entries(PRESETS).map(([k, pr]) => el('button.btn.sm', { onclick: () => addPreset(k) }, k === 'entra' ? 'Microsoft Entra ID' : k === 'generic' ? 'Anderer (OIDC)' : pr.name))))));
    const ru = body.querySelector('code');
    mount(ru, redirect());
    scope.listen(window, 'beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  }

  async function directory() {
    const data = await get('/settings', scope.signal);
    const s = data.settings;
    const d = s.directory;
    s.sso ??= { enabled: false, domain: '' };
    d.urls ??= []; d.panel_admin_groups ??= []; d.panel_viewer_groups ??= []; d.panel_editor_groups ??= []; d.panel_support_groups ??= [];
    let dirty = false;
    const saveBtn = el('button.btn.primary', { disabled: true, onclick: save }, 'Speichern');
    const markDirty = () => { dirty = true; saveBtn.disabled = !isAdmin; };
    setActions(saveBtn);
    async function save() {
      saveBtn.disabled = true;
      try { await put('/settings', s); dirty = false; toast('Verzeichnis gespeichert', 'ok'); } catch (e) { saveBtn.disabled = false; errToast(e); }
    }
    const inp = (k, attrs = {}) => el('input', { value: d[k] ?? '', ...attrs, oninput: (e) => { d[k] = attrs.type === 'number' ? +e.target.value : e.target.value; markDirty(); } });
    const result = el('div');
    const filterIn = inp('user_filter', { class: 'mono' });
    let tUser, tPw;
    async function test(mode) {
      mount(result, el('span.muted', null, 'Prüfe …'));
      try {
        const r = await post('/access/test', { directory: d, mode, username: tUser.value, password: tPw.value });
        if (!r.ok) return mount(result, el('div.callout.bad', null, r.error, el('small', null, ` (${r.ms} ms)`)));
        if (!r.user) return mount(result, el('div.callout.ok', null, `Verbindung und Dienstkonto in Ordnung – Base-DN „${r.base_dn}“ gefunden (${r.ms} ms).`));
        const u = r.user;
        mount(result, el('div.callout.ok', null, el('div.stack', { style: { gap: '6px' } },
          el('b', null, mode === 'login' ? 'Anmeldung erfolgreich' : 'Benutzer gefunden', ` (${r.ms} ms)`),
          el('dl.kv', null,
            el('dt', null, 'Konto'), el('dd', null, `${u.display || ''} (${u.username})`),
            el('dt', null, 'DN'), el('dd.mono', null, u.dn),
            u.email ? [el('dt', null, 'E-Mail'), el('dd', null, u.email)] : null,
            el('dt', null, 'Gruppen'), el('dd', null, u.groups.length ? u.groups.map(g => el('span.chip', { style: { margin: '1px' } }, g)) : '–'),
            el('dt', null, 'Darf auf'), el('dd', null, (r.sites_allowed || []).join(', ') || '–'),
            r.sites_denied?.length ? [el('dt', null, 'Kein Zugriff'), el('dd', null, r.sites_denied.join(', '))] : null,
            r.panel_role !== undefined ? [el('dt', null, 'Panel'), el('dd', null, r.panel_role ? roleLabel(r.panel_role) : 'kein Zugriff')] : null))));
      } catch (e) { mount(result, el('div.callout.bad', null, e.message)); }
    }
    mount(body,
      el('div.grid.g-main', null,
        el('div.stack', null,
          panel('Active Directory / LDAP', el('div.stack', null,
            el('div.fields', null,
              el('div.field', null, el('span', null, 'Verzeichnis'), toggle(d.enabled, (v) => { d.enabled = v; markDirty(); }, d.enabled ? 'aktiv' : 'aus')),
              el('div.field.wide', null, el('span', null, 'Server'), linesInput(d.urls, (v) => { d.urls = v; markDirty(); }, { rows: 2, placeholder: 'ldaps://dc1.firma.local\nldaps://dc2.firma.local' }),
                el('small', null, 'Ein Server pro Zeile, der nächste dient als Ausfallreserve. Empfohlen: ldaps:// (Port 636). Für ldap:// unbedingt StartTLS aktivieren.')),
              el('div.field', null, el('span', null, 'StartTLS'), toggle(d.start_tls, (v) => { d.start_tls = v; markDirty(); }, 'bei ldap:// verschlüsseln')),
              el('div.field', null, el('span', null, 'Zertifikat'), toggle(d.skip_verify, (v) => { d.skip_verify = v; markDirty(); }, 'nicht prüfen (nur zum Testen)')),
              el('div.field.wide', null, el('span', null, 'CA-Zertifikat der Domänencontroller'), el('textarea.mono', { rows: 3, placeholder: '-----BEGIN CERTIFICATE-----\n… (optional, PEM der AD-Zertifizierungsstelle)', value: d.ca_cert || '', oninput: (e) => { d.ca_cert = e.target.value; markDirty(); } }),
                el('small', null, 'Nötig, wenn die DCs Zertifikate einer internen CA nutzen, der der Server nicht vertraut. Tipp: Root der internen Caddy-CA findest du unter Interne CA.')),
              field('Dienstkonto (Bind-DN)', inp('bind_dn', { class: 'mono', placeholder: 'CN=svc-sentinel,OU=Dienste,DC=firma,DC=local' }), 'Lesekonto für die Benutzersuche, auch als svc-sentinel@firma.local möglich.'),
              field('Passwort des Dienstkontos', el('input', { type: 'password', autocomplete: 'new-password', placeholder: data.secrets_set?.directory_bind_password ? '•••••• gespeichert – leer lassen zum Beibehalten' : '', oninput: (e) => { d.bind_password = e.target.value; markDirty(); } })),
              el('div.field.wide', null, el('span', null, 'Base-DN'), inp('base_dn', { class: 'mono', placeholder: 'DC=firma,DC=local' })),
              el('div.field.wide', null, el('span', null, 'Benutzerfilter'), filterIn,
                el('small', null, '{user} = eingegebener Name ohne Domäne (aus FIRMA\\max oder max@firma.local), {input} = Eingabe wie getippt. Der Standard findet aktive Konten über sAMAccountName oder UPN. ',
                  el('a', { href: '#', onclick: (e) => { e.preventDefault(); d.user_filter = filterIn.value = data.defaults.directory.user_filter; markDirty(); } }, 'Standard wiederherstellen'))),
              field('Attribut Benutzername', inp('user_attr', { placeholder: 'sAMAccountName' })),
              field('Attribut Anzeigename', inp('display_attr', { placeholder: 'displayName' })),
              field('Attribut E-Mail', inp('mail_attr', { placeholder: 'mail' })),
              el('div.field', null, el('span', null, 'Gruppen'), toggle(d.nested_groups, (v) => { d.nested_groups = v; markDirty(); }, 'verschachtelte Gruppen auflösen (AD)')),
              field('Timeout (s)', inp('timeout_s', { type: 'number', min: 1, max: 60 }))))),
          panel('Zweiter Faktor & Schutz', el('div.fields', null,
            field('Name in der Authenticator-App', inp('totp_issuer', { placeholder: 'Caddy Sentinel' })),
            field('Sperre nach Fehlversuchen', inp('lockout_attempts', { type: 'number', min: 1, max: 50 }), 'pro Konto; pro IP gilt das Vierfache'),
            field('Sperrdauer (Minuten)', inp('lockout_minutes', { type: 'number', min: 1, max: 1440 })))),
          panel('Single Sign-on', el('div.stack', null,
            el('p.muted', null, 'Einmal anmelden, alle Sites nutzen: Policies mit aktiviertem SSO teilen sich ein Sitzungs-Cookie für die Domain und alle Subdomains (z. B. wiki.firma.local und git.firma.local unter firma.local). Abmelden gilt dann ebenfalls überall. Gruppen und zweiter Faktor werden trotzdem pro Site geprüft – fehlt der Code für eine strengere Site, fragt Sentinel ihn nach.'),
            el('div.fields', null,
              el('div.field', null, el('span', null, 'SSO'), toggle(s.sso.enabled, (v) => { s.sso.enabled = v; markDirty(); }, 'aktiv')),
              field('Domain', el('input', { value: s.sso.domain || '', placeholder: 'firma.local', oninput: (e) => { s.sso.domain = e.target.value; markDirty(); } }), 'Alle beteiligten Sites müssen darunter liegen und HTTPS nutzen.')))),
          panel('Panel-Anmeldung mit AD', el('div.stack', null,
            el('p.muted', null, 'Erlaubt die Anmeldung an diesem Panel mit Domänenkonten. Die Rolle ergibt sich bei jedem Login aus den Gruppen. Lokale Konten funktionieren weiterhin (Notfallzugang).'),
            el('div.fields', null,
              el('div.field', null, el('span', null, 'Panel-Login'), toggle(d.panel_login, (v) => { d.panel_login = v; markDirty(); }, 'Verzeichniskonten zulassen')),
              el('div.field', null, el('span', null, '2FA'), toggle(d.panel_require_totp, (v) => { d.panel_require_totp = v; markDirty(); }, 'für AD-Konten verlangen')),
              field('Administratoren-Gruppen', linesInput(d.panel_admin_groups, (v) => { d.panel_admin_groups = v; markDirty(); }, { rows: 2, placeholder: 'IT-Admins' })),
              field('Bearbeiter-Gruppen', linesInput(d.panel_editor_groups, (v) => { d.panel_editor_groups = v; markDirty(); }, { rows: 2, placeholder: 'Web-Team' }), 'Caddyfile, Policies, Regelsätze, Feeds, Monitore, Sperren'),
              field('Support-Gruppen', linesInput(d.panel_support_groups, (v) => { d.panel_support_groups = v; markDirty(); }, { rows: 2, placeholder: 'IT-Support' }), 'alles sehen, Sperren aufheben/setzen'),
              field('Leser-Gruppen', linesInput(d.panel_viewer_groups, (v) => { d.panel_viewer_groups = v; markDirty(); }, { rows: 2, placeholder: 'IT-Leitung' })))))),
        el('div.stack', null,
          panel('Verbindung testen', el('div.stack', null,
            el('p.muted', null, 'Testet die Einstellungen aus dem Formular – auch ungespeichert.'),
            el('button.btn', { onclick: () => test('connection'), disabled: !isAdmin }, 'Verbindung & Dienstkonto prüfen'),
            field('Benutzer', tUser = el('input', { placeholder: 'max.mustermann oder FIRMA\\max', autocomplete: 'off' })),
            field('Passwort (nur für Anmeldetest)', tPw = el('input', { type: 'password', autocomplete: 'new-password' })),
            el('div.row', null,
              el('button.btn', { onclick: () => test('user'), disabled: !isAdmin }, 'Benutzer suchen'),
              el('button.btn', { onclick: () => test('login'), disabled: !isAdmin }, 'Anmeldung testen')),
            result)),
          panel('So funktioniert es', el('ol', { style: { margin: 0, paddingLeft: '18px', lineHeight: 1.6 } },
            el('li', null, 'Verzeichnis hier verbinden und testen.'),
            el('li', null, 'In der Policy der Site den Reiter „Anmeldung“ aktivieren, Gruppen eintragen.'),
            el('li', null, 'Beim ersten Besuch meldet sich der Benutzer mit seinem Domänenkonto an und scannt den QR-Code für die Authenticator-App.'),
            el('li', null, 'Danach: Passwort + 6-stelliger Code. Neues Handy? Auf der Kontoseite /.sentinel/auth/me selbst umziehen – oder unter „Konten“ die 2FA zurücksetzen.'))))));
    scope.listen(window, 'beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  }

  draw();
}
