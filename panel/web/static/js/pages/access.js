import { el, mount, get, post, put, del, qs, panel, tabs, field, toggle, linesInput, toast, errToast, confirmDialog, empty, fmtInt, fmtAgo, fmtDateTime, ipLink, roleLabel } from '../ui.js';
import { setActions } from '../app.js';

const RESULT = {
  ok: ['ok', 'angemeldet'],
  fail: ['bad', 'fehlgeschlagen'],
  denied: ['warn', 'kein Zugriff'],
  locked: ['bad', 'gesperrt'],
  enroll: ['info', '2FA-Einrichtung'],
  error: ['bad', 'Verzeichnisfehler'],
};
const resultBadge = (r) => { const [k, l] = RESULT[r] || ['', r]; return el('span.badge.' + k, null, l); };

export async function render(root, _p, scope, q) {
  let tab = q.get('tab') || 'overview';
  const me = (window.__status || {}).user || {};
  const isAdmin = me.role === 'admin';
  const body = el('div.stack');
  const draw = () => {
    history.replaceState(null, '', '#/access' + (tab === 'overview' ? '' : '?tab=' + tab));
    setActions();
    mount(root, tabs([['overview', 'Übersicht'], ['users', 'Benutzer'], ['log', 'Anmeldeprotokoll'], ['directory', 'Verzeichnis']], tab, (t) => { tab = t; draw(); }), body);
    ({ overview, users, log, directory })[tab]().catch(errToast);
  };

  async function overview() {
    const [ov, recent] = await Promise.all([get('/access/overview', scope.signal), get('/access/log?limit=12', scope.signal)]);
    const st = ov.stats_24h || {};
    const locked = Object.entries(ov.locked || {});
    mount(body,
      el('p.muted', null, 'Schützt beliebige Sites hinter Caddy mit einer Anmeldung über Active Directory (LDAP) und optional einem zweiten Faktor (TOTP). Welche Site eine Anmeldung verlangt, legst du pro Policy im Reiter „Anmeldung“ fest.'),
      !ov.directory.enabled ? el('div.callout.warn', null, 'Noch kein Verzeichnis eingerichtet. ', el('a', { href: '#/access?tab=directory', onclick: (e) => { e.preventDefault(); tab = 'directory'; draw(); } }, 'Jetzt Active Directory verbinden'), '.') : null,
      el('div.kpis', null,
        el('div.kpi', null, el('div.label', null, 'Geschützte Policies'), el('div.value', null, ov.sites.length)),
        el('div.kpi', null, el('div.label', null, 'Bekannte Konten'), el('div.value', null, fmtInt(ov.users)), el('div.muted', null, `${fmtInt(ov.enrolled)} mit 2FA`)),
        el('div.kpi.ok', null, el('div.label', null, 'Anmeldungen 24 h'), el('div.value', null, fmtInt(st.ok || 0))),
        el('div.kpi.' + ((st.fail || 0) + (st.locked || 0) ? 'bad' : ''), null, el('div.label', null, 'Fehlversuche 24 h'), el('div.value', null, fmtInt((st.fail || 0) + (st.locked || 0))), el('div.muted', null, `${fmtInt(st.denied || 0)} ohne Berechtigung`))),
      locked.length ? panel('Vorübergehend gesperrte Konten', el('div.table-wrap', null, el('table', null,
        el('tbody', null, locked.map(([u, n]) => el('tr', null, el('td', null, el('b', null, u)), el('td', null, `${n} Fehlversuche`),
          el('td.right', null, isAdmin ? el('button.btn.sm', { onclick: async () => { await post(`/access/users/${encodeURIComponent(u)}/unlock`); toast('Entsperrt', 'ok'); overview(); } }, 'Entsperren') : null))))))) : null,
      panel('Geschützte Sites', ov.sites.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Policy'), el('th', null, 'Hosts'), el('th', null, '2FA'), el('th', null, 'Erlaubt'), el('th', null, 'Sitzung'), el('th', null, 'Ausnahmen'))),
        el('tbody', null, ov.sites.map(x => el('tr', null,
          el('td', null, el('a', { href: '#/policies/' + x.policy }, x.name), !x.auth.enabled ? el('div', null, el('small.muted', null, 'Login nur über Pfad-Regeln')) : null, x.auth.sso ? el('span.badge.info', { style: { marginLeft: '6px' } }, 'SSO') : null,
            x.rules?.length ? el('div', null, el('small.muted', null, 'Regeln: ' + x.rules.join(', '))) : null),
          el('td', null, x.hosts?.length ? x.hosts.map(h => el('div.mono', null, h)) : el('span.muted', null, x.default ? 'alle übrigen Hosts' : 'per Direktive „sentinel ' + x.policy + '“')),
          el('td', null, x.auth.require_totp ? el('span.badge.ok', null, 'Pflicht') : el('span.badge.warn', null, 'nur Passwort'), x.auth.totp_skip_networks?.length ? el('div', null, el('small', null, 'außer ' + x.auth.totp_skip_networks.join(', '))) : null),
          el('td', null, (x.auth.allowed_groups.length || x.auth.allowed_users.length) ? [...x.auth.allowed_groups.map(g => el('span.chip', { style: { margin: '1px' } }, g.replace(/^CN=([^,]+).*/i, '$1'))), ...x.auth.allowed_users.map(u => el('span.chip', { style: { margin: '1px' } }, '👤 ' + u))] : el('span.muted', null, 'alle Verzeichniskonten')),
          el('td', null, x.auth.session_hours + ' h', x.auth.bind_ip ? el('div', null, el('small', null, 'an IP gebunden')) : null),
          el('td', null, [...x.auth.exempt_paths.map(p => el('div.mono', null, p)), ...x.auth.bypass_networks.map(n => el('div.mono', null, n + ' (Netz)'))].length ? [...x.auth.exempt_paths.map(p => el('div.mono', null, p)), ...x.auth.bypass_networks.map(n => el('div.mono', null, n + ' (Netz)'))] : el('span.muted', null, '–'))))))) :
        empty('Noch keine Site geschützt', 'Öffne eine Policy und aktiviere im Reiter „Anmeldung“ den Login.', el('a.btn', { href: '#/policies' }, 'Zu den Policies'))),
      panel('Letzte Anmeldeversuche', logTable(recent), el('button.btn.sm', { onclick: () => { tab = 'log'; draw(); } }, 'Alle anzeigen')));
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

  async function users() {
    const list = await get('/access/users', scope.signal);
    const act = async (u, action, title, text, label) => {
      if (title && !await confirmDialog(title, text, label)) return;
      try { await post(`/access/users/${encodeURIComponent(u.username)}/${action}`); toast('Erledigt', 'ok'); users(); } catch (e) { errToast(e); }
    };
    mount(body, panel('Verzeichniskonten', el('div.stack', null,
      el('p.muted', null, 'Konten erscheinen hier nach der ersten erfolgreichen Anmeldung. Passwörter und Gruppen bleiben im Active Directory; Sentinel speichert nur den TOTP-Schlüssel und die letzten Anmeldedaten.'),
      list.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Konto'), el('th', null, 'Gruppen'), el('th', null, '2FA'), el('th', null, 'Letzte Anmeldung'), el('th.num', null, 'Logins'), isAdmin ? el('th', null, '') : null)),
        el('tbody', null, list.map(u => el('tr', null,
          el('td', null, el('b', null, u.display || u.username), u.disabled ? el('span.badge.bad', { style: { marginLeft: '6px' } }, 'gesperrt') : null,
            el('div', null, el('small.mono', null, u.username), u.email ? el('small.muted', null, ' · ' + u.email) : null)),
          el('td', { style: { maxWidth: '320px' } }, u.groups.slice(0, 5).map(g => el('span.chip', { style: { margin: '1px' } }, g)), u.groups.length > 5 ? el('small.muted', { title: u.groups.join('\n') }, ` +${u.groups.length - 5}`) : null),
          el('td', null, u.totp_enabled ? el('span.badge.ok', null, 'eingerichtet') : el('span.badge', null, 'nicht eingerichtet')),
          el('td.nowrap', null, u.last_login ? [fmtAgo(u.last_login * 1000), el('div', null, el('small.muted', null, `${u.last_host} · ${u.last_ip}`))] : '–'),
          el('td.num', null, fmtInt(u.logins)),
          isAdmin ? el('td.nowrap', null,
            el('button.btn.sm', { onclick: () => act(u, 'revoke', 'Sitzungen beenden', `Alle Site-Anmeldungen von ${u.username} werden sofort ungültig.`, 'Beenden') }, 'Abmelden'), ' ',
            u.totp_enabled ? el('button.btn.sm', { onclick: () => act(u, 'reset-totp', '2FA zurücksetzen', `${u.username} richtet beim nächsten Login einen neuen Authenticator ein (z. B. nach Handywechsel). Bestehende Sitzungen enden.`, 'Zurücksetzen') }, '2FA zurücksetzen') : null, ' ',
            u.disabled ? el('button.btn.sm', { onclick: () => act(u, 'enable') }, 'Entsperren') : el('button.btn.sm.danger', { onclick: () => act(u, 'disable', 'Konto sperren', `${u.username} kann sich nicht mehr an geschützten Sites anmelden, auch wenn das AD-Konto aktiv ist. Laufende Sitzungen enden sofort.`, 'Sperren') }, 'Sperren'), ' ',
            el('button.btn.sm', {
              onclick: async () => {
                if (!await confirmDialog('Konto entfernen', `${u.username} aus Sentinel entfernen? Der TOTP-Schlüssel wird gelöscht, laufende Sitzungen enden. Beim nächsten Login wird das Konto neu angelegt.`, 'Entfernen')) return;
                try { await del('/access/users/' + encodeURIComponent(u.username)); users(); } catch (e) { errToast(e); }
              },
            }, 'Entfernen')) : null))))) : empty('Noch keine Anmeldungen', 'Sobald sich jemand an einer geschützten Site anmeldet, erscheint das Konto hier.'))));
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
            el('li', null, 'Danach: Passwort + 6-stelliger Code. Handy verloren? Unter „Benutzer“ die 2FA zurücksetzen.'))))));
    scope.listen(window, 'beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  }

  draw();
}
