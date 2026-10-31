// Caddy instances: the local Caddy plus further servers that connect through
// their Sentinel agent (each with an own token).
import { el, mount, get, post, put, del, panel, field, toast, errToast, confirmDialog, modal, copy, fmtAgo, instState, empty } from '../ui.js';
import { setActions } from '../app.js';

const COLORS = ['#2d47c9', '#0e7490', '#b45309', '#7c3aed', '#be185d', '#15803d', '#c2410c', '#475569'];
const MODE = {
  local: ['Lokal', 'Direkter Zugriff auf Admin-API und Caddyfile'],
  full: ['Fernverwaltung', 'Caddyfile über den Agent bearbeitbar'],
  read: ['Nur lesen', 'Konfiguration, Backends, Zertifikate sichtbar – Caddyfile nicht bearbeitbar'],
  off: ['Aus', 'Agent erlaubt keinen Konfigurationszugriff'],
};

export async function render(root, _p, scope) {
  const me = window.__status?.user || {};
  const isAdmin = !me.role || me.role === 'admin';
  setActions(isAdmin ? el('button.btn.primary', { onclick: create }, 'Instanz hinzufügen') : null);

  async function load() {
    const { instances } = await get('/instances', scope.signal);
    instState.setList(instances);
    mount(root,
      el('p.muted', null, 'Ein Panel für mehrere Caddy-Server. Jede Instanz verbindet sich über ihren Sentinel-Agent mit einem eigenen Token – nur ausgehend, der Server braucht keinen offenen Port. Statistiken lassen sich pro Instanz oder gesammelt ansehen; Editor, Request-Fluss, Sites und Zertifikate zeigen immer genau eine Instanz, farbig markiert.'),
      el('div.inst-grid', null, instances.map(card)),
      panel('So wird ein weiterer Caddy angebunden', el('div.stack', null,
        el('ol', { style: { margin: 0, paddingLeft: '20px', lineHeight: 1.7 } },
          el('li', null, 'Caddy mit Sentinel-Modul auf dem Server installieren – das Installationsskript hat dafür den Modus ', el('code', null, '--agent'), ' (der fertige Befehl erscheint nach dem Anlegen).'),
          el('li', null, '„Instanz hinzufügen“ – Name und Farbe wählen.'),
          el('li', null, 'Den angezeigten Befehl auf dem Server ausführen – oder bei einem vorhandenen Sentinel-Caddy den Block in die Caddyfile einfügen und Caddy neu laden.'),
          el('li', null, 'Optional ', el('code', null, 'remote full'), ' setzen, damit die Caddyfile hier bearbeitet werden kann. Dafür braucht der Caddy-Benutzer Schreibrechte auf das Konfigurationsverzeichnis.')))));
  }

  function card(i) {
    const mode = MODE[i.remote] || ['–', 'Agent hat sich noch nicht gemeldet'];
    return el('section.inst-card', { style: { '--ic': i.color || 'var(--primary)' } },
      el('div.row', null,
        el('h3', null, i.name),
        i.local ? el('span.badge', null, 'Panel-Server') : null,
        el('span', { style: { marginLeft: 'auto' } }, el('span.dot.' + (i.online ? 'ok' : 'bad')), ' ', i.online ? 'verbunden' : 'offline')),
      i.description ? el('p.muted', { style: { margin: 0, fontSize: '13px' } }, i.description) : null,
      el('dl.kv', null,
        el('dt', null, 'ID'), el('dd.mono', null, i.id),
        el('dt', null, 'Zugriff'), el('dd', { title: mode[1] }, mode[0], el('small.muted', null, ' – ' + mode[1])),
        i.caddyfile ? [el('dt', null, 'Caddyfile'), el('dd.mono', null, i.caddyfile)] : null,
        el('dt', null, 'Zuletzt gemeldet'), el('dd', null, i.last_seen ? fmtAgo(i.last_seen * 1000) : 'noch nie'),
        i.version ? [el('dt', null, 'Sentinel'), el('dd', null, i.version)] : null,
        !i.local && i.token_hint ? [el('dt', null, 'Token'), el('dd.mono', null, i.token_hint + '…')] : null),
      i.nodes?.length ? el('div.nodes', null, el('b', { style: { fontSize: '12.5px' } }, i.nodes.length > 1 ? `${i.nodes.length} Server mit diesem Token` : 'Server'),
        i.nodes.map(n => el('div', null, el('span.dot.' + (n.online ? 'ok' : 'bad')), el('span.mono', null, n.id), el('span.muted', null, n.addr), el('span.muted', null, 'Caddy ' + (n.caddy_version || '?'))))) : null,
      !i.online && !i.local && !i.last_seen ? el('div.callout.warn', null, 'Noch keine Verbindung. Block mit dem Token in die Caddyfile des Servers eintragen und Caddy neu laden.') : null,
      i.nodes?.length > 1 && i.remote === 'full' ? el('div.callout.warn', null, 'Mehrere Server teilen sich dieses Token. Änderungen an der Caddyfile gehen an den Server, der zuerst antwortet – für Fernverwaltung besser je Server eine eigene Instanz.') : null,
      isAdmin ? el('div.row', { style: { marginTop: 'auto' } },
        el('button.btn.sm', { onclick: () => edit(i) }, 'Bearbeiten'),
        el('button.btn.sm', { onclick: () => rotate(i) }, i.local ? 'Token erneuern' : 'Neues Token'),
        !i.local ? el('button.btn.sm.danger', { onclick: () => remove(i) }, 'Entfernen') : null) : null);
  }

  function colorPicker(value, onChange) {
    const wrap = el('div.color-pick', { role: 'radiogroup', 'aria-label': 'Farbe' });
    const draw = (v) => mount(wrap, COLORS.map(c => el('button' + (c === v ? '.active' : ''), { type: 'button', style: { '--c': c }, 'aria-label': c, 'aria-checked': c === v ? 'true' : 'false', role: 'radio', onclick: () => { draw(c); onChange(c); } })));
    draw(value);
    return wrap;
  }

  function form(i = {}) {
    const v = { name: i.name || '', color: i.color || COLORS[instState.list.length % COLORS.length], description: i.description || '' };
    const body = el('div.stack', null,
      field('Name', el('input', { value: v.name, placeholder: 'z. B. Web-Server Rechenzentrum', oninput: (e) => v.name = e.target.value, required: true }), 'So erscheint die Instanz überall im Panel.'),
      el('div.field', null, el('span', null, 'Farbe'), colorPicker(v.color, (c) => v.color = c), el('small.muted', null, 'Markiert die Instanz in Listen, Diagrammen und auf jeder Seite.')),
      field('Beschreibung', el('input', { value: v.description, placeholder: 'optional', oninput: (e) => v.description = e.target.value })));
    return { v, body };
  }

  function create() {
    const { v, body } = form();
    modal('Caddy-Instanz hinzufügen', body, {
      actions: [{ label: 'Abbrechen' }, {
        label: 'Anlegen', kind: 'primary', onClick: async () => {
          const res = await post('/instances', v);
          showToken(res.instance, res.token, res.panel_url);
          await load();
        },
      }],
    });
  }

  function edit(i) {
    const { v, body } = form(i);
    modal('Instanz bearbeiten', body, {
      actions: [{ label: 'Abbrechen' }, { label: 'Speichern', kind: 'primary', onClick: async () => { await put('/instances/' + i.id, v); toast('Gespeichert', 'ok'); await load(); } }],
    });
  }

  async function rotate(i) {
    if (!await confirmDialog('Token erneuern', `Das bisherige Token von „${i.name}“ wird sofort ungültig. Der Agent verbindet sich erst wieder, wenn das neue Token eingetragen ist${i.local ? ' (lokal: wird automatisch aus der Token-Datei gelesen)' : ''}.`, 'Erneuern')) return;
    try {
      const res = await post(`/instances/${i.id}/rotate`);
      if (i.local) toast('Token erneuert – der lokale Agent liest es aus der Token-Datei', 'ok', 6000);
      else showToken(i, res.token, res.panel_url);
      await load();
    } catch (e) { errToast(e); }
  }

  async function remove(i) {
    if (!await confirmDialog('Instanz entfernen', `„${i.name}“ entfernen? Der Agent wird sofort abgewiesen. Gespeicherte Statistiken bleiben erhalten, bis sie nach der Aufbewahrungsfrist gelöscht werden.`, 'Entfernen')) return;
    try { await del('/instances/' + i.id); toast('Entfernt', 'ok'); if (instState.value === i.id) instState.set('all'); await load(); } catch (e) { errToast(e); }
  }

  function showToken(i, token, panelURL) {
    let mode = 'full';
    const pre = el('pre.mono', { style: { whiteSpace: 'pre-wrap' } });
    const cmd = el('pre.mono', { style: { whiteSpace: 'pre-wrap' } });
    const draw = () => {
      // the token goes in as environment variable, not as argument (process list)
      cmd.textContent = `SENTINEL_AGENT_TOKEN='${token}' bash <(wget -qO- https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh) \\
  --agent --panel ${panelURL} --remote ${mode}`;
      pre.textContent = `{
	sentinel {
		panel ${panelURL}
		token ${token}${mode === 'full' ? `
		remote full
		caddyfile /etc/caddy/Caddyfile` : mode === 'off' ? `
		remote off` : ''}
	}
}`;
    };
    draw();
    modal(`Token für „${i.name}“`, el('div.stack', null,
      el('div.callout.warn', null, 'Das Token wird nur jetzt angezeigt. Bei Verlust einfach ein neues erzeugen.'),
      el('div.row', null, el('code', { style: { userSelect: 'all', wordBreak: 'break-all', fontSize: '13px' } }, token), el('button.btn.sm', { onclick: () => copy(token) }, 'Kopieren')),
      el('div.field', null, el('span', null, 'Zugriff des Panels auf diesen Caddy'),
        el('div.seg', { role: 'group' }, [['full', 'Bearbeiten (remote full)'], ['read', 'Nur lesen'], ['off', 'Kein Zugriff']].map(([k, l]) => {
          const b = el('button' + (k === mode ? '.active' : ''), { type: 'button', onclick: () => { mode = k; b.parentNode.querySelectorAll('button').forEach(x => x.classList.toggle('active', x === b)); draw(); } }, l);
          return b;
        }))),
      el('h4', { style: { margin: '6px 0 0' } }, 'Neuer Server: per Installationsskript'),
      el('p', { style: { margin: 0 } }, 'Installiert Caddy mit Sentinel-Modul als systemd-Dienst und verbindet ihn mit diesem Panel:'),
      cmd,
      el('button.btn.sm', { onclick: () => copy(cmd.textContent), style: { alignSelf: 'flex-start' } }, 'Befehl kopieren'),
      el('h4', { style: { margin: '6px 0 0' } }, 'Vorhandener Caddy mit Sentinel-Modul'),
      el('p', { style: { margin: 0 } }, 'In die globalen Optionen der Caddyfile auf dem Server einfügen (Pfad der Caddyfile anpassen) und Caddy neu laden:'),
      pre,
      el('button.btn.sm', { onclick: () => copy(pre.textContent), style: { alignSelf: 'flex-start' } }, 'Block kopieren'),
      el('p.muted', { style: { margin: 0, fontSize: '12.5px' } }, 'Die Panel-Adresse muss vom Server aus erreichbar sein (unter Einstellungen › Benachrichtigungen lässt sich die öffentliche Panel-URL fest eintragen). Für „Bearbeiten“ braucht der Benutzer, unter dem Caddy läuft, Schreibrechte auf das Konfigurationsverzeichnis.')),
    { wide: true });
  }

  await load();
}
