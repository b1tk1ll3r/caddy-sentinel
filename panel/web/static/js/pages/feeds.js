import { el, mount, get, post, put, del, panel, field, toggle, toast, errToast, modal, confirmDialog, empty, fmtInt, fmtAgo } from '../ui.js';
import { setActions } from '../app.js';

export async function render(root, _p, scope) {
  const load = async () => draw(await get('/feeds', scope.signal));
  const polName = Object.fromEntries((await get('/policies', scope.signal)).policies.map(p => [p.id, p.name]));
  setActions(el('button.btn.primary', { onclick: () => edit() }, 'Eigene Liste anlegen'));

  function draw(d) {
    const have = new Set(d.feeds.map(f => f.id));
    const presets = d.presets.filter(p => !have.has(p.id));
    mount(root,
      el('p.muted', null, 'Threat-Feeds sind IP-Listen bekannter Angreifer, Botnetze oder Anonymisierungsdienste. Sentinel lädt sie regelmäßig, verteilt sie an Caddy und prüft jeden Request in Mikrosekunden dagegen. Was passiert, legst du pro Policy fest (Policies › Geo & Feeds): blockieren, Bot-Challenge oder nur markieren.'),
      panel('Aktive Listen', d.feeds.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Liste'), el('th', null, 'Quelle'), el('th.num', null, 'Einträge'), el('th', null, 'Aktualisiert'), el('th', null, 'Verwendet in'), el('th', null, ''))),
        el('tbody', null, d.feeds.map(f => el('tr', null,
          el('td', null, el('b', null, f.name), !f.enabled ? el('span.badge', { style: { marginLeft: '6px' } }, 'aus') : null, f.description ? el('div', null, el('small', null, f.description)) : null),
          el('td', null, f.url ? el('small.mono', null, f.url.replace(/^https?:\/\//, '')) : el('span.badge.primary', null, 'manuell')),
          el('td.num', null, fmtInt(f.count)),
          el('td.nowrap', null, f.updated ? fmtAgo(f.updated * 1000) : '–', f.last_error ? el('div', null, el('small', { style: { color: 'var(--bad)' } }, f.last_error)) : null),
          el('td', null, (d.usage[f.id] || []).map(pid => el('a.badge.primary', { href: '#/policies/' + pid, style: { marginRight: '4px' } }, polName[pid] || pid)), !(d.usage[f.id] || []).length ? el('small', null, 'keiner Policy zugeordnet') : null),
          el('td.nowrap', null,
            f.url ? el('button.btn.sm', { onclick: async (e) => { e.target.disabled = true; try { await post(`/feeds/${f.id}/refresh`); toast(`${f.name} aktualisiert`, 'ok'); load(); } catch (err) { errToast(err); e.target.disabled = false; } } }, 'Jetzt laden') : null, ' ',
            el('button.btn.sm', { onclick: () => edit(f) }, 'Bearbeiten'))))))) : empty('Noch keine Listen', 'Aktiviere unten eine der bekannten Listen oder lege eine eigene an.')),
      presets.length ? panel('Bekannte Listen', el('div.group-grid', null, presets.map(p => el('div.group', { style: { flexDirection: 'column', alignItems: 'stretch' } },
        el('b', null, p.name), el('small', null, p.description), el('small.mono', { style: { wordBreak: 'break-all' } }, p.url),
        el('div', { style: { marginTop: 'auto', paddingTop: '6px' } }, el('button.btn.sm', {
          onclick: async () => {
            try { await post('/feeds', { preset: p.id }); toast(`${p.name} wird geladen …`, 'ok'); setTimeout(load, 2500); load(); } catch (e) { errToast(e); }
          },
        }, 'Aktivieren')))))) : null,
      el('small', null, 'Nutzungsbedingungen der Anbieter beachten (z. B. Spamhaus: nicht-kommerziell frei). Listen mit vielen dynamischen IPs besser für die Bot-Challenge statt für harte Sperren verwenden.'));
  }

  async function edit(f) {
    let full = f ? await get('/feeds/' + f.id) : { name: '', url: '', description: '', enabled: true, interval_min: 360, content: '' };
    const d = { ...full };
    let contentEl;
    modal(f ? `Liste „${f.name}“` : 'Eigene Liste', [
      el('div.fields', null,
        field('Name', el('input', { value: d.name, oninput: (e) => { d.name = e.target.value; } })),
        field('Beschreibung', el('input', { value: d.description, oninput: (e) => { d.description = e.target.value; } })),
        el('div.field.wide', null, el('span', null, 'Download-URL (leer = manuell gepflegt)'), el('input.mono', {
          value: d.url, placeholder: 'https://…', oninput: (e) => { d.url = e.target.value.trim(); contentEl.readOnly = !!d.url; },
        })),
        field('Aktualisieren alle (Min.)', el('input', { type: 'number', min: 15, value: d.interval_min, oninput: (e) => { d.interval_min = +e.target.value; } })),
        el('div.field', null, el('span', null, 'Aktiv'), toggle(d.enabled, (v) => { d.enabled = v; }, 'an Caddy verteilen'))),
      el('label.field', null, el('span', null, d.url ? 'Inhalt (vom Server geladen, schreibgeschützt)' : 'IPs und Netze, eine pro Zeile'),
        contentEl = el('textarea.code', { rows: 12, value: full.content || '', readonly: !!d.url, placeholder: '# Kommentar\n203.0.113.0/24\n198.51.100.7\n2001:db8::/32' })),
    ], {
      wide: true,
      actions: [
        f ? { label: 'Löschen', kind: 'danger', onClick: async () => { if (!await confirmDialog('Liste löschen', `„${f.name}“ löschen?`, 'Löschen')) return false; await del('/feeds/' + f.id); load(); } } : null,
        { label: 'Abbrechen' },
        {
          label: 'Speichern', kind: 'primary', onClick: async () => {
            const body = { ...d, content: d.url ? undefined : contentEl.value };
            f ? await put('/feeds/' + f.id, body) : await post('/feeds', body);
            toast('Liste gespeichert', 'ok');
            setTimeout(load, d.url ? 2500 : 0);
            load();
          },
        },
      ].filter(Boolean),
    });
  }

  await load();
}
