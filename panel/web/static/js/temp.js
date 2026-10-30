// Temporary list entries ("tolerate this IP for an hour", "allow the partner
// network until Friday"): list and dialog, used on the security page, the
// policy access tab and the IP profile.
import { el, mount, get, post, del, toast, errToast, field, select, untilInput, fmtUnix, fmtUntil, can, empty, ipLink } from './ui.js';

export const TEMP_LISTS = {
  trusted: ['Vertrauenswürdig', 'alle Prüfungen werden übersprungen, auch Sperren'],
  never_ban: ['Nie sperren', 'das IDS sperrt diese Adresse nicht automatisch'],
  allow: ['Erlaubt-Liste', 'zählt im Modus „Nur Freigabeliste“ als freigegeben'],
  deny: ['Sperrliste', 'wird für diese Policy blockiert'],
};

/** Table of active temporary entries; scope "" = all, "global" or a policy ID. */
export function tempTable(entries, { onChange, policies = {} } = {}) {
  if (!entries.length) return empty('Keine befristeten Einträge', 'Befristete Einträge laufen von selbst ab – nichts bleibt aus Versehen dauerhaft offen.');
  return el('div.table-wrap', null, el('table', null,
    el('thead', null, el('tr', null, el('th', null, 'Adresse'), el('th', null, 'Liste'), el('th', null, 'Gilt für'), el('th', null, 'Bis'), el('th', null, 'Notiz'), el('th'))),
    el('tbody', null, entries.map(t => el('tr', null,
      el('td', null, t.value.includes('/') ? el('span.mono', null, t.value) : ipLink(t.value)),
      el('td', null, el('span.badge.' + (t.list === 'deny' ? 'bad' : t.list === 'trusted' ? 'warn' : 'info'), { title: TEMP_LISTS[t.list]?.[1] }, TEMP_LISTS[t.list]?.[0] || t.list)),
      el('td', null, t.scope === 'global' ? 'alle Sites' : 'Policy ' + (policies[t.scope] || t.scope)),
      el('td.nowrap', { title: fmtUnix(t.until) }, fmtUntil(t.until)),
      el('td', null, t.note || el('span.muted', null, '–'), el('div', null, el('small.muted', null, `${t.author} · ${fmtUnix(t.created)}`))),
      el('td.right', null, can(t.scope === 'global' ? 'bans' : 'policy') ? el('button.btn.sm', {
        onclick: async () => { try { await del('/temp/' + t.id); toast('Eintrag entfernt', 'ok'); onChange?.(); } catch (e) { errToast(e); } },
      }, 'Beenden') : null))))));
}

/** Dialog for a new temporary entry. */
export function tempDialog({ value = '', scope = 'global', list, policies = [], onDone } = {}, modal) {
  const st = { value, scope, list: list || (scope === 'global' ? 'trusted' : 'allow'), until: Math.floor(Date.now() / 1000) + 3600, note: '' };
  const listBox = el('div');
  const drawLists = () => {
    const opts = st.scope === 'global' ? ['trusted', 'never_ban'] : ['allow', 'deny'];
    if (!opts.includes(st.list)) st.list = opts[0];
    mount(listBox, field('Liste', select(opts.map(k => [k, TEMP_LISTS[k][0] + ' – ' + TEMP_LISTS[k][1]]), st.list, (v) => { st.list = v; })));
  };
  drawLists();
  const body = el('div.stack', null,
    el('div.fields', null,
      field('IP oder Netz', el('input.mono', { value: st.value, placeholder: '203.0.113.7 oder 198.51.100.0/24', oninput: (e) => { st.value = e.target.value.trim(); } })),
      field('Gilt für', select([['global', 'alle Sites (global)'], ...policies.map(p => [p.id, 'Policy „' + p.name + '“'])], st.scope, (v) => { st.scope = v; drawLists(); }))),
    listBox,
    el('label.field', null, el('span', null, 'Endet'), untilInput(st.until, (v) => { st.until = v; }, { required: true })),
    field('Notiz (warum?)', el('input', { placeholder: 'z. B. Pentest der Firma X, Ticket #4711', oninput: (e) => { st.note = e.target.value; } })),
    el('small.muted', null, 'Danach entfernt Sentinel den Eintrag selbst und vermerkt das im Ereignisprotokoll.'));
  return modal('Befristet freigeben oder sperren', body, {
    actions: [{ label: 'Abbrechen' }, {
      label: 'Eintragen', kind: 'primary', onClick: async () => {
        await post('/temp', st);
        toast('Befristet eingetragen bis ' + fmtUnix(st.until), 'ok');
        onDone?.();
      },
    }],
  });
}

/** Loads and shows the temporary entries (optionally only for scope). */
export function tempPanelBody(scope, policiesById, signal) {
  const box = el('div');
  const load = () => get('/temp' + (scope ? '?scope=' + encodeURIComponent(scope) : ''), signal)
    .then(list => mount(box, tempTable(list, { onChange: load, policies: policiesById })))
    .catch(e => mount(box, el('div.callout.bad', null, e.message)));
  load();
  box.reload = load;
  return box;
}
