// Saved views: store the filters of a page (the URL with its query, plus
// time range and Caddy instance) under a name – privately or for everyone.
import { el, mount, get, post, del, toast, errToast, prompt, rangeState, instState, toggle, modal, field, confirmDialog } from './ui.js';

/** Bar with the saved views of a page and a "save" button. */
export function viewsBar(page, scope) {
  const box = el('div.views-bar');
  const load = async () => {
    let list = [];
    try { list = await get('/views?page=' + encodeURIComponent(page), scope?.signal); } catch { /* optional */ }
    const me = window.__status?.user || {};
    mount(box,
      el('span.muted', null, 'Ansichten:'),
      list.length ? list.map(v => el('span.view-chip', null,
        el('a', { href: v.route, title: (v.shared ? 'Geteilt' : 'Privat') + (v.owner && v.owner !== me.username ? ' · von ' + v.owner : ''), onclick: (e) => { e.preventDefault(); applyView(v); } }, v.shared ? '👥 ' : '', v.name),
        (v.user_id === me.id || me.role === 'admin') ? el('button.x', {
          title: 'Ansicht löschen', onclick: async () => {
            if (!await confirmDialog('Ansicht löschen', `„${v.name}“ löschen?`, 'Löschen')) return;
            try { await del('/views/' + v.id); load(); } catch (e) { errToast(e); }
          },
        }, '✕') : null)) : el('span.muted', null, 'noch keine'),
      el('button.btn.sm.ghost', { onclick: save, title: 'Aktuelle Filter, Zeitraum und Instanz speichern' }, '＋ Ansicht speichern'));
  };
  async function save() {
    let name = '', shared = false;
    modal('Ansicht speichern', el('div.stack', null,
      field('Name', el('input', { placeholder: 'z. B. 403 auf dem Wiki, letzte Stunde', oninput: (e) => { name = e.target.value; } })),
      toggle(false, (v) => { shared = v; }, 'für alle Panel-Benutzer sichtbar'),
      el('small.muted', null, 'Gespeichert werden die Filter dieser Seite, der Zeitraum (' + rangeState.value + ')' + (instState.multi() ? ' und die gewählte Caddy-Instanz' : '') + '. Auch über die Suche (Strg+K) erreichbar.')), {
      actions: [{ label: 'Abbrechen' }, {
        label: 'Speichern', kind: 'primary', onClick: async () => {
          if (!name.trim()) throw new Error('Name fehlt');
          const u = new URL(location.href);
          const params = new URLSearchParams(u.hash.split('?')[1] || '');
          params.set('range', rangeState.value);
          if (instState.value !== 'all') params.set('inst', instState.value);
          const route = u.hash.split('?')[0] + '?' + params.toString();
          await post('/views', { page, name: name.trim(), route, shared });
          toast('Ansicht gespeichert', 'ok');
          load();
        },
      }],
    });
  }
  load();
  return box;
}

/** Opens a saved view: time range and instance first, then the route. */
export function applyView(v) {
  const q = new URLSearchParams(v.route.split('?')[1] || '');
  const r = q.get('range');
  if (r && r !== rangeState.value) rangeState.set(r);
  const i = q.get('inst');
  if (i && instState.list.find(x => x.id === i) && instState.value !== i) instState.set(i);
  if (location.hash === v.route) window.dispatchEvent(new HashChangeEvent('hashchange'));
  else location.hash = v.route;
}

export { prompt };
