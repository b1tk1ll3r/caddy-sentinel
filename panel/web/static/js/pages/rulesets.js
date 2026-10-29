import { el, mount, get, post, put, del, panel, field, toast, errToast, confirmDialog, prompt, empty } from '../ui.js';
import { ruleBuilder, wafMeta } from '../rulebuilder.js';
import { setActions } from '../app.js';

export async function render(root, [id], scope) {
  const [data, presets, meta, pols] = await Promise.all([get('/rulesets', scope.signal), get('/presets', scope.signal), wafMeta(), get('/policies', scope.signal)]);
  const polName = Object.fromEntries(pols.policies.map(p => [p.id, p.name]));

  if (!id) {
    setActions(el('button.btn.primary', { onclick: create }, 'Neuer Regelsatz'));
    mount(root,
      el('p.muted', null, 'Regelsätze bündeln WAF-Regeln, die du in mehreren Policies wiederverwenden kannst – z. B. „WordPress-Härtung“ für alle WordPress-Sites. Die Regeln laufen nach der CRS-Initialisierung und vor den CRS-Prüfungen.'),
      panel('Deine Regelsätze', data.rulesets.length ? el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Name'), el('th', null, 'Beschreibung'), el('th.num', null, 'Regeln'), el('th', null, 'Verwendet in'))),
        el('tbody', null, data.rulesets.map(r => el('tr.clickable', { onclick: () => { location.hash = '#/rulesets/' + r.id; } },
          el('td', null, el('b', null, r.name)), el('td.muted', null, r.description),
          el('td.num', null, `${r.rules.filter(x => x.enabled).length}/${r.rules.length}`),
          el('td', null, (data.usage[r.id] || []).map(pid => el('span.badge', { style: { marginRight: '4px' } }, polName[pid] || pid)), !(data.usage[r.id] || []).length ? el('span.muted', null, 'noch keiner Policy zugewiesen') : null))))) : empty('Noch keine Regelsätze', 'Starte mit einer Vorlage unten oder lege einen leeren Regelsatz an.')),
      panel('Vorlagen', el('div.group-grid', null, presets.map(pr => el('div.group', { style: { flexDirection: 'column', alignItems: 'stretch' } },
        el('b', null, pr.name), el('small', null, pr.description),
        el('small', null, pr.rules.map(r => r.name).join(' · ')),
        el('div', { style: { marginTop: 'auto', paddingTop: '6px' } }, el('button.btn.sm', {
          onclick: async () => {
            try { const rs = await post('/rulesets/from-preset', { key: pr.key }); toast(`„${rs.name}“ angelegt`, 'ok'); location.hash = '#/rulesets/' + rs.id; } catch (e) { errToast(e); }
          },
        }, 'Als Regelsatz anlegen')))))));
    return;
  }

  async function create() {
    const name = await prompt('Neuer Regelsatz', 'Name', 'Eigene Regeln');
    if (!name) return;
    try { const rs = await post('/rulesets', { name, description: '', rules: [] }); location.hash = '#/rulesets/' + rs.id; } catch (e) { errToast(e); }
  }

  const orig = data.rulesets.find(r => r.id === id);
  if (!orig) { mount(root, empty('Regelsatz nicht gefunden', null, el('a', { href: '#/rulesets' }, 'Zur Übersicht'))); return; }
  const rs = structuredClone(orig);
  rs.rules ??= [];
  let dirty = false;
  const saveBtn = el('button.btn.primary', { disabled: true, onclick: save }, 'Speichern');
  const markDirty = () => { dirty = true; saveBtn.disabled = false; };
  const errBox = el('div');
  async function save() {
    saveBtn.disabled = true;
    try {
      await put('/rulesets/' + rs.id, rs);
      dirty = false;
      mount(errBox);
      toast('Regelsatz gespeichert', 'ok');
      render(root, [id], scope);
    } catch (e) { saveBtn.disabled = false; mount(errBox, el('div.callout.bad', null, e.message)); }
  }
  setActions(
    el('a.btn', { href: '#/rulesets' }, 'Alle Regelsätze'),
    el('button.btn', {
      onclick: () => { sessionStorage.setItem('waf.rules', JSON.stringify(rs.rules)); location.hash = '#/waf?rules=1'; },
    }, 'Testen'),
    el('button.btn.danger', {
      onclick: async () => {
        if (!await confirmDialog('Regelsatz löschen', `„${rs.name}“ endgültig löschen?`, 'Löschen')) return;
        try { await del('/rulesets/' + rs.id); location.hash = '#/rulesets'; } catch (e) { errToast(e); }
      },
    }, 'Löschen'),
    saveBtn);
  const used = data.usage[rs.id] || [];
  mount(root,
    errBox,
    panel('Regelsatz', el('div.fields', null,
      field('Name', el('input', { value: rs.name, oninput: (e) => { rs.name = e.target.value; markDirty(); } })),
      field('Beschreibung', el('input', { value: rs.description || '', oninput: (e) => { rs.description = e.target.value; markDirty(); } })),
      el('div.field.wide', null, el('span', null, 'Verwendet in'), el('div', null, used.length ? used.map(pid => el('a.badge.primary', { href: '#/policies/' + pid, style: { marginRight: '6px' } }, polName[pid] || pid)) : el('span.muted', null, 'Keiner Policy zugewiesen – unter Policies › WAF › Regelsätze aktivieren.'))))),
    panel('Regeln', ruleBuilder(rs.rules, meta, markDirty)));
  scope.listen(window, 'beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
}
