// Transfer parts of one policy to other policies, with a preview per target.
import { el, mount, post, modal, toast, errToast, can } from './ui.js';

export function openTransfer(src, policies) {
  const others = policies.filter(p => p.id !== src.id);
  if (!others.length) { toast('Es gibt keine weitere Policy', 'info'); return; }
  const SECTIONS = [['ip', 'IP-Listen'], ['geo', 'Geo & Threat-Feeds'], ['filters', 'Filter'], ['bots', 'Bots & Crawler'], ['ratelimits', 'Ratelimits'], ['pathrules', 'Pfad-Regeln'],
    ['waf', 'WAF'], ['challenge', 'Bot-Challenge'], ['auth', 'Anmeldung'], ['headers', 'Sicherheits-Header'], ['block', 'Sperrseite'], ['ids', 'IDS-Anpassungen'], ['maintenance', 'Wartungsmodus']];
  const sel = new Set(), targets = new Set();
  const preview = el('div');
  const chk = (set, key, label, sub) => el('label.check', null, el('input', { type: 'checkbox', onchange: (e) => { e.target.checked ? set.add(key) : set.delete(key); mount(preview); } }), el('span', null, label, sub ? el('small.muted', null, ' ' + sub) : null));
  const run = async (apply) => {
    if (!sel.size || !targets.size) throw new Error('Bereiche und Ziel-Policies auswählen');
    const r = await post(`/policies/${src.id}/transfer`, { targets: [...targets], sections: [...sel], apply });
    mount(preview, el('div.stack', null, r.targets.map(t => el('div.transfer-target', null,
      el('div.row', null, el('b', null, t.name), t.saved ? el('span.badge.ok', null, 'übernommen') : null, t.error ? el('span.badge.bad', null, 'Fehler') : null),
      t.error ? el('div.callout.bad', null, t.error) : null,
      t.sections.map(s => el('div', null, el('small', null, el('b', null, s.label + ': ')), s.changes.length ? el('ul.diff', null, s.changes.map(c => el('li.mono', null, c))) : el('small.muted', null, 'keine Änderung')))))));
    return r;
  };
  const m = modal(`Aus „${src.name}“ übernehmen`, el('div.stack', null,
    el('p.muted', { style: { margin: 0 } }, 'Kopiert die gewählten Bereiche dieser Policy (gespeicherter Stand) in andere Policies. Bei Ratelimits und Pfad-Regeln werden gleichnamige ersetzt und neue ergänzt, alles andere wird ersetzt. Erst die Vorschau prüfen, dann übernehmen.'),
    el('div.grid.g2', null,
      el('div', null, el('h4', null, 'Bereiche'), el('div.checks', null, SECTIONS.map(([k, l]) => chk(sel, k, l)))),
      el('div', null, el('h4', null, 'In diese Policies'), el('div.checks', null, others.map(p => chk(targets, p.id, p.name, p.hosts?.length ? p.hosts.join(', ') : ''))))),
    preview), {
    wide: true,
    actions: [{ label: 'Schließen' },
      { label: 'Vorschau', onClick: async () => { await run(false); return false; } },
      can('policy') ? {
        label: 'Übernehmen', kind: 'primary', onClick: async () => {
          const r = await run(true);
          const ok = r.targets.filter(t => t.saved).length;
          toast(`${ok} Policy${ok === 1 ? '' : 's'} aktualisiert`, ok ? 'ok' : 'bad');
          return false;
        },
      } : null].filter(Boolean),
  });
  return m;
}

export { errToast };
