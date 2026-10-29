// WAF false-positive assistant: proposes the narrowest exclusion for
// requests the WAF blocked and applies it to the policy.
import { el, mount, get, post, modal, toast, errToast, fmtInt, qs, can } from './ui.js';

const RISK = { niedrig: 'ok', mittel: 'warn', hoch: 'bad' };

export function openWafAssistant({ policy, host = '', path = '', inst = '' }) {
  const body = el('div.stack', null, el('div.diag-skel', null, 'Analysiere die WAF-Blockaden der letzten 7 Tage …'));
  const m = modal('Fehlalarm-Assistent (WAF)', body, { wide: true });
  const load = (p) => get(`/policies/${encodeURIComponent(policy)}/waf-analyze` + qs({ host, path: p, inst }))
    .then(a => draw(a)).catch(e => mount(body, el('div.callout.bad', null, e.message)));
  load(path);

  function draw(a) {
    if (!a.blocked) { mount(body, el('div.callout.info', null, a.notes.join(' '))); return; }
    const total = a.blocked;
    mount(body,
      el('p', { style: { margin: 0 } }, `Policy „${a.policy_name}“${host ? ' · ' + host : ''}: ${fmtInt(total)} WAF-Blockaden in 7 Tagen, davon ${fmtInt(a.in_scope)} unter `, el('code', null, a.prefix), ` von ${fmtInt(a.ips)} Client${a.ips === 1 ? '' : 's'}.`),
      a.paths.length > 1 ? el('div.row', null, el('span.muted', null, 'Bereich:'), a.paths.slice(0, 6).map(p => el('button.btn.sm' + (p.key.startsWith(a.prefix) ? '' : '.ghost'), { title: `${p.count} Blockaden`, onclick: () => { mount(body, el('div.diag-skel', null, 'Analysiere …')); load(p.key); } }, p.key))) : null,
      a.notes.map(n => el('div.callout' + (/Vorsicht|Angriff/.test(n) ? '.warn' : ''), null, n)),
      el('h4', { style: { margin: '6px 0 0' } }, 'Beteiligte Regeln'),
      el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Regel'), el('th', null, 'Meldung'), el('th.num', null, 'Treffer'), el('th', null, 'Gefunden in'))),
        el('tbody', null, a.rules.slice(0, 12).map(r => el('tr', null, el('td.mono', null, r.id), el('td', null, r.msg), el('td.num', null, fmtInt(r.count)), el('td.mono.muted', null, (r.targets || []).slice(0, 4).join(', ') || '–')))))),
      el('h4', { style: { margin: '6px 0 0' } }, 'Vorschläge – vom engsten zum breitesten'),
      el('div.stack', null, a.suggestions.map(s => el('div.sugg', null,
        el('div.row', null,
          el('span.badge.' + (RISK[s.risk] || 'info'), { title: 'Wie viel Schutz dabei verloren geht' }, 'Risiko ' + s.risk),
          el('b', null, s.title),
          el('span.grow'),
          el('span', { title: 'Blockierte Anfragen der letzten 7 Tage, die mit dieser Ausnahme durchgegangen wären' }, el('b', null, fmtInt(s.prevented)), ` von ${fmtInt(total)} verhindert`)),
        el('p.muted', { style: { margin: '4px 0 6px', fontSize: '13px' } }, s.detail),
        s.exclusion ? el('code', { style: { fontSize: '12px' } }, describe(s)) : null,
        can('policy') ? el('div.row', { style: { marginTop: '6px' } }, el('button.btn.sm' + (s.risk === 'niedrig' ? '.primary' : ''), {
          onclick: async (e) => {
            e.currentTarget.disabled = true;
            try {
              await post(`/policies/${encodeURIComponent(policy)}/waf-exclude`, s);
              toast('Angewendet – Caddy übernimmt die Änderung in Sekunden', 'ok', 5000);
              m.close();
            } catch (err) { errToast(err); e.currentTarget.disabled = false; }
          },
        }, 'Anwenden')) : null))),
      el('p.muted', { style: { margin: 0, fontSize: '12.5px' } }, 'Angewendete Ausnahmen stehen in der Policy unter WAF › Ausnahmen und lassen sich dort wieder entfernen.'));
  }
}

function describe(s) {
  const x = s.exclusion;
  return `Regel ${x.rules.join(', ')}` + (x.target ? ` · nur ${x.target}` : '') + (x.path_prefix ? ` · Pfade ab ${x.path_prefix}` : ' · alle Pfade');
}
