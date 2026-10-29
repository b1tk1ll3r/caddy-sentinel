// Visual WAF rule builder shared by policies and rulesets.
import { el, mount, get, post, select, toggle, debounce, modal } from './ui.js';

let metaCache;
export async function wafMeta() {
  if (!metaCache) metaCache = get('/waf/meta');
  return metaCache;
}

const ACTION_OPTS = [
  ['block', 'Blockieren'], ['score', 'Anomalie-Score erhöhen'], ['log', 'Nur protokollieren'],
  ['allow', 'Erlauben (WAF überspringen)'], ['exclude', 'CRS-Regeln ausnehmen'],
];

export function newRule() {
  return { id: 0, name: 'Neue Regel', enabled: true, mode: 'builder', action: 'block', status: 403, score: 5, severity: 'CRITICAL', exclude: [], conditions: [{ field: 'path', op: 'begins', value: '/', negate: false }], raw: '', note: '' };
}

/** rules: array (mutated in place); onChange called after edits. */
export function ruleBuilder(rules, meta, onChange) {
  const wrap = el('div');
  const preview = el('pre.block', { hidden: true });
  const errors = el('div');
  const changed = () => { onChange(); compile(); };
  const compile = debounce(async () => {
    try {
      const res = await post('/rules/compile', { rules });
      mount(errors, res.errors.map(e => el('div.callout.bad', { style: { marginBottom: '6px' } }, e)));
      preview.textContent = res.directives || '# keine aktiven Regeln';
    } catch (e) { mount(errors, el('div.callout.bad', null, e.message)); }
  }, 500);

  const fieldOpts = meta.fields.map(f => [f.key, f.label]);
  const opOpts = meta.ops.map(o => [o.key, o.label]);
  const namedFields = new Set(meta.fields.filter(f => f.named).map(f => f.key));

  const draw = () => {
    mount(wrap, rules.length ? rules.map((r, i) => ruleCard(r, i)) : el('p.muted', null, 'Noch keine Regeln.'),
      errors,
      el('div.row', { style: { marginTop: '10px' } },
        el('button.btn', { onclick: () => { rules.push(newRule()); draw(); changed(); } }, 'Regel hinzufügen'),
        el('button.btn', { onclick: () => { rules.push({ ...newRule(), mode: 'raw', name: 'SecLang-Regel', raw: 'SecRule REQUEST_URI "@contains /beispiel" "id:1000001,phase:1,deny,status:403,log,msg:\'Beispiel\'"' }); draw(); changed(); } }, 'SecLang-Regel hinzufügen'),
        el('button.btn.ghost', { onclick: () => { preview.hidden = !preview.hidden; compile(); } }, 'Erzeugtes SecLang anzeigen')),
      preview);
    compile();
  };

  const ruleCard = (r, i) => {
    const move = (d) => { const j = i + d; if (j < 0 || j >= rules.length) return; [rules[i], rules[j]] = [rules[j], rules[i]]; draw(); changed(); };
    const body = el('div.rule-body');
    const drawBody = () => {
      if (r.mode === 'raw') {
        mount(body, el('textarea.code', { rows: 4, spellcheck: 'false', value: r.raw, oninput: (e) => { r.raw = e.target.value; changed(); } }),
          el('small', null, 'Roh-SecLang (ModSecurity/Coraza). IDs selbst vergeben, außerhalb 9xxxxx (CRS).'));
        return;
      }
      mount(body,
        r.conditions.map((c, ci) => condRow(r, c, ci)),
        el('div.row', null,
          el('button.btn.sm.ghost', { onclick: () => { r.conditions.push({ field: 'path', op: 'contains', value: '', negate: false }); drawBody(); changed(); } }, '+ Bedingung (UND)'),
          el('span.grow'),
          el('span.muted', null, 'Dann:'),
          select(ACTION_OPTS, r.action, (v) => { r.action = v; drawBody(); changed(); }, { 'aria-label': 'Aktion' }),
          r.action === 'block' ? el('input', { type: 'number', min: 400, max: 599, value: r.status || 403, title: 'Status-Code', style: { width: '80px' }, oninput: (e) => { r.status = +e.target.value; changed(); } }) : null,
          r.action === 'score' ? el('input', { type: 'number', min: 1, max: 100, value: r.score || 5, title: 'Punkte', style: { width: '70px' }, oninput: (e) => { r.score = +e.target.value; changed(); } }) : null,
          r.action === 'block' || r.action === 'log' || r.action === 'score' ? select(['CRITICAL', 'ERROR', 'WARNING', 'NOTICE'], r.severity || 'CRITICAL', (v) => { r.severity = v; changed(); }, { 'aria-label': 'Schwere' }) : null),
        r.action === 'exclude' ? el('label.field', null, el('span', null, 'Auszunehmende CRS-Regeln (ID, Bereich, tag:…, oder ID;ARGS:feld) – kommagetrennt'),
          el('input', { value: (r.exclude || []).join(', '), placeholder: '942100, 941000-941999, tag:attack-sqli, 942100;ARGS:password', oninput: (e) => { r.exclude = e.target.value.split(',').map(s => s.trim()).filter(Boolean); changed(); } })) : null,
        el('input', { value: r.note || '', placeholder: 'Notiz (optional)', oninput: (e) => { r.note = e.target.value; changed(); } }));
    };
    const condRow = (rule, c, ci) => {
      const row = el('div.cond' + (namedFields.has(c.field) ? '.named' : ''), null,
        el('span.lead', null, ci === 0 ? 'Wenn' : 'und'),
        select(fieldOpts, c.field, (v) => { c.field = v; row.classList.toggle('named', namedFields.has(v)); changed(); }, { 'aria-label': 'Feld' }),
        el('input.name-input', { value: c.name || '', placeholder: 'Name', oninput: (e) => { c.name = e.target.value; changed(); } }),
        el('div.row', { style: { gap: '4px', flexWrap: 'nowrap' } },
          select([['', 'ist'], ['1', 'ist nicht']], c.negate ? '1' : '', (v) => { c.negate = !!v; changed(); }, { 'aria-label': 'Negation' }),
          select(opOpts, c.op, (v) => { c.op = v; changed(); }, { 'aria-label': 'Operator' })),
        el('input', { value: c.value || '', placeholder: c.op === 'words' ? 'wort1 wort2 …' : c.op === 'ip' ? '10.0.0.0/8, 192.168.1.5' : 'Wert', oninput: (e) => { c.value = e.target.value; changed(); } }),
        el('div.row', { style: { gap: '2px', flexWrap: 'nowrap' } },
          el('button.icon-btn', {
            title: 'Transformationen', onclick: () => transformDialog(c, changed),
          }, (c.transform || []).length ? 't:' + c.transform.length : 't'),
          el('button.icon-btn', { title: 'Bedingung entfernen', disabled: rule.conditions.length === 1, onclick: () => { rule.conditions.splice(ci, 1); drawBody(); changed(); } }, '✕')));
      return row;
    };
    drawBody();
    return el('div.rule' + (r.enabled ? '' : '.off'), null,
      el('div.rule-head', null,
        toggle(r.enabled, (v) => { r.enabled = v; draw(); changed(); }),
        el('input.name', { value: r.name, 'aria-label': 'Regelname', oninput: (e) => { r.name = e.target.value; changed(); } }),
        r.id ? el('span.badge.mono', { title: 'SecRule-ID' }, '#' + r.id) : el('span.badge', null, 'neu'),
        el('span.badge', null, r.mode === 'raw' ? 'SecLang' : 'Builder'),
        el('button.icon-btn', { title: 'nach oben', onclick: () => move(-1) }, '↑'),
        el('button.icon-btn', { title: 'nach unten', onclick: () => move(1) }, '↓'),
        el('button.icon-btn', { title: 'Regel löschen', onclick: () => { rules.splice(i, 1); draw(); changed(); } }, '✕')),
      body);
  };

  function transformDialog(c, onCh) {
    const sel = new Set(c.transform || []);
    modal('Transformationen', [
      el('p.muted', null, 'Werden vor dem Vergleich auf den Wert angewendet, z. B. Kleinschreibung oder URL-Dekodierung gegen Umgehungsversuche.'),
      el('div.chips', null, meta.transforms.map(t => el('span.chip' + (sel.has(t) ? '.on' : ''), {
        onclick: (e) => { sel.has(t) ? sel.delete(t) : sel.add(t); e.currentTarget.classList.toggle('on'); },
      }, t))),
    ], { actions: [{ label: 'Abbrechen' }, { label: 'Übernehmen', kind: 'primary', onClick: () => { c.transform = [...sel]; onCh(); draw(); } }] });
  }

  draw();
  return wrap;
}
