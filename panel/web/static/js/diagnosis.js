// Readable diagnosis of a single request: who stopped it, why, evidence,
// fixes and whether the current configuration would still stop it.
import { el, mount, get, post, del, toast, errToast, instChip, can } from './ui.js';
import { openWafAssistant } from './waffp.js';

const WHO = {
  sentinel: ['Sentinel', 'Von Sentinel (Policy, Regeln, WAF …) entschieden'],
  caddy: ['Caddy', 'Von Caddy selbst beantwortet (Route, Dateien, Proxy-Fehler)'],
  backend: ['Backend', 'Vom Backend hinter Caddy beantwortet'],
  client: ['Client', 'Liegt am Client (Anmeldung, Schlüssel, zu viele Anfragen)'],
};
const VERDICT_CLASS = { blocked: 'bad', error: 'bad', challenge: 'warn', login: 'warn', redirect: 'info', ok: 'ok', test: 'warn' };
const STATE_ICON = { passed: '✓', stopped: '✕', warn: '!', served: '✓', not_reached: '' };
const NOW_CLASS = { fixed: 'ok', ok: 'ok', same: 'bad', other: 'warn', new_block: 'warn', unknown: 'info' };
const NOW_TITLE = { fixed: 'Inzwischen behoben', ok: 'Aktuell unverändert', same: 'Tritt weiterhin auf', other: 'Scheitert jetzt woanders', new_block: 'Würde jetzt blockiert', unknown: 'Nicht sicher vorhersagbar' };
const STEP_ICON = { pass: '✓', skip: '–', block: '✕', challenge: '!', login: '!', redirect: '↪', info: 'i', warn: '!' };

/** Loads the diagnosis for a request row (with or without database ID). */
export function loadDiagnosis(r, signal) {
  return r.id ? get(`/requests/${r.id}/explain`, signal) : post('/explain', r);
}

/** Placeholder that fills itself with the diagnosis. */
export function diagnosisBox(r, opts = {}) {
  const box = el('div.diag.loading', null, el('div.diag-skel', null, 'Diagnose wird erstellt …'));
  loadDiagnosis(r).then(d => mount(box, diagnosisView(d, opts)), (e) => mount(box, el('div.callout.warn', null, 'Keine Diagnose möglich: ' + e.message)))
    .finally(() => box.classList.remove('loading'));
  return box;
}

export function diagnosisView(d, { compact = false, onUnban } = {}) {
  const cls = VERDICT_CLASS[d.verdict] || 'info';
  const who = WHO[d.who];
  return el('div.diag-view', null,
    el('section.diag-head.' + cls, null,
      el('div.diag-who', null,
        instChip(d.request.inst),
        who ? el('span.who-chip.' + d.who, { title: who[1] }, who[0]) : null,
        el('span.diag-status', null, d.request.s || ''),
        d.policy_name ? el('span.muted', null, 'Policy ' + d.policy_name) : null),
      el('h3.diag-title', null, d.headline),
      d.explain ? el('p.diag-explain', null, d.explain) : null),
    pipeline(d.pipeline),
    d.facts?.length ? el('dl.kv.diag-facts', null, d.facts.map(f => [el('dt', null, f.label), el('dd' + (f.mono ? '.mono' : ''), null, f.value)])) : null,
    d.fixes?.length ? el('section.diag-fixes', null,
      el('h4', null, d.verdict === 'ok' || d.verdict === 'redirect' ? 'Falls das nicht gewollt ist' : 'So lässt es sich beheben'),
      el('ul', null, d.fixes.map(f => el('li', null,
        f.action === 'unban' && can('bans')
          ? el('button.btn.sm', { onclick: async (e) => { e.currentTarget.disabled = true; try { await del('/bans/' + encodeURIComponent(f.arg)); toast(`${f.arg} entsperrt`, 'ok'); onUnban?.(); } catch (err) { errToast(err); } } }, f.label)
          : f.action === 'waf-assist'
            ? el('button.btn.sm.primary', { onclick: () => { const [policy, host, path, inst] = f.arg.split('|'); openWafAssistant({ policy, host, path, inst }); } }, f.label)
            : el('a.btn.sm', { href: f.href }, f.label),
        f.hint ? el('small.muted', null, f.hint) : null)))) : null,
    !compact && d.now ? nowView(d) : null);
}

function pipeline(steps) {
  if (!steps?.length) return null;
  return el('ol.pipe', { 'aria-label': 'Weg der Anfrage' }, steps.map(s => el('li.' + s.state, { title: s.detail || ({ passed: 'durchlaufen', not_reached: 'nicht mehr erreicht', served: 'ausgeliefert' })[s.state] || '' },
    el('span.ic', null, STATE_ICON[s.state] ?? ''), el('span', null, s.label))));
}

function nowView(d) {
  const n = d.now;
  // a backend/Caddy error is not "fine" just because Sentinel lets it through
  const passOnly = d.verdict === 'error' && n.state === 'ok';
  return el('section.diag-now.' + (passOnly ? 'info' : NOW_CLASS[n.state] || 'info'), null,
    el('div.row', null, el('b', null, 'Mit der aktuellen Konfiguration: ', passOnly ? 'Sentinel lässt weiterhin durch' : NOW_TITLE[n.state] || ''),
      d.simulate ? el('a.btn.sm', { href: d.simulate, style: { marginLeft: 'auto' } }, 'Im Simulator öffnen') : null),
    el('p', null, n.text),
    n.notes?.length ? el('ul.diag-notes', null, n.notes.map(x => el('li', null, x))) : null,
    n.steps?.length ? el('details', null, el('summary', null, 'Alle Prüfschritte der Simulation'),
      el('ul.tsteps', null, n.steps.map(s => el('li.' + s.result, null, el('span.ic', null, STEP_ICON[s.result] || '·'), el('b', null, s.label), el('span', null, s.detail || ({ pass: 'ok', skip: 'übersprungen' })[s.result] || ''))))) : null);
}
