import { el, mount, get, post, del, qs, panel, tabs, empty, fmtInt, fmtCompact, fmtUntil, fmtAgo, fmtDateTime, ipLink, rangeState, toast, errToast, modal, field, select, confirmDialog, debounce, ACTIONS, actionLabel } from '../ui.js';
import { timeChart } from '../charts.js';
import { kpi, eventList, topTable, seg } from '../widgets.js';
import { bus } from '../app.js';

const SIGNAL_LABEL = {
  waf_block: 'WAF-Blocks', waf_detect: 'WAF-Treffer', honeypot: 'Honeypot', not_found: '404-Scans', auth_fail: 'Auth-Fehler', bad_request: 'Fehlerhafte Requests',
  scanner_ua: 'Scanner-Tool', rate_limit: 'Ratelimit', user_agent: 'Gesperrter UA', method: 'Unerlaubte Methode', ip_deny: 'IP-Sperrliste', burst: 'Request-Burst', body_limit: 'Body zu groß', geo_block: 'Geo-Sperre', feed_block: 'Threat-Feed', challenge: 'Bot-Challenge',
};

export async function render(root, _p, scope, q) {
  let tab = q.get('tab') || 'overview';
  const body = el('div.stack');
  const draw = () => {
    history.replaceState(null, '', '#/security' + (tab === 'overview' ? '' : '?tab=' + tab));
    mount(root, tabs([['overview', 'Lage'], ['events', 'Ereignisse'], ['bans', 'Sperren'], ['scores', 'Bedrohungs-Scores'], ['audit', 'Audit-Log']], tab, (t) => { tab = t; draw(); }), body);
    ({ overview, events, bans, scores, audit })[tab](body, scope);
  };
  const onRange = () => draw();
  rangeState.listeners.add(onRange);
  scope.on(() => rangeState.listeners.delete(onRange));
  draw();
}

async function overview(body, scope) {
  const q = qs({ range: rangeState.value });
  const [ov, sc, bansList, rules, paths] = await Promise.all([
    get('/stats/overview' + q, scope.signal), get('/security/scores?n=12', scope.signal), get('/bans', scope.signal),
    get('/stats/rules' + q + '&limit=10', scope.signal), get('/stats/top' + q + '&dim=path,ip&action=any&limit=10', scope.signal),
  ]);
  const c = ov.current;
  const series = [{ label: 'Blockiert', color: 'var(--series-4)', values: c.series.map(x => x.blocked) }];
  const st = window.__status || {};
  mount(body,
    st.ids_dry_run ? el('div.callout.warn', null, 'Das IDS läuft im Testmodus: Es meldet, sperrt aber niemanden. Umschalten unter ', el('a', { href: '#/settings' }, 'Einstellungen'), '.') : null,
    !st.ids_enabled ? el('div.callout.bad', null, 'Die automatische Bedrohungserkennung ist ausgeschaltet.') : null,
    el('div.kpis', null,
      kpi('Aktive Sperren', fmtInt(bansList.length), { kind: bansList.length ? 'warn' : '' }),
      kpi('Blockierte Requests', fmtCompact(c.blocked), { kind: c.blocked ? 'bad' : '' }),
      kpi('WAF blockiert', fmtCompact(c.by_action?.waf_block || 0)),
      kpi('WAF erkannt', fmtCompact(c.by_action?.waf_detect || 0)),
      kpi('Honeypot', fmtCompact(c.by_action?.honeypot || 0)),
      kpi('Ratelimit', fmtCompact((c.by_action?.rate_limit || 0) + (c.by_action?.rate_ban || 0))),
      kpi('Geo & Feeds', fmtCompact((c.by_action?.geo_block || 0) + (c.by_action?.feed_block || 0))),
      kpi('Bot-Challenges', fmtCompact(c.by_action?.challenge || 0), { sub: (c.by_action?.challenge_pass ? ` · ${fmtCompact(c.by_action.challenge_pass)} gelöst` : '') }),
      kpi('Beobachtete IPs', fmtInt(st.tracked_ips || 0))),
    el('div.grid.g-main', null,
      panel('Blockierte Requests', timeChart({ series, t: c.series.map(x => x.t), kind: 'bar', height: 200, yFormat: fmtCompact })),
      panel('Eingriffe nach Art', Object.keys(c.by_action || {}).length ? el('table', null, el('tbody', null,
        Object.entries(c.by_action).sort((a, b) => b[1] - a[1]).map(([a, n]) => el('tr', null, el('td', null, actionLabel(a)), el('td.num', null, fmtInt(n)))))) : empty('Keine Eingriffe'))),
    el('div.grid.g2', null,
      panel('Auffälligste Clients', scoreTable(sc), el('a', { href: '#/security?tab=scores' }, 'Alle')),
      panel('Häufigste WAF-Regeln', rules.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Regel'), el('th', null, 'Beschreibung'), el('th.num', null, 'Treffer'), el('th.num', null, 'Blockiert'), el('th', null, ''))),
        el('tbody', null, rules.map(r => el('tr', null, el('td.mono', null, r.id), el('td', null, el('span.trunc', { title: r.msg }, r.msg)),
          el('td.num', null, fmtInt(r.count)), el('td.num', null, fmtInt(r.blocked)),
          el('td', null, el('a', { href: '#/policies?exclude=' + r.id, title: 'Fehlalarm? Regel in einer Policy ausnehmen' }, 'ausnehmen'))))))) : empty('Keine WAF-Treffer'))),
    el('div.grid.g2', null,
      panel('Angegriffene Pfade', topTable(paths.path, { label: 'Pfad', onPick: (p) => { location.hash = '#/analytics?action=any&path=' + encodeURIComponent(p); } })),
      panel('Angreifende IPs', topTable(paths.ip, { label: 'IP', render: (ip) => el('span.mono', null, ip), onPick: (ip) => { location.hash = '#/ip/' + ip; } }))),
  );
}

function scoreTable(list) {
  if (!list.length) return empty('Keine auffälligen Clients', 'Scores entstehen durch WAF-Treffer, Scans, Honeypots, Auth-Fehler und mehr.');
  const th = (window.__settingsThreshold) || 100;
  return el('div.table-wrap', null, el('table', null,
    el('thead', null, el('tr', null, el('th', null, 'IP'), el('th', null, 'Score'), el('th', null, 'Signale'), el('th.num', null, 'Requests'), el('th', null, 'Zuletzt'))),
    el('tbody', null, list.map(s => el('tr.clickable', { onclick: () => { location.hash = '#/ip/' + s.ip; } },
      el('td', null, el('span.mono', null, s.ip)),
      el('td.nowrap', null, el('div.row', { style: { gap: '6px', flexWrap: 'nowrap' } }, el('div.score-meter', null, el('i' + (s.score >= th * .7 ? '.hot' : ''), { style: { width: Math.min(100, s.score / th * 100) + '%' } })), Math.round(s.score))),
      el('td', null, Object.entries(s.signals).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => el('span.badge', { style: { marginRight: '4px' } }, `${SIGNAL_LABEL[k] || k} ${Math.round(v)}`))),
      el('td.num', null, fmtInt(s.requests)),
      el('td.nowrap.muted', null, fmtAgo(s.last_seen)))))));
}

async function events(body, scope) {
  let type = '', minSev = 0, search = '';
  const box = el('div');
  let last = [];
  const load = async (more) => {
    const before = more && last.length ? last[last.length - 1].id : '';
    const evs = await get('/events' + qs({ type, min_sev: minSev || '', q: search, limit: 100, before }), scope.signal);
    last = more ? last.concat(evs) : evs;
    mount(box, eventList(last), evs.length === 100 ? el('button.btn', { onclick: () => load(true), style: { margin: '10px' } }, 'Ältere laden') : null);
  };
  mount(body, panel(null, el('div.stack', null,
    el('div.row', null,
      select([['', 'Alle Arten'], ['waf', 'WAF'], ['honeypot', 'Honeypot'], ['ban,unban', 'Sperren'], ['alert', 'Alarme'], ['ratelimit', 'Ratelimit'], ['useragent', 'User-Agent'], ['config', 'Konfiguration'], ['agent', 'Agent']], type, (v) => { type = v; load(); }),
      seg([[0, 'Alle'], [2, 'ab Mittel'], [3, 'ab Hoch']], 0, (v) => { minSev = v; load(); }),
      el('input', { type: 'search', placeholder: 'Suche in Ereignissen …', oninput: debounce((e) => { search = e.target.value; load(); }, 300) })),
    box)));
  await load();
  scope.listen(bus, 'event', () => load());
}

async function bans(body, scope) {
  const list = await get('/bans', scope.signal);
  const box = el('div');
  const unban = async (ip) => {
    if (!await confirmDialog('Sperre aufheben', `${ip} wird sofort wieder zugelassen und sein Bedrohungs-Score zurückgesetzt.`, 'Aufheben', 'primary')) return;
    try { await del('/bans/' + encodeURIComponent(ip)); toast(`${ip} entsperrt`, 'ok'); bans(body, scope); } catch (e) { errToast(e); }
  };
  mount(box, list.length ? el('div.table-wrap', null, el('table', null,
    el('thead', null, el('tr', null, el('th', null, 'IP / Netz'), el('th', null, 'Grund'), el('th', null, 'Quelle'), el('th', null, 'Seit'), el('th', null, 'Dauer'), el('th.num', null, 'Sperren gesamt'), el('th', null, ''))),
    el('tbody', null, list.map(b => el('tr', null,
      el('td', null, b.ip.includes('/') ? el('span.mono', null, b.ip) : ipLink(b.ip)),
      el('td', null, b.reason),
      el('td', null, el('span.badge' + (b.source === 'ids' ? '.bad' : b.source === 'manual' ? '.primary' : ''), null, { ids: 'IDS', manual: 'manuell', rate: 'Ratelimit' }[b.source] || b.source)),
      el('td.nowrap', { title: fmtDateTime(b.created * 1000) }, fmtAgo(b.created * 1000)),
      el('td.nowrap', null, fmtUntil(b.until)),
      el('td.num', null, b.bans || 1),
      el('td', null, el('button.btn.sm', { onclick: () => unban(b.ip) }, 'Aufheben'))))))) : empty('Keine aktiven Sperren', 'Gesperrte IPs erhalten sofort 403 auf allen Sites mit Sentinel.'));
  mount(body, panel(`Aktive Sperren (${list.length})`, box, el('button.btn.primary', { onclick: () => banDialog(() => bans(body, scope)) }, 'IP sperren')));
}

export function banDialog(onDone, ip = '') {
  let ipIn, dur, reason;
  modal('IP oder Netz sperren', [
    field('IP oder CIDR', ipIn = el('input', { value: ip, placeholder: '203.0.113.7 oder 198.51.100.0/24', required: true })),
    field('Dauer', dur = select([[3600, '1 Stunde'], [86400, '1 Tag'], [604800, '7 Tage'], [2592000, '30 Tage'], [0, 'dauerhaft']], 86400, () => { })),
    field('Grund', reason = el('input', { placeholder: 'z. B. Spam, Scraper …' })),
  ], {
    actions: [{ label: 'Abbrechen' }, {
      label: 'Sperren', kind: 'danger', onClick: async () => {
        await post('/bans', { ip: ipIn.value.trim(), seconds: +dur.value, reason: reason.value });
        toast(`${ipIn.value} gesperrt`, 'ok');
        onDone?.();
      },
    }],
  });
}

async function scores(body, scope) {
  const settings = await get('/settings', scope.signal);
  window.__settingsThreshold = settings.settings.ids.ban_threshold;
  const list = await get('/security/scores?n=200', scope.signal);
  mount(body, panel(`Bedrohungs-Scores (${list.length})`, el('div.stack', null,
    el('p.muted', null, `Jedes verdächtige Signal erhöht den Score einer IP; er halbiert sich alle ${Math.round(settings.settings.ids.half_life_seconds / 60)} Minuten. Ab ${settings.settings.ids.ban_threshold} Punkten sperrt das IDS die IP automatisch.`),
    scoreTable(list))));
}

async function audit(body, scope) {
  const evs = await get('/events?type=audit&limit=300', scope.signal);
  mount(body, panel('Audit-Log', el('div.stack', null,
    el('p.muted', null, 'Wer hat wann was geändert – inklusive An- und fehlgeschlagener Abmeldungen.'),
    evs.length ? el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, 'Zeit'), el('th', null, 'Aktion'), el('th', null, 'Benutzer'), el('th', null, 'IP'))),
      el('tbody', null, evs.map(e => {
        const d = e.detail || {};
        return el('tr', null,
          el('td.nowrap', { title: fmtDateTime(e.ts) }, fmtDateTime(e.ts)),
          el('td', null, e.severity >= 2 ? el('span.badge.warn', { style: { marginRight: '6px' } }, 'Warnung') : null, e.title.replace(/^[^:]+: /, '')),
          el('td', null, d.user || '–'),
          el('td.mono', null, d.ip || e.ip || ''));
      })))) : empty('Noch keine Einträge'))));
}
