// Form mode for site blocks: edit addresses, Sentinel policy, target
// (proxy, files, PHP, redirect, response), path routes, matchers with rules,
// TLS, headers and logging – with a live preview of the generated block and
// a diff against the current text. Unknown parts stay untouched.
import { el, mount, modal, field, toggle, select, linesInput, toast } from './ui.js';
import { seg } from './widgets.js';
import { createEditor } from './editor.js';
import { modelFromSite, siteFromModel, emptyModel } from './sitemodel.js';
import { lint } from './caddylint.js';
import { diffView } from './diff.js';
import { VALUES } from './caddydocs.js';

const MATCHER_TYPES = [['path', 'Pfad'], ['method', 'Methode'], ['client_ip', 'Client-IP'], ['remote_ip', 'Verbindungs-IP'], ['host', 'Host'], ['header', 'Header'], ['query', 'Query'], ['protocol', 'Protokoll'], ['path_regexp', 'Pfad (Regex)'], ['expression', 'Ausdruck (CEL)']];
const MATCHER_HINT = { path: '/admin/*', method: 'POST PUT', client_ip: 'private_ranges', remote_ip: '10.0.0.0/8', host: 'api.example.com', header: 'X-Requested-With XMLHttpRequest', query: 'debug=1', protocol: 'https', path_regexp: '^/u/[0-9]+$', expression: '{method} == "POST"' };

/**
 * @param {object} opts
 *   text, node      – existing block (or null for a new site)
 *   policies        – [{id,name}]
 *   onApply(text, where)
 */
export function openSiteForm({ text = '', node = null, policies = [], onApply }) {
  const isNew = !node;
  const parsed = node ? modelFromSite(text, node) : { model: emptyModel(), warnings: [] };
  const m = parsed.model;
  if (isNew) m.addresses = ['app.example.com'];
  const original = node ? text.slice(node.from, node.to) : '';
  const extra = { www: isNew, where: 'file' };

  const formBox = el('div.sf-form');
  const previewHost = el('div.sf-preview');
  const lintBox = el('div.sf-lint');
  const diffBox = el('div', { hidden: true });
  let tab = 'preview';
  const preview = createEditor({ value: '', readOnly: true });
  preview.setContext({ policies });
  previewHost.append(preview.el);

  function generated() {
    let out = siteFromModel(m);
    const primary = m.addresses.map(a => a.trim()).filter(Boolean)[0] || '';
    if (isNew && extra.www && primary && !primary.startsWith('www.') && !primary.startsWith('*') && !primary.startsWith(':') && !primary.includes('://') && /\./.test(primary)) {
      out += `\n\nwww.${primary} {\n\tredir https://${primary}{uri} permanent\n}`;
    }
    return out;
  }

  const refresh = () => {
    const g = generated();
    preview.setValue(g);
    const issues = lint(g, { policies }).filter(d => d.severity !== 'info' || /sentinel/.test(d.message));
    mount(lintBox, issues.length ? issues.map(d => el('div.' + d.severity, null, el('b', null, d.severity === 'error' ? 'Fehler' : d.severity === 'warning' ? 'Warnung' : 'Hinweis'), ' ', d.message)) : el('div.ok', null, '✓ Keine Auffälligkeiten'));
    if (!isNew) mount(diffBox, diffView({ [m.addresses[0] || 'Site']: [original, g] }));
  };

  // ------------------------------------------------------------ helpers
  const inp = (obj, k, attrs = {}) => el('input', { value: obj[k] ?? '', ...attrs, oninput: (e) => { obj[k] = e.target.value; refresh(); } });
  const tog = (obj, k, label) => toggle(!!obj[k], (v) => { obj[k] = v; refresh(); }, label);
  const section = (title, ...body) => el('section.sf-sec', null, el('h4', null, title), ...body);
  const rowList = (items, render, onAdd, addLabel) => {
    const box = el('div.sf-rows');
    const draw = () => mount(box, ...items.map((it, i) => el('div.sf-row', null, ...render(it, i, draw),
      el('button.icon-btn', { title: 'Entfernen', onclick: () => { items.splice(i, 1); draw(); refresh(); } }, '✕'))),
    el('button.btn.sm', { onclick: () => { items.push(onAdd()); draw(); refresh(); } }, addLabel));
    draw();
    return box;
  };

  // ------------------------------------------------------------ target
  const targetBox = el('div.stack');
  function drawTarget() {
    const h = m.handler;
    const t = h.type;
    let body = null;
    if (t === 'proxy') {
      if (!h.upstreams.length) h.upstreams = ['127.0.0.1:8080'];
      body = el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'Upstreams'), linesInput(h.upstreams, (v) => { h.upstreams = v; refresh(); drawTarget(); }, { rows: 2, placeholder: '127.0.0.1:8080\napp:3000\nhttps://backend.intern' }), el('small', null, 'Ein Backend pro Zeile – bei mehreren verteilt Caddy die Last.')),
        h.upstreams.length > 1 ? field('Verteilung', select([['', 'Standard (zufällig)'], ...VALUES.lb_policy.map(([v, d]) => [v, `${v} – ${d}`])], h.lb_policy, (v) => { h.lb_policy = v; refresh(); })) : null,
        field('Health-Check-Pfad', inp(h, 'health_uri', { placeholder: '/health' }), 'aktive Prüfung der Backends'),
        h.health_uri ? field('Intervall', inp(h, 'health_interval', { placeholder: '30s' })) : null,
        el('div.field', null, el('span', null, 'HTTPS zum Backend'), tog(h, 'https_backend', 'transport http { tls }')),
        h.https_backend ? el('div.field', null, el('span', null, 'Zertifikat'), tog(h, 'skip_verify', 'nicht prüfen ⚠')) : null,
        el('div.field', null, el('span', null, 'Host-Header'), tog(h, 'host_header', 'Host des Backends senden')),
        el('div.field.wide', null, el('span', null, 'Weitere Optionen im reverse_proxy-Block'), el('textarea.mono', {
          rows: Math.max(2, h.proxyExtra.length + 1), value: h.proxyExtra.join('\n'), placeholder: 'flush_interval -1\nheader_down -X-Powered-By',
          oninput: (e) => { h.proxyExtra = e.target.value.split('\n').filter(l => l.trim()); refresh(); },
        })));
    } else if (t === 'static' || t === 'spa' || t === 'php') {
      body = el('div.fields', null,
        field('Verzeichnis (root)', inp(h, 'root', { class: 'mono', placeholder: '/var/www/html' })),
        t === 'php' ? field('PHP-FPM', inp(h, 'php', { class: 'mono', placeholder: 'unix//run/php/php-fpm.sock' })) : null,
        el('div.field', null, el('span', null, 'Verzeichnislisten'), tog(h, 'browse', 'anzeigen')),
        t === 'spa' ? el('p.muted', null, 'Unbekannte Pfade liefern /index.html (try_files) – für React, Vue, Angular …') : null);
    } else if (t === 'redirect') {
      body = el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'Ziel'), inp(h, 'redirect_to', { class: 'mono', placeholder: 'https://example.com{uri}' })),
        field('Art', select([['permanent', '301 dauerhaft'], ['temporary', '302 vorübergehend'], ['308', '308 dauerhaft (Methode bleibt)'], ['307', '307 vorübergehend (Methode bleibt)'], ['html', 'per HTML-Seite']], h.redirect_code || 'temporary', (v) => { h.redirect_code = v; refresh(); })));
    } else if (t === 'respond') {
      body = el('div.fields', null,
        el('div.field.wide', null, el('span', null, 'Antworttext'), inp(h, 'body', { placeholder: 'OK' })),
        field('Status', inp(h, 'status', { placeholder: '200', inputmode: 'numeric' })));
    } else {
      body = el('p.muted', null, 'Kein Haupt-Ziel – Requests werden nur über Pfad-Routen, Regeln oder weitere Direktiven beantwortet.');
    }
    mount(targetBox,
      seg([['proxy', 'Reverse Proxy'], ['static', 'Statisch'], ['spa', 'Single-Page-App'], ['php', 'PHP'], ['redirect', 'Weiterleitung'], ['respond', 'Antwort'], ['none', 'Keins']], t, (v) => {
        h.type = v;
        if (v === 'redirect' && !h.redirect_to) h.redirect_to = 'https://example.com{uri}';
        drawTarget(); refresh();
      }),
      body);
  }
  drawTarget();

  // ------------------------------------------------------------ TLS
  const tlsBox = el('div');
  function drawTLS() {
    const tl = m.tls;
    mount(tlsBox, el('div.stack', null,
      seg([['auto', 'Automatisch (Let’s Encrypt)'], ['internal', 'Interne CA'], ['email', 'ACME mit E-Mail'], ['files', 'Eigenes Zertifikat']], tl.mode, (v) => { tl.mode = v; drawTLS(); refresh(); }),
      tl.mode === 'email' ? field('E-Mail', inp(tl, 'email', { placeholder: 'admin@example.com' })) : null,
      tl.mode === 'files' ? el('div.fields', null, field('Zertifikat', inp(tl, 'cert', { class: 'mono', placeholder: '/etc/ssl/site.crt' })), field('Schlüssel', inp(tl, 'key', { class: 'mono', placeholder: '/etc/ssl/site.key' }))) : null,
      tl.mode === 'internal' ? el('p.muted', null, 'Zertifikat von Caddys interner CA – Clients müssen deren Root vertrauen (siehe „Interne CA“).') : null));
  }
  drawTLS();

  // ------------------------------------------------------------ matchers & rules
  const rulesBox = el('div');
  function drawRules() {
    const names = m.matchers.map(x => x.name).filter(Boolean);
    mount(rulesBox,
      el('h5', null, 'Benannte Matcher'),
      rowList(m.matchers, (mm, i, redraw) => [
        el('input.mono', { value: mm.name, style: { width: '120px' }, placeholder: '@name', oninput: (e) => { mm.name = e.target.value.startsWith('@') ? e.target.value : '@' + e.target.value; refresh(); }, onchange: () => drawRules() }),
        el('div.stack', { style: { flex: 1, gap: '4px' } },
          rowList(mm.conds, (c) => [
            select(MATCHER_TYPES, c.type, (v) => { c.type = v; refresh(); }),
            el('label.row', { style: { gap: '4px', fontSize: '12px' } }, el('input', { type: 'checkbox', checked: c.not, onchange: (e) => { c.not = e.target.checked; refresh(); } }), 'nicht'),
            el('input.mono', { value: c.value, placeholder: MATCHER_HINT[c.type] || '', style: { flex: 1 }, oninput: (e) => { c.value = e.target.value; refresh(); } }),
          ], () => ({ type: 'path', value: '', not: false }), '+ Bedingung')),
      ], () => ({ name: '@neu' + (m.matchers.length + 1), conds: [{ type: 'path', value: '/admin/*', not: false }] }), '+ Matcher'),
      el('h5', null, 'Regeln für Matcher'),
      rowList(m.rules, (r) => [
        select([['', '– Matcher –'], ...names.map(n => [n, n])], r.matcher, (v) => { r.matcher = v; refresh(); }),
        select([['respond', 'antworten'], ['redirect', 'weiterleiten'], ['proxy', 'an Backend'], ['abort', 'Verbindung abbrechen']], r.action, (v) => { r.action = v; refresh(); }),
        r.action !== 'abort' ? el('input.mono', { value: r.value, style: { flex: 1 }, placeholder: { respond: '"Kein Zugriff" 403', redirect: 'https://example.com/login', proxy: 'admin-app:8080' }[r.action], oninput: (e) => { r.value = e.target.value; refresh(); } }) : el('span.grow'),
      ], () => ({ matcher: names[0] || '', action: 'respond', value: '403' }), '+ Regel'));
  }
  drawRules();

  // ------------------------------------------------------------ form
  mount(formBox,
    parsed.warnings.length ? el('div.callout.warn', null, parsed.warnings.join(' ')) : null,
    section('Adressen',
      linesInput(m.addresses, (v) => { m.addresses = v; refresh(); }, { rows: 2, placeholder: 'app.example.com\nhttp://intern.lan:8080' }),
      el('small.muted', null, 'Domain, auch mit Port oder http:// (ohne TLS). Wildcards wie *.example.com brauchen eine DNS-Challenge.'),
      isNew ? el('div', { style: { marginTop: '6px' } }, toggle(extra.www, (v) => { extra.www = v; refresh(); }, 'www-Variante auf die Domain weiterleiten')) : null),
    section('Schutz durch Sentinel',
      el('div.row', null, tog(m.sentinel, 'on', 'sentinel aktiv'),
        select([['', 'Policy automatisch (nach Host)'], ...policies.map(p => [p.id, p.name])], m.sentinel.policy, (v) => { m.sentinel.policy = v; refresh(); }))),
    section('Ziel', targetBox),
    section('Pfad-Routen',
      el('small.muted', null, 'Eigene Ziele für Pfade (handle). Mit „Präfix entfernen“ kommt /static/a.css beim Ziel als /a.css an.'),
      rowList(m.routes, (r) => [
        el('input.mono', { value: r.path, placeholder: '/api/*', style: { width: '120px' }, oninput: (e) => { r.path = e.target.value; refresh(); } }),
        el('label.row', { style: { gap: '4px', fontSize: '12px' }, title: 'handle_path' }, el('input', { type: 'checkbox', checked: r.strip, onchange: (e) => { r.strip = e.target.checked; refresh(); } }), 'Präfix entfernen'),
        select([['proxy', 'Backend'], ['static', 'Dateien'], ['respond', 'Antwort'], ['redirect', 'Weiterleitung']], r.type, (v) => { r.type = v; refresh(); }),
        el('input.mono', { value: r.target, style: { flex: 1 }, placeholder: 'api:3000 · /srv/static · "OK" · https://…', oninput: (e) => { r.target = e.target.value; refresh(); } }),
        el('input', { value: r.status, style: { width: '64px' }, placeholder: 'Status', oninput: (e) => { r.status = e.target.value; refresh(); } }),
      ], () => ({ path: '/api/*', strip: false, type: 'proxy', target: '127.0.0.1:3000', status: '' }), '+ Route')),
    section('Matcher & Regeln', rulesBox),
    section('TLS', tlsBox),
    section('Optionen',
      el('div.row', null, tog(m, 'encode', 'Kompression (zstd, gzip)'), toggle(m.headers.security, (v) => { m.headers.security = v; refresh(); }, 'Sicherheits-Header (HSTS, nosniff, Frame-Options, Referrer-Policy, ohne Server)')),
      el('h5', null, 'Eigene Header'),
      rowList(m.headers.custom, (h) => [
        el('input.mono', { value: h[0], placeholder: 'X-Robots-Tag', style: { width: '200px' }, oninput: (e) => { h[0] = e.target.value; refresh(); } }),
        el('input.mono', { value: h[1], placeholder: '"noindex"', style: { flex: 1 }, oninput: (e) => { h[1] = e.target.value; refresh(); } }),
      ], () => ['', ''], '+ Header'),
      el('h5', null, 'Zugriffs-Log'),
      el('div.row', null, tog(m.log, 'on', 'aktiv'), m.log.on ? inp(m.log, 'file', { class: 'mono', placeholder: '/var/log/caddy/site.log (leer = Standardausgabe)', style: { flex: 1 } }) : null, m.log.on ? tog(m.log, 'json', 'JSON') : null)),
    section('Weitere Direktiven',
      el('small.muted', null, 'Alles, was das Formular nicht kennt, bleibt hier unverändert erhalten (Plugins, import, komplexe Blöcke).'),
      el('textarea.mono', { rows: Math.max(3, m.extras.split('\n').length + 1), value: m.extras, oninput: (e) => { m.extras = e.target.value; refresh(); } })),
    isNew ? section('Einfügen', select([['file', 'Neue Datei sites/<domain>.caddy'], ['main', 'Ans Ende der Haupt-Caddyfile'], ['cursor', 'An der Cursor-Position']], extra.where, (v) => { extra.where = v; })) : null);

  const tabsEl = el('div.row', { style: { gap: '4px' } });
  const drawTabs = () => mount(tabsEl, seg([['preview', 'Ergebnis'], ...(isNew ? [] : [['diff', 'Änderungen']])], tab, (v) => { tab = v; previewHost.hidden = v !== 'preview'; diffBox.hidden = v !== 'diff'; }));
  drawTabs();

  const box = el('div.sf', null, formBox, el('div.sf-side', null, tabsEl, previewHost, diffBox, el('h5', null, 'Prüfung'), lintBox));
  refresh();
  modal(isNew ? 'Neue Site' : 'Site bearbeiten – ' + (m.addresses[0] || ''), box, {
    wide: true,
    actions: [{ label: 'Abbrechen' }, {
      label: isNew ? 'Einfügen' : 'Übernehmen', kind: 'primary', onClick: () => {
        if (!m.addresses.some(a => a.trim())) { toast('Mindestens eine Adresse angeben', 'bad'); return false; }
        const g = generated();
        if (!isNew && g === original) { toast('Keine Änderungen', 'info', 1500); return; }
        onApply(g, extra.where, m);
      },
    }],
  });
}
