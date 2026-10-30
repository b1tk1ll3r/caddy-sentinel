// Site wizard: a new site in three steps – kind, domain and target, check –
// including a DNS check before the certificate request would fail.
import { el, mount, get, post, modal, toast, errToast, field, toggle, select, instChip, instState, can } from './ui.js';

const KINDS = [
  ['proxy', 'Reverse Proxy', 'Leitet an eine Anwendung weiter (Docker-Container, Server im LAN …)'],
  ['static', 'Statische Dateien', 'Liefert HTML, Bilder, Downloads aus einem Verzeichnis'],
  ['php', 'PHP-Anwendung', 'PHP-FPM, z. B. WordPress, Nextcloud, Kimai'],
  ['redirect', 'Weiterleitung', 'Leitet alle Aufrufe auf eine andere Adresse um'],
];

const DNS_LABEL = { ok: ['ok', 'zeigt auf diesen Server'], mismatch: ['bad', 'zeigt woandershin'], missing: ['bad', 'kein DNS-Eintrag'], unknown: ['warn', 'nicht sicher prüfbar'], wildcard: ['warn', 'Wildcard'] };

export async function openSiteWizard({ onDone } = {}) {
  const pl = await get('/policies');
  const pols = pl.policies;
  const def = pols.find(p => p.id === pl.default) || null;
  const st = { kind: 'proxy', domains: '', upstream: '', root: '/srv/www/', php: 'unix//run/php/php-fpm.sock', target: 'https://', policy: '', www: false, internal: false, compress: true, monitor: true };
  let step = 1, preview = null, dns = null;
  const body = el('div.stack');
  const m = modal('Neue Site', body, { wide: true });
  const inst = instState.effective();
  const domains = () => st.domains.split(/[\s,]+/).map(d => d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '')).filter(Boolean);
  const internalHint = () => domains().some(d => /\.(local|lan|internal|home\.arpa|intern)$/.test(d.split(':')[0]) || !d.includes('.'));
  const req = (apply) => ({ ...st, domains: domains(), apply });

  const footer = (...btns) => el('div.row.wizard-foot', null, el('span.muted', null, `Schritt ${step} von 3`), el('span.grow'), ...btns);

  function draw() {
    if (step === 1) {
      mount(body,
        instState.multi() ? el('div.callout', null, 'Die Site wird auf ', instChip(inst, { always: true }), ' angelegt (oben auf der Seite umschaltbar).') : null,
        el('div.kind-grid', null, KINDS.map(([k, l, d]) => el('button.wiz-kind' + (st.kind === k ? '.on' : ''), { type: 'button', onclick: () => { st.kind = k; step = 2; draw(); } }, el('b', null, l), el('small', null, d)))),
        footer());
      return;
    }
    if (step === 2) {
      const kindFields = {
        proxy: field('Ziel', el('input.mono', { value: st.upstream, placeholder: '10.0.0.5:8080 oder http://app:3000', oninput: (e) => { st.upstream = e.target.value; } }), 'Mehrere Ziele mit Leerzeichen trennen (Lastverteilung).'),
        static: field('Verzeichnis', el('input.mono', { value: st.root, placeholder: '/srv/www/meine-site', oninput: (e) => { st.root = e.target.value; } }), 'Muss für den Benutzer caddy lesbar sein.'),
        php: [field('Verzeichnis', el('input.mono', { value: st.root, placeholder: '/srv/www/wordpress', oninput: (e) => { st.root = e.target.value; } })),
          field('PHP-FPM', el('input.mono', { value: st.php, oninput: (e) => { st.php = e.target.value; } }), 'Socket (unix//run/php/php8.3-fpm.sock) oder Adresse (127.0.0.1:9000)')],
        redirect: field('Ziel', el('input.mono', { value: st.target, placeholder: 'https://www.example.com', oninput: (e) => { st.target = e.target.value; } }), 'Pfad und Query bleiben erhalten (301).'),
      }[st.kind];
      const tlsToggle = el('div');
      const drawTls = () => mount(tlsToggle, toggle(st.internal, (v) => { st.internal = v; }, 'Zertifikat der internen CA (tls internal)'),
        internalHint() && !st.internal ? el('small.warn-text', null, ' – empfohlen: interne Namen bekommen kein öffentliches Zertifikat') : null);
      drawTls();
      mount(body,
        el('div.fields', null,
          el('div.field.wide', null, el('span', null, 'Domain(s)'), el('input.mono', { value: st.domains, placeholder: 'app.example.com', oninput: (e) => { st.domains = e.target.value; drawTls(); } }),
            el('small', null, 'Mehrere mit Komma. Für interne Dienste z. B. wiki.firma.local.')),
          kindFields,
          field('Policy', select([['', `Standard-Policy${def ? ' („' + def.name + '“)' : ''}`], ...pols.map(p => [p.id, p.name])], st.policy, (v) => { st.policy = v; }), 'Die Domains werden der Policy zugeordnet – Schutz ab der ersten Anfrage.')),
        el('div.stack', { style: { gap: '6px' } },
          st.kind !== 'redirect' ? toggle(st.www, (v) => { st.www = v; }, 'www-Variante anlegen und auf die Domain umleiten') : null,
          tlsToggle,
          st.kind !== 'redirect' ? toggle(st.compress, (v) => { st.compress = v; }, 'Komprimieren (zstd, gzip)') : null,
          st.kind !== 'redirect' && can('policy') ? toggle(st.monitor, (v) => { st.monitor = v; }, 'Verfügbarkeit überwachen (Monitor anlegen)') : null),
        footer(el('button.btn', { onclick: () => { step = 1; draw(); } }, 'Zurück'), el('button.btn.primary', { onclick: next }, 'Weiter: prüfen')));
      return;
    }
    // step 3
    const okDNS = !dns || dns.every(d => d.status === 'ok' || d.status === 'unknown' || (st.internal && d.status !== 'mismatch'));
    mount(body,
      el('h4', { style: { margin: 0 } }, 'DNS'),
      el('div.table-wrap', null, el('table', null, el('tbody', null, (dns || []).map(d => {
        const [k, l] = DNS_LABEL[d.status] || ['', d.status];
        return el('tr', null, el('td.mono', null, d.domain), el('td', null, el('span.badge.' + k, null, l)), el('td', null, d.resolved.length ? el('span.mono', null, d.resolved.join(', ')) : '–', d.cname ? el('small.muted', null, ' (CNAME ' + d.cname + ')') : null, el('div', null, el('small.muted', null, d.message))));
      })))),
      !okDNS ? el('div.callout.warn', null, 'Mindestens eine Domain zeigt nicht auf diesen Server. Caddy legt die Site trotzdem an, das Zertifikat klappt aber erst, wenn der DNS-Eintrag stimmt.') : null,
      el('h4', { style: { margin: '6px 0 0' } }, preview.mode === 'file' ? 'Neue Datei ' + preview.file : 'Wird an ' + preview.file + ' angehängt'),
      el('pre.block', { style: { maxHeight: '260px' } }, preview.content),
      preview.validation?.ok === false ? el('div.callout.bad', null, 'Caddy meldet einen Fehler: ', preview.validation.error || (preview.validation.diagnostics || []).map(d => d.message).join('; ') || 'ungültig') : el('div.callout.ok', null, 'Caddy hat die Konfiguration geprüft – sie ist gültig.'),
      footer(el('button.btn', { onclick: () => { step = 2; draw(); } }, 'Zurück'),
        can('config') ? el('button.btn.primary', { disabled: preview.validation?.ok === false, onclick: create }, 'Site anlegen') : el('span.muted', null, 'Anlegen erfordert die Rolle Bearbeiter')));
  }

  async function next(e) {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      if (!domains().length) throw new Error('Domain fehlt');
      [preview, dns] = await Promise.all([post('/sites/wizard', req(false)), get('/sites/dnscheck?domains=' + encodeURIComponent(domains().join(',')))]);
      step = 3; draw();
    } catch (err) { errToast(err); btn.disabled = false; }
  }

  async function create(e) {
    e.currentTarget.disabled = true;
    try {
      const r = await post('/sites/wizard', req(true));
      if (r.validation && r.validation.ok === false) throw new Error('Caddy hat die Konfiguration abgelehnt');
      if (st.monitor && st.kind !== 'redirect' && can('policy')) {
        const d = domains()[0];
        const scheme = d.includes(':') && !st.internal ? 'http://' : 'https://';
        await post('/monitors', { name: d, url: scheme + d + '/', interval_s: 60, timeout_s: 10, expect_status: '', keyword: '', insecure: st.internal, enabled: true }).catch(() => { });
      }
      m.close();
      toast(`${domains()[0]} ist angelegt – Caddy hat die Konfiguration geladen`, 'ok', 6000);
      onDone?.();
    } catch (err) { errToast(err); e.currentTarget && (e.currentTarget.disabled = false); }
  }

  draw();
}
