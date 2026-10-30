// Global search (Ctrl+K / Cmd+K): pages and settings, hosts, IPs, error
// page references, policies and rules, accounts, instances, saved views.
import { el, mount, get, debounce, can } from './ui.js';

const PAGES = [
  ['Übersicht', '#/', 'Dashboard Warnungen'],
  ['Live-Traffic', '#/live', 'Stream Anfragen live'],
  ['Analysen', '#/analytics', 'Requests Statistik Explorer'],
  ['Fehleranalyse', '#/failures', 'Referenz warum blockiert 403 502'],
  ['Sites', '#/sites', 'Domains Hosts Site-Assistent neue Site'],
  ['Request-Fluss', '#/flow', 'Simulator Trace'],
  ['Verfügbarkeit', '#/uptime', 'Monitore Uptime'],
  ['Zertifikate', '#/certs', 'TLS ACME Ablauf'],
  ['Interne CA', '#/pki', 'PKI ACME-Server'],
  ['Caddy-Instanzen', '#/instances', 'Server Agent verbinden'],
  ['Caddyfile-Editor', '#/editor', 'Konfiguration bearbeiten'],
  ['Policies', '#/policies', 'Regeln WAF Wartung Bots'],
  ['Regelsätze', '#/rulesets', 'WAF Regeln'],
  ['Sicherheit', '#/security', 'Sperren Bans IDS Ereignisse'],
  ['Site-Login', '#/access', 'Anmeldung AD OAuth Konten'],
  ['Site-Login › Konten', '#/access?tab=users', 'Zugangskonten Benutzer anlegen'],
  ['Site-Login › Zugriffstokens', '#/access?tab=tokens', 'Bearer Token Skript'],
  ['Site-Login › Self-Service', '#/access?tab=selfservice', 'Passwort vergessen zurücksetzen Wiederherstellungscodes Kontoseite neues Handy'],
  ['Site-Login › OAuth / OIDC', '#/access?tab=oauth', 'Microsoft Entra Google Keycloak GitHub'],
  ['Site-Login › Verzeichnis', '#/access?tab=directory', 'Active Directory LDAP SSO'],
  ['Threat-Feeds', '#/feeds', 'Listen Blocklist'],
  ['WAF-Tester', '#/waf', 'Testen Regel'],
  ['Einstellungen', '#/settings', 'Konfiguration'],
  ['Einstellungen › Benachrichtigungen', '#/settings?tab=alerts', 'Webhook Teams Matrix ntfy Telegram E-Mail stummschalten'],
  ['Einstellungen › API-Tokens', '#/settings?tab=tokens', 'Bearer Token API Automatisierung'],
  ['Einstellungen › Über & Lizenzen', '#/settings?tab=about', 'Lizenz Apache Open Source Drittanbieter Version GeoIP Quellenangabe'],
  ['Einstellungen › Benutzer', '#/settings?tab=users', 'Panel Rollen'],
  ['Einstellungen › Netz & Vertrauen', '#/settings?tab=network', 'vertrauenswürdig GeoIP Proxy'],
];

const KIND = { page: 'Seite', request: 'Anfrage', ip: 'IP', host: 'Host', policy: 'Policy', rule: 'Regel', ruleset: 'Regelsatz', instance: 'Instanz', account: 'Konto', user: 'Benutzer', feed: 'Feed', monitor: 'Monitor', temp: 'Befristet', view: 'Ansicht' };

let open = null;

export function openSearch() {
  if (!document.querySelector('.shell')) return; // not signed in
  if (open) { open.input.focus(); return; }
  let sel = 0, hits = [], seq = 0;
  const input = el('input.search-input', { type: 'search', placeholder: 'Suchen: Host, IP, Referenz (ABCD-EFGH), Policy, Regel, Konto, Seite …', 'aria-label': 'Suche', autocomplete: 'off', spellcheck: 'false' });
  const list = el('ul.search-list', { role: 'listbox' });
  const hint = el('div.search-hint', null, '↑↓ auswählen · Enter öffnen · Esc schließen');
  const box = el('div.search-box', { role: 'dialog', 'aria-label': 'Suche' }, input, list, hint);
  const wrap = el('div.search-wrap', { onmousedown: (e) => { if (e.target === wrap) close(); } }, box);
  const close = () => { wrap.remove(); open = null; };
  const go = (h) => { if (!h) return; close(); if (location.hash === h.href) window.dispatchEvent(new HashChangeEvent('hashchange')); location.hash = h.href; };
  const draw = () => {
    mount(list, hits.length ? hits.map((h, i) => el('li' + (i === sel ? '.sel' : ''), {
      role: 'option', 'aria-selected': i === sel ? 'true' : 'false',
      onmouseenter: () => { sel = i; draw(); }, onclick: () => go(h),
    }, el('span.kind', null, KIND[h.kind] || h.kind), el('span.t', null, h.title), h.sub ? el('span.s', null, h.sub) : null)) : el('li.none', null, input.value.trim().length < 2 ? 'Mindestens zwei Zeichen eingeben' : 'Nichts gefunden'));
    list.querySelector('.sel')?.scrollIntoView({ block: 'nearest' });
  };
  const search = debounce(async () => {
    const q = input.value.trim();
    const my = ++seq;
    const lq = q.toLowerCase();
    const pages = q.length >= 2 ? PAGES.filter(([t, , k]) => (t + ' ' + k).toLowerCase().includes(lq)).filter(([t]) => !t.includes('Benutzer') || can('admin'))
      .map(([t, href]) => ({ kind: 'page', title: t, href })) : [];
    hits = pages.slice(0, 5);
    sel = 0;
    draw();
    if (q.length < 2) return;
    try {
      const r = await get('/search?q=' + encodeURIComponent(q));
      if (my !== seq) return;
      hits = [...r.hits, ...pages].slice(0, 40);
      draw();
    } catch { /* keep page hits */ }
  }, 160);
  input.addEventListener('input', search);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { sel = Math.min(hits.length - 1, sel + 1); draw(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { sel = Math.max(0, sel - 1); draw(); e.preventDefault(); }
    else if (e.key === 'Enter') { go(hits[sel]); e.preventDefault(); }
    else if (e.key === 'Escape') { close(); e.preventDefault(); }
  });
  document.body.append(wrap);
  open = { input };
  draw();
  setTimeout(() => input.focus(), 10);
}

export function installSearchKey() {
  document.addEventListener('keydown', (e) => {
    const mac = /Mac|iPhone|iPad/.test(navigator.platform || '');
    // on macOS Ctrl+K belongs to the editor (delete to line end): use Cmd+K there
    if ((mac ? e.metaKey : e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openSearch(); }
    else if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) && !document.activeElement?.isContentEditable && !document.querySelector('.modal-wrap')) { e.preventDefault(); openSearch(); }
  });
}
