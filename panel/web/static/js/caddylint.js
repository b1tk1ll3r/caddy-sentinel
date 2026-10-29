// Local checks for the Caddyfile editor. They run on every keystroke and
// complement Caddy's own validation (adapt) with hints Caddy does not give:
// typos with "did you mean", undefined/unused matchers, unreachable handlers,
// sites without Sentinel, plaintext basic-auth passwords and more.
//
// lint(text, ctx) -> [{ from, to, severity, message, fixes?: [{ name, changes: [{from,to,insert}] }] }]
import { parse, walk, siteAddresses, suggest } from './caddyfile.js';
import { GLOBAL, DIRECTIVES, MATCHERS, SUBS, STRICT_SUBS, DIRECTIVE_ORDER, DEPRECATED } from './caddydocs.js';

const KNOWN_DIRECTIVES = new Set([...Object.keys(DIRECTIVES), 'import', 'invoke', 'basicauth', 'skip_log']);
const ROUTE_LIKE = new Set(['site', 'routes', 'snippet', 'named_route']);

/**
 * @param {string} text
 * @param {{policies?: {id:string,name:string}[], snippets?: string[]}} ctx
 */
export function lint(text, ctx = {}) {
  const out = [];
  const { nodes, errors } = parse(text);
  const add = (severity, from, to, message, fixes) => out.push({ severity, from, to: Math.max(to, from + 1), message, fixes });
  for (const e of errors) add('error', e.from, e.to, e.message);

  const localSnippets = new Map(); // name -> node
  for (const n of nodes) if (n.kind === 'snippet') localSnippets.set(n.name.slice(1, -1), n);
  const knownSnippets = new Set([...localSnippets.keys(), ...(ctx.snippets || [])]);
  const policies = ctx.policies || null;

  const lineStartOf = (pos) => text.lastIndexOf('\n', pos - 1) + 1;
  const lineEndOf = (pos) => { const i = text.indexOf('\n', pos); return i < 0 ? text.length : i; };
  const deleteLine = (n) => {
    const a = lineStartOf(n.from);
    const b = Math.min(text.length, lineEndOf(n.to) + 1);
    return [{ from: a, to: b, insert: '' }];
  };
  const rename = (tok, to) => [{ from: tok.from, to: tok.to, insert: to }];

  // ------------------------------------------------------------ top level
  const seenAddr = new Map();
  for (const n of nodes) {
    if (n.kind === 'site') {
      for (const a of siteAddresses(n)) {
        const key = a.toLowerCase().replace(/^https?:\/\//, (m) => m.toLowerCase());
        if (seenAddr.has(key)) add('error', n.from, n.from + n.name.length, `Adresse „${a}“ ist bereits in Zeile ${seenAddr.get(key) + 1} definiert`);
        else seenAddr.set(key, n.line);
      }
      if (!n.children) add('warning', n.from, n.to, 'Site ohne Block – fehlt „{“?');
    }
    if (n.kind === 'global') lintGlobal(n);
    if (n.children && ROUTE_LIKE.has(n.kind)) lintRoutes(n, n);
    if (n.kind === 'site' && n.children) lintSiteExtras(n);
  }

  // ------------------------------------------------------------ global options
  function lintGlobal(g) {
    for (const o of g.children || []) {
      if (o.kind === 'matcher') continue;
      if (!GLOBAL[o.name]) {
        const s = suggest(o.name, Object.keys(GLOBAL));
        add('warning', o.from, o.from + o.name.length, `Unbekannte globale Option „${o.name}“` + (s ? ` – meintest du „${s}“?` : ' (Plugin?)'), s ? [{ name: `„${s}“ einsetzen`, changes: rename(o.tokens[0], s) }] : undefined);
        continue;
      }
      if (o.name === 'admin' && o.args[0]?.value === 'off') add('warning', o.from, o.to, '„admin off“ schaltet die Admin-API ab – das Sentinel-Panel kann Caddy dann nicht mehr steuern');
      if (o.children && STRICT_SUBS.has(o.name)) checkSubs(o, GLOBAL[o.name].sub || {});
    }
  }

  // ------------------------------------------------------------ directives in sites/snippets/handle blocks
  function lintRoutes(block, site) {
    const unmatched = [];
    for (const d of block.children || []) {
      if (d.kind === 'matcher') { lintMatcherDef(d); continue; }
      const name = d.name;
      if (DEPRECATED[name]) {
        add('info', d.from, d.from + name.length, `„${name}“ heißt seit Caddy 2.8 „${DEPRECATED[name]}“`, [{ name: `In „${DEPRECATED[name]}“ umbenennen`, changes: rename(d.tokens[0], DEPRECATED[name]) }]);
      } else if (!KNOWN_DIRECTIVES.has(name) && !name.startsWith('{')) {
        const s = suggest(name, [...KNOWN_DIRECTIVES]);
        add('warning', d.from, d.from + name.length, `Unbekannte Direktive „${name}“` + (s ? ` – meintest du „${s}“?` : ' – Tippfehler oder Plugin?'), s ? [{ name: `„${s}“ einsetzen`, changes: rename(d.tokens[0], s) }] : undefined);
      }
      if (name === 'import') lintImport(d);
      if (name === 'sentinel') lintSentinel(d);
      if (name === 'basic_auth' || name === 'basicauth') lintBasicAuth(d);
      if (name === 'reverse_proxy') lintProxy(d);
      if (d.children && STRICT_SUBS.has(name)) checkSubs(d, DIRECTIVES[name]?.sub || {});
      if (d.children && d.kind === 'routes') lintRoutes(d, site);
      // unmatched terminal handlers
      if (['redir', 'abort', 'error', 'respond', 'reverse_proxy', 'file_server'].includes(name) && !hasMatcher(d)) unmatched.push(d);
    }
    if (unmatched.length > 1) {
      unmatched.sort((a, b) => DIRECTIVE_ORDER.indexOf(a.name) - DIRECTIVE_ORDER.indexOf(b.name));
      const first = unmatched[0];
      for (const d of unmatched.slice(1)) {
        if (d.name === first.name) continue;
        add('warning', d.from, d.from + d.name.length, `„${d.name}“ wird nie erreicht: „${first.name}“ (Zeile ${first.line + 1}) beantwortet bereits alle Requests. Matcher oder handle-Blöcke verwenden.`);
      }
    }
  }

  function hasMatcher(d) {
    const a = d.args[0];
    if (!a || a.quoted) return false;
    if (a.value.startsWith('@')) return true;
    if (a.value === '*') return false;
    if (a.value.startsWith('/')) {
      // redir /old /new and respond /health 200 – a path matcher; redir <to> alone is not
      if (d.name === 'redir') return d.args.length >= 2 && !/^[0-9]{3}$|^(permanent|temporary|html)$/.test(d.args[1].value);
      return true;
    }
    return false;
  }

  function checkSubs(d, subs) {
    const names = Object.keys(subs);
    if (!names.length) return;
    for (const c of d.children) {
      if (c.name.startsWith('@') || c.name === 'import') continue;
      if (subs[c.name]) {
        if (c.name === 'transport' && c.children) checkSubs(c, SUBS.transport);
        if (c.name === 'tls_insecure_skip_verify') add('warning', c.from, c.to, 'Zertifikat des Upstreams wird nicht geprüft – Man-in-the-Middle möglich');
        continue;
      }
      // reverse_proxy: transport options directly in the block are a common mistake
      if (d.name === 'reverse_proxy' && SUBS.transport[c.name]) {
        add('error', c.from, c.from + c.name.length, `„${c.name}“ gehört in „transport http { … }“`);
        continue;
      }
      const s = suggest(c.name, names);
      add('warning', c.from, c.from + c.name.length, `„${c.name}“ ist keine Option von „${d.name}“` + (s ? ` – meintest du „${s}“?` : ''), s ? [{ name: `„${s}“ einsetzen`, changes: rename(c.tokens[0], s) }] : undefined);
    }
  }

  function lintMatcherDef(m) {
    // single line: @name <matcher> <args>; block: @name { <matcher> … }
    const check = (tok, node) => {
      if (!tok || tok.quoted || MATCHERS[tok.value] || tok.value === 'not') return;
      if (tok.value.startsWith('{') || tok.value.startsWith('`')) return; // CEL shorthand
      if (tok.value.startsWith('/')) {
        add('warning', tok.from, tok.to, `Matcher-Typ fehlt – meintest du „path ${tok.value}“?`, [{ name: `„path ${tok.value}“`, changes: [{ from: tok.from, to: tok.from, insert: 'path ' }] }]);
        return;
      }
      const s = suggest(tok.value, Object.keys(MATCHERS));
      add('warning', tok.from, tok.to, `Unbekannter Matcher „${tok.value}“` + (s ? ` – meintest du „${s}“?` : ''), s ? [{ name: `„${s}“ einsetzen`, changes: rename(tok, s) }] : undefined);
      void node;
    };
    if (m.children) for (const c of m.children) check(c.tokens[0], c);
    else check(m.args[0], m);
  }

  function lintImport(d) {
    const a = d.args[0];
    if (!a) { add('error', d.from, d.to, 'import ohne Ziel'); return; }
    const v = a.value;
    if (/[/.*]/.test(v) || a.quoted) return; // file pattern
    if (!knownSnippets.has(v)) {
      const s = suggest(v, [...knownSnippets]);
      add('error', a.from, a.to, `Snippet „${v}“ ist nicht definiert` + (s ? ` – meintest du „${s}“?` : '') + ' (definieren mit „(' + v + ') { … }“)', s ? [{ name: `„${s}“ einsetzen`, changes: rename(a, s) }] : undefined);
    }
  }

  function lintSentinel(d) {
    const a = d.args[0];
    if (!a || !policies) return;
    if (!policies.find(p => p.id === a.value)) {
      const s = suggest(a.value, policies.map(p => p.id), 3);
      add('error', a.from, a.to, `Policy „${a.value}“ gibt es nicht` + (s ? ` – meintest du „${s}“?` : ` (vorhanden: ${policies.map(p => p.id).join(', ')})`), s ? [{ name: `„${s}“ einsetzen`, changes: rename(a, s) }] : undefined);
    }
  }

  function lintBasicAuth(d) {
    for (const c of d.children || []) {
      const pw = c.args[c.args.length - 1];
      if (!pw) continue;
      const v = pw.value;
      if (/^\$2[aby]\$/.test(v) || /^\{.*\}$/.test(v) || v.startsWith('$argon') || v.startsWith('{$')) continue;
      add('error', pw.from, pw.to, 'Passwort muss als Hash angegeben werden – erzeugen mit „caddy hash-password“');
    }
  }

  function lintProxy(d) {
    for (const c of d.children || []) {
      if (c.name !== 'header_up') continue;
      const f = (c.args[0]?.value || '').replace(/^[+-]/, '');
      if (/^X-Forwarded-(For|Proto|Host)$/i.test(f) && !c.args[0].value.startsWith('-')) {
        add('info', c.from, c.to, `„${f}“ setzt Caddy automatisch – die Zeile ist überflüssig`, [{ name: 'Zeile entfernen', changes: deleteLine(c) }]);
      }
      if (/^Host$/i.test(f) && /^\{(host|http\.request\.host)\}$/.test(c.args[1]?.value || '')) {
        add('info', c.from, c.to, 'Caddy reicht den Host-Header ohnehin unverändert durch', [{ name: 'Zeile entfernen', changes: deleteLine(c) }]);
      }
    }
  }

  // ------------------------------------------------------------ per site
  function lintSiteExtras(site) {
    // named matchers: defined vs. used (scope: this site)
    const defs = new Map();
    const used = new Map();
    let imports = false;
    walk(site.children, (n) => {
      if (n.kind === 'matcher') defs.set(n.name, n);
      if (n.name === 'import') imports = true;
      for (const t of n.args) if (!t.quoted && /^@[\w-]+$/.test(t.value)) { if (!used.has(t.value)) used.set(t.value, []); used.get(t.value).push(t); }
    });
    for (const [name, toks] of used) {
      if (defs.has(name) || imports) continue;
      for (const t of toks) {
        const s = suggest(name, [...defs.keys()]);
        add('error', t.from, t.to, `Matcher „${name}“ ist in dieser Site nicht definiert` + (s ? ` – meintest du „${s}“?` : ''), s ? [{ name: `„${s}“ einsetzen`, changes: rename(t, s) }] : undefined);
      }
    }
    for (const [name, n] of defs) {
      if (!used.has(name)) add('warning', n.from, n.from + name.length, `Matcher „${name}“ wird nicht verwendet`, [{ name: 'Definition entfernen', changes: deleteLine(n) }]);
    }

    // sentinel present?
    let has = false;
    walk(site.children, (n) => {
      if (n.name === 'sentinel') has = true;
      if (n.name === 'import') {
        const sn = localSnippets.get(n.args[0]?.value);
        if (sn) walk(sn.children || [], (x) => { if (x.name === 'sentinel') has = true; });
        else if (n.args[0] && !/[/.*]/.test(n.args[0].value)) has = has || (ctx.sentinelSnippets || []).includes(n.args[0].value);
      }
    });
    const onlyRedirect = site.children.length > 0 && site.children.every(c => c.name === 'redir');
    if (!has && !onlyRedirect && site.children.length) {
      const first = site.children[0];
      const indent = first ? text.slice(lineStartOf(first.from), first.from) : '\t';
      add('info', site.from, site.from + site.name.length, 'Ohne „sentinel“: keine Policy, kein WAF, kein IDS und keine Metriken für diese Site',
        [{ name: '„sentinel“ einfügen', changes: [{ from: site.open + 1, to: site.open + 1, insert: '\n' + (indent || '\t') + 'sentinel' }] }]);
    }

    // file_server without root
    let root = false, fileServer = null;
    walk(site.children, (n) => { if (n.name === 'root') root = true; if (n.name === 'file_server' && !fileServer) fileServer = n; });
    if (fileServer && !root && !fileServer.children?.some(c => c.name === 'root')) {
      add('info', fileServer.from, fileServer.from + fileServer.name.length, '„file_server“ ohne „root“ liefert das Arbeitsverzeichnis von Caddy aus', [{ name: '„root * /var/www/html“ ergänzen', changes: [{ from: lineStartOf(fileServer.from), to: lineStartOf(fileServer.from), insert: text.slice(lineStartOf(fileServer.from), fileServer.from) + 'root * /var/www/html\n' }] }]);
    }
  }

  out.sort((a, b) => a.from - b.from);
  return out;
}
