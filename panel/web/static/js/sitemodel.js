// Site block <-> form model. Everything the form understands is turned into
// fields; everything else (plugins, complex blocks, imports, comments) is kept
// verbatim in `extras` and written back unchanged.
import { parse, siteAddresses } from './caddyfile.js';

export const SECURITY_HEADERS = [
  ['Strict-Transport-Security', '"max-age=31536000; includeSubDomains"'],
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'SAMEORIGIN'],
  ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  ['-Server', ''],
];

export function emptyModel() {
  return {
    addresses: [],
    sentinel: { on: true, policy: '' },
    tls: { mode: 'auto', email: '', cert: '', key: '' },
    encode: true,
    headers: { security: false, custom: [] },
    log: { on: false, file: '', json: true, roll: [] },
    handler: { type: 'proxy', upstreams: ['127.0.0.1:8080'], lb_policy: '', health_uri: '', health_interval: '', https_backend: false, skip_verify: false, host_header: false, proxyExtra: [], root: '/var/www/html', browse: false, php: 'unix//run/php/php-fpm.sock', redirect_to: '', redirect_code: 'permanent', body: '', status: '' },
    routes: [],
    matchers: [],
    rules: [],
    extras: '',
    comments: 0,
  };
}

const tv = (t) => t ? t.value : '';
const q = (s) => (s === '' || /[\s"{}#`]/.test(s) && !/^\{[^\s]*\}$/.test(s)) ? JSON.stringify(s) : s;
const isMatcherArg = (t) => t && !t.quoted && (t.value.startsWith('@') || (t.value.startsWith('/') && t.value !== '/'));
const MATCHER_TYPES = ['path', 'method', 'client_ip', 'remote_ip', 'host', 'header', 'query', 'protocol', 'path_regexp', 'expression'];

/**
 * Builds a model from a site block (text of the whole Caddyfile + node).
 * @returns {{model: object, warnings: string[]}}
 */
export function modelFromSite(text, node) {
  const m = emptyModel();
  const warnings = [];
  m.addresses = siteAddresses(node);
  m.sentinel.on = false;
  m.encode = false;
  m.handler = { ...m.handler, type: 'none', upstreams: [] };
  const extras = [];
  const keep = (n) => extras.push(rawSlice(text, n));
  let root = null, fileServer = null, tryFiles = null, php = null;

  for (const n of node.children || []) {
    const name = n.name, args = n.args, a0 = tv(args[0]);
    const block = n.children;
    switch (name) {
      case 'sentinel':
        if (block) { keep(n); break; }
        m.sentinel = { on: true, policy: a0 };
        continue;
      case 'tls':
        if (block) { keep(n); break; }
        if (a0 === 'internal') m.tls.mode = 'internal';
        else if (args.length === 2) { m.tls.mode = 'files'; m.tls.cert = a0; m.tls.key = tv(args[1]); }
        else if (a0.includes('@')) { m.tls.mode = 'email'; m.tls.email = a0; }
        else keep(n);
        continue;
      case 'encode':
        if (block || isMatcherArg(args[0])) { keep(n); break; }
        m.encode = true;
        continue;
      case 'header': {
        if (isMatcherArg(args[0])) { keep(n); break; }
        const raw = (ts) => ts.map(t => t.text).join(' ');
        const lines = block ? block.map(c => [c.tokens[0].text, raw(c.args), c]) : [[args[0]?.text || '', raw(args.slice(1)), n]];
        if (lines.some(([, , c]) => c.children || c.name === 'defer' || c.name === 'match')) { keep(n); break; }
        for (const [k, v] of lines) m.headers.custom.push([k, v]);
        continue;
      }
      case 'log': {
        if (!block && !args.length) { m.log = { on: true, file: '', json: false }; continue; }
        const out = block?.find(c => c.name === 'output');
        const fmt = block?.find(c => c.name === 'format');
        const others = (block || []).filter(c => c !== out && c !== fmt);
        if (args.length || others.length || (out && tv(out.args[0]) !== 'file') || (fmt && (tv(fmt.args[0]) !== 'json' || fmt.children))) { keep(n); break; }
        m.log = { on: true, file: out ? tv(out.args[1]) : '', json: !!fmt, roll: (out?.children || []).map(c => [c.tokens[0].text, ...c.args.map(a => a.text)].join(' ')) };
        if (out?.children?.some(c => c.children)) { m.log.on = false; keep(n); }
        continue;
      }
      case 'reverse_proxy': {
        if (isMatcherArg(args[0])) {
          if (args[0].value.startsWith('@') && !block && args.length === 2) { m.rules.push({ matcher: a0, action: 'proxy', value: tv(args[1]) }); continue; }
          keep(n); break;
        }
        if (m.handler.type !== 'none') { keep(n); break; }
        const h = { ...emptyModel().handler, type: 'proxy', upstreams: args.map(tv), proxyExtra: [] };
        for (const c of block || []) {
          if (c.name === 'to' && !c.children) h.upstreams.push(...c.args.map(tv));
          else if (['lb_policy', 'health_uri', 'health_interval'].includes(c.name) && !c.children && c.args.length === 1) h[c.name] = tv(c.args[0]);
          else if (c.name === 'header_up' && tv(c.args[0]) === 'Host' && tv(c.args[1]) === '{upstream_hostport}' && !c.children) h.host_header = true;
          else if (c.name === 'transport' && tv(c.args[0]) === 'http' && c.children && c.children.every(x => ['tls', 'tls_insecure_skip_verify'].includes(x.name) && !x.args.length)) {
            h.https_backend = c.children.some(x => x.name === 'tls');
            h.skip_verify = c.children.some(x => x.name === 'tls_insecure_skip_verify');
          } else h.proxyExtra.push(rawSlice(text, c));
        }
        m.handler = h;
        continue;
      }
      case 'root':
        if (args.length === 2 && a0 === '*' && !block) { root = n; continue; }
        if (args.length === 1 && !a0.startsWith('@') && !block) { root = n; continue; }
        keep(n); break;
      case 'file_server':
        if (block || isMatcherArg(args[0]) || (args.length && a0 !== 'browse')) { keep(n); break; }
        fileServer = n;
        continue;
      case 'try_files':
        if (!block && args.map(tv).join(' ') === '{path} /index.html') { tryFiles = n; continue; }
        keep(n); break;
      case 'php_fastcgi':
        if (block || isMatcherArg(args[0]) || args.length !== 1) { keep(n); break; }
        php = n;
        continue;
      case 'redir':
        if (isMatcherArg(args[0]) && args[0].value.startsWith('@') && args.length >= 2 && !block) { m.rules.push({ matcher: a0, action: 'redirect', value: args.slice(1).map(t => t.text).join(' ') }); continue; }
        if (!block && args.length >= 1 && !isMatcherArg(args[0]) && m.handler.type === 'none') {
          m.handler = { ...emptyModel().handler, type: 'redirect', upstreams: [], redirect_to: a0, redirect_code: tv(args[1]) || 'temporary' };
          continue;
        }
        keep(n); break;
      case 'respond':
        if (args[0]?.value?.startsWith?.('@') && !block) { m.rules.push({ matcher: a0, action: 'respond', value: args.slice(1).map(t => t.text).join(' ') }); continue; }
        if (!block && !isMatcherArg(args[0]) && m.handler.type === 'none') {
          const st = args.length === 2 ? tv(args[1]) : /^\d{3}$/.test(a0) ? a0 : '';
          const body = args.length === 2 || !/^\d{3}$/.test(a0) ? a0 : '';
          m.handler = { ...emptyModel().handler, type: 'respond', upstreams: [], body, status: st };
          continue;
        }
        keep(n); break;
      case 'abort':
        if (args[0]?.value?.startsWith('@') && args.length === 1 && !block) { m.rules.push({ matcher: a0, action: 'abort', value: '' }); continue; }
        keep(n); break;
      case 'handle':
      case 'handle_path': {
        const r = routeFromHandle(n);
        if (r) { m.routes.push(r); continue; }
        keep(n); break;
      }
      default:
        if (n.kind === 'matcher') {
          const mm = matcherFromNode(n);
          if (mm) { m.matchers.push(mm); continue; }
        }
        keep(n);
    }
  }

  // static / SPA / PHP from root + file_server (+ try_files / php_fastcgi)
  if (fileServer && root && m.handler.type === 'none') {
    m.handler = { ...emptyModel().handler, type: php ? 'php' : tryFiles ? 'spa' : 'static', upstreams: [], root: tv(root.args[root.args.length - 1]), browse: fileServer.args.some(a => a.value === 'browse'), php: php ? tv(php.args[0]) : emptyModel().handler.php };
  } else {
    for (const x of [root, fileServer, tryFiles, php]) if (x) extras.push(rawSlice(text, x));
  }

  // security header set
  // (only when names and values match exactly – otherwise they stay editable rows)
  const sec = SECURITY_HEADERS.every(([k, v]) => m.headers.custom.some(([h, hv]) => h === k && hv === v));
  if (sec) {
    m.headers.security = true;
    m.headers.custom = m.headers.custom.filter(([h, hv]) => !SECURITY_HEADERS.some(([k, v]) => k === h && v === hv));
  }

  // comments inside the block are kept as extras
  const { comments } = parse(text);
  const inner = comments.filter(c => c.from > node.open && c.from < node.close);
  m.comments = inner.length;
  if (inner.length) {
    warnings.push(`${inner.length} Kommentar${inner.length > 1 ? 'e' : ''} im Block landen unter „Weitere Direktiven“ (Position am Ende).`);
    for (const c of inner) extras.push(c.text);
  }
  m.extras = extras.join('\n');
  return { model: m, warnings };
}

function routeFromHandle(n) {
  const path = tv(n.args[0]);
  if (n.args.length !== 1 || !path.startsWith('/') || !n.children) return null;
  const kids = n.children;
  const r = { path, strip: n.name === 'handle_path', type: '', target: '', status: '' };
  if (kids.length === 1 && kids[0].name === 'reverse_proxy' && !kids[0].children && kids[0].args.length >= 1 && !isMatcherArg(kids[0].args[0])) {
    r.type = 'proxy'; r.target = kids[0].args.map(tv).join(' ');
  } else if (kids.length === 1 && kids[0].name === 'respond' && !kids[0].children && kids[0].args.length >= 1) {
    r.type = 'respond'; r.target = tv(kids[0].args[0]); r.status = tv(kids[0].args[1]);
  } else if (kids.length === 1 && kids[0].name === 'redir' && !kids[0].children && kids[0].args.length >= 1) {
    r.type = 'redirect'; r.target = tv(kids[0].args[0]); r.status = tv(kids[0].args[1]);
  } else if (kids.length === 2 && kids[0].name === 'root' && kids[1].name === 'file_server' && !kids[1].args.length && !kids[1].children) {
    r.type = 'static'; r.target = tv(kids[0].args[kids[0].args.length - 1]);
  } else return null;
  return r;
}

function matcherFromNode(n) {
  const conds = [];
  const fromTokens = (name, args) => {
    if (!MATCHER_TYPES.includes(name) && name !== 'not') return false;
    if (name === 'not') {
      const inner = args[0];
      if (!inner || !MATCHER_TYPES.includes(inner.value)) return false;
      conds.push({ type: inner.value, value: args.slice(1).map(a => a.quoted ? JSON.stringify(a.value) : a.value).join(' '), not: true });
      return true;
    }
    conds.push({ type: name, value: args.map(a => a.quoted ? JSON.stringify(a.value) : a.value).join(' '), not: false });
    return true;
  };
  if (n.children) {
    for (const c of n.children) if (c.children || !fromTokens(c.name, c.args)) return null;
  } else {
    if (!n.args.length || !fromTokens(n.args[0].value, n.args.slice(1))) return null;
  }
  return { name: n.name, conds };
}

/** Source text of a node from the start of its first line, dedented. */
export function rawSlice(text, n) {
  const ls = text.lastIndexOf('\n', n.from - 1) + 1;
  const raw = text.slice(ls, n.to);
  const indent = text.slice(ls, n.from);
  return raw.split('\n').map(l => l.startsWith(indent) ? l.slice(indent.length) : l.replace(/^[\t ]+/, '')).join('\n');
}

/** Generates the site block text from a model. */
export function siteFromModel(m) {
  const L = [];
  const I = '\t';
  const addrs = m.addresses.map(a => a.trim()).filter(Boolean);
  L.push(`${addrs.join(', ') || 'example.com'} {`);
  if (m.sentinel.on) L.push(I + 'sentinel' + (m.sentinel.policy ? ' ' + m.sentinel.policy : ''));
  switch (m.tls.mode) {
    case 'internal': L.push(I + 'tls internal'); break;
    case 'email': if (m.tls.email) L.push(I + 'tls ' + m.tls.email); break;
    case 'files': if (m.tls.cert && m.tls.key) L.push(I + `tls ${q(m.tls.cert)} ${q(m.tls.key)}`); break;
  }
  if (m.encode) L.push(I + 'encode zstd gzip');
  const hdrs = [...(m.headers.security ? SECURITY_HEADERS : []), ...m.headers.custom.filter(([k]) => k.trim())];
  if (hdrs.length === 1) L.push(I + 'header ' + hdrs[0][0] + (hdrs[0][1] ? ' ' + hdrs[0][1] : ''));
  else if (hdrs.length) {
    L.push(I + 'header {');
    for (const [k, v] of hdrs) L.push(I + I + k + (v ? ' ' + v : ''));
    L.push(I + '}');
  }
  if (m.log.on) {
    if (!m.log.file && !m.log.json) L.push(I + 'log');
    else {
      L.push(I + 'log {');
      if (m.log.file) {
        const roll = m.log.roll?.length ? m.log.roll : ['roll_size 50MiB', 'roll_keep 5'];
        L.push(I + I + `output file ${q(m.log.file)} {`, ...roll.map(r => I + I + I + r), I + I + '}');
      }
      if (m.log.json) L.push(I + I + 'format json');
      L.push(I + '}');
    }
  }
  for (const mm of m.matchers) {
    const conds = mm.conds.filter(c => c.type && c.value.trim());
    if (!conds.length) continue;
    const name = mm.name.startsWith('@') ? mm.name : '@' + mm.name;
    if (conds.length === 1) L.push(I + `${name} ${conds[0].not ? 'not ' : ''}${conds[0].type} ${conds[0].value.trim()}`);
    else {
      L.push(I + name + ' {');
      for (const c of conds) L.push(I + I + `${c.not ? 'not ' : ''}${c.type} ${c.value.trim()}`);
      L.push(I + '}');
    }
  }
  for (const r of m.rules) {
    if (!r.matcher) continue;
    switch (r.action) {
      case 'respond': L.push(I + `respond ${r.matcher} ${r.value || '403'}`); break;
      case 'redirect': L.push(I + `redir ${r.matcher} ${r.value}`); break;
      case 'proxy': L.push(I + `reverse_proxy ${r.matcher} ${r.value}`); break;
      case 'abort': L.push(I + `abort ${r.matcher}`); break;
    }
  }
  for (const r of m.routes) {
    if (!r.path) continue;
    L.push(I + `${r.strip ? 'handle_path' : 'handle'} ${r.path} {`);
    switch (r.type) {
      case 'proxy': L.push(I + I + 'reverse_proxy ' + r.target); break;
      case 'static': L.push(I + I + 'root * ' + q(r.target), I + I + 'file_server'); break;
      case 'respond': L.push(I + I + 'respond ' + q(r.target) + (r.status ? ' ' + r.status : '')); break;
      case 'redirect': L.push(I + I + 'redir ' + r.target + (r.status ? ' ' + r.status : '')); break;
    }
    L.push(I + '}');
  }
  const h = m.handler;
  switch (h.type) {
    case 'proxy': {
      const ups = h.upstreams.map(u => u.trim()).filter(Boolean);
      const opts = [];
      if (h.lb_policy) opts.push('lb_policy ' + h.lb_policy);
      if (h.health_uri) opts.push('health_uri ' + h.health_uri);
      if (h.health_interval) opts.push('health_interval ' + h.health_interval);
      if (h.host_header) opts.push('header_up Host {upstream_hostport}');
      if (h.https_backend || h.skip_verify) {
        opts.push('transport http {');
        if (h.https_backend) opts.push('\ttls');
        if (h.skip_verify) opts.push('\ttls_insecure_skip_verify');
        opts.push('}');
      }
      for (const x of h.proxyExtra || []) opts.push(...x.split('\n'));
      if (opts.length) {
        L.push(I + 'reverse_proxy ' + ups.join(' ') + ' {');
        for (const o of opts) L.push(I + I + o);
        L.push(I + '}');
      } else L.push(I + 'reverse_proxy ' + (ups.join(' ') || 'localhost:8080'));
      break;
    }
    case 'static': case 'spa': case 'php':
      L.push(I + 'root * ' + q(h.root || '/var/www/html'));
      if (h.type === 'spa') L.push(I + 'try_files {path} /index.html');
      if (h.type === 'php') L.push(I + 'php_fastcgi ' + (h.php || 'unix//run/php/php-fpm.sock'));
      L.push(I + 'file_server' + (h.browse ? ' browse' : ''));
      break;
    case 'redirect':
      L.push(I + 'redir ' + (h.redirect_to || 'https://example.com{uri}') + (h.redirect_code ? ' ' + h.redirect_code : ''));
      break;
    case 'respond':
      L.push(I + 'respond ' + q(h.body ?? '') + (h.status ? ' ' + h.status : ''));
      break;
  }
  if (m.extras.trim()) for (const l of m.extras.replace(/\s+$/, '').split('\n')) L.push(l.trim() ? I + l : '');
  L.push('}');
  return L.join('\n');
}
