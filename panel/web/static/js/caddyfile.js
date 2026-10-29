// Caddyfile tokenizer and parser (positions, nested blocks) shared by the
// editor (folding, breadcrumbs, completion context), the linter and the
// site form. Mirrors Caddy's lexer closely enough for editing purposes:
// "quoted" and `backtick` tokens, heredocs (<<MARK … MARK), # comments,
// line continuation with a trailing backslash.

/**
 * @typedef {{text:string, value:string, from:number, to:number, line:number, quoted:boolean, kind?:string}} Token
 * @typedef {{name:string, args:Token[], tokens:Token[], children:Node[]|null, line:number, endLine:number,
 *            from:number, to:number, open:number, close:number, parent:Node|null, depth:number, kind:string}} Node
 */

const ROUTE_CONTAINERS = new Set(['handle', 'handle_path', 'route', 'handle_errors', 'handle_response', 'intercept']);

/** Tokenizes text. Returns tokens plus newline markers ({nl:true}) and comments. */
export function tokenize(text) {
  const out = [];
  const comments = [];
  let i = 0, line = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '\n') { out.push({ nl: true, from: i, line }); line++; i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) {
      let j = text.indexOf('\n', i); if (j < 0) j = n;
      comments.push({ from: i, to: j, line, text: text.slice(i, j) });
      i = j; continue;
    }
    if (c === '\\' && (text[i + 1] === '\n' || (text[i + 1] === '\r' && text[i + 2] === '\n'))) {
      // line continuation
      i += text[i + 1] === '\n' ? 2 : 3; line++; continue;
    }
    const start = i, startLine = line;
    if (c === '"') {
      let j = i + 1, val = '';
      while (j < n && text[j] !== '"') {
        if (text[j] === '\\' && j + 1 < n) { val += text[j + 1]; j += 2; continue; }
        if (text[j] === '\n') line++;
        val += text[j]; j++;
      }
      out.push({ text: text.slice(start, Math.min(j + 1, n)), value: val, from: start, to: Math.min(j + 1, n), line: startLine, quoted: true, unterminated: j >= n });
      i = j + 1; continue;
    }
    if (c === '`') {
      let j = text.indexOf('`', i + 1);
      const unterminated = j < 0;
      if (j < 0) j = n - 1;
      const val = text.slice(i + 1, j);
      line += (val.match(/\n/g) || []).length;
      out.push({ text: text.slice(start, j + 1), value: val, from: start, to: j + 1, line: startLine, quoted: true, unterminated });
      i = j + 1; continue;
    }
    // heredoc
    const hd = /^<<([A-Za-z0-9_]+)[ \t]*\r?\n/.exec(text.slice(i, i + 80));
    if (hd) {
      const mark = hd[1];
      const bodyStart = i + hd[0].length;
      // the closing marker may be indented and followed by more tokens ("EOF 200")
      const re = new RegExp('^[ \\t]*' + mark + '(?=[ \\t]|$)', 'm');
      const rest = text.slice(bodyStart);
      const m = re.exec(rest);
      const end = m ? bodyStart + m.index + m[0].length : n;
      const val = m ? rest.slice(0, m.index).replace(/\n$/, '') : rest;
      line += (text.slice(i, end).match(/\n/g) || []).length;
      out.push({ text: text.slice(start, end), value: val, from: start, to: end, line: startLine, quoted: true, heredoc: true, unterminated: !m });
      i = end; continue;
    }
    let j = i;
    while (j < n && !/\s/.test(text[j])) j++;
    const w = text.slice(i, j);
    out.push({ text: w, value: w, from: i, to: j, line, quoted: false });
    i = j;
  }
  return { tokens: out, comments };
}

/** Parses text into a tree. Returns { nodes, errors, comments, lineCount }. */
export function parse(text) {
  const { tokens, comments } = tokenize(text);
  const errors = [];
  let p = 0;

  function readLine() {
    // tokens up to the next newline marker
    const ts = [];
    while (p < tokens.length && tokens[p].nl) p++;
    while (p < tokens.length && !tokens[p].nl) ts.push(tokens[p++]);
    return ts;
  }

  function block(parent, depth, open) {
    const nodes = [];
    while (p < tokens.length) {
      while (p < tokens.length && tokens[p].nl) p++;
      if (p >= tokens.length) break;
      const t = tokens[p];
      if (!t.quoted && t.text === '}') {
        if (!parent) { errors.push({ from: t.from, to: t.to, message: 'Schließende Klammer ohne öffnende' }); p++; continue; }
        p++;
        return { nodes, close: t };
      }
      const ts = readLine();
      if (!ts.length) continue;
      // a "}" at the end of a line closes the block
      let closeTok = null;
      const last = ts[ts.length - 1];
      if (ts.length > 1 && !last.quoted && last.text === '}' && parent) { closeTok = ts.pop(); }
      const node = { name: '', args: [], tokens: ts, children: null, line: ts[0].line, endLine: ts[ts.length - 1].line, from: ts[0].from, to: ts[ts.length - 1].to, open: -1, close: -1, parent, depth, kind: '' };
      const lt = ts[ts.length - 1];
      const opens = !lt.quoted && lt.text === '{';
      const head = opens ? ts.slice(0, -1) : ts;
      node.name = head.length ? head[0].value : '';
      node.args = head.slice(1);
      node.kind = kindOf(node, parent, depth);
      if (opens) {
        node.open = lt.from;
        const r = block(node, depth + 1, lt);
        node.children = r.nodes;
        if (r.close) { node.close = r.close.from; node.to = r.close.to; node.endLine = r.close.line; }
        else { node.to = text.length; node.endLine = text.split('\n').length - 1; }
      }
      nodes.push(node);
      if (closeTok) return { nodes, close: closeTok };
    }
    if (parent) errors.push({ from: open?.from ?? parent.from, to: (open?.to ?? parent.to), message: `Block „${parent.name || '{'}“ wird nicht geschlossen – „}“ fehlt` });
    return { nodes, close: null };
  }

  const r = block(null, 0, null);
  for (const t of tokens) if (!t.nl && t.unterminated) errors.push({ from: t.from, to: Math.min(t.from + 1, text.length), message: t.heredoc ? 'Heredoc wird nicht beendet' : 'Zeichenkette wird nicht geschlossen' });
  return { nodes: r.nodes, errors, comments, tokens };
}

function kindOf(node, parent, depth) {
  const name = node.name;
  if (depth === 0) {
    if (name === '' || name === '{') return 'global';
    if (name === 'import' && !node.tokens.some(t => !t.quoted && t.text === '{')) return 'import';
    if (name.startsWith('(') && name.endsWith(')')) return 'snippet';
    if (name.startsWith('&(')) return 'named_route';
    return 'site';
  }
  if (name.startsWith('@')) return 'matcher';
  if (parent && parent.kind === 'global') return 'option';
  if (ROUTE_CONTAINERS.has(name)) return 'routes';
  if (parent && (parent.kind === 'site' || parent.kind === 'routes' || parent.kind === 'snippet' || parent.kind === 'named_route')) return 'directive';
  return 'sub';
}

/** Walks all nodes depth-first. */
export function walk(nodes, fn) {
  for (const n of nodes) {
    fn(n);
    if (n.children) walk(n.children, fn);
  }
}

/** Innermost node (with block) that contains pos, plus the chain from the root. */
export function pathAt(nodes, pos) {
  const chain = [];
  let list = nodes;
  for (;;) {
    const n = list.find(x => x.from <= pos && pos <= x.to);
    if (!n) break;
    chain.push(n);
    if (!n.children || pos <= n.open || (n.close >= 0 && pos > n.close)) break;
    list = n.children;
  }
  return chain;
}

/** Site/global/snippet block containing pos (top-level node). */
export function topBlockAt(nodes, pos) {
  return nodes.find(n => n.from <= pos && pos <= n.to) || null;
}

/** Human readable label of a node for breadcrumbs. */
export function nodeLabel(n) {
  if (n.kind === 'global') return 'Globale Optionen';
  const args = n.args.map(a => a.text).join(' ');
  if (n.depth === 0) return [n.name, args].filter(Boolean).join(' ');
  return [n.name, args].filter(Boolean).join(' ').slice(0, 60);
}

/** Site addresses of a top-level site node. */
export function siteAddresses(n) {
  return [n.name, ...n.args.map(a => a.value)].join(' ').split(/[\s,]+/).filter(Boolean);
}

/** Levenshtein distance for did-you-mean hints. */
export function distance(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m || !n) return m || n;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[n];
}

export function suggest(word, candidates, max = 2) {
  let best = null, bd = Infinity;
  for (const c of candidates) {
    const d = distance(word, c);
    if (d < bd) { bd = d; best = c; }
  }
  return bd <= Math.max(1, Math.min(max, Math.floor(word.length / 3))) ? best : null;
}
