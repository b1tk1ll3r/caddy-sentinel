// Caddyfile editor based on CodeMirror 6 (vendor/codemirror.js).
// Syntax highlighting, folding, bracket matching, multiple cursors,
// context-aware completion with value hints, hover docs, local lint rules
// with quick fixes, server diagnostics, go-to-definition and renaming.
import {
  EditorState, Compartment,
  EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection, dropCursor,
  rectangularSelection, crosshairCursor, highlightSpecialChars, hoverTooltip, scrollPastEnd, Prec,
  history, historyKeymap, defaultKeymap, indentWithTab,
  StreamLanguage, syntaxHighlighting, HighlightStyle, bracketMatching, foldGutter, foldKeymap, foldService,
  indentOnInput, indentUnit, foldAll, unfoldAll, codeFolding,
  search, searchKeymap, openSearchPanel, highlightSelectionMatches, gotoLine,
  autocompletion, closeBrackets, closeBracketsKeymap, completionKeymap, snippet, snippetCompletion, startCompletion,
  linter, lintGutter, lintKeymap, forceLinting, openLintPanel,
  tags as t,
} from '../vendor/codemirror.js';
import { el } from './ui.js';
import { GLOBAL, DIRECTIVES, MATCHERS, PLACEHOLDERS, SUBS, SNIPPETS, VALUES, STATUS, STATUS_DIRECTIVES, HEADERS, HEADER_DIRECTIVES, DOC_LINK } from './caddydocs.js';
import { parse, pathAt, nodeLabel, walk } from './caddyfile.js';
import { lint } from './caddylint.js';

const ROUTE_CONTAINERS = new Set(['handle', 'handle_path', 'route', 'handle_errors', 'handle_response', 'intercept']);
const ROUTE_LIKE = new Set(['site', 'routes', 'snippet', 'named_route']);

// ---------------------------------------------------------------- parse cache

const parseCache = new WeakMap();
function parsed(state) {
  let r = parseCache.get(state.doc);
  if (!r) { r = parse(state.doc.toString()); parseCache.set(state.doc, r); }
  return r;
}

/** Block stack at pos as [{kind, name}] (only blocks whose "{" is before pos). */
function stackAt(state, pos) {
  const chain = pathAt(parsed(state).nodes, pos);
  const out = [];
  for (const n of chain) {
    if (!n.children || pos <= n.open || (n.close >= 0 && pos > n.close)) continue;
    let kind = n.kind;
    if (kind === 'option' || kind === 'sub') kind = 'directive';
    if (n.name === 'transport') kind = 'transport';
    out.push({ kind, name: n.name, node: n });
  }
  return out;
}

// ---------------------------------------------------------------- language

function blockKind(head, stack) {
  const top = stack[stack.length - 1];
  if (!top) {
    if (!head) return 'global';
    if (head.startsWith('(')) return 'snippet';
    if (head.startsWith('&(')) return 'named_route';
    return 'site';
  }
  if (head && head.startsWith('@')) return 'matcher';
  if (top.kind === 'global') return 'option';
  if (head && ROUTE_CONTAINERS.has(head)) return 'routes';
  if (ROUTE_LIKE.has(top.kind)) return 'directive';
  return 'sub';
}

function classify(w, isFirst, stack) {
  const top = stack[stack.length - 1];
  if (isFirst) {
    if (!top) return w === 'import' ? 'dir' : w.startsWith('(') || w.startsWith('&(') ? 'snippet' : 'site';
    if (w.startsWith('@')) return 'matcher';
    if (top.kind === 'global') return GLOBAL[w] ? 'dir' : 'unknown';
    if (top.kind === 'matcher') return MATCHERS[w] || w === 'not' ? 'sub' : 'unknown';
    if (ROUTE_LIKE.has(top.kind)) return DIRECTIVES[w] || w === 'import' || w === 'invoke' ? 'dir' : 'unknown';
    return 'sub';
  }
  if (w.startsWith('@')) return 'matcher';
  if (/^\{[^}]*\}$/.test(w) || /^\{\$/.test(w)) return 'ph';
  if (/^-?\d+(\.\d+)?(ms|s|m|h|d|KB|MB|GB|KiB|MiB|GiB|B|xx)?$/.test(w)) return 'num';
  if (/^(https?|unix|tcp|udp|h2c):\/?\//.test(w) || /^[\w.-]+:\d+$/.test(w)) return 'addr';
  if (/^\*?\/[^\s]*$/.test(w) || w === '*') return 'path';
  return null;
}

const caddyLang = StreamLanguage.define({
  name: 'caddyfile',
  startState: () => ({ stack: [], first: true, head: null, backtick: false, heredoc: null, heredocNext: null }),
  copyState: (s) => ({ ...s, stack: s.stack.slice() }),
  token(stream, st) {
    if (stream.sol()) {
      st.first = true; st.head = null;
      if (st.heredocNext) { st.heredoc = st.heredocNext; st.heredocNext = null; }
    }
    if (st.heredoc) {
      const m = stream.string.match(new RegExp('^\\s*' + st.heredoc + '(?=\\s|$)'));
      if (stream.sol() && m) { stream.pos = m[0].length; st.heredoc = null; st.first = false; return 'str'; }
      stream.skipToEnd(); return 'str';
    }
    if (st.backtick) {
      if (stream.skipTo('`')) { stream.next(); st.backtick = false; } else stream.skipToEnd();
      return 'str';
    }
    if (stream.eatSpace()) return null;
    const ch = stream.peek();
    if (ch === '#' && (stream.pos === 0 || /\s/.test(stream.string[stream.pos - 1]))) { stream.skipToEnd(); return 'comment'; }
    if (ch === '"') {
      stream.next();
      let esc = false;
      while (!stream.eol()) { const c = stream.next(); if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === '"') break; }
      if (st.first) st.head = '"';
      st.first = false;
      return 'str';
    }
    if (ch === '`') {
      stream.next();
      if (stream.skipTo('`')) stream.next(); else { stream.skipToEnd(); st.backtick = true; }
      st.first = false;
      return 'str';
    }
    const hd = stream.match(/^<<([A-Za-z0-9_]+)\s*$/);
    if (hd) { st.heredocNext = hd[1]; st.first = false; return 'str'; }
    stream.match(/^\S+/);
    const w = stream.current();
    if (w === '{') { st.stack.push({ kind: blockKind(st.head, st.stack), name: st.head || '' }); st.first = false; return 'brace'; }
    if (w === '}') { st.stack.pop(); st.first = false; return 'brace'; }
    const isFirst = st.first;
    st.first = false;
    if (isFirst) st.head = w;
    return classify(w, isFirst, st.stack);
  },
  blankLine(st) { st.first = true; st.head = null; if (st.heredocNext) { st.heredoc = st.heredocNext; st.heredocNext = null; } },
  indent(st, textAfter, cx) {
    if (st.heredoc || st.backtick) return null;
    return Math.max(0, st.stack.length - (/^\s*\}/.test(textAfter) ? 1 : 0)) * cx.unit;
  },
  languageData: {
    commentTokens: { line: '#' },
    closeBrackets: { brackets: ['{', '"', '`'] },
    indentOnInput: /^\s*\}$/,
  },
  tokenTable: {
    site: t.heading, snippet: t.macroName, dir: t.keyword, sub: t.propertyName, unknown: t.invalid,
    matcher: t.labelName, ph: t.special(t.variableName), num: t.number, addr: t.url, path: t.attributeValue,
    str: t.string, comment: t.lineComment, brace: t.brace,
  },
});

const highlight = HighlightStyle.define([
  { tag: t.heading, color: 'var(--tk-site)', fontWeight: '600' },
  { tag: t.macroName, color: 'var(--tk-matcher)', fontWeight: '600' },
  { tag: t.keyword, color: 'var(--tk-dir)', fontWeight: '600' },
  { tag: t.propertyName, color: 'var(--tk-sub)' },
  { tag: t.invalid, color: 'var(--tk-unknown)', textDecoration: 'underline dotted' },
  { tag: t.labelName, color: 'var(--tk-matcher)' },
  { tag: t.special(t.variableName), color: 'var(--tk-ph)' },
  { tag: t.number, color: 'var(--tk-num)' },
  { tag: t.url, color: 'var(--tk-site)' },
  { tag: t.attributeValue, color: 'var(--tk-path)' },
  { tag: t.string, color: 'var(--tk-str)' },
  { tag: t.lineComment, color: 'var(--tk-comment)', fontStyle: 'italic' },
  { tag: t.brace, color: 'var(--muted)' },
]);

// folding: every "{ … }" block, based on the parser
const caddyFold = foldService.of((state, lineStart, lineEnd) => {
  const { nodes } = parsed(state);
  let found = null;
  walk(nodes, (n) => {
    if (found || !n.children || n.open < lineStart || n.open > lineEnd || n.close < 0) return;
    const closeLine = state.doc.lineAt(n.close);
    if (closeLine.number <= state.doc.lineAt(n.open).number) return;
    found = { from: n.open + 1, to: n.close };
  });
  return found;
});

const theme = EditorView.theme({
  '&': { height: '100%', backgroundColor: 'var(--ed-bg)', color: 'var(--ink)', fontSize: '13px' },
  '.cm-scroller': { fontFamily: 'var(--mono)', lineHeight: '20px' },
  '.cm-content': { padding: '8px 0', caretColor: 'var(--ink)' },
  '.cm-gutters': { backgroundColor: 'var(--surface-2)', color: 'var(--muted)', borderRight: '1px solid var(--line-2)' },
  '.cm-activeLine': { backgroundColor: 'color-mix(in srgb, var(--primary) 6%, transparent)' },
  '.cm-activeLineGutter': { backgroundColor: 'color-mix(in srgb, var(--primary) 10%, transparent)', color: 'var(--ink)' },
  '&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection': { backgroundColor: 'color-mix(in srgb, var(--primary) 25%, transparent) !important' },
  '.cm-cursor': { borderLeftColor: 'var(--ink)' },
  '.cm-matchingBracket': { backgroundColor: 'color-mix(in srgb, var(--ok) 25%, transparent)', outline: '1px solid color-mix(in srgb, var(--ok) 50%, transparent)' },
  '.cm-nonmatchingBracket': { backgroundColor: 'var(--bad-soft)' },
  '.cm-selectionMatch': { backgroundColor: 'color-mix(in srgb, var(--warn) 20%, transparent)' },
  '.cm-searchMatch': { backgroundColor: 'color-mix(in srgb, var(--warn) 30%, transparent)', outline: '1px solid var(--warn)' },
  '.cm-searchMatch-selected': { backgroundColor: 'color-mix(in srgb, var(--primary) 30%, transparent)' },
  '.cm-foldPlaceholder': { background: 'var(--surface-3)', border: '1px solid var(--line)', color: 'var(--muted)', padding: '0 6px', borderRadius: '4px' },
  '.cm-foldGutter span': { color: 'var(--muted)' },
  '.cm-tooltip': { background: 'var(--surface)', border: '1px solid var(--line)', borderRadius: '6px', boxShadow: 'var(--shadow-pop)', color: 'var(--ink)' },
  '.cm-tooltip-autocomplete > ul': { fontFamily: 'var(--mono)', fontSize: '12.5px', maxHeight: '320px' },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': { background: 'var(--primary-soft)', color: 'var(--ink)' },
  '.cm-completionDetail': { color: 'var(--muted)', fontFamily: 'var(--font)', fontStyle: 'normal', marginLeft: '1em' },
  '.cm-completionInfo': { fontFamily: 'var(--font)', maxWidth: '360px', padding: '8px 10px' },
  '.cm-panels': { background: 'var(--surface-2)', color: 'var(--ink)', borderColor: 'var(--line)' },
  '.cm-panels input, .cm-panels button': { font: 'inherit', fontSize: '12.5px' },
  '.cm-textfield': { background: 'var(--surface)', color: 'var(--ink)', border: '1px solid var(--line)', borderRadius: '4px', padding: '3px 6px' },
  '.cm-button': { background: 'var(--surface)', color: 'var(--ink)', border: '1px solid var(--line)', borderRadius: '4px', backgroundImage: 'none' },
  '.cm-diagnostic-error': { borderLeftColor: 'var(--bad)' },
  '.cm-diagnostic-warning': { borderLeftColor: 'var(--warn)' },
  '.cm-diagnostic-info': { borderLeftColor: 'var(--info)' },
  '.cm-diagnosticAction': { background: 'var(--primary)', color: 'var(--primary-ink)', borderRadius: '4px', padding: '1px 8px' },
  '.cm-lintRange-error': { backgroundImage: 'none', textDecoration: 'underline wavy var(--bad)', textUnderlineOffset: '3px' },
  '.cm-lintRange-warning': { backgroundImage: 'none', textDecoration: 'underline wavy var(--warn)', textUnderlineOffset: '3px' },
  '.cm-lintRange-info': { backgroundImage: 'none', textDecoration: 'underline dotted var(--info)', textUnderlineOffset: '3px' },
  '.cm-panel.cm-gotoLine': { padding: '6px 10px' },
});

const phrases = EditorState.phrases.of({
  'Find': 'Suchen', 'Replace': 'Ersetzen', 'next': 'weiter', 'previous': 'zurück', 'all': 'alle',
  'match case': 'Groß/klein', 'regexp': 'Regex', 'by word': 'ganzes Wort', 'replace': 'ersetzen', 'replace all': 'alle ersetzen',
  'close': 'schließen', 'current match': 'aktueller Treffer', 'on line': 'in Zeile', 'replaced match on line $': 'Treffer in Zeile $ ersetzt',
  'replaced $ matches': '$ Treffer ersetzt', 'Go to line': 'Gehe zu Zeile', 'go': 'los',
  'Folded lines': 'Zeilen eingeklappt', 'Unfolded lines': 'Zeilen ausgeklappt', 'to': 'bis', 'folded code': 'eingeklappt', 'unfold': 'ausklappen',
  'Fold line': 'Einklappen', 'Unfold line': 'Ausklappen', 'Diagnostics': 'Hinweise', 'No diagnostics': 'Keine Hinweise',
  'Completions': 'Vorschläge', 'Control character': 'Steuerzeichen', 'Selection deleted': 'Auswahl gelöscht',
});

// ---------------------------------------------------------------- docs

export function docFor(word, isFirst, top) {
  if (word.startsWith('{')) {
    const p = PLACEHOLDERS.find(([k]) => k === word || (k.includes('<') && word.startsWith(k.split('<')[0])));
    return p ? { s: p[0], d: p[1] } : null;
  }
  if (!isFirst) return null;
  if (top?.kind === 'global' && GLOBAL[word]) return GLOBAL[word];
  if (top?.kind === 'matcher' && MATCHERS[word]) return { s: MATCHERS[word][0], d: MATCHERS[word][1] };
  if (top && (top.kind === 'directive' || top.kind === 'transport')) {
    const subs = top.kind === 'transport' ? SUBS.transport : (DIRECTIVES[top.name]?.sub || GLOBAL[top.name]?.sub || {});
    if (subs[word]) return { s: subs[word][0], d: subs[word][1] };
  }
  if (DIRECTIVES[word]) return DIRECTIVES[word];
  if (GLOBAL[word]) return GLOBAL[word];
  return null;
}

/** compatibility for older callers */
export function analyze(text) {
  return { lines: text.split('\n'), tree: parse(text) };
}

// ---------------------------------------------------------------- editor

export function createEditor({ value = '', onChange, onSave, onCursor, onFormat, onCommand, onOpenSnippet, readOnly = false } = {}) {
  let ctx = { policies: window.__sentinelPolicies || [], snippets: [], sentinelSnippets: [], files: [] };
  let serverDiags = [];
  const states = new Map(); // file key -> EditorState (keeps undo history per file)
  let currentKey = null;
  const readOnlyComp = new Compartment();

  // ------------------------------------------------------------ completion
  function context(state, pos) {
    const line = state.doc.lineAt(pos);
    const before = line.text.slice(0, pos - line.from);
    const m = before.match(/[^\s"]*$/);
    const word = m ? m[0] : '';
    const stack = stackAt(state, pos);
    const isFirst = before.trim() === word;
    const words = before.trim().split(/\s+/);
    return { line, before, word, from: pos - word.length, stack, top: stack[stack.length - 1], isFirst, lineText: line.text, first: words[0] || '', argIndex: isFirst ? 0 : words.length - (word ? 1 : 0) };
  }

  function definedMatchers(state, pos) {
    const site = parsed(state).nodes.find(n => n.from <= pos && pos <= n.to);
    const out = new Set();
    if (site?.children) walk(site.children, (n) => { if (n.kind === 'matcher') out.add(n.name); });
    return [...out];
  }

  function upstreamsInDoc(state) {
    const s = new Set();
    for (const m of state.doc.toString().matchAll(/reverse_proxy(?:\s+@[\w-]+|\s+\/\S*)?\s+([^\s{]+)/g)) s.add(m[1]);
    return [...s].filter(x => !x.startsWith('{'));
  }

  const tplToCM = (s) => s.replace(/\$0/g, '${}');

  function completions(cx) {
    const c = context(cx.state, cx.pos);
    const { word } = c;
    if (!cx.explicit && !word && !(c.isFirst && c.top && c.before.trim() === '')) return null;
    if (!cx.explicit && !word && !c.isFirst) return null;
    const opts = [];
    const add = (label, detail, apply, type, info, boost) => opts.push({ label, detail, apply: apply ?? label, type, info, boost });
    const addSnip = (label, detail, tpl, type = 'snippet', info) => opts.push(snippetCompletion(tplToCM(tpl), { label, detail, type, info }));
    const top = c.top;
    const lineHead = c.first;

    if (word.startsWith('{')) {
      PLACEHOLDERS.forEach(([p, d]) => add(p, d, p, 'variable'));
    } else if (word.startsWith('@') && !c.isFirst) {
      definedMatchers(cx.state, cx.pos).forEach(m => add(m, 'benannter Matcher', m, 'variable'));
    } else if (lineHead === 'import' && !c.isFirst) {
      const local = [...cx.state.doc.toString().matchAll(/^\s*\(([^)\s]+)\)/gm)].map(m => m[1]);
      [...new Set([...local, ...ctx.snippets])].forEach(s => add(s, 'Snippet', s, 'function'));
      (ctx.files || []).forEach(f => add(f, 'Datei', f, 'text'));
      add('sites/*.caddy', 'alle Dateien im Ordner sites', 'sites/*.caddy', 'text');
    } else if (c.isFirst) {
      if (!top) {
        SNIPPETS.forEach(s => addSnip(s.label, 'Vorlage', s.text));
        add('import', 'Datei oder Snippet einbinden', 'import ', 'keyword');
      } else if (top.kind === 'global') {
        Object.entries(GLOBAL).forEach(([k, v]) => add(k, v.s, k + ' ', 'keyword', v.d));
      } else if (top.kind === 'matcher') {
        Object.entries(MATCHERS).forEach(([k, v]) => add(k, v[0], k + ' ', 'property', v[1]));
      } else if (ROUTE_LIKE.has(top.kind)) {
        Object.entries(DIRECTIVES).forEach(([k, v]) => v.snip ? addSnip(k, v.s, v.snip, 'keyword', v.d) : add(k, v.s, k + ' ', 'keyword', v.d));
        add('import', 'import <snippet|datei>', 'import ', 'keyword');
        if (word.startsWith('@')) Object.entries(MATCHERS).forEach(([k, v]) => addSnip((word.length > 1 ? word : '@name') + ' ' + k, v[0], (word.length > 1 ? word : '@${1:name}') + ' ' + k + ' ${}', 'variable'));
        SNIPPETS.slice(6, 12).forEach(s => addSnip(s.label, 'Vorlage', s.text));
      } else {
        const subs = top.kind === 'transport' ? SUBS.transport : (DIRECTIVES[top.name]?.sub || GLOBAL[top.name]?.sub || {});
        Object.entries(subs).forEach(([k, v]) => add(k, v[0], k + ' ', 'property', v[1]));
        if (top.name === 'timeouts') ['read_body', 'read_header', 'write', 'idle'].forEach(k => add(k, `${k} <duration>`, k + ' ', 'property'));
        if (HEADER_DIRECTIVES.has(top.name)) HEADERS.forEach(([h, v]) => add(h, v, h + (v ? ' ' + v : ''), 'property'));
      }
    } else {
      // argument position
      const head = lineHead;
      const vals = VALUES[head];
      if (vals) vals.forEach(([v, d]) => add(v, d, v, 'enum', undefined, 2));
      if (head === 'sentinel' && c.stack.length && c.top?.kind !== 'global') (ctx.policies || []).forEach(p => add(p.id, p.name, p.id, 'enum', 'Policy', 3));
      if (STATUS_DIRECTIVES.has(head)) STATUS.forEach(([s, d]) => add(s, d, s, 'constant'));
      if (HEADER_DIRECTIVES.has(head) && c.argIndex <= 2) HEADERS.forEach(([h, v]) => add(h, v, h + (v ? ' ' + v : ''), 'property'));
      if (head === 'reverse_proxy' || head === 'to') {
        upstreamsInDoc(cx.state).forEach(u => add(u, 'bereits verwendet', u, 'text', undefined, 1));
        ['localhost:8080', '127.0.0.1:3000', 'unix//run/app.sock', 'https://backend.example.com'].forEach(u => add(u, 'Beispiel', u, 'text'));
      }
      const sub = docFor(head, true, c.top);
      if (sub && /<(duration|interval)>/.test(sub.s)) ['5s', '30s', '1m', '5m', '1h', '24h'].forEach(v => add(v, 'Dauer', v, 'constant'));
      if (sub && /<size>/.test(sub.s)) ['1MB', '10MB', '100MB', '1GB'].forEach(v => add(v, 'Größe', v, 'constant'));
      if (c.argIndex === 1 && (DIRECTIVES[head] && /<matcher>/.test(DIRECTIVES[head].s))) {
        definedMatchers(cx.state, cx.pos).forEach(m => add(m, 'Matcher', m, 'variable', undefined, 1));
        ['*', '/api/*', '/admin/*'].forEach(p => add(p, 'Pfad-Matcher', p, 'text'));
      }
      definedMatchers(cx.state, cx.pos).forEach(m => add(m, 'Matcher', m, 'variable'));
      if (word && !opts.length) PLACEHOLDERS.forEach(([p, d]) => add(p, d, p, 'variable'));
    }
    if (!opts.length) return null;
    // dedupe by label
    const seen = new Set();
    const options = opts.filter(o => !seen.has(o.label) && seen.add(o.label));
    return { from: c.from, options, validFor: /^[\w@{}.\-$/:*]*$/ };
  }

  // ------------------------------------------------------------ hover docs
  const hover = hoverTooltip((view, pos) => {
    const line = view.state.doc.lineAt(pos);
    const off = pos - line.from;
    const text = line.text;
    if (off >= text.length || /\s/.test(text[off])) return null;
    let a = off, b = off;
    while (a > 0 && !/\s/.test(text[a - 1])) a--;
    while (b < text.length && !/\s/.test(text[b])) b++;
    const word = text.slice(a, b);
    const stack = stackAt(view.state, line.from + a);
    const top = stack[stack.length - 1];
    const isFirst = text.slice(0, a).trim() === '';
    let d = docFor(word, isFirst, top);
    let name = word;
    if (!d && word.includes('{')) {
      const ph = word.match(/\{[^}]+\}/g)?.map(p => docFor(p, false, top)).filter(Boolean);
      if (ph?.length) d = { s: ph.map(p => p.s).join('  '), d: ph.map(p => p.d).join(' · ') };
    }
    if (!d) return null;
    const isDirective = isFirst && (DIRECTIVES[word] || GLOBAL[word]) && (!top || ROUTE_LIKE.has(top.kind) || top.kind === 'global');
    return {
      pos: line.from + a, end: line.from + b, above: true,
      create: () => ({
        dom: el('div.ed-doc', null, el('code', null, d.s), el('p', null, d.d),
          isDirective ? el('a', { href: DOC_LINK(name, top?.kind === 'global' && !DIRECTIVES[name]), target: '_blank', rel: 'noopener noreferrer' }, 'Offizielle Doku ↗') : null),
      }),
    };
  }, { hoverTime: 350 });

  // ------------------------------------------------------------ lint
  const linting = linter((view) => {
    const doc = view.state.doc;
    const out = [];
    for (const d of serverDiags) {
      if (!d.line || d.line > doc.lines) continue;
      const l = doc.line(d.line);
      out.push({ from: l.from + (l.text.length - l.text.trimStart().length), to: l.to, severity: d.severity === 'error' ? 'error' : d.severity === 'warning' ? 'warning' : 'info', message: d.message, source: 'Caddy' });
    }
    for (const d of lint(doc.toString(), ctx)) {
      out.push({
        from: Math.min(d.from, doc.length), to: Math.min(d.to, doc.length), severity: d.severity, message: d.message, source: 'Sentinel',
        actions: (d.fixes || []).map(f => ({ name: f.name, apply: (v) => v.dispatch({ changes: f.changes, userEvent: 'input.fix' }) })),
      });
    }
    return out;
  }, { delay: 300 });

  // ------------------------------------------------------------ navigation helpers
  function wordAt(state, pos) {
    const line = state.doc.lineAt(pos);
    const off = pos - line.from;
    const text = line.text;
    let a = off, b = off;
    while (a > 0 && !/\s/.test(text[a - 1])) a--;
    while (b < text.length && !/\s/.test(text[b])) b++;
    return { word: text.slice(a, b), from: line.from + a, to: line.from + b, line, before: text.slice(0, a) };
  }

  function gotoDefinition(view, pos = view.state.selection.main.head) {
    const { word, before } = wordAt(view.state, pos);
    const { nodes } = parsed(view.state);
    const jump = (p) => { view.dispatch({ selection: { anchor: p }, scrollIntoView: true, effects: EditorView.scrollIntoView(p, { y: 'center' }) }); view.focus(); return true; };
    if (word.startsWith('@')) {
      const site = nodes.find(n => n.from <= pos && pos <= n.to);
      let target = null;
      if (site?.children) walk(site.children, (n) => { if (!target && n.kind === 'matcher' && n.name === word) target = n; });
      if (target) return jump(target.from);
    }
    const head = before.trim().split(/\s+/)[0];
    if (head === 'import' || head === 'invoke') {
      const name = head === 'invoke' ? '&(' + word + ')' : '(' + word + ')';
      const def = nodes.find(n => n.name === name);
      if (def) return jump(def.from);
      if (head === 'import') { onOpenSnippet?.(word); return true; }
    }
    return false;
  }

  function renameMatcher(view) {
    const pos = view.state.selection.main.head;
    const { word } = wordAt(view.state, pos);
    if (!/^@[\w-]+$/.test(word)) return false;
    const site = parsed(view.state).nodes.find(n => n.from <= pos && pos <= n.to);
    if (!site) return false;
    const to = window.prompt(`Matcher ${word} umbenennen in:`, word);
    if (!to || to === word || !/^@[\w-]+$/.test(to)) return true;
    const changes = [];
    const re = new RegExp(word.replace(/[-]/g, '\\-') + '(?![\\w-])', 'g');
    const text = view.state.doc.sliceString(site.from, site.to);
    for (const m of text.matchAll(re)) changes.push({ from: site.from + m.index, to: site.from + m.index + word.length, insert: to });
    view.dispatch({ changes, userEvent: 'input.rename' });
    return true;
  }

  // ------------------------------------------------------------ extensions
  const extensions = [
    lineNumbers(), highlightActiveLineGutter(), highlightSpecialChars(), history(), foldGutter({ openText: '▾', closedText: '▸' }),
    codeFolding({ placeholderText: '…' }), drawSelection(), dropCursor(), EditorState.allowMultipleSelections.of(true),
    indentOnInput(), indentUnit.of('\t'), EditorState.tabSize.of(4), syntaxHighlighting(highlight), bracketMatching(), closeBrackets(),
    autocompletion({ override: [completions], activateOnTyping: true, icons: true, maxRenderedOptions: 80, closeOnBlur: true }),
    rectangularSelection(), crosshairCursor(), highlightActiveLine(), highlightSelectionMatches(), search({ top: true }),
    caddyLang, caddyFold, hover, linting, lintGutter(), theme, phrases, scrollPastEnd(),
    readOnlyComp.of([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]),
    Prec.high(keymap.of([
      { key: 'Mod-s', run: () => { onSave?.(); return true; }, preventDefault: true },
      { key: 'Mod-g', run: gotoLine, preventDefault: true },
      { key: 'Mod-h', run: openSearchPanel, preventDefault: true },
      { key: 'F12', run: (v) => gotoDefinition(v) },
      { key: 'F2', run: renameMatcher },
      { key: 'Shift-Alt-f', run: () => { onFormat?.(); return true; } },
      { key: 'F1', run: () => { onCommand?.(); return true; } },
      { key: 'Mod-Shift-p', run: () => { onCommand?.(); return true; }, preventDefault: true },
      { key: 'Mod-Space', run: startCompletion },
    ])),
    keymap.of([...closeBracketsKeymap, ...defaultKeymap, ...searchKeymap, ...historyKeymap, ...foldKeymap, ...completionKeymap, ...lintKeymap, indentWithTab]),
    EditorView.domEventHandlers({
      mousedown(e, view) {
        if (!(e.ctrlKey || e.metaKey) || e.altKey) return false;
        const pos = view.posAtCoords({ x: e.clientX, y: e.clientY });
        if (pos == null) return false;
        const { word } = wordAt(view.state, pos);
        if (!word.startsWith('@') && !/^(import|invoke)\s/.test(view.state.doc.lineAt(pos).text.trim())) return false;
        if (gotoDefinition(view, pos)) { e.preventDefault(); return true; }
        return false;
      },
    }),
    EditorView.updateListener.of((u) => {
      if (u.docChanged) onChange?.(u.state.doc.toString());
      if (u.docChanged || u.selectionSet) emitCursor(u.state);
    }),
  ];

  const mkState = (doc) => EditorState.create({ doc, extensions });
  const view = new EditorView({ state: mkState(value) });
  const root = el('div.editor.cm-host', null);
  root.append(view.dom);

  function emitCursor(state) {
    if (!onCursor) return;
    const pos = state.selection.main.head;
    const line = state.doc.lineAt(pos);
    const stack = stackAt(state, pos);
    const chain = pathAt(parsed(state).nodes, pos);
    onCursor({
      line: line.number, col: pos - line.from + 1, first: line.text.trim().split(/\s+/)[0] || '', stack, top: stack[stack.length - 1],
      crumbs: chain.map(n => ({ label: nodeLabel(n), from: n.from, kind: n.kind })), selections: state.selection.ranges.length,
    });
  }

  function selectRange(from, to) {
    view.dispatch({ selection: { anchor: from, head: to }, effects: EditorView.scrollIntoView(from, { y: 'center' }) });
  }

  return {
    el: root,
    view,
    getValue: () => view.state.doc.toString(),
    setValue(v, key) {
      if (currentKey != null) states.set(currentKey, view.state);
      currentKey = key ?? null;
      const saved = key != null ? states.get(key) : null;
      view.setState(saved && saved.doc.toString() === v ? saved : mkState(v));
      view.dispatch({ effects: readOnlyComp.reconfigure([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]) });
      forceLinting(view);
      emitCursor(view.state);
    },
    forget(key) { states.delete(key); },
    replaceAll(v) {
      const head = Math.min(view.state.selection.main.head, v.length);
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v }, selection: { anchor: head }, userEvent: 'input.replace' });
    },
    replaceRange(from, to, text, select = true) {
      view.dispatch({ changes: { from, to, insert: text }, selection: select ? { anchor: from, head: from + text.length } : undefined, scrollIntoView: true, userEvent: 'input.replace' });
    },
    setDiagnostics(d) { serverDiags = d || []; forceLinting(view); },
    setContext(c) { ctx = { ...ctx, ...c }; forceLinting(view); },
    focus() { view.focus(); },
    setReadOnly(r) { readOnly = r; view.dispatch({ effects: readOnlyComp.reconfigure([EditorState.readOnly.of(r), EditorView.editable.of(!r)]) }); },
    goto(line, col = 1) {
      const l = view.state.doc.line(Math.max(1, Math.min(line, view.state.doc.lines)));
      const pos = Math.min(l.from + col - 1, l.to);
      view.dispatch({ selection: { anchor: pos }, effects: EditorView.scrollIntoView(pos, { y: 'center' }) });
      view.focus();
    },
    gotoPos(pos) { view.dispatch({ selection: { anchor: pos }, effects: EditorView.scrollIntoView(pos, { y: 'center' }) }); view.focus(); },
    insertAtCursor(tpl) {
      const { from, to } = view.state.selection.main;
      const line = view.state.doc.lineAt(from);
      const indent = line.text.match(/^[\t ]*/)[0];
      const text = tplToCM(tpl).replace(/\n/g, '\n' + indent);
      snippet(text)(view, null, from, to);
      view.focus();
    },
    appendText(text) {
      const v = view.state.doc.toString();
      const sep = v.endsWith('\n\n') ? '' : v.endsWith('\n') ? '\n' : '\n\n';
      view.dispatch({ changes: { from: v.length, insert: sep + text }, selection: { anchor: v.length + sep.length }, effects: EditorView.scrollIntoView(v.length + sep.length, { y: 'start' }) });
    },
    select(from, to) { selectRange(from, to); },
    selection: () => [view.state.selection.main.from, view.state.selection.main.to],
    openSearch() { openSearchPanel(view); },
    gotoLineDialog() { gotoLine(view); },
    foldAll() { foldAll(view); },
    unfoldAll() { unfoldAll(view); },
    openDiagnostics() { openLintPanel(view); },
    gotoDefinition() { return gotoDefinition(view); },
    renameMatcher() { return renameMatcher(view); },
    tree: () => parsed(view.state),
    /** top-level block node at the cursor (site, global, snippet) */
    blockAtCursor() {
      const pos = view.state.selection.main.head;
      return parsed(view.state).nodes.find(n => n.from <= pos && pos <= n.to) || null;
    },
    lintNow: () => lint(view.state.doc.toString(), ctx),
  };
}
