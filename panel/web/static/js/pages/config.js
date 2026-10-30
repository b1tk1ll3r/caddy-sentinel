import { select, field, el, mount, get, post, toast, errToast, modal, confirmDialog, prompt, debounce, fmtDateTime, fmtAgo, empty, can } from '../ui.js';
import { createEditor, docFor } from '../editor.js';
import { withInstance } from '../instancebar.js';
import { openSiteForm } from '../siteform.js';
import { parse } from '../caddyfile.js';
import { GLOBAL, DIRECTIVES, MATCHERS, SNIPPETS, DOC_LINK, SUBS } from '../caddydocs.js';
import { setActions } from '../app.js';

export { diffLines, diffView } from '../diff.js';
import { diffView } from '../diff.js';

// ---------------------------------------------------------------- page

export async function render(root, _p, scope) {
  ({ root } = withInstance(root, { preferEditable: true }));
  const [meta, pols] = await Promise.all([get('/config/files', scope.signal), get('/policies', scope.signal)]);
  if (meta.editable === false) {
    mount(root, el('div.callout.warn', null,
      el('b', null, 'Die Caddyfile dieser Instanz ist im Panel nicht bearbeitbar. '),
      meta.mode === 'read' ? 'Der Agent erlaubt nur lesenden Zugriff. ' : '',
      'Für die Bearbeitung in der Caddyfile des Servers ergänzen und Caddy neu laden:',
      el('pre.mono', { style: { marginTop: '8px' } }, '{\n\tsentinel {\n\t\tremote full\n\t\tcaddyfile /etc/caddy/Caddyfile\n\t}\n}'),
      'Der Benutzer, unter dem Caddy läuft, braucht Schreibrechte auf das Verzeichnis. Request-Fluss, Sites und Zertifikate funktionieren auch ohne.'));
    return;
  }
  window.__sentinelPolicies = pols.policies.map(p => ({ id: p.id, name: p.name }));
  const orig = {};      // path -> server content
  const buffers = {};   // path -> edited content
  const deleted = new Set();
  let files = meta.files;
  let current = meta.main;
  let lastValidation = null;
  let validating = false;

  const load = async (path) => {
    if (orig[path] === undefined) {
      const f = await get('/config/file?path=' + encodeURIComponent(path));
      orig[path] = f.content;
    }
    return buffers[path] ?? orig[path];
  };
  await load(current);

  const dirty = () => Object.keys(buffers).filter(p => buffers[p] !== orig[p]);

  // --- UI elements
  const filesBox = el('div.ed-files');
  const outlineBox = el('div.ed-outline');
  const diagBox = el('div.ed-diags', { hidden: true });
  const statusMsg = el('span.msg');
  const cursorInfo = el('span');
  const docsBox = el('div');
  const fileLabel = el('strong.mono', null, current);
  const applyBtn = el('button.btn.primary', { onclick: () => apply() }, 'Übernehmen');
  let docsSearch;

  const crumbsBox = el('div.ed-crumbs');
  const formBtn = el('button.btn.sm', { onclick: () => editSiteAtCursor(), title: 'Site-Block am Cursor im Formular bearbeiten', disabled: true }, 'Formular');
  const ed = createEditor({
    value: '',
    onChange: (v) => {
      buffers[current] = v;
      drawFiles();
      scheduleValidate();
      drawOutlineDebounced();
    },
    onSave: () => apply(),
    onFormat: () => format(),
    onCommand: () => commandPalette(),
    onOpenSnippet: (name) => openSnippet(name),
    onCursor: (c) => {
      cursorInfo.textContent = `Zeile ${c.line}, Spalte ${c.col}` + (c.selections > 1 ? ` · ${c.selections} Cursor` : '');
      drawCrumbs(c.crumbs || []);
      formBtn.disabled = !(c.crumbs?.[0]?.kind === 'site');
      showContextDocs(c);
    },
  });
  ed.setValue(await load(current), current);

  // --- breadcrumbs
  function drawCrumbs(cr) {
    mount(crumbsBox, cr.length ? cr.flatMap((x, i) => [i ? el('span.sep', null, '›') : null, el('a', { title: x.label, onclick: () => ed.gotoPos(x.from) }, x.label)]) : el('span.muted', null, 'außerhalb eines Blocks'));
  }

  // --- knowledge about the other files (snippets, imports)
  async function refreshContext() {
    const snippets = new Set(), sentinelSnippets = new Set();
    for (const f of files) {
      if (deleted.has(f.path)) continue;
      const src = f.path === current ? ed.getValue() : (buffers[f.path] ?? await load(f.path).catch(() => ''));
      for (const n of parse(src || '').nodes) {
        if (n.kind !== 'snippet') continue;
        const name = n.name.slice(1, -1);
        if (f.path !== current) snippets.add(name);
        if ((src.slice(n.from, n.to)).match(/^\s*sentinel\b/m)) sentinelSnippets.add(name);
      }
    }
    ed.setContext({ policies: window.__sentinelPolicies || [], snippets: [...snippets], sentinelSnippets: [...sentinelSnippets], files: files.map(f => f.path).filter(p => p !== meta.main) });
  }

  async function openSnippet(name) {
    for (const f of files) {
      const src = f.path === current ? ed.getValue() : (buffers[f.path] ?? await load(f.path).catch(() => ''));
      const n = parse(src || '').nodes.find(x => x.name === '(' + name + ')');
      if (n) {
        if (f.path !== current) await openFile(f.path);
        ed.gotoPos(n.from);
        return;
      }
    }
    toast(`Snippet „${name}“ nicht gefunden`, 'bad');
  }

  // --- site form
  function editSiteAtCursor() {
    const n = ed.blockAtCursor();
    if (!n || n.kind !== 'site') return toast('Cursor in einen Site-Block setzen', 'info');
    editSite(n);
  }
  function editSite(n) {
    if (!n.children) return toast('Dieser Site-Block hat keinen Inhalt in { }', 'info');
    openSiteForm({
      text: ed.getValue(), node: n, policies: window.__sentinelPolicies || [],
      onApply: (g) => { ed.replaceRange(n.from, n.to, matchIndent(g), false); ed.gotoPos(n.from); toast('Site aktualisiert – mit Strg+Z rückgängig', 'ok', 4000); },
    });
  }
  function newSite() {
    openSiteForm({
      policies: window.__sentinelPolicies || [],
      onApply: async (text, where, m) => {
        text = matchIndent(text) + '\n';
        if (where === 'cursor') { ed.insertAtCursor(text.replace(/\$/g, '\\$')); return; }
        if (where === 'main') {
          if (current !== meta.main) await openFile(meta.main);
          ed.appendText(text);
          return;
        }
        const primary = (m.addresses[0] || 'site').replace(/^https?:\/\//, '').replace(/[^a-z0-9.-]/gi, '_');
        const path = `sites/${primary}.caddy`;
        if (!files.find(f => f.path === path)) files.push({ path, writable: true });
        orig[path] = orig[path] ?? null;
        buffers[path] = (buffers[path] ? buffers[path].replace(/\s*$/, '\n\n') : '') + text;
        const mainSrc = buffers[meta.main] ?? await load(meta.main);
        if (!/^\s*import\s+"?sites\/\*/m.test(mainSrc)) {
          buffers[meta.main] = mainSrc.replace(/\s*$/, '\n') + '\nimport sites/*.caddy\n';
          toast('„import sites/*.caddy“ wurde in der Caddyfile ergänzt', 'info', 6000);
        }
        await openFile(path);
        drawFiles();
        validate();
      },
    });
  }

  // --- command palette & shortcuts
  const COMMANDS = [
    ['Übernehmen', 'Strg+S', () => apply()],
    ['Prüfen', '', () => validate(false)],
    ['Vollständig prüfen (caddy validate)', '', () => validate(true)],
    ['Formatieren', 'Umschalt+Alt+F', () => format()],
    ['Suchen / Ersetzen', 'Strg+F / Strg+H', () => ed.openSearch()],
    ['Gehe zu Zeile', 'Strg+G', () => ed.gotoLineDialog()],
    ['Gehe zu Definition (Matcher, Snippet)', 'F12 / Strg+Klick', () => ed.gotoDefinition()],
    ['Matcher umbenennen', 'F2', () => ed.renameMatcher()],
    ['Alles einklappen', 'Strg+Alt+[', () => ed.foldAll()],
    ['Alles ausklappen', 'Strg+Alt+]', () => ed.unfoldAll()],
    ['Hinweise-Liste öffnen', 'Strg+Umschalt+M', () => ed.openDiagnostics()],
    ['Site im Formular bearbeiten', '', () => editSiteAtCursor()],
    ['Neue Site …', '', () => newSite()],
    ['Sentinel in alle Sites einfügen', '', () => insertSentinel()],
    ['Vorlage einfügen …', '', () => snippetMenu()],
    ['Ausstehende Änderungen anzeigen', '', () => showDiff()],
    ['Versionen …', '', () => versions()],
    ['Tastenkürzel anzeigen', '', () => shortcuts()],
  ];
  function commandPalette() {
    let idx = 0, list, inp;
    let shown = COMMANDS;
    const m = modal('Befehle', [
      inp = el('input', { placeholder: 'Befehl suchen …', 'aria-label': 'Befehl suchen', oninput: () => { idx = 0; draw(); }, onkeydown: (e) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); idx = Math.min(idx + 1, shown.length - 1); draw(); }
        if (e.key === 'ArrowUp') { e.preventDefault(); idx = Math.max(idx - 1, 0); draw(); }
        if (e.key === 'Enter') { e.preventDefault(); run(shown[idx]); }
      } }),
      list = el('div.cmd-list'),
    ]);
    const run = (c) => { if (!c) return; m.close(); setTimeout(() => c[2](), 0); };
    function draw() {
      const q = inp.value.toLowerCase();
      shown = COMMANDS.filter(c => c[0].toLowerCase().includes(q));
      mount(list, shown.map((c, i) => el('button' + (i === idx ? '.active' : ''), { onclick: () => run(c) }, c[0], c[1] ? el('kbd', null, c[1]) : null)));
    }
    draw();
  }
  function shortcuts() {
    const K = [
      ['Vorschläge', 'Strg+Leertaste'], ['Übernehmen', 'Strg+S'], ['Befehle', 'F1 · Strg+Umschalt+P'],
      ['Suchen / Ersetzen', 'Strg+F · Strg+H'], ['Nächstes Vorkommen zusätzlich markieren', 'Strg+D'], ['Alle Vorkommen markieren', 'Strg+Umschalt+L'],
      ['Weiterer Cursor', 'Alt+Klick'], ['Block-Auswahl (Spalten)', 'Alt+Ziehen'], ['Zeile verschieben', 'Alt+↑ / Alt+↓'], ['Zeile duplizieren', 'Umschalt+Alt+↑ / ↓'],
      ['Zeile löschen', 'Strg+Umschalt+K'], ['Kommentar an/aus', 'Strg+/'], ['Einrücken / Ausrücken', 'Tab / Umschalt+Tab'],
      ['Block einklappen / ausklappen', 'Strg+Umschalt+[ / ]'], ['Alles einklappen / ausklappen', 'Strg+Alt+[ / ]'],
      ['Passende Klammer', 'wird automatisch markiert'], ['Gehe zu Zeile', 'Strg+G'], ['Gehe zu Definition', 'F12 · Strg+Klick'],
      ['Matcher umbenennen', 'F2'], ['Formatieren', 'Umschalt+Alt+F'], ['Nächster Hinweis', 'F8'], ['Hinweise-Liste', 'Strg+Umschalt+M'],
      ['Rückgängig / Wiederholen', 'Strg+Z / Strg+Y'],
    ];
    modal('Tastenkürzel', el('table.keys-table', null, el('tbody', null, K.map(([a, b]) => el('tr', null, el('td', null, a), el('td', null, b.split(' · ').map(k => el('kbd', null, k))))))), { wide: false });
  }

  function drawFiles() {
    const d = new Set(dirty());
    mount(filesBox, files.filter(f => !deleted.has(f.path)).map(f => el('a' + (f.path === current ? '.active' : ''), {
      title: f.path + (f.writable ? '' : ' (schreibgeschützt)'), onclick: () => openFile(f.path),
    }, f.main ? '◆ ' : '', f.path, !f.writable ? el('small', null, ' 🔒') : null, d.has(f.path) ? el('span.mod', { title: 'geändert' }, '●') : null)),
    el('a', { onclick: newFile, style: { color: 'var(--primary)' } }, '+ Neue Datei'));
    applyBtn.disabled = d.size === 0 && deleted.size === 0;
    applyBtn.textContent = d.size || deleted.size ? `Übernehmen (${d.size + deleted.size})` : 'Übernehmen';
  }

  function drawOutline() {
    post('/config/outline', { content: ed.getValue() }).then(res => {
      const bl = res.blocks || [];
      const kindLabel = { global: 'G', site: 'S', snippet: '( )', named_route: '&' };
      mount(outlineBox, bl.length ? bl.map(b => el('a', { onclick: () => ed.goto(b.start), title: (b.keys || []).join(' ') || 'Globale Optionen' },
        el('span.kind.' + b.kind, null, kindLabel[b.kind] || '?'),
        el('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis' } }, b.kind === 'global' ? 'Globale Optionen' : (b.keys || []).join(' ')),
        b.kind === 'site' && !b.sentinel ? el('small', { title: 'ohne sentinel', style: { color: 'var(--warn)' } }, '!') : el('small', null, b.start),
        b.kind === 'site' ? el('button.icon-btn', { title: 'Im Formular bearbeiten', style: { padding: '0 4px', fontSize: '12px' }, onclick: (e) => { e.stopPropagation(); const n = ed.tree().nodes.find(x => x.kind === 'site' && x.line + 1 === b.start); if (n) editSite(n); } }, '✎') : null)) : el('small', { style: { padding: '0 12px' } }, res.error || 'Keine Blöcke'));
    }).catch(() => { });
  }
  const drawOutlineDebounced = debounce(drawOutline, 400);

  async function openFile(path) {
    current = path;
    fileLabel.textContent = path;
    ed.setValue(await load(path), path);
    ed.setDiagnostics(diagsFor(path));
    drawFiles();
    drawOutline();
    refreshContext();
    ed.focus();
  }

  // keep the indentation style of the file (tabs vs. spaces) for generated blocks
  function matchIndent(text) {
    const m = /^( +)\S/m.exec(ed.getValue());
    return m ? text.replace(/^\t+/gm, (t) => m[1].repeat(t.length)) : text;
  }

  document.addEventListener('keydown', (e) => {
    if (e.defaultPrevented || document.querySelector('.modal-wrap')) return;
    if (e.key === 'F1' || ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'p')) { e.preventDefault(); commandPalette(); }
  }, { signal: scope.signal });

  async function newFile() {
    const name = await prompt('Neue Konfigurationsdatei', 'Pfad relativ zum Caddyfile-Verzeichnis (z. B. sites/blog.caddy)', 'sites/neu.caddy');
    if (!name) return;
    if (!/\.(caddy|caddyfile|conf|snippet)$|(^|\/)Caddyfile/.test(name)) return toast('Dateiname muss auf .caddy, .caddyfile oder .conf enden', 'bad');
    if (!files.find(f => f.path === name)) files.push({ path: name, writable: true });
    orig[name] = orig[name] ?? null;
    buffers[name] = buffers[name] ?? `# ${name}\n`;
    await openFile(name);
    toast('Datei angelegt – nicht vergessen, sie per import einzubinden', 'info', 6000);
  }

  function diagsFor(path) {
    return (lastValidation?.diagnostics || []).filter(d => (d.file || meta.main) === path && d.line > 0);
  }

  function drawDiagnostics() {
    const v = lastValidation;
    if (!v) return;
    ed.setDiagnostics(diagsFor(current));
    const items = [...(v.diagnostics || []).map(d => ({ ...d })), ...(v.hints || []).map(h => ({ severity: 'info', message: h }))];
    diagBox.hidden = items.length === 0;
    mount(diagBox, items.map(d => el('div.' + d.severity, {
      onclick: async () => { if (d.file && d.file !== current) await openFile(d.file); if (d.line) ed.goto(d.line); },
    }, el('b', null, d.severity === 'error' ? 'Fehler' : d.severity === 'warning' ? 'Warnung' : 'Hinweis'),
      d.line ? el('span.mono', null, `${d.file || meta.main}:${d.line}`) : null, el('span', null, d.message))));
    if (v.ok) {
      const sites = v.sites?.length ?? 0;
      statusMsg.replaceChildren(el('span.dot.ok'), ` Gültig · ${sites} Site${sites === 1 ? '' : 's'}` + (v.full ? ' · vollständig geprüft' : ''));
    } else {
      statusMsg.replaceChildren(el('span.dot.bad'), ' ' + (v.diagnostics?.[0]?.message || v.error || 'ungültig'));
    }
  }

  let revalidate = false;
  async function validate(full = false) {
    if (!can('config')) { statusMsg.replaceChildren(el('span.dot'), ' Prüfen über Caddy erfordert das Recht „Konfiguration“'); return; }
    if (validating) { revalidate = true; return; }
    validating = true;
    statusMsg.replaceChildren(el('span.dot'), full ? ' Vollständige Prüfung läuft …' : ' Prüfe …');
    try {
      const changed = {};
      for (const p of dirty()) changed[p] = buffers[p];
      changed[current] = ed.getValue();
      if (!changed[meta.main]) changed[meta.main] = await load(meta.main);
      lastValidation = await post('/config/validate', { files: changed, full });
      drawDiagnostics();
    } catch (e) {
      statusMsg.replaceChildren(el('span.dot.bad'), ' ' + e.message);
    } finally {
      validating = false;
      if (revalidate) { revalidate = false; setTimeout(() => validate(false), 50); }
    }
  }
  const scheduleValidate = debounce(() => validate(false), 800);

  function showContextDocs(c) {
    if (docsSearch?.value) return;
    const top = c.top;
    let name = c.first, d = docFor(c.first, true, top);
    if ((!d || top?.kind === 'directive') && top && (DIRECTIVES[top.name] || GLOBAL[top.name] || top.kind === 'transport')) {
      // inside a block: show the parent with its subdirectives
      const pd = top.kind === 'transport' ? { s: 'transport http|fastcgi { … }', d: 'Transport-Optionen des Reverse Proxys.', sub: SUBS.transport } : (DIRECTIVES[top.name] || GLOBAL[top.name]);
      return drawDoc(top.name, pd, d && d !== pd ? { name, d } : null, !!GLOBAL[top.name] && !DIRECTIVES[top.name]);
    }
    if (!d && top?.kind === 'global') return drawList('Globale Optionen', GLOBAL, true);
    if (!d && top?.kind === 'matcher') return drawMatchers();
    if (!d) return drawList('Direktiven', DIRECTIVES, false);
    drawDoc(name, d, null, top?.kind === 'global');
  }

  function insertLine(text) { ed.insertAtCursor(text); }

  function drawDoc(name, d, child, global) {
    const subs = d.sub ? Object.entries(d.sub) : [];
    mount(docsBox, el('div.doc', null,
      el('h3', { style: { margin: '8px 0 4px' } }, el('span.mono', null, name)),
      el('code', null, d.s),
      el('p', null, d.d),
      child ? el('div.callout', { style: { margin: '6px 0' } }, el('b.mono', null, child.name), el('div', null, child.d.d || child.d[1])) : null,
      subs.length ? [el('h4', { style: { padding: '8px 0 4px' } }, 'Unterdirektiven – klicken zum Einfügen'),
        el('div.subs', null, subs.map(([k, [syn, desc]]) => el('button', { onclick: () => insertLine(k + ' ') }, el('b', null, k), el('small', null, desc), el('small.mono', null, syn))))] : null,
      d.snip ? el('button.btn.sm', { onclick: () => insertLine(d.snip), style: { marginTop: '8px' } }, 'Beispiel einfügen') : null,
      el('p', { style: { marginTop: '10px' } }, el('a', { href: DOC_LINK(name, global), target: '_blank', rel: 'noopener noreferrer' }, 'Offizielle Dokumentation öffnen'))));
  }

  function drawList(title, obj, global) {
    mount(docsBox, el('div.doc', null, el('h4', { style: { padding: '8px 0 4px' } }, title), el('div.subs', null,
      Object.entries(obj).map(([k, d]) => el('button', { onclick: () => drawDoc(k, d, null, global) }, el('b', null, k), el('small', null, d.d))))));
  }
  function drawMatchers() {
    mount(docsBox, el('div.doc', null, el('h4', { style: { padding: '8px 0 4px' } }, 'Matcher'), el('div.subs', null,
      Object.entries(MATCHERS).map(([k, [syn, desc]]) => el('button', { onclick: () => insertLine(k + ' ') }, el('b', null, k), el('small', null, desc), el('small.mono', null, syn))))));
  }

  docsSearch = el('input', {
    type: 'search', placeholder: 'Direktive oder Option suchen …', 'aria-label': 'Dokumentation durchsuchen',
    oninput: (e) => {
      const q = e.target.value.toLowerCase().trim();
      if (!q) return drawList('Direktiven', DIRECTIVES, false);
      const hits = [
        ...Object.entries(DIRECTIVES).filter(([k, d]) => k.includes(q) || d.d.toLowerCase().includes(q)).map(([k, d]) => [k, d, false]),
        ...Object.entries(GLOBAL).filter(([k, d]) => k.includes(q) || d.d.toLowerCase().includes(q)).map(([k, d]) => [k, d, true]),
      ];
      mount(docsBox, el('div.doc', null, el('div.subs', null, hits.length ? hits.map(([k, d, g]) => el('button', { onclick: () => drawDoc(k, d, null, g) },
        el('b', null, k), el('small', null, (g ? 'Globale Option · ' : '') + d.d))) : el('small', null, 'Nichts gefunden'))));
    },
  });

  // --- actions
  async function format() {
    const res = await post('/config/format', { content: ed.getValue() });
    if (res.content !== ed.getValue()) { ed.replaceAll(res.content); toast('Formatiert', 'ok', 1500); }
  }

  async function insertSentinel() {
    const res = await post('/config/insert-sentinel', { content: ed.getValue() });
    if (!res.inserted) return toast('Alle Site-Blöcke dieser Datei enthalten bereits sentinel', 'info');
    ed.replaceAll(res.content);
    toast(`sentinel in ${res.inserted} Site${res.inserted > 1 ? 's' : ''} eingefügt`, 'ok');
  }

  function snippetMenu() {
    const m = modal('Vorlage einfügen', el('div.snippet-list', null, el('div.subs', null,
      SNIPPETS.map(s => el('button', { onclick: () => { m.close(); ed.insertAtCursor(s.text); } }, el('b', null, s.label),
        el('small.mono', { style: { whiteSpace: 'pre', display: 'block', maxHeight: '60px', overflow: 'hidden' } }, s.text.replace(/\$\{\d+:([^}]*)\}/g, '$1')))))));
  }

  function showDiff() {
    const pairs = {};
    for (const p of dirty()) pairs[p] = [orig[p], buffers[p]];
    for (const p of deleted) pairs[p] = [orig[p], null];
    modal('Ausstehende Änderungen', diffView(pairs), { wide: true, actions: [{ label: 'Schließen' }] });
  }

  async function apply() {
    buffers[current] = ed.getValue();
    const d = dirty();
    if (!d.length && !deleted.size) return toast('Keine Änderungen', 'info', 1500);
    const pairs = {};
    for (const p of d) pairs[p] = [orig[p], buffers[p]];
    for (const p of deleted) pairs[p] = [orig[p], null];
    let note;
    modal('Konfiguration übernehmen', [
      el('p', null, 'Sentinel prüft die Konfiguration, schreibt die Dateien und lädt Caddy ohne Neustart neu. Lehnt Caddy die Konfiguration ab, werden die alten Dateien wiederhergestellt.'),
      diffView(pairs),
      el('label.field', null, el('span', null, 'Notiz zur Version'), note = el('input', { placeholder: 'z. B. Blog hinzugefügt' })),
    ], {
      wide: true,
      actions: [{ label: 'Abbrechen' }, {
        label: 'Prüfen und übernehmen', kind: 'primary', onClick: async () => {
          const filesToSend = {};
          for (const p of d) filesToSend[p] = buffers[p];
          const res = await post('/config/apply', { files: filesToSend, delete: [...deleted], note: note.value });
          lastValidation = res;
          drawDiagnostics();
          if (!res.applied) {
            toast('Nicht übernommen: ' + (res.diagnostics?.[0]?.message || res.error || 'Konfiguration ungültig'), 'bad', 8000);
            return true;
          }
          for (const p of d) orig[p] = buffers[p];
          for (const p of deleted) { delete orig[p]; delete buffers[p]; files = files.filter(f => f.path !== p); }
          deleted.clear();
          drawFiles();
          toast(`Übernommen – Caddy läuft mit Version #${res.version}`, 'ok', 5000);
          return true;
        },
      }],
    });
  }

  async function discard() {
    if (!dirty().length && !deleted.size) return;
    if (!await confirmDialog('Änderungen verwerfen', 'Alle ungespeicherten Änderungen in allen Dateien gehen verloren.', 'Verwerfen')) return;
    for (const p of Object.keys(buffers)) { delete buffers[p]; ed.forget(p); }
    deleted.clear();
    files = (await get('/config/files')).files;
    ed.forget(current);
    ed.setValue(await load(current), current);
    drawFiles(); drawOutline(); validate();
  }

  async function versions() {
    const vs = await get('/config/versions');
    const m = modal('Versionen', vs.length ? el('div.table-wrap', null, el('table', null,
      el('thead', null, el('tr', null, el('th', null, '#'), el('th', null, 'Zeit'), el('th', null, 'Von'), el('th', null, 'Notiz'), el('th', null, ''))),
      el('tbody', null, vs.map((v, i) => el('tr', null,
        el('td.mono', null, v.id), el('td.nowrap', { title: fmtDateTime(v.created * 1000) }, fmtAgo(v.created * 1000)),
        el('td', null, v.author), el('td', null, v.note, i === 0 ? el('span.badge.ok', { style: { marginLeft: '6px' } }, 'aktuell') : null),
        el('td.nowrap', null,
          el('button.btn.sm', { onclick: () => compare(v) }, 'Vergleichen'), ' ',
          i > 0 ? el('button.btn.sm', { onclick: () => restore(v) }, 'Wiederherstellen') : null)))))) : empty('Noch keine Versionen'), { wide: true });
    async function compare(v) {
      const res = await get('/config/versions/' + v.id);
      const pairs = {};
      const names = new Set([...Object.keys(res.files), ...files.map(f => f.path)]);
      for (const n of names) pairs[n] = [res.files[n], buffers[n] ?? await load(n).catch(() => null)];
      modal(`Version #${v.id} → aktueller Stand`, diffView(pairs), { wide: true, actions: [{ label: 'Schließen' }] });
    }
    async function restore(v) {
      if (!await confirmDialog(`Version #${v.id} wiederherstellen`, 'Die Dateien werden auf diesen Stand gesetzt und Caddy neu geladen. Der aktuelle Stand bleibt als Version erhalten.', 'Wiederherstellen', 'primary')) return;
      try {
        const res = await post(`/config/versions/${v.id}/restore`);
        if (!res.applied) return toast('Wiederherstellung abgelehnt: ' + (res.diagnostics?.[0]?.message || res.error), 'bad', 8000);
        m.close();
        toast(`Version #${v.id} wiederhergestellt`, 'ok');
        for (const k of Object.keys(orig)) delete orig[k];
        for (const k of Object.keys(buffers)) { delete buffers[k]; ed.forget(k); }
        ed.forget(current);
        files = (await get('/config/files')).files;
        ed.setValue(await load(current).catch(() => load(meta.main)), current);
        drawFiles(); drawOutline(); validate();
      } catch (e) { errToast(e); }
    }
  }

  async function deleteFile() {
    if (current === meta.main) return toast('Die Haupt-Caddyfile kann nicht gelöscht werden', 'bad');
    if (!await confirmDialog('Datei löschen', `${current} wird beim Übernehmen gelöscht.`, 'Zum Löschen vormerken')) return;
    if (orig[current] == null) { files = files.filter(f => f.path !== current); delete buffers[current]; }
    else deleted.add(current);
    await openFile(meta.main);
  }

  const layout = el('div.editor-layout', null,
    el('aside.ed-side', null, el('h4', null, 'Dateien'), filesBox, el('h4', null, 'Gliederung'), outlineBox),
    el('section.ed-center', null,
      el('div.ed-toolbar', null, fileLabel, el('span.grow'),
        el('button.btn.sm', { onclick: () => validate(false), title: 'Über die Caddy-Admin-API adaptieren' }, 'Prüfen'),
        el('button.btn.sm', { onclick: () => validate(true), title: 'caddy validate: provisioniert alle Module' }, 'Vollständig prüfen'),
        el('button.btn.sm', { onclick: format }, 'Formatieren'),
        el('button.btn.sm', { onclick: insertSentinel, title: 'Fügt `sentinel` in alle Site-Blöcke ohne die Direktive ein' }, 'Sentinel einfügen'),
        el('button.btn.sm', { onclick: newSite, title: 'Neue Site per Formular anlegen' }, 'Neue Site'),
        formBtn,
        el('button.btn.sm', { onclick: snippetMenu }, 'Vorlage …'),
        el('button.btn.sm', { onclick: () => ed.openSearch(), title: 'Strg+F / Strg+H' }, 'Suchen'),
        el('button.btn.sm', { onclick: commandPalette, title: 'Alle Befehle (F1)' }, 'Befehle'),
        el('button.btn.sm', { onclick: showDiff }, 'Änderungen'),
        el('button.btn.sm.ghost', { onclick: deleteFile, title: 'Datei löschen' }, 'Löschen'),
        el('button.btn.sm.ghost', { onclick: () => layout.classList.toggle('docs-open'), class: 'docs-toggle' }, 'Doku')),
      ed.el,
      diagBox,
      el('div.ed-status', null, statusMsg, crumbsBox, el('span.grow'), cursorInfo, el('a.muted.keys', { onclick: shortcuts, style: { cursor: 'pointer' }, title: 'Alle Tastenkürzel' }, 'F1: Befehle · ⌨ Kürzel'))),
    el('aside.ed-docs', null, el('h4', null, 'Referenz'), docsSearch, docsBox));

  setActions(
    el('button.btn', { onclick: versions }, 'Versionen'),
    el('button.btn', { onclick: discard }, 'Verwerfen'),
    applyBtn);
  mount(root, layout);
  drawFiles();
  drawOutline();
  drawList('Direktiven', DIRECTIVES, false);
  validate();
  refreshContext();
  scope.listen(window, 'beforeunload', (e) => { if (dirty().length) { e.preventDefault(); e.returnValue = ''; } });
  window.__leaveGuard = () => dirty().length > 0 || deleted.size > 0;
  scope.on(() => { window.__leaveGuard = null; });
  scope.on(() => { if (dirty().length) toast('Hinweis: ungespeicherte Editor-Änderungen wurden verworfen', 'bad', 6000); });
}
