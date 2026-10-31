import { can, el, mount, get, post, put, del, panel, field, toggle, toast, errToast, modal, confirmDialog, empty, fmtMs, fmtAgo, fmtDateTime, fmtPct } from '../ui.js';
import { spark } from '../charts.js';
import { setActions, bus } from '../app.js';

export async function render(root, _p, scope) {
  const load = async () => {
    const mons = await get('/monitors', scope.signal);
    draw(mons);
  };
  if (can('policy')) setActions(
    el('button.btn', { onclick: suggest }, 'Sites übernehmen'),
    el('button.btn.primary', { onclick: () => edit() }, 'Monitor hinzufügen'));
  else setActions();

  function pct(v) { return v < 0 ? '–' : fmtPct(v).replace(',0 %', ' %'); }
  function bars(b) {
    return el('div.upbars', { 'aria-label': 'Verfügbarkeit der letzten 90 Stunden' }, b.map((v, i) => el('i.' + (v < 0 ? 'none' : v >= 0.999 ? 'up' : v >= 0.9 ? 'part' : 'down'), {
      title: `vor ${89 - i} Std.: ${v < 0 ? 'keine Daten' : pct(v)}`,
    })));
  }

  function draw(mons) {
    const down = mons.filter(m => m.enabled && m.state && !m.state.up).length;
    mount(root,
      el('p.muted', null, 'Sentinel ruft die Adressen regelmäßig selbst auf und meldet Ausfälle (zwei Fehlschläge in Folge) sowie die Wiederherstellung über die eingerichteten Benachrichtigungen.'),
      mons.length ? el('div.kpis', null,
        el('div.kpi.' + (down ? 'bad' : 'ok'), null, el('div.label', null, 'Status'), el('div.value', null, down ? `${down} gestört` : 'Alles erreichbar')),
        el('div.kpi', null, el('div.label', null, 'Monitore'), el('div.value', null, mons.length))) : null,
      panel('Monitore', mons.length ? el('div.table-wrap', null, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'Name'), el('th', null, 'Status'), el('th', null, 'Letzte 90 Stunden'), el('th.num', null, '24 h'), el('th.num', null, '7 Tage'), el('th.num', null, '30 Tage'), el('th', null, 'Antwortzeit'), el('th', null, ''))),
        el('tbody', null, mons.map(m => {
          const st = m.state;
          const last = st?.last;
          return el('tr', null,
            el('td', null, el('b', null, m.name), el('div', null, el('small.mono', null, m.url))),
            el('td', { style: { maxWidth: '240px' } }, !m.enabled ? el('span.badge', null, 'pausiert') : !st ? el('span.badge', null, 'wartet') : st.up ? el('span.badge.ok', null, 'erreichbar') : el('span.badge.bad', null, 'gestört'),
              st ? el('div', null, el('small', { title: fmtDateTime(new Date(st.since).getTime()) }, (st.up ? 'seit ' : 'seit ') + fmtAgo(new Date(st.since).getTime()).replace('vor ', ''))) : null,
              last?.error ? el('div', null, el('small', { title: last.error, style: { color: st?.up ? 'var(--warn)' : 'var(--bad)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, last.error.replace(/^Get "[^"]+": /, ''))) : null),
            el('td', null, bars(m.bars || [])),
            el('td.num', null, pct(m.uptime_24h)), el('td.num', null, pct(m.uptime_7d)), el('td.num', null, pct(m.uptime_30d)),
            el('td.nowrap', null, spark(m.lat || [], { width: 110 }), el('small', null, 'Ø ' + fmtMs(m.avg_ms))),
            el('td.nowrap', null, can('policy') ? el('button.btn.sm', { onclick: () => edit(m) }, 'Bearbeiten') : null));
        })))) : empty('Noch keine Monitore', 'Übernimm die Hosts aus deiner Caddy-Konfiguration oder lege eine Adresse an.', el('button.btn', { onclick: suggest }, 'Sites übernehmen'))));
  }

  async function suggest() {
    try {
      const list = await get('/monitors/suggest');
      if (!list.length) return toast('Alle Hosts aus der Konfiguration werden bereits überwacht', 'info');
      const chosen = new Set(list.map(m => m.url));
      modal('Sites überwachen', [
        el('p.muted', null, 'Diese Hosts stehen in der laufenden Caddy-Konfiguration:'),
        el('div.stack', { style: { gap: '6px' } }, list.map(m => el('label.toggle', null,
          el('input', { type: 'checkbox', checked: true, onchange: (e) => e.target.checked ? chosen.add(m.url) : chosen.delete(m.url) }),
          el('span.track', null, el('span.thumb')), el('span.mono', null, m.url)))),
      ], {
        actions: [{ label: 'Abbrechen' }, {
          label: 'Überwachen', kind: 'primary', onClick: async () => {
            for (const m of list.filter(x => chosen.has(x.url))) await post('/monitors', m);
            toast(`${chosen.size} Monitore angelegt`, 'ok');
            load();
          },
        }],
      });
    } catch (e) { errToast(e); }
  }

  function edit(m) {
    const d = m ? { ...m } : { name: '', url: 'https://', interval_s: 60, timeout_s: 10, expect_status: '', keyword: '', insecure: false, enabled: true };
    const result = el('div');
    const inp = (k, attrs = {}) => el('input', { value: d[k] ?? '', ...attrs, oninput: (e) => { d[k] = attrs.type === 'number' ? +e.target.value : e.target.value; } });
    modal(m ? 'Monitor bearbeiten' : 'Neuer Monitor', [
      el('div.fields', null,
        field('Name', inp('name', { placeholder: 'Blog' })),
        el('div.field.wide', null, el('span', null, 'URL'), inp('url', { placeholder: 'https://example.com/health', class: 'mono' })),
        field('Intervall (s)', inp('interval_s', { type: 'number', min: 15 })),
        field('Timeout (s)', inp('timeout_s', { type: 'number', min: 1, max: 60 })),
        field('Erwarteter Status', inp('expect_status', { placeholder: 'leer = < 400, z. B. 200 oder 2xx' })),
        field('Muss enthalten', inp('keyword', { placeholder: 'optionales Schlüsselwort' })),
        el('div.field', null, el('span', null, 'Zertifikat'), toggle(d.insecure, (v) => { d.insecure = v; }, 'nicht prüfen')),
        el('div.field', null, el('span', null, 'Aktiv'), toggle(d.enabled, (v) => { d.enabled = v; }, 'überwachen'))),
      el('div.row', null, el('button.btn.sm', {
        onclick: async () => {
          mount(result, el('span.muted', null, 'Prüfe …'));
          try {
            const c = await post('/monitors/test', d);
            mount(result, el('div.callout.' + (c.ok ? 'ok' : 'bad'), null, c.ok ? `Erreichbar: Status ${c.status} in ${fmtMs(c.ms)}` : `Fehler: ${c.error || 'Status ' + c.status}`, c.ok && c.error ? el('div', null, c.error) : null));
          } catch (e) { mount(result, el('div.callout.bad', null, e.message)); }
        },
      }, 'Jetzt testen'), result),
    ], {
      actions: [
        m ? { label: 'Löschen', kind: 'danger', onClick: async () => { if (!await confirmDialog('Monitor löschen', `„${m.name}“ und seinen Verlauf löschen?`, 'Löschen')) return false; await del('/monitors/' + m.id); load(); } } : null,
        { label: 'Abbrechen' },
        { label: 'Speichern', kind: 'primary', onClick: async () => { m ? await put('/monitors/' + m.id, d) : await post('/monitors', d); toast('Monitor gespeichert', 'ok'); load(); } },
      ].filter(Boolean),
    });
  }

  await load();
  scope.interval(() => { if (!document.hidden) load().catch(() => { }); }, 20000);
  scope.listen(bus, 'monitor', () => load().catch(() => { }));
}
