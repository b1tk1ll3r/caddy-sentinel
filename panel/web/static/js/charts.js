// Minimal SVG charts with hover tooltips. No dependencies.
import { el } from './ui.js';

const NS = 'http://www.w3.org/2000/svg';
const s = (tag, attrs = {}, ...kids) => {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v);
  for (const k of kids) if (k) n.append(k);
  return n;
};

// Axis scale with round ticks (1, 2, 2.5, 5 × 10^k) and at most `maxTicks`
// intervals. Counts never get fractional ticks.
function niceScale(v, maxTicks = 4, integer = false) {
  if (!(v > 0)) return { max: maxTicks, step: 1 };
  const raw = v / maxTicks;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  let step = p * 10;
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (m * p >= raw) { step = m * p; break; }
  }
  if (integer && !Number.isInteger(step)) step = step < 1 ? 1 : Math.ceil(step / 5) * 5;
  return { max: Math.ceil(v / step - 1e-9) * step, step };
}

const tfmt = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit' });
const dfmt = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit' });
const dtfmt = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

function timeLabel(t, span) {
  const d = new Date(t * 1000);
  return span > 2 * 86400 ? dfmt.format(d) : tfmt.format(d);
}

/**
 * Time series chart.
 * opts: { t: [unix], series: [{label, values, color, dashed}], stacked, kind: 'area'|'line'|'bar',
 *         height, yFormat, tipFormat, step }
 */
export function timeChart(opts) {
  const host = el('div.chart', { style: { height: (opts.height || 200) + 'px' } });
  const tip = el('div.chart-tip', { hidden: true });
  host.append(tip);
  let svg;
  const draw = () => {
    const W = Math.max(host.clientWidth, 200);
    const H = opts.height || 200;
    const padL = 44, padR = 8, padT = 8, padB = 22;
    const iw = W - padL - padR, ih = H - padT - padB;
    const t = opts.t || [];
    const n = t.length;
    const series = opts.series.filter(x => !x.hidden);
    const stacked = opts.stacked;
    const tops = new Array(n).fill(0);
    let max = 0;
    for (let i = 0; i < n; i++) {
      let acc = 0;
      for (const sr of series) {
        const v = sr.values[i] || 0;
        if (stacked) acc += v; else acc = Math.max(acc, v);
      }
      tops[i] = acc;
      max = Math.max(max, acc);
    }
    const empty = n === 0 || max === 0;
    const sc = niceScale(max, 4, !opts.fractional);
    max = sc.max;
    const x = (i) => padL + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v) => padT + ih - (v / max) * ih;
    if (svg) svg.remove();
    svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': opts.label || 'Diagramm' });
    // grid
    const yf = opts.yFormat || ((v) => v);
    for (let v = 0; v <= max + sc.step / 2; v += sc.step) {
      const yy = y(v);
      svg.append(s('line', { x1: padL, x2: W - padR, y1: yy, y2: yy, class: 'grid' }));
      svg.append(s('text', { x: padL - 6, y: yy + 3, class: 'axis', 'text-anchor': 'end' }, document.createTextNode(yf(v))));
    }
    // x labels
    if (n > 1) {
      const span = t[n - 1] - t[0];
      const ticks = Math.min(6, Math.max(2, Math.floor(iw / 90)));
      for (let k = 0; k <= ticks; k++) {
        const i = Math.round((k / ticks) * (n - 1));
        svg.append(s('text', { x: x(i), y: H - 6, class: 'axis', 'text-anchor': k === 0 ? 'start' : k === ticks ? 'end' : 'middle' },
          document.createTextNode(timeLabel(t[i], span))));
      }
    }
    // series
    const base = new Array(n).fill(0);
    const kind = opts.kind || 'area';
    if (n === 0) { /* nothing to draw yet */ } else if (kind === 'bar') {
      // thin bars with a gap to the neighbour; the data end is rounded
      const slot = iw / Math.max(n, 1);
      const gap = slot > 6 ? 2 : slot > 3 ? 1 : 0;
      const bw = Math.max(1, slot - gap);
      for (const [si, sr] of series.entries()) {
        const g = s('g', { fill: sr.color });
        const last = si === series.length - 1 || !stacked;
        for (let i = 0; i < n; i++) {
          const v = sr.values[i] || 0;
          if (!v) continue;
          const y0 = stacked ? base[i] : 0;
          const h = Math.max((v / max) * ih, 1);
          const bx = padL + i * slot, by = y(y0) - h;
          const r = last && bw >= 6 ? Math.min(3, bw / 2, h) : 0;
          g.append(s('path', { d: r ? `M${bx},${by + h}V${by + r}Q${bx},${by} ${bx + r},${by}H${bx + bw - r}Q${bx + bw},${by} ${bx + bw},${by + r}V${by + h}Z` : `M${bx},${by + h}V${by}H${bx + bw}V${by + h}Z` }));
          if (stacked) base[i] += v;
        }
        svg.append(g);
      }
    } else {
      for (const sr of series) {
        // a stacked series without any value would draw its line along the
        // top of the stack and look like data
        if (stacked && !sr.values.some(v => v > 0)) continue;
        let d = '', area = '';
        for (let i = 0; i < n; i++) {
          const v = sr.values[i] || 0;
          const y0 = stacked ? base[i] : 0;
          d += (i ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(y0 + v).toFixed(1);
        }
        if (kind === 'area') {
          area = d;
          for (let i = n - 1; i >= 0; i--) area += 'L' + x(i).toFixed(1) + ',' + y(stacked ? base[i] : 0).toFixed(1);
          area += 'Z';
          svg.append(s('path', { d: area, fill: sr.color, 'fill-opacity': stacked ? 0.55 : 0.14, stroke: 'none' }));
        }
        svg.append(s('path', { d, fill: 'none', stroke: sr.color, 'stroke-width': sr.width || 2, 'stroke-dasharray': sr.dashed ? '5 4' : null, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
        if (stacked) for (let i = 0; i < n; i++) base[i] += sr.values[i] || 0;
      }
    }
    if (empty) {
      svg.append(s('text', { x: padL + iw / 2, y: padT + ih / 2, class: 'axis empty-note', 'text-anchor': 'middle' },
        document.createTextNode(n === 0 ? 'Noch keine Daten' : 'Keine Ereignisse im Zeitraum')));
    }
    // markers (e.g. configuration changes): markers closer than 10 px are
    // drawn as one, with the number of events
    const marks = (opts.markers || []).filter(m => n > 1 && m.t >= t[0] && m.t <= t[n - 1] + (t[1] - t[0]));
    const mx = (mt) => Math.min(padL + iw, padL + ((mt - t[0]) / Math.max(1, t[n - 1] - t[0])) * iw);
    const groups = [];
    for (const m of [...marks].sort((a, b) => a.t - b.t)) {
      const xx = mx(m.t);
      const g = groups[groups.length - 1];
      if (g && xx - g.x < 10) g.items.push(m); else groups.push({ x: xx, items: [m] });
    }
    for (const gr of groups) {
      const xx = gr.x;
      const g = s('g', { class: 'marker', style: `color:${gr.items[0].color || 'var(--ink-2)'}` });
      g.append(s('line', { x1: xx, x2: xx, y1: padT + 8, y2: padT + ih, stroke: 'currentColor', 'stroke-dasharray': '2 3', 'stroke-width': 1, opacity: 0.7 }));
      g.append(s('path', { d: `M${xx},${padT} L${xx + 5},${padT + 5} L${xx},${padT + 10} L${xx - 5},${padT + 5}Z`, fill: 'currentColor', stroke: 'var(--surface)', 'stroke-width': 1.5 }));
      if (gr.items.length > 1) g.append(s('text', { x: xx + 8, y: padT + 9, class: 'axis marker-n' }, document.createTextNode(String(gr.items.length))));
      svg.append(g);
    }
    // hover
    const cross = s('line', { y1: padT, y2: padT + ih, class: 'cross', visibility: 'hidden' });
    svg.append(cross);
    const overlay = s('rect', { x: padL, y: padT, width: iw, height: ih, fill: 'transparent' });
    svg.append(overlay);
    const tipFmt = opts.tipFormat || yf;
    overlay.addEventListener('mousemove', (e) => {
      const r = svg.getBoundingClientRect();
      const px = e.clientX - r.left;
      const i = Math.max(0, Math.min(n - 1, Math.round(((px - padL) / iw) * (n - 1))));
      if (!n || empty) return;
      cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('visibility', 'visible');
      tip.replaceChildren(
        el('div.tip-time', null, dtfmt.format(new Date(t[i] * 1000))),
        ...series.map(sr => el('div.tip-row', null, el('i', { style: { background: sr.color } }), el('span', null, sr.label), el('b', null, tipFmt(sr.values[i] || 0)))),
        ...marks.filter(m => m.t >= t[i] && (i === n - 1 || m.t < t[i + 1])).map(m => el('div.tip-mark', null, '◆ ', m.label)));
      tip.hidden = false;
      const left = x(i) + 12;
      tip.style.left = (left + 180 > W ? x(i) - 12 - tip.offsetWidth : left) + 'px';
      tip.style.top = padT + 'px';
    });
    overlay.addEventListener('mouseleave', () => { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); });
    if (opts.onMarker && marks.length) overlay.addEventListener('click', (e) => {
      const r = svg.getBoundingClientRect();
      const px = e.clientX - r.left;
      let best = null, bd = 12;
      for (const gr of groups) { const d = Math.abs(gr.x - px); if (d < bd) { bd = d; best = gr; } }
      if (best) opts.onMarker(best.items[best.items.length - 1], best.items);
    });
    host.prepend(svg);
  };
  const ro = new ResizeObserver(() => draw());
  ro.observe(host);
  host.update = (o) => { Object.assign(opts, o); draw(); };
  host.destroy = () => ro.disconnect();
  queueMicrotask(draw);
  return host;
}

export function legend(series, onToggle) {
  return el('div.legend', null, series.map(sr => el('button.legend-item' + (sr.hidden ? '.off' : ''), {
    onclick: onToggle ? (e) => { sr.hidden = !sr.hidden; e.currentTarget.classList.toggle('off', sr.hidden); onToggle(); } : null,
    type: 'button',
  }, el('i', { style: { background: sr.color } }), sr.label)));
}

/** Sparkline (inline SVG). */
export function spark(values, { width = 120, height = 28, color = 'var(--primary)' } = {}) {
  const n = values?.length || 0;
  if (n < 2) return s('svg', { width, height, class: 'spark', 'aria-hidden': 'true' });
  const max = Math.max(1, ...values);
  let d = '';
  for (let i = 0; i < n; i++) {
    const xx = n <= 1 ? 0 : (i / (n - 1)) * width;
    const yy = height - 2 - (values[i] / max) * (height - 4);
    d += (i ? 'L' : 'M') + xx.toFixed(1) + ',' + yy.toFixed(1);
  }
  return s('svg', { width, height, viewBox: `0 0 ${width} ${height}`, class: 'spark', 'aria-hidden': 'true' },
    s('path', { d: d + `L${width},${height}L0,${height}Z`, fill: color, 'fill-opacity': 0.12 }),
    s('path', { d, fill: 'none', stroke: color, 'stroke-width': 1.4 }));
}

/** Vertical bar chart for categorical data (e.g. latency histogram). */
export function barChart(labels, values, { height = 160, color = 'var(--primary)', format = (v) => v } = {}) {
  const max = Math.max(1, ...values);
  return el('div.vbars', { style: { height: height + 'px' } }, labels.map((l, i) =>
    el('div.vbar', { title: `${l}: ${format(values[i])}` },
      el('div.vbar-fill', { style: { height: ((values[i] / max) * 100).toFixed(1) + '%', background: color } }),
      el('span', null, l))));
}

/** Horizontal share bar (stacked) */
export function shareBar(parts) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  return el('div.sharebar', null, parts.filter(p => p.value > 0).map(p =>
    el('span', { style: { width: (p.value / total * 100) + '%', background: p.color }, title: `${p.label}: ${p.value}` })));
}
