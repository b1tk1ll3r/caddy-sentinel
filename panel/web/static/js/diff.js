import { el } from './ui.js';


export function diffLines(a, b) {
  const A = a.split('\n'), B = b.split('\n');
  // trim common prefix/suffix for speed
  let pre = 0;
  while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
  let suf = 0;
  while (suf < A.length - pre && suf < B.length - pre && A[A.length - 1 - suf] === B[B.length - 1 - suf]) suf++;
  const a2 = A.slice(pre, A.length - suf), b2 = B.slice(pre, B.length - suf);
  const n = a2.length, m = b2.length;
  const ops = [];
  if (n * m > 4e6) {
    a2.forEach(l => ops.push(['-', l])); b2.forEach(l => ops.push(['+', l]));
  } else {
    const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a2[i] === b2[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    let i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && a2[i] === b2[j]) { ops.push([' ', a2[i]]); i++; j++; }
      else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) { ops.push(['+', b2[j]]); j++; }
      else { ops.push(['-', a2[i]]); i++; }
    }
  }
  // build hunks with 3 lines of context
  const full = A.slice(0, pre).map(l => [' ', l]).concat(ops, A.slice(A.length - suf).map(l => [' ', l]));
  const out = [];
  let lastShown = -1;
  const changed = full.map(o => o[0] !== ' ');
  for (let k = 0; k < full.length; k++) {
    const near = changed.slice(Math.max(0, k - 3), k + 4).some(Boolean);
    if (!near) continue;
    if (lastShown !== -1 && k - lastShown > 1) out.push(['@', '…']);
    out.push(full[k]);
    lastShown = k;
  }
  return out;
}

export function diffView(files) {
  const parts = [];
  for (const [name, [oldT, newT]] of Object.entries(files)) {
    const d = diffLines(oldT ?? '', newT ?? '');
    if (!d.some(x => x[0] === '+' || x[0] === '-')) continue;
    parts.push(el('div.file', null, name + (oldT == null ? ' (neu)' : newT == null ? ' (gelöscht)' : '')));
    for (const [op, l] of d) parts.push(el('div' + (op === '+' ? '.add' : op === '-' ? '.del' : op === '@' ? '.hunk' : ''), null, (op === '@' ? '' : op + ' ') + l));
  }
  return parts.length ? el('div.diff', null, parts) : el('p.muted', null, 'Keine Unterschiede.');
}

