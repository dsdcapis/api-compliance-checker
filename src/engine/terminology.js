import { isObj, findNearMatch, conventionOf } from './util.js';

/** Every property name declared anywhere in the document. */
export function vocabulary(doc) {
  const names = new Set();
  const seen = new Set();
  const walk = (n) => {
    if (n === null || typeof n !== 'object' || seen.has(n)) return;
    seen.add(n);
    if (isObj(n.properties)) for (const k of Object.keys(n.properties)) names.add(k);
    for (const [k, v] of Object.entries(n)) if (k !== 'example' && k !== 'examples') walk(v);
  };
  walk(doc);
  return names;
}

export function checkTerminology(std, impl, ctx) {
  const sv = vocabulary(std);
  const iv = vocabulary(impl);

  // Near-miss names the structural diff didn't already pair up (e.g. in additional schemas).
  for (const name of iv) {
    if (sv.has(name) || ctx.reportedNames.has(name)) continue;
    const near = findNearMatch(name, sv);
    if (near) {
      ctx.add({ severity: 'warning', category: 'terminology', rule: 'term-variant', location: `field "${name}"`,
        message: `"${name}" looks like the standard term "${near.name}" (${near.reason}).`,
        standard: near.name, yours: name, hint: `Use the standard term "${near.name}".` });
    }
  }

  // Naming convention.
  const counts = {};
  for (const n of sv) { const c = conventionOf(n); counts[c] = (counts[c] || 0) + 1; }
  const [dominant, count] = Object.entries(counts).sort((a, b) => b[1] - a[1])[0] || [];
  if (!dominant || count / sv.size < 0.7) return;
  const off = [...iv].filter((n) => !sv.has(n) && conventionOf(n) !== dominant && conventionOf(n) !== 'mixed');
  if (off.length) {
    ctx.add({ severity: 'warning', category: 'terminology', rule: 'naming-convention', location: `${off.length} field name(s)`,
      message: `The standard names fields in ${dominant}; these do not: ${off.slice(0, 12).join(', ')}${off.length > 12 ? ` … (+${off.length - 12} more)` : ''}.`,
      standard: dominant, yours: [...new Set(off.map(conventionOf))].join(', ') });
  }
}
