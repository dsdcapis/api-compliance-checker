// Small, dependency-free helpers shared by the engine (runs in browser and Node).

export const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

export const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/** Collapse case and separators so `pro_number`, `ProNumber`, `pro-number` compare equal. */
export const squash = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Returns a short reason string when two identifiers look like the same concept
 * spelled differently, otherwise null.
 */
export function nameSimilarity(standardName, implName) {
  if (standardName === implName) return null;
  const a = squash(standardName);
  const b = squash(implName);
  if (!a || !b) return null;
  if (a === b) return 'casing/separator differs';
  const longest = Math.max(a.length, b.length);
  if (longest >= 5) {
    const d = levenshtein(a, b);
    if (d <= (longest >= 10 ? 2 : 1)) return 'spelling differs';
  }
  // Abbreviation / truncation, e.g. `proNum` vs `proNumber`, `qty` handled poorly on purpose.
  // Kept tight (≤3 extra chars) so compound names like `paymentCard` are not read as `payment`.
  if (Math.min(a.length, b.length) >= 4 && (a.startsWith(b) || b.startsWith(a)) && longest - Math.min(a.length, b.length) <= 3) {
    return 'abbreviated or extended';
  }
  return null;
}

/** Best near-match for `name` among `candidates`, or null. */
export function findNearMatch(name, candidates) {
  let best = null;
  for (const c of candidates) {
    const reason = nameSimilarity(name, c);
    if (!reason) continue;
    const score = levenshtein(squash(name), squash(c));
    if (!best || score < best.score) best = { name: c, reason, score };
  }
  return best;
}

export function caseStyle(name) {
  if (/^[a-z][a-zA-Z0-9]*$/.test(name)) return /[A-Z]/.test(name) ? 'camelCase' : 'lowercase';
  if (/^[A-Z][a-zA-Z0-9]*$/.test(name)) return /^[A-Z0-9]+$/.test(name) ? 'UPPERCASE' : 'PascalCase';
  if (/^[a-z][a-z0-9]*(_[a-z0-9]+)+$/.test(name)) return 'snake_case';
  if (/^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(name)) return 'kebab-case';
  if (/^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$/.test(name)) return 'SCREAMING_SNAKE';
  return 'mixed';
}

/** camelCase and single-word lowercase names are the same convention. */
export const conventionOf = (name) => {
  const s = caseStyle(name);
  return s === 'lowercase' ? 'camelCase' : s;
};

export const fmt = (v) => {
  if (v === undefined) return '(none)';
  if (typeof v === 'string') return v;
  try {
    const s = JSON.stringify(v);
    return s.length > 160 ? s.slice(0, 157) + '…' : s;
  } catch {
    return String(v);
  }
};
