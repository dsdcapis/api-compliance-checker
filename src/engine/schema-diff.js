import { isObj, findNearMatch, fmt } from './util.js';
import { refName } from './refs.js';

const MAX_DEPTH = 40;

/** Deref + flatten `allOf` so both sides are compared on their effective shape. */
export function normalizeSchema(node, resolver, depth = 0) {
  const { node: n, ref } = resolver.deref(node);
  if (!isObj(n)) return { schema: {}, ref };
  if (!Array.isArray(n.allOf) || depth > 10) return { schema: n, ref };

  const merged = { ...n, properties: { ...(n.properties || {}) }, required: [...(n.required || [])] };
  delete merged.allOf;
  for (const part of n.allOf) {
    const { schema: p } = normalizeSchema(part, resolver, depth + 1);
    if (p.type && !merged.type) merged.type = p.type;
    Object.assign(merged.properties, p.properties || {});
    merged.required.push(...(p.required || []));
    for (const k of ['enum', 'format', 'items', 'oneOf', 'anyOf', 'nullable', 'additionalProperties']) {
      if (p[k] !== undefined && merged[k] === undefined) merged[k] = p[k];
    }
  }
  if (!Object.keys(merged.properties).length) delete merged.properties;
  merged.required = [...new Set(merged.required)];
  if (!merged.required.length) delete merged.required;
  return { schema: merged, ref };
}

function typeInfo(s) {
  let types = [];
  if (Array.isArray(s.type)) types = s.type;
  else if (typeof s.type === 'string') types = [s.type];
  else if (s.properties) types = ['object'];
  else if (s.items) types = ['array'];
  const nullable = s.nullable === true || types.includes('null');
  return { types: types.filter((t) => t !== 'null'), nullable };
}

/** Does `inner` fit inside `outer`? integer is a subset of number. */
const typeFits = (inner, outer) => outer.includes(inner) || (inner === 'integer' && outer.includes('number'));

const CONSTRAINTS = [
  // [keyword, which direction is "stricter"]
  ['maxLength', 'lower'], ['minLength', 'higher'],
  ['maximum', 'lower'], ['minimum', 'higher'],
  ['maxItems', 'lower'], ['minItems', 'higher'],
];

/**
 * Compare a standard schema against an implementation schema.
 * dir = 'request'  -> implementation must ACCEPT everything the standard allows.
 * dir = 'response' -> implementation must only SEND what the standard allows.
 */
export function diffSchema(stdNode, implNode, base, path, dir, ctx, depth = 0) {
  if (ctx.exhausted() || depth > MAX_DEPTH) return;
  const s0 = normalizeSchema(stdNode, ctx.std);
  const i0 = normalizeSchema(implNode, ctx.impl);
  const s = s0.schema;
  const i = i0.schema;

  // Shared component pairs are compared once; their findings are reported at the first place they appear.
  if (s0.ref && i0.ref) {
    const key = `${dir}|${s0.ref}|${i0.ref}`;
    if (ctx.seenPairs.has(key)) return;
    ctx.seenPairs.add(key);
    if (refName(s0.ref) !== refName(i0.ref) && depth === 0) {
      ctx.add({
        severity: 'info', category: 'terminology', rule: 'schema-name',
        location: loc(base, path),
        message: `Schema is named "${refName(i0.ref)}"; the standard calls it "${refName(s0.ref)}".`,
        standard: refName(s0.ref), yours: refName(i0.ref),
      });
    }
  }
  if (i0.ref && ctx.impl.unresolved.has(i0.ref)) return; // reported once globally

  const where = loc(base, path);
  const st = typeInfo(s);
  const it = typeInfo(i);

  // ---- type --------------------------------------------------------------
  if (st.types.length && it.types.length) {
    const ok = dir === 'request'
      ? st.types.every((t) => typeFits(t, it.types))
      : it.types.every((t) => typeFits(t, st.types));
    if (!ok) {
      ctx.add({
        severity: 'breaking', category: 'fields', rule: 'type-mismatch', location: where,
        message: `Data type differs from the standard.`,
        standard: st.types.join(' | '), yours: it.types.join(' | '),
      });
      return; // children are meaningless once the type differs
    }
  } else if (st.types.length && !it.types.length && !i.oneOf && !i.anyOf && depth > 0) {
    ctx.add({
      severity: 'warning', category: 'fields', rule: 'type-missing', location: where,
      message: `No data type declared; the standard specifies "${st.types.join(' | ')}".`,
      standard: st.types.join(' | '), yours: '(untyped)',
    });
  }

  if (dir === 'request' && st.nullable && !it.nullable) {
    ctx.add({ severity: 'warning', category: 'fields', rule: 'nullable', location: where,
      message: 'The standard allows null here but your API does not accept null.', standard: 'nullable', yours: 'not nullable' });
  }
  if (dir === 'response' && it.nullable && !st.nullable) {
    ctx.add({ severity: 'warning', category: 'fields', rule: 'nullable', location: where,
      message: 'Your API may return null here; the standard does not allow null.', standard: 'not nullable', yours: 'nullable' });
  }

  // ---- format ------------------------------------------------------------
  if (s.format && i.format && s.format !== i.format) {
    ctx.add({ severity: 'warning', category: 'fields', rule: 'format', location: where,
      message: `Format differs from the standard.`, standard: s.format, yours: i.format });
  } else if (s.format && !i.format && depth > 0) {
    ctx.add({ severity: 'info', category: 'fields', rule: 'format-missing', location: where,
      message: `The standard declares format "${s.format}"; your definition omits it.`, standard: s.format, yours: '(none)' });
  }

  // ---- enum --------------------------------------------------------------
  diffEnum(s, i, where, dir, ctx);

  // ---- constraints -------------------------------------------------------
  for (const [kw, strictDir] of CONSTRAINTS) {
    const sv = s[kw];
    const iv = i[kw];
    if (sv === undefined && iv === undefined) continue;
    if (sv !== undefined && iv !== undefined && sv !== iv) {
      const implStricter = strictDir === 'lower' ? iv < sv : iv > sv;
      const risky = dir === 'request' ? implStricter : !implStricter;
      ctx.add({ severity: risky ? 'warning' : 'info', category: 'fields', rule: 'constraint', location: where,
        message: `${kw} differs from the standard${risky ? (dir === 'request' ? ' — your API may reject valid standard payloads' : ' — your API may send values the standard does not allow') : ''}.`,
        standard: sv, yours: iv });
    } else if (sv === undefined && iv !== undefined && dir === 'request') {
      ctx.add({ severity: 'info', category: 'fields', rule: 'constraint-added', location: where,
        message: `Your API adds a ${kw} limit that is not in the standard.`, standard: '(none)', yours: iv });
    } else if (sv !== undefined && iv === undefined && dir === 'response') {
      ctx.add({ severity: 'info', category: 'fields', rule: 'constraint-missing', location: where,
        message: `The standard limits ${kw}; your definition does not.`, standard: sv, yours: '(none)' });
    }
  }
  if (s.pattern && i.pattern && s.pattern !== i.pattern) {
    ctx.add({ severity: 'warning', category: 'fields', rule: 'pattern', location: where,
      message: 'Validation pattern differs from the standard.', standard: s.pattern, yours: i.pattern });
  }

  // ---- object properties -------------------------------------------------
  if (s.properties || i.properties) diffProperties(s, i, base, path, dir, ctx, depth);

  if (dir === 'response' && s.additionalProperties === false && i.additionalProperties !== false && i.properties) {
    ctx.add({ severity: 'info', category: 'fields', rule: 'additional-properties', location: where,
      message: 'The standard forbids undeclared properties here; your definition allows them.' });
  }

  // ---- arrays ------------------------------------------------------------
  if (s.items || i.items) {
    if (s.items && i.items) diffSchema(s.items, i.items, base, [...path, '[]'], dir, ctx, depth + 1);
  }

  // ---- composition -------------------------------------------------------
  for (const kw of ['oneOf', 'anyOf']) {
    const sa = Array.isArray(s[kw]) ? s[kw] : null;
    const ia = Array.isArray(i[kw]) ? i[kw] : null;
    if (sa && ia) {
      if (sa.length !== ia.length) {
        ctx.add({ severity: 'warning', category: 'fields', rule: 'composition', location: where,
          message: `${kw} has ${ia.length} option(s); the standard has ${sa.length}.`, standard: sa.length, yours: ia.length });
      }
      for (let k = 0; k < Math.min(sa.length, ia.length); k++) {
        diffSchema(sa[k], ia[k], base, [...path, `${kw}[${k}]`], dir, ctx, depth + 1);
      }
    } else if (sa && !ia) {
      ctx.add({ severity: 'warning', category: 'fields', rule: 'composition', location: where,
        message: `The standard defines ${sa.length} alternative shapes (${kw}) here; your definition has a single shape.` });
    } else if (!sa && ia && dir === 'response') {
      ctx.add({ severity: 'warning', category: 'fields', rule: 'composition', location: where,
        message: `Your API may return one of ${ia.length} shapes (${kw}); the standard defines a single shape.` });
    }
  }
}

function diffProperties(s, i, base, path, dir, ctx, depth) {
  const sp = s.properties || {};
  const ip = i.properties || {};
  const sreq = new Set(s.required || []);
  const ireq = new Set(i.required || []);
  const missing = Object.keys(sp).filter((k) => !(k in ip));
  const extra = new Set(Object.keys(ip).filter((k) => !(k in sp)));

  for (const name of Object.keys(sp)) {
    ctx.stats.fieldsChecked++;
    if (name in ip) ctx.stats.fieldsMatched++;
  }

  // Renamed / misspelled fields: pair them up so they are reported once, as terminology.
  for (const m of missing) {
    const near = findNearMatch(m, extra);
    if (near) {
      extra.delete(near.name);
      const sev = sreq.has(m) || ireq.has(near.name) ? 'breaking' : 'warning';
      ctx.add({ severity: sev, category: 'terminology', rule: 'field-name', location: loc(base, [...path, near.name]),
        message: `Field "${near.name}" appears to be the standard field "${m}" (${near.reason}). Clients built to the standard will not find it.`,
        standard: m, yours: near.name, hint: `Rename "${near.name}" to "${m}".` });
      diffSchema(sp[m], ip[near.name], base, [...path, m], dir, ctx, depth + 1);
      continue;
    }
    const required = sreq.has(m);
    ctx.add({
      severity: required ? 'breaking' : 'warning', category: 'fields', rule: required ? 'missing-required-field' : 'missing-optional-field',
      location: loc(base, [...path, m]),
      message: required
        ? `Required standard field "${m}" is missing.`
        : `Optional standard field "${m}" is not supported${dir === 'request' ? ' — data sent by clients will be dropped' : ''}.`,
      standard: required ? 'required' : 'optional', yours: '(absent)',
    });
  }

  for (const e of extra) {
    const required = ireq.has(e);
    ctx.add({
      severity: required && dir === 'request' ? 'breaking' : 'info', category: 'fields', rule: 'additional-field',
      location: loc(base, [...path, e]),
      message: required && dir === 'request'
        ? `Your API requires field "${e}", which is not in the standard. Standard-compliant clients will not send it.`
        : `Additional field "${e}" is not in the standard.`,
      standard: '(absent)', yours: required ? 'required' : 'optional',
    });
  }

  for (const name of Object.keys(sp)) {
    if (!(name in ip)) continue;
    const sr = sreq.has(name);
    const ir = ireq.has(name);
    if (dir === 'request' && ir && !sr) {
      ctx.add({ severity: 'breaking', category: 'requirements', rule: 'required-mismatch', location: loc(base, [...path, name]),
        message: `Your API requires "${name}", but it is optional in the standard. Compliant requests that omit it will be rejected.`,
        standard: 'optional', yours: 'required' });
    } else if (dir === 'response' && sr && !ir) {
      ctx.add({ severity: 'warning', category: 'requirements', rule: 'required-mismatch', location: loc(base, [...path, name]),
        message: `The standard requires "${name}" to always be present in the response; your API marks it optional.`,
        standard: 'required', yours: 'optional' });
    } else if (dir === 'request' && sr && !ir) {
      ctx.add({ severity: 'info', category: 'requirements', rule: 'required-relaxed', location: loc(base, [...path, name]),
        message: `The standard requires "${name}"; your API accepts requests without it.`, standard: 'required', yours: 'optional' });
    }
    diffSchema(sp[name], ip[name], base, [...path, name], dir, ctx, depth + 1);
  }
}

function diffEnum(s, i, where, dir, ctx) {
  const se = Array.isArray(s.enum) ? s.enum.filter((v) => v !== null) : null;
  const ie = Array.isArray(i.enum) ? i.enum.filter((v) => v !== null) : null;
  if (!se && !ie) return;
  if (se && !ie) {
    ctx.add({ severity: dir === 'response' ? 'warning' : 'info', category: 'fields', rule: 'enum-missing', location: where,
      message: `The standard restricts this to a fixed list of values; your definition does not.`, standard: se, yours: '(any value)' });
    return;
  }
  if (!se && ie) {
    if (dir === 'request') {
      ctx.add({ severity: 'warning', category: 'fields', rule: 'enum-added', location: where,
        message: `Your API restricts this to a fixed list of values; the standard allows any value.`, standard: '(any value)', yours: ie });
    }
    return;
  }
  const key = (v) => JSON.stringify(v);
  const iset = new Set(ie.map(key));
  const sset = new Set(se.map(key));
  const missing = se.filter((v) => !iset.has(key(v)));
  const extra = ie.filter((v) => !sset.has(key(v)));
  const extraStrings = new Set(extra.filter((v) => typeof v === 'string'));

  for (const m of missing) {
    const near = typeof m === 'string' ? findNearMatch(m, extraStrings) : null;
    if (near) {
      extraStrings.delete(near.name);
      extra.splice(extra.indexOf(near.name), 1);
      ctx.add({ severity: 'breaking', category: 'terminology', rule: 'enum-value-name', location: where,
        message: `Code value "${near.name}" appears to be the standard value "${m}" (${near.reason}).`,
        standard: m, yours: near.name, hint: `Use the exact standard value "${m}".` });
      continue;
    }
    ctx.add({ severity: dir === 'request' ? 'breaking' : 'info', category: 'fields', rule: 'enum-value-missing', location: where,
      message: dir === 'request'
        ? `Standard value ${fmt(m)} is not accepted by your API.`
        : `Your API never returns standard value ${fmt(m)}.`,
      standard: m, yours: '(absent)' });
  }
  for (const e of extra) {
    ctx.add({ severity: dir === 'response' ? 'breaking' : 'info', category: 'fields', rule: 'enum-value-extra', location: where,
      message: dir === 'response'
        ? `Your API may return value ${fmt(e)}, which is not in the standard. Standard clients will not recognize it.`
        : `Your API accepts additional value ${fmt(e)}, which is not in the standard.`,
      standard: '(absent)', yours: e });
  }
}

function loc(base, path) {
  if (!path.length) return base;
  return `${base} › ${path.join('.').replace(/\.\[\]/g, '[]')}`;
}
