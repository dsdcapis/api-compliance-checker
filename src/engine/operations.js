import { HTTP_METHODS, isObj, nameSimilarity, findNearMatch } from './util.js';
import { diffSchema } from './schema-diff.js';

const normPath = (p) => (p.replace(/\{[^}]+\}/g, '{}').replace(/\/+$/, '') || '/');
const pathParamNames = (p) => [...p.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
const mediaBase = (m) => m.split(';')[0].trim().toLowerCase();
const isSuccess = (code) => /^2/.test(code);
const isErrorCode = (code) => /^[45]/.test(code) || code === 'default';

/** Pair each standard path with the implementation path that serves it. */
export function matchPaths(stdPaths, implPaths, ctx) {
  const implList = Object.keys(implPaths);
  const used = new Set();
  const matches = [];
  const prefixes = new Map();

  const take = (stdPath, implPath, how, extra = {}) => {
    used.add(implPath);
    matches.push({ stdPath, implPath, how, ...extra });
  };

  for (const sp of Object.keys(stdPaths)) {
    const sn = normPath(sp);
    const free = implList.filter((p) => !used.has(p));

    let hit = free.find((p) => normPath(p) === sn);
    if (hit) { take(sp, hit, 'exact'); continue; }

    // Standard paths start with "/", so a suffix match always lands on a segment boundary.
    hit = sn !== '/' && free.find((p) => {
      const n = normPath(p);
      return n.length > sn.length && n.endsWith(sn);
    });
    if (hit) {
      const prefix = normPath(hit).slice(0, normPath(hit).length - sn.length);
      prefixes.set(prefix, (prefixes.get(prefix) || 0) + 1);
      take(sp, hit, 'prefix', { prefix });
      continue;
    }

    hit = free.find((p) => normPath(p).toLowerCase() === sn.toLowerCase());
    if (hit) { take(sp, hit, 'case'); continue; }

    // Same shape, with one or more segments spelled differently.
    const sseg = sn.split('/');
    hit = free.find((p) => {
      const iseg = normPath(p).split('/');
      if (iseg.length !== sseg.length) return false;
      let diffs = 0;
      for (let k = 0; k < sseg.length; k++) {
        if (sseg[k] === iseg[k]) continue;
        if (!nameSimilarity(sseg[k], iseg[k])) return false;
        diffs++;
      }
      return diffs > 0;
    });
    if (hit) { take(sp, hit, 'similar'); continue; }

    matches.push({ stdPath: sp, implPath: null, how: 'missing' });
  }

  for (const [prefix, count] of prefixes) {
    ctx.add({ severity: 'warning', category: 'http', rule: 'path-prefix', location: `paths (${count})`,
      message: `Your paths add the prefix "${prefix}" in front of the standard paths.`,
      standard: '(no prefix)', yours: prefix,
      hint: `Move "${prefix}" into servers[].url so the paths themselves match the standard exactly.` });
  }

  const extras = implList.filter((p) => !used.has(p));
  return { matches, extras };
}

function collectParams(pathItem, op, resolver) {
  const out = new Map();
  for (const raw of [...(pathItem.parameters || []), ...(op.parameters || [])]) {
    const { node: p } = resolver.deref(raw);
    if (!isObj(p) || !p.name || !p.in) continue;
    const name = p.in === 'header' ? p.name.toLowerCase() : p.name;
    out.set(`${p.in}:${name}`, { ...p, _key: name });
  }
  return out;
}

const AUTH_HEADERS = new Set(['authorization', 'x-api-key', 'api-key', 'apikey', 'cookie']);

function diffParameters(stdItem, stdOp, implItem, implOp, pathRename, base, ctx) {
  const sp = collectParams(stdItem, stdOp, ctx.std);
  const ip = collectParams(implItem, implOp, ctx.impl);
  const usedImpl = new Set();

  for (const [key, s] of sp) {
    ctx.stats.fieldsChecked++;
    let implKey = key;
    if (s.in === 'path' && pathRename.has(s.name)) implKey = `path:${pathRename.get(s.name)}`;
    let i = ip.get(implKey);
    const where = `${base} › ${s.in} parameter "${s.name}"`;

    if (!i) {
      // Same name, different location?
      const elsewhere = [...ip.values()].find((p) => p._key === s._key && !usedImpl.has(`${p.in}:${p._key}`));
      if (elsewhere) {
        usedImpl.add(`${elsewhere.in}:${elsewhere._key}`);
        ctx.add({ severity: 'breaking', category: 'http', rule: 'param-location', location: where,
          message: `Parameter "${s.name}" is expected in the ${s.in}; your API reads it from the ${elsewhere.in}.`,
          standard: s.in, yours: elsewhere.in });
        continue;
      }
      const sameIn = [...ip.values()].filter((p) => p.in === s.in && !sp.has(`${p.in}:${p._key}`) && !usedImpl.has(`${p.in}:${p._key}`));
      const near = findNearMatch(s._key, sameIn.map((p) => p._key));
      if (near) {
        i = ip.get(`${s.in}:${near.name}`);
        usedImpl.add(`${s.in}:${near.name}`);
        if (s.in !== 'path') {
          ctx.add({ severity: s.required ? 'breaking' : 'warning', category: 'terminology', rule: 'param-name', location: where,
            message: `Parameter "${i.name}" appears to be the standard parameter "${s.name}" (${near.reason}).`,
            standard: s.name, yours: i.name, hint: `Rename to "${s.name}".` });
        }
      } else {
        ctx.add({ severity: s.required ? 'breaking' : 'warning', category: s.required ? 'requirements' : 'fields',
          rule: 'missing-parameter', location: where,
          message: s.required ? `Required ${s.in} parameter "${s.name}" is missing.` : `Optional ${s.in} parameter "${s.name}" is not supported.`,
          standard: s.required ? 'required' : 'optional', yours: '(absent)' });
        continue;
      }
    } else {
      usedImpl.add(implKey);
      ctx.stats.fieldsMatched++;
    }

    const sr = !!s.required;
    const ir = !!i.required;
    if (ir && !sr) {
      ctx.add({ severity: 'breaking', category: 'requirements', rule: 'required-mismatch', location: where,
        message: `Your API requires "${s.name}", but it is optional in the standard.`, standard: 'optional', yours: 'required' });
    } else if (sr && !ir) {
      ctx.add({ severity: 'info', category: 'requirements', rule: 'required-relaxed', location: where,
        message: `The standard requires "${s.name}"; your API treats it as optional.`, standard: 'required', yours: 'optional' });
    }
    if (s.schema || i.schema) diffSchema(s.schema || {}, i.schema || {}, where, [], 'request', ctx, 1);
  }

  for (const [key, i] of ip) {
    if (usedImpl.has(key) || sp.has(key)) continue;
    if (i.in === 'path' && [...pathRename.values()].includes(i.name)) continue;
    if (i.in === 'header' && AUTH_HEADERS.has(i._key)) continue; // covered by security checks
    ctx.add({ severity: i.required ? 'breaking' : 'info', category: 'fields', rule: 'additional-parameter',
      location: `${base} › ${i.in} parameter "${i.name}"`,
      message: i.required
        ? `Your API requires ${i.in} parameter "${i.name}", which is not in the standard. Standard clients will not send it.`
        : `Additional optional ${i.in} parameter "${i.name}" is not in the standard.`,
      standard: '(absent)', yours: i.required ? 'required' : 'optional' });
  }
}

function diffContent(sContent, iContent, base, dir, ctx, missingSeverity) {
  const s = isObj(sContent) ? sContent : {};
  const i = isObj(iContent) ? iContent : {};
  const iByBase = new Map(Object.keys(i).map((m) => [mediaBase(m), m]));
  for (const sm of Object.keys(s)) {
    const im = iByBase.get(mediaBase(sm)) || iByBase.get('*/*') || (mediaBase(sm).endsWith('+json') ? iByBase.get('application/json') : undefined);
    if (!im) {
      ctx.add({ severity: missingSeverity, category: 'http', rule: 'media-type', location: base,
        message: `Content type "${sm}" from the standard is not supported.`, standard: sm, yours: Object.keys(i).join(', ') || '(none)' });
      continue;
    }
    if (im !== sm && mediaBase(im) !== mediaBase(sm)) {
      ctx.add({ severity: 'warning', category: 'http', rule: 'media-type', location: base,
        message: `Content type differs from the standard.`, standard: sm, yours: im });
    }
    const ss = s[sm]?.schema;
    const is = i[im]?.schema;
    if (ss && is) diffSchema(ss, is, base, [], dir, ctx, 0);
    else if (ss && !is) {
      ctx.add({ severity: missingSeverity, category: 'fields', rule: 'schema-missing', location: base,
        message: 'The standard defines a body schema here; your definition has none.' });
    }
  }
}

function diffRequestBody(stdOp, implOp, base, ctx) {
  const { node: s } = ctx.std.deref(stdOp.requestBody);
  const { node: i } = ctx.impl.deref(implOp.requestBody);
  const where = `${base} › request body`;
  if (!isObj(s) && !isObj(i)) return;
  if (isObj(s) && !isObj(i)) {
    ctx.add({ severity: 'breaking', category: 'fields', rule: 'request-body-missing', location: where,
      message: 'The standard defines a request body; your operation does not accept one.' });
    return;
  }
  if (!isObj(s) && isObj(i)) {
    ctx.add({ severity: i.required ? 'breaking' : 'info', category: 'fields', rule: 'request-body-extra', location: where,
      message: i.required ? 'Your operation requires a request body; the standard does not define one.' : 'Your operation accepts an optional request body not defined in the standard.' });
    return;
  }
  if (i.required && !s.required) {
    ctx.add({ severity: 'breaking', category: 'requirements', rule: 'required-mismatch', location: where,
      message: 'Your API requires the request body; it is optional in the standard.', standard: 'optional', yours: 'required' });
  }
  diffContent(s.content, i.content, where, 'request', ctx, 'breaking');
}

function diffResponses(stdOp, implOp, base, ctx) {
  const sr = isObj(stdOp.responses) ? stdOp.responses : {};
  const ir = isObj(implOp.responses) ? implOp.responses : {};
  const iCodes = Object.keys(ir).map(String);
  const implSuccess = iCodes.filter(isSuccess);

  for (const code of Object.keys(sr).map(String)) {
    const where = `${base} › response ${code}`;
    let ic = iCodes.find((c) => c === code) || iCodes.find((c) => c.toUpperCase() === `${code[0]}XX`);
    const category = isErrorCode(code) ? 'errors' : 'http';
    if (!ic) {
      if (isSuccess(code)) {
        ctx.add({ severity: 'breaking', category: 'http', rule: 'success-status', location: where,
          message: implSuccess.length
            ? `The standard returns ${code} on success; your API returns ${implSuccess.join(', ')}.`
            : `The standard returns ${code} on success; your operation documents no success response.`,
          standard: code, yours: implSuccess.join(', ') || '(none)' });
      } else if (iCodes.includes('default')) {
        ctx.add({ severity: 'info', category, rule: 'status-default', location: where,
          message: `Status ${code} is only covered by your "default" response. Document it explicitly so clients know the error shape.`, standard: code, yours: 'default' });
        ic = 'default';
      } else {
        ctx.add({ severity: 'warning', category, rule: 'status-missing', location: where,
          message: `Status ${code} defined by the standard is not documented by your API.`, standard: code, yours: '(absent)' });
      }
      if (!ic) continue;
    } else if (ic !== code) {
      ctx.add({ severity: 'info', category, rule: 'status-range', location: where,
        message: `Status ${code} is covered by your range response ${ic}.`, standard: code, yours: ic });
    }

    const { node: s } = ctx.std.deref(sr[code]);
    const { node: i } = ctx.impl.deref(ir[ic]);
    if (!isObj(s) || !isObj(i)) continue;
    const sev = isSuccess(code) ? 'breaking' : 'warning';
    if (isObj(s.content) && Object.keys(s.content).length && !isObj(i.content)) {
      ctx.add({ severity: sev, category: isSuccess(code) ? 'fields' : 'errors', rule: 'response-body-missing', location: where,
        message: 'The standard defines a response body here; your response has none.' });
    } else {
      diffContent(s.content, i.content, where, 'response', ctx, sev);
    }
    const sh = isObj(s.headers) ? Object.keys(s.headers) : [];
    const ih = new Set(isObj(i.headers) ? Object.keys(i.headers).map((h) => h.toLowerCase()) : []);
    for (const h of sh) {
      if (!ih.has(h.toLowerCase())) {
        ctx.add({ severity: 'warning', category: 'http', rule: 'response-header', location: where,
          message: `Response header "${h}" from the standard is not documented.`, standard: h, yours: '(absent)' });
      }
    }
  }

  for (const code of iCodes) {
    if (code in sr || code === 'default') continue;
    if (/^[1-5]XX$/i.test(code)) continue;
    ctx.add({ severity: 'info', category: isErrorCode(code) ? 'errors' : 'http', rule: 'status-extra', location: `${base} › response ${code}`,
      message: `Your API documents status ${code}, which is not in the standard.`, standard: '(absent)', yours: code });
  }
}

export function diffOperations(std, impl, ctx) {
  const stdPaths = isObj(std.paths) ? std.paths : {};
  const implPaths = isObj(impl.paths) ? impl.paths : {};
  const { matches, extras } = matchPaths(stdPaths, implPaths, ctx);
  const pairs = [];

  for (const m of matches) {
    const { node: sItem } = ctx.std.deref(stdPaths[m.stdPath]);
    const stdMethods = HTTP_METHODS.filter((k) => isObj(sItem?.[k]));

    if (!m.implPath) {
      for (const method of stdMethods) {
        ctx.stats.operationsChecked++;
        ctx.add({ severity: 'breaking', category: 'paths', rule: 'missing-operation', location: `${method.toUpperCase()} ${m.stdPath}`,
          message: `Operation ${method.toUpperCase()} ${m.stdPath} from the standard was not found in your API.`,
          standard: `${method.toUpperCase()} ${m.stdPath}`, yours: '(absent)' });
      }
      continue;
    }

    if (m.how === 'case' || m.how === 'similar') {
      ctx.add({ severity: 'breaking', category: 'terminology', rule: 'path-name', location: m.implPath,
        message: `Path "${m.implPath}" appears to be the standard path "${m.stdPath}" (${m.how === 'case' ? 'casing differs' : 'spelling differs'}). URL paths are case- and spelling-sensitive.`,
        standard: m.stdPath, yours: m.implPath, hint: `Use "${m.stdPath}".` });
    }
    const sTrail = m.stdPath.length > 1 && m.stdPath.endsWith('/');
    const iTrail = m.implPath.length > 1 && m.implPath.endsWith('/');
    if (sTrail !== iTrail) {
      ctx.add({ severity: 'warning', category: 'http', rule: 'trailing-slash', location: m.implPath,
        message: `Trailing slash differs from the standard path. Many servers treat "/x" and "/x/" as different resources.`,
        standard: m.stdPath, yours: m.implPath });
    }

    const sNames = pathParamNames(m.stdPath);
    const iNames = pathParamNames(m.implPath);
    const rename = new Map();
    sNames.forEach((n, k) => {
      if (iNames[k] !== undefined) rename.set(n, iNames[k]);
      if (iNames[k] !== undefined && iNames[k] !== n) {
        ctx.add({ severity: 'info', category: 'terminology', rule: 'path-param-name', location: m.implPath,
          message: `Path parameter "{${iNames[k]}}" is named "{${n}}" in the standard.`, standard: n, yours: iNames[k] });
      }
    });

    const { node: iItem } = ctx.impl.deref(implPaths[m.implPath]);
    for (const method of stdMethods) {
      ctx.stats.operationsChecked++;
      const base = `${method.toUpperCase()} ${m.stdPath}`;
      const sOp = sItem[method];
      const iOp = iItem?.[method];
      if (!isObj(iOp)) {
        ctx.add({ severity: 'breaking', category: 'paths', rule: 'missing-operation', location: base,
          message: `Method ${method.toUpperCase()} is not implemented on ${m.implPath}.`,
          standard: base, yours: `(no ${method.toUpperCase()})` });
        continue;
      }
      ctx.stats.operationsMatched++;
      pairs.push({ method, stdPath: m.stdPath, implPath: m.implPath, sOp, iOp, sItem, iItem });
      if (sOp.operationId && iOp.operationId && sOp.operationId !== iOp.operationId) {
        ctx.add({ severity: 'info', category: 'terminology', rule: 'operation-id', location: base,
          message: `operationId "${iOp.operationId}" differs from the standard "${sOp.operationId}". Generated client code will use different method names.`,
          standard: sOp.operationId, yours: iOp.operationId });
      }
      diffParameters(sItem, sOp, iItem, iOp, rename, base, ctx);
      diffRequestBody(sOp, iOp, base, ctx);
      diffResponses(sOp, iOp, base, ctx);
    }
    for (const method of HTTP_METHODS.filter((k) => isObj(iItem?.[k]) && !stdMethods.includes(k))) {
      ctx.add({ severity: 'info', category: 'paths', rule: 'additional-operation', location: `${method.toUpperCase()} ${m.implPath}`,
        message: `Additional operation ${method.toUpperCase()} ${m.implPath} is not in the standard.` });
    }
  }

  for (const p of extras) {
    const { node: item } = ctx.impl.deref(implPaths[p]);
    const methods = HTTP_METHODS.filter((k) => isObj(item?.[k])).map((k) => k.toUpperCase());
    ctx.add({ severity: 'info', category: 'paths', rule: 'additional-path', location: p,
      message: `Additional path ${p} (${methods.join(', ') || 'no operations'}) is not in the standard.` });
  }
  return pairs;
}
