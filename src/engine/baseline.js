import { HTTP_METHODS, isObj } from './util.js';
import { refName } from './refs.js';
import { scanSensitive } from './sensitive.js';

// DSDC baseline rules for HTTP, security and error handling. These apply to every
// submission regardless of which standard is selected, because the published
// standards define little or nothing in these areas. Severities are deliberate:
// "breaking" is reserved for problems that put data or interoperability at risk.

const listOps = (ops, max = 8) => (ops.length <= max ? ops.join(', ') : `${ops.slice(0, max).join(', ')} … (+${ops.length - max} more)`);
const isLocal = (url) => /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(url);

function allOperations(doc, resolver) {
  const out = [];
  for (const [path, raw] of Object.entries(isObj(doc.paths) ? doc.paths : {})) {
    const { node: item } = resolver.deref(raw);
    if (!isObj(item)) continue;
    for (const m of HTTP_METHODS) {
      if (isObj(item[m])) out.push({ path, method: m, op: item[m], item, label: `${m.toUpperCase()} ${path}` });
    }
  }
  return out;
}

function responseCodes(op) {
  return Object.keys(isObj(op.responses) ? op.responses : {}).map(String);
}
const has = (codes, test) => codes.some((c) => test(c.toUpperCase()));

export function checkBaseline(std, impl, pairs, ctx) {
  const ops = allOperations(impl, ctx.impl);
  const stdOpFor = new Map(pairs.map((p) => [`${p.method} ${p.implPath}`, p.sOp]));
  const stdHas = (o, code) => responseCodes(stdOpFor.get(`${o.method} ${o.path}`) || {}).includes(code);

  checkHttp(std, impl, ops, ctx);
  checkSecurity(std, impl, ops, ctx, stdHas);
  checkErrors(std, impl, ops, ctx, stdHas);
}

// ---------------------------------------------------------------------------
function checkHttp(std, impl, ops, ctx) {
  const sv = String(std.openapi || '');
  const iv = String(impl.openapi || '');
  if (sv && iv && sv.split('.').slice(0, 2).join('.') !== iv.split('.').slice(0, 2).join('.')) {
    ctx.add({ severity: 'info', category: 'http', rule: 'openapi-version', location: 'openapi',
      message: `Your document is OpenAPI ${iv}; the standard is written in OpenAPI ${sv}. Minor-version differences change some schema keywords (e.g. nullable).`,
      standard: sv, yours: iv });
  }
  if (!impl.info?.version) {
    ctx.add({ severity: 'warning', category: 'http', rule: 'info-version', location: 'info.version', message: 'API version (info.version) is not declared.' });
  }

  const servers = Array.isArray(impl.servers) ? impl.servers.filter(isObj) : [];
  if (!servers.length) {
    ctx.add({ severity: 'warning', category: 'http', rule: 'servers-missing', location: 'servers',
      message: 'No server URLs are declared, so clients cannot tell where the API is hosted.', hint: 'Add servers[] with your HTTPS base URL(s).' });
  }
  for (const s of servers) {
    if (typeof s.url === 'string' && /^http:\/\//i.test(s.url) && !isLocal(s.url)) {
      ctx.add({ severity: 'breaking', category: 'security', rule: 'plain-http', location: `servers › ${s.url}`,
        message: 'Server URL uses unencrypted HTTP. DSDC APIs carry commercial shipment data and must be served over HTTPS (TLS 1.2+).',
        standard: 'https://', yours: s.url });
    }
  }

  const ids = new Map();
  const bodyOnSafe = [];
  const noSuccess = [];
  const bodyOn204 = [];
  const createdNoLocation = [];
  for (const o of ops) {
    if (o.op.operationId) ids.set(o.op.operationId, [...(ids.get(o.op.operationId) || []), o.label]);
    if (['get', 'head', 'delete'].includes(o.method) && o.op.requestBody) bodyOnSafe.push(o.label);
    const codes = responseCodes(o.op);
    if (!has(codes, (c) => c.startsWith('2'))) noSuccess.push(o.label);
    for (const c of ['204', '304']) {
      const { node: r } = ctx.impl.deref(o.op.responses?.[c]);
      if (isObj(r?.content) && Object.keys(r.content).length) bodyOn204.push(`${o.label} (${c})`);
    }
    const { node: created } = ctx.impl.deref(o.op.responses?.['201']);
    if (isObj(created) && !Object.keys(created.headers || {}).some((h) => h.toLowerCase() === 'location')) createdNoLocation.push(o.label);
  }
  for (const [id, where] of ids) {
    if (where.length > 1) ctx.add({ severity: 'warning', category: 'http', rule: 'operation-id-duplicate', location: listOps(where),
      message: `operationId "${id}" is used by more than one operation. It must be unique.` });
  }
  if (bodyOnSafe.length) ctx.add({ severity: 'warning', category: 'http', rule: 'body-on-get', location: listOps(bodyOnSafe),
    message: 'GET, HEAD and DELETE requests should not carry a request body; many proxies and clients drop it.' });
  if (noSuccess.length) ctx.add({ severity: 'warning', category: 'http', rule: 'no-success-response', location: listOps(noSuccess),
    message: 'Operation documents no 2xx success response.' });
  if (bodyOn204.length) ctx.add({ severity: 'warning', category: 'http', rule: 'body-on-204', location: listOps(bodyOn204),
    message: '204 No Content and 304 Not Modified responses must not include a body.' });
  if (createdNoLocation.length) ctx.add({ severity: 'info', category: 'http', rule: 'created-location', location: listOps(createdNoLocation),
    message: '201 Created responses should include a Location header pointing at the new resource.' });

  const badPaths = Object.keys(isObj(impl.paths) ? impl.paths : {}).filter((p) =>
    p.split('/').some((seg) => seg && !seg.startsWith('{') && /[A-Z_ ]/.test(seg)));
  if (badPaths.length) ctx.add({ severity: 'info', category: 'http', rule: 'path-style', location: listOps(badPaths),
    message: 'Path segments contain uppercase letters, underscores or spaces. DSDC standard paths use lowercase segments.' });
}

// ---------------------------------------------------------------------------
function schemeKey(s) {
  if (!isObj(s)) return 'unknown';
  if (s.type === 'http') return `http:${String(s.scheme || '').toLowerCase()}`;
  if (s.type === 'apiKey') return `apiKey:${s.in}:${String(s.name || '').toLowerCase()}`;
  return s.type;
}
const describeScheme = (k) => ({ 'http:bearer': 'HTTP Bearer token', 'http:basic': 'HTTP Basic', oauth2: 'OAuth 2.0', openIdConnect: 'OpenID Connect', mutualTLS: 'Mutual TLS' }[k] || (k.startsWith('apiKey:') ? `API key (${k.split(':')[1]} "${k.split(':')[2]}")` : k));

function checkSecurity(std, impl, ops, ctx, stdHas) {
  const iSchemes = isObj(impl.components?.securitySchemes) ? impl.components.securitySchemes : {};
  const sSchemes = isObj(std.components?.securitySchemes) ? std.components.securitySchemes : {};
  const resolved = Object.fromEntries(Object.entries(iSchemes).map(([n, s]) => [n, ctx.impl.deref(s).node]));

  if (!Object.keys(resolved).length) {
    ctx.add({ severity: 'breaking', category: 'security', rule: 'no-auth', location: 'components.securitySchemes',
      message: 'No authentication is defined. DSDC APIs exchange commercial shipment data and must require authentication.',
      hint: 'Define components.securitySchemes (OAuth 2.0 client credentials or a bearer token is recommended) and apply it with a top-level security requirement.' });
  }

  // Compare against what the standard declares, when it declares anything.
  const sKeys = new Set(Object.values(sSchemes).map((s) => schemeKey(ctx.std.deref(s).node)));
  const iKeys = new Set(Object.values(resolved).map(schemeKey));
  if (sKeys.size) {
    const supported = [...sKeys].filter((k) => iKeys.has(k));
    if (!supported.length && iKeys.size) {
      ctx.add({ severity: 'breaking', category: 'security', rule: 'auth-mismatch', location: 'components.securitySchemes',
        message: 'None of the authentication methods defined by the standard are supported.',
        standard: [...sKeys].map(describeScheme).join(', '), yours: [...iKeys].map(describeScheme).join(', ') });
    } else {
      for (const k of sKeys) if (!iKeys.has(k) && iKeys.size) {
        ctx.add({ severity: 'info', category: 'security', rule: 'auth-option-missing', location: 'components.securitySchemes',
          message: `The standard also allows ${describeScheme(k)}; your API does not offer it.`, standard: describeScheme(k), yours: '(absent)' });
      }
    }
  }

  for (const [name, s] of Object.entries(resolved)) {
    const where = `securitySchemes › ${name}`;
    if (s.type === 'apiKey' && s.in === 'query') ctx.add({ severity: 'warning', category: 'security', rule: 'apikey-in-query', location: where,
      message: 'API key is passed in the query string, where it ends up in server, proxy and browser logs.', hint: 'Send the key in a request header instead.' });
    if (s.type === 'http' && String(s.scheme).toLowerCase() === 'basic') ctx.add({ severity: 'warning', category: 'security', rule: 'basic-auth', location: where,
      message: 'HTTP Basic sends long-lived credentials on every request.', hint: 'Prefer OAuth 2.0 client credentials or short-lived bearer tokens.' });
    if (s.type === 'oauth2' && isObj(s.flows)) {
      for (const flow of ['implicit', 'password']) {
        if (s.flows[flow]) ctx.add({ severity: 'warning', category: 'security', rule: 'oauth-flow', location: `${where} › ${flow}`,
          message: `The OAuth 2.0 "${flow}" flow is deprecated by OAuth 2.0 Security Best Current Practice (RFC 9700).`,
          hint: 'Use clientCredentials for system-to-system or authorizationCode with PKCE for user-delegated access.' });
      }
      for (const [flow, f] of Object.entries(s.flows)) {
        for (const k of ['tokenUrl', 'authorizationUrl', 'refreshUrl']) {
          if (typeof f?.[k] === 'string' && /^http:\/\//i.test(f[k]) && !isLocal(f[k])) ctx.add({ severity: 'breaking', category: 'security', rule: 'plain-http', location: `${where} › ${flow}.${k}`,
            message: `${k} uses unencrypted HTTP; tokens would be exposed.`, standard: 'https://', yours: f[k] });
        }
        if (isObj(f) && (!isObj(f.scopes) || !Object.keys(f.scopes).length)) ctx.add({ severity: 'info', category: 'security', rule: 'oauth-scopes', location: `${where} › ${flow}`,
          message: 'No OAuth scopes are defined. Scopes let partners grant least-privilege access (e.g. read-only tracking).' });
      }
    }
  }

  const globalSec = Array.isArray(impl.security) ? impl.security : null;
  const unsecured = [];
  const no401 = [];
  for (const o of ops) {
    const sec = Array.isArray(o.op.security) ? o.op.security : globalSec;
    const open = !sec || !sec.length || sec.some((r) => isObj(r) && !Object.keys(r).length);
    if (open) { if (Object.keys(resolved).length) unsecured.push(o.label); continue; }
    for (const req of sec) for (const n of Object.keys(req || {})) {
      if (!(n in resolved)) ctx.add({ severity: 'breaking', category: 'security', rule: 'unknown-scheme', location: o.label,
        message: `Security requirement references "${n}", which is not defined in components.securitySchemes.` });
    }
    const codes = responseCodes(o.op);
    if (!codes.includes('401') && !has(codes, (c) => c === '4XX' || c === 'DEFAULT') && !stdHas(o, '401')) no401.push(o.label);
  }
  if (unsecured.length) ctx.add({ severity: 'warning', category: 'security', rule: 'unsecured-operation', location: listOps(unsecured),
    message: 'Operation has no security requirement and is publicly accessible.', hint: 'Add a top-level `security` block or one per operation.' });
  if (no401.length) ctx.add({ severity: 'warning', category: 'security', rule: 'missing-401', location: listOps(no401),
    message: 'Secured operation does not document 401 Unauthorized.' });

  const sensitiveQuery = [];
  for (const o of ops) {
    for (const raw of [...(o.item.parameters || []), ...(o.op.parameters || [])]) {
      const { node: p } = ctx.impl.deref(raw);
      if (isObj(p) && p.in === 'query' && /(pass(word)?|secret|token|api[-_]?key|ssn|card)/i.test(p.name || '')) sensitiveQuery.push(`${o.label} (${p.name})`);
    }
  }
  if (sensitiveQuery.length) ctx.add({ severity: 'warning', category: 'security', rule: 'sensitive-query', location: listOps(sensitiveQuery),
    message: 'Sensitive values are passed as query parameters, which are logged by servers and proxies.', hint: 'Move them to headers or the request body.' });

  const secrets = scanSensitive(impl);
  for (const h of secrets.slice(0, 25)) {
    const card = h.kind === 'Payment card number';
    ctx.add({ severity: 'warning', category: 'security', rule: card ? 'card-data' : 'secret-in-spec', location: h.path.join('.'),
      message: card
        ? 'A payment card number appears in the document. It has been redacted from anything sent to DSDC; remove it from your specification.'
        : `${h.kind} appears to be a real credential. It has been redacted from anything sent to DSDC; rotate it if it is live.` });
  }
}

// ---------------------------------------------------------------------------
function errorShape(response, resolver) {
  const { node: r } = resolver.deref(response);
  if (!isObj(r)) return null;
  const content = isObj(r.content) ? r.content : null;
  if (!content || !Object.keys(content).length) return { type: null, shape: null };
  const [type, media] = Object.entries(content)[0];
  const schema = media?.schema;
  let shape = '(inline)';
  if (isObj(schema)) {
    if (schema.$ref) shape = refName(schema.$ref);
    else if (schema.type === 'array' && schema.items?.$ref) shape = `${refName(schema.items.$ref)}[]`;
  } else shape = null;
  return { type, shape };
}

function checkErrors(std, impl, ops, ctx, stdHas) {
  const no4xx = [];
  const no5xx = [];
  const no400 = [];
  const no404 = [];
  const noBody = [];
  const shapes = new Map();
  const types = new Set();

  for (const o of ops) {
    const codes = responseCodes(o.op).map((c) => c.toUpperCase());
    const hasDefault = codes.includes('DEFAULT');
    if (!has(codes, (c) => c.startsWith('4')) && !hasDefault) no4xx.push(o.label);
    if (!has(codes, (c) => c.startsWith('5')) && !hasDefault) no5xx.push(o.label);
    const params = [...(o.item.parameters || []), ...(o.op.parameters || [])].map((p) => ctx.impl.deref(p).node);
    if ((o.op.requestBody || params.some((p) => p?.in === 'query' || p?.in === 'path')) && !codes.includes('400') && !codes.includes('4XX') && !stdHas(o, '400')) no400.push(o.label);
    if (params.some((p) => p?.in === 'path') && !codes.includes('404') && !codes.includes('4XX') && !stdHas(o, '404')) no404.push(o.label);

    for (const c of codes) {
      if (!/^[45]/.test(c) && c !== 'DEFAULT') continue;
      const shape = errorShape(o.op.responses[c] ?? o.op.responses[c.toLowerCase()], ctx.impl);
      if (!shape) continue;
      if (!shape.shape) { if (!['404', '401', '403'].includes(c)) noBody.push(`${o.label} (${c})`); continue; }
      shapes.set(shape.shape, [...(shapes.get(shape.shape) || []), `${o.label} (${c})`]);
      if (shape.type) types.add(shape.type.split(';')[0]);
    }
  }

  if (no4xx.length) ctx.add({ severity: 'warning', category: 'errors', rule: 'no-client-errors', location: listOps(no4xx),
    message: 'Operation documents no 4xx client-error responses, so clients cannot tell how validation failures are reported.' });
  if (no400.length) ctx.add({ severity: 'warning', category: 'errors', rule: 'missing-400', location: listOps(no400),
    message: 'Operation accepts input but does not document 400 Bad Request.' });
  if (no404.length) ctx.add({ severity: 'warning', category: 'errors', rule: 'missing-404', location: listOps(no404),
    message: 'Operation addresses a resource by path parameter but does not document 404 Not Found.' });
  if (no5xx.length) ctx.add({ severity: 'info', category: 'errors', rule: 'no-server-errors', location: listOps(no5xx),
    message: 'Operation documents no 5xx or default response for server failures.' });
  if (noBody.length) ctx.add({ severity: 'warning', category: 'errors', rule: 'error-without-body', location: listOps(noBody),
    message: 'Error response has no body schema, so clients cannot read what went wrong.' });
  if (shapes.size > 1) ctx.add({ severity: 'info', category: 'errors', rule: 'inconsistent-errors', location: 'responses (4xx/5xx)',
    message: `Error responses use ${shapes.size} different shapes: ${[...shapes.keys()].join(', ')}. A single error model is easier for clients to handle.` });

  // Compare against the standard's error model, when it has one.
  const stdOps = allOperations(std, ctx.std);
  const stdTypes = new Set();
  const stdShapes = new Set();
  for (const o of stdOps) for (const c of responseCodes(o.op)) {
    if (!/^[45]/.test(c) && c !== 'default') continue;
    const s = errorShape(o.op.responses[c], ctx.std);
    if (s?.type) stdTypes.add(s.type.split(';')[0]);
    if (s?.shape) stdShapes.add(s.shape);
  }
  const stdComponents = Object.values(isObj(std.components?.responses) ? std.components.responses : {});
  for (const r of stdComponents) { const s = errorShape(r, ctx.std); if (s?.type) stdTypes.add(s.type.split(';')[0]); }

  if (stdTypes.has('application/problem+json') && types.size && !types.has('application/problem+json')) {
    ctx.add({ severity: 'warning', category: 'errors', rule: 'problem-details', location: 'responses (4xx/5xx)',
      message: 'The standard reports errors as application/problem+json (RFC 9457 Problem Details); your error responses do not.',
      standard: 'application/problem+json', yours: [...types].join(', ') });
  }
  if (stdShapes.size && shapes.size) {
    const overlap = [...shapes.keys()].some((k) => stdShapes.has(k));
    if (!overlap) ctx.add({ severity: 'warning', category: 'errors', rule: 'error-model', location: 'responses (4xx/5xx)',
      message: 'Your error responses do not use the standard\'s error model.', standard: [...stdShapes].join(', '), yours: [...shapes.keys()].join(', ') });
  }
  if (!stdTypes.size && !stdShapes.size && !types.has('application/problem+json') && shapes.size) {
    ctx.add({ severity: 'info', category: 'errors', rule: 'problem-details-suggest', location: 'responses (4xx/5xx)',
      message: 'Consider RFC 9457 Problem Details (application/problem+json) for error bodies; it is already used by the DSDC FTL In-Transit Visibility standard.' });
  }

  const anyRateLimit = ops.some((o) => responseCodes(o.op).includes('429'));
  if (ops.length && !anyRateLimit) ctx.add({ severity: 'info', category: 'errors', rule: 'rate-limit', location: 'responses',
    message: 'No 429 Too Many Requests response is documented. If you rate-limit, document 429 with a Retry-After header.' });
}
