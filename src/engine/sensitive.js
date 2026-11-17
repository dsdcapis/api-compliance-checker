import { isObj } from './util.js';

// Detection of credentials and payment-card data inside a submitted document.
// Used both to warn the submitter and to redact before anything is sent.

const SECRET_KEY = /(pass(word|wd)?|secret|token|api[-_]?key|apikey|authorization|client[-_]?secret|private[-_]?key|access[-_]?key|bearer|cookie|session)/i;

const PATTERNS = [
  ['JSON Web Token', /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/],
  ['AWS access key', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{30,}\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ['Stripe-style secret key', /\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['Bearer credential', /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/i],
  ['Basic credential', /\bBasic\s+[A-Za-z0-9+/=]{12,}/],
  ['Credentials in URL', /[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i],
];
const URL_CREDENTIALS = PATTERNS.find(([label]) => label === 'Credentials in URL')[1];

const PLACEHOLDER = /^(\*+|x+|<.*>|\{.*\}|\$\{.*\}|string|password|secret|token|your[-_ ]?.*|example.*|changeme|redacted.*|\.\.\.|null|true|false)$/i;

/** Luhn-valid 13–19 digit sequences (spaces/dashes allowed) — payment card numbers. */
const CARD_CANDIDATE = /(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])/g;
function luhn(digits) {
  let sum = 0;
  let dbl = false;
  for (let k = digits.length - 1; k >= 0; k--) {
    let d = digits.charCodeAt(k) - 48;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}
export function findCardNumbers(str) {
  const out = [];
  for (const m of String(str).matchAll(CARD_CANDIDATE)) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length >= 13 && digits.length <= 19 && /^[2-6]/.test(digits) && !/^(\d)\1+$/.test(digits) && luhn(digits)) out.push(m[0]);
  }
  return out;
}

function classify(key, value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  if (findCardNumbers(value).length) return 'Payment card number';
  for (const [label, re] of PATTERNS) if (re.test(value)) return label;
  if (key && SECRET_KEY.test(key) && value.length >= 8 && !PLACEHOLDER.test(value.trim()) && !/\s/.test(value.trim())) {
    return `Value of "${key}"`;
  }
  return null;
}

// Only literal data values are inspected; descriptions are prose.
const DATA_KEYS = new Set(['example', 'examples', 'default', 'value', 'const', 'enum', 'x-example']);

/** Walk the document and list values that look like real credentials or card numbers. */
export function scanSensitive(doc, limit = 200) {
  const hits = [];
  const seen = new Set();
  const walk = (node, path, inData, parentKey) => {
    if (hits.length >= limit || node === null || typeof node !== 'object' || seen.has(node)) return;
    seen.add(node);
    for (const [k, v] of Object.entries(node)) {
      const p = [...path, k];
      const data = inData || DATA_KEYS.has(k);
      if (typeof v === 'string') {
        // Server URLs and descriptions can also leak credentials embedded in URLs or card numbers.
        const kind = data ? classify(Array.isArray(node) ? parentKey : k, v)
          : (k === 'url' || k === 'description' || k === 'summary') ? (findCardNumbers(v).length ? 'Payment card number' : (URL_CREDENTIALS.test(v) ? 'Credentials in URL' : null))
          : null;
        if (kind) hits.push({ path: p, kind });
      } else if (typeof v === 'object') {
        walk(v, p, data, Array.isArray(node) ? parentKey : k);
      }
    }
  };
  walk(doc, [], false, null);
  return hits;
}

/**
 * Deep-copy the document with sensitive values replaced. Optionally masks server
 * hostnames so internal infrastructure is not disclosed.
 */
export function redactDocument(doc, { maskServers = false } = {}) {
  const hits = scanSensitive(doc, 10000);
  const copy = structuredClone(doc);
  for (const h of hits) {
    let cur = copy;
    for (let k = 0; k < h.path.length - 1; k++) cur = cur?.[h.path[k]];
    if (cur && typeof cur === 'object') cur[h.path[h.path.length - 1]] = `***REDACTED (${h.kind})***`;
  }
  const maskUrl = (u) => (typeof u === 'string' ? u.replace(/^([a-z][a-z0-9+.-]*:\/\/)([^/]+)/i, '$1redacted.example') : u);
  if (maskServers) {
    const fix = (servers) => Array.isArray(servers) && servers.forEach((s) => { if (isObj(s)) s.url = maskUrl(s.url); });
    fix(copy.servers);
    for (const item of Object.values(isObj(copy.paths) ? copy.paths : {})) {
      if (!isObj(item)) continue;
      fix(item.servers);
      for (const op of Object.values(item)) if (isObj(op)) fix(op.servers);
    }
  }
  return { doc: copy, redactions: hits.length };
}

/** Every hostname named in servers[] at document, path or operation level. */
export function serverHosts(doc) {
  const hosts = new Set();
  const take = (servers) => Array.isArray(servers) && servers.forEach((s) => {
    const m = isObj(s) && typeof s.url === 'string' && s.url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i);
    if (m) hosts.add(m[1].replace(/^[^@]*@/, ''));
  });
  take(doc?.servers);
  for (const item of Object.values(isObj(doc?.paths) ? doc.paths : {})) {
    if (!isObj(item)) continue;
    take(item.servers);
    for (const op of Object.values(item)) if (isObj(op)) take(op.servers);
  }
  return [...hosts].filter((h) => h && !/^(localhost|127\.0\.0\.1)(:|$)/i.test(h));
}

/** Last-resort text scrub for free-form strings (e.g. the report) before sending. */
export function scrubText(text, { hosts = [] } = {}) {
  let out = String(text);
  for (const host of hosts) out = out.split(host).join('redacted.example');
  for (const c of findCardNumbers(out)) out = out.split(c).join('***REDACTED (Payment card number)***');
  for (const [label, re] of PATTERNS) out = out.replace(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'), `***REDACTED (${label})***`);
  return out;
}
