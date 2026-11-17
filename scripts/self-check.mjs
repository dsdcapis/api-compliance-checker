// Sanity check: every standard compared with itself must yield no diff findings
// (baseline HTTP/security/error findings are expected and ignored here).
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { compare } from '../src/engine/index.js';

const dir = resolve(process.argv[2] || 'dist/standards');
const { standards } = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
const BASELINE = new Set(['openapi-version', 'info-version', 'servers-missing', 'plain-http', 'operation-id-duplicate', 'body-on-get',
  'no-success-response', 'body-on-204', 'created-location', 'path-style', 'no-auth', 'auth-mismatch', 'auth-option-missing', 'apikey-in-query',
  'basic-auth', 'oauth-flow', 'oauth-scopes', 'unknown-scheme', 'unsecured-operation', 'missing-401', 'sensitive-query', 'secret-in-spec',
  'card-data', 'no-client-errors', 'missing-400', 'missing-404', 'no-server-errors', 'error-without-body', 'inconsistent-errors',
  'problem-details', 'error-model', 'problem-details-suggest', 'rate-limit', 'unresolved-ref']);

let failed = 0;
for (const s of standards) {
  const doc = JSON.parse(readFileSync(join(dir, `${s.id}.json`), 'utf8'));
  const t = Date.now();
  const r = compare(doc, structuredClone(doc), s);
  const diff = r.findings.filter((f) => !BASELINE.has(f.rule));
  console.log(`${diff.length ? '✗' : '✓'} ${s.id.padEnd(46)} ops ${r.coverage.operations.matched}/${r.coverage.operations.total}  fields ${r.coverage.fields.matched}/${r.coverage.fields.total}  baseline B${r.counts.breaking}/W${r.counts.warning}/I${r.counts.info}  ${Date.now() - t}ms`);
  for (const f of diff.slice(0, 5)) console.log('     ', f.rule, '|', f.location, '|', f.message);
  if (diff.length) failed++;
}
process.exit(failed ? 1 : 0);
