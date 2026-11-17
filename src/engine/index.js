import { isObj } from './util.js';
import { makeResolver } from './refs.js';
import { diffOperations } from './operations.js';
import { checkBaseline } from './baseline.js';
import { checkTerminology } from './terminology.js';

export { scanSensitive, redactDocument, scrubText, serverHosts } from './sensitive.js';
export { vocabulary } from './terminology.js';

export const SEVERITIES = ['breaking', 'warning', 'info'];
export const CATEGORIES = {
  paths: 'Paths & operations',
  fields: 'Fields',
  requirements: 'Field requirements',
  terminology: 'Terminology',
  http: 'HTTP',
  security: 'Security',
  errors: 'Error handling',
  general: 'Document',
};

const MAX_FINDINGS = 3000;

function makeContext(std, impl) {
  const findings = [];
  const keys = new Set();
  const ctx = {
    std: makeResolver(std),
    impl: makeResolver(impl),
    seenPairs: new Set(),
    reportedNames: new Set(),
    stats: { operationsChecked: 0, operationsMatched: 0, fieldsChecked: 0, fieldsMatched: 0 },
    truncated: false,
    exhausted: () => findings.length >= MAX_FINDINGS,
    add(f) {
      if (findings.length >= MAX_FINDINGS) { ctx.truncated = true; return; }
      const key = `${f.rule}|${f.location}|${f.message}`;
      if (keys.has(key)) return;
      keys.add(key);
      if (f.category === 'terminology' && typeof f.yours === 'string') ctx.reportedNames.add(f.yours);
      findings.push(f);
    },
    findings,
  };
  return ctx;
}

/**
 * Compare an implementation's OpenAPI document against a DSDC standard.
 * Both arguments are already-parsed objects. Never throws on malformed input;
 * problems are reported as findings.
 */
export function compare(standard, implementation, meta = {}) {
  const ctx = makeContext(standard, isObj(implementation) ? implementation : {});
  const impl = isObj(implementation) ? implementation : null;

  if (!impl) {
    ctx.add({ severity: 'breaking', category: 'general', rule: 'not-an-object', location: '(document)',
      message: 'The submitted YAML is not an object. Paste a complete OpenAPI document.' });
  } else if (impl.swagger) {
    ctx.add({ severity: 'breaking', category: 'general', rule: 'swagger-2', location: 'swagger',
      message: `This is a Swagger ${impl.swagger} document. DSDC standards are OpenAPI 3.x; convert it (e.g. with swagger2openapi) and try again.`,
      standard: standard.openapi, yours: `swagger ${impl.swagger}` });
  } else if (!impl.openapi) {
    ctx.add({ severity: 'breaking', category: 'general', rule: 'not-openapi', location: 'openapi',
      message: 'The document has no "openapi" version field, so it is not recognisable as an OpenAPI document.' });
  } else if (!isObj(impl.paths) || !Object.keys(impl.paths).length) {
    ctx.add({ severity: 'breaking', category: 'general', rule: 'no-paths', location: 'paths',
      message: 'The document defines no paths, so there is nothing to compare.' });
  } else {
    const pairs = diffOperations(standard, impl, ctx);
    checkBaseline(standard, impl, pairs, ctx);
    checkTerminology(standard, impl, ctx);
    for (const ref of ctx.impl.unresolved) {
      ctx.add({ severity: 'warning', category: 'general', rule: 'unresolved-ref', location: ref,
        message: `Reference "${ref}" could not be resolved${ref.startsWith('#') ? '' : ' (external files are not uploaded — bundle your spec into one file)'}. Anything behind it was not checked.` });
    }
  }
  if (ctx.truncated) {
    ctx.add = () => {};
    ctx.findings.push({ severity: 'warning', category: 'general', rule: 'truncated', location: '(report)',
      message: `More than ${MAX_FINDINGS} findings; the report was truncated. Fix the breaking issues first and re-run.` });
  }

  return summarize(ctx, standard, impl, meta);
}

function summarize(ctx, standard, impl, meta) {
  const order = (s) => SEVERITIES.indexOf(s);
  const catOrder = Object.keys(CATEGORIES);
  const findings = ctx.findings.sort((a, b) =>
    order(a.severity) - order(b.severity) || catOrder.indexOf(a.category) - catOrder.indexOf(b.category) || String(a.location).localeCompare(String(b.location)));

  const counts = { breaking: 0, warning: 0, info: 0 };
  const byCategory = {};
  for (const f of findings) {
    counts[f.severity]++;
    byCategory[f.category] ??= { breaking: 0, warning: 0, info: 0 };
    byCategory[f.category][f.severity]++;
  }
  const verdict = counts.breaking ? 'fail' : counts.warning ? 'pass-with-warnings' : 'pass';
  const s = ctx.stats;
  return {
    verdict,
    counts,
    byCategory,
    coverage: {
      operations: { matched: s.operationsMatched, total: s.operationsChecked },
      fields: { matched: s.fieldsMatched, total: s.fieldsChecked },
    },
    standard: { ...meta, title: standard.info?.title, version: standard.info?.version },
    implementation: { title: impl?.info?.title, version: impl?.info?.version, openapi: impl?.openapi },
    findings,
    generatedAt: new Date().toISOString(),
  };
}

const VERDICT_TEXT = { pass: 'PASS', 'pass-with-warnings': 'PASS WITH WARNINGS', fail: 'FAIL' };
export const verdictLabel = (v) => VERDICT_TEXT[v] || v;

const cell = (v) => {
  if (v === undefined || v === null || v === '') return '';
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').slice(0, 300);
};

/** Plain Markdown report — used for download and for the email body. */
export function toMarkdown(report, { maxFindings = Infinity } = {}) {
  const r = report;
  const lines = [
    `# DSDC API compliance report — ${verdictLabel(r.verdict)}`,
    '',
    `- **Standard:** ${r.standard.family ? `${r.standard.family} · ` : ''}${r.standard.title || r.standard.id || ''} ${r.standard.version || ''}`.trim(),
    `- **Submitted API:** ${r.implementation.title || '(untitled)'} ${r.implementation.version || ''} (OpenAPI ${r.implementation.openapi || '?'})`,
    `- **Generated:** ${r.generatedAt}`,
    `- **Breaking:** ${r.counts.breaking} · **Warnings:** ${r.counts.warning} · **Info:** ${r.counts.info}`,
    `- **Operations matched:** ${r.coverage.operations.matched}/${r.coverage.operations.total} · **Standard fields found:** ${r.coverage.fields.matched}/${r.coverage.fields.total}`,
    '',
  ];
  const shown = r.findings.slice(0, maxFindings);
  for (const sev of SEVERITIES) {
    const group = shown.filter((f) => f.severity === sev);
    if (!group.length) continue;
    lines.push(`## ${sev === 'breaking' ? 'Breaking issues' : sev === 'warning' ? 'Warnings' : 'Additional / informational'} (${r.counts[sev]})`, '');
    lines.push('| Area | Location | Finding | Standard | Yours |', '|---|---|---|---|---|');
    for (const f of group) {
      lines.push(`| ${CATEGORIES[f.category] || f.category} | ${cell(f.location)} | ${cell(f.message)}${f.hint ? ` _${cell(f.hint)}_` : ''} | ${cell(f.standard)} | ${cell(f.yours)} |`);
    }
    lines.push('');
  }
  if (shown.length < r.findings.length) lines.push(`_…${r.findings.length - shown.length} more findings omitted. Download the full report from the checker._`, '');
  return lines.join('\n');
}
