// Sends the compliance result to the DSDC team through a form relay.
// The recipient address is configured inside the relay service, never in this
// public page, so it cannot be harvested from the page source.
//
// Providers (set via repository variables at build time, see README):
//   web3forms  – https://web3forms.com      (access key is designed to be public)
//   formspree  – https://formspree.io/f/<id>
//   webhook    – any HTTPS endpoint that accepts JSON (e.g. Power Automate "When an HTTP request is received")
//   none       – results are shown to the user only

const MAX_YAML_CHARS = 250_000;

export function isConfigured(config) {
  const n = config?.notify;
  if (!n || n.provider === 'none') return false;
  if (n.provider === 'web3forms') return !!n.accessKey;
  return !!n.endpoint;
}

export function buildPayload({ report, markdown, submitter, yamlText, standard }) {
  let yaml = yamlText || null;
  let yamlTruncated = false;
  if (yaml && yaml.length > MAX_YAML_CHARS) {
    yaml = yaml.slice(0, MAX_YAML_CHARS);
    yamlTruncated = true;
  }
  const verdict = { pass: 'PASS', 'pass-with-warnings': 'PASS WITH WARNINGS', fail: 'FAIL' }[report.verdict];
  return {
    subject: `[DSDC Compliance] ${verdict} — ${submitter.company || 'Unknown company'} — ${standard.family} ${standard.title} ${standard.version}`,
    submitter,
    standard: { id: standard.id, family: standard.family, title: standard.title, version: standard.version },
    api: report.implementation,
    verdict,
    counts: report.counts,
    coverage: report.coverage,
    generatedAt: report.generatedAt,
    report: markdown,
    yaml,
    yamlTruncated,
  };
}

export function asText(p) {
  return [
    `Verdict: ${p.verdict}`,
    `Standard: ${p.standard.family} ${p.standard.title} ${p.standard.version}`,
    `Submitted API: ${p.api.title || '(untitled)'} ${p.api.version || ''}`,
    `Submitted by: ${p.submitter.name} <${p.submitter.email}> — ${p.submitter.company}`,
    `Breaking: ${p.counts.breaking}  Warnings: ${p.counts.warning}  Info: ${p.counts.info}`,
    `Operations matched: ${p.coverage.operations.matched}/${p.coverage.operations.total}  Standard fields found: ${p.coverage.fields.matched}/${p.coverage.fields.total}`,
    '',
    p.report,
    '',
    p.yaml ? `----- Submitted YAML (secrets redacted)${p.yamlTruncated ? ' — TRUNCATED' : ''} -----\n${p.yaml}` : '(Submitter chose not to include their YAML.)',
  ].join('\n');
}

export async function send(config, payload) {
  const n = config.notify;
  let url;
  let body;
  if (n.provider === 'web3forms') {
    url = 'https://api.web3forms.com/submit';
    body = {
      access_key: n.accessKey,
      subject: payload.subject,
      from_name: 'DSDC API Compliance Checker',
      replyto: payload.submitter.email,
      name: payload.submitter.name,
      email: payload.submitter.email,
      company: payload.submitter.company,
      verdict: payload.verdict,
      message: asText(payload),
      botcheck: '',
    };
  } else if (n.provider === 'formspree') {
    url = n.endpoint;
    body = { _subject: payload.subject, _replyto: payload.submitter.email, name: payload.submitter.name, email: payload.submitter.email,
      company: payload.submitter.company, verdict: payload.verdict, message: asText(payload) };
  } else {
    url = n.endpoint;
    body = { ...payload, text: asText(payload) };
  }

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
  });
  if (!res.ok) {
    let detail = '';
    try { detail = (await res.json())?.message || ''; } catch { /* ignore */ }
    throw new Error(`Notification service responded ${res.status}${detail ? `: ${detail}` : ''}`);
  }
}
