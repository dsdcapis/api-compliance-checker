import YAML from 'yaml';
import { compare, toMarkdown, verdictLabel, CATEGORIES, SEVERITIES, scanSensitive, redactDocument, scrubText, serverHosts, vocabulary } from '../engine/index.js';
import { isConfigured, buildPayload, send, asText } from './notify.js';

const MAX_INPUT_BYTES = 5 * 1024 * 1024;
const RENDER_PAGE = 300;

const $ = (id) => document.getElementById(id);
const state = { config: { notify: { provider: 'none' } }, manifest: null, cache: new Map(), parsed: null, report: null, sentKeys: new Set(), renderLimit: RENDER_PAGE };

/** Tiny DOM builder. Strings are always inserted as text, never as HTML. */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const show = (v) => (v === undefined || v === null || v === '' ? '' : typeof v === 'string' ? v : JSON.stringify(v));

// ---------------------------------------------------------------- bootstrap
async function init() {
  try {
    const r = await fetch('config.json', { cache: 'no-store' });
    if (r.ok) state.config = await r.json();
  } catch { /* defaults */ }

  try {
    const r = await fetch('standards/manifest.json', { cache: 'no-cache' });
    state.manifest = await r.json();
  } catch {
    $('standard-meta').textContent = 'Could not load the list of standards. Please refresh the page.';
    $('standard-meta').className = 'hint bad';
    return;
  }
  const d = new Date(state.manifest.generatedAt);
  $('standards-date').textContent = `Standards last refreshed ${d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}.`;

  $('notify-note').textContent = isConfigured(state.config)
    ? 'When you run the check, the results (and your redacted YAML, if selected) are emailed to the DSDC team, who may follow up with you.'
    : 'Result notifications are not configured on this site yet. Your results will only be shown on this page.';

  document.querySelectorAll('input[name="family"]').forEach((r) => r.addEventListener('change', fillApis));
  $('api').addEventListener('change', fillVersions);
  $('version').addEventListener('change', describeStandard);
  fillApis();

  let t;
  $('yaml').addEventListener('input', () => { clearTimeout(t); t = setTimeout(parseInput, 250); });
  $('file').addEventListener('change', (e) => e.target.files[0] && readFile(e.target.files[0]));
  const drop = $('drop');
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => e.dataTransfer.files[0] && readFile(e.dataTransfer.files[0]));

  $('detect').addEventListener('click', detectStandard);
  $('checker').addEventListener('submit', onSubmit);

  $('sev-filter').addEventListener('change', () => { state.renderLimit = RENDER_PAGE; renderFindings(); });
  $('cat-filter').addEventListener('change', () => { state.renderLimit = RENDER_PAGE; renderFindings(); });
  $('search').addEventListener('input', () => { state.renderLimit = RENDER_PAGE; renderFindings(); });
  $('dl-md').addEventListener('click', () => download(`dsdc-compliance-${stamp()}.md`, toMarkdown(state.report), 'text/markdown'));
  $('dl-json').addEventListener('click', () => download(`dsdc-compliance-${stamp()}.json`, JSON.stringify(state.report, null, 2), 'application/json'));
}

// ---------------------------------------------------------------- standards
const family = () => document.querySelector('input[name="family"]:checked').value;
const standardsFor = (fam) => state.manifest.standards.filter((s) => s.family === fam);

function fillApis() {
  const sel = $('api');
  const apis = new Map();
  for (const s of standardsFor(family())) if (!apis.has(s.api) || s.latest) apis.set(s.api, s.title);
  sel.replaceChildren(...[...apis].sort((a, b) => a[1].localeCompare(b[1])).map(([api, title]) => h('option', { value: api }, title)));
  fillVersions();
}

function fillVersions() {
  const list = standardsFor(family()).filter((s) => s.api === $('api').value);
  $('version').replaceChildren(...list.map((s) => h('option', { value: s.id, selected: s.latest }, `${s.version}${s.latest ? ' (latest)' : ''}`)));
  describeStandard();
}

const selectedStandard = () => state.manifest.standards.find((s) => s.id === $('version').value);

function describeStandard() {
  const s = selectedStandard();
  const meta = $('standard-meta');
  meta.className = 'hint';
  if (!s) { meta.textContent = ''; return; }
  meta.replaceChildren(
    `${s.title} · OpenAPI ${s.openapi} · ${s.operations} operation${s.operations === 1 ? '' : 's'}${s.preview ? ' · public preview' : ''} · `,
    h('a', { href: s.source, target: '_blank', rel: 'noopener noreferrer' }, 'view source'),
  );
}

async function loadStandard(id) {
  if (!state.cache.has(id)) {
    const r = await fetch(`standards/${encodeURIComponent(id)}.json`);
    if (!r.ok) throw new Error(`Could not load standard ${id} (${r.status}).`);
    state.cache.set(id, await r.json());
  }
  return state.cache.get(id);
}

function selectStandard(s) {
  document.querySelector(`input[name="family"][value="${s.family}"]`).checked = true;
  fillApis();
  $('api').value = s.api;
  fillVersions();
  $('version').value = s.id;
  describeStandard();
}

const normPath = (p) => p.replace(/\{[^}]+\}/g, '{}').replace(/\/+$/, '').toLowerCase();
async function detectStandard() {
  const out = $('detect-result');
  if (!state.parsed?.doc?.paths) return;
  out.textContent = ' Comparing…';
  const mine = Object.keys(state.parsed.doc.paths).map(normPath);
  const myWords = vocabulary(state.parsed.doc);
  let best = null;
  for (const s of state.manifest.standards.filter((x) => x.latest)) {
    let doc;
    try { doc = await loadStandard(s.id); } catch { continue; }
    const theirs = Object.keys(doc.paths || {}).map(normPath);
    const hits = theirs.filter((p) => mine.some((m) => m === p || m.endsWith(p))).length;
    const pathScore = theirs.length ? hits / theirs.length : 0;
    // Several standards share paths (FTL eBOL reuses the LTL eBOL paths), so field names break ties.
    const words = vocabulary(doc);
    const shared = [...words].filter((w) => myWords.has(w)).length;
    const fieldScore = words.size + myWords.size ? shared / (words.size + myWords.size - shared) : 0;
    const score = pathScore + fieldScore;
    if (!best || score > best.score) best = { s, score, pathScore, fieldScore };
  }
  if (!best || best.score === 0) {
    out.textContent = ' No standard shares paths or fields with your YAML. Choose one manually.';
    return;
  }
  selectStandard(best.s);
  out.textContent = ` Selected ${best.s.family} ${best.s.title} ${best.s.version} (${Math.round(best.pathScore * 100)}% of its paths and ${Math.round(best.fieldScore * 100)}% field overlap).`;
}

// ---------------------------------------------------------------- input
function readFile(file) {
  if (file.size > MAX_INPUT_BYTES) { setParse(`File is ${(file.size / 1048576).toFixed(1)} MB; the limit is 5 MB.`, 'bad'); return; }
  const reader = new FileReader();
  reader.onload = () => { $('yaml').value = reader.result; parseInput(); };
  reader.onerror = () => setParse('Could not read that file.', 'bad');
  reader.readAsText(file);
}

function setParse(msg, cls = '') {
  const el = $('parse-status');
  el.textContent = msg;
  el.className = `hint ${cls}`;
}

function parseInput() {
  const text = $('yaml').value;
  state.parsed = null;
  $('detect-row').hidden = true;
  if (!text.trim()) { setParse(''); return; }
  if (new Blob([text]).size > MAX_INPUT_BYTES) { setParse('Input is larger than 5 MB.', 'bad'); return; }

  let doc;
  try {
    const parsed = YAML.parseDocument(text, { prettyErrors: true, uniqueKeys: true });
    if (parsed.errors.length) {
      const e = parsed.errors[0];
      const line = e.linePos?.[0]?.line;
      setParse(`YAML error${line ? ` on line ${line}` : ''}: ${e.message.split('\n')[0]}`, 'bad');
      return;
    }
    doc = parsed.toJS({ maxAliasCount: 100 });
  } catch (e) {
    setParse(`Could not parse: ${e.message.split('\n')[0]}`, 'bad');
    return;
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) { setParse('This is not an OpenAPI document (expected a mapping at the top level).', 'bad'); return; }

  state.parsed = { doc, text };
  if (doc.swagger) { setParse(`Swagger ${doc.swagger} detected. DSDC standards use OpenAPI 3.x. Convert it first (e.g. with swagger2openapi).`, 'bad'); return; }
  if (!doc.openapi) { setParse('Parsed, but there is no "openapi" field. Is this a complete OpenAPI document?', 'warn'); return; }

  const paths = Object.keys(doc.paths || {}).length;
  const secrets = scanSensitive(doc);
  const parts = [`✓ OpenAPI ${doc.openapi} · “${doc.info?.title || 'untitled'}” ${doc.info?.version || ''} · ${paths} path${paths === 1 ? '' : 's'}`];
  if (secrets.length) parts.push(` · ⚠ ${secrets.length} credential/card-like value${secrets.length === 1 ? '' : 's'} found. These will be redacted before sharing.`);
  setParse(parts.join(''), secrets.length ? 'warn' : 'ok');
  $('detect-row').hidden = !paths;
  $('detect-result').textContent = '';
}

// ---------------------------------------------------------------- run
async function onSubmit(e) {
  e.preventDefault();
  const status = $('run-status');
  if (!state.parsed) parseInput();
  if (!state.parsed?.doc) { status.textContent = 'Add a valid OpenAPI YAML first.'; $('yaml').focus(); return; }
  const notify = isConfigured(state.config);
  if (notify) {
    for (const id of ['name', 'company', 'email']) {
      if (!$(id).reportValidity()) return;
    }
  }
  const std = selectedStandard();
  if (!std) return;

  const btn = $('run');
  btn.disabled = true;
  status.textContent = 'Checking…';
  try {
    const stdDoc = await loadStandard(std.id);
    // Engine mutates nothing, but give it a private copy anyway.
    state.report = compare(stdDoc, structuredClone(state.parsed.doc), { id: std.id, family: std.family, title: std.title, version: std.version, source: std.source });
    state.renderLimit = RENDER_PAGE;
    renderReport(std);
    status.textContent = '';
    $('results').focus();
    $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (notify) await notifyTeam(std);
  } catch (err) {
    status.textContent = `Something went wrong: ${err.message}`;
  } finally {
    btn.disabled = false;
  }
}

async function notifyTeam(std) {
  const el = $('send-status');
  el.hidden = false;
  if ($('website').value) { el.className = 'callout callout-good'; el.textContent = 'Results sent.'; return; } // honeypot

  const submitter = { name: $('name').value.trim(), company: $('company').value.trim(), email: $('email').value.trim() };
  const hosts = $('mask-servers').checked ? serverHosts(state.parsed.doc) : [];
  let yamlText = null;
  if ($('include-yaml').checked) {
    const { doc } = redactDocument(state.parsed.doc, { maskServers: hosts.length > 0 });
    yamlText = scrubText(YAML.stringify(doc, { aliasDuplicateObjects: false, lineWidth: 0 }), { hosts });
  }
  // Findings quote server URLs, so the report is scrubbed too.
  const markdown = scrubText(toMarkdown(state.report, { maxFindings: 150 }), { hosts });
  const payload = buildPayload({ report: state.report, markdown, submitter, yamlText, standard: std });

  const key = JSON.stringify([std.id, submitter.email, state.report.counts, yamlText?.length, state.parsed.text.length]);
  $('sent-body').textContent = asText(payload);
  $('sent-preview').hidden = false;
  if (state.sentKeys.has(key)) {
    el.className = 'callout';
    el.textContent = 'These results were already sent to the DSDC team.';
    return;
  }
  el.className = 'callout';
  el.textContent = 'Sending results to the DSDC team…';
  try {
    await send(state.config, payload);
    state.sentKeys.add(key);
    el.className = 'callout callout-good';
    el.textContent = `Results sent to the DSDC team${yamlText ? ' with your redacted YAML' : ''}. They may contact you at ${submitter.email}.`;
  } catch (err) {
    el.className = 'callout callout-bad';
    el.replaceChildren(`Your results are below, but we could not notify the DSDC team (${err.message}). `,
      h('button', { type: 'button', class: 'link', onclick: () => notifyTeam(std) }, 'Try again'));
  }
}

// ---------------------------------------------------------------- render
const VERDICT_TEXT = {
  fail: (r) => `${r.counts.breaking} breaking issue${r.counts.breaking === 1 ? '' : 's'} must be fixed before this API is compliant.`,
  'pass-with-warnings': () => 'No breaking issues. Review the warnings below; they may still cause problems for partners.',
  pass: () => 'Your definition matches the standard with no breaking issues or warnings.',
};

function renderReport(std) {
  const r = state.report;
  $('results').hidden = false;
  $('verdict').className = `verdict ${r.verdict}`;
  $('verdict-standard').textContent = `${std.family} · ${std.title} ${std.version}`;
  $('results-title').textContent = verdictLabel(r.verdict);
  $('verdict-text').textContent = VERDICT_TEXT[r.verdict](r);
  for (const s of SEVERITIES) $(`n-${s}`).textContent = r.counts[s];
  const pct = (m, t) => (t ? `${Math.round((m / t) * 100)}%` : '—');
  $('coverage').textContent = `Operations implemented: ${r.coverage.operations.matched} of ${r.coverage.operations.total} (${pct(r.coverage.operations.matched, r.coverage.operations.total)}) · Standard fields found by exact name: ${r.coverage.fields.matched} of ${r.coverage.fields.total} (${pct(r.coverage.fields.matched, r.coverage.fields.total)})`;
  $('send-status').hidden = true;
  $('sent-preview').hidden = true;

  const cats = $('category-summary');
  cats.replaceChildren(...Object.entries(CATEGORIES).filter(([k]) => k !== 'general' || r.byCategory.general).map(([k, label]) => {
    const c = r.byCategory[k] || { breaking: 0, warning: 0, info: 0 };
    const clean = !c.breaking && !c.warning;
    return h('button', { type: 'button', class: `cat${clean ? ' clean' : ''}`, onclick: () => { $('cat-filter').value = k; renderFindings(); } },
      h('strong', {}, label),
      h('span', { class: 'b' }, `${c.breaking} breaking`), ' · ', h('span', { class: 'w' }, `${c.warning} warn`), ' · ', h('span', { class: 'i' }, `${c.info} info`));
  }));

  $('cat-filter').replaceChildren(h('option', { value: '' }, 'All areas'),
    ...Object.entries(CATEGORIES).filter(([k]) => r.byCategory[k]).map(([k, label]) => h('option', { value: k }, label)));
  $('search').value = '';
  renderFindings();
}

function renderFindings() {
  const r = state.report;
  if (!r) return;
  const sev = new Set([...$('sev-filter').querySelectorAll('input:checked')].map((i) => i.value));
  const cat = $('cat-filter').value;
  const q = $('search').value.trim().toLowerCase();
  const list = r.findings.filter((f) => sev.has(f.severity) && (!cat || f.category === cat)
    && (!q || `${f.location} ${f.message} ${show(f.standard)} ${show(f.yours)}`.toLowerCase().includes(q)));

  const items = list.slice(0, state.renderLimit).map((f) => {
    const cmp = [];
    if (f.standard !== undefined) cmp.push(h('dt', {}, 'Standard'), h('dd', {}, show(f.standard)));
    if (f.yours !== undefined) cmp.push(h('dt', {}, 'Yours'), h('dd', {}, show(f.yours)));
    return h('li', { class: `finding ${f.severity}` },
      h('div', { class: 'meta' }, h('span', { class: `badge ${f.severity}` }, f.severity), h('span', { class: 'area' }, CATEGORIES[f.category] || f.category), h('span', { class: 'loc' }, f.location)),
      h('p', {}, f.message),
      f.hint ? h('p', { class: 'fix' }, `Fix: ${f.hint}`) : null,
      cmp.length ? h('dl', { class: 'compare' }, cmp) : null);
  });
  if (list.length > state.renderLimit) {
    items.push(h('li', {}, h('button', { type: 'button', class: 'btn btn-secondary', onclick: () => { state.renderLimit += RENDER_PAGE; renderFindings(); } },
      `Show ${Math.min(RENDER_PAGE, list.length - state.renderLimit)} more of ${list.length - state.renderLimit} remaining`)));
  }
  if (!list.length) items.push(h('li', { class: 'muted' }, r.findings.length ? 'No findings match these filters.' : 'No findings.'));
  $('findings').replaceChildren(...items);
  $('shown-count').textContent = `Showing ${Math.min(list.length, state.renderLimit)} of ${list.length} matching finding${list.length === 1 ? '' : 's'} (${r.findings.length} total).`;
}

// ---------------------------------------------------------------- utils
const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

init();
