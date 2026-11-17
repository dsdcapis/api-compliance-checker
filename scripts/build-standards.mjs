// Fetches the public DSDC standards repositories, finds every root OpenAPI
// document, bundles external $refs into it, and writes:
//   <out>/standards/<id>.json   one self-contained document per standard
//   <out>/standards/manifest.json
//
// Usage: node scripts/build-standards.mjs [outDir]
// Env:   STANDARDS_SRC  where to clone/read the repos (default .standards-src)

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import $RefParser from '@apidevtools/json-schema-ref-parser';
import YAML from 'yaml';

const root = resolve(import.meta.dirname, '..');
const outDir = resolve(process.argv[2] || join(root, 'dist'));
const srcDir = resolve(process.env.STANDARDS_SRC || join(root, '.standards-src'));
const { sources, exclude } = JSON.parse(readFileSync(join(root, 'config/sources.json'), 'utf8'));

const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9.]+/g, '-').replace(/^-|-$/g, '');

function versionKey(v) {
  const parts = String(v).replace(/^v/i, '').split(/[.-]/);
  return parts.map((p) => (/^\d+$/.test(p) ? Number(p) : -1));
}
function compareVersions(a, b) {
  const x = versionKey(a);
  const y = versionKey(b);
  for (let k = 0; k < Math.max(x.length, y.length); k++) {
    const d = (x[k] ?? 0) - (y[k] ?? 0);
    if (d) return d;
  }
  return 0;
}

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(ya?ml|json)$/i.test(name)) out.push(p);
  }
  return out;
}

function checkout(src) {
  const dest = join(srcDir, src.repo.split('/')[1]);
  if (!existsSync(dest)) {
    mkdirSync(srcDir, { recursive: true });
    execFileSync('git', ['clone', '--quiet', '--depth', '1', '--branch', src.branch, `https://github.com/${src.repo}.git`, dest], { stdio: 'inherit' });
  }
  const sha = execFileSync('git', ['-C', dest, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  return { dest, sha };
}

const manifest = { generatedAt: new Date().toISOString(), families: [], standards: [] };
mkdirSync(join(outDir, 'standards'), { recursive: true });

for (const src of sources) {
  const { dest, sha } = checkout(src);
  manifest.families.push({ id: src.family, label: src.label, repo: src.repo, commit: sha });
  const base = join(dest, src.dir);
  if (!existsSync(base)) { console.warn(`! ${src.repo}: no ${src.dir}/ directory`); continue; }

  for (const file of walk(base)) {
    const rel = relative(dest, file).split(sep).join('/');
    if (exclude.some((x) => `/${rel}`.includes(x))) continue;
    let doc;
    try {
      doc = YAML.parse(readFileSync(file, 'utf8'), { maxAliasCount: 1000 });
    } catch (e) {
      console.warn(`! skip ${src.repo}/${rel}: ${e.message}`);
      continue;
    }
    if (!doc || typeof doc !== 'object' || !doc.openapi || !doc.paths || !Object.keys(doc.paths).length) continue;

    // api-specs/<api>/<version>/<file>
    const segs = relative(base, file).split(sep);
    const apiDir = segs[0];
    const versionDir = segs.length > 2 ? segs[1] : doc.info?.version || '1.0';

    let bundled;
    try {
      // Some standards reference public schemas by URL (e.g. RFC 9457 ProblemDetails on SwaggerHub).
      bundled = await $RefParser.bundle(file, { resolve: { http: { timeout: 15000, redirects: 3 } } });
    } catch (e) {
      console.warn(`! could not bundle ${src.repo}/${rel}: ${e.message}`);
      continue;
    }

    const id = `${slug(src.family)}-${slug(apiDir)}-${slug(versionDir)}`;
    writeFileSync(join(outDir, 'standards', `${id}.json`), JSON.stringify(bundled));
    manifest.standards.push({
      id,
      family: src.family,
      api: apiDir,
      title: doc.info?.title || apiDir,
      version: versionDir.replace(/^v/i, ''),
      infoVersion: doc.info?.version || null,
      openapi: doc.openapi,
      preview: /preview|draft|beta|alpha/i.test(versionDir),
      operations: Object.values(doc.paths).reduce((n, item) => n + Object.keys(item || {}).filter((k) => ['get', 'put', 'post', 'delete', 'patch', 'head', 'options'].includes(k)).length, 0),
      source: `https://github.com/${src.repo}/blob/${sha}/${rel.split('/').map(encodeURIComponent).join('/')}`,
    });
    console.log(`✓ ${id}  (${rel})`);
  }
}

// Mark the newest version of each API so the UI can pre-select it.
const groups = new Map();
for (const s of manifest.standards) {
  const k = `${s.family}|${s.api}`;
  groups.set(k, [...(groups.get(k) || []), s]);
}
for (const list of groups.values()) {
  list.sort((a, b) => compareVersions(b.version, a.version));
  list[0].latest = true;
}
manifest.standards.sort((a, b) => a.family.localeCompare(b.family) || a.title.localeCompare(b.title) || compareVersions(b.version, a.version));

writeFileSync(join(outDir, 'standards', 'manifest.json'), JSON.stringify(manifest, null, 2));
console.log(`\n${manifest.standards.length} standards written to ${relative(root, join(outDir, 'standards'))}`);
if (!manifest.standards.length) process.exit(1);
