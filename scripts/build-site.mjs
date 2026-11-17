// Assembles the static site into <outDir>:
//   - copies site/ (HTML, CSS, icon)
//   - bundles src/app/main.js (+ engine + yaml parser) into assets/app.js — no CDNs
//   - writes config.json from environment (repository variables in CI)
//   - writes a Content-Security-Policy that only allows the configured notification endpoint
//
// Env: NOTIFY_PROVIDER = web3forms | formspree | webhook | none
//      NOTIFY_ENDPOINT = https://… (formspree / webhook)
//      NOTIFY_ACCESS_KEY = web3forms access key (public by design)

import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { build } from 'esbuild';

const root = resolve(import.meta.dirname, '..');
const out = resolve(process.argv[2] || join(root, 'dist'));
mkdirSync(out, { recursive: true });

cpSync(join(root, 'site'), out, { recursive: true });
writeFileSync(join(out, '.nojekyll'), '');

await build({
  entryPoints: [join(root, 'src/app/main.js')],
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  minify: true,
  sourcemap: false,
  legalComments: 'linked',
  outfile: join(out, 'assets/app.js'),
});

const provider = (process.env.NOTIFY_PROVIDER || 'none').trim().toLowerCase();
const endpoint = (process.env.NOTIFY_ENDPOINT || '').trim();
const accessKey = (process.env.NOTIFY_ACCESS_KEY || '').trim();

if (!['none', 'web3forms', 'formspree', 'webhook'].includes(provider)) throw new Error(`Unknown NOTIFY_PROVIDER "${provider}"`);
if (['formspree', 'webhook'].includes(provider) && !/^https:\/\//.test(endpoint)) throw new Error('NOTIFY_ENDPOINT must be an https:// URL');
if (provider === 'web3forms' && !accessKey) throw new Error('NOTIFY_ACCESS_KEY is required for web3forms');

const notify = { provider };
if (endpoint && provider !== 'web3forms') notify.endpoint = endpoint;
if (accessKey && provider === 'web3forms') notify.accessKey = accessKey;
writeFileSync(join(out, 'config.json'), JSON.stringify({ notify }, null, 2));

const connect = ["'self'"];
if (provider === 'web3forms') connect.push('https://api.web3forms.com');
else if (provider !== 'none') connect.push(new URL(endpoint).origin);

const csp = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  `connect-src ${connect.join(' ')}`,
  "form-action 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join('; ');

const indexPath = join(out, 'index.html');
writeFileSync(indexPath, readFileSync(indexPath, 'utf8').replace('<!--CSP-->', `<meta http-equiv="Content-Security-Policy" content="${csp}">`));

console.log(`site built → ${out}  (notifications: ${provider})`);
