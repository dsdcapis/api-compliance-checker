// Minimal local static server for previewing the built site: npm run serve
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';

const root = resolve(process.argv[2] || 'dist');
const port = Number(process.env.PORT || 8080);
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.txt': 'text/plain' };

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  let p = normalize(join(root, decodeURIComponent(url.pathname)));
  if (!p.startsWith(root)) { res.writeHead(403).end(); return; }
  if (url.pathname.endsWith('/')) p = join(p, 'index.html');
  try {
    const body = await readFile(p);
    res.writeHead(200, { 'Content-Type': types[extname(p)] || 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end('Not found');
  }
}).listen(port, () => console.log(`http://localhost:${port}/`));
