// Serves the built OpenCTI front (dist/) on :3000 and proxies the API to the
// dev backend on :4000. Port 3000 deliberately: the backend accepts one origin
// and that is the one it is configured for.
import http from 'node:http';
import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs';
import { join, extname, normalize } from 'node:path';

const DIST = process.argv[2];
const PORT = Number(process.argv[3] ?? 3000);
const BACK = Number(process.argv[4] ?? 4000);
const API = ['/graphql', '/auth', '/stream', '/storage', '/logout', '/schema', '/taxii2', '/feeds', '/chatbot', '/static'];
const MIME = { '.html':'text/html', '.js':'text/javascript', '.mjs':'text/javascript', '.css':'text/css',
  '.json':'application/json', '.svg':'image/svg+xml', '.png':'image/png', '.jpg':'image/jpeg',
  '.woff':'font/woff', '.woff2':'font/woff2', '.ttf':'font/ttf', '.ico':'image/x-icon', '.map':'application/json' };

http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const isApi = API.some((p) => url.pathname === p || url.pathname.startsWith(`${p}/`))
    || /\/embedded\//.test(url.pathname);
  if (isApi) {
    const proxy = http.request({ hostname: 'localhost', port: BACK, path: req.url, method: req.method,
      headers: { ...req.headers, host: `localhost:${BACK}` } }, (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers); up.pipe(res);
    });
    proxy.on('error', (e) => { res.writeHead(502); res.end(`proxy: ${e.message}`); });
    req.pipe(proxy);
    return;
  }
  // static, with SPA fallback
  const rel = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
  let file = join(DIST, rel);
  if (!existsSync(file) || statSync(file).isDirectory()) file = join(DIST, 'index.html');
  // index.html ships with placeholders the BACKEND normally substitutes when it
  // serves the front (opencti-graphql/src/http/httpPlatform.js). Serving the raw
  // file leaves `%APP_TITLE%` and friends in place and the app never boots — so
  // do the same substitution here, with the same defaults.
  if (file.endsWith('index.html')) {
    const html = readFileSync(file, 'utf8')
      .replace(/%BASE_PATH%/g, '')
      .replace(/%APP_SCRIPT_SNIPPET%/g, '')
      .replace(/%APP_TITLE%/g, 'OpenCTI - Cyber Threat Intelligence Platform')
      .replace(/%APP_DESCRIPTION%/g, 'OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables.')
      .replace(/%APP_FAVICON%/g, './assets/static/favicon.png');
    res.writeHead(200, { 'content-type': 'text/html', 'cache-control': 'no-store' });
    res.end(html);
    return;
  }
  res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' });
  createReadStream(file).pipe(res);
}).listen(PORT, () => console.log(`stack served on http://localhost:${PORT} (api -> :${BACK})`));
