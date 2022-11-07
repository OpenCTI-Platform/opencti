const express = require('express');
const { readFileSync } = require('fs');
const helmet = require('helmet');
const path = require('path');
const dotenv = require('dotenv');
const https = require('https');

dotenv.config();

if(process.env.SERVER_HOST === undefined) throw new Error('SERVER_URL env not set.');
if(process.env.API_URL === undefined) throw new Error('API_URL env not set.');
if(process.env.SSL_CRT_FILE === undefined) throw new Error("SSL_CRT_FILE env not set.")
if(process.env.SSL_KEY_FILE === undefined) throw new Error("SSL_KEY_FILE env not set.")

const serverUrl = new URL(process.env.SERVER_HOST);
const apiUrl = new URL(process.env.API_URL);
const port = parseInt(process.env.PORT || '8443');

const cert = readFileSync(process.env.SSL_CRT_FILE);
const key = readFileSync(process.env.SSL_KEY_FILE);

const freshworks = 'https://widget.freshworks.com/';

const app = express();

const httpsServer = https.createServer({key, cert, passphrase: process.env.SSL_KEY_PASS || null}, app);

const scriptSrc = [
  "'self'",
  "'unsafe-inline'",
  freshworks,
];

const styleSrc = [
  "'self'",
  "'unsafe-inline'",
  'https://fonts.googleapis.com/',
  freshworks,
];

const connectSrc = [
  "'self'",
  `ws${serverUrl.protocol === 'https' ? 's' : ''}://${serverUrl.host}`,
  serverUrl.origin,
  apiUrl.origin,
  freshworks
];

const securityMiddleware = helmet({
  referrerPolicy: { policy: 'unsafe-url' },
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc,
      styleSrc,
      fontSrc: ["'self'", 'https://fonts.gstatic.com/'],
      imgSrc: ["'self'", 'data:', serverUrl.origin, 'https://map.opencti.io/'],
      connectSrc,
      objectSrc: ["'self'", serverUrl.origin],
      frameSrc: ["'self'", serverUrl.origin],
    },
  },
});

app.use(express.static(path.join(__dirname, 'build')));
app.use(securityMiddleware);

app.get('/*', (req, res) => {
  const data = readFileSync(path.join(__dirname,`build/index.html`), 'utf8');
  const withOptionValued = data.replace(/%BASE_PATH%/g, './');
  res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.header('Expires', '-1');
  res.header('Pragma', 'no-cache');
  return res.send(withOptionValued);
})

httpsServer.listen(port, () => console.log(`Server running on port ${port}...`));
