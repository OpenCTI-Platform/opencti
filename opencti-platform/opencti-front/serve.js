const express = require('express');
const { readFileSync } = require('fs');
const helmet = require('helmet');
const path = require('path');
const dotenv = require('dotenv')

dotenv.config();

if(process.env.SERVER_HOST === undefined) throw new Error('SERVER_URL env not set.');
if(process.env.API_URL === undefined) throw new Error('API_URL env not set.');

const serverUrl = new URL(process.env.SERVER_HOST);
const apiUrl = new URL(process.env.API_URL);
const freshworks = 'https://widget.freshworks.com/';

const app = express();

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
]

const connectSrc = [
  "'self'",
  `ws${serverUrl.protocol === 'https' ? 's' : ''}://${serverUrl.host}`,
  serverUrl.origin,
  apiUrl.origin,
  freshworks
]

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

app.listen(8778,() => console.log('listening...'))
