
const express = require('express');
const cors = require('cors');
const { readFileSync } = require('fs');
const helmet = require('helmet');
const path = require('path');

const app = express();

const scriptSrc = [
  "'self'",
  "'unsafe-inline'",
  'https://widget.freshworks.com/',
];

const securityMiddleware = helmet({
  expectCt: { enforce: true, maxAge: 30 },
  referrerPolicy: { policy: 'unsafe-url' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc,
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com/',
        'https://widget.freshworks.com/',
      ],
      fontSrc: ["'self'", 'https://fonts.gstatic.com/'],
      imgSrc: ["'self'", 'data:', 'https://*', 'http://*'],
      connectSrc: ["'self'", 'wss://*', 'ws://*', 'data:', 'http://*', 'https://*'],
      objectSrc: ["'self'", 'data:', 'http://*', 'https://*'],
      frameSrc: ["'self'", 'data:', 'http://*', 'https://*'],
    },
  },
});

app.use(express.static(path.join(__dirname, 'build')));
app.use(cors())

app.get('/*', (req, res) => {
  const data = readFileSync(path.join(__dirname,`build/index.html`), 'utf8');
  const withOptionValued = data.replace(/%BASE_PATH%/g, './');
  res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.header('Expires', '-1');
  res.header('Pragma', 'no-cache');
  return res.send(withOptionValued);
})

app.listen(8778,() => console.log('listening...'))
