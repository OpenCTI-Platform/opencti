/* eslint-disable camelcase */
import express from 'express';
import * as R from 'ramda';
import { URL } from 'url';
// noinspection NodeCoreCodingAssistance
import { readFileSync } from 'fs';
// noinspection NodeCoreCodingAssistance
import path from 'path';
import bodyParser from 'body-parser';
import compression from 'compression';
import helmet from 'helmet';
import nconf from 'nconf';
import puppeteer from 'puppeteer';
import markdownPdf from 'markdown-pdf';
import RateLimit from 'express-rate-limit';
import sanitize from 'sanitize-filename';
import contentDisposition from 'content-disposition';
import { basePath, booleanConf, DEV_MODE, logApp, logAudit } from '../config/conf';
import passport, { empty, isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { authenticateUser, authenticateUserFromRequest, loginFromProvider, userWithOrigin } from '../domain/user';
import { downloadFile, loadFile, getFileContent } from '../database/minio';
import { checkSystemDependencies } from '../initialization';
import { getSettings } from '../domain/settings';
import createSeeMiddleware from '../graphql/sseMiddleware';
import initTaxiiApi from './httpTaxii';
import { initializeSession } from '../database/session';
import { LOGIN_ACTION } from '../config/audit';

const onHealthCheck = () => checkSystemDependencies().then(() => getSettings());

const setCookieError = (res, message) => {
  res.cookie('opencti_flash', message || 'Unknown error', {
    maxAge: 5000,
    httpOnly: false,
    secure: booleanConf('app:https_cert:cookie_secure', false),
  });
};

const extractRefererPathFromReq = (req) => {
  const refererUrl = new URL(req.headers.referer);
  // Keep only the pathname to prevent OPEN REDIRECT CWE-601
  return refererUrl.pathname;
};

const createApp = async (apolloServer) => {
  const appSessionHandler = initializeSession();
  const limiter = new RateLimit({
    windowMs: nconf.get('app:rate_protection:time_window') * 1000, // seconds
    max: nconf.get('app:rate_protection:max_requests'),
    handler: (req, res /* , next */) => {
      res.status(429).send({ message: 'Too many requests, please try again later.' });
    },
  });
  const scriptSrc = ["'self'", "'unsafe-inline'", 'http://cdn.jsdelivr.net/npm/@apollographql/'];
  if (DEV_MODE) {
    scriptSrc.push("'unsafe-eval'");
  }
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
          'http://cdn.jsdelivr.net/npm/@apollographql/',
          'https://fonts.googleapis.com/',
        ],
        fontSrc: ["'self'", 'https://fonts.gstatic.com/'],
        imgSrc: ["'self'", 'data:', 'https://*', 'http://*'],
        connectSrc: ["'self'", 'wss://*', 'ws://*', 'http://*', 'https://*'],
        objectSrc: ["'none'"],
      },
    },
  });
  // Init the http server
  const app = express();
  app.use(limiter);
  if (DEV_MODE) {
    app.set('json spaces', 2);
  }
  app.use(securityMiddleware);
  app.use(compression({}));

  // -- Generated CSS with correct base path
  app.get(`${basePath}/static/css/*`, (req, res) => {
    const cssFileName = R.last(req.url.split('/'));
    const data = readFileSync(path.join(__dirname, `../../public/static/css/${sanitize(cssFileName)}`), 'utf8');
    const withBasePath = data.replace(/%BASE_PATH%/g, basePath);
    res.header('Content-Type', 'text/css');
    res.send(withBasePath);
  });
  app.use(`${basePath}/static`, express.static(path.join(__dirname, '../../public/static')));

  app.use(appSessionHandler.session);
  // app.use(refreshSessionMiddleware);
  apolloServer.applyMiddleware({ app, cors: true, onHealthCheck, path: `${basePath}/graphql` });
  app.use(bodyParser.json({ limit: '100mb' }));

  const seeMiddleware = createSeeMiddleware();
  seeMiddleware.applyMiddleware({ app });

  // -- Init Taxii rest api
  initTaxiiApi(app);

  // -- File download
  app.get(`${basePath}/storage/get/:file(*)`, async (req, res, next) => {
    try {
      const auth = await authenticateUserFromRequest(req);
      if (!auth) res.sendStatus(403);
      const { file } = req.params;
      const stream = await downloadFile(file);
      res.attachment(file);
      stream.pipe(res);
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- File view
  app.get(`${basePath}/storage/view/:file(*)`, async (req, res, next) => {
    try {
      const auth = await authenticateUserFromRequest(req);
      if (!auth) res.sendStatus(403);
      const { file } = req.params;
      const data = await loadFile(auth, file);
      res.setHeader('Content-disposition', contentDisposition(data.name, { type: 'inline' }));
      res.setHeader('Content-type', data.metaData.mimetype);
      const stream = await downloadFile(file);
      stream.pipe(res);
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- Pdf view
  app.get(`${basePath}/storage/pdf/:file(*)`, async (req, res, next) => {
    try {
      const auth = await authenticateUserFromRequest(req);
      if (!auth) res.sendStatus(403);
      const { file } = req.params;
      const data = await loadFile(auth, file);
      if (data.metaData.mimetype === 'text/markdown') {
        const stream = await downloadFile(file);
        const pdfStream = stream.pipe(
          markdownPdf({
            remarkable: {
              // eslint-disable-next-line global-require
              plugins: [require('remarkable-classy'), require('remarkable-admonitions')],
            },
          })
        );
        res.setHeader('Content-disposition', contentDisposition(data.name, { type: 'inline' }));
        res.setHeader('Content-type', 'application/pdf');
        pdfStream.pipe(res);
      } else if (data.metaData.mimetype === 'text/html') {
        const content = await getFileContent(file);
        const browser = await puppeteer.launch();
        const page = await browser.newPage();
        await page.setContent(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>HTML to PDF Example</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  ${content}
</body>
</html>
`);
        const buffer = await page.pdf({ format: 'A4', margin: 20 });
        await browser.close();
        res.setHeader('Content-disposition', contentDisposition(data.name, { type: 'inline' }));
        res.setHeader('Content-type', 'application/pdf');
        res.send(buffer);
      } else {
        res.send('Unsupported file type');
      }
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- Client HTTPS Cert login custom strategy
  app.get(`${basePath}/auth/cert`, (req, res, next) => {
    try {
      const redirect = extractRefererPathFromReq(req);
      const isActivated = isStrategyActivated(STRATEGY_CERT);
      if (!isActivated) {
        setCookieError(res, 'Cert authentication is not available');
        res.redirect(redirect);
      } else {
        const cert = req.socket.getPeerCertificate();
        if (!R.isEmpty(cert) && req.client.authorized) {
          const { CN, emailAddress } = cert.subject;
          if (empty(emailAddress)) {
            setCookieError(res, 'Client certificate need a correct emailAddress');
            res.redirect(redirect);
          } else {
            const userInfo = { email: emailAddress, name: empty(CN) ? emailAddress : CN };
            loginFromProvider(userInfo)
              .then(async (user) => {
                await authenticateUser(req, user, 'cert');
                res.redirect(redirect);
              })
              .catch((err) => {
                setCookieError(res, err?.message);
                res.redirect(redirect);
              });
          }
        } else {
          setCookieError(res, 'You must select a correct certificate');
          res.redirect(redirect);
        }
      }
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- Passport login
  app.get(`${basePath}/auth/:provider`, (req, res, next) => {
    try {
      const { provider } = req.params;
      req.session.referer = extractRefererPathFromReq(req);
      passport.authenticate(provider, {}, (err) => {
        setCookieError(res, err?.message);
        next(err);
      })(req, res, next);
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- Passport callback
  const urlencodedParser = bodyParser.urlencoded({ extended: true });
  app.all(`${basePath}/auth/:provider/callback`, urlencodedParser, passport.initialize({}), (req, res, next) => {
    try {
      const { provider } = req.params;
      const { referer } = req.session;
      passport.authenticate(provider, {}, async (err, user) => {
        if (err || !user) {
          logAudit.error(userWithOrigin(req, {}), LOGIN_ACTION, { provider, error: err?.message });
          setCookieError(res, err?.message);
          return res.redirect(referer);
        }
        // noinspection UnnecessaryLocalVariableJS
        await authenticateUser(req, user, provider);
        req.session.referer = null;
        return res.redirect(referer);
      })(req, res, next);
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // Other routes - Render index.html
  app.get('*', (req, res) => {
    const data = readFileSync(`${__dirname}/../../public/index.html`, 'utf8');
    const withOptionValued = data.replace(/%BASE_PATH%/g, basePath);
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.header('Expires', '-1');
    res.header('Pragma', 'no-cache');
    return res.send(withOptionValued);
  });

  // Error handling
  app.use((err, req, res, next) => {
    logApp.error(`[EXPRESS] Error http call`, { error: err, referer: req.headers.referer });
    res.redirect('/');
    next();
  });
  return { app, seeMiddleware };
};

export default createApp;
