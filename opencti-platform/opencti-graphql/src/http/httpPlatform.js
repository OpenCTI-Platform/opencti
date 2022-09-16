/* eslint-disable camelcase */
import express from 'express';
import * as R from 'ramda';
// noinspection NodeCoreCodingAssistance
import { readFileSync } from 'fs';
// noinspection NodeCoreCodingAssistance
import path from 'path';
import bodyParser from 'body-parser';
import compression from 'compression';
import helmet from 'helmet';
import nconf from 'nconf';
import RateLimit from 'express-rate-limit';
import sanitize from 'sanitize-filename';
import { basePath, booleanConf, DEV_MODE, logApp, logAudit } from '../config/conf';
import passport, { empty, isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { authenticateUser, loginFromProvider, userWithOrigin } from '../domain/user';
import createSeeMiddleware from '../graphql/sseMiddleware';
import initTaxiiApi from './httpTaxii';
import { initializeSession } from '../database/session';
import { LOGIN_ACTION } from '../config/audit';
import { configureKeycloakMiddleware, getKeycloak, getKeycloakMiddleware } from '../service/keycloak';

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

const createApp = async () => {
  const appSessionHandler = initializeSession();
  const limiter = new RateLimit({
    windowMs: nconf.get('app:rate_protection:time_window') * 1000, // seconds
    max: nconf.get('app:rate_protection:max_requests'),
    handler: (req, res /* , next */) => {
      res.status(429).send({ message: 'Too many requests, please try again later.' });
    },
  });
  const scriptSrc = [
    "'self'",
    "'unsafe-inline'",
    'http://cdn.jsdelivr.net/npm/@apollographql/',
    'https://widget.freshworks.com/',
  ];
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
  app.use(`${basePath}/docs`, express.static(path.join(__dirname, '../../public/static/docs')));

  configureKeycloakMiddleware(`${basePath}/graphql`, app);

  app.use(appSessionHandler.session);
  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '10mb';
  app.use(bodyParser.json({ limit: requestSizeLimit }));

  const seeMiddleware = createSeeMiddleware();
  seeMiddleware.applyMiddleware({ app });

  // -- Init Taxii rest api
  initTaxiiApi(app);

  // -- File download
  // app.get(`${basePath}/storage/get/:file(*)`, async (req, res, next) => {
  //   try {
  //     const auth = await authenticateUserFromRequest(req);
  //     if (!auth) res.sendStatus(403);
  //     const { file } = req.params;
  //     const stream = await downloadFile(file);
  //     res.attachment(file);
  //     stream.pipe(res);
  //   } catch (e) {
  //     setCookieError(res, e?.message);
  //     next(e);
  //   }
  // });

  // -- File view
  // app.get(`${basePath}/storage/view/:file(*)`, async (req, res, next) => {
  //   try {
  //     const auth = await authenticateUserFromRequest(req);
  //     if (!auth) res.sendStatus(403);
  //     const { file } = req.params;
  //     const data = await loadFile(auth, file);
  //     res.setHeader('Content-disposition', contentDisposition(data.name, { type: 'inline' }));
  //     if (data.metaData.mimetype === 'text/html') {
  //       res.set({ 'Content-type': 'text/html; charset=utf-8' });
  //     } else {
  //       res.setHeader('Content-type', data.metaData.mimetype);
  //     }
  //     const stream = await downloadFile(file);
  //     stream.pipe(res);
  //   } catch (e) {
  //     setCookieError(res, e?.message);
  //     next(e);
  //   }
  // });

  // -- Pdf view
  // app.get(`${basePath}/storage/html/:file(*)`, async (req, res, next) => {
  //   try {
  //     const auth = await authenticateUserFromRequest(req);
  //     if (!auth) res.sendStatus(403);
  //     const { file } = req.params;
  //     const data = await loadFile(auth, file);
  //     if (data.metaData.mimetype === 'text/markdown') {
  //       const markDownData = await getFileContent(file);
  //       const converter = new showdown.Converter();
  //       const html = converter.makeHtml(markDownData);
  //       res.send(html);
  //     } else {
  //       res.send('Unsupported file type');
  //     }
  //   } catch (e) {
  //     setCookieError(res, e?.message);
  //     next(e);
  //   }
  // });

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
      req.session.referer = req.headers.referer;
      const { provider } = req.params;
      logApp.debug(`[Passport] Login auth/${provider}/ -> [referer:${req.headers.referer}]`);
      passport.authenticate(provider, {}, (err) => {
        setCookieError(res, err?.message);
        logApp.debug(`[Passport] Auth error callback]`);
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
    const { referer } = req.session;
    logApp.debug(`[Passport] Passport initialize auth/oidc/callback -> [referer:${referer}]`);
    const { provider } = req.params;
    // const host = req.headers.host
    passport.authenticate(provider, {}, async (err, user) => {
      if (err || !user) {
        logApp.debug(`[Passport] Authentication failed: [referer: ${referer}`);
        logAudit.error(userWithOrigin(req, {}), LOGIN_ACTION, { provider, error: err?.message });
        setCookieError(res, err?.message);
        return res.redirect(referer);
      }
      logApp.debug(`[Passport] User authenticated: [referer: ${referer}`);
      // noinspection UnnecessaryLocalVariableJS
      await authenticateUser(req, user, provider);
      req.session.referer = null;
      return res.redirect(referer);
    })(req, res, next);
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

export const applyWildcard = (app) => {
  app.get('*', (req, res) => {
    const data = readFileSync(`${__dirname}/../../public/index.html`, 'utf8');
    const withOptionValued = data.replace(/%BASE_PATH%/g, basePath);
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.header('Expires', '-1');
    res.header('Pragma', 'no-cache');
    return res.send(withOptionValued);
  });
};
