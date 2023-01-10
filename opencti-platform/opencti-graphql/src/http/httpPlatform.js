/* eslint-disable camelcase */
import express from 'express';
import * as R from 'ramda';
import { URL } from 'node:url';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import bodyParser from 'body-parser';
import compression from 'compression';
import helmet from 'helmet';
import nconf from 'nconf';
import showdown from 'showdown';
import rateLimit from 'express-rate-limit';
import contentDisposition from 'content-disposition';
import { basePath, booleanConf, DEV_MODE, logApp, logAudit } from '../config/conf';
import passport, { empty, isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { authenticateUser, authenticateUserFromRequest, loginFromProvider, userWithOrigin } from '../domain/user';
import { downloadFile, getFileContent, loadFile } from '../database/file-storage';
import createSseMiddleware from '../graphql/sseMiddleware';
import initTaxiiApi from './httpTaxii';
import { LOGIN_ACTION } from '../config/audit';
import initHttpRollingFeeds from './httpRollingFeed';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEntityFromCache } from '../database/cache';

const setCookieError = (res, message) => {
  res.cookie('opencti_flash', message || 'Unknown error', {
    maxAge: 5000,
    httpOnly: false,
    secure: booleanConf('app:https_cert:cookie_secure', false),
    sameSite: 'strict',
  });
};

const extractRefererPathFromReq = (req) => {
  const refererUrl = new URL(req.headers.referer);
  // Keep only the pathname to prevent OPEN REDIRECT CWE-601
  return refererUrl.pathname;
};

const createApp = async (app) => {
  const limiter = rateLimit({
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
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc,
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'http://cdn.jsdelivr.net/npm/@apollographql/',
          'https://fonts.googleapis.com/',
        ],
        scriptSrcAttr: [
          "'self'",
          "'unsafe-inline'",
          'http://cdn.jsdelivr.net/npm/@apollographql/',
          'https://fonts.googleapis.com/',
        ],
        fontSrc: ["'self'", 'data:', 'https://fonts.gstatic.com/'],
        imgSrc: ["'self'", 'data:', 'https://*', 'http://*'],
        connectSrc: ["'self'", 'wss://*', 'ws://*', 'data:', 'http://*', 'https://*'],
        objectSrc: ["'self'", 'data:', 'http://*', 'https://*'],
        frameSrc: ["'self'", 'data:', 'http://*', 'https://*'],
      },
    },
  });
  // Init the http server
  app.use(limiter);
  if (DEV_MODE) {
    app.set('json spaces', 2);
  }
  app.use(securityMiddleware);
  app.use(compression({}));

  // -- Serv playground resources
  app.use(`${basePath}/static/@apollographql/graphql-playground-react@1.7.42/build/static`, express.static('static/playground'));

  // -- Serv flags resources
  app.use(`${basePath}/static/flags`, express.static('static/flags'));

  // -- Serv frontend static resources
  app.use(`${basePath}/static`, express.static(path.join(__dirname, '../public/static')));

  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '10mb';
  app.use(bodyParser.json({ limit: requestSizeLimit }));

  const sseMiddleware = createSseMiddleware();
  sseMiddleware.applyMiddleware({ app });

  // -- Init Taxii rest api
  initTaxiiApi(app);

  // -- Init rolling feeds rest api
  initHttpRollingFeeds(app);

  // -- File download
  app.get(`${basePath}/storage/get/:file(*)`, async (req, res, next) => {
    try {
      const executeContext = executionContext('storage_get');
      const auth = await authenticateUserFromRequest(executeContext, req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const stream = await downloadFile(executeContext, file);
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
      const executeContext = executionContext('storage_view');
      const auth = await authenticateUserFromRequest(executeContext, req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const data = await loadFile(executeContext, auth, file);
      res.set('Content-disposition', contentDisposition(data.name, { type: 'inline' }));
      res.set({ 'Content-Security-Policy': 'sandbox' });
      res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.set({ Pragma: 'no-cache' });
      if (data.metaData.mimetype === 'text/html') {
        res.set({ 'Content-type': 'text/html; charset=utf-8' });
      } else {
        res.set('Content-type', data.metaData.mimetype);
      }
      const stream = await downloadFile(executeContext, file);
      stream.pipe(res);
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- Pdf view
  app.get(`${basePath}/storage/html/:file(*)`, async (req, res, next) => {
    try {
      const executeContext = executionContext('storage_html');
      const auth = await authenticateUserFromRequest(executeContext, req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const data = await loadFile(executeContext, auth, file);
      if (data.metaData.mimetype === 'text/markdown') {
        const markDownData = await getFileContent(file);
        const converter = new showdown.Converter();
        const html = converter.makeHtml(markDownData);
        res.set({ 'Content-Security-Policy': 'sandbox' });
        res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
        res.send(html);
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
      const context = executionContext('cert_strategy');
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
                await authenticateUser(context, req, user, 'cert');
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
  app.all(`${basePath}/auth/:provider/callback`, urlencodedParser, passport.initialize({}), async (req, res, next) => {
    const { referer } = req.session;
    const { provider } = req.params;
    const callbackLogin = () => new Promise((accept, reject) => {
      passport.authenticate(provider, {}, (err, user) => {
        if (err || !user) {
          reject(err);
        } else {
          accept(user);
        }
      })(req, res, next);
    });
    try {
      const context = executionContext(`${provider}_strategy`);
      const logged = await callbackLogin();
      await authenticateUser(context, req, logged, provider);
    } catch (err) {
      logAudit.error(userWithOrigin(req, {}), LOGIN_ACTION, { provider, error: err?.message });
      setCookieError(res, 'Invalid authentication, please ask your administrator');
    } finally {
      res.redirect(referer ?? '/');
    }
  });

  // Other routes - Render index.html
  app.get('*', async (req, res) => {
    const context = executionContext('app_loading');
    const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const data = readFileSync(`${__dirname}/../public/index.html`, 'utf8');
    const title = await settings?.platform_title ?? 'Cyber threat intelligence platform';
    const description = 'OpenCTI is an open source platform allowing organizations'
      + ' to manage their cyber threat intelligence knowledge and observables.';
    const settingFavicon = settings?.platform_favicon;
    const withOptionValued = data
      .replace(/%BASE_PATH%/g, basePath)
      .replace(/%APP_TITLE%/g, title)
      .replace(/%APP_DESCRIPTION%/g, description)
      .replace(/%APP_FAVICON%/g, settingFavicon ?? `${basePath}/static/ext/favicon.png`)
      .replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`);
    res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.set('Expires', '-1');
    res.set('Pragma', 'no-cache');
    return res.send(withOptionValued);
  });

  // Error handling
  app.use((err, req, res, next) => {
    logApp.error('[EXPRESS] Error http call', { error: err, referer: req.headers.referer });
    res.redirect('/');
    next();
  });
  return { sseMiddleware };
};

export default createApp;
