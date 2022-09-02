/* eslint-disable camelcase */
import express from 'express';
import * as R from 'ramda';
import { URL } from 'node:url';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import bodyParser from 'body-parser';
import prometheus from 'express-prometheus-middleware';
import compression from 'compression';
import helmet from 'helmet';
import nconf from 'nconf';
import showdown from 'showdown';
import rateLimit from 'express-rate-limit';
import contentDisposition from 'content-disposition';
import { basePath, booleanConf, DEV_MODE, formatPath, logApp, logAudit } from '../config/conf';
import passport, { empty, isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { authenticateUser, authenticateUserFromRequest, loginFromProvider, userWithOrigin } from '../domain/user';
import { downloadFile, getFileContent, loadFile } from '../database/file-storage';
import createSeeMiddleware from '../graphql/sseMiddleware';
import initTaxiiApi from './httpTaxii';
import { LOGIN_ACTION } from '../config/audit';
import initHttpRollingFeeds from './httpRollingFeed';

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
  // -- Telemetry
  const exposePrometheusMetrics = booleanConf('app:telemetry:prometheus:enabled', false);
  if (exposePrometheusMetrics) {
    const metricsPath = nconf.get('app:telemetry:prometheus:metrics_path') || '/prometheus/metrics';
    const fullMetricsPath = `${basePath}${formatPath(metricsPath)}`;
    logApp.info(`Adding prometheus middleware (for metrics) on path: ${fullMetricsPath}`);
    app.use(
      prometheus({
        metricsPath: fullMetricsPath,
        collectDefaultMetrics: true,
        requestDurationBuckets: [0.1, 0.5, 1, 1.5],
        requestLengthBuckets: [512, 1024, 5120, 10240, 51200, 102400],
        responseLengthBuckets: [512, 1024, 5120, 10240, 51200, 102400],
      })
    );
  }

  // -- Serv playground resources
  app.use(`${basePath}/static/@apollographql/graphql-playground-react@1.7.42/build/static`, express.static('static/playground'));

  // -- Serv static resources
  app.use(`${basePath}/static`, express.static(path.join(__dirname, '../public/static')));

  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '10mb';
  app.use(bodyParser.json({ limit: requestSizeLimit }));

  const seeMiddleware = createSeeMiddleware();
  seeMiddleware.applyMiddleware({ app });

  // -- Init Taxii rest api
  initTaxiiApi(app);

  // -- Init rolling feeds rest api
  initHttpRollingFeeds(app);

  // -- File download
  app.get(`${basePath}/storage/get/:file(*)`, async (req, res, next) => {
    try {
      const auth = await authenticateUserFromRequest(req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
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
      const auth = await authenticateUserFromRequest(req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const data = await loadFile(auth, file);
      res.set('Content-disposition', contentDisposition(data.name, { type: 'inline' }));
      res.set({ 'Content-Security-Policy': 'sandbox' });
      res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.set({ Pragma: 'no-cache' });
      if (data.metaData.mimetype === 'text/html') {
        res.set({ 'Content-type': 'text/html; charset=utf-8' });
      } else {
        res.set('Content-type', data.metaData.mimetype);
      }
      const stream = await downloadFile(file);
      stream.pipe(res);
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- Pdf view
  app.get(`${basePath}/storage/html/:file(*)`, async (req, res, next) => {
    try {
      const auth = await authenticateUserFromRequest(req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const data = await loadFile(auth, file);
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
    const { provider } = req.params;
    const { referer } = req.session;
    passport.authenticate(provider, {}, async (err, user) => {
      if (err || !user) {
        logAudit.error(userWithOrigin(req, {}), LOGIN_ACTION, { provider, error: err?.message });
        setCookieError(res, err?.message);
        return res.redirect(referer ?? '/');
      }
      // noinspection UnnecessaryLocalVariableJS
      await authenticateUser(req, user, provider);
      req.session.referer = null;
      return res.redirect(referer ?? '/');
    })(req, res, next);
  });

  // Other routes - Render index.html
  app.get('*', (req, res) => {
    const data = readFileSync(`${__dirname}/../public/index.html`, 'utf8');
    const withOptionValued = data.replace(/%BASE_PATH%/g, basePath);
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
  return { seeMiddleware };
};

export default createApp;
