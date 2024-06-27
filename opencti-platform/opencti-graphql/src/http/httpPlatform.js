/* eslint-disable camelcase */
import { URL } from 'node:url';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import express from 'express';
import bodyParser from 'body-parser';
import compression from 'compression';
import helmet from 'helmet';
import nconf from 'nconf';
import showdown from 'showdown';
import archiver from 'archiver';
import validator from 'validator';
import archiverZipEncrypted from 'archiver-zip-encrypted';
import rateLimit from 'express-rate-limit';
import contentDisposition from 'content-disposition';
import { basePath, booleanConf, DEV_MODE, logApp, OPENCTI_SESSION } from '../config/conf';
import passport, { isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { authenticateUser, authenticateUserFromRequest, HEADERS_AUTHENTICATORS, loginFromProvider, userWithOrigin } from '../domain/user';
import { downloadFile, getFileContent, loadFile, isStorageAlive } from '../database/file-storage';
import createSseMiddleware from '../graphql/sseMiddleware';
import initTaxiiApi from './httpTaxii';
import initHttpRollingFeeds from './httpRollingFeed';
import { DEFAULT_INVALID_CONF_VALUE, executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEntityFromCache } from '../database/cache';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';
import { internalLoadById } from '../database/middleware-loader';
import { delUserContext, redisIsAlive } from '../database/redis';
import { UnknownError } from '../config/errors';
import { rabbitMQIsAlive } from '../database/rabbitmq';
import { isEngineAlive } from '../database/engine';
import { checkFileAccess } from '../modules/internal/document/document-domain';

const setCookieError = (res, message) => {
  res.cookie('opencti_flash', message || 'Unknown error', {
    maxAge: 5000,
    httpOnly: false,
    secure: booleanConf('app:https_cert:cookie_secure', false),
    sameSite: 'strict',
  });
};

const extractRefererPathFromReq = (req) => {
  if (isNotEmptyField(req.headers.referer)) {
    try {
      const refererUrl = new URL(req.headers.referer);
      // Keep only the pathname to prevent OPEN REDIRECT CWE-601
      return refererUrl.pathname;
    } catch {
      // prevent any invalid referer
      logApp.warn('Invalid referer for redirect extraction', { referer: req.headers.referer });
    }
  }
  return undefined;
};

const publishFileDownload = async (executeContext, auth, file) => {
  const { filename, entity_id } = file.metaData;
  const entity = entity_id ? await internalLoadById(executeContext, auth, entity_id) : undefined;
  const data = buildContextDataForFile(entity, file.id, filename);
  await publishUserAction({
    user: auth,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'download',
    context_data: data
  });
};

const publishFileRead = async (executeContext, auth, file) => {
  const { filename, entity_id } = file.metaData;
  const entity = entity_id ? await internalLoadById(executeContext, auth, entity_id) : undefined;
  const data = buildContextDataForFile(entity, file.id, filename);
  await publishUserAction({
    user: auth,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'read',
    context_data: data
  });
};

const createApp = async (app) => {
  const limiter = rateLimit({
    windowMs: nconf.get('app:rate_protection:time_window') * 1000, // seconds
    max: nconf.get('app:rate_protection:max_requests'),
    handler: (req, res /* , next */) => {
      res.status(429).send({ message: 'Too many requests, please try again later.' });
    },
  });
  const scriptSrc = ["'self'", "'unsafe-inline'", 'http://cdn.jsdelivr.net/npm/@apollographql/', 'https://www.googletagmanager.com/'];
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
        manifestSrc: ["'self'", 'data:', 'https://*', 'http://*'],
        connectSrc: ["'self'", 'wss://*', 'ws://*', 'data:', 'http://*', 'https://*'],
        objectSrc: ["'self'", 'data:', 'http://*', 'https://*'],
        frameSrc: ["'self'", 'data:', 'http://*', 'https://*'],
      },
    },
  });
  // Init the http server
  app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);
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

  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '15mb';
  app.use(bodyParser.json({ limit: requestSizeLimit }));

  const sseMiddleware = createSseMiddleware();
  sseMiddleware.applyMiddleware({ app });

  // -- Init Taxii rest api
  initTaxiiApi(app);

  // -- Init rolling feeds rest api
  initHttpRollingFeeds(app);

  // -- Register the encryption module
  archiver.registerFormat('zip-encrypted', archiverZipEncrypted);

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
      const data = await loadFile(executeContext, auth, file);
      const { id, metaData: { filename, entity_id } } = data;
      await checkFileAccess(executeContext, auth, 'download', { id, filename, entity_id });
      // If file is attach to a specific instance, we need to contr
      await publishFileDownload(executeContext, auth, data);
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
      const executeContext = executionContext('storage_view');
      const auth = await authenticateUserFromRequest(executeContext, req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const data = await loadFile(executeContext, auth, file);
      const { id, metaData: { filename, entity_id } } = data;
      await checkFileAccess(executeContext, auth, 'read', { id, filename, entity_id });
      await publishFileRead(executeContext, auth, data);
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
      const executeContext = executionContext('storage_html');
      const auth = await authenticateUserFromRequest(executeContext, req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const data = await loadFile(executeContext, auth, file);
      const { id, metaData: { filename, entity_id } } = data;
      await checkFileAccess(executeContext, auth, 'read', { id, filename, entity_id });
      const { mimetype } = data.metaData;
      if (mimetype === 'text/markdown') {
        const markDownData = await getFileContent(file);
        const converter = new showdown.Converter();
        const html = converter.makeHtml(markDownData);
        await publishFileRead(executeContext, auth, data);
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

  // -- Encrypted view
  app.get(`${basePath}/storage/encrypted/:file(*)`, async (req, res, next) => {
    try {
      const executeContext = executionContext('storage_encrypted');
      const auth = await authenticateUserFromRequest(executeContext, req, res);
      if (!auth) {
        res.sendStatus(403);
        return;
      }
      const { file } = req.params;
      const data = await loadFile(executeContext, auth, file);
      const { id, metaData: { filename, entity_id } } = data;
      await checkFileAccess(executeContext, auth, 'download', { id, filename, entity_id });
      await publishFileDownload(executeContext, auth, data);
      const archive = archiver.create('zip-encrypted', { zlib: { level: 8 }, encryptionMethod: 'aes256', password: nconf.get('app:artifact_zip_password') });
      archive.append(await downloadFile(file), { name: filename });
      archive.finalize();
      res.attachment(`${filename}.zip`);
      archive.pipe(res);
    } catch (e) {
      setCookieError(res, e?.message);
      next(e);
    }
  });

  // -- Client HTTPS Cert login custom strategy
  app.get(`${basePath}/auth/cert`, (req, res, next) => {
    try {
      const context = executionContext('cert_strategy');
      const redirect = extractRefererPathFromReq(req) ?? '/';
      const isActivated = isStrategyActivated(STRATEGY_CERT);
      if (!isActivated) {
        setCookieError(res, 'Cert authentication is not available');
        res.redirect(redirect);
      } else {
        const cert = req.socket.getPeerCertificate();
        if (isNotEmptyField(cert) && req.client.authorized) {
          const { CN, emailAddress } = cert.subject;
          if (isEmptyField(emailAddress)) {
            setCookieError(res, 'Client certificate need a correct emailAddress');
            res.redirect(redirect);
          } else {
            const userInfo = { email: emailAddress, name: isEmptyField(CN) ? emailAddress : CN };
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

  // Logout
  app.get(`${basePath}/logout`, async (req, res, next) => {
    try {
      const referer = extractRefererPathFromReq(req) ?? '/';
      const provider = req.session.session_provider?.provider;
      const { user } = req.session;
      if (user) {
        const withOrigin = userWithOrigin(req, user);
        await publishUserAction({
          user: withOrigin,
          event_type: 'authentication',
          event_access: 'administration',
          event_scope: 'logout',
          context_data: undefined
        });
        await delUserContext(user);
        res.clearCookie(OPENCTI_SESSION);
        req.session.destroy(() => {
          const strategy = passport._strategy(provider);
          if (strategy) {
            if (strategy.logout_remote === true && strategy.logout) {
              req.user = user; // Needed for passport
              strategy.logout(req, (error, request) => {
                if (error) {
                  setCookieError(res, 'Error generating logout uri');
                  next(error);
                } else {
                  res.redirect(request);
                }
              });
            } else {
              res.redirect(referer);
            }
          } else {
            const headerStrategy = HEADERS_AUTHENTICATORS.find((h) => h.provider === provider);
            if (headerStrategy && headerStrategy.logout_uri) {
              res.redirect(headerStrategy.logout_uri);
            } else {
              res.redirect(referer);
            }
          }
        });
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
      const strategy = passport._strategy(provider);
      const referer = extractRefererPathFromReq(req);
      if (strategy._saml) {
        // For SAML, no session is required, referer will be send back through RelayState
        req.query.RelayState = referer;
      } else {
        // For openid / oauth, session is required so we can use it
        req.session.referer = referer;
      }
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
  app.all(`${basePath}/auth/:provider/callback`, urlencodedParser, async (req, res, next) => {
    const referer = req.body.RelayState ?? req.session.referer;
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
      logApp.error(err, { provider });
      setCookieError(res, 'Invalid authentication, please ask your administrator');
    } finally {
      res.redirect(referer ?? '/');
    }
  });

  // -- Healthcheck
  app.get(`${basePath}/health`, async (req, res) => {
    try {
      res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.setTimeout(5000, () => {
        res.status(503).send({ status: 'error', error: 'request timeout' });
      });
      const configAccessKey = nconf.get('app:health_access_key');
      if (configAccessKey === DEFAULT_INVALID_CONF_VALUE || isEmptyField(configAccessKey)) {
        res.status(401).send({ status: 'unauthorized' });
      } else {
        const { health_access_key: access_key } = req.query;
        if (configAccessKey === 'public' || configAccessKey === access_key) {
          await Promise.all([isEngineAlive(), isStorageAlive(), rabbitMQIsAlive(), redisIsAlive()]);
          res.status(200).send({ status: 'success' });
        } else {
          res.status(401).send({ status: 'unauthorized' });
        }
      }
    } catch (e) {
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // Other routes - Render index.html
  app.get('*', async (_, res) => {
    const context = executionContext('app_loading');
    const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const data = readFileSync(`${__dirname}/../public/index.html`, 'utf8');
    const settingsTitle = settings?.platform_title;
    const description = 'OpenCTI is an open source platform allowing organizations'
      + ' to manage their cyber threat intelligence knowledge and observables.';
    const settingFavicon = settings?.platform_favicon;
    const withOptionValued = data
      .replace(/%BASE_PATH%/g, basePath)
      .replace(/%APP_TITLE%/g, isNotEmptyField(settingsTitle) ? validator.escape(settingsTitle)
        : 'OpenCTI - Cyber Threat Intelligence Platform')
      .replace(/%APP_DESCRIPTION%/g, validator.escape(description))
      .replace(/%APP_FAVICON%/g, isNotEmptyField(settingFavicon) ? validator.escape(settingFavicon)
        : `${basePath}/static/ext/favicon.png`)
      .replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`);
    res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.set('Expires', '-1');
    res.set('Pragma', 'no-cache');
    return res.send(withOptionValued);
  });

  // Error handling
  app.use((err, req, res, next) => {
    logApp.error(UnknownError('Http call interceptor fail', { cause: err, referer: req.headers.referer }));
    res.redirect('/');
    next();
  });
  return { sseMiddleware };
};

export default createApp;
