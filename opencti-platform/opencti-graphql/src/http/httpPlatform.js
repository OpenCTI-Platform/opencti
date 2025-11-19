/* eslint-disable camelcase */
import { URL } from 'node:url';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import express from 'express';
import bodyParser from 'body-parser';
import compression, { filter as compressionFilter } from 'compression';
import helmet from 'helmet';
import nconf from 'nconf';
import { marked } from 'marked';
import archiver from 'archiver';
import validator from 'validator';
import archiverZipEncrypted from 'archiver-zip-encrypted';
import rateLimit from 'express-rate-limit';
import contentDisposition from 'content-disposition';
import { printSchema } from 'graphql/utilities';
import { basePath, DEV_MODE, ENABLED_UI, logApp, OPENCTI_SESSION, PLATFORM_VERSION, AUTH_PAYLOAD_BODY_SIZE, getBaseUrl } from '../config/conf';
import passport, { isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { HEADERS_AUTHENTICATORS, loginFromProvider, sessionAuthenticateUser, userWithOrigin } from '../domain/user';
import { downloadFile, getFileContent, isStorageAlive } from '../database/raw-file-storage';
import { loadFile } from '../database/file-storage';
import { DEFAULT_INVALID_CONF_VALUE, executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEntityFromCache } from '../database/cache';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';
import { internalLoadById } from '../database/middleware-loader';
import { delUserContext, redisIsAlive } from '../database/redis';
import { rabbitMQIsAlive } from '../database/rabbitmq';
import { isEngineAlive } from '../database/engine';
import createSseMiddleware from '../graphql/sseMiddleware';
import initTaxiiApi from './httpTaxii';
import initHttpRollingFeeds from './httpRollingFeed';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { setCookieError } from './httpUtils';
import { getChatbotProxy } from './httpChatbotProxy';

export const sanitizeReferer = (refererToSanitize) => {
  if (!refererToSanitize) return '/';
  const base = getBaseUrl();
  const resolvedUrl = new URL(refererToSanitize, base).toString();
  if (resolvedUrl === base || resolvedUrl.startsWith(`${base}/`)) {
    // same domain URL accept the redirection
    if (refererToSanitize.startsWith('/') && !refererToSanitize.startsWith('//')) {
      // in case of relative URL, keep relative.
      return refererToSanitize;
    }
    return resolvedUrl;
  }
  logApp.info('Error auth provider callback : url has been altered', { url: refererToSanitize });
  return '/';
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

const createApp = async (app, schema) => {
  const limiter = rateLimit({
    windowMs: nconf.get('app:rate_protection:time_window') * 1000, // seconds
    limit: nconf.get('app:rate_protection:max_requests'),
    handler: (req, res /* , next */) => {
      res.status(429).send({ message: 'Too many requests, please try again later.' });
    },
  });

  // Init the http server
  app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);
  app.use(limiter);
  if (DEV_MODE) {
    app.set('json spaces', 2);
  }

  // Configure server security
  const buildSecurity = (opts) => helmet({
    expectCt: { enforce: true, maxAge: 30 },
    referrerPolicy: { policy: 'unsafe-url' },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: opts.scriptSrc,
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
        frameSrc: opts.allowedFrameSrc,
        frameAncestors: opts.frameAncestorDomains,
      },
    },
    xFrameOptions: !opts.isIframeAllowed,
  });

  const ancestorsFromConfig = nconf.get('app:public_dashboard_authorized_domains')?.trim() ?? '';
  const frameAncestorDomains = ancestorsFromConfig === '' ? "'none'" : ancestorsFromConfig;
  const allowedFrameSrc = ["'self'"];
  const scriptSrc = ["'self'", "'unsafe-inline'", 'http://cdn.jsdelivr.net/npm/@apollographql/', 'https://www.googletagmanager.com/'];
  if (DEV_MODE) {
    scriptSrc.push("'unsafe-eval'");
  }
  const securityOpts = {
    frameAncestorDomains: "'none'",
    allowedFrameSrc,
    scriptSrc,
    isIframeAllowed: false,
  };

  app.use((req, res, next) => {
    const urlString = req.url;
    if (urlString && (urlString.startsWith(`${basePath}/public`))) {
      const securityMiddleware = buildSecurity({
        ...securityOpts,
        frameAncestorDomains,
        isIframeAllowed: frameAncestorDomains !== "'none'",
      });
      securityMiddleware(req, res, next);
    } else {
      const securityMiddleware = buildSecurity(securityOpts);
      securityMiddleware(req, res, next);
    }
  });

  app.use(compression({
    filter: (req, res) => res.getHeader('Content-Type') !== 'text/event-stream' && compressionFilter(req, res),
  }));

  if (ENABLED_UI) {
    // -- Serv flags resources
    app.use(`${basePath}/static/flags`, express.static('static/flags'));

    // -- Serv frontend static resources
    app.use(`${basePath}/static`, express.static(path.join(__dirname, '../public/static')));
  }

  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '50mb';
  app.use(express.json({ limit: requestSizeLimit }));

  const sseMiddleware = createSseMiddleware();
  sseMiddleware.applyMiddleware({ app });

  // -- Init Taxii rest api
  initTaxiiApi(app);

  // -- Init rolling feeds rest api
  initHttpRollingFeeds(app);

  // -- Register the encryption module
  archiver.registerFormat('zip-encrypted', archiverZipEncrypted);

  // -- API schema
  app.get(`${basePath}/schema`, async (req, res) => {
    const context = await createAuthenticatedContext(req, res, 'schema_get');
    if (!context.user) {
      res.sendStatus(403);
      return;
    }
    res.set('Cache-Control', 'public, max-age=3600'); // 1 hour cache
    res.set('Vary', 'X-OPENCTI-SCHEMA-VARY-CACHE'); // Way for client to invalidate cache
    res.json({ version: PLATFORM_VERSION, schema: printSchema(schema) });
  });

  // -- File download
  app.get(`${basePath}/storage/get/*file`, async (req, res) => {
    try {
      const context = await createAuthenticatedContext(req, res, 'storage_get');
      if (!context.user) {
        res.sendStatus(403);
        return;
      }
      const file = req.params.file.join('/');
      const data = await loadFile(context, context.user, file);
      // If file is attach to a specific instance, we need to contr
      await publishFileDownload(context, context.user, data);
      const stream = await downloadFile(file);
      res.attachment(file);
      stream.pipe(res);
    } catch (e) {
      setCookieError(res, e.message);
      logApp.error('Error getting storage get file', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // -- File view
  app.get(`${basePath}/storage/view/*file`, async (req, res) => {
    try {
      const context = await createAuthenticatedContext(req, res, 'storage_view');
      if (!context.user) {
        res.sendStatus(403);
        return;
      }
      const file = req.params.file.join('/');
      const data = await loadFile(context, context.user, file);
      await publishFileRead(context, context.user, data);
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
      setCookieError(res, e.message);
      logApp.error('Error getting storage view file', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // -- embedded loader
  const uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
  const embeddedFileGetPath = new RegExp(`${basePath}/(.*)/(${uuidPattern})/(.*)embedded/(.*)$`, 'i');
  app.get(embeddedFileGetPath, async (req, res) => {
    try {
      const [_, id, __, filename] = Object.values(req.params);
      const context = await createAuthenticatedContext(req, res, 'storage_view_embedded');
      if (!context.user) {
        res.sendStatus(403);
        return;
      }
      const element = await internalLoadById(context, context.user, id);
      const file = `embedded/${element.entity_type}/${id}/${filename}`;
      const data = await loadFile(context, context.user, file);
      await publishFileRead(context, context.user, data);
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
      setCookieError(res, e.message);
      logApp.error('Error getting storage view file', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // -- Pdf view
  app.get(`${basePath}/storage/html/*file`, async (req, res) => {
    try {
      const context = await createAuthenticatedContext(req, res, 'storage_html');
      if (!context.user) {
        res.sendStatus(403);
        return;
      }
      const file = req.params.file.join('/');
      const data = await loadFile(context, context.user, file);
      const { mimetype } = data.metaData;
      if (mimetype === 'text/markdown') {
        const markDownData = await getFileContent(file);
        const html = marked(markDownData);
        await publishFileRead(context, context.user, data);
        res.set({ 'Content-Security-Policy': 'sandbox' });
        res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
        res.send(html);
      } else {
        res.send('Unsupported file type');
      }
    } catch (e) {
      setCookieError(res, e.message);
      logApp.error('Error getting html file', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // -- Encrypted view
  app.get(`${basePath}/storage/encrypted/*file`, async (req, res) => {
    try {
      const context = await createAuthenticatedContext(req, res, 'storage_encrypted');
      if (!context.user) {
        res.sendStatus(403);
        return;
      }
      const file = req.params.file.join('/');
      const data = await loadFile(context, context.user, file);
      const { metaData: { filename } } = data;
      await publishFileDownload(context, context.user, data);
      const archive = archiver.create('zip-encrypted', { zlib: { level: 8 }, encryptionMethod: 'aes256', password: nconf.get('app:artifact_zip_password') });
      archive.append(await downloadFile(file), { name: filename });
      await archive.finalize();
      res.attachment(`${filename}.zip`);
      archive.pipe(res);
    } catch (e) {
      setCookieError(res, e.message);
      logApp.error('Error getting encrypted file', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // -- Client HTTPS Cert login custom strategy
  app.get(`${basePath}/auth/cert`, (req, res) => {
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
                await sessionAuthenticateUser(context, req, user, 'cert');
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
      setCookieError(res, e.message);
      logApp.error('Error auth by cert', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // Logout
  app.get(`${basePath}/logout`, async (req, res) => {
    try {
      const referer = extractRefererPathFromReq(req) ?? '/';
      const provider = req.session.session_provider;
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
            if (strategy.logout_remote === true) {
              logApp.debug('[LOGOUT] Looking for logout_remote parameters: ', strategy.logout_remote);
              if (strategy.logout) {
                logApp.debug('[LOGOUT] requesting remote logout using authentication strategy parameters.');
                req.user = user; // Needed for passport
                strategy.logout(req, (error, request) => {
                  // When logout is implemented for strategy
                  if (error) {
                    setCookieError(res, 'Error generating logout uri');
                    res.status(503).send({ status: 'error', error: error.message });
                  } else {
                    logApp.debug('[LOGOUT] Remote logout ok');
                    res.redirect(request);
                  }
                });
              } else {
                logApp.info('[LOGOUT] No remote logout implementation found in strategy.');
                res.redirect(referer);
              }
            } else {
              logApp.debug('[LOGOUT] OpenCTI logout only, remote logout on IDP not requested.');
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
      setCookieError(res, e.message);
      logApp.error('Error logout', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
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
      setCookieError(res, e.message);
      logApp.error('Error auth provider', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // -- Passport callback
  // -- Default limit is '100kb' based on https://expressjs.com/en/resources/middleware/body-parser.html
  const urlencodedParser = AUTH_PAYLOAD_BODY_SIZE ? bodyParser.urlencoded({ extended: true, limit: AUTH_PAYLOAD_BODY_SIZE }) : bodyParser.urlencoded({ extended: true });
  app.all(`${basePath}/auth/:provider/callback`, urlencodedParser, async (req, res, next) => {
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
      await sessionAuthenticateUser(context, req, logged, provider);
    } catch (e) {
      logApp.error('Error auth provider callback', { cause: e, provider });
      setCookieError(res, 'Invalid authentication, please ask your administrator');
    } finally {
      const referer = req.body?.RelayState ?? req.session.referer;
      const sanitizedReferer = sanitizeReferer(referer);
      res.redirect(sanitizedReferer);
    }
  });

  // -- Healthcheck
  const healthCheckTimeout = async (promise, message) => {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error(message)), 15000); // 15 seconds timeout
    });
    return Promise.race([promise, timeoutPromise]);
  };
  app.get(`${basePath}/health`, async (req, res) => {
    try {
      res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      const configAccessKey = nconf.get('app:health_access_key');
      if (configAccessKey === DEFAULT_INVALID_CONF_VALUE || isEmptyField(configAccessKey)) {
        res.status(401).send({ status: 'unauthorized' });
      } else {
        const { health_access_key: access_key } = req.query;
        if (configAccessKey === 'public' || configAccessKey === access_key) {
          const engineAlive = healthCheckTimeout(isEngineAlive(), 'Timeout checking elastic/opensearch health');
          const storageAlive = healthCheckTimeout(isStorageAlive(), 'Timeout checking storage health');
          const rabbitMQAlive = healthCheckTimeout(rabbitMQIsAlive(), 'Timeout checking rabbitmq health');
          const redisAlive = healthCheckTimeout(redisIsAlive(), 'Timeout checking redis health');
          await Promise.all([engineAlive, storageAlive, rabbitMQAlive, redisAlive]);
          res.status(200).send({ status: 'success' });
        } else {
          res.status(401).send({ status: 'unauthorized' });
        }
      }
    } catch (e) {
      logApp.error('Error in health check', { cause: e });
      res.status(503).send({ status: 'error', error: e.message });
    }
  });

  // -- Chatbot Proxy
  app.post(`${basePath}/chatbot`, getChatbotProxy);

  // Other routes - Render index.html
  app.get('*any', async (_, res) => {
    if (ENABLED_UI) {
      const context = executionContext('app_loading');
      const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
      const data = await readFile(`${__dirname}/../public/index.html`, 'utf8');
      const settingsTitle = settings?.platform_title;
      const description = 'OpenCTI is an open source platform allowing organizations'
          + ' to manage their cyber threat intelligence knowledge and observables.';
      const settingFavicon = settings?.platform_favicon;
      const withOptionValued = data
        .replace(/%BASE_PATH%/g, basePath)
        .replace(/%APP_SCRIPT_SNIPPET%/g, nconf.get('app:script_snippet')?.trim() ?? '')
        .replace(/%APP_TITLE%/g, isNotEmptyField(settingsTitle) ? validator.escape(settingsTitle)
          : 'OpenCTI - Cyber Threat Intelligence Platform')
        .replace(/%APP_DESCRIPTION%/g, validator.escape(description))
        .replace(/%APP_FAVICON%/g, isNotEmptyField(settingFavicon) ? validator.escape(settingFavicon)
          : `${basePath}/static/ext/favicon.png`)
        .replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`);
      res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.set('Expires', '-1');
      res.set('Pragma', 'no-cache');
      res.send(withOptionValued);
    } else {
      res.status(503).send({ status: 'error', error: 'Interface is disabled by configuration' });
    }
  });

  // Any random unexpected request not GET
  app.use((_req, res, _next) => {
    res.status(404).send({ status: 'error', error: 'Path not found' });
  });

  // Error handling
  app.use((err, req, res, _next) => {
    logApp.error('Http call interceptor fail', { cause: err, referer: req.headers?.referer });
    res.status(500).send({ status: 'error', error: DEV_MODE ? err.stack : err.message });
  });

  return { sseMiddleware };
};

export default createApp;
