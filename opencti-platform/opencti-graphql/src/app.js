/* eslint-disable camelcase */
import express from 'express';
import * as R from 'ramda';
// noinspection NodeCoreCodingAssistance
import { readFileSync } from 'fs';
// noinspection NodeCoreCodingAssistance
import path from 'path';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import helmet from 'helmet';
import nconf from 'nconf';
import { v4 as uuidv4 } from 'uuid';
import RateLimit from 'express-rate-limit';
import sanitize from 'sanitize-filename';
import contentDisposition from 'content-disposition';
import session from 'express-session';
import conf, { basePath, DEV_MODE, logger, OPENCTI_SESSION } from './config/conf';
import passport from './config/providers';
import { authenticateUser } from './domain/user';
import { downloadFile, loadFile } from './database/minio';
import { checkSystemDependencies } from './initialization';
import { getSettings } from './domain/settings';
import createSeeMiddleware from './graphql/sseMiddleware';
import initTaxiiApi from './taxiiApi';
import { redisSessionStore } from './database/redis';

const ONE_DAY_SESSION = 86400 * 1000;
const sessionSecret = nconf.get('app:session_secret') || nconf.get('app:admin:password');
export const sessionMiddleware = (staticSession) =>
  session({
    genid: () => uuidv4(),
    name: OPENCTI_SESSION,
    store: redisSessionStore(staticSession),
    secret: sessionSecret,
    proxy: true,
    rolling: !staticSession,
    saveUninitialized: false,
    resave: false,
    cookie: {
      secure: conf.get('app:cookie_secure'),
      _expires: staticSession ? ONE_DAY_SESSION : conf.get('app:session_timeout'),
    },
  });
let webSession;
let apiSession;
const createApp = async (apolloServer, broadcaster) => {
  // Init the http server
  const app = express();
  app.set('json spaces', 2);
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
  app.use(bodyParser.json({ limit: '100mb' }));
  app.use(cookieParser());
  app.use(compression());
  webSession = sessionMiddleware(false);
  apiSession = sessionMiddleware(true);
  app.use((req, res, next) => {
    // If no referer (web site), prevent session extension
    // https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Referer
    const isApiSession = !req.headers.referer;
    return isApiSession ? apiSession(req, res, next) : webSession(req, res, next);
  });
  app.use(cookieParser());
  app.use(compression());
  app.use(helmet());
  app.use(helmet.frameguard());
  app.use(helmet.expectCt({ enforce: true, maxAge: 30 }));
  app.use(helmet.referrerPolicy({ policy: 'unsafe-url' }));
  app.use(
    helmet.contentSecurityPolicy({
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
        connectSrc: ["'self'", 'wss://*', 'ws://*'],
        objectSrc: ["'none'"],
      },
    })
  );
  app.use(bodyParser.json({ limit: '100mb' }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(limiter);

  let seeMiddleware;
  if (broadcaster) {
    seeMiddleware = createSeeMiddleware(broadcaster);
    seeMiddleware.applyMiddleware({ app });
  }

  const urlencodedParser = bodyParser.urlencoded({ extended: true });

  // -- Init Taxii rest api
  initTaxiiApi(app);

  // -- Generated CSS with correct base path
  app.get(`${basePath}/static/css/*`, (req, res) => {
    const cssFileName = R.last(req.url.split('/'));
    const data = readFileSync(path.join(__dirname, `../public/static/css/${sanitize(cssFileName)}`), 'utf8');
    const withBasePath = data.replace(/%BASE_PATH%/g, basePath);
    res.header('Content-Type', 'text/css');
    res.send(withBasePath);
  });
  app.use(`${basePath}/static`, express.static(path.join(__dirname, '../public/static')));

  // -- File download
  app.get(`${basePath}/storage/get/:file(*)`, async (req, res) => {
    const auth = await authenticateUser(req);
    if (!auth) res.sendStatus(403);
    const { file } = req.params;
    const stream = await downloadFile(file);
    res.attachment(file);
    stream.pipe(res);
  });

  // -- File view
  app.get(`${basePath}/storage/view/:file(*)`, async (req, res) => {
    const auth = await authenticateUser(req);
    if (!auth) res.sendStatus(403);
    const { file } = req.params;
    const data = await loadFile(file);
    res.setHeader('Content-disposition', contentDisposition(data.name, { type: 'inline' }));
    res.setHeader('Content-type', data.metaData.mimetype);
    const stream = await downloadFile(file);
    stream.pipe(res);
  });

  // -- Passport login
  app.get(`${basePath}/auth/:provider`, (req, res, next) => {
    const { provider } = req.params;
    req.session.referer = req.headers.referer;
    passport.authenticate(provider, {}, () => {})(req, res, next);
  });

  // -- Passport callback
  app.get(`${basePath}/auth/:provider/callback`, urlencodedParser, (req, res, next) => {
    const { provider } = req.params;
    passport.authenticate(provider, {}, async (err, token) => {
      if (err || !token) {
        return res.redirect(`/dashboard?message=${err.message}`);
      }
      // noinspection UnnecessaryLocalVariableJS
      await authenticateUser(req, token.uuid);
      const { referer } = req.session;
      req.session.referer = null;
      return res.redirect(referer);
    })(req, res, next);
  });

  // -- HealthCheck
  const serverHealthCheck = () => checkSystemDependencies().then(() => getSettings());

  // Apply middleware to answer to graphql call
  apolloServer.applyMiddleware({ app, onHealthCheck: serverHealthCheck, path: `${basePath}/graphql` });

  // Other routes - Render index.html
  app.get('*', (req, res) => {
    const data = readFileSync(`${__dirname}/../public/index.html`, 'utf8');
    const withOptionValued = data.replace(/%BASE_PATH%/g, basePath);
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.header('Expires', '-1');
    res.header('Pragma', 'no-cache');
    return res.send(withOptionValued);
  });

  // Error handling
  app.use((err, req, res, next) => {
    logger.error(`[EXPRESS] Error http call`, { error: err });
    res.redirect('/');
    next();
  });

  return { app, seeMiddleware };
};

export const getWebSession = () => webSession;
export default createApp;
