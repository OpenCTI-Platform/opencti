import express from 'express';
// noinspection NodeJsCodingAssistanceForCoreModules
import { readFileSync } from 'fs';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import compression from 'compression';
import helmet from 'helmet';
import { isEmpty } from 'ramda';
import path from 'path';
import nconf from 'nconf';
import { logger, OPENCTI_TOKEN } from './config/conf';
import passport from './config/providers';
import { authentication, setAuthenticationCookie } from './domain/user';
import { downloadFile, loadFile } from './database/minio';

const createApp = (apolloServer) => {
  // Init the http server
  const app = express();
  const sessionSecret = nconf.get('app:session_secret') || nconf.get('app:admin:password');
  app.use(session({ secret: sessionSecret, saveUninitialized: true, resave: true }));
  app.use(cookieParser());
  app.use(compression());
  app.use(helmet());
  app.use(bodyParser.json({ limit: '100mb' }));

  const extractTokenFromBearer = (bearer) => (bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : null);
  const AppBasePath = nconf.get('app:base_path');
  const basePath = isEmpty(AppBasePath) || AppBasePath.startsWith('/') ? AppBasePath : `/${AppBasePath}`;
  const urlencodedParser = bodyParser.urlencoded({ extended: true });

  // -- Generated CSS with correct base path
  app.get('/static/css/*', (req, res) => {
    const data = readFileSync(path.join(__dirname, `../public${req.url}`), 'utf8');
    const withBasePath = data.replace(/%BASE_PATH%/g, basePath);
    res.header('Content-Type', 'text/css');
    res.send(withBasePath);
  });
  app.use('/static', express.static(path.join(__dirname, '../public/static')));

  // -- File download
  app.get('/storage/get/:file(*)', async (req, res) => {
    let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : null;
    token = token || extractTokenFromBearer(req.headers.authorization);
    const auth = await authentication(token);
    if (!auth) res.sendStatus(403);
    const { file } = req.params;
    const stream = await downloadFile(file);
    res.attachment(file);
    stream.pipe(res);
  });

  // -- File view
  app.get('/storage/view/:file(*)', async (req, res) => {
    let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : null;
    token = token || extractTokenFromBearer(req.headers.authorization);
    const auth = await authentication(token);
    if (!auth) res.sendStatus(403);
    const { file } = req.params;
    const data = await loadFile(file);
    res.setHeader('Content-disposition', `inline; filename="${data.name}"`);
    res.setHeader('Content-type', data.metaData.mimetype);
    const stream = await downloadFile(file);
    stream.pipe(res);
  });

  // -- Passport login
  app.get('/auth/:provider', (req, res, next) => {
    const { provider } = req.params;
    passport.authenticate(provider)(req, res, next);
  });

  // -- Passport callback
  app.get('/auth/:provider/callback', urlencodedParser, passport.initialize(), (req, res, next) => {
    const { provider } = req.params;
    passport.authenticate(provider, (err, token) => {
      if (err || !token) {
        return res.redirect(`/login?message=${err.message}`);
      }
      setAuthenticationCookie(token, res);
      return res.redirect('/dashboard');
    })(req, res, next);
  });

  const serverHealthCheck = () => {
    return new Promise((resolve) => {
      // TODO @Julien Implements a real health function
      // Check grakn and ES connection?
      resolve();
    });
  };
  apolloServer.applyMiddleware({ app, onHealthCheck: serverHealthCheck });

  // Other routes
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

  return app;
};

export default createApp;
