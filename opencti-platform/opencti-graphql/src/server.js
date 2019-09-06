import express from 'express';
import http from 'http';
import { readFileSync } from 'fs';
import bodyParser from 'body-parser';
import { createTerminus } from '@godaddy/terminus';
import cookie from 'cookie';
import cookieParser from 'cookie-parser';
import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import compression from 'compression';
import helmet from 'helmet';
import { dissocPath, filter, isEmpty, map, not, pipe } from 'ramda';
import path from 'path';
import nconf from 'nconf';
import conf, {
  DEV_MODE,
  isAppRealTime,
  logger,
  OPENCTI_TOKEN
} from './config/conf';
import passport, { ACCESS_PROVIDERS } from './config/security';
import { findByTokenUUID, setAuthenticationCookie } from './domain/user';
import schema from './schema/schema';
import { buildValidationError, TYPE_AUTH, Unknown } from './config/errors';
import init from './initialization';

// Init the http server
const app = express();
app.use(cookieParser());
app.use(compression());
app.use(helmet());
app.use(bodyParser.json({ limit: '100mb' }));

// Static for generated fronted
const AppBasePath = nconf.get('app:base_path');
const basePath =
  isEmpty(AppBasePath) || AppBasePath.startsWith('/')
    ? AppBasePath
    : `/${AppBasePath}`;
// -- Generated CSS with correct base path
app.use('/static/css/*', (req, res) => {
  const data = readFileSync(
    path.join(__dirname, `../public${req.baseUrl}`),
    'utf8'
  );
  const withBasePath = data.replace(/%BASE_PATH%/g, basePath);
  res.header('Content-Type', 'text/css');
  return res.send(withBasePath);
});
// -- render other statics in standard way
app.use('/static', express.static(path.join(__dirname, '../public/static')));

// region Login
const urlencodedParser = bodyParser.urlencoded({ extended: true });
app.get('/auth/:provider', (req, res, next) => {
  const { provider } = req.params;
  passport.authenticate(provider)(req, res, next);
});
app.get(
  '/auth/:provider/callback',
  urlencodedParser,
  passport.initialize(),
  (req, res, next) => {
    const { provider } = req.params;
    passport.authenticate(provider, (err, token) => {
      if (err || !token) return res.status(err.status).send(err);
      setAuthenticationCookie(token, res);
      return res.redirect('/dashboard');
    })(req, res, next);
  }
);

export const authentication = async token => {
  if (!token) return undefined;
  try {
    return await findByTokenUUID(token);
  } catch (err) {
    logger.error(`[OPENCTI] Authentication error ${token} > `, err);
    return undefined;
  }
};

export const extractTokenFromBearer = bearer =>
  bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : null;
// endregion

const server = new ApolloServer({
  schema,
  introspection: true,
  playground: {
    settings: {
      'request.credentials': 'same-origin'
    }
  },
  async context({ req, res, connection }) {
    if (connection) return { user: connection.context.user }; // For websocket connection.
    let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : null;
    token = token || extractTokenFromBearer(req.headers.authorization);
    const auth = await authentication(token);
    return { res, user: auth };
  },
  tracing: DEV_MODE,
  formatError: error => {
    logger.error('[OPENCTI] Technical error > ', error); // Log the complete error.
    let e = apolloFormatError(error);
    if (e instanceof GraphQLError) {
      const errorCode = e.extensions.exception.code;
      if (errorCode === 'ERR_GRAPHQL_CONSTRAINT_VALIDATION') {
        const { fieldName } = e.extensions.exception;
        const ConstraintError = buildValidationError(fieldName);
        e = apolloFormatError(ConstraintError);
      } else {
        e = apolloFormatError(new Unknown());
      }
    }
    // Remove the exception stack in production.
    return DEV_MODE ? e : dissocPath(['extensions', 'exception'], e);
  },
  // After formatError
  formatResponse: (response, { context }) => {
    // If we have a auth failure, clear the user cookie
    const isAuthFailure = response.errors
      ? pipe(
          map(e => apolloFormatError(e)),
          filter(e => e.data && e.data.type === TYPE_AUTH),
          isEmpty,
          not
        )(response.errors)
      : false;
    if (isAuthFailure) context.res.clearCookie(OPENCTI_TOKEN);
    return response;
  },
  subscriptions: {
    // https://www.apollographql.com/docs/apollo-server/features/subscriptions.html
    onConnect: async (connectionParams, webSocket) => {
      const cookies = webSocket.upgradeReq.headers.cookie;
      const parsedCookies = cookies ? cookie.parse(cookies) : null;
      let token = parsedCookies ? parsedCookies[OPENCTI_TOKEN] : null;
      token = token || extractTokenFromBearer(connectionParams.authorization);
      const user = await authentication(token);
      return { user };
    }
  }
});

server.applyMiddleware({ app });

app.all('*', (req, res) => {
  const data = readFileSync(`${__dirname}/../public/index.html`, 'utf8');
  const withOptionValued = data
    .replace(/%BASE_PATH%/g, basePath)
    .replace(/%WS_ACTIVATED%/g, isAppRealTime)
    .replace(/%ACCESS_PROVIDERS%/g, ACCESS_PROVIDERS);
  res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.header('Expires', '-1');
  res.header('Pragma', 'no-cache');
  return res.send(withOptionValued);
});

const httpServer = http.createServer(app);
if (isAppRealTime) {
  server.installSubscriptionHandlers(httpServer);
}

function onSignal() {
  logger.info('OpenCTI is starting cleanup');
}

function onShutdown() {
  logger.info('Cleanup finished, OpenCTI shutdown');
}

const PORT = conf.get('app:port');
init()
  .then(() => {
    httpServer.listen(PORT, () => {
      createTerminus(httpServer, {
        signal: 'SIGINT',
        timeout: 1000,
        onSignal,
        onShutdown
      });
      logger.info(
        `🚀 Api ready on http://domain:${PORT}${
          server.graphqlPath
        }, base path ${nconf.get('app:base_path')}`
      );
      if (isAppRealTime) {
        logger.info(
          `🚀 WebSocket ready at ws://domain:${PORT}${server.subscriptionsPath}`
        );
      } else {
        logger.info(
          `🚀 WebSocket deactivated, config your redis and activate it`
        );
      }
    });
  })
  .catch(e => {
    logger.error('[OPENCTI] Start error > ', e);
    process.exit(1);
  });
