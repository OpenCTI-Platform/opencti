import express from 'express';
import http from 'http';
import bodyParser from 'body-parser';
import { createTerminus } from '@godaddy/terminus';
import cookie from 'cookie';
import { verify } from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import compression from 'compression';
import helmet from 'helmet';
import { dissocPath, pipe, map, filter, isEmpty, not } from 'ramda';
import path from 'path';
import conf, { DEV_MODE, logger, OPENCTI_TOKEN } from './config/conf';
import passport from './config/security';
import { findByTokenId, setAuthenticationCookie } from './domain/user';
import schema from './schema/schema';
import { ConstraintFailure, TYPE_AUTH, Unknown } from './config/errors';

// Init the http server
const app = express();
app.use(cookieParser());
app.use(compression());
app.use(helmet());

// Static for generated fronted
app.use('/', express.static(path.join(__dirname, '../public')));
app.use('/static', express.static(path.join(__dirname, '../public/static')));

// #### Login
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

const authentication = async token => {
  if (!token) return undefined;
  try {
    const decodedToken = verify(token, conf.get('jwt:secret'));
    return await findByTokenId(decodedToken.uuid);
  } catch (err) {
    logger.error(token, err);
    return undefined;
  }
};

const extractTokenFromBearer = bearer =>
  bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : null;

const server = new ApolloServer({
  schema,
  async context({ req, res, connection }) {
    if (connection) return { user: connection.context.user }; // For websocket connection.
    let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : null;
    token = token || extractTokenFromBearer(req.headers.authorization);
    const auth = await authentication(token);
    return { res, user: auth };
  },
  tracing: DEV_MODE,
  formatError: error => {
    logger.error(error); // Log the complete error.
    let e = apolloFormatError(error);
    if (e instanceof GraphQLError) {
      const errorCode = e.extensions.exception.code;
      if (errorCode === 'ERR_GRAPHQL_CONSTRAINT_VALIDATION') {
        const { fieldName } = e.extensions.exception;
        const ConstraintError = new ConstraintFailure(fieldName);
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
          filter(e => e.data.type === TYPE_AUTH),
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
      return { user: await authentication(token) };
    }
  }
});

server.applyMiddleware({ app });

const indexPath = { root: `${__dirname}/../public` };
app.all('*', (req, res) => res.sendFile('index.html', indexPath));

const httpServer = http.createServer(app);
server.installSubscriptionHandlers(httpServer);

function onSignal() {
  logger.info('OpenCTI is starting cleanup');
}

function onShutdown() {
  logger.info('Cleanup finished, OpenCTI shutdown');
}

const PORT = conf.get('app:port');
httpServer.listen(PORT, () => {
  createTerminus(httpServer, {
    signal: 'SIGINT',
    timeout: 1000,
    onSignal,
    onShutdown
  });
  logger.info(
    `🚀 Server ready at http://localhost:${PORT}${server.graphqlPath}`
  );
  logger.info(
    `🚀 Subscriptions ready at ws://localhost:${PORT}${
      server.subscriptionsPath
    }`
  );
});
