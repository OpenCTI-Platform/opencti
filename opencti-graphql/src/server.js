import express from 'express';
import http from 'http';
import bodyParser from 'body-parser';
import { createTerminus } from '@godaddy/terminus';
import { sign, verify } from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { ApolloServer } from 'apollo-server-express';
import moment from 'moment';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import compression from 'compression';
import helmet from 'helmet';
import { dissocPath } from 'ramda';
import conf, { DEV_MODE, logger, OPENCTI_TOKEN } from './config/conf';
import passport from './config/security';
import { findByTokenId } from './domain/user';
import driver from './database/neo4j';
import schema from './schema/schema';
import { UnknownError } from './config/errors';

// Init the http server
const app = express();
app.use(cookieParser());
app.use(compression());
app.use(helmet());

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
      const creation = moment(token.created_at);
      const maxDuration = moment.duration(token.duration);
      const expires = creation.add(maxDuration).toDate();
      // Create and setup the auth token.
      res.cookie('opencti_token', sign(token, conf.get('jwt:secret')), {
        httpOnly: false,
        expires,
        secure: !DEV_MODE
      });
      return res.redirect('/dashboard');
    })(req, res, next);
  }
);

const authentication = async token => {
  let authToken = token;
  if (!authToken) {
    // If no token in the request
    if (DEV_MODE) {
      authToken = conf.get('jwt:dev_token');
    } else {
      // If not in dev mode, you can't authenticate
      return undefined;
    }
  }
  try {
    const decodedToken = verify(authToken, conf.get('jwt:secret'));
    const user = await findByTokenId(decodedToken.id);
    return { user };
  } catch (err) {
    logger.error(err);
    return { user: undefined };
  }
};

const extractTokenFromBearer = bearer =>
  bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : undefined;

const server = new ApolloServer({
  schema,
  context({ req, connection }) {
    if (connection) return connection.context.user; // For websocket connection.
    let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : undefined;
    token = token || extractTokenFromBearer(req.headers.authorization);
    return authentication(token);
  },
  tracing: DEV_MODE,
  formatError: error => {
    logger.error(error); // Log the complete error.
    let e = apolloFormatError(error);
    if (e instanceof GraphQLError) {
      e = apolloFormatError(new UnknownError()); // Forward only an unknown error
    }
    // Remove the exception stack in production.
    return DEV_MODE ? e : dissocPath(['extensions', 'exception'], e);
  },
  subscriptions: {
    // https://www.apollographql.com/docs/apollo-server/features/subscriptions.html
    onConnect: connectionParams => ({
      user: authentication(
        extractTokenFromBearer(connectionParams.authorization)
      )
    })
  }
});

server.applyMiddleware({ app });
const httpServer = http.createServer(app);
server.installSubscriptionHandlers(httpServer);

function onSignal() {
  logger.info('OpenCTI is starting cleanup');
  driver.close();
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
