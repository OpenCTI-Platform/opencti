import express from 'express';
import http from 'http';
import bodyParser from 'body-parser';
import { createTerminus } from '@godaddy/terminus';
import { sign, verify } from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { ApolloServer, AuthenticationError } from 'apollo-server-express';
import moment from 'moment';
import { dissocPath } from 'ramda';
import conf, { logger } from './config/conf';
import passport from './config/security';
import { findByTokenId } from './domain/user';
import driver from './database/neo4j';
import schema from './schema/schema';

const devMode = process.env.NODE_ENV === 'development';

const app = express();
app.use(cookieParser());

// #### Login
const urlencodedParser = bodyParser.urlencoded({ extended: true });
// ## Local strategy
app.post(
  '/auth/api',
  urlencodedParser,
  passport.initialize(),
  (req, res, next) => {
    passport.authenticate('local', (err, token) => {
      if (err || !token) return res.status(err.status).send(err);
      return res.send(sign(token, conf.get('jwt:secret')));
    })(req, res, next);
  }
);
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
        secure: !devMode
      });
      return res.redirect('/dashboard');
    })(req, res, next);
  }
);

function onSignal() {
  logger.info('OpenCTI is starting cleanup');
  driver.close();
}

function onShutdown() {
  logger.info('Cleanup finished, OpenCTI shutdown');
}

const options = {
  signal: 'SIGINT',
  timeout: 1000,
  onSignal,
  onShutdown
};

const authentication = async token => {
  let user;
  try {
    const decodedToken = verify(token, conf.get('jwt:secret'));
    user = await findByTokenId(decodedToken.id);
  } catch (err) {
    if (devMode) {
      // In dev mode, inject a JWT token to be automatically 'logged'
      user = await findByTokenId(conf.get('jwt:dev_token'));
    } else {
      throw new AuthenticationError('Authentication required');
    }
  }
  return { user };
};

const extractTokenFromBearer = bearer =>
  bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : null;

const server = new ApolloServer({
  schema,
  context({ req, connection }) {
    if (connection) return connection.context.user; // For websocket connection.
    let token = req.cookies ? req.cookies.opencti_token : null;
    token = token || extractTokenFromBearer(req.headers.authorization);
    return authentication(token);
  },
  formatError: error => {
    logger.error(error);
    return dissocPath(['extensions', 'exception'], error);
  },
  subscriptions: {
    // https://www.apollographql.com/docs/apollo-server/features/subscriptions.html
    onConnect: connectionParams =>
      authentication(extractTokenFromBearer(connectionParams.authorization))
  }
});

server.applyMiddleware({ app });
const httpServer = http.createServer(app);
server.installSubscriptionHandlers(httpServer);

const PORT = conf.get('app:port');
httpServer.listen(PORT, () => {
  createTerminus(httpServer, options);
  logger.info(
    `🚀 Server ready at http://localhost:${PORT}${server.graphqlPath}`
  );
  logger.info(
    `🚀 Subscriptions ready at ws://localhost:${PORT}${
      server.subscriptionsPath
    }`
  );
});
