import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import { dissocPath } from 'ramda';
import createSchema from './schema';
import { DEV_MODE } from '../config/conf';
import { authenticateUser } from '../domain/user';
import { UnknownError, ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import { sessionMiddleware } from '../app';

const buildContext = (user, req, res) => {
  const workId = req.headers['opencti-work-id'];
  if (user) {
    const origin = {
      ip: req.ip,
      user_id: user.id,
      applicant_id: req.headers['opencti-applicant-id'],
      call_retry_number: req.headers['opencti-retry-number'],
    };
    return { req, res, user: { ...user, origin }, workId };
  }
  return { req, res, user, workId };
};
const createApolloServer = () => {
  return new ApolloServer({
    schema: createSchema(),
    introspection: true,
    playground: {
      settings: {
        'request.credentials': 'same-origin',
      },
    },
    async context({ req, res, connection }) {
      // For websocket connection.
      if (connection) {
        return { req, res, user: connection.context.user };
      }
      // If session already open
      const user = await authenticateUser(req);
      // Return the context
      return buildContext(user, req, res);
    },
    tracing: DEV_MODE,
    plugins: [loggerPlugin, httpResponsePlugin],
    formatError: (error) => {
      let e = apolloFormatError(error);
      if (e instanceof GraphQLError) {
        const errorCode = e.extensions.exception.code;
        if (errorCode === 'ERR_GRAPHQL_CONSTRAINT_VALIDATION') {
          const { fieldName } = e.extensions.exception;
          const ConstraintError = ValidationError(fieldName);
          e = apolloFormatError(ConstraintError);
        } else {
          e = apolloFormatError(UnknownError(errorCode));
        }
      }
      // Remove the exception stack in production.
      return DEV_MODE ? e : dissocPath(['extensions', 'exception'], e);
    },
    subscriptions: {
      keepAlive: 10000,
      // https://www.apollographql.com/docs/apollo-server/features/subscriptions.html
      onConnect: async (connectionParams, webSocket) => {
        const wsSession = await new Promise((resolve) => {
          // use same session parser as normal gql queries
          sessionMiddleware()(webSocket.upgradeReq, {}, () => {
            if (webSocket.upgradeReq.session) {
              resolve(webSocket.upgradeReq.session);
            }
            return false;
          });
        });
        // We have a good session. attach to context
        if (wsSession.user_id) {
          return { user: wsSession.user };
        }
        // throwing error rejects the connection
        return { user: null };
      },
    },
  });
};

export default createApolloServer;
