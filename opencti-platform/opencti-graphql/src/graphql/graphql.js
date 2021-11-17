import { ApolloServer, UserInputError } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { dissocPath } from 'ramda';
import ConstraintDirectiveError from 'graphql-constraint-directive/lib/error';
import createSchema from './schema';
import conf, { DEV_MODE } from '../config/conf';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import { applicationSession } from '../database/session';

const buildContext = (user, req, res) => {
  const workId = req.headers['opencti-work-id'];
  if (user) {
    return { req, res, user: userWithOrigin(req, user), workId };
  }
  return { req, res, user, workId };
};
const createApolloServer = () => {
  const cdnUrl = conf.get('app:playground_cdn_url');
  return new ApolloServer({
    schema: createSchema(),
    introspection: true,
    playground: {
      cdnUrl,
      settings: {
        'request.credentials': 'same-origin',
      },
    },
    async context({ req, res, connection }) {
      // For websocket connection.
      if (connection) {
        return { req, res, user: connection.context.user };
      }
      // Get user session from request
      const user = await authenticateUserFromRequest(req, res);
      // Return the context
      return buildContext(user, req, res);
    },
    tracing: DEV_MODE,
    plugins: [loggerPlugin, httpResponsePlugin],
    formatError: (error) => {
      let e = apolloFormatError(error);
      if (e instanceof UserInputError) {
        if (e.originalError instanceof ConstraintDirectiveError) {
          const { originalError } = e.originalError;
          const { fieldName } = originalError;
          const ConstraintError = ValidationError(fieldName, originalError);
          e = apolloFormatError(ConstraintError);
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
          const { session } = applicationSession();
          session(webSocket.upgradeReq, {}, () => {
            if (webSocket.upgradeReq.session) {
              resolve(webSocket.upgradeReq.session);
            }
            return false;
          });
        });
        // We have a good session. attach to context
        if (wsSession.user) {
          return { user: wsSession.user };
        }
        // throwing error rejects the connection
        return { user: null };
      },
    },
  });
};

export default createApolloServer;
