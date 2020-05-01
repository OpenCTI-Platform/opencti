import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import { dissocPath, pathOr } from 'ramda';
import cookie from 'cookie';
import createSchema from './schema';
import nconf, { DEV_MODE, logger, OPENCTI_TOKEN } from '../config/conf';
import { authentication } from '../domain/user';
import { buildValidationError, LEVEL_ERROR, LEVEL_WARNING, Unknown } from '../config/errors';
import PerformancePlugin from './performancePlugin';

const extractTokenFromBearer = (bearer) => (bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : null);
const plugins = [];
const perfLogger = nconf.get('app:performance_logger') || false;
if (perfLogger) plugins.push(PerformancePlugin);
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
      if (connection) return { user: connection.context.user }; // For websocket connection.
      let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : null;
      token = token || extractTokenFromBearer(req.headers.authorization);
      const auth = await authentication(token);
      return { res, user: auth };
    },
    tracing: DEV_MODE,
    plugins,
    formatError: (error) => {
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
      const errorLevel = pathOr(LEVEL_ERROR, ['data', 'level'], e);
      if (errorLevel === LEVEL_WARNING) {
        logger.warn('[OPENCTI] Technical error', { error }); // Log the complete error.
      } else {
        logger.error('[OPENCTI] Technical error', { error }); // Log the complete error.
      }
      // Remove the exception stack in production.
      return DEV_MODE ? e : dissocPath(['extensions', 'exception'], e);
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
      },
    },
  });
};

export default createApolloServer;
