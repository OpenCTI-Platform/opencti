import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import { dissocPath } from 'ramda';
import cookie from 'cookie';
import createSchema from './schema';
import { DEV_MODE, OPENCTI_TOKEN } from '../config/conf';
import { authentication } from '../domain/user';
import { UnknownError, ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';

export const extractTokenFromBearer = (bearer) =>
  bearer && bearer.length > 10 ? bearer.substring('Bearer '.length) : null;
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
      if (!auth) return { res, user: auth };
      const origin = {
        ip: req.ip,
        user_id: auth.id,
        applicant_id: req.headers['opencti-applicant-id'],
        call_retry_number: req.headers['opencti-retry-number'],
      };
      const workId = req.headers['opencti-work-id'];
      const authMeta = { ...auth, origin };
      return { res, user: authMeta, workId };
    },
    tracing: DEV_MODE,
    plugins: [loggerPlugin],
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
