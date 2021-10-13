import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import { dissocPath } from 'ramda';
import createSchema from './schema';
import conf, { DEV_MODE } from '../config/conf';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { UnknownError, ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import { applicationSession } from '../database/session';
// Keycloak
import { expandToken } from '../service/keycloak';
// import configureKeycloak from './keycloak-config.js';
// import cors from "cors";
// import { KeycloakContext, KeycloakTypeDefs, KeycloakSchemaDirectives } from 'keycloak-connect-graphql';

// mocks
import mocks from './mocks.js' ;

const buildContext = (user, req, res) => {
  // const kauth = new KeycloakContext({ req }, keycloak);
  // const dbName = req.headers['x-cyio-client'];
  const workId = req.headers['opencti-work-id'];
  if (user) {
    return { req, res, user: userWithOrigin(req, user), workId };
  }
  return { req, res, user, workId };
};

// perform the standard keycloak-connect middleware setup on our app
// const { keycloak } = configureKeycloak(app, graphqlPath)  // Same ApolloServer initialization as before, plus the drain plugin.

const createApolloServer = () => {
  const cdnUrl = conf.get('app:playground_cdn_url');
  return new ApolloServer({
    schema: createSchema(),
    introspection: true,
    mocks,
    mockEntireSchema: false,
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
      const user = await authenticateUserFromRequest(req);
      if (user === undefined) return buildContext(user, req, res);
      const expandedInfo = expandToken(req.headers);
      const combined = { ...user, ...expandedInfo };
      // Get user session from request
      // Return the context
      return buildContext(combined, req, res);
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
