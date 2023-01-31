import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { execute, GraphQLError, subscribe } from 'graphql';
import { dissocPath } from 'ramda';
import { SubscriptionServer } from 'subscriptions-transport-ws';
import { createPrometheusExporterPlugin } from '@bmatei/apollo-prometheus-exporter';
import nconf from 'nconf';
import {
  ApolloServerPluginLandingPageDisabled,
  ApolloServerPluginLandingPageGraphQLPlayground,
} from 'apollo-server-core';
import createSchema from './schema';
import conf, { basePath, DEV_MODE } from '../config/conf';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { UnknownError, ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import { checkSystemDependencies } from '../initialization';
import { getSettings } from '../domain/settings';
import { applicationSession } from '../database/session';
import StardogKB from '../datasources/stardog.js';
import Artemis from '../datasources/artemis.js';
import DynamoDB from '../datasources/dynamoDB.js';
import querySelectMap from '../cyio/schema/querySelectMap';
import {
  applyKeycloakContext,
  authDirectiveTransformer,
  getKeycloak,
  permissionDirectiveTransformer,
  roleDirectiveTransformer,
} from '../service/keycloak';

const onHealthCheck = () => checkSystemDependencies().then(() => getSettings());

const buildContext = (user, req, res) => {
  const workId = req.headers['opencti-work-id'];
  const clientId = req.headers['x-cyio-client'];
  const token = req.headers.authorization;
  const context = { clientId, req, res, workId, token };

  // Stardog database
  if (clientId !== undefined) {
    context.dbName = `db${clientId}`;
  }
  // Keycloak configuration
  applyKeycloakContext(context, req);
  // OpenCTI user info
  if (user) {
    context.user = userWithOrigin(req, user);
  }
  return context;
};

// perform the standard keycloak-connect middleware setup on our app
// const { keycloak } = configureKeycloak(app, graphqlPath)  // Same ApolloServer initialization as before, plus the drain plugin.

// TODO: WORKAROUND - remove when self-signed cert issue is resolved
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

const plugins = [
  loggerPlugin,
  httpResponsePlugin,
  process.env.NODE_ENV === 'production'
    ? ApolloServerPluginLandingPageDisabled()
    : ApolloServerPluginLandingPageGraphQLPlayground({
        cdnUrl: conf.get('app:playground_cdn_url'),
        settings: {
          'request.credentials': 'same-origin',
        },
      }),
  {
    requestDidStart: async () => {
      return {
        async executionDidStart() {
          return {
            willResolveField: ({ source, args, context, info }) => {
              context.selectMap = querySelectMap(info);
            },
          };
        },
      };
    },
  },
];

const createApolloServer = async (app, httpServer) => {
  if (process.env.GRAPHQL_METRICS_ENABLED === '1') plugins.push(createPrometheusExporterPlugin({ app }));
  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '10mb';
  const allowedOrigins = nconf.get('app:cors:origins') || [];
  const cdnUrl = conf.get('app:playground_cdn_url');

  let schema = createSchema();
  schema = authDirectiveTransformer(schema, 'kcAuth');
  schema = permissionDirectiveTransformer(schema);
  schema = roleDirectiveTransformer(schema);

  let subscriptionServer;
  plugins.push({
    async serverWillStart() {
      return {
        async drainServer() {
          subscriptionServer.close();
        },
      };
    },
  });

  const server = new ApolloServer({
    schema,
    introspection: true,
    mocks: false,
    preserveResolvers: true,
    mockEntireSchema: false,
    dataSources: () => ({
      Stardog: new StardogKB(),
      Artemis: new Artemis(),
      DynamoDB: new DynamoDB(),
    }),
    // TODO: Remove/disable playground in server
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
      const user = await authenticateUserFromRequest(req);
      return buildContext(user, req, res);
    },
    tracing: false,
    plugins,
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
  });

  subscriptionServer = SubscriptionServer.create(
    {
      schema,
      execute,
      subscribe,
      validationRules: server.requestOptions.validationRules,
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
    {
      server: httpServer,
      path: server.graphqlPath,
    }
  );

  await server.start();

  server.applyMiddleware({
    app,
    cors: {
      origin: allowedOrigins,
      credentials: true,
    },
    bodyParserConfig: {
      limit: requestSizeLimit,
    },
    onHealthCheck,
    path: `${basePath}/graphql`,
  });
};

export default createApolloServer;
