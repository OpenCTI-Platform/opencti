import { ApolloServer } from 'apollo-server-express';
import { formatError as apolloFormatError } from 'apollo-errors';
import { GraphQLError } from 'graphql';
import { dissocPath } from 'ramda';
import createSchema from './schema';
import conf, {basePath, DEV_MODE} from '../config/conf';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { UnknownError, ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import {createPrometheusExporterPlugin} from "@bmatei/apollo-prometheus-exporter";
import {checkSystemDependencies} from "../initialization";
import {getSettings} from "../domain/settings";
import { applicationSession } from '../database/session';
// Stardog
import StardogKB from '../datasources/stardog.js';

// import cors from "cors";

// Keycloak
// import configureKeycloak from './keycloak-config.js';
// import { KeycloakContext, KeycloakTypeDefs, KeycloakSchemaDirectives } from 'keycloak-connect-graphql';

// mocks
import mockList from './mocks.js' ;
import nconf from "nconf";
import querySelectMap from "../cyio/schema/querySelectMap";

const onHealthCheck = () => checkSystemDependencies().then(() => getSettings());

const buildContext = (user, req, res) => {
  const workId = req.headers['opencti-work-id'];
  // const kauth = new KeycloakContext({ req }, keycloak);
  const clientId = req.headers['x-cyio-client'];
  let dbName;
  if(clientId !== undefined){
    dbName = `db${clientId}`;
  }

  if (user) {
    return { req, res, user: userWithOrigin(req, user), workId, dbName, };
  }
  return { req, res, user, workId, dbName, };
};

// perform the standard keycloak-connect middleware setup on our app
// const { keycloak } = configureKeycloak(app, graphqlPath)  // Same ApolloServer initialization as before, plus the drain plugin.

// check to see if mocks are disbled
let mocks;
if (process.env.MOCKS === '0') {
  mocks = false;
}
else {
  mocks = mockList;
}

let plugins = [
  loggerPlugin,
  httpResponsePlugin,
  {
     requestDidStart: () => {
      return {
        executionDidStart: () => {
          return {
            willResolveField: ({source, args, context, info}) =>{
              context.selectMap = querySelectMap(info)
            }
          }
        }
      }
    }
  }
];

const createApolloServer = (app) => {
  if(process.env.GRAPHQL_METRICS_ENABLED === '1') plugins.push(createPrometheusExporterPlugin({app}))
  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '10mb';

  const cdnUrl = conf.get('app:playground_cdn_url');
  const server = new ApolloServer({
    schema: createSchema(),
    introspection: true,
    mocks,
    mockEntireSchema: false,
    dataSources: () => ({ 
      Stardog: new StardogKB( )
    }),
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
    tracing: true,
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
  server.applyMiddleware({
    app,
      cors: true,
      bodyParserConfig: {
      limit: requestSizeLimit,
    },
    onHealthCheck,
      path: `${basePath}/graphql`,
  })
  return server;
};

export default createApolloServer;
