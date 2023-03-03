import { ApolloServer, UserInputError } from 'apollo-server-express';
import { ApolloServerPluginLandingPageGraphQLPlayground, ApolloServerPluginLandingPageDisabled } from 'apollo-server-core';
import { formatError as apolloFormatError } from 'apollo-errors';
import { dissocPath } from 'ramda';
import ConstraintDirectiveError from 'graphql-constraint-directive/lib/error';
import createSchema from './schema';
import {
  basePath,
  DEV_MODE,
  PLAYGROUND_INTROSPECTION_DISABLED,
  ENABLED_TRACING,
  PLAYGROUND_ENABLED
} from '../config/conf';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import telemetryPlugin from './telemetryPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import { executionContext } from '../utils/access';

const createApolloServer = () => {
  const schema = createSchema();
  const appolloPlugins = [loggerPlugin, httpResponsePlugin];
  // In production mode, we use static from the server
  const playgroundOptions = DEV_MODE ? {} : {
    cdnUrl: `${basePath}/static`,
    title: 'OpenCTI Playground',
    faviconUrl: `${basePath}/static/@apollographql/graphql-playground-react@1.7.42/build/static/favicon.png`
  };
  const playgroundPlugin = ApolloServerPluginLandingPageGraphQLPlayground(playgroundOptions);
  appolloPlugins.push(PLAYGROUND_ENABLED ? playgroundPlugin : ApolloServerPluginLandingPageDisabled());
  // Schema introspection must be accessible only for auth users.
  const secureIntrospectionPlugin = {
    requestDidStart: ({ request, context }) => {
      // Is schema introspection request
      if ((request.query.includes('__schema') || request.query.includes('__type'))) {
        // If introspection explicitly disabled or user is not authenticated
        if (!PLAYGROUND_ENABLED || PLAYGROUND_INTROSPECTION_DISABLED || !context.user) {
          throw ValidationError('GraphQL introspection not authorized!');
        }
      }
    },
  };
  appolloPlugins.push(secureIntrospectionPlugin);
  if (ENABLED_TRACING) {
    appolloPlugins.push(telemetryPlugin);
  }
  const apolloServer = new ApolloServer({
    schema,
    introspection: true, // Will be disabled by plugin if needed
    persistedQueries: false,
    async context({ req, res, connection }) {
      const executeContext = executionContext('api');
      executeContext.req = req;
      executeContext.res = res;
      executeContext.workId = req.headers['opencti-work-id'];
      if (connection && connection.context.user) {
        executeContext.user = userWithOrigin(req, connection.context.user);
      } else {
        const user = await authenticateUserFromRequest(executeContext, req, res);
        if (user) {
          executeContext.user = userWithOrigin(req, user);
        }
      }
      return executeContext;
    },
    tracing: DEV_MODE,
    plugins: appolloPlugins,
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
  });
  return { schema, apolloServer };
};

export default createApolloServer;
