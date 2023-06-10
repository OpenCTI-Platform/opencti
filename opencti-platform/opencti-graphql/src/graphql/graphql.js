import { ApolloServer, UserInputError } from 'apollo-server-express';
import { ApolloServerPluginLandingPageGraphQLPlayground, ApolloServerPluginLandingPageDisabled } from 'apollo-server-core';
import { formatError as apolloFormatError } from 'apollo-errors';
import { ApolloArmor } from '@escape.tech/graphql-armor';
import { dissocPath } from 'ramda';
import ConstraintDirectiveError from 'graphql-constraint-directive/lib/error';
import createSchema from './schema';
import {
  basePath,
  DEV_MODE,
  PLAYGROUND_INTROSPECTION_DISABLED,
  ENABLED_TRACING,
  PLAYGROUND_ENABLED, GRAPHQL_ARMOR_ENABLED
} from '../config/conf';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { ForbiddenAccess, ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import telemetryPlugin from './telemetryPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import { executionContext } from '../utils/access';

const createApolloServer = () => {
  const schema = createSchema();
  const apolloPlugins = [loggerPlugin, httpResponsePlugin];
  const apolloValidationRules = [];
  if (GRAPHQL_ARMOR_ENABLED) {
    const armor = new ApolloArmor({
      costLimit: { // Blocking too expensive requests (DoS attack attempts).
        maxCost: 10000
      },
      blockFieldSuggestion: { // It will prevent suggesting fields in case of an erroneous request.
        enabled: true,
      },
      maxAliases: { // Limit the number of aliases in a document.
        n: 15,
      },
      maxDirectives: { // Limit the number of directives in a document.
        n: 50,
      },
      maxDepth: { // maxDepth: Limit the depth of a document.
        n: 20,
      },
      maxTokens: { // Limit the number of GraphQL tokens in a document.
        n: 2000,
      }
    });
    const protection = armor.protect();
    apolloPlugins.push(...protection.plugins);
    apolloValidationRules.push(...protection.validationRules);
  }
  // In production mode, we use static from the server
  const playgroundOptions = DEV_MODE ? { settings: { 'request.credentials': 'include' } } : {
    cdnUrl: `${basePath}/static`,
    title: 'OpenCTI Playground',
    faviconUrl: `${basePath}/static/@apollographql/graphql-playground-react@1.7.42/build/static/favicon.png`,
    settings: { 'request.credentials': 'include' }
  };
  const playgroundPlugin = ApolloServerPluginLandingPageGraphQLPlayground(playgroundOptions);
  apolloPlugins.push(PLAYGROUND_ENABLED ? playgroundPlugin : ApolloServerPluginLandingPageDisabled());
  // Schema introspection must be accessible only for auth users.
  const introspectionPatterns = ['__schema {', '__schema(', '__type {', '__type('];
  const secureIntrospectionPlugin = {
    requestDidStart: ({ request, context }) => {
      // Is schema introspection request
      if (introspectionPatterns.some((pattern) => request.query.includes(pattern))) {
        // If introspection explicitly disabled or user is not authenticated
        if (!PLAYGROUND_ENABLED || PLAYGROUND_INTROSPECTION_DISABLED || !context.user) {
          throw ForbiddenAccess({ reason: 'GraphQL introspection not authorized!' });
        }
      }
    },
  };
  apolloPlugins.push(secureIntrospectionPlugin);
  if (ENABLED_TRACING) {
    apolloPlugins.push(telemetryPlugin);
  }
  const apolloServer = new ApolloServer({
    schema,
    introspection: true, // Will be disabled by plugin if needed
    persistedQueries: false,
    validationRules: apolloValidationRules,
    async context({ req, res }) {
      const executeContext = executionContext('api');
      executeContext.req = req;
      executeContext.res = res;
      executeContext.workId = req.headers['opencti-work-id'];
      const user = await authenticateUserFromRequest(executeContext, req, res);
      if (user) {
        executeContext.user = userWithOrigin(req, user);
      }
      return executeContext;
    },
    tracing: DEV_MODE,
    plugins: apolloPlugins,
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
