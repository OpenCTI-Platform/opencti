import { ApolloServer } from '@apollo/server';
import { ApolloArmor } from '@escape.tech/graphql-armor';
import { dissocPath } from 'ramda';
import { createValidation as createAliasBatch } from 'graphql-no-alias';
import { GraphQLError } from 'graphql/error';
import { createApollo4QueryValidationPlugin } from 'graphql-constraint-directive/apollo4';
import createSchema from './schema';
import conf, { DEV_MODE, ENABLED_METRICS, ENABLED_TRACING, GRAPHQL_ARMOR_DISABLED, logApp, PLAYGROUND_ENABLED, PLAYGROUND_INTROSPECTION_DISABLED } from '../config/conf';
import { AuthRequired, muteError, ResourceNotFoundError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import telemetryPlugin from './telemetryPlugin';
import tracingPlugin from './tracingPlugin';
import httpResponsePlugin from './httpResponsePlugin';

const createApolloServer = () => {
  const schema = createSchema();
  // graphql-constraint-directive plugin configuration
  const formats = {
    'not-blank': (value) => {
      if (value.length > 0 && value.trim() === '') {
        throw new GraphQLError('Value cannot have only whitespace(s)');
      }
      return true;
    }
  };
  const constraintPlugin = createApollo4QueryValidationPlugin({ formats });
  const apolloPlugins = [loggerPlugin, httpResponsePlugin, constraintPlugin];
  // Protect batch graphql through alias usage
  const batchPermissions = {
    Query: {
      '*': conf.get('app:graphql:batching_protection:query_default') ?? 2, // default value for all queries
      subTypes: conf.get('app:graphql:batching_protection:query_subtypes') ?? 4 // subTypes are used multiple times for schema fetching
    },
    Mutation: {
      '*': conf.get('app:graphql:batching_protection:mutation_default') ?? 1, // default value for all mutations
      token: 1 // force default value for login mutation
    }
  };
  const { validation: batchValidationRule } = createAliasBatch({ permissions: batchPermissions });
  const apolloValidationRules = [batchValidationRule];
  // optional graphql-armor plugin configuration
  // Still disable by default for now as required more testing
  if (!GRAPHQL_ARMOR_DISABLED) {
    const armor = new ApolloArmor({
      blockFieldSuggestion: { // It will prevent suggesting fields in case of an erroneous request.
        enabled: conf.get('app:graphql:armor_protection:block_field_suggestion') ?? true,
      },
      costLimit: { // Limit the complexity of a GraphQL document.
        maxCost: conf.get('app:graphql:armor_protection:cost_limit') ?? 3000000,
      },
      maxDepth: { // maxDepth: Limit the depth of a document.
        n: conf.get('app:graphql:armor_protection:max_depth') ?? 20,
      },
      maxDirectives: { // Limit the number of directives in a document.
        n: conf.get('app:graphql:armor_protection:max_directives') ?? 20,
      },
      maxTokens: { // Limit the number of GraphQL tokens in a document.
        n: conf.get('app:graphql:armor_protection:max_tokens') ?? 100000,
      },
      maxAliases: { // Limit the number of aliases in a document.
        enabled: false, // Handled by graphql-no-alias
      },
    });
    const protection = armor.protect();
    apolloPlugins.push(...protection.plugins);
    apolloValidationRules.push(...protection.validationRules);
  }

  const secureIntrospectionPlugin = {
    requestDidStart: () => {
      return {
        didResolveOperation: ({ contextValue, request }) => {
          const isIntrospectionRequest = request.query?.includes('__schema');
          if (isIntrospectionRequest) {
            const isIntrospectionDisabled = !PLAYGROUND_ENABLED || PLAYGROUND_INTROSPECTION_DISABLED;
            if (isIntrospectionDisabled) {
              throw muteError(ResourceNotFoundError('GraphQL introspection not authorized!'));
            }
            // is user authenticated
            if (!contextValue?.user) {
              throw AuthRequired();
            }
          }
        },
      };
    },
  };
  apolloPlugins.push(secureIntrospectionPlugin);
  if (ENABLED_TRACING) {
    apolloPlugins.push(tracingPlugin);
  }
  if (ENABLED_METRICS) {
    apolloPlugins.push(telemetryPlugin);
  }

  apolloPlugins.push({
    // see https://www.apollographql.com/docs/apollo-server/integrations/plugins-event-reference
    startupDidFail: ({ error }) => {
      logApp.error('[APOLLO] Startup failed', { cause: error });
    },
    contextCreationDidFail: ({ error }) => {
      logApp.warn('[APOLLO] Context creation failed', { cause: error });
    },
    unexpectedErrorProcessingRequest: ({ error }) => {
      logApp.warn('[APOLLO] Unexpected error processing request', { cause: error });
    },
  });

  const apolloServer = new ApolloServer({
    schema,
    introspection: true, // Will be disabled by plugin if needed
    persistedQueries: false,
    validationRules: apolloValidationRules,
    csrfPrevention: false, // CSRF is handled by helmet
    tracing: DEV_MODE,
    plugins: apolloPlugins,
    logger: {
      debug: (msg) => logApp.debug(`[APOLLO] ${msg}`),
      info: (msg) => logApp.info(`[APOLLO] ${msg}`),
      warn: (msg) => logApp.warn(`[APOLLO] ${msg}`),
      error: (msg) => logApp.error(`[APOLLO] ${msg}`),
    },
    formatError: (error) => {
      // To maintain compatibility with client in version 3.
      const enrichedError = { ...error, name: error.extensions?.code ?? error.name };
      // Remove the exception stack in production.
      return DEV_MODE ? enrichedError : dissocPath(['extensions', 'exception'], enrichedError);
    },
  });
  return { schema, apolloServer };
};

export default createApolloServer;
