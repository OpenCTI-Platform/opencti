import { ApolloServer } from '@apollo/server';
import { ApolloArmor } from '@escape.tech/graphql-armor';
import { dissocPath } from 'ramda';
import { ApolloServerPluginLandingPageDisabled } from '@apollo/server/plugin/disabled';
import { ApolloServerPluginLandingPageProductionDefault } from '@apollo/server/plugin/landingPage/default';
import { ApolloServerErrorCode } from '@apollo/server/errors';
import { createValidation as createAliasBatch } from 'graphql-no-alias';
import { constraintDirectiveDocumentation } from 'graphql-constraint-directive';
import { GraphQLError } from 'graphql/error';
import { createApollo4QueryValidationPlugin } from 'graphql-constraint-directive/apollo4';
import createSchema from './schema';
import conf, { DEV_MODE, ENABLED_TRACING, GRAPHQL_ARMOR_DISABLED, PLAYGROUND_ENABLED, PLAYGROUND_INTROSPECTION_DISABLED } from '../config/conf';
import { ForbiddenAccess, ValidationError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import telemetryPlugin from './telemetryPlugin';
import httpResponsePlugin from './httpResponsePlugin';

const createApolloServer = () => {
  let schema = createSchema();
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
  schema = constraintDirectiveDocumentation()(schema);
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
  // In production mode, we use static from the server
  if (PLAYGROUND_ENABLED) {
    apolloPlugins.push(ApolloServerPluginLandingPageProductionDefault({ embed: true }));
  } else {
    apolloPlugins.push(ApolloServerPluginLandingPageDisabled());
  }

  // Schema introspection must be accessible only for auth users.
  const secureIntrospectionPlugin = {
    requestDidStart: (requestContext) => {
      const { contextValue, request } = requestContext;
      // Is schema have introspection request
      if (['__schema'].some((pattern) => request.query.includes(pattern))) {
        // If introspection explicitly disabled or user is not authenticated
        if (!PLAYGROUND_ENABLED || PLAYGROUND_INTROSPECTION_DISABLED || !contextValue?.user) {
          throw ForbiddenAccess('GraphQL introspection not authorized!');
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
    csrfPrevention: false, // CSRF is handled by helmet
    tracing: DEV_MODE,
    plugins: apolloPlugins,
    /* cors: {
      origin: 'http://localhost:4000',
      credentials: true,
    }, */
    formatError: (formattedError) => {
      let error = formattedError;
      // For constraint lib user input failure, replace the lib error by the opencti validation one.
      if (formattedError.extensions?.code === ApolloServerErrorCode.BAD_USER_INPUT) {
        error = ValidationError(formattedError.message, formattedError.extensions?.field, formattedError.extensions);
      }
      // To maintain compatibility with client in version 3.
      const enrichedError = { ...error, name: error.extensions?.code ?? error.name };
      // Remove the exception stack in production.
      return DEV_MODE ? enrichedError : dissocPath(['extensions', 'exception'], enrichedError);
    },
  });
  return { schema, apolloServer };
};

export default createApolloServer;
