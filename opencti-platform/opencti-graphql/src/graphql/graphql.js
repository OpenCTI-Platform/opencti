import { ApolloServer } from '@apollo/server';
import { ApolloArmor } from '@escape.tech/graphql-armor';
import { dissocPath } from 'ramda';
import { createValidation as createAliasBatch } from 'graphql-no-alias';
import { BREAK, getOperationAST, GraphQLError, parse, specifiedRules, validate, visit } from 'graphql';
import { createApollo4QueryValidationPlugin } from 'graphql-constraint-directive/apollo4';
import createSchema from './schema';
import conf, {
  booleanConf,
  DEV_MODE,
  ENABLED_METRICS,
  ENABLED_TRACING,
  GRAPHQL_ARMOR_DISABLED,
  GRAPHQL_SECURE_BY_DEFAULT,
  logApp,
  PLAYGROUND_ENABLED,
  PLAYGROUND_INTROSPECTION_DISABLED,
} from '../config/conf';
import { AuthRequired, BadUserInputError, muteError, ResourceNotFoundError } from '../config/errors';
import loggerPlugin from './loggerPlugin';
import telemetryPlugin from './telemetryPlugin';
import tracingPlugin from './tracingPlugin';
import httpResponsePlugin from './httpResponsePlugin';
import { pushAll } from '../utils/arrayUtil';

// graphql-js appends suggestions to validation and input errors: fields, arguments, types, enum values...
// Removing them prevents the enumeration of the schema when introspection is disabled.
// Linear scan instead of a regex: the message can echo a user string, that a regex would scan in quadratic time.
const SUGGESTION_START = ' Did you mean ';
export const removeSuggestions = (message) => {
  let result = '';
  let cursor = 0;
  let start = message.indexOf(SUGGESTION_START);
  while (start !== -1) {
    const end = message.indexOf('?', start + SUGGESTION_START.length);
    if (end === -1) {
      break; // No closing "?" remains, so no later suggestion can be complete
    }
    result += message.slice(cursor, start);
    cursor = end + 1;
    start = message.indexOf(SUGGESTION_START, cursor);
  }
  return result + message.slice(cursor);
};

const INTROSPECTION_FIELDS = ['__schema', '__type'];
const isIntrospectionDocument = (document) => {
  let isIntrospection = false;
  visit(document, {
    Field: (node) => {
      if (INTROSPECTION_FIELDS.includes(node.name.value)) {
        isIntrospection = true;
        return BREAK;
      }
      return undefined;
    },
  });
  return isIntrospection;
};

const checkIntrospection = (document, user) => {
  if (isIntrospectionDocument(document)) {
    const isIntrospectionDisabled = !PLAYGROUND_ENABLED || PLAYGROUND_INTROSPECTION_DISABLED;
    if (isIntrospectionDisabled) {
      throw muteError(ResourceNotFoundError('GraphQL introspection not authorized!'));
    }
    // is user authenticated
    if (!user) {
      throw AuthRequired();
    }
  }
};

// Validation shared by the HTTP and the WebSocket endpoints
const createGraphqlProtection = () => {
  // Protect batch graphql through alias usage
  const batchPermissions = {
    Query: {
      '*': conf.get('app:graphql:batching_protection:query_default') ?? 2, // default value for all queries
      subTypes: conf.get('app:graphql:batching_protection:query_subtypes') ?? 4, // subTypes are used multiple times for schema fetching
    },
    Mutation: {
      '*': conf.get('app:graphql:batching_protection:mutation_default') ?? 1, // default value for all mutations
      token: 1, // force default value for login mutation
    },
  };
  const { validation: batchValidationRule } = createAliasBatch({ permissions: batchPermissions });
  const validationRules = [batchValidationRule];
  // optional graphql-armor configuration
  const blockFieldSuggestion = !GRAPHQL_ARMOR_DISABLED && booleanConf('app:graphql:armor_protection:block_field_suggestion', true);
  // Limit the number of GraphQL tokens in a document, in the parser to reject it as a parse failure
  const parseOptions = GRAPHQL_ARMOR_DISABLED ? {} : { maxTokens: conf.get('app:graphql:armor_protection:max_tokens') ?? 100000 };
  if (!GRAPHQL_ARMOR_DISABLED) {
    const armor = new ApolloArmor({
      blockFieldSuggestion: { // Handled by formatGraphqlErrorMessage, armor misses the enum value suggestions
        enabled: false,
      },
      costLimit: { // Limit the complexity of a GraphQL document.
        maxCost: conf.get('app:graphql:armor_protection:cost_limit') ?? 50000000,
      },
      maxDepth: { // maxDepth: Limit the depth of a document.
        n: conf.get('app:graphql:armor_protection:max_depth') ?? 20,
      },
      maxDirectives: { // Limit the number of directives in a document.
        n: conf.get('app:graphql:armor_protection:max_directives') ?? 20,
      },
      maxTokens: { // Handled by parseOptions, armor checks it in a hook that ends as an internal error
        enabled: false,
      },
      maxAliases: { // Limit the number of aliases in a document.
        enabled: false, // Handled by graphql-no-alias
      },
    });
    pushAll(validationRules, armor.protect().validationRules);
  }
  const formatGraphqlErrorMessage = (message) => (blockFieldSuggestion ? removeSuggestions(message) : message);
  return { validationRules, parseOptions, formatGraphqlErrorMessage };
};

// graphql-ws validates the operation before building its context: authenticate, parse and validate in onSubscribe instead.
// The context function is the one of the HTTP server, it throws when the user is not authenticated.
export const createSubscriptionServerOptions = ({ schema, protection, context }) => {
  const { validationRules, parseOptions, formatGraphqlErrorMessage } = protection;
  const formatErrors = (errors) => errors.map((error) => ({ ...error.toJSON(), message: formatGraphqlErrorMessage(error.message) }));
  return {
    schema,
    onSubscribe: async (ctx, _id, payload) => {
      const contextValue = await context(ctx);
      let document;
      try {
        document = parse(payload.query, parseOptions);
      } catch (error) {
        return [error];
      }
      const validationErrors = validate(schema, document, [...specifiedRules, ...validationRules]);
      if (validationErrors.length > 0) {
        return validationErrors;
      }
      try {
        checkIntrospection(document, contextValue.user);
      } catch (error) {
        return [error];
      }
      // Queries and mutations over WebSocket bypass the HTTP rate limiter and the input constraints, the UI only subscribes
      const operation = getOperationAST(document, payload.operationName);
      if (GRAPHQL_SECURE_BY_DEFAULT && operation && operation.operation !== 'subscription') {
        return [muteError(BadUserInputError('Only subscriptions are allowed over WebSocket'))];
      }
      return { schema, document, operationName: payload.operationName, variableValues: payload.variables, contextValue };
    },
    onError: (_ctx, _id, _payload, errors) => formatErrors(errors),
    onNext: (_ctx, _id, _payload, _args, result) => (result.errors ? { ...result, errors: formatErrors(result.errors) } : result),
  };
};

const createApolloServer = (schema = createSchema()) => {
  const protection = createGraphqlProtection();
  // graphql-constraint-directive plugin configuration
  const formats = {
    'not-blank': (value) => {
      if (value.length > 0 && value.trim() === '') {
        throw new GraphQLError('Value cannot have only whitespace(s)');
      }
      return true;
    },
  };
  const constraintPlugin = createApollo4QueryValidationPlugin({ formats });
  // An unknown operationName must be rejected before graphql-constraint-directive, which crashes on it.
  // Keep this hook synchronous and first: Apollo calls the hooks in order, a synchronous throw stops the next ones.
  const operationResolutionPlugin = {
    requestDidStart: () => ({
      didResolveOperation: ({ operation, request }) => {
        if (!operation && request.operationName) {
          throw muteError(BadUserInputError('Unknown operation name'));
        }
      },
    }),
  };
  const apolloPlugins = [operationResolutionPlugin, loggerPlugin, httpResponsePlugin, constraintPlugin];

  const secureIntrospectionPlugin = {
    requestDidStart: () => {
      return {
        didResolveOperation: ({ contextValue, document }) => {
          checkIntrospection(document, contextValue?.user);
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
    validationRules: protection.validationRules,
    parseOptions: protection.parseOptions,
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
      const enrichedError = { ...error, message: protection.formatGraphqlErrorMessage(error.message), name: error.extensions?.code ?? error.name };
      // Remove the exception stack in production.
      return DEV_MODE ? enrichedError : dissocPath(['extensions', 'exception'], enrichedError);
    },
  });
  return { schema, apolloServer, protection };
};

export default createApolloServer;
