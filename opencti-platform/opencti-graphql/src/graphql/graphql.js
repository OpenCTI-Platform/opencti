import { ApolloServer } from '@apollo/server';
import { ApolloServerErrorCode } from '@apollo/server/errors';
import { ApolloArmor } from '@escape.tech/graphql-armor';
import { dissoc, dissocPath, pick } from 'ramda';
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
import {
  ACCESS_REQUIRED,
  AUTH_ERRORS,
  AuthRequired,
  BadUserInputError,
  CLIENT_INPUT_ERRORS,
  DRAFT_LOCKED_ERROR,
  FUNCTIONAL_ERRORS,
  LTS_REQUIRED_ACTIVATION,
  muteError,
  RESOURCE_NOT_FOUND_ERROR,
  ResourceNotFoundError,
  WORK_NOT_ALIVE_ERROR,
} from '../config/errors';
import { getRequestId, resolveRequestId, SERVER_ERROR_MESSAGE } from '../http/httpUtils';
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

const SCHEMA_FIELD = '__schema';
const TYPE_FIELD = '__type';
const getIntrospectionFields = (document) => {
  const fields = new Set();
  visit(document, {
    Field: (node) => {
      const { value } = node.name;
      if (value === SCHEMA_FIELD || value === TYPE_FIELD) {
        fields.add(value);
        // __schema decides alone, no need to look further
        return value === SCHEMA_FIELD ? BREAK : undefined;
      }
      return undefined;
    },
  });
  return fields;
};

const checkIntrospection = (document, user) => {
  const fields = getIntrospectionFields(document);
  if (fields.size === 0) {
    return;
  }
  // Without the secure defaults, any authenticated user can read a type with __type:
  // other products of the suite (OpenAEV, XTM One) rely on it.
  const isTypeAllowed = !fields.has(SCHEMA_FIELD) && !GRAPHQL_SECURE_BY_DEFAULT;
  const isIntrospectionDisabled = !PLAYGROUND_ENABLED || PLAYGROUND_INTROSPECTION_DISABLED;
  if (isIntrospectionDisabled && !isTypeAllowed) {
    throw muteError(ResourceNotFoundError('GraphQL introspection not authorized!'));
  }
  // is user authenticated
  if (!user) {
    throw AuthRequired();
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
  const hideErrorDetails = !booleanConf('app:graphql:show_error_details', true);
  return { validationRules, parseOptions, formatGraphqlErrorMessage, hideErrorDetails };
};

// An explicit list, not the error category: some BUSINESS errors carry internals (shard failures, storage paths).
const CLIENT_ERROR_CODES = new Set([
  ...AUTH_ERRORS,
  LTS_REQUIRED_ACTIVATION,
  RESOURCE_NOT_FOUND_ERROR,
  ...FUNCTIONAL_ERRORS,
  ...CLIENT_INPUT_ERRORS,
  DRAFT_LOCKED_ERROR,
  WORK_NOT_ALIVE_ERROR,
  ACCESS_REQUIRED,
  ApolloServerErrorCode.GRAPHQL_PARSE_FAILED,
  ApolloServerErrorCode.GRAPHQL_VALIDATION_FAILED,
  ApolloServerErrorCode.BAD_USER_INPUT,
  ApolloServerErrorCode.BAD_REQUEST,
  ApolloServerErrorCode.OPERATION_RESOLUTION_FAILURE,
  ApolloServerErrorCode.PERSISTED_QUERY_NOT_FOUND,
  ApolloServerErrorCode.PERSISTED_QUERY_NOT_SUPPORTED,
]);

export const isClientGraphqlError = (formattedError, error) => {
  const code = formattedError.extensions?.code;
  if (!code) {
    // Parse and validation errors of graphql-js over WebSocket: they carry no code and wrap no error
    return error instanceof GraphQLError && !error.originalError;
  }
  return CLIENT_ERROR_CODES.has(code);
};

export const hideGraphqlErrorDetails = (formattedError, error) => {
  const { message, extensions = {} } = formattedError;
  const position = pick(['locations', 'path', 'name'], formattedError);
  if (!isClientGraphqlError(formattedError, error)) {
    const code = extensions.code ?? ApolloServerErrorCode.INTERNAL_SERVER_ERROR;
    return { ...position, message: SERVER_ERROR_MESSAGE, extensions: { code } };
  }
  const clientExtensions = pick(['code'], extensions);
  if (extensions.data) {
    clientExtensions.data = dissoc('cause', extensions.data);
  }
  return { ...position, message, extensions: clientExtensions };
};

// graphql-ws validates the operation before building its context: authenticate, parse and validate in onSubscribe instead.
// The context function is the one of the HTTP server, it throws when the user is not authenticated.
export const createSubscriptionServerOptions = ({ schema, protection, context }) => {
  const { validationRules, parseOptions, formatGraphqlErrorMessage, hideErrorDetails } = protection;
  const formatError = (error, requestId) => {
    const formattedError = { ...error.toJSON(), message: formatGraphqlErrorMessage(error.message) };
    const isClientError = isClientGraphqlError(formattedError, error);
    if (!isClientError) {
      // No Apollo logger plugin over WebSocket: the error is logged here, with the id given to the client.
      logApp.error('[GRAPHQL] WebSocket operation error', { cause: error, request_id: requestId });
    }
    const resultError = hideErrorDetails ? hideGraphqlErrorDetails(formattedError, error) : formattedError;
    return { ...resultError, extensions: { ...resultError.extensions, request_id: requestId } };
  };
  const formatErrors = (errors) => {
    const requestId = resolveRequestId(undefined);
    return errors.map((error) => formatError(error, requestId));
  };
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
    // Outside production, graphql-ws closes the socket with the message of an internal error as reason
    ...(hideErrorDetails ? { isProd: true } : {}),
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
    requestDidStart: () => ({
      willSendResponse: ({ response, contextValue }) => {
        const requestId = contextValue?.res ? getRequestId(contextValue.res) : undefined;
        if (!requestId || response.body.kind !== 'single' || !response.body.singleResult.errors) {
          return;
        }
        response.body.singleResult.errors = response.body.singleResult.errors.map((error) => ({
          ...error,
          extensions: { ...error.extensions, request_id: requestId },
        }));
      },
    }),
  });

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
    formatError: (formattedError, error) => {
      // To maintain compatibility with client in version 3.
      const enrichedError = {
        ...formattedError,
        message: protection.formatGraphqlErrorMessage(formattedError.message),
        name: formattedError.extensions?.code ?? formattedError.name,
      };
      if (protection.hideErrorDetails) {
        return hideGraphqlErrorDetails(enrichedError, error);
      }
      // Remove the exception stack in production.
      return DEV_MODE ? enrichedError : dissocPath(['extensions', 'exception'], enrichedError);
    },
  });
  return { schema, apolloServer, protection };
};

export default createApolloServer;
