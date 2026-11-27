import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { execute as executeGraphql, type ExecutionArgs, type GraphQLError } from 'graphql';
import { AuthenticationFailure, ClientAbortError, DatabaseError, EngineShardsError, FunctionalError, UnsupportedError } from '../../../src/config/errors';

vi.mock('../../../src/graphql/schema', () => ({
  default: vi.fn(),
}));

const engineFailure = () => DatabaseError('Fail to execute engine pagination', {
  cause: { meta: { statusCode: 400 } },
  root_cause: 'index_not_found_exception',
  query: { index: ['opencti_stix_domain_objects*'] },
});

const schema = makeExecutableSchema({
  typeDefs: `
    type Query {
      databaseFailure: String
      crash: String
      refusal: String
      abort: String
      login: String
      shards: String
      unsupported: String
    }
    type Subscription {
      databaseFailure: String
    }
  `,
  resolvers: {
    Query: {
      databaseFailure: () => {
        throw engineFailure();
      },
      crash: () => {
        throw new Error('connect ECONNREFUSED 10.0.0.12:9200');
      },
      refusal: () => {
        throw FunctionalError('This widget cannot be broken down', { reason: 'too_large' });
      },
      abort: () => {
        throw ClientAbortError('Client disconnected', { cause: { meta: { connection: { url: 'https://user:secret@engine:9200' } } } });
      },
      login: () => {
        throw AuthenticationFailure('Bad login or password', { lock: 'temporary', remaining_minutes: 5 });
      },
      unsupported: () => {
        throw UnsupportedError('Load file from storage fail', { filename: 'import/global/secret.pdf' });
      },
      shards: () => {
        throw EngineShardsError({ shards: { total: 2, failed: 1, failures: [{ index: 'opencti_stix_domain_objects-000001', node: 'node-1' }] } });
      },
    },
  },
});

const REQUEST_ID = 'req-20495';
const logError = vi.fn();

// The protections are read once, when the module is loaded: reload it with the given setting.
const loadGraphql = async (showErrorDetails?: boolean) => {
  vi.resetModules();
  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../src/config/conf')>();
    return {
      ...actual,
      logApp: { ...actual.logApp, error: logError },
      booleanConf: (key: string, defaultValue: boolean) => {
        if (key === 'app:graphql:show_error_details' && showErrorDetails !== undefined) {
          return showErrorDetails;
        }
        return defaultValue;
      },
    };
  });
  return import('../../../src/graphql/graphql');
};

const execute = async (showErrorDetails: boolean | undefined, query: string) => {
  const { default: createApolloServer } = await loadGraphql(showErrorDetails);
  const { apolloServer } = createApolloServer(schema);
  await apolloServer.start();
  const contextValue = { user: { id: 'user' }, res: { locals: { requestId: REQUEST_ID } } };
  const response = await apolloServer.executeOperation({ query }, { contextValue });
  await apolloServer.stop();
  if (response.body.kind !== 'single') {
    throw new Error('Unexpected incremental response');
  }
  return response.body.singleResult;
};

const subscriptionErrors = async (showErrorDetails: boolean | undefined, query: string) => {
  const { default: createApolloServer, createSubscriptionServerOptions } = await loadGraphql(showErrorDetails);
  const { protection } = createApolloServer(schema);
  const options = createSubscriptionServerOptions({ schema, protection, context: async () => ({ user: { id: 'user' } }) });
  const payload = { query };
  const execArgs = await options.onSubscribe({} as never, 'id', payload);
  if (Array.isArray(execArgs)) {
    return options.onError({} as never, 'id', payload, execArgs as GraphQLError[]);
  }
  const result = await executeGraphql(execArgs as ExecutionArgs);
  return options.onNext({} as never, 'id', payload, execArgs as never, result).errors;
};

describe('GraphQL error details', () => {
  afterEach(() => {
    vi.doUnmock('../../../src/config/conf');
    logError.mockReset();
  });

  describe('http', () => {
    it('should keep the error details by default', async () => {
      const result = await execute(undefined, '{ databaseFailure }');
      expect(result.errors?.[0].message).toEqual('Fail to execute engine pagination');
      expect(result.errors?.[0].extensions?.data).toMatchObject({ root_cause: 'index_not_found_exception' });
      expect(result.errors?.[0].extensions?.request_id).toEqual(REQUEST_ID);
    });

    it('should only answer the code, a generic message and the request id of a database error', async () => {
      const result = await execute(false, '{ databaseFailure }');
      expect(result.errors).toEqual([{
        message: 'An unexpected error occurred',
        locations: [{ line: 1, column: 3 }],
        path: ['databaseFailure'],
        name: 'DATABASE_ERROR',
        extensions: { code: 'DATABASE_ERROR', request_id: REQUEST_ID },
      }]);
    });

    it('should hide the message of an error without code', async () => {
      const result = await execute(false, '{ crash }');
      expect(result.errors?.[0].message).toEqual('An unexpected error occurred');
      expect(result.errors?.[0].extensions).toEqual({ code: 'INTERNAL_SERVER_ERROR', request_id: REQUEST_ID });
    });

    it('should keep the message and data of a business error', async () => {
      const result = await execute(false, '{ refusal }');
      expect(result.errors?.[0].message).toEqual('This widget cannot be broken down');
      expect(result.errors?.[0].extensions).toMatchObject({ code: 'FUNCTIONAL_ERROR', data: { reason: 'too_large' }, request_id: REQUEST_ID });
    });

    it('should keep the message and data of an authentication error', async () => {
      const result = await execute(false, '{ login }');
      expect(result.errors?.[0].message).toEqual('Bad login or password');
      expect(result.errors?.[0].extensions).toMatchObject({ code: 'AUTH_FAILURE', data: { lock: 'temporary', remaining_minutes: 5 } });
    });

    it('should hide the shard failures of the engine', async () => {
      const result = await execute(false, '{ shards }');
      expect(result.errors?.[0].message).toEqual('An unexpected error occurred');
      expect(result.errors?.[0].extensions).toEqual({ code: 'DATABASE_ERROR', request_id: REQUEST_ID });
    });

    it('should hide a business error that is not written for the caller', async () => {
      const result = await execute(false, '{ unsupported }');
      expect(result.errors?.[0].message).toEqual('An unexpected error occurred');
      expect(result.errors?.[0].extensions).toEqual({ code: 'UNSUPPORTED_ERROR', request_id: REQUEST_ID });
    });

    it('should remove the cause of a business error', async () => {
      const result = await execute(false, '{ abort }');
      expect(result.errors?.[0].message).toEqual('Client disconnected');
      expect(result.errors?.[0].extensions?.data).not.toHaveProperty('cause');
    });

    it('should keep the validation errors of the query', async () => {
      const result = await execute(false, '{ unknownField }');
      expect(result.errors?.[0].message).toEqual('Cannot query field "unknownField" on type "Query".');
      expect(result.errors?.[0].extensions?.code).toEqual('GRAPHQL_VALIDATION_FAILED');
    });
  });

  describe('websocket', () => {
    it('should keep the error details by default', async () => {
      const errors = await subscriptionErrors(undefined, '{ databaseFailure }');
      const requestId = errors?.[0].extensions?.request_id;
      expect(errors?.[0].message).toEqual('Fail to execute engine pagination');
      expect(errors?.[0].extensions?.data).toMatchObject({ root_cause: 'index_not_found_exception' });
      expect(requestId).toEqual(expect.any(String));
      expect(logError).toHaveBeenCalledWith('[GRAPHQL] WebSocket operation error', expect.objectContaining({ request_id: requestId }));
    });

    it('should hide the details of a database error and log it with the request id', async () => {
      const errors = await subscriptionErrors(false, '{ databaseFailure }');
      const requestId = errors?.[0].extensions?.request_id;
      expect(errors).toEqual([{
        message: 'An unexpected error occurred',
        locations: [{ line: 1, column: 3 }],
        path: ['databaseFailure'],
        extensions: { code: 'DATABASE_ERROR', request_id: expect.any(String) },
      }]);
      expect(logError).toHaveBeenCalledWith('[GRAPHQL] WebSocket operation error', expect.objectContaining({ request_id: requestId }));
    });

    it('should hide the message of an error without code', async () => {
      const errors = await subscriptionErrors(false, '{ crash }');
      expect(errors?.[0].message).toEqual('An unexpected error occurred');
      expect(errors?.[0].extensions?.code).toEqual('INTERNAL_SERVER_ERROR');
    });

    it('should keep the message and data of a business error', async () => {
      const errors = await subscriptionErrors(false, '{ refusal }');
      expect(errors?.[0]).toMatchObject({ message: 'This widget cannot be broken down', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_large' } } });
      expect(logError).not.toHaveBeenCalled();
    });

    it('should keep the validation errors of the query', async () => {
      const errors = await subscriptionErrors(false, '{ unknownField }');
      expect(errors?.[0].message).toEqual('Cannot query field "unknownField" on type "Query".');
      expect(errors?.[0].extensions?.request_id).toEqual(expect.any(String));
      expect(logError).not.toHaveBeenCalled();
    });

    it('should close the socket with a generic reason on an internal error', async () => {
      const { default: createApolloServer, createSubscriptionServerOptions } = await loadGraphql(false);
      const { protection } = createApolloServer(schema);
      const options = createSubscriptionServerOptions({ schema, protection, context: async () => ({}) });
      expect(options.isProd).toBe(true);
    });

    it('should leave the close reason to the environment by default', async () => {
      const { default: createApolloServer, createSubscriptionServerOptions } = await loadGraphql(undefined);
      const { protection } = createApolloServer(schema);
      const options = createSubscriptionServerOptions({ schema, protection, context: async () => ({}) });
      expect(options).not.toHaveProperty('isProd');
    });
  });
});
