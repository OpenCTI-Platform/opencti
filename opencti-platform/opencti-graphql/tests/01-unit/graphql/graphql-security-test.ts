import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeExecutableSchema } from '@graphql-tools/schema';
import type { GraphQLError } from 'graphql';

vi.mock('../../../src/graphql/schema', () => ({
  default: vi.fn(),
}));

const schema = makeExecutableSchema({
  typeDefs: `
    enum Level { LOW HIGH }
    type Node {
      name: String
      parent: Node
    }
    type Query {
      node: Node
      level(value: Level): String
    }
    type Subscription {
      node: Node
    }
  `,
  resolvers: {
    Query: {
      node: () => ({ name: 'node' }),
      level: (_: unknown, { value }: { value: string }) => value,
    },
  },
});

interface GraphqlSecurityConfig {
  armorDisabled?: boolean;
  playgroundEnabled?: boolean;
  introspectionDisabled?: boolean;
  secureByDefault?: boolean;
  config?: Record<string, boolean>;
}

// The GraphQL protections are read once, when the module is loaded:
// reload it with the given resolved configuration.
const loadGraphql = async ({ armorDisabled = false, playgroundEnabled = false, introspectionDisabled = true, secureByDefault = false, config = {} }: GraphqlSecurityConfig) => {
  vi.resetModules();
  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../src/config/conf')>();
    return {
      ...actual,
      GRAPHQL_ARMOR_DISABLED: armorDisabled,
      GRAPHQL_SECURE_BY_DEFAULT: secureByDefault,
      PLAYGROUND_ENABLED: playgroundEnabled,
      PLAYGROUND_INTROSPECTION_DISABLED: introspectionDisabled,
      booleanConf: (key: string, defaultValue: boolean) => (key in config ? config[key] : defaultValue),
    };
  });
  return import('../../../src/graphql/graphql');
};

const loadApolloServer = async (graphqlConfig: GraphqlSecurityConfig) => {
  const { default: createApolloServer } = await loadGraphql(graphqlConfig);
  const { apolloServer } = createApolloServer(schema);
  await apolloServer.start();
  return apolloServer;
};

const execute = async (apolloServer: Awaited<ReturnType<typeof loadApolloServer>>, query: string, operationName?: string, user: unknown = { id: 'user' }) => {
  const response = await apolloServer.executeOperation({ query, operationName }, { contextValue: { user } });
  await apolloServer.stop();
  if (response.body.kind !== 'single') {
    throw new Error('Unexpected incremental response');
  }
  return response.body.singleResult;
};

// Options of the WebSocket server, with a context resolving the given user, or rejecting when there is none
const loadSubscriptionServer = async (graphqlConfig: GraphqlSecurityConfig, user: unknown = { id: 'user' }) => {
  const { default: createApolloServer, createSubscriptionServerOptions } = await loadGraphql(graphqlConfig);
  const { protection } = createApolloServer(schema);
  const context = vi.fn(async () => {
    if (!user) {
      throw new Error('User must be authenticated');
    }
    return { user };
  });
  return { options: createSubscriptionServerOptions({ schema, protection, context }), context };
};

const subscribe = async (options: Awaited<ReturnType<typeof loadSubscriptionServer>>['options'], query: string, operationName?: string) => {
  const payload = { query, operationName };
  const result = await options.onSubscribe({} as never, 'id', payload);
  if (Array.isArray(result)) {
    return { errors: options.onError({} as never, 'id', payload, result as GraphQLError[]) };
  }
  return { execArgs: result };
};

const deepQuery = (depth: number) => `{ node { ${'parent { '.repeat(depth)}name${' }'.repeat(depth)} } }`;
const directivesQuery = (count: number) => `{ node { ${'name @include(if: true) '.repeat(count)}} }`;

describe('GraphQL security', () => {
  afterEach(() => {
    vi.doUnmock('../../../src/config/conf');
  });

  describe('field suggestions', () => {
    it('should remove field suggestions when armor is enabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: false });
      const result = await execute(apolloServer, '{ nod { name } }');
      expect(result.errors?.[0].message).toEqual('Cannot query field "nod" on type "Query".');
    });

    it('should remove enum value suggestions when armor is enabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: false });
      const result = await execute(apolloServer, '{ level(value: LOWW) }');
      expect(result.errors?.[0].message).toEqual('Value "LOWW" does not exist in "Level" enum.');
    });

    it('should keep suggestions when armor is disabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: true });
      const result = await execute(apolloServer, '{ nod { name } }');
      expect(result.errors?.[0].message).toContain('Did you mean "node"?');
    });

    it('should keep suggestions when block_field_suggestion is disabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: false, config: { 'app:graphql:armor_protection:block_field_suggestion': false } });
      const result = await execute(apolloServer, '{ nod { name } }');
      expect(result.errors?.[0].message).toContain('Did you mean "node"?');
    });

    it('should remove every suggestion of a message', async () => {
      const { removeSuggestions } = await loadGraphql({});
      expect(removeSuggestions('A. Did you mean "b"? C. Did you mean "d", or "e"?')).toEqual('A. C.');
      expect(removeSuggestions('A. Did you mean "b"? C. Did you mean')).toEqual('A. C. Did you mean');
    });

    it('should remove suggestions in linear time', async () => {
      const { removeSuggestions } = await loadGraphql({});
      // A quadratic scan of this user controlled message would take minutes
      const message = ' Did you mean '.repeat(100000);
      const start = Date.now();
      expect(removeSuggestions(message)).toEqual(message);
      expect(Date.now() - start).toBeLessThan(1000);
    });
  });

  describe('armor protection', () => {
    it('should reject a query deeper than the max depth when armor is enabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: false });
      const result = await execute(apolloServer, deepQuery(25));
      expect(result.errors?.[0].message).toEqual('Syntax Error: Query depth limit of 20 exceeded, found 27.');
    });

    it('should accept a deep query when armor is disabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: true });
      const result = await execute(apolloServer, deepQuery(25));
      expect(result.errors).toBeUndefined();
    });

    it('should reject a query with more directives than the max when armor is enabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: false });
      const result = await execute(apolloServer, directivesQuery(25));
      expect(result.errors?.[0].message).toEqual('Syntax Error: Directives limit of 20 exceeded, found 25.');
    });

    it('should accept many directives when armor is disabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: true });
      const result = await execute(apolloServer, directivesQuery(25));
      expect(result.errors).toBeUndefined();
    });

    it('should reject a query with more tokens than the max as a parse failure when armor is enabled', async () => {
      const apolloServer = await loadApolloServer({ armorDisabled: false });
      const result = await execute(apolloServer, `{ node { ${'name '.repeat(100000)}} }`);
      expect(result.errors?.[0].extensions?.code).toEqual('GRAPHQL_PARSE_FAILED');
      expect(result.errors?.[0].message).toEqual('Syntax Error: Document contains more than 100000 tokens. Parsing aborted.');
    });
  });

  describe('operation name', () => {
    it('should reject an unknown operation name as a bad user input', async () => {
      const apolloServer = await loadApolloServer({});
      const result = await execute(apolloServer, 'query Known { node { name } }', 'Unknown');
      expect(result.errors?.[0].extensions?.code).toEqual('BAD_USER_INPUT_ERROR');
      expect(result.errors?.[0].message).toEqual('Unknown operation name');
    });

    it('should execute a known operation name', async () => {
      const apolloServer = await loadApolloServer({});
      const result = await execute(apolloServer, 'query Known { node { name } } query Other { level(value: LOW) }', 'Known');
      expect(result.errors).toBeUndefined();
      expect(result.data).toEqual({ node: { name: 'node' } });
    });
  });

  describe('introspection', () => {
    it.each([
      ['__schema', '{ __schema { queryType { name } } }'],
      ['__type', '{ __type(name: "Node") { fields { name } } }'],
      ['__type in a fragment', '{ ...Introspection } fragment Introspection on Query { __type(name: "Node") { name } }'],
    ])('should reject %s when introspection is disabled', async (_, query) => {
      const apolloServer = await loadApolloServer({ playgroundEnabled: true, introspectionDisabled: true });
      const result = await execute(apolloServer, query);
      expect(result.errors?.[0].message).toEqual('GraphQL introspection not authorized!');
    });

    it('should reject __type when the playground is disabled', async () => {
      const apolloServer = await loadApolloServer({ playgroundEnabled: false, introspectionDisabled: false });
      const result = await execute(apolloServer, '{ __type(name: "Node") { name } }');
      expect(result.errors?.[0].message).toEqual('GraphQL introspection not authorized!');
    });

    it('should accept __type when introspection is enabled', async () => {
      const apolloServer = await loadApolloServer({ playgroundEnabled: true, introspectionDisabled: false });
      const result = await execute(apolloServer, '{ __type(name: "Node") { name } }');
      expect(result.errors).toBeUndefined();
      expect(result.data).toEqual({ __type: { name: 'Node' } });
    });

    it('should require an authenticated user when introspection is enabled', async () => {
      const apolloServer = await loadApolloServer({ playgroundEnabled: true, introspectionDisabled: false });
      const result = await execute(apolloServer, '{ __schema { queryType { name } } }', undefined, null);
      expect(result.errors?.[0].extensions?.code).toEqual('AUTH_REQUIRED');
    });

    it('should accept __typename when introspection is disabled', async () => {
      const apolloServer = await loadApolloServer({ playgroundEnabled: false, introspectionDisabled: true });
      const result = await execute(apolloServer, '{ node { __typename name } }');
      expect(result.errors).toBeUndefined();
      expect(result.data).toEqual({ node: { __typename: 'Node', name: 'node' } });
    });
  });

  describe('websocket', () => {
    it('should authenticate before validating the operation', async () => {
      const { options, context } = await loadSubscriptionServer({ armorDisabled: true }, null);
      await expect(subscribe(options, '{ nod { name } }')).rejects.toThrow('User must be authenticated');
      expect(context).toHaveBeenCalledOnce();
    });

    it('should return the execution arguments of a valid subscription with its context', async () => {
      const { options } = await loadSubscriptionServer({ secureByDefault: true });
      const { execArgs } = await subscribe(options, 'subscription Watch { node { name } }', 'Watch');
      expect(execArgs).toMatchObject({ schema, operationName: 'Watch', contextValue: { user: { id: 'user' } } });
    });

    it('should remove suggestions when armor is enabled', async () => {
      const { options } = await loadSubscriptionServer({ armorDisabled: false });
      const { errors } = await subscribe(options, 'subscription { nod { name } }');
      expect(errors?.[0].message).toEqual('Cannot query field "nod" on type "Subscription".');
    });

    it('should keep suggestions when armor is disabled', async () => {
      const { options } = await loadSubscriptionServer({ armorDisabled: true });
      const { errors } = await subscribe(options, 'subscription { nod { name } }');
      expect(errors?.[0].message).toContain('Did you mean "node"?');
    });

    it('should apply armor when enabled', async () => {
      const { options } = await loadSubscriptionServer({ armorDisabled: false });
      const { errors } = await subscribe(options, `subscription ${deepQuery(25)}`);
      expect(errors?.[0].message).toEqual('Syntax Error: Query depth limit of 20 exceeded, found 27.');
    });

    it('should apply the max tokens when armor is enabled', async () => {
      const { options } = await loadSubscriptionServer({ armorDisabled: false });
      const { errors } = await subscribe(options, `subscription { node { ${'name '.repeat(100000)}} }`);
      expect(errors?.[0].message).toEqual('Syntax Error: Document contains more than 100000 tokens. Parsing aborted.');
    });

    it('should apply the batching protection', async () => {
      const { options } = await loadSubscriptionServer({ armorDisabled: true });
      const { errors } = await subscribe(options, '{ a: node { name } b: node { name } c: node { name } }');
      expect(errors?.[0].message).toEqual('Allowed number of calls for Query->node has been exceeded (max: 2)');
    });

    it('should reject introspection when disabled', async () => {
      const { options } = await loadSubscriptionServer({ playgroundEnabled: true, introspectionDisabled: true });
      const { errors } = await subscribe(options, '{ __type(name: "Node") { name } }');
      expect(errors?.[0].message).toEqual('GraphQL introspection not authorized!');
    });

    it('should reject queries and mutations when secure by default', async () => {
      const { options } = await loadSubscriptionServer({ secureByDefault: true });
      const { errors } = await subscribe(options, '{ node { name } }');
      expect(errors?.[0].message).toEqual('Only subscriptions are allowed over WebSocket');
    });

    it('should accept queries when not secure by default', async () => {
      const { options } = await loadSubscriptionServer({ secureByDefault: false });
      const { execArgs, errors } = await subscribe(options, '{ node { name } }');
      expect(errors).toBeUndefined();
      expect(execArgs).toMatchObject({ contextValue: { user: { id: 'user' } } });
    });
  });
});
