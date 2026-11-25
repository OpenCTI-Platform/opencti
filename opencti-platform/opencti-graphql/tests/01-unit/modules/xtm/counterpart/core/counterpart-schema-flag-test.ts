import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { graphql, parse } from 'graphql';
import { makeExecutableSchema } from '@graphql-tools/schema';

// The two queries carry @ff(flags: ["XTM_COUNTERPARTS"], softFail: true, defaultValue: "[]") in the schema
// itself: with the flag off they answer [] and their resolvers are never reached.
const COUNTERPART_SCHEMA = readFileSync(new URL('../../../../../../src/modules/xtm/counterpart/core/counterpart.graphql', import.meta.url), 'utf8');
const DIRECTIVES = `
  directive @auth(for: [Capabilities] = [], and: Boolean = false, forDraft: [Capabilities] = []) on OBJECT | FIELD_DEFINITION
  directive @ff(flags: [String!]!, softFail: Boolean = false, defaultValue: String = null) on FIELD_DEFINITION
  enum Capabilities { KNOWLEDGE }
`;

const buildSchema = async (flagOn: boolean, resolvers: { xtmConnections: () => unknown; xtmCounterpartsOf: () => unknown }) => {
  vi.resetModules();
  vi.doMock('../../../../../../src/config/conf', () => ({
    isFeatureEnabled: vi.fn((flag: string) => flagOn && flag === 'XTM_COUNTERPARTS'),
  }));
  const { makeFeatureFlagDirectiveTransformer } = await import('../../../../../../src/graphql/featureFlagDirective');
  const schema = makeExecutableSchema({ typeDefs: parse(DIRECTIVES + COUNTERPART_SCHEMA), resolvers: { Query: resolvers } });
  return makeFeatureFlagDirectiveTransformer()(schema);
};

const QUERY = '{ xtmConnections { product connected } xtmCounterpartsOf(ids: ["id-1"]) { id product status } }';

describe('XTM counterparts schema: @ff XTM_COUNTERPARTS on the two queries', () => {
  afterEach(() => {
    vi.resetAllMocks();
    vi.doUnmock('../../../../../../src/config/conf');
  });

  it('answers [] for both queries without reaching the resolvers while the flag is off', async () => {
    const xtmConnections = vi.fn(() => [{ product: 'openaev', connected: true }]);
    const xtmCounterpartsOf = vi.fn(() => [{ id: 'id-1', product: 'openaev', status: 'not_found' }]);
    const schema = await buildSchema(false, { xtmConnections, xtmCounterpartsOf });
    const result = await graphql({ schema, source: QUERY });
    expect(result.errors).toBeUndefined();
    expect(result.data).toEqual({ xtmConnections: [], xtmCounterpartsOf: [] });
    expect(xtmConnections).not.toHaveBeenCalled();
    expect(xtmCounterpartsOf).not.toHaveBeenCalled();
  });

  it('calls the resolvers while the flag is on', async () => {
    const xtmConnections = vi.fn(() => [{ product: 'openaev', connected: true }]);
    const xtmCounterpartsOf = vi.fn(() => [{ id: 'id-1', product: 'openaev', status: 'not_found' }]);
    const schema = await buildSchema(true, { xtmConnections, xtmCounterpartsOf });
    const result = await graphql({ schema, source: QUERY });
    expect(result.errors).toBeUndefined();
    expect(result.data).toEqual({
      xtmConnections: [{ product: 'openaev', connected: true }],
      xtmCounterpartsOf: [{ id: 'id-1', product: 'openaev', status: 'not_found' }],
    });
  });
});
