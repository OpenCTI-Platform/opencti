import { afterEach, describe, expect, it, vi } from 'vitest';
import { graphql, parse } from 'graphql';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { makeFeatureFlagDirectiveTransformer } from '../../../src/graphql/featureFlagDirective';
import { isFeatureEnabled } from '../../../src/config/conf';

vi.mock('../../../src/config/conf', () => ({
  isFeatureEnabled: vi.fn(),
}));

describe('featureFlagDirective', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('returns a Forbidden error when none of the flags are enabled', async () => {
    const typeDefs = parse(`
      directive @ff(flags: [String!]!, softFail: Boolean = false) on FIELD_DEFINITION
      type Query {
        flaggedFeature: String @ff(flags: ["SOME_FLAG", "SOME_OTHER_FLAG"])
      }
    `);
    const resolvers = {
      Query: {
        flaggedFeature: () => 'experimental content',
      },
    };
    vi.mocked(isFeatureEnabled).mockReturnValue(false);

    let schema = makeExecutableSchema({ typeDefs, resolvers });
    schema = makeFeatureFlagDirectiveTransformer()(schema);

    const result = await graphql({ schema, source: '{ flaggedFeature }' });

    expect(result.errors).not.toBeUndefined();
    expect(result.errors?.[0].message).toMatch(/You are not allowed to do this/i);
    expect(result.errors?.[0].extensions?.code).toMatch(/FORBIDDEN_ACCESS/i);
  });

  it('calls the resolver when one of the flags is enabled', async () => {
    const typeDefs = parse(`
      directive @ff(flags: [String!]!, softFail: Boolean = false) on FIELD_DEFINITION
      type Query {
        flaggedFeature: String @ff(flags: ["SOME_FLAG", "SOME_OTHER_FLAG"])
      }
    `);
    const resolvers = {
      Query: {
        flaggedFeature: () => 'experimental content',
      },
    };
    vi.mocked(isFeatureEnabled).mockImplementation((flag: string) => {
      return flag === 'SOME_FLAG';
    });

    let schema = makeExecutableSchema({ typeDefs, resolvers });
    schema = makeFeatureFlagDirectiveTransformer()(schema);

    const result = await graphql({ schema, source: '{ flaggedFeature }' });

    expect(result.data?.flaggedFeature).toBe('experimental content');
  });

  it('returns null when none of the flags are enabled and softFail is set', async () => {
    const typeDefs = parse(`
      directive @ff(flags: [String!]!, softFail: Boolean = false) on FIELD_DEFINITION
      type Query {
        flaggedFeature: String @ff(flags: ["SOME_FLAG"], softFail: true)
      }
    `);
    const resolvers = {
      Query: {
        flaggedFeature: () => 'experimental content',
      },
    };
    vi.mocked(isFeatureEnabled).mockReturnValue(false);

    let schema = makeExecutableSchema({ typeDefs, resolvers });
    schema = makeFeatureFlagDirectiveTransformer()(schema);

    const result = await graphql({ schema, source: '{ flaggedFeature }' });

    expect(result.errors).toBeUndefined();
    expect(result.data?.flaggedFeature).toBeNull();
  });
});
