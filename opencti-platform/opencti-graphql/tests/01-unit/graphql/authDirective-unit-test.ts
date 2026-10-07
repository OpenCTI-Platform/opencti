import { describe, expect, it } from 'vitest';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { graphql } from 'graphql';
import { authDirectiveBuilder } from '../../../src/graphql/authDirective';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { BYPASS, PUBLIC_DASHBOARD_REFERER } from '../../../src/utils/access';

const typeDefs = `
  directive @auth(for: [String!] = [], and: Boolean = false, forDraft: [String!] = []) on OBJECT | FIELD_DEFINITION
  type Query {
    restricted: String @auth(for: ["SETTINGS_SETACCESSES"])
    open: String @auth(for: [])
  }
`;

const resolvers = {
  Query: {
    restricted: () => 'restricted-value',
    open: () => 'open-value',
  },
};

const buildSchema = () => {
  const schema = makeExecutableSchema({ typeDefs, resolvers });
  const { authDirectiveTransformer } = authDirectiveBuilder('auth');
  return authDirectiveTransformer(schema);
};

const buildUser = (overrides: Record<string, unknown> = {}) => ({
  id: 'standard-user-id',
  capabilities: [],
  administrated_organizations: [],
  origin: {},
  ...overrides,
});

const runRestrictedQuery = async (user: unknown) => {
  return graphql({
    schema: buildSchema(),
    source: '{ restricted }',
    contextValue: { user, otp_mandatory: false, user_otp_validated: true },
  });
};

describe('authDirective capability check', () => {
  it('denies access when the user is missing the required capability', async () => {
    const result = await runRestrictedQuery(buildUser());
    expect(result.data?.restricted).toBeNull();
    expect(result.errors?.[0]?.message).toBe('You are not allowed to do this.');
  });

  it('grants access when the user has the required capability', async () => {
    const user = buildUser({ capabilities: [{ name: 'SETTINGS_SETACCESSES' }] });
    const result = await runRestrictedQuery(user);
    expect(result.errors).toBeUndefined();
    expect(result.data?.restricted).toBe('restricted-value');
  });

  it('grants access when the user has the BYPASS capability', async () => {
    const user = buildUser({ capabilities: [{ name: BYPASS }] });
    const result = await runRestrictedQuery(user);
    expect(result.errors).toBeUndefined();
    expect(result.data?.restricted).toBe('restricted-value');
  });

  it('grants access to the platform admin id even without the required capability', async () => {
    const user = buildUser({ id: OPENCTI_ADMIN_UUID });
    const result = await runRestrictedQuery(user);
    expect(result.errors).toBeUndefined();
    expect(result.data?.restricted).toBe('restricted-value');
  });

  it('denies access to the platform admin id when the origin referer is restricted', async () => {
    const user = buildUser({
      id: OPENCTI_ADMIN_UUID,
      origin: { referer: PUBLIC_DASHBOARD_REFERER },
    });
    const result = await runRestrictedQuery(user);
    expect(result.data?.restricted).toBeNull();
    expect(result.errors?.[0]?.message).toBe('You are not allowed to do this.');
  });

  it('still denies access for a restricted origin referer without the BYPASS capability', async () => {
    const user = buildUser({
      capabilities: [{ name: 'KNOWLEDGE' }],
      origin: { referer: PUBLIC_DASHBOARD_REFERER },
    });
    const result = await runRestrictedQuery(user);
    expect(result.data?.restricted).toBeNull();
    expect(result.errors?.[0]?.message).toBe('You are not allowed to do this.');
  });
});
