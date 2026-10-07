import { describe, expect, it } from 'vitest';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { graphql } from 'graphql';
import { authDirectiveBuilder } from '../../../src/graphql/authDirective';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { BYPASS, PUBLIC_DASHBOARD_REFERER } from '../../../src/utils/access';
import { getDraftContext, recordDraftClosedByRequest } from '../../../src/utils/draftContext';
import type { AuthContext } from '../../../src/types/user';

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

describe('authDirective in a draft the request closed', () => {
  const draftTypeDefs = `
    directive @auth(for: [String!] = [], and: Boolean = false, forDraft: [String!] = []) on OBJECT | FIELD_DEFINITION
    type Query {
      open: String @auth(for: [])
    }
    type Mutation {
      closeDraft(id: String!): String @auth(for: [])
      write: String @auth(for: ["KNOWLEDGE_KNUPDATE"])
    }
  `;
  const draftResolvers = {
    Query: { open: () => 'open-value' },
    Mutation: {
      // A validation or a deletion records the draft when its closure starts (see runDraftClosureHandlers)
      closeDraft: (_: unknown, { id }: { id: string }, context: AuthContext) => {
        recordDraftClosedByRequest(context, id);
        return id;
      },
      write: (_: unknown, __: unknown, context: AuthContext) => `written in ${getDraftContext(context, context.user) ?? 'live'}`,
    },
  };
  const runDocument = (source: string, draftContext?: string) => graphql({
    schema: authDirectiveBuilder('auth').authDirectiveTransformer(makeExecutableSchema({ typeDefs: draftTypeDefs, resolvers: draftResolvers })),
    source,
    contextValue: { user: buildUser({ capabilities: [{ name: BYPASS }] }), draft_context: draftContext, otp_mandatory: false, user_otp_validated: true },
  });

  it('refuses a write in a later root field of a document that closed its draft', async () => {
    const result = await runDocument('mutation { closeDraft(id: "draft-a") write }', 'draft-a');
    expect(result.data?.closeDraft).toBe('draft-a');
    expect(result.data?.write).toBeNull();
    expect(result.errors?.map((error) => error.message)).toEqual(['Cannot execute a mutation in a draft that this request closed']);
  });

  it('refuses it for a user whose own draft is the one closed', async () => {
    const result = await graphql({
      schema: authDirectiveBuilder('auth').authDirectiveTransformer(makeExecutableSchema({ typeDefs: draftTypeDefs, resolvers: draftResolvers })),
      source: 'mutation { closeDraft(id: "draft-a") write }',
      contextValue: { user: buildUser({ capabilities: [{ name: BYPASS }], draft_context: 'draft-a' }), otp_mandatory: false, user_otp_validated: true },
    });
    expect(result.data?.write).toBeNull();
  });

  it('still runs a write in another draft or in the live knowledge after a draft was closed', async () => {
    expect((await runDocument('mutation { closeDraft(id: "draft-b") write }', 'draft-a')).data?.write).toBe('written in draft-a');
    expect((await runDocument('mutation { closeDraft(id: "draft-a") write }')).data?.write).toBe('written in live');
    expect((await runDocument('mutation { write }', 'draft-a')).data?.write).toBe('written in draft-a');
  });
});
