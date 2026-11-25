import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { graphql, Kind, parse, print } from 'graphql';
import { authDirectiveBuilder } from '../../../src/graphql/authDirective';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { BYPASS, PUBLIC_DASHBOARD_REFERER } from '../../../src/utils/access';

const typeDefs = `
  directive @auth(for: [String!] = [], and: Boolean = false, forDraft: [String!] = []) on OBJECT | FIELD_DEFINITION
  type Query {
    restricted: String @auth(for: ["SETTINGS_SETACCESSES"])
    open: String @auth(for: [])
    knowledgeUpdate: String @auth(for: ["KNOWLEDGE_KNUPDATE"])
    knowledgeDelete: String @auth(for: ["KNOWLEDGE_KNUPDATE_KNDELETE"])
    labelsManage: String @auth(for: ["SETTINGS_SETLABELS"])
    draftKnowledge: String @auth(for: ["KNOWLEDGE"], forDraft: ["KNOWLEDGE"])
  }
`;

const resolvers = {
  Query: {
    restricted: () => 'restricted-value',
    open: () => 'open-value',
    knowledgeUpdate: () => 'update-value',
    knowledgeDelete: () => 'delete-value',
    labelsManage: () => 'labels-value',
    draftKnowledge: () => 'draft-value',
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

describe('authDirective - knowledge access in draft only', () => {
  const run = (user: unknown) => graphql({
    schema: buildSchema(),
    source: '{ draftKnowledge }',
    contextValue: { user, otp_mandatory: false, user_otp_validated: true },
  });

  it('grants a draft query to a user having knowledge access only in draft, outside any draft', async () => {
    const result = await run(buildUser({ capabilitiesInDraft: [{ name: 'KNOWLEDGE' }] }));
    expect(result.errors).toBeUndefined();
    expect(result.data?.draftKnowledge).toBe('draft-value');
  });

  it('denies a draft query to a user without any knowledge access', async () => {
    const result = await run(buildUser({ capabilitiesInDraft: [{ name: 'SETTINGS_SETLABELS' }] }));
    expect(result.data?.draftKnowledge).toBeNull();
    expect(result.errors?.[0]?.message).toBe('You are not allowed to do this.');
  });

  it('declares forDraft KNOWLEDGE on draft workspace queries, except administration and dashboard ones', () => {
    // Restriction administration and dashboard stats are outside of any draft: base KNOWLEDGE only
    const baseOnly = ['draftWorkspacesRestricted', 'draftWorkspacesNumber', 'draftWorkspacesTimeSeries', 'draftWorkspacesDistribution'];
    const doc = parse(readFileSync('src/modules/draftWorkspace/draftWorkspace.graphql', 'utf8'));
    const queryType = doc.definitions.find((d) => d.kind === Kind.OBJECT_TYPE_DEFINITION && d.name.value === 'Query');
    const fields = queryType && 'fields' in queryType ? queryType.fields ?? [] : [];
    expect(fields.length).toBeGreaterThan(0);
    fields.forEach((field) => {
      const auth = field.directives?.find((d) => d.name.value === 'auth');
      const forDraft = auth?.arguments?.find((a) => a.name.value === 'forDraft');
      const expected = baseOnly.includes(field.name.value) ? undefined : '[KNOWLEDGE]';
      expect(forDraft && print(forDraft.value), field.name.value).toBe(expected);
    });
  });
});

describe('authDirective - verified form submission', () => {
  const formOnlyUser = buildUser({ capabilities: [{ name: 'KNOWLEDGE_KNFORMINTAKE' }] });
  const run = (field: string, formSubmission?: boolean) => graphql({
    schema: buildSchema(),
    source: `{ ${field} }`,
    contextValue: { user: formOnlyUser, otp_mandatory: false, user_otp_validated: true, form_submission: formSubmission },
  });

  it('denies Create / Update knowledge to a form-only user outside a verified form submission', async () => {
    const result = await run('knowledgeUpdate');
    expect(result.data?.knowledgeUpdate).toBeNull();
    expect(result.errors?.[0]?.message).toBe('You are not allowed to do this.');
  });

  it('grants Create / Update knowledge to a form-only user during a verified form submission', async () => {
    const result = await run('knowledgeUpdate', true);
    expect(result.errors).toBeUndefined();
    expect(result.data?.knowledgeUpdate).toBe('update-value');
  });

  it('gives nothing else than Create / Update knowledge during a verified form submission', async () => {
    const deleted = await run('knowledgeDelete', true);
    expect(deleted.data?.knowledgeDelete).toBeNull();
    expect(deleted.errors?.[0]?.message).toBe('You are not allowed to do this.');
    const labels = await run('labelsManage', true);
    expect(labels.data?.labelsManage).toBeNull();
    expect(labels.errors?.[0]?.message).toBe('You are not allowed to do this.');
  });
});
