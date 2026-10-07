import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { testContext, USER_EDITOR } from '../../../utils/testQuery';
import * as entrepriseEdition from '../../../../src/enterprise-edition/ee';
import {
  getDefaultInvestigationPolicy,
  loadInvestigationPolicy,
  updateInvestigationPolicyStreamPosition,
} from '../../../../src/modules/investigationRun/investigationPolicy-domain';

const POLICY_ADD = gql`
  mutation PolicyAdd($input: InvestigationPolicyAddInput!) {
    investigationPolicyAdd(input: $input) {
      id
      name
      is_default
      pack_id
      pack_options
      allowed_actions
      max_iterations
      max_enrichment_jobs
      max_minutes
      attribution_min_confidence
      runs_count
      acceptance { rate }
    }
  }
`;
const POLICY_PATCH = gql`
  mutation PolicyPatch($id: ID!, $input: [EditInput!]!) {
    investigationPolicyFieldPatch(id: $id, input: $input) { id pack_id pack_options max_iterations }
  }
`;
const POLICY_DELETE = gql`mutation PolicyDelete($id: ID!) { investigationPolicyDelete(id: $id) }`;
const POLICIES = gql`
  query Policies { investigationPolicies(first: 50) { edges { node { id name is_default } } } }
`;
const PACKS = gql`
  query Packs { investigationPacks { available reason packs { slug } } }
`;
const CONNECTORS = gql`
  query PolicyConnectors { investigationEnrichmentConnectors { id name active } }
`;
const POLICY_READ = gql`
  query PolicyRead($id: ID!) { investigationPolicy(id: $id) { id name is_default } }
`;
const POLICIES_TO_START = gql`
  query PoliciesToStart { investigationPolicies(first: 50) { edges { node { id name description is_default allowed_actions attribution_min_confidence } } } }
`;
const POLICY_RUN_AS = gql`
  query PolicyRunAs($id: ID!) { investigationPolicy(id: $id) { id run_as_id } }
`;

describe('Case Autopilot investigation policies', () => {
  const created: string[] = [];

  beforeAll(() => {
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  afterAll(async () => {
    for (let index = 0; index < created.length; index += 1) {
      await queryAsAdmin({ query: POLICY_DELETE, variables: { id: created[index] } });
    }
    vi.restoreAllMocks();
  });

  it('keeps a single default policy, created once on first use', async () => {
    const first = await getDefaultInvestigationPolicy(testContext);
    const second = await getDefaultInvestigationPolicy(testContext);
    expect(second.internal_id).toEqual(first.internal_id);
    const { data } = await queryAsAdminWithSuccess({ query: POLICIES, variables: {} });
    const defaults = data.investigationPolicies.edges.filter((edge: { node: { is_default: boolean } }) => edge.node.is_default);
    expect(defaults).toHaveLength(1);
    expect(defaults[0].node.id).toEqual(first.internal_id);
  });

  it('creates a policy naming a pack, its options and the engine budget', async () => {
    const { data } = await queryAsAdminWithSuccess({
      query: POLICY_ADD,
      variables: {
        input: {
          name: 'SOC night shift',
          pack_id: 'opencti-case-investigation',
          pack_options: { leads: 'off' },
          allowed_actions: ['enrichment', 'create_note'],
          max_iterations: 6,
          max_enrichment_jobs: 5,
          max_minutes: 20,
          attribution_min_confidence: 70,
        },
      },
    });
    const policy = data.investigationPolicyAdd;
    created.push(policy.id);
    expect(policy).toMatchObject({
      name: 'SOC night shift',
      is_default: false,
      pack_id: 'opencti-case-investigation',
      pack_options: { leads: 'off' },
      allowed_actions: ['enrichment', 'create_note'],
      max_iterations: 6,
      max_enrichment_jobs: 5,
      max_minutes: 20,
      attribution_min_confidence: 70,
      runs_count: 0,
    });
    expect(policy.acceptance.rate).toBeNull();
  });

  it('patches the pack options and the iterations budget', async () => {
    const { data } = await queryAsAdminWithSuccess({
      query: POLICY_PATCH,
      variables: { id: created[0], input: [{ key: 'pack_options', value: [{ leads: 'on' }] }, { key: 'max_iterations', value: [12] }] },
    });
    expect(data.investigationPolicyFieldPatch).toMatchObject({ pack_options: { leads: 'on' }, max_iterations: 12 });
  });

  it('refuses a budget outside its bounds', async () => {
    const result = await queryAsAdmin({ query: POLICY_ADD, variables: { input: { name: 'Too many iterations', max_iterations: 51 } } });
    expect(result.errors?.length).toBe(1);
  });

  it('lets only the users who manage customization change policies', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: POLICY_ADD, variables: { input: { name: 'Editor policy' } } });
    const { data } = await queryAsUserWithSuccess(USER_EDITOR, { query: POLICIES, variables: {} });
    expect(data.investigationPolicies.edges.length).toBeGreaterThan(0);
  });

  it('shows who starts a run what a policy may do, its connectors, approvals and identity only to who manages customization', async () => {
    const { data } = await queryAsUserWithSuccess(USER_EDITOR, { query: POLICIES_TO_START, variables: {} });
    const policyId = data.investigationPolicies.edges[0].node.id;
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: POLICY_RUN_AS, variables: { id: policyId } });
    const managed = await queryAsAdminWithSuccess({ query: POLICY_RUN_AS, variables: { id: policyId } });
    expect(managed.data?.investigationPolicy.id).toBe(policyId);
  });

  it('says the pack catalog is not available when XTM One is not connected', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: PACKS, variables: {} });
    expect(data.investigationPacks).toEqual({ available: false, reason: 'engine_not_configured', packs: [] });
  });

  it('accepts only enrichment connectors and bounded pack options', async () => {
    const connectors = await queryAsAdmin({ query: POLICY_ADD, variables: { input: { name: 'Unknown connector', enrichment_connector_ids: ['not-a-connector'] } } });
    expect(connectors.errors?.[0]?.message).toContain('only accept enrichment connectors');
    const options = await queryAsAdmin({ query: POLICY_ADD, variables: { input: { name: 'Numeric option', pack_options: { leads: 1 } } } });
    expect(options.errors?.[0]?.message).toContain('Invalid pack option');
    const { data } = await queryAsAdminWithSuccess({ query: CONNECTORS, variables: {} });
    expect(Array.isArray(data.investigationEnrichmentConnectors)).toBe(true);
  });

  it('reads a policy by id and promotes another policy to default, the previous default stepping down', async () => {
    const previous = await getDefaultInvestigationPolicy(testContext);
    const read = await queryAsAdminWithSuccess({ query: POLICY_READ, variables: { id: created[0] } });
    expect(read.data.investigationPolicy).toMatchObject({ id: created[0], name: 'SOC night shift', is_default: false });
    try {
      await queryAsAdminWithSuccess({ query: POLICY_PATCH, variables: { id: created[0], input: [{ key: 'is_default', value: [true] }] } });
      const { data } = await queryAsAdminWithSuccess({ query: POLICIES, variables: {} });
      const defaults = data.investigationPolicies.edges.filter((edge: { node: { is_default: boolean } }) => edge.node.is_default);
      expect(defaults.map((edge: { node: { id: string } }) => edge.node.id)).toEqual([created[0]]);
    } finally {
      await queryAsAdminWithSuccess({ query: POLICY_PATCH, variables: { id: previous.internal_id, input: [{ key: 'is_default', value: [true] }] } });
    }
    const restored = await getDefaultInvestigationPolicy(testContext);
    expect(restored.internal_id).toBe(previous.internal_id);
  });

  it('moves the request for information cursor only from where it stands, and only while the hook is on', async () => {
    const policyId = created[0];
    // The hook is off: the cursor does not move.
    expect(await updateInvestigationPolicyStreamPosition(testContext, policyId, '', '2-0')).toBe(false);
    // Turned on, the hook starts from that moment.
    await queryAsAdminWithSuccess({ query: POLICY_PATCH, variables: { id: policyId, input: [{ key: 'trigger_on_case_rfi_creation', value: [true] }] } });
    const enabled = await loadInvestigationPolicy(testContext, policyId);
    expect(enabled?.last_event_id).toMatch(/^\d+-0$/);
    const start = enabled?.last_event_id as string;
    expect(await updateInvestigationPolicyStreamPosition(testContext, policyId, '1-0', '9999999999998-0')).toBe(false);
    expect(await updateInvestigationPolicyStreamPosition(testContext, policyId, start, '9999999999998-0')).toBe(true);
    expect(await updateInvestigationPolicyStreamPosition(testContext, policyId, '9999999999998-0', '9999999999999-0')).toBe(true);
    await queryAsAdminWithSuccess({ query: POLICY_PATCH, variables: { id: policyId, input: [{ key: 'trigger_on_case_rfi_creation', value: [false] }] } });
  });
});
