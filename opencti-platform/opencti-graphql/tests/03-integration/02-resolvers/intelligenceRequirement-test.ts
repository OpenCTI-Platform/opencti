import gql from 'graphql-tag';
import { beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUser } from '../../utils/testQueryHelper';
import { SYSTEM_USER } from '../../../src/utils/access';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { BasicStoreEntity } from '../../../src/types/store';

const IR_FIELDS = `
  id
  name
  ir_question
  ir_priority
  ir_status
  ir_thresholds
  ir_rescan_days
  ir_brief_frequency
  ir_kiqs { id text criteria_ids }
  ir_subject_groups { id name kind role entity_ids entities { id } keywords }
  ir_scope_criteria { id name kind mode target_types from_group_ids conditions { id name } }
  ir_relevance_rules { id name points required enabled }
  currentUserAccessRight
`;

const PREVIEW_QUERY = gql`
  query IrPreview($input: IntelligenceRequirementInput!) {
    intelligenceRequirementPreview(input: $input) {
      valid
      errors
      warnings
      groups { id kind matching_count unresolved_ids entities { id entity_type } }
      criteria { id kind today_count note warnings }
    }
  }
`;

const ADD_QUERY = gql`
  mutation IrAdd($input: IntelligenceRequirementInput!) {
    intelligenceRequirementAdd(input: $input) { ${IR_FIELDS} }
  }
`;

const UPDATE_QUERY = gql`
  mutation IrUpdate($id: ID!, $input: IntelligenceRequirementInput!) {
    intelligenceRequirementUpdate(id: $id, input: $input) { ${IR_FIELDS} }
  }
`;

const STATUS_QUERY = gql`
  mutation IrStatus($id: ID!, $status: IntelligenceRequirementStatus!) {
    intelligenceRequirementStatusUpdate(id: $id, status: $status) { id ir_status }
  }
`;

const READ_QUERY = gql`
  query Ir($id: ID!) {
    intelligenceRequirement(id: $id) { ${IR_FIELDS} }
  }
`;

const INDICATORS_QUERY = gql`
  query IrIndicators($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_entities_count
      ir_inbox_open_count
      ir_inbox_counts { open proposed entered score health brief done }
      ir_stored_counts { entities items }
      ir_entities_by_type { entity_type count }
      ir_processing_status { state progress lag_seconds active_requirements }
      ir_activity(days: 7) { date value }
    }
  }
`;

const LIST_QUERY = gql`
  query Irs($search: String) {
    intelligenceRequirements(first: 50, search: $search) { edges { node { id name } } }
  }
`;

const MATCHES_QUERY = gql`
  query IrMatches($id: ID!) {
    intelligenceRequirementMatches(id: $id, first: 10) { edges { node { id match_entity_id match_status match_score } } }
  }
`;

const ITEMS_QUERY = gql`
  query IrItems($id: ID!) {
    intelligenceRequirementItems(id: $id, first: 10) { edges { node { id item_kind item_status } } }
  }
`;

const TEST_ENTITY_QUERY = gql`
  query IrTestEntity($input: IntelligenceRequirementInput!, $entityId: ID!, $irId: ID) {
    intelligenceRequirementTestEntity(input: $input, entity_id: $entityId, ir_id: $irId) {
      entity_id
      entity_type
      in_requirement
      score
      verdict
      criteria { criterion_id matched conditions { name met } }
      rules { name points hit }
    }
  }
`;

const HEALTH_QUERY = gql`
  mutation IrHealth($id: ID!) {
    intelligenceRequirementHealthCheck(id: $id)
  }
`;

const DELETE_QUERY = gql`
  mutation IrDelete($id: ID!) {
    intelligenceRequirementDelete(id: $id)
  }
`;

const MALWARE_STIX_ID = 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88';

// Loose shape on purpose: the tests mutate it into invalid configurations
const buildInput = (malwareId: string, name = 'IR integration requirement'): Record<string, any> => ({
  name,
  ir_question: 'Which malware matter for this test?',
  ir_priority: 'high',
  ir_kiqs: [{ id: 'kiq-1', text: 'Which malware is tracked?', criteria_ids: ['c-members'] }],
  ir_subject_groups: [
    { id: 'g-malware', name: 'Tracked malware', kind: 'list', role: 'both', entity_ids: [malwareId] },
    { id: 'g-keywords', name: 'Keywords', kind: 'keywords', role: 'entry', keywords: ['integration-ir-keyword'] },
  ],
  ir_scope_criteria: [
    { id: 'c-members', name: 'Members', kind: 'attribute', from_group_ids: ['g-malware'], target_types: ['Malware'], mode: 'auto' },
    { id: 'c-targets', name: 'Targets', kind: 'graph', from_group_ids: ['g-malware'], relationship_types: ['targets'], direction: 'outgoing', mode: 'propose' },
    { id: 'c-keywords', name: 'Mentions', kind: 'keywords', from_group_ids: ['g-keywords'], target_types: ['Report'], mode: 'propose' },
  ],
  ir_relevance_rules: [
    {
      id: 'r-confidence',
      name: 'Confident',
      applies_to_types: ['Malware'],
      points: 40,
      filters: { mode: 'and', filterGroups: [], filters: [{ key: ['confidence'], values: ['10'], operator: 'gt' }] },
    },
  ],
  ir_thresholds: [30, 70],
  ir_rescan_days: 1,
});

describe('Intelligence requirement resolvers', () => {
  let malwareId = '';
  let irId = '';
  let restrictedIrId = '';

  beforeAll(async () => {
    const malware = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, MALWARE_STIX_ID, { type: ENTITY_TYPE_MALWARE });
    malwareId = malware.internal_id;
  });

  it('should preview a valid configuration with its resolved subjects and criteria', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: PREVIEW_QUERY, variables: { input: buildInput(malwareId) } });
    const preview = data.intelligenceRequirementPreview;
    expect(preview.valid).toBe(true);
    expect(preview.errors).toEqual([]);
    const listGroup = preview.groups.find((g: { id: string }) => g.id === 'g-malware');
    expect(listGroup.matching_count).toEqual(1);
    expect(listGroup.unresolved_ids).toEqual([]);
    expect(listGroup.entities[0].entity_type).toEqual('Malware');
    expect(preview.criteria.map((c: { id: string }) => c.id)).toEqual(['c-members', 'c-targets', 'c-keywords']);
    expect(preview.criteria[0].today_count).toEqual(1);
  });

  it('should preview an invalid configuration with its errors', async () => {
    const input = buildInput(malwareId);
    input.ir_scope_criteria[0].from_group_ids = ['unknown-group'];
    const { data } = await queryAsAdminWithSuccess({ query: PREVIEW_QUERY, variables: { input } });
    expect(data.intelligenceRequirementPreview.valid).toBe(false);
    expect(data.intelligenceRequirementPreview.errors.length).toEqual(1);
  });

  it('should preview a dynamic subject group resolved from its filters', async () => {
    const input = buildInput(malwareId);
    input.ir_subject_groups = [
      {
        id: 'g-filter',
        name: 'Every malware',
        kind: 'filter',
        role: 'both',
        filters: { mode: 'and', filterGroups: [], filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq' }] },
      },
    ];
    input.ir_kiqs = [];
    input.ir_scope_criteria = [
      { id: 'c-filter', name: 'Members', kind: 'attribute', from_group_ids: ['g-filter'], target_types: ['Malware'], mode: 'auto' },
      { id: 'c-filter-targets', name: 'Targets', kind: 'graph', from_group_ids: ['g-filter'], relationship_types: ['targets'], direction: 'outgoing', mode: 'propose' },
    ];
    const { data } = await queryAsAdminWithSuccess({ query: PREVIEW_QUERY, variables: { input } });
    const preview = data.intelligenceRequirementPreview;
    expect(preview.valid).toBe(true);
    const group = preview.groups.find((g: { id: string }) => g.id === 'g-filter');
    expect(group.matching_count).toBeGreaterThanOrEqual(1);
    expect(preview.criteria.map((c: { id: string }) => c.id)).toEqual(['c-filter', 'c-filter-targets']);
    const test = await queryAsAdminWithSuccess({ query: TEST_ENTITY_QUERY, variables: { input, entityId: malwareId } });
    expect(test.data.intelligenceRequirementTestEntity.entity_id).toEqual(malwareId);
  });

  it('should refuse to create an invalid requirement', async () => {
    const input = buildInput(malwareId);
    input.ir_subject_groups[0].entity_ids = [];
    const result = await queryAsAdmin({ query: ADD_QUERY, variables: { input } });
    expect(result.errors?.length).toEqual(1);
  });

  it('should create a requirement with its defaults', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: ADD_QUERY, variables: { input: buildInput(malwareId) } });
    const ir = data.intelligenceRequirementAdd;
    irId = ir.id;
    expect(ir.name).toEqual('IR integration requirement');
    expect(ir.ir_status).toEqual('active');
    expect(ir.ir_brief_frequency).toEqual('off');
    expect(ir.ir_thresholds).toEqual([30, 70]);
    expect(ir.ir_rescan_days).toEqual(1);
    expect(ir.ir_subject_groups.length).toEqual(2);
    expect(ir.ir_subject_groups[0].entities[0].id).toEqual(malwareId);
    expect(ir.ir_scope_criteria.length).toEqual(3);
    expect(ir.ir_relevance_rules[0]).toMatchObject({ id: 'r-confidence', points: 40, required: false, enabled: true });
    expect(ir.currentUserAccessRight).toEqual('admin');
  });

  it('should read and list the requirement', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: irId } });
    expect(data.intelligenceRequirement.id).toEqual(irId);
    expect(data.intelligenceRequirement.ir_kiqs).toEqual([{ id: 'kiq-1', text: 'Which malware is tracked?', criteria_ids: ['c-members'] }]);
    const list = await queryAsAdminWithSuccess({ query: LIST_QUERY, variables: { search: 'IR integration' } });
    expect(list.data.intelligenceRequirements.edges.map((e: { node: { id: string } }) => e.node.id)).toContain(irId);
  });

  it('should compute the list indicators of the requirement', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: INDICATORS_QUERY, variables: { id: irId } });
    const ir = data.intelligenceRequirement;
    expect(ir.ir_entities_count).toBeGreaterThanOrEqual(0);
    expect(ir.ir_inbox_open_count).toEqual(ir.ir_inbox_counts.open);
    expect(ir.ir_stored_counts.entities).toBeGreaterThanOrEqual(ir.ir_entities_count);
    expect(['live', 'catching_up', 'paused']).toContain(ir.ir_processing_status.state);
    expect(ir.ir_processing_status.progress).toBeGreaterThanOrEqual(0);
    expect(ir.ir_processing_status.progress).toBeLessThanOrEqual(100);
    expect(ir.ir_processing_status.active_requirements).toBeGreaterThanOrEqual(1);
    expect(Array.isArray(ir.ir_activity)).toBe(true);
    expect(Array.isArray(ir.ir_entities_by_type)).toBe(true);
  });

  it('should test the configuration on one entity without writing', async () => {
    const variables = { input: buildInput(malwareId), entityId: malwareId, irId };
    const { data } = await queryAsAdminWithSuccess({ query: TEST_ENTITY_QUERY, variables });
    const test = data.intelligenceRequirementTestEntity;
    expect(test.entity_id).toEqual(malwareId);
    expect(test.entity_type).toEqual('Malware');
    expect(test.criteria.map((c: { criterion_id: string }) => c.criterion_id)).toContain('c-members');
    expect(test.criteria.map((c: { criterion_id: string }) => c.criterion_id)).not.toContain('c-keywords');
    expect(typeof test.verdict).toEqual('string');
    expect(test.score).toBeGreaterThanOrEqual(0);
    const stored = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: irId } });
    expect(stored.data.intelligenceRequirement.ir_scope_criteria.length).toEqual(3);
  });

  it('should refuse to test an unknown entity', async () => {
    const variables = { input: buildInput(malwareId), entityId: 'unknown-entity-id' };
    const result = await queryAsAdmin({ query: TEST_ENTITY_QUERY, variables });
    expect(result.errors?.length).toEqual(1);
  });

  it('should update the relevance of the requirement', async () => {
    const input = buildInput(malwareId, 'IR integration requirement updated');
    input.ir_relevance_rules[0].points = 60;
    const { data } = await queryAsAdminWithSuccess({ query: UPDATE_QUERY, variables: { id: irId, input } });
    expect(data.intelligenceRequirementUpdate.name).toEqual('IR integration requirement updated');
    expect(data.intelligenceRequirementUpdate.ir_relevance_rules[0].points).toEqual(60);
  });

  it('should update the scope of the requirement and convert a required rule into a condition', async () => {
    const input = buildInput(malwareId, 'IR integration requirement updated');
    input.ir_scope_criteria = input.ir_scope_criteria.slice(0, 1);
    input.ir_relevance_rules.push({
      id: 'r-required',
      name: 'Required confidence',
      applies_to_types: ['Malware'],
      points: 0,
      required: true,
      filters: { mode: 'and', filterGroups: [], filters: [{ key: ['confidence'], values: ['0'], operator: 'gte' }] },
    } as never);
    const { data } = await queryAsAdminWithSuccess({ query: UPDATE_QUERY, variables: { id: irId, input } });
    const ir = data.intelligenceRequirementUpdate;
    expect(ir.ir_scope_criteria.length).toEqual(1);
    expect(ir.ir_scope_criteria[0].conditions.map((c: { id: string }) => c.id)).toEqual(['r-required']);
    expect(ir.ir_relevance_rules.map((r: { id: string }) => r.id)).toEqual(['r-confidence']);
  });

  it('should refuse to update an unknown requirement', async () => {
    const result = await queryAsAdmin({ query: UPDATE_QUERY, variables: { id: 'unknown-ir-id', input: buildInput(malwareId) } });
    expect(result.errors?.length).toEqual(1);
  });

  it('should list the entities and the inbox of the requirement', async () => {
    const matches = await queryAsAdminWithSuccess({ query: MATCHES_QUERY, variables: { id: irId } });
    expect(Array.isArray(matches.data.intelligenceRequirementMatches.edges)).toBe(true);
    const items = await queryAsAdminWithSuccess({ query: ITEMS_QUERY, variables: { id: irId } });
    expect(Array.isArray(items.data.intelligenceRequirementItems.edges)).toBe(true);
  });

  it('should run the health checks on demand', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: HEALTH_QUERY, variables: { id: irId } });
    expect(data.intelligenceRequirementHealthCheck).toBeGreaterThanOrEqual(0);
  });

  it('should pause and resume the requirement', async () => {
    const paused = await queryAsAdminWithSuccess({ query: STATUS_QUERY, variables: { id: irId, status: 'paused' } });
    expect(paused.data.intelligenceRequirementStatusUpdate.ir_status).toEqual('paused');
    const indicators = await queryAsAdminWithSuccess({ query: INDICATORS_QUERY, variables: { id: irId } });
    expect(indicators.data.intelligenceRequirement.ir_processing_status.state).toEqual('paused');
    const active = await queryAsAdminWithSuccess({ query: STATUS_QUERY, variables: { id: irId, status: 'active' } });
    expect(active.data.intelligenceRequirementStatusUpdate.ir_status).toEqual('active');
  });

  it('should hide a requirement from a user who is not one of its authorized members', async () => {
    const input = { ...buildInput(malwareId, 'IR integration restricted'), authorized_members: [{ id: ADMIN_USER.id, access_right: 'admin' }] };
    const { data } = await queryAsAdminWithSuccess({ query: ADD_QUERY, variables: { input } });
    restrictedIrId = data.intelligenceRequirementAdd.id;
    const read = await queryAsUser(USER_PARTICIPATE, { query: READ_QUERY, variables: { id: restrictedIrId } });
    expect(read.data?.intelligenceRequirement ?? null).toBeNull();
    const list = await queryAsUser(USER_PARTICIPATE, { query: LIST_QUERY, variables: { search: 'IR integration restricted' } });
    const ids = (list.data?.intelligenceRequirements?.edges ?? []).map((e: { node: { id: string } }) => e.node.id);
    expect(ids).not.toContain(restrictedIrId);
  });

  it('should delete the requirements and everything stored for them', async () => {
    await queryAsAdminWithSuccess({ query: DELETE_QUERY, variables: { id: irId } });
    await queryAsAdminWithSuccess({ query: DELETE_QUERY, variables: { id: restrictedIrId } });
    const { data } = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: irId } });
    expect(data.intelligenceRequirement).toBeNull();
    const matches = await queryAsAdminWithSuccess({ query: MATCHES_QUERY, variables: { id: irId } });
    expect(matches.data.intelligenceRequirementMatches.edges.length).toEqual(0);
  });
});
