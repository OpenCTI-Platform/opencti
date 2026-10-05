import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR, USER_PLATFORM_ADMIN } from '../../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { elUpdate } from '../../../../src/database/engine';
import { createEntity } from '../../../../src/database/middleware';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { DECAY_MANAGER_USER } from '../../../../src/utils/access';
import { STIX_EXT_OCTI_PROVENANCE } from '../../../../src/types/stix-2-1-extensions';
import { ENTITY_TYPE_DECAY_RULE } from '../../../../src/modules/decayRule/decayRule-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../../src/modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_TRIGGER } from '../../../../src/modules/notification/notification-types';
import { applyKnowledgeDecayRules } from '../../../../src/modules/provenance/provenance-freshness';
import { PROVENANCE_BACKFILL_LOCK_KEY, restartProvenanceBackfill, runProvenanceBackfillBatch } from '../../../../src/modules/provenance/provenance-backfill';
import { lockResources } from '../../../../src/lock/master-lock';
import { wait } from '../../../../src/database/utils';
import { notifyProvenanceChange } from '../../../../src/modules/provenance/provenance-notification';
import { PROVENANCE_SIDE_CHANNEL_FIELDS, SOURCE_KIND_FEED, type StoreAssertion, type StoreConflictValue } from '../../../../src/modules/provenance/provenance-types';
import { buildProvenanceScriptParams, PROVENANCE_UPDATE_SCRIPT, writeProvenanceUpdate } from '../../../../src/modules/provenance/provenance-write';
import type { BasicStoreBase } from '../../../../src/types/store';
import { checkRetentionRule } from '../../../../src/modules/retentionRules/retentionRules-domain';
import { RetentionRuleScope, RetentionUnit } from '../../../../src/generated/graphql';
import { up as enableRecommendedRelationshipTypes } from '../../../../src/migrations/1791221292579-provenance-recommended-relationship-types';

const MALWARE_NAME = 'Provenance malware';

const MALWARE_ADD = gql`
  mutation MalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) { id standard_id }
  }
`;

const MALWARE_PROVENANCE = gql`
  query MalwareProvenance($id: String!) {
    malware(id: $id) {
      id
      description
      updated_at
      corroboration_count
      single_sourced
      has_conflicts
      last_asserted_at
      freshness_days
      freshness_stale
      x_opencti_assertions { source_id source_kind source_name assert_count confidence first_asserted_at last_asserted_at }
      x_opencti_conflicts { field values { value_hash display adoptable source_id source_name } }
      toStix
    }
  }
`;

const CONFLICT_ADOPT = gql`
  mutation ConflictAdopt($id: ID!, $field: String!, $hash: String!) {
    provenanceConflictAdopt(id: $id, field: $field, value_hash: $hash) { ... on StixCoreObject { id } }
  }
`;

const CONFLICT_DISMISS = gql`
  mutation ConflictDismiss($id: ID!, $field: String!, $hash: String!) {
    provenanceConflictDismiss(id: $id, field: $field, value_hash: $hash) { ... on StixCoreObject { id } }
  }
`;

const ASSERT = gql`
  mutation ProvenanceAssert($id: ID!) {
    provenanceAssert(id: $id) { ... on StixCoreObject { id } ... on StixCoreRelationship { id } }
  }
`;

const STIX_CORE_OBJECTS = gql`
  query StixCoreObjects($filters: FilterGroup, $search: String, $orderBy: StixCoreObjectsOrdering) {
    stixCoreObjects(filters: $filters, search: $search, orderBy: $orderBy, orderMode: asc, first: 50) {
      edges { node { id } }
    }
  }
`;

const RELATION_PROVENANCE = gql`
  query RelationProvenance($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      description
      corroboration_count
      freshness_stale
      procedures { text source_id }
    }
  }
`;

const KNOWLEDGE_RULE_ADD = gql`
  mutation KnowledgeDecayRuleAdd($input: KnowledgeDecayRuleAddInput!) {
    knowledgeDecayRuleAdd(input: $input) { id target_scope target_types freshness_policy stale_after_days decay_lifetime appliedIndicatorsCount }
  }
`;

const DECAY_RULE = gql`
  query DecayRule($id: String!) {
    decayRule(id: $id) { id active stale_after_days staleElementsCount target_scope }
  }
`;

const KNOWLEDGE_DECAY_RULES_INVOLVED = gql`
  query KnowledgeDecayRulesInvolved {
    knowledgeDecayRulesInvolvedCount
  }
`;

const DECAY_RULES = gql`
  query DecayRules($filters: FilterGroup) {
    decayRules(filters: $filters, first: 50) { edges { node { id name built_in active target_scope } } }
  }
`;

const DECAY_RULE_PATCH = gql`
  mutation DecayRulePatch($id: ID!, $input: [EditInput!]!) {
    decayRuleFieldPatch(id: $id, input: $input) { id active stale_after_days }
  }
`;

const DECAY_RULE_DELETE = gql`
  mutation DecayRuleDelete($id: ID!) { decayRuleDelete(id: $id) }
`;

const RELATIONSHIP_TRACKING = gql`
  query RelationshipTracking {
    entitySettingByType(targetType: "stix-core-relationship") {
      id
      provenance_untracked_types
      provenance_relationship_tracking { relationship_type tracked recommended }
    }
  }
`;
const RELATIONSHIP_TRACKING_EDIT = gql`
  mutation RelationshipTrackingEdit($types: [String!]!, $tracked: Boolean!) {
    provenanceRelationshipTrackingEdit(relationship_types: $types, tracked: $tracked) { id }
  }
`;
type RelationshipTracking = { relationship_type: string; tracked: boolean; recommended: boolean };
const trackingByType = (setting: { provenance_relationship_tracking: RelationshipTracking[] }) => {
  return new Map(setting.provenance_relationship_tracking.map((entry) => [entry.relationship_type, entry]));
};
const setRelationshipTracking = async (types: string[], tracked: boolean) => {
  await queryAsAdminWithSuccess({ query: RELATIONSHIP_TRACKING_EDIT, variables: { types, tracked } });
  resetCacheForEntity(ENTITY_TYPE_ENTITY_SETTING);
};

const loadMalware = async (id: string) => {
  const result = await queryAsAdminWithSuccess({ query: MALWARE_PROVENANCE, variables: { id } });
  return result.data?.malware;
};

const loadRelation = async (id: string) => {
  const result = await queryAsAdminWithSuccess({ query: RELATION_PROVENANCE, variables: { id } });
  return result.data?.stixCoreRelationship;
};

const DAY_IN_MS = 24 * 60 * 60 * 1000;
// Test helper: move the last assertion of an element in the past
const ageElement = async (id: string, days: number) => {
  const element = await internalLoadById<BasicStoreBase & { _index: string }>(testContext, ADMIN_USER, id);
  const date = new Date(Date.now() - days * DAY_IN_MS).toISOString();
  await elUpdate(testContext, element._index, element.internal_id, {
    script: { source: 'ctx._source.last_asserted_at = params.date; for (a in ctx._source.x_opencti_assertions) { a.last_asserted_at = params.date; }', params: { date } },
  });
};

describe('Provenance: every fact knows who said it', () => {
  let malwareId = '';
  let boundedMalwareId = '';
  let attackPatternId = '';
  let usesId = '';
  let ruleId = '';
  let takeoverRuleId = '';
  let triggerId = '';
  const retentionMalwareIds: string[] = [];

  afterAll(async () => {
    if (ruleId) {
      await queryAsAdminWithSuccess({ query: DECAY_RULE_DELETE, variables: { id: ruleId } });
    }
    if (takeoverRuleId) {
      await queryAsAdminWithSuccess({ query: DECAY_RULE_DELETE, variables: { id: takeoverRuleId } });
    }
    if (triggerId) {
      await queryAsAdminWithSuccess({ query: gql`mutation TriggerDelete($id: ID!) { triggerKnowledgeDelete(id: $id) }`, variables: { id: triggerId } });
    }
    const deleteQuery = gql`mutation Delete($id: ID!) { stixDomainObjectEdit(id: $id) { delete } }`;
    if (malwareId) {
      await queryAsAdminWithSuccess({ query: deleteQuery, variables: { id: malwareId } });
    }
    if (boundedMalwareId) {
      await queryAsAdminWithSuccess({ query: deleteQuery, variables: { id: boundedMalwareId } });
    }
    if (attackPatternId) {
      await queryAsAdminWithSuccess({ query: deleteQuery, variables: { id: attackPatternId } });
    }
    for (let index = 0; index < retentionMalwareIds.length; index += 1) {
      await queryAsAdminWithSuccess({ query: deleteQuery, variables: { id: retentionMalwareIds[index] } });
    }
  });

  it('should record the assertion of the creating source', async () => {
    const created = await queryAsAdminWithSuccess({
      query: MALWARE_ADD,
      variables: { input: { name: MALWARE_NAME, description: 'Initial description', confidence: 80, is_family: false } },
    });
    malwareId = created.data?.malwareAdd.id;
    const malware = await loadMalware(malwareId);
    expect(malware.corroboration_count).toEqual(1);
    expect(malware.single_sourced).toEqual(true);
    expect(malware.has_conflicts).toEqual(false);
    expect(malware.freshness_days).toEqual(0);
    expect(malware.x_opencti_assertions).toHaveLength(1);
    expect(malware.x_opencti_assertions[0]).toMatchObject({ source_id: ADMIN_USER.id, source_kind: 'user', assert_count: 1, confidence: 80 });
  });

  it('should never let a client inject provenance', async () => {
    const forgedAssertion = { source_id: 'forged', source_kind: 'feed', source_name: 'Forged', first_asserted_at: '2020-01-01T00:00:00.000Z', last_asserted_at: '2020-01-01T00:00:00.000Z', assert_count: 1000, confidence: 100, work_id: null };
    await createEntity(testContext, ADMIN_USER, {
      name: MALWARE_NAME,
      confidence: 80,
      is_family: false,
      corroboration_count: 99,
      single_sourced: false,
      x_opencti_assertions: [forgedAssertion],
    }, ENTITY_TYPE_MALWARE);
    const malware = await loadMalware(malwareId);
    expect(malware.corroboration_count).toEqual(1);
    expect(malware.single_sourced).toEqual(true);
    expect(malware.x_opencti_assertions.map((assertion: { source_id: string }) => assertion.source_id)).toEqual([ADMIN_USER.id]);
  });

  it('should corroborate and keep the losing value as a conflict on upsert', async () => {
    await queryAsUserWithSuccess(USER_EDITOR, {
      query: MALWARE_ADD,
      variables: { input: { name: MALWARE_NAME, description: 'Editor description', confidence: 90, is_family: false } },
    });
    const malware = await loadMalware(malwareId);
    expect(malware.corroboration_count).toEqual(2);
    expect(malware.single_sourced).toEqual(false);
    expect(malware.description).toEqual('Editor description');
    expect(malware.has_conflicts).toEqual(true);
    const conflict = malware.x_opencti_conflicts.find((entry: { field: string }) => entry.field === 'description');
    expect(conflict.values).toHaveLength(1);
    expect(conflict.values[0]).toMatchObject({ display: 'Initial description', adoptable: true, source_id: ADMIN_USER.id });
    // The re-assertion of an identical value only touches provenance (no update)
    await queryAsUserWithSuccess(USER_EDITOR, {
      query: MALWARE_ADD,
      variables: { input: { name: MALWARE_NAME, description: 'Editor description', confidence: 90, is_family: false } },
    });
    const reasserted = await loadMalware(malwareId);
    const editorAssertion = reasserted.x_opencti_assertions.find((assertion: { source_id: string }) => assertion.source_id !== ADMIN_USER.id);
    expect(editorAssertion.assert_count).toEqual(2);
    expect(reasserted.corroboration_count).toEqual(2);
    // Provenance is a side channel: the element itself is not updated
    expect(reasserted.updated_at).toEqual(malware.updated_at);
  });

  it('should export the provenance summary in STIX without source names', async () => {
    const malware = await loadMalware(malwareId);
    const stix = JSON.parse(malware.toStix);
    const extension = stix.extensions[STIX_EXT_OCTI_PROVENANCE];
    expect(extension).toMatchObject({ extension_type: 'property-extension', corroboration_count: 2, single_sourced: false, has_conflicts: true });
    expect(extension.conflicting_fields).toEqual(['description']);
    expect(extension.sources_by_kind.user).toEqual(2);
    expect(JSON.stringify(extension)).not.toContain(ADMIN_USER.name);
  });

  it('should keep counting the sources whose detail no longer fits in the bounded assertions', async () => {
    const created = await createEntity(testContext, ADMIN_USER, { name: `${MALWARE_NAME} bounded`, confidence: 50, is_family: false }, ENTITY_TYPE_MALWARE);
    boundedMalwareId = created.id;
    const element = await internalLoadById<BasicStoreBase & { _index: string }>(testContext, ADMIN_USER, boundedMalwareId);
    const feedAssertion = (id: string, first: string, last: string): StoreAssertion => ({
      source_id: id, source_kind: SOURCE_KIND_FEED, source_name: `Feed ${id}`, first_asserted_at: first, last_asserted_at: last, assert_count: 1, confidence: 50, work_id: null,
    });
    const params = buildProvenanceScriptParams({
      assertions: [
        feedAssertion('feed-earliest', '2020-01-01T00:00:00.000Z', '2020-01-02T00:00:00.000Z'),
        feedAssertion('feed-middle', '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z'),
        feedAssertion('feed-recent', '2026-09-01T00:00:00.000Z', '2026-09-02T00:00:00.000Z'),
      ],
    });
    // Detail bound lowered to 2 to exercise the eviction of the stored script
    await elUpdate(testContext, element._index, element.internal_id, {
      script: { source: PROVENANCE_UPDATE_SCRIPT, lang: 'painless', params: { ...params, max_assertions: 2 } },
    });
    const malware = await loadMalware(boundedMalwareId);
    // The creating user and three feeds are all counted; the details keep the earliest and the most recent source
    expect(malware.corroboration_count).toEqual(4);
    expect(malware.single_sourced).toEqual(false);
    expect(malware.x_opencti_assertions.map((assertion: { source_id: string }) => assertion.source_id).sort())
      .toEqual([ADMIN_USER.id, 'feed-earliest'].sort());
    const stix = JSON.parse(malware.toStix);
    expect(stix.extensions[STIX_EXT_OCTI_PROVENANCE]).toMatchObject({ corroboration_count: 4, first_asserted: '2020-01-01T00:00:00.000Z' });
  });

  it('should filter and sort on corroboration and freshness', async () => {
    const search = async (filters: object) => {
      const result = await queryAsAdminWithSuccess({ query: STIX_CORE_OBJECTS, variables: { search: MALWARE_NAME, filters } });
      return result.data?.stixCoreObjects.edges.map((edge: { node: { id: string } }) => edge.node.id);
    };
    const filter = (key: string, values: string[], operator = 'eq') => ({ mode: 'and', filters: [{ key: [key], values, operator }], filterGroups: [] });
    expect(await search(filter('corroboration_count', ['2'], 'gte'))).toContain(malwareId);
    expect(await search(filter('corroboration_count', ['3'], 'gte'))).not.toContain(malwareId);
    expect(await search(filter('single_sourced', ['true']))).not.toContain(malwareId);
    expect(await search(filter('has_conflicts', ['true']))).toContain(malwareId);
    expect(await search(filter('freshness_days', ['1'], 'lte'))).toContain(malwareId);
    expect(await search(filter('freshness_days', ['10'], 'gte'))).not.toContain(malwareId);
    expect(await search(filter('assertion_source_ids', [ADMIN_USER.id]))).toContain(malwareId);
    const sorted = await queryAsAdminWithSuccess({ query: STIX_CORE_OBJECTS, variables: { search: MALWARE_NAME, orderBy: 'freshness_days' } });
    expect(sorted.data?.stixCoreObjects.edges.length).toBeGreaterThan(0);
  });

  it('should adopt and dismiss conflicting values', async () => {
    const malware = await loadMalware(malwareId);
    const proposal = malware.x_opencti_conflicts.find((entry: { field: string }) => entry.field === 'description').values[0];
    await queryAsAdminWithSuccess({ query: CONFLICT_ADOPT, variables: { id: malwareId, field: 'description', hash: proposal.value_hash } });
    const adopted = await loadMalware(malwareId);
    expect(adopted.description).toEqual('Initial description');
    const conflict = adopted.x_opencti_conflicts.find((entry: { field: string }) => entry.field === 'description');
    expect(conflict.values.map((value: { display: string }) => value.display)).toEqual(['Editor description']);
    await queryAsAdminWithSuccess({ query: CONFLICT_DISMISS, variables: { id: malwareId, field: 'description', hash: conflict.values[0].value_hash } });
    const dismissed = await loadMalware(malwareId);
    expect(dismissed.has_conflicts).toEqual(false);
    expect(dismissed.x_opencti_conflicts ?? []).toEqual([]);
  });

  it('should keep the attribution of every source proposing the same conflicting value', async () => {
    const created = await createEntity(testContext, ADMIN_USER, { name: `${MALWARE_NAME} shared proposal`, confidence: 50, is_family: false }, ENTITY_TYPE_MALWARE);
    retentionMalwareIds.push(created.id);
    const element = await internalLoadById<BasicStoreBase & { _index: string }>(testContext, ADMIN_USER, created.id);
    const proposal = (sourceId: string, at: string): StoreConflictValue => ({
      value_hash: 'shared-hash', display: 'Shared description', value: '"Shared description"', source_id: sourceId, source_kind: SOURCE_KIND_FEED, source_name: `Feed ${sourceId}`, confidence: 50, last_asserted_at: at,
    });
    const params = buildProvenanceScriptParams({
      conflictsAdd: [
        { field: 'description', value: proposal('feed-a', '2026-09-01T00:00:00.000Z') },
        { field: 'description', value: proposal('feed-b', '2026-09-02T00:00:00.000Z') },
        { field: 'description', value: proposal('feed-a', '2026-09-03T00:00:00.000Z') },
      ],
    });
    await elUpdate(testContext, element._index, element.internal_id, { script: { source: PROVENANCE_UPDATE_SCRIPT, lang: 'painless', params } });
    const malware = await loadMalware(created.id);
    const conflict = malware.x_opencti_conflicts.find((entry: { field: string }) => entry.field === 'description');
    // One proposal per source: the repeated proposal of feed-a refreshes its own record
    expect(conflict.values.map((value: { value_hash: string; source_id: string }) => `${value.value_hash}:${value.source_id}`).sort()).toEqual([
      'shared-hash:feed-a',
      'shared-hash:feed-b',
    ]);
    // Retained provenance is not curated while the type is no longer tracked
    const setting = await queryAsAdminWithSuccess({ query: gql`query { entitySettingByType(targetType: "Malware") { id } }` });
    const TRACKING_PATCH = gql`mutation Patch($ids: [ID!]!, $input: [EditInput!]!) { entitySettingsFieldPatch(ids: $ids, input: $input) { id } }`;
    const setTracking = async (value: string) => {
      await queryAsAdminWithSuccess({ query: TRACKING_PATCH, variables: { ids: [setting.data?.entitySettingByType.id], input: [{ key: 'provenance_tracking', value: [value] }] } });
      resetCacheForEntity(ENTITY_TYPE_ENTITY_SETTING);
    };
    await setTracking('false');
    try {
      await queryAsAdminWithError(
        { query: CONFLICT_DISMISS, variables: { id: created.id, field: 'description', hash: 'shared-hash' } },
        'Provenance is not tracked for this element',
      );
    } finally {
      await setTracking('true');
    }
    // Dismissing the value removes the proposal of every source
    await queryAsAdminWithSuccess({ query: CONFLICT_DISMISS, variables: { id: created.id, field: 'description', hash: 'shared-hash' } });
    const dismissed = await loadMalware(created.id);
    expect(dismissed.has_conflicts).toEqual(false);
  });

  it('should only count the conflicts older than the retention date in the retention preview', async () => {
    const withConflict = async (name: string, lastAssertedAt: string) => {
      const created = await createEntity(testContext, ADMIN_USER, { name, confidence: 50, is_family: false }, ENTITY_TYPE_MALWARE);
      const element = await internalLoadById<BasicStoreBase & { _index: string }>(testContext, ADMIN_USER, created.id);
      const conflicts = [{
        field: 'description',
        values: [{ value_hash: `hash-${name}`, display: 'Other description', value: '"Other description"', source_id: 'feed-retention', source_kind: SOURCE_KIND_FEED, source_name: 'Feed retention', confidence: 50, last_asserted_at: lastAssertedAt }],
      }];
      await elUpdate(testContext, element._index, element.internal_id, {
        script: { source: 'ctx._source.x_opencti_conflicts = params.conflicts; ctx._source.has_conflicts = true;', lang: 'painless', params: { conflicts } },
      });
      retentionMalwareIds.push(created.id);
      return created.id;
    };
    const freshId = await withConflict(`${MALWARE_NAME} fresh conflict`, new Date().toISOString());
    const outdatedId = await withConflict(`${MALWARE_NAME} outdated conflict`, '2020-01-01T00:00:00.000Z');
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: ['internal_id'], values: [freshId, outdatedId] }], filterGroups: [] });
    const count = await checkRetentionRule(testContext, {
      name: 'Outdated conflicts', filters, max_retention: 30, retention_unit: RetentionUnit.Days, scope: RetentionRuleScope.Conflicts,
    });
    expect(count).toEqual(1);
  });

  it('should preserve distinct procedures on uses relationships', async () => {
    const attackPattern = await queryAsAdminWithSuccess({
      query: gql`mutation AttackPatternAdd($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) { id } }`,
      variables: { input: { name: 'Provenance attack pattern', x_mitre_id: 'T9999' } },
    });
    attackPatternId = attackPattern.data?.attackPatternAdd.id;
    const addUses = gql`mutation RelationAdd($input: StixCoreRelationshipAddInput) { stixCoreRelationshipAdd(input: $input) { id } }`;
    const created = await queryAsAdminWithSuccess({
      query: addUses,
      variables: { input: { fromId: malwareId, toId: attackPatternId, relationship_type: 'uses', description: 'Spearphishing attachment', confidence: 80 } },
    });
    usesId = created.data?.stixCoreRelationshipAdd.id;
    await queryAsUserWithSuccess(USER_EDITOR, {
      query: addUses,
      variables: { input: { fromId: malwareId, toId: attackPatternId, relationship_type: 'uses', description: 'Spearphishing link to a credential harvesting page', confidence: 90 } },
    });
    const relation = await loadRelation(usesId);
    expect(relation.corroboration_count).toEqual(2);
    expect(relation.procedures.map((procedure: { text: string }) => procedure.text).sort()).toEqual([
      'Spearphishing attachment',
      'Spearphishing link to a credential harvesting page',
    ]);
    // Default policy keeps the longest procedure as description
    expect(relation.description).toEqual('Spearphishing link to a credential harvesting page');
    // The same procedure asserted by another source keeps the attribution of both sources
    await queryAsUserWithSuccess(USER_EDITOR, {
      query: addUses,
      variables: { input: { fromId: malwareId, toId: attackPatternId, relationship_type: 'uses', description: 'Spearphishing attachment', confidence: 90 } },
    });
    const attributed = await loadRelation(usesId);
    const attachmentSources = attributed.procedures
      .filter((procedure: { text: string }) => procedure.text === 'Spearphishing attachment')
      .map((procedure: { source_id: string }) => procedure.source_id);
    expect(attachmentSources).toHaveLength(2);
    expect(attachmentSources).toContain(ADMIN_USER.id);
  });

  it('should flag stale knowledge with knowledge decay rules and reset it on re-assertion', async () => {
    const created = await queryAsAdminWithSuccess({
      query: KNOWLEDGE_RULE_ADD,
      variables: {
        input: { name: 'Stale uses for tests', order: 100, active: true, target_scope: 'relationship', target_types: ['uses'], freshness_policy: 'flag', stale_after_days: 30 },
      },
    });
    ruleId = created.data?.knowledgeDecayRuleAdd.id;
    expect(created.data?.knowledgeDecayRuleAdd).toMatchObject({ target_scope: 'relationship', target_types: ['uses'], freshness_policy: 'flag', stale_after_days: 30, appliedIndicatorsCount: 0 });
    await ageElement(usesId, 60);
    resetCacheForEntity(ENTITY_TYPE_DECAY_RULE);
    const run = await applyKnowledgeDecayRules(testContext, DECAY_MANAGER_USER, { batchSize: 100 });
    expect(run.flagged).toBeGreaterThanOrEqual(1);
    expect(run.errors).toEqual(0);
    expect((await loadRelation(usesId)).freshness_stale).toEqual(true);
    const rule = await queryAsAdminWithSuccess({ query: DECAY_RULE, variables: { id: ruleId } });
    expect(rule.data?.decayRule.staleElementsCount).toEqual(1);
    // Counted for any user with knowledge access, without the customization capability that lists the rules
    const involved = await queryAsUserWithSuccess(USER_EDITOR, { query: KNOWLEDGE_DECAY_RULES_INVOLVED });
    expect(involved.data?.knowledgeDecayRulesInvolvedCount).toBeGreaterThanOrEqual(1);
    // A longer delay makes the knowledge fresh again under the new configuration
    await queryAsAdminWithSuccess({ query: DECAY_RULE_PATCH, variables: { id: ruleId, input: [{ key: 'stale_after_days', value: ['90'] }] } });
    expect((await loadRelation(usesId)).freshness_stale).toEqual(false);
    resetCacheForEntity(ENTITY_TYPE_DECAY_RULE);
    await applyKnowledgeDecayRules(testContext, DECAY_MANAGER_USER, { batchSize: 100 });
    expect((await loadRelation(usesId)).freshness_stale).toEqual(false);
    // Flagged again with a shorter delay, then re-asserted by an analyst
    await queryAsAdminWithSuccess({ query: DECAY_RULE_PATCH, variables: { id: ruleId, input: [{ key: 'stale_after_days', value: ['30'] }] } });
    resetCacheForEntity(ENTITY_TYPE_DECAY_RULE);
    await applyKnowledgeDecayRules(testContext, DECAY_MANAGER_USER, { batchSize: 100 });
    expect((await loadRelation(usesId)).freshness_stale).toEqual(true);
    await queryAsUserWithSuccess(USER_EDITOR, { query: ASSERT, variables: { id: usesId } });
    expect((await loadRelation(usesId)).freshness_stale).toEqual(false);
  });

  it('should let a higher priority knowledge decay rule take over flagged knowledge', async () => {
    const staleCount = async (id: string) => (await queryAsAdminWithSuccess({ query: DECAY_RULE, variables: { id } })).data?.decayRule.staleElementsCount;
    await ageElement(usesId, 60);
    resetCacheForEntity(ENTITY_TYPE_DECAY_RULE);
    await applyKnowledgeDecayRules(testContext, DECAY_MANAGER_USER, { batchSize: 100 });
    expect(await staleCount(ruleId)).toEqual(1);
    const created = await queryAsAdminWithSuccess({
      query: KNOWLEDGE_RULE_ADD,
      variables: {
        input: { name: 'Higher priority stale uses for tests', order: 200, active: true, target_scope: 'relationship', target_types: ['uses'], freshness_policy: 'flag', stale_after_days: 30 },
      },
    });
    takeoverRuleId = created.data?.knowledgeDecayRuleAdd.id;
    expect((await loadRelation(usesId)).freshness_stale).toEqual(false);
    expect(await staleCount(ruleId)).toEqual(0);
    resetCacheForEntity(ENTITY_TYPE_DECAY_RULE);
    await applyKnowledgeDecayRules(testContext, DECAY_MANAGER_USER, { batchSize: 100 });
    expect((await loadRelation(usesId)).freshness_stale).toEqual(true);
    expect(await staleCount(takeoverRuleId)).toEqual(1);
    expect(await staleCount(ruleId)).toEqual(0);
    // Moved below the first rule, the rule releases what it flagged and the first rule takes it back
    await queryAsAdminWithSuccess({ query: DECAY_RULE_PATCH, variables: { id: takeoverRuleId, input: [{ key: 'order', value: ['50'] }] } });
    expect((await loadRelation(usesId)).freshness_stale).toEqual(false);
    expect(await staleCount(takeoverRuleId)).toEqual(0);
    resetCacheForEntity(ENTITY_TYPE_DECAY_RULE);
    await applyKnowledgeDecayRules(testContext, DECAY_MANAGER_USER, { batchSize: 100 });
    expect((await loadRelation(usesId)).freshness_stale).toEqual(true);
    expect(await staleCount(ruleId)).toEqual(1);
    expect(await staleCount(takeoverRuleId)).toEqual(0);
    await queryAsUserWithSuccess(USER_EDITOR, { query: ASSERT, variables: { id: usesId } });
  });

  it('should ship built-in knowledge decay rules disabled and only allow their activation', async () => {
    const rules = await queryAsAdminWithSuccess({
      query: DECAY_RULES,
      variables: { filters: { mode: 'and', filters: [{ key: ['target_scope'], values: ['relationship', 'entity'] }, { key: ['built_in'], values: ['true'] }], filterGroups: [] } },
    });
    const builtIn = rules.data?.decayRules.edges.map((edge: { node: any }) => edge.node);
    expect(builtIn.length).toEqual(3);
    builtIn.forEach((rule: { active: boolean }) => expect(rule.active).toEqual(false));
    const { id } = builtIn[0];
    const activated = await queryAsAdminWithSuccess({ query: DECAY_RULE_PATCH, variables: { id, input: [{ key: 'active', value: ['true'] }] } });
    expect(activated.data?.decayRuleFieldPatch.active).toEqual(true);
    await queryAsAdminWithSuccess({ query: DECAY_RULE_PATCH, variables: { id, input: [{ key: 'active', value: ['false'] }] } });
    await queryAsAdminWithError(
      { query: DECAY_RULE_PATCH, variables: { id, input: [{ key: 'stale_after_days', value: ['1'] }] } },
      `Built-in knowledge decay rule ${id} can only be activated or deactivated`,
    );
  });

  it('should keep the provenance entity settings to the customization capability', async () => {
    const setting = await queryAsAdminWithSuccess({ query: gql`query { entitySettingByType(targetType: "Malware") { id } }` });
    const PATCH = gql`mutation Patch($ids: [ID!]!, $input: [EditInput!]!) { entitySettingsFieldPatch(ids: $ids, input: $input) { id provenance_tracking } }`;
    const keys = ['provenance_tracking', 'procedures_preservation', 'procedures_description_policy'];
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      await queryAsUserIsExpectedForbidden(USER_PLATFORM_ADMIN, {
        query: PATCH,
        variables: { ids: [setting.data?.entitySettingByType.id], input: [{ key, value: [key === 'procedures_description_policy' ? 'longest' : 'false'] }] },
      });
    }
    const unchanged = await queryAsAdminWithSuccess({ query: gql`query { entitySettingByType(targetType: "Malware") { provenance_tracking } }` });
    expect(unchanged.data?.entitySettingByType.provenance_tracking).toEqual(true);
  });

  it('should track provenance per relationship type, the recommended types out of the box', async () => {
    const initial = await queryAsAdminWithSuccess({ query: RELATIONSHIP_TRACKING });
    const tracking = trackingByType(initial.data?.entitySettingByType);
    expect(tracking.get('uses')).toEqual({ relationship_type: 'uses', tracked: true, recommended: true });
    expect(tracking.get('targets')).toEqual({ relationship_type: 'targets', tracked: true, recommended: true });
    expect(tracking.get('attributed-to')).toEqual({ relationship_type: 'attributed-to', tracked: true, recommended: true });
    expect(tracking.get('indicates')?.recommended).toEqual(false);
    const relatedTo = gql`mutation RelationAdd($input: StixCoreRelationshipAddInput) { stixCoreRelationshipAdd(input: $input) { id } }`;
    await setRelationshipTracking(['related-to'], false);
    try {
      const updated = await queryAsAdminWithSuccess({ query: RELATIONSHIP_TRACKING });
      const afterEdit = trackingByType(updated.data?.entitySettingByType);
      expect(afterEdit.get('related-to')?.tracked).toEqual(false);
      expect(afterEdit.get('uses')?.tracked).toEqual(true);
      expect(updated.data?.entitySettingByType.provenance_untracked_types).toContain('related-to');
      expect(updated.data?.entitySettingByType.provenance_untracked_types).not.toContain('uses');
      // The writer consults the switch of the relationship type
      const created = await queryAsAdminWithSuccess({
        query: relatedTo,
        variables: { input: { fromId: malwareId, toId: attackPatternId, relationship_type: 'related-to', confidence: 80 } },
      });
      const untracked = await loadRelation(created.data?.stixCoreRelationshipAdd.id);
      expect(untracked.corroboration_count).toBeNull();
      const uses = await loadRelation(usesId);
      expect(uses.corroboration_count).toEqual(2);
    } finally {
      await setRelationshipTracking(['related-to'], true);
    }
    // Relationship types only, and only with the customization capability, through either mutation
    await queryAsAdminWithError({ query: RELATIONSHIP_TRACKING_EDIT, variables: { types: ['Malware'], tracked: true } }, 'Provenance tracking is configured on relationship types');
    await queryAsUserIsExpectedForbidden(USER_PLATFORM_ADMIN, { query: RELATIONSHIP_TRACKING_EDIT, variables: { types: ['uses'], tracked: false } });
    const PATCH = gql`mutation Patch($ids: [ID!]!, $input: [EditInput!]!) { entitySettingsFieldPatch(ids: $ids, input: $input) { id } }`;
    await queryAsUserIsExpectedForbidden(USER_PLATFORM_ADMIN, {
      query: PATCH,
      variables: { ids: [initial.data?.entitySettingByType.id], input: [{ key: 'provenance_relationship_types', value: ['{"uses":false}'] }] },
    });
    await queryAsAdminWithError({
      query: PATCH,
      variables: { ids: [initial.data?.entitySettingByType.id], input: [{ key: 'provenance_relationship_types', value: ['{"Malware":true}'] }] },
    }, 'The JSON schema is not valid');
    const settled = trackingByType((await queryAsAdminWithSuccess({ query: RELATIONSHIP_TRACKING })).data?.entitySettingByType);
    expect(settled.get('uses')?.tracked).toEqual(true);
  });

  it('should enable the recommended relationship types of an existing platform by migration, once', async () => {
    const settingId = (await queryAsAdminWithSuccess({ query: RELATIONSHIP_TRACKING })).data?.entitySettingByType.id;
    const storedTypes = () => internalLoadById<BasicStoreBase & { _index: string; provenance_relationship_types?: string }>(testContext, ADMIN_USER, settingId);
    const runMigration = () => new Promise<void>((resolve, reject) => {
      enableRecommendedRelationshipTypes((error?: Error) => (error ? reject(error) : resolve())).catch(reject);
    });
    // A platform upgraded from a version without per relationship type tracking
    const before = await storedTypes();
    await elUpdate(testContext, before._index, before.internal_id, { script: { source: "ctx._source.remove('provenance_relationship_types')", lang: 'painless' } });
    expect((await storedTypes()).provenance_relationship_types).toBeUndefined();
    await runMigration();
    expect(JSON.parse((await storedTypes()).provenance_relationship_types ?? '{}')).toEqual({ uses: true, targets: true, 'attributed-to': true });
    resetCacheForEntity(ENTITY_TYPE_ENTITY_SETTING);
    // A type turned off afterwards stays off when the migration is replayed
    await setRelationshipTracking(['uses'], false);
    try {
      await runMigration();
      expect(JSON.parse((await storedTypes()).provenance_relationship_types ?? '{}').uses).toEqual(false);
    } finally {
      await setRelationshipTracking(['uses'], true);
    }
  });

  it('should restart the backfill only once the batch in progress released its lock', async () => {
    const batchLock = await lockResources([PROVENANCE_BACKFILL_LOCK_KEY], { retryCount: 0 });
    let restartedAt = 0;
    const restart = restartProvenanceBackfill(testContext).then((state) => {
      restartedAt = Date.now();
      return state;
    });
    await wait(1000);
    const releasedAt = Date.now();
    await batchLock.unlock();
    expect((await restart).status).toEqual('pending');
    expect(restartedAt).toBeGreaterThanOrEqual(releasedAt);
  });

  it('should rebuild the provenance of existing knowledge with the backfill', async () => {
    const element = await internalLoadById<BasicStoreBase & { _index: string }>(testContext, ADMIN_USER, malwareId);
    await elUpdate(testContext, element._index, element.internal_id, {
      script: { source: 'for (field in params.fields) { ctx._source.remove(field); }', params: { fields: PROVENANCE_SIDE_CHANNEL_FIELDS } },
    });
    expect((await loadMalware(malwareId)).corroboration_count).toBeNull();
    const restarted = await queryAsAdminWithSuccess({ query: gql`mutation { provenanceBackfillRestart { status processed } }` });
    expect(restarted.data?.provenanceBackfillRestart).toMatchObject({ status: 'pending', processed: 0 });
    let state = await runProvenanceBackfillBatch(testContext, { batchSize: 5000 });
    for (let iteration = 0; iteration < 20 && state?.status !== 'completed'; iteration += 1) {
      state = await runProvenanceBackfillBatch(testContext, { batchSize: 5000 });
    }
    expect(state?.status).toEqual('completed');
    expect(state?.errors).toEqual(0);
    const backfilled = await loadMalware(malwareId);
    expect(backfilled.corroboration_count).toBeGreaterThanOrEqual(1);
    expect(backfilled.x_opencti_assertions.map((assertion: { source_id: string }) => assertion.source_id)).toContain(ADMIN_USER.id);
    const status = await queryAsAdminWithSuccess({ query: gql`query { provenanceBackfill { status processed expected errors } }` });
    expect(status.data?.provenanceBackfill).toMatchObject({ status: 'completed', errors: 0 });
    expect(status.data?.provenanceBackfill.processed).toBeGreaterThan(0);
  });

  it('should report a conflict value as new only to the write that created it, even from a stale element', async () => {
    const element = await internalLoadById<BasicStoreBase & { _index: string }>(testContext, ADMIN_USER, malwareId);
    const value: StoreConflictValue = {
      value_hash: 'provenance-test-concurrent-hash',
      display: 'Concurrent description',
      value: JSON.stringify('Concurrent description'),
      source_id: 'provenance-test-concurrent-source',
      source_kind: SOURCE_KIND_FEED,
      source_name: 'Concurrent source',
      confidence: 50,
      last_asserted_at: new Date().toISOString(),
    };
    const update = { conflictsAdd: [{ field: 'description', value }] };
    const first = await writeProvenanceUpdate(testContext, element, update, { withCurrent: true });
    const second = await writeProvenanceUpdate(testContext, element, update, { withCurrent: true });
    expect(first.newConflicts).toHaveLength(1);
    expect(second.newConflicts).toHaveLength(0);
    const stored = (second.current?.x_opencti_conflicts ?? []).find((conflict) => conflict.field === 'description');
    expect(stored?.values.filter((entry) => entry.value_hash === value.value_hash)).toHaveLength(1);
    await writeProvenanceUpdate(testContext, element, { conflictsRemove: [{ field: 'description', value_hash: value.value_hash }] }, { refresh: true });
  });

  it('should notify corroboration triggers when the threshold is reached', async () => {
    const trigger = await queryAsAdminWithSuccess({
      query: gql`mutation TriggerAdd($input: TriggerLiveAddInput!) { triggerKnowledgeLiveAdd(input: $input) { id event_types corroboration_threshold } }`,
      variables: {
        input: {
          name: 'Corroborated malwares',
          event_types: ['corroboration', 'conflict'],
          instance_trigger: false,
          filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Malware'] }], filterGroups: [] }),
        },
      },
    });
    triggerId = trigger.data?.triggerKnowledgeLiveAdd.id;
    expect(trigger.data?.triggerKnowledgeLiveAdd).toMatchObject({ event_types: ['corroboration', 'conflict'], corroboration_threshold: 2 });
    resetCacheForEntity(ENTITY_TYPE_TRIGGER);
    expect(await notifyProvenanceChange(testContext, { internal_id: malwareId }, { corroboration: { from: 1, to: 2 } })).toEqual(1);
    expect(await notifyProvenanceChange(testContext, { internal_id: malwareId }, { corroboration: { from: 2, to: 3 } })).toEqual(0);
    expect(await notifyProvenanceChange(testContext, { internal_id: malwareId }, { conflictFields: ['description'] })).toEqual(1);
  });

  it('should compute provenance statistics and distributions', async () => {
    const statistics = await queryAsAdminWithSuccess({
      query: gql`query { provenanceStatistics { total with_provenance single_sourced corroborated with_conflicts stale } }`,
    });
    const stats = statistics.data?.provenanceStatistics;
    expect(stats.total).toBeGreaterThanOrEqual(stats.with_provenance);
    expect(stats.corroborated).toBeGreaterThanOrEqual(1);
    const freshness = await queryAsAdminWithSuccess({ query: gql`query { provenanceFreshnessDistribution { label value } }` });
    expect(freshness.data?.provenanceFreshnessDistribution.map((entry: { label: string }) => entry.label)).toEqual(['0-30', '31-90', '91-180', '181-365', '366+', 'unknown']);
    const kinds = await queryAsAdminWithSuccess({ query: gql`query { provenanceSourceKindsDistribution { source_kind count } }` });
    expect(kinds.data?.provenanceSourceKindsDistribution.find((entry: { source_kind: string }) => entry.source_kind === 'user').count).toBeGreaterThanOrEqual(1);
    const byType = await queryAsAdminWithSuccess({ query: gql`query { provenanceSingleSourcedByType(types: ["Malware"]) { entity_type total single_sourced } }` });
    const malwares = byType.data?.provenanceSingleSourcedByType.find((entry: { entity_type: string }) => entry.entity_type === 'Malware');
    expect(malwares.total).toBeGreaterThanOrEqual(malwares.single_sourced);
  });

  it('should compute the provenance statistics of each type for the customization', async () => {
    const TYPE_STATISTICS = gql`query TypeStatistics($types: [String!]!) { provenanceTypeStatistics(types: $types) { entity_type with_provenance corroborated last_asserted_at } }`;
    const relationships = await queryAsAdminWithSuccess({ query: TYPE_STATISTICS, variables: { types: ['stix-core-relationship'] } });
    const uses = relationships.data?.provenanceTypeStatistics.find((entry: { entity_type: string }) => entry.entity_type === 'uses');
    expect(uses.with_provenance).toBeGreaterThanOrEqual(1);
    expect(uses.corroborated).toBeGreaterThanOrEqual(1);
    expect(new Date(uses.last_asserted_at).getTime()).toBeLessThanOrEqual(Date.now());
    expect(relationships.data?.provenanceTypeStatistics.map((entry: { entity_type: string }) => entry.entity_type)).not.toContain('Malware');
    const malwares = await queryAsAdminWithSuccess({ query: TYPE_STATISTICS, variables: { types: ['Malware'] } });
    expect(malwares.data?.provenanceTypeStatistics.map((entry: { entity_type: string }) => entry.entity_type)).toEqual(['Malware']);
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: TYPE_STATISTICS, variables: { types: ['Malware'] } });
  });
});
