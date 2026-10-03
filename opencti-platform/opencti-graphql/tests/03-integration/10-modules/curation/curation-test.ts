import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import * as entrepriseEdition from '../../../../src/enterprise-edition/ee';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { addIntrusionSet } from '../../../../src/domain/intrusionSet';
import { addMalware } from '../../../../src/domain/malware';
import { createRelation, deleteElementById } from '../../../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { RELATION_USES } from '../../../../src/schema/stixCoreRelationship';
import * as curationSettings from '../../../../src/modules/curation/curation-settings';
import { getCurationSettings } from '../../../../src/modules/curation/curation-settings';
import { addOrganization } from '../../../../src/modules/organization/organization-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { runContradictionScan, runIncrementalDuplicateDetection } from '../../../../src/modules/curation/curation-scan';
import {
  AUTHORITY_SOURCE_AUTHOR,
  ENTITY_TYPE_CURATION_POLICY,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT,
  ENTITY_TYPE_MERGE_RECORD,
} from '../../../../src/modules/curation/curation-types';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { redisCurationSwapFieldWriter } from '../../../../src/database/redis';

const PROPOSALS_FOR_ENTITY_QUERY = gql`
  query CurationProposalsForEntity($id: ID!, $status: [CurationProposalStatus!]) {
    curationProposalsForEntity(id: $id, status: $status) {
      id
      proposal_kind
      proposal_status
      recommended_action
      confidence_score
      subject_ids
      merge_record_id
      evidence {
        evidence_type
        score
        weight
        description
      }
    }
  }
`;

const PROPOSAL_QUERY = gql`
  query CurationProposal($id: ID!) {
    curationProposal(id: $id) {
      id
      proposal_status
      can_apply
      can_revert
      restricted_subjects_count
      subjects {
        ... on BasicObject {
          id
        }
      }
    }
  }
`;

const ACCEPT_MUTATION = gql`
  mutation CurationProposalAccept($id: ID!, $input: CurationProposalAcceptInput) {
    curationProposalAccept(id: $id, input: $input) {
      id
      proposal_status
      merge_record_id
      decision_rationale
    }
  }
`;

const REJECT_MUTATION = gql`
  mutation CurationProposalReject($id: ID!, $rationale: String) {
    curationProposalReject(id: $id, rationale: $rationale) {
      id
      proposal_status
      decision_rationale
    }
  }
`;

const REVERT_MUTATION = gql`
  mutation CurationProposalRevert($id: ID!) {
    curationProposalRevert(id: $id) {
      id
      proposal_status
    }
  }
`;

const MERGE_RECORD_QUERY = gql`
  query MergeRecord($id: ID!) {
    mergeRecord(id: $id) {
      id
      merge_status
      is_reversible
      merge_target_id
      merge_source_ids
      relationships_redirected_count
      sources {
        id
        name
        reverted_at
      }
    }
  }
`;

const UNMERGE_MUTATION = gql`
  mutation UnmergeEntity($mergeRecordId: ID!) {
    unmergeEntity(mergeRecordId: $mergeRecordId) {
      id
      merge_status
      is_reversible
    }
  }
`;

const RESOLVE_QUERY = gql`
  query CurationResolve($name: String!, $type: String!) {
    curationResolve(name: $name, type: $type) {
      entity_id
      match_type
      score
    }
  }
`;

const SETTINGS_QUERY = gql`
  query CurationSettings {
    curationSettings {
      id
      curation_enabled
      curated_entity_types
      ambiguous_band_min
      ambiguous_band_max
      merge_record_retention_days
      force_scan
      available_detectors
      provenance_available
      graph_similarity_available
      authority_connector_sources {
        source_id
      }
    }
  }
`;

const SETTINGS_EDIT_MUTATION = gql`
  mutation CurationSettingsEdit($input: CurationSettingsInput!) {
    curationSettingsEdit(input: $input) {
      id
      merge_record_retention_days
      ambiguous_band_min
      ambiguous_band_max
    }
  }
`;

const HEALTH_REFRESH_MUTATION = gql`
  mutation KnowledgeHealthRefresh {
    knowledgeHealthRefresh {
      id
      health_score
      score_breakdown {
        component
        weight
        score
      }
    }
  }
`;

const HEALTH_QUERY = gql`
  query KnowledgeHealth {
    knowledgeHealth {
      id
      health_score
    }
    curationStatistics {
      open_count
      active_merge_records_count
    }
  }
`;

const POLICY_ADD_MUTATION = gql`
  mutation CurationPolicyAdd($input: CurationPolicyAddInput!) {
    curationPolicyAdd(input: $input) {
      id
      name
      policy_enabled
      auto_apply_threshold
    }
  }
`;

const POLICY_DRY_RUN_QUERY = gql`
  query CurationPolicyDryRun($id: ID!) {
    curationPolicyDryRun(id: $id) {
      eligible_count
      excluded_count
      exclusions {
        key
        count
      }
    }
  }
`;

const POLICY_DELETE_MUTATION = gql`
  mutation CurationPolicyDelete($id: ID!) {
    curationPolicyDelete(id: $id)
  }
`;

const NAME_A = 'Zcuraxor-Test';
const NAME_B = 'zcuraxor test';
const NAME_C = 'Qwyvern Curation';
const NAME_D = 'qwyvern-curation';
const createdEntities: Array<{ id: string; type: string }> = [];

const createIntrusionSet = async (input: Record<string, unknown>) => {
  const created = await addIntrusionSet(testContext, ADMIN_USER, input);
  createdEntities.push({ id: created.id, type: ENTITY_TYPE_INTRUSION_SET });
  return created as BasicStoreEntity;
};

const openProposalsFor = async (entityId: string) => {
  const result = await queryAsAdminWithSuccess({ query: PROPOSALS_FOR_ENTITY_QUERY, variables: { id: entityId, status: ['open'] } });
  return result.data?.curationProposalsForEntity as Array<Record<string, any>>;
};

const deleteAllOfType = async (type: string) => {
  const elements = await fullEntitiesList(testContext, ADMIN_USER, [type]);
  for (let index = 0; index < elements.length; index += 1) {
    await deleteElementById(testContext, ADMIN_USER, elements[index].internal_id, type);
  }
};

describe('Knowledge curation', () => {
  let entityA: BasicStoreEntity;
  let entityB: BasicStoreEntity;
  let malwareId: string;
  let usesFromB: string;

  beforeAll(async () => {
    entityA = await createIntrusionSet({ name: NAME_A, description: 'Curation integration test actor' });
    entityB = await createIntrusionSet({ name: NAME_B, description: 'Curation integration test actor' });
    const malware = await addMalware(testContext, ADMIN_USER, { name: 'Zcuraxor curation malware', is_family: true });
    malwareId = malware.id;
    createdEntities.push({ id: malwareId, type: ENTITY_TYPE_MALWARE });
    const relation = await createRelation(testContext, ADMIN_USER, { fromId: entityB.id, toId: malwareId, relationship_type: RELATION_USES });
    usesFromB = relation.id;
  });

  afterAll(async () => {
    for (let index = 0; index < createdEntities.length; index += 1) {
      const { id, type } = createdEntities[index];
      const existing = await storeLoadById(testContext, ADMIN_USER, id, type);
      if (existing) await deleteElementById(testContext, ADMIN_USER, id, type);
    }
    await deleteAllOfType(ENTITY_TYPE_CURATION_PROPOSAL);
    await deleteAllOfType(ENTITY_TYPE_MERGE_RECORD);
    await deleteAllOfType(ENTITY_TYPE_CURATION_POLICY);
    await deleteAllOfType(ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT);
  });

  it('should expose the curation settings', async () => {
    const result = await queryAsAdminWithSuccess({ query: SETTINGS_QUERY, variables: {} });
    const settings = result.data?.curationSettings;
    expect(settings.curation_enabled).toBe(true);
    expect(settings.curated_entity_types).toContain(ENTITY_TYPE_INTRUSION_SET);
    expect(settings.available_detectors).toEqual(expect.arrayContaining(['normalization', 'similarity', 'behavior', 'contradiction', 'staleness', 'relationship_conflict']));
    expect(settings.ambiguous_band_min).toBeLessThan(settings.ambiguous_band_max);
    expect(typeof settings.provenance_available).toBe('boolean');
    expect(typeof settings.graph_similarity_available).toBe('boolean');
    expect(Array.isArray(settings.authority_connector_sources)).toBe(true);
  });

  it('should refuse curation settings changes to a user without the customization capability', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: SETTINGS_EDIT_MUTATION, variables: { input: { merge_record_retention_days: 30 } } });
  });

  it('should validate and save curation settings', async () => {
    const invalid = await queryAsAdmin({ query: SETTINGS_EDIT_MUTATION, variables: { input: { ambiguous_band_min: 0.9, ambiguous_band_max: 0.5 } } });
    expect(invalid.errors?.[0]?.message).toContain('ambiguous band');
    const saved = await queryAsAdminWithSuccess({ query: SETTINGS_EDIT_MUTATION, variables: { input: { merge_record_retention_days: 200 } } });
    expect(saved.data?.curationSettingsEdit.merge_record_retention_days).toBe(200);
    await queryAsAdminWithSuccess({ query: SETTINGS_EDIT_MUTATION, variables: { input: { merge_record_retention_days: 365 } } });
  });

  it('should propose to merge two spellings of the same name, with evidence', async () => {
    const settings = await getCurationSettings(testContext);
    const stats = await runIncrementalDuplicateDetection(testContext, settings, [entityA.id, entityB.id]);
    expect(stats.created).toBeGreaterThan(0);
    const proposals = await openProposalsFor(entityA.id);
    const merge = proposals.find((proposal) => proposal.subject_ids.includes(entityB.id));
    expect(merge).toBeDefined();
    expect(merge?.proposal_kind).toBe('merge');
    expect(merge?.recommended_action).toBe('merge');
    expect(merge?.confidence_score).toBeGreaterThan(0);
    expect(merge?.evidence.length).toBeGreaterThan(0);
    expect(merge?.evidence.some((item: { evidence_type: string }) => item.evidence_type === 'canonical_collision')).toBe(true);
  });

  it('should not propose the same finding twice', async () => {
    const settings = await getCurationSettings(testContext);
    await runIncrementalDuplicateDetection(testContext, settings, [entityA.id, entityB.id]);
    const proposals = await openProposalsFor(entityA.id);
    expect(proposals.filter((proposal) => proposal.subject_ids.includes(entityB.id)).length).toBe(1);
  });

  it('should resolve an importer name to an existing entity', async () => {
    const result = await queryAsAdminWithSuccess({ query: RESOLVE_QUERY, variables: { name: NAME_A, type: ENTITY_TYPE_INTRUSION_SET } });
    const resolution = result.data?.curationResolve;
    expect(resolution).not.toBeNull();
    expect([entityA.id, entityB.id]).toContain(resolution.entity_id);
    expect(resolution.score).toBeGreaterThan(0);
    const unknown = await queryAsAdminWithSuccess({ query: RESOLVE_QUERY, variables: { name: 'Nothing like any curation name', type: ENTITY_TYPE_INTRUSION_SET } });
    expect(unknown.data?.curationResolve).toBeNull();
  });

  it('should refuse to apply a proposal to a user without the update capability', async () => {
    const [merge] = (await openProposalsFor(entityA.id)).filter((proposal) => proposal.subject_ids.includes(entityB.id));
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: ACCEPT_MUTATION, variables: { id: merge.id, input: { target_id: entityA.id } } });
  });

  it('should accept the merge and record it reversibly, then unmerge', async () => {
    const [merge] = (await openProposalsFor(entityA.id)).filter((proposal) => proposal.subject_ids.includes(entityB.id));
    const details = await queryAsAdminWithSuccess({ query: PROPOSAL_QUERY, variables: { id: merge.id } });
    expect(details.data?.curationProposal.can_apply).toBe(true);
    expect(details.data?.curationProposal.restricted_subjects_count).toBe(0);

    const accepted = await queryAsAdminWithSuccess({
      query: ACCEPT_MUTATION,
      variables: { id: merge.id, input: { target_id: entityA.id, rationale: 'Same intrusion set' } },
    });
    expect(accepted.data?.curationProposalAccept.proposal_status).toBe('accepted');
    const mergeRecordId = accepted.data?.curationProposalAccept.merge_record_id;
    expect(mergeRecordId).toBeTruthy();
    const applied = await queryAsAdminWithSuccess({ query: PROPOSAL_QUERY, variables: { id: merge.id } });
    expect(applied.data?.curationProposal.can_revert).toBe(true);
    expect(await storeLoadById(testContext, ADMIN_USER, entityB.id, ENTITY_TYPE_INTRUSION_SET)).toBeUndefined();

    const record = await queryAsAdminWithSuccess({ query: MERGE_RECORD_QUERY, variables: { id: mergeRecordId } });
    expect(record.data?.mergeRecord.merge_status).toBe('active');
    expect(record.data?.mergeRecord.is_reversible).toBe(true);
    expect(record.data?.mergeRecord.merge_target_id).toBe(entityA.id);
    expect(record.data?.mergeRecord.merge_source_ids).toEqual([entityB.id]);
    expect(record.data?.mergeRecord.relationships_redirected_count).toBeGreaterThanOrEqual(1);
    const movedRelation = await storeLoadById(testContext, ADMIN_USER, usesFromB, RELATION_USES) as unknown as { fromId: string };
    expect(movedRelation.fromId).toBe(entityA.id);

    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: UNMERGE_MUTATION, variables: { mergeRecordId } });
    const unmerged = await queryAsAdminWithSuccess({ query: UNMERGE_MUTATION, variables: { mergeRecordId } });
    expect(unmerged.data?.unmergeEntity.merge_status).toBe('reverted');
    expect(unmerged.data?.unmergeEntity.is_reversible).toBe(false);

    const restored = await storeLoadById(testContext, ADMIN_USER, entityB.id, ENTITY_TYPE_INTRUSION_SET) as BasicStoreEntity;
    expect(restored).toBeDefined();
    expect(restored.standard_id).toBe(entityB.standard_id);
    expect(restored.name).toBe(NAME_B);
    const restoredRelation = await storeLoadById(testContext, ADMIN_USER, usesFromB, RELATION_USES) as unknown as { fromId: string };
    expect(restoredRelation.fromId).toBe(entityB.id);
  });

  it('should reject a proposal and suppress the same finding', async () => {
    const entityC = await createIntrusionSet({ name: NAME_C });
    const entityD = await createIntrusionSet({ name: NAME_D });
    const settings = await getCurationSettings(testContext);
    await runIncrementalDuplicateDetection(testContext, settings, [entityC.id, entityD.id]);
    const [proposal] = (await openProposalsFor(entityC.id)).filter((candidate) => candidate.subject_ids.includes(entityD.id));
    expect(proposal).toBeDefined();
    const rejected = await queryAsAdminWithSuccess({ query: REJECT_MUTATION, variables: { id: proposal.id, rationale: 'Two distinct groups' } });
    expect(rejected.data?.curationProposalReject.proposal_status).toBe('rejected');
    expect(rejected.data?.curationProposalReject.decision_rationale).toBe('Two distinct groups');

    await runIncrementalDuplicateDetection(testContext, settings, [entityC.id, entityD.id]);
    const reopened = (await openProposalsFor(entityC.id)).filter((candidate) => candidate.subject_ids.includes(entityD.id));
    expect(reopened.length).toBe(0);
  });

  it('should propose to fix inverted dates, and refuse to write the inverted dates back', async () => {
    const inverted = await createIntrusionSet({
      name: 'Zcuraxor inverted dates',
      first_seen: '2024-06-01T00:00:00.000Z',
      last_seen: '2024-01-01T00:00:00.000Z',
    });
    const settings = await getCurationSettings(testContext);
    await runContradictionScan(testContext, settings);
    const [contradiction] = (await openProposalsFor(inverted.id)).filter((proposal) => proposal.recommended_action === 'fix_dates');
    expect(contradiction).toBeDefined();
    expect(contradiction.proposal_kind).toBe('contradiction');

    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id: contradiction.id } });
    const fixed = await storeLoadById(testContext, ADMIN_USER, inverted.id, ENTITY_TYPE_INTRUSION_SET) as unknown as { first_seen: string; last_seen: string };
    expect(new Date(fixed.first_seen).getTime()).toBeLessThanOrEqual(new Date(fixed.last_seen).getTime());

    const details = await queryAsAdminWithSuccess({ query: PROPOSAL_QUERY, variables: { id: contradiction.id } });
    expect(details.data?.curationProposal.can_revert).toBe(false);
    const refused = await queryAsAdmin({ query: REVERT_MUTATION, variables: { id: contradiction.id } });
    expect(refused.errors?.[0]?.message).toContain('A date fix cannot be reverted');
    const unchanged = await storeLoadById(testContext, ADMIN_USER, inverted.id, ENTITY_TYPE_INTRUSION_SET) as unknown as { first_seen: string; last_seen: string };
    expect(unchanged.first_seen).toEqual(fixed.first_seen);
    expect(unchanged.last_seen).toEqual(fixed.last_seen);
  });

  it('should compute the Knowledge Health snapshot and statistics', async () => {
    const refreshed = await queryAsAdminWithSuccess({ query: HEALTH_REFRESH_MUTATION, variables: {} });
    const snapshot = refreshed.data?.knowledgeHealthRefresh;
    expect(snapshot.health_score).toBeGreaterThanOrEqual(0);
    expect(snapshot.health_score).toBeLessThanOrEqual(100);
    const totalWeight = snapshot.score_breakdown.reduce((acc: number, item: { weight: number }) => acc + item.weight, 0);
    expect(totalWeight).toBeCloseTo(1, 5);
    const health = await queryAsAdminWithSuccess({ query: HEALTH_QUERY, variables: {} });
    expect(health.data?.knowledgeHealth.id).toBe(snapshot.id);
    expect(health.data?.curationStatistics.open_count).toBeGreaterThanOrEqual(0);
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: HEALTH_REFRESH_MUTATION, variables: {} });
  });

  it('keeps the writer history of a field exact when a stream batch is processed again', async () => {
    const entityId = `curation-test-${Date.now()}`;
    const swap = (writer: string, eventId: string) => redisCurationSwapFieldWriter(entityId, 'name', writer, eventId, 600);
    expect(await swap('user-a', '1000-0')).toEqual({ previous: null, replayed: false });
    expect(await swap('user-b', '1001-0')).toEqual({ previous: 'user-a', replayed: false });
    // The batch is processed again from its first event: each event reports the writer it overwrote the first time
    expect(await swap('user-a', '1000-0')).toEqual({ previous: null, replayed: true });
    expect(await swap('user-b', '1001-0')).toEqual({ previous: 'user-a', replayed: true });
    // An event older than the recorded ones is a replay too, and the next event overwrites the last real writer
    expect(await swap('user-x', '999-0')).toEqual({ previous: null, replayed: true });
    expect(await swap('user-c', '1002-0')).toEqual({ previous: 'user-b', replayed: false });
  });

  describe('source field authority', () => {
    let authoritative: { id: string };
    let secondary: { id: string };

    beforeAll(async () => {
      authoritative = await addOrganization(testContext, ADMIN_USER, { name: 'Zcuraxor authoritative source' });
      secondary = await addOrganization(testContext, ADMIN_USER, { name: 'Zcuraxor secondary source' });
      createdEntities.push({ id: authoritative.id, type: ENTITY_TYPE_IDENTITY_ORGANIZATION }, { id: secondary.id, type: ENTITY_TYPE_IDENTITY_ORGANIZATION });
      const settings = await getCurationSettings(testContext);
      vi.spyOn(curationSettings, 'getCurationSettings').mockResolvedValue({
        ...settings,
        field_authority_enabled: true,
        field_authority_rules: [{
          entity_type: ENTITY_TYPE_INTRUSION_SET,
          attribute: 'description',
          sources: [
            { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: authoritative.id },
            { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: secondary.id },
          ],
        }],
      });
    });

    afterAll(() => {
      vi.mocked(curationSettings.getCurationSettings).mockRestore();
    });

    it('should keep the value of the more authoritative source on upsert, whatever the confidence', async () => {
      const name = 'Zcuraxor field authority actor';
      const created = await createIntrusionSet({ name, description: 'From the authoritative source', createdBy: authoritative.id });
      await addIntrusionSet(testContext, ADMIN_USER, { name, description: 'From the secondary source', createdBy: secondary.id });
      const afterSecondary = await storeLoadById(testContext, ADMIN_USER, created.id, ENTITY_TYPE_INTRUSION_SET) as BasicStoreEntity;
      expect(afterSecondary.description).toBe('From the authoritative source');
      await addIntrusionSet(testContext, ADMIN_USER, { name, description: 'Updated by the authoritative source', createdBy: authoritative.id });
      const afterAuthoritative = await storeLoadById(testContext, ADMIN_USER, created.id, ENTITY_TYPE_INTRUSION_SET) as BasicStoreEntity;
      expect(afterAuthoritative.description).toBe('Updated by the authoritative source');
    });
  });

  describe('curation policies (Enterprise Edition)', () => {
    beforeAll(() => {
      vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
      vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    });

    afterAll(() => {
      vi.restoreAllMocks();
    });

    it('should refuse curation policies without Enterprise Edition', async () => {
      vi.mocked(entrepriseEdition.checkEnterpriseEdition).mockRejectedValueOnce(new Error('Enterprise edition is not enabled'));
      const refused = await queryAsAdmin({
        query: POLICY_ADD_MUTATION,
        variables: { input: { name: 'Community attempt', policy_entity_types: [ENTITY_TYPE_INTRUSION_SET], policy_kinds: ['merge'], auto_apply_threshold: 0.99 } },
      });
      expect(refused.errors?.length).toBeGreaterThan(0);
    });

    it('should validate, create, dry run and delete a curation policy', async () => {
      const invalid = await queryAsAdmin({
        query: POLICY_ADD_MUTATION,
        variables: { input: { name: 'Too permissive', policy_entity_types: [ENTITY_TYPE_INTRUSION_SET], policy_kinds: ['merge'], auto_apply_threshold: 0.2 } },
      });
      expect(invalid.errors?.[0]?.message).toContain('between 0.5 and 1');

      const created = await queryAsAdminWithSuccess({
        query: POLICY_ADD_MUTATION,
        variables: { input: { name: 'Intrusion set duplicates', policy_entity_types: [ENTITY_TYPE_INTRUSION_SET], policy_kinds: ['merge', 'alias'], auto_apply_threshold: 0.99 } },
      });
      const policy = created.data?.curationPolicyAdd;
      expect(policy.policy_enabled).toBe(false);
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: POLICY_DRY_RUN_QUERY, variables: { id: policy.id } });

      const dryRun = await queryAsAdminWithSuccess({ query: POLICY_DRY_RUN_QUERY, variables: { id: policy.id } });
      expect(dryRun.data?.curationPolicyDryRun.eligible_count).toBeGreaterThanOrEqual(0);
      expect(dryRun.data?.curationPolicyDryRun.excluded_count).toBeGreaterThanOrEqual(0);

      const deleted = await queryAsAdminWithSuccess({ query: POLICY_DELETE_MUTATION, variables: { id: policy.id } });
      expect(deleted.data?.curationPolicyDelete).toBe(policy.id);
    });
  });
});
