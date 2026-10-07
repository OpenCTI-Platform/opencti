import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import * as entrepriseEdition from '../../src/enterprise-edition/ee';
import { ADMIN_USER, testContext, USER_EDITOR, USER_PARTICIPATE } from '../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../utils/testQueryHelper';
import { elUpdate } from '../../src/database/engine';
import { completePendingMergeRecords, expireMergeRecords } from '../../src/modules/curation/curation-merge-record';
import { addIntrusionSet } from '../../src/domain/intrusionSet';
import { addCampaign } from '../../src/domain/campaign';
import { addMalware } from '../../src/domain/malware';
import { addIndicator } from '../../src/modules/indicator/indicator-domain';
import * as middleware from '../../src/database/middleware';
import * as redis from '../../src/database/redis';
import { createRelation, deleteElementById, updateAttribute } from '../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../src/database/middleware-loader';
import { wait } from '../../src/database/utils';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../src/schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../src/modules/indicator/indicator-types';
import { RELATION_ATTRIBUTED_TO, RELATION_BASED_ON, RELATION_RELATED_TO, RELATION_USES } from '../../src/schema/stixCoreRelationship';
import { addStixCyberObservable } from '../../src/domain/stixCyberObservable';
import { ENTITY_IPV4_ADDR } from '../../src/schema/stixCyberObservable';
import { getCurationSettings } from '../../src/modules/curation/curation-settings';
import { persistProposalDraft, refreshProposalRestrictions, retireProposalsOfDeletedSubjects } from '../../src/modules/curation/curation-proposals';
import { loadPolicyFacts } from '../../src/modules/curation/curation-policies';
import { computeHealthMetrics } from '../../src/modules/curation/curation-health';
import { EditOperation } from '../../src/generated/graphql';
import { INPUT_MARKINGS } from '../../src/schema/general';
import { MARKING_TLP_RED } from '../../src/schema/identifier';
import { RELATION_OBJECT_MARKING } from '../../src/schema/stixRefRelationship';
import { ENTITY_TYPE_BACKGROUND_TASK } from '../../src/schema/internalObject';
import {
  ACTION_ACKNOWLEDGE,
  ACTION_ADD_ALIASES,
  ACTION_FIX_DATES,
  ACTION_MERGE,
  ACTION_PRESERVE_PROCEDURE,
  ACTION_RESOLVE_ATTRIBUTION,
  ACTION_REVOKE,
  ACTION_SET_FIELD,
  ACTION_UNREVOKE_INDICATOR,
  DETECTOR_CONTRADICTION,
  DETECTOR_FIELD_AUTHORITY,
  DETECTOR_NORMALIZATION,
  DETECTOR_RELATIONSHIP_CONFLICT,
  DETECTOR_STALENESS,
  ENTITY_TYPE_CURATION_POLICY,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_MERGE_RECORD,
  EVIDENCE_STALENESS,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_FIELD_PRECEDENCE,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
  PROPOSAL_KIND_STALE,
  type BasicStoreEntityCurationProposal,
  type ProposalDraft,
} from '../../src/modules/curation/curation-types';
import type { BasicStoreEntity } from '../../src/types/store';

const PROPOSAL_FIELDS = `
  id
  proposal_kind
  proposal_status
  recommended_action
  target_id
  decision_rationale
  policy_id
  applied_patch
  merge_record_id
  can_apply
  can_revert
  adjudicable
  choice_required
  adjudication {
    decision
    rationale
  }
  decidedBy {
    id
  }
  subjects {
    ... on BasicObject {
      id
    }
  }
`;

const PROPOSAL_QUERY = gql`
  query CurationActionsProposal($id: ID!) {
    curationProposal(id: $id) {
      ${PROPOSAL_FIELDS}
    }
  }
`;

const PROPOSALS_QUERY = gql`
  query CurationActionsProposals($first: Int, $filters: FilterGroup, $search: String) {
    curationProposals(first: $first, filters: $filters, search: $search, orderBy: confidence_score, orderMode: desc) {
      edges {
        node {
          id
          proposal_kind
          confidence_score
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

const ACCEPT_MUTATION = gql`
  mutation CurationActionsAccept($id: ID!, $input: CurationProposalAcceptInput) {
    curationProposalAccept(id: $id, input: $input) {
      ${PROPOSAL_FIELDS}
    }
  }
`;

const DECIDE_MUTATION = gql`
  mutation CurationActionsDecide($id: ID!, $input: CurationProposalDecideInput!) {
    curationProposalDecide(id: $id, input: $input) {
      ${PROPOSAL_FIELDS}
    }
  }
`;

const REVERT_MUTATION = gql`
  mutation CurationActionsRevert($id: ID!) {
    curationProposalRevert(id: $id) {
      id
      proposal_status
    }
  }
`;

const APPLY_MUTATION = gql`
  mutation CurationActionsApply($id: ID!, $policyId: ID, $expectedUpdatedAt: DateTime) {
    curationProposalApply(id: $id, policy_id: $policyId, expected_updated_at: $expectedUpdatedAt) {
      id
      proposal_status
      policy_id
    }
  }
`;

const ADJUDICATE_MUTATION = gql`
  mutation CurationActionsAdjudicate($id: ID!) {
    curationProposalAdjudicate(id: $id) {
      id
    }
  }
`;

const ADJUDICATION_AVAILABLE_QUERY = gql`
  query CurationActionsAdjudicationAvailable {
    curationAdjudicationAvailable
  }
`;

const BULK_ACCEPT_MUTATION = gql`
  mutation CurationActionsBulkAccept($ids: [ID!]!) {
    curationProposalsBulkAccept(ids: $ids)
  }
`;

const BULK_REJECT_MUTATION = gql`
  mutation CurationActionsBulkReject($ids: [ID!]!, $rationale: String) {
    curationProposalsBulkReject(ids: $ids, rationale: $rationale)
  }
`;

const SCAN_REQUEST_MUTATION = gql`
  mutation CurationActionsScanRequest {
    curationScanRequest {
      id
      force_scan
    }
  }
`;

const POLICY_ADD_MUTATION = gql`
  mutation CurationActionsPolicyAdd($input: CurationPolicyAddInput!) {
    curationPolicyAdd(input: $input) {
      id
      policy_enabled
      applied_count
    }
  }
`;

const POLICY_QUERY = gql`
  query CurationActionsPolicy($id: ID!) {
    curationPolicy(id: $id) {
      id
      policy_enabled
      applied_count
      auto_apply_threshold
    }
  }
`;

const POLICIES_QUERY = gql`
  query CurationActionsPolicies($search: String) {
    curationPolicies(first: 10, search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const POLICY_PATCH_MUTATION = gql`
  mutation CurationActionsPolicyPatch($id: ID!, $input: [EditInput!]!) {
    curationPolicyFieldPatch(id: $id, input: $input) {
      id
      policy_enabled
      auto_apply_threshold
    }
  }
`;

const POLICY_APPLY_MUTATION = gql`
  mutation CurationActionsPolicyApply($id: ID!) {
    curationPolicyApply(id: $id)
  }
`;

const MERGE_RECORDS_QUERY = gql`
  query CurationActionsMergeRecords($search: String) {
    mergeRecords(first: 50, search: $search) {
      edges {
        node {
          id
          merge_status
          is_reversible
          irreversible_reason
          relationships_recreatable_count
        }
      }
    }
  }
`;

const UNMERGE_MUTATION = gql`
  mutation CurationActionsUnmerge($mergeRecordId: ID!, $sourceIds: [ID!]) {
    unmergeEntity(mergeRecordId: $mergeRecordId, sourceIds: $sourceIds) {
      id
      merge_status
    }
  }
`;

const PREFIX = 'Zcuractions';
const createdEntities: Array<{ id: string; type: string }> = [];
const createdProposalIds: string[] = [];

const track = <T extends { id: string }>(element: T, type: string): T => {
  createdEntities.push({ id: element.id, type });
  return element;
};

const createIntrusionSet = async (name: string, input: Record<string, unknown> = {}) => {
  return track(await addIntrusionSet(testContext, ADMIN_USER, { name, ...input }), ENTITY_TYPE_INTRUSION_SET) as BasicStoreEntity;
};

const subjectOf = (element: BasicStoreEntity) => ({ id: element.id, entity_type: element.entity_type, name: element.name });

const evidenceFor = (evidenceType: string, description: string) => [{ evidence_type: evidenceType, score: 1, weight: 1, description }];

const createProposal = async (draft: ProposalDraft) => {
  const settings = await getCurationSettings(testContext);
  const { proposal } = await persistProposalDraft(testContext, settings, draft);
  expect(proposal).toBeTruthy();
  const id = proposal?.internal_id as string;
  createdProposalIds.push(id);
  return id;
};

const loadProposal = async (id: string) => {
  const result = await queryAsAdminWithSuccess({ query: PROPOSAL_QUERY, variables: { id } });
  return result.data?.curationProposal;
};

const loadIntrusionSet = async (id: string) => storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_INTRUSION_SET) as unknown as Promise<Record<string, any>>;

describe('Knowledge curation actions', () => {
  afterAll(async () => {
    for (let index = 0; index < createdProposalIds.length; index += 1) {
      const existing = await storeLoadById(testContext, ADMIN_USER, createdProposalIds[index], ENTITY_TYPE_CURATION_PROPOSAL);
      if (existing) await deleteElementById(testContext, ADMIN_USER, createdProposalIds[index], ENTITY_TYPE_CURATION_PROPOSAL);
    }
    for (let index = createdEntities.length - 1; index >= 0; index -= 1) {
      const { id, type } = createdEntities[index];
      const existing = await storeLoadById(testContext, ADMIN_USER, id, type);
      if (existing) await deleteElementById(testContext, ADMIN_USER, id, type);
    }
    // Every entity and proposal of the suite is deleted one by one: the 10 s hook default is too short on a busy platform.
  }, 120000);

  it('should add the proposed aliases, and remove them again on revert', async () => {
    const target = await createIntrusionSet(`${PREFIX} Alias Target`);
    const taxonomyName = `${PREFIX} Taxonomy Name`;
    const id = await createProposal({
      kind: PROPOSAL_KIND_ALIAS,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target)],
      target_id: target.id,
      recommended_action: ACTION_ADD_ALIASES,
      action_payload: { aliases: [taxonomyName, target.name] },
      evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
      confidence: 0.7,
    });
    const listed = await queryAsAdminWithSuccess({
      query: PROPOSALS_QUERY,
      variables: { first: 5, search: PREFIX, filters: { mode: 'and', filters: [{ key: ['proposal_kind'], values: [PROPOSAL_KIND_ALIAS] }], filterGroups: [] } },
    });
    expect(listed.data?.curationProposals.edges.map((edge: { node: { id: string } }) => edge.node.id)).toContain(id);
    // One subject has nothing to merge with: the proposal takes alias, distinct or skip only.
    const merged = await queryAsAdmin({ query: DECIDE_MUTATION, variables: { id, input: { decision: 'merge', rationale: 'Same actor', apply: true } } });
    expect(merged.errors?.[0]?.message).toContain('A merge needs two subjects');
    expect((await loadProposal(id)).proposal_status).toBe('open');

    const accepted = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { rationale: 'Known alias' } } });
    expect(accepted.data?.curationProposalAccept.proposal_status).toBe('accepted');
    expect(accepted.data?.curationProposalAccept.can_revert).toBe(true);
    expect(accepted.data?.curationProposalAccept.decidedBy.id).toBe(ADMIN_USER.id);
    // The name of the target itself is never added as one of its aliases.
    expect((await loadIntrusionSet(target.id)).aliases).toEqual([taxonomyName]);
    const again = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
    expect(again.errors?.[0]?.message).toContain('already decided');

    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    expect(reverted.data?.curationProposalRevert.proposal_status).toBe('reverted');
    expect((await loadIntrusionSet(target.id)).aliases ?? []).toEqual([]);
    const twice = await queryAsAdmin({ query: REVERT_MUTATION, variables: { id } });
    expect(twice.errors?.[0]?.message).toContain('Only applied curation proposals can be reverted');
  });

  it('should refuse an alias decision while the other subject exists, record a decision without applying it, and reject on distinct', async () => {
    const first = await createIntrusionSet(`${PREFIX} Decision One`);
    const second = await createIntrusionSet(`${PREFIX} Decision Two`);
    const third = await createIntrusionSet(`${PREFIX} Decision Three`);
    const mergeDraft = (left: BasicStoreEntity, right: BasicStoreEntity): ProposalDraft => ({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(left), subjectOf(right)],
      target_id: left.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('name_similarity', 'Similar names'),
      confidence: 0.6,
    });
    const aliasId = await createProposal(mergeDraft(first, second));
    const missingRationale = await queryAsAdmin({ query: DECIDE_MUTATION, variables: { id: aliasId, input: { decision: 'alias', rationale: '  ', apply: true } } });
    expect(missingRationale.errors?.[0]?.message).toContain('A rationale is required');
    const foreignTarget = await queryAsAdmin({ query: DECIDE_MUTATION, variables: { id: aliasId, input: { decision: 'alias', rationale: 'Sub-group', target_id: third.id } } });
    expect(foreignTarget.errors?.[0]?.message).toContain('The target must be one of the proposal subjects');

    // An alias names a single entity: the name of a subject that still exists cannot become an alias of another one.
    const refused = await queryAsAdmin({
      query: DECIDE_MUTATION,
      variables: { id: aliasId, input: { decision: 'alias', rationale: 'A sub-group of the same actor', apply: true, target_id: second.id } },
    });
    expect(refused.errors?.[0]?.message).toContain('These names still belong to other entities');
    expect((await loadProposal(aliasId)).proposal_status).toBe('open');
    expect((await loadIntrusionSet(second.id)).aliases ?? []).toEqual([]);
    // Once the other subject is gone, its name is free: the alias decision applies.
    await deleteElementById(testContext, ADMIN_USER, first.id, ENTITY_TYPE_INTRUSION_SET);
    const applied = await queryAsAdminWithSuccess({
      query: DECIDE_MUTATION,
      variables: { id: aliasId, input: { decision: 'alias', rationale: 'A sub-group of the same actor', apply: true, target_id: second.id } },
    });
    expect(applied.data?.curationProposalDecide.proposal_status).toBe('accepted');
    expect(applied.data?.curationProposalDecide.adjudication.decision).toBe('alias');
    expect((await loadIntrusionSet(second.id)).aliases).toEqual([first.name]);

    const fourth = await createIntrusionSet(`${PREFIX} Decision Four`);
    const recordedId = await createProposal(mergeDraft(fourth, third));
    const recorded = await queryAsAdminWithSuccess({
      query: DECIDE_MUTATION,
      variables: { id: recordedId, input: { decision: 'merge', rationale: 'Probably the same actor', agent_slug: 'opencti-curator', model: 'test-model' } },
    });
    expect(recorded.data?.curationProposalDecide.proposal_status).toBe('open');
    expect(recorded.data?.curationProposalDecide.adjudication.rationale).toBe('Probably the same actor');
    const distinct = await queryAsAdminWithSuccess({
      query: DECIDE_MUTATION,
      variables: { id: recordedId, input: { decision: 'distinct', rationale: 'Two different actors', apply: true } },
    });
    expect(distinct.data?.curationProposalDecide.proposal_status).toBe('rejected');
    expect(await loadIntrusionSet(third.id)).toBeDefined();
  });

  it('should create a single proposal when the same finding is persisted concurrently', async () => {
    const element = await createIntrusionSet(`${PREFIX} Concurrent`);
    const settings = await getCurationSettings(testContext);
    const draft: ProposalDraft = {
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [subjectOf(element)],
      target_id: element.id,
      recommended_action: ACTION_ACKNOWLEDGE,
      evidence: evidenceFor('no_recent_activity', 'No update for 24 months'),
      confidence: 0.5,
    };
    const results = await Promise.all([1, 2, 3].map(() => persistProposalDraft(testContext, settings, draft)));
    const ids = new Set(results.map((result) => result.proposal?.internal_id));
    ids.forEach((id) => createdProposalIds.push(id as string));
    expect(ids.size).toBe(1);
    expect(results.filter((result) => result.created)).toHaveLength(1);
  });

  const LONG_AGO = '2020-01-01T00:00:00.000Z';
  const stalenessEvidence = [{
    evidence_type: EVIDENCE_STALENESS,
    score: 0.7,
    weight: 0.7,
    description: 'No update and no new relationship since 2020-01-01 (more than 12 months)',
    details: JSON.stringify({ last_activity: LONG_AGO, months: 12 }),
  }];
  const ageIntrusionSet = async (id: string) => {
    const stored = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_INTRUSION_SET) as unknown as BasicStoreEntity;
    await elUpdate(testContext, stored._index, stored.internal_id, {
      script: { source: 'ctx._source.updated_at = params.date', lang: 'painless', params: { date: LONG_AGO } },
    });
  };
  const createStaleProposal = (element: BasicStoreEntity) => createProposal({
    kind: PROPOSAL_KIND_STALE,
    detector: DETECTOR_STALENESS,
    subjects: [subjectOf(element)],
    target_id: element.id,
    recommended_action: ACTION_REVOKE,
    action_payload: { element_id: element.id },
    evidence: stalenessEvidence,
    confidence: 0.8,
  });

  it('should revoke an entity and restore it on revert', async () => {
    const stale = await createIntrusionSet(`${PREFIX} Stale`);
    await ageIntrusionSet(stale.id);
    const id = await createStaleProposal(stale);
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: ACCEPT_MUTATION, variables: { id } });
    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id } });
    expect((await loadIntrusionSet(stale.id)).revoked).toBe(true);
    await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    expect((await loadIntrusionSet(stale.id)).revoked).toBe(false);
  });

  it('should not revoke an entity that was updated since its staleness proposal', async () => {
    const updated = await createIntrusionSet(`${PREFIX} Stale Updated`);
    const id = await createStaleProposal(updated);
    const refused = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
    expect(refused.errors?.[0]?.message).toContain('not stale any more');
    expect((await loadIntrusionSet(updated.id)).revoked).toBe(false);
    expect((await loadProposal(id)).proposal_status).toBe('open');
  });

  it('should not revoke an entity that gained a relationship since its staleness proposal', async () => {
    const related = await createIntrusionSet(`${PREFIX} Stale Related`);
    await ageIntrusionSet(related.id);
    const id = await createStaleProposal(related);
    const malware = track(await addMalware(testContext, ADMIN_USER, { name: `${PREFIX} stale malware`, is_family: true }), ENTITY_TYPE_MALWARE);
    await createRelation(testContext, ADMIN_USER, { fromId: related.id, toId: malware.id, relationship_type: RELATION_USES });
    const refused = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
    expect(refused.errors?.[0]?.message).toContain('not stale any more');
    expect((await loadIntrusionSet(related.id)).revoked).toBe(false);
  });

  it('should set the authoritative value of a field, and keep a later edit on revert', async () => {
    const element = await createIntrusionSet(`${PREFIX} Field`, { description: 'From a secondary source' });
    const id = await createProposal({
      kind: PROPOSAL_KIND_FIELD_PRECEDENCE,
      detector: DETECTOR_FIELD_AUTHORITY,
      subjects: [subjectOf(element)],
      target_id: element.id,
      recommended_action: ACTION_SET_FIELD,
      action_payload: { element_id: element.id, key: 'description', value: 'From the authoritative source', overwritten_value: 'From a secondary source' },
      evidence: evidenceFor('field_conflict', 'The authoritative source wrote another value'),
      confidence: 0.9,
    });
    // An accept never writes another value than the detector's.
    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { action_payload: JSON.stringify({ value: 'Something else' }) } } });
    expect((await loadIntrusionSet(element.id)).description).toBe('From the authoritative source');
    await updateAttribute(testContext, ADMIN_USER, element.id, ENTITY_TYPE_INTRUSION_SET, [{ key: 'description', value: ['Edited by an analyst'] }]);
    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    expect(reverted.data?.curationProposalRevert.proposal_status).toBe('reverted');
    expect((await loadIntrusionSet(element.id)).description).toBe('Edited by an analyst');
  });

  it('should not restore the authoritative value of a field written again since its proposal', async () => {
    const element = await createIntrusionSet(`${PREFIX} Field Rewritten`, { description: 'From a secondary source' });
    const id = await createProposal({
      kind: PROPOSAL_KIND_FIELD_PRECEDENCE,
      detector: DETECTOR_FIELD_AUTHORITY,
      subjects: [subjectOf(element)],
      target_id: element.id,
      recommended_action: ACTION_SET_FIELD,
      action_payload: { element_id: element.id, key: 'description', value: 'From the authoritative source', overwritten_value: 'From a secondary source' },
      evidence: evidenceFor('field_conflict', 'The authoritative source wrote another value'),
      confidence: 0.9,
    });
    await updateAttribute(testContext, ADMIN_USER, element.id, ENTITY_TYPE_INTRUSION_SET, [{ key: 'description', value: ['Newer authoritative value'] }]);
    const refused = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
    expect(refused.errors?.[0]?.message).toContain('written again since the proposal was raised');
    expect((await loadIntrusionSet(element.id)).description).toBe('Newer authoritative value');
    expect((await loadProposal(id)).proposal_status).toBe('open');
  });

  it('should ignore an action payload that is not an object, and refuse one that is not JSON', async () => {
    const element = await createIntrusionSet(`${PREFIX} Payload`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [subjectOf(element)],
      target_id: element.id,
      recommended_action: ACTION_ACKNOWLEDGE,
      evidence: evidenceFor('no_recent_activity', 'No update for 24 months'),
      confidence: 0.5,
    });
    const malformed = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id, input: { action_payload: '[1, 2]' } } });
    expect(malformed.errors).toBeUndefined();
    expect(malformed.data?.curationProposalAccept.proposal_status).toBe('accepted');
    const second = await createIntrusionSet(`${PREFIX} Payload Two`);
    const otherId = await createProposal({
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [subjectOf(second)],
      target_id: second.id,
      recommended_action: ACTION_ACKNOWLEDGE,
      evidence: evidenceFor('no_recent_activity', 'No update for 24 months'),
      confidence: 0.5,
    });
    const invalid = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id: otherId, input: { action_payload: '{not json' } } });
    expect(invalid.errors?.[0]?.message).toContain('The action payload must be a JSON object');
  });

  it('should keep the chosen attribution, and restore the removed one from the trash on revert', async () => {
    const campaign = track(await addCampaign(testContext, ADMIN_USER, { name: `${PREFIX} Campaign` }), ENTITY_TYPE_CAMPAIGN) as BasicStoreEntity;
    const kept = await createIntrusionSet(`${PREFIX} Attribution Kept`);
    const removed = await createIntrusionSet(`${PREFIX} Attribution Removed`);
    const keptRelation = await createRelation(testContext, ADMIN_USER, { fromId: campaign.id, toId: kept.id, relationship_type: RELATION_ATTRIBUTED_TO });
    const removedRelation = await createRelation(testContext, ADMIN_USER, { fromId: campaign.id, toId: removed.id, relationship_type: RELATION_ATTRIBUTED_TO });
    const id = await createProposal({
      kind: PROPOSAL_KIND_CONTRADICTION,
      detector: DETECTOR_CONTRADICTION,
      subjects: [subjectOf(campaign), subjectOf(kept), subjectOf(removed)],
      target_id: campaign.id,
      recommended_action: ACTION_RESOLVE_ATTRIBUTION,
      action_payload: {
        relationships: [
          { actor_id: kept.id, relationship_id: keptRelation.id },
          { actor_id: removed.id, relationship_id: removedRelation.id },
        ],
      },
      evidence: evidenceFor('attribution_conflict', 'The campaign is attributed to two distinct intrusion sets'),
      confidence: 0.9,
    });
    const unchosen = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
    expect(unchosen.errors?.[0]?.message).toContain('Choose which attribution to keep');

    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { action_payload: JSON.stringify({ keep_actor_id: kept.id }) } } });
    expect(await storeLoadById(testContext, ADMIN_USER, removedRelation.id, RELATION_ATTRIBUTED_TO)).toBeUndefined();
    expect(await storeLoadById(testContext, ADMIN_USER, keptRelation.id, RELATION_ATTRIBUTED_TO)).toBeDefined();

    // The platform refuses to re-create an element during the 5 seconds that follow its deletion.
    await wait(5010);
    await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    expect(await storeLoadById(testContext, ADMIN_USER, removedRelation.id, RELATION_ATTRIBUTED_TO)).toBeDefined();
  });

  it('should carry the restrictions of the attributions in conflict, and never resolve one the user cannot read', async () => {
    const campaign = track(await addCampaign(testContext, ADMIN_USER, { name: `${PREFIX} Hidden Campaign` }), ENTITY_TYPE_CAMPAIGN) as BasicStoreEntity;
    const kept = await createIntrusionSet(`${PREFIX} Hidden Attribution Kept`);
    const hidden = await createIntrusionSet(`${PREFIX} Hidden Attribution Removed`);
    const keptRelation = await createRelation(testContext, ADMIN_USER, { fromId: campaign.id, toId: kept.id, relationship_type: RELATION_ATTRIBUTED_TO });
    const hiddenRelation = await createRelation(testContext, ADMIN_USER, { fromId: campaign.id, toId: hidden.id, relationship_type: RELATION_ATTRIBUTED_TO });
    const draft: ProposalDraft = {
      kind: PROPOSAL_KIND_CONTRADICTION,
      detector: DETECTOR_CONTRADICTION,
      subjects: [subjectOf(campaign), subjectOf(kept), subjectOf(hidden)],
      target_id: campaign.id,
      recommended_action: ACTION_RESOLVE_ATTRIBUTION,
      action_payload: {
        relationships: [
          { actor_id: kept.id, relationship_id: keptRelation.id },
          { actor_id: hidden.id, relationship_id: hiddenRelation.id },
        ],
      },
      evidence: evidenceFor('attribution_conflict', 'The campaign is attributed to two distinct intrusion sets'),
      confidence: 0.9,
    };
    const id = await createProposal(draft);
    const markingsOf = async () => {
      const stored = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as Record<string, string[]>;
      return stored[RELATION_OBJECT_MARKING] ?? [];
    };
    expect(await markingsOf()).toHaveLength(0);
    expect((await queryAsUserWithSuccess(USER_EDITOR, { query: PROPOSAL_QUERY, variables: { id } })).data?.curationProposal).not.toBeNull();

    // One attribution becomes TLP:RED before the proposal follows it: the editor, who cannot read it, can neither read
    // the proposal nor resolve it, since every read checks the relationships the action names.
    await updateAttribute(testContext, ADMIN_USER, hiddenRelation.id, RELATION_ATTRIBUTED_TO, [
      { key: INPUT_MARKINGS, value: [MARKING_TLP_RED], operation: EditOperation.Add },
    ]);
    expect((await queryAsUserWithSuccess(USER_EDITOR, { query: PROPOSAL_QUERY, variables: { id } })).data?.curationProposal).toBeNull();
    await queryAsUserIsExpectedError(
      USER_EDITOR,
      { query: ACCEPT_MUTATION, variables: { id, input: { action_payload: JSON.stringify({ keep_actor_id: kept.id }) } } },
      'Curation proposal not found',
      'FUNCTIONAL_ERROR',
    );
    expect(await storeLoadById(testContext, ADMIN_USER, hiddenRelation.id, RELATION_ATTRIBUTED_TO)).toBeDefined();
    expect((await loadProposal(id)).proposal_status).toBe('open');

    // The proposal then carries the marking of the attribution: found again through its endpoints, or detected again.
    expect(await refreshProposalRestrictions(testContext, [campaign.id])).toBe(1);
    expect(await markingsOf()).toHaveLength(1);
    expect((await queryAsUserWithSuccess(USER_EDITOR, { query: PROPOSAL_QUERY, variables: { id } })).data?.curationProposal).toBeNull();
    const settings = await getCurationSettings(testContext);
    const redetected = await persistProposalDraft(testContext, settings, draft);
    expect(redetected.proposal?.internal_id).toBe(id);
    expect(await markingsOf()).toHaveLength(1);
  });

  it('should move an unchanged open proposal in and out of the ambiguous band when the band changes', async () => {
    const left = await createIntrusionSet(`${PREFIX} Band Left`);
    const right = await createIntrusionSet(`${PREFIX} Band Right`);
    const draft: ProposalDraft = {
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(left), subjectOf(right)],
      target_id: left.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    };
    const settings = await getCurationSettings(testContext);
    const id = await createProposal(draft);
    const inBand = async () => (await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as BasicStoreEntityCurationProposal).in_ambiguous_band;
    // The same finding detected again once the band covers its confidence, then once it does not any more.
    const widened = await persistProposalDraft(testContext, { ...settings, ambiguous_band_min: 0.5, ambiguous_band_max: 0.95 }, draft);
    expect(widened.proposal?.internal_id).toBe(id);
    expect(await inBand()).toBe(true);
    await persistProposalDraft(testContext, { ...settings, ambiguous_band_min: 0.1, ambiguous_band_max: 0.2 }, draft);
    expect(await inBand()).toBe(false);
  });

  it('should reactivate a revoked indicator that an active observable is still based on', async () => {
    const indicator = track(await addIndicator(testContext, ADMIN_USER, {
      name: `${PREFIX} indicator`,
      pattern: "[ipv4-addr:value = '198.51.100.77']",
      pattern_type: 'stix',
      x_opencti_main_observable_type: 'IPv4-Addr',
    } as any), ENTITY_TYPE_INDICATOR) as unknown as BasicStoreEntity;
    const observable = track(
      await addStixCyberObservable(testContext, ADMIN_USER, { type: ENTITY_IPV4_ADDR, IPv4Addr: { value: '198.51.100.77' }, x_opencti_score: 80 }),
      ENTITY_IPV4_ADDR,
    ) as unknown as BasicStoreEntity;
    await createRelation(testContext, ADMIN_USER, { fromId: indicator.id, toId: observable.id, relationship_type: RELATION_BASED_ON });
    const created = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    const revokeScore = created.decay_applied_rule?.decay_revoke_score;
    expect(revokeScore).toBeTypeOf('number');
    // Revoked as the decay manager leaves it: at its revoke score, with the decay state of its first lifetime.
    await updateAttribute(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR, [
      { key: 'revoked', value: [true] },
      { key: 'x_opencti_score', value: [revokeScore] },
    ]);
    const revoked = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    // The observable the indicator is based on is seen active after the revocation.
    await wait(10);
    await updateAttribute(testContext, ADMIN_USER, observable.id, ENTITY_IPV4_ADDR, [{ key: 'x_opencti_score', value: [90] }]);
    const id = await createProposal({
      kind: PROPOSAL_KIND_CONTRADICTION,
      detector: DETECTOR_CONTRADICTION,
      subjects: [{ id: indicator.id, entity_type: ENTITY_TYPE_INDICATOR, name: indicator.name }],
      target_id: indicator.id,
      recommended_action: ACTION_UNREVOKE_INDICATOR,
      action_payload: { indicator_id: indicator.id },
      evidence: evidenceFor('revoked_indicator', 'A revoked indicator is still the basis of an active observable'),
      confidence: 0.75,
    });
    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id } });
    const reactivated = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    expect(reactivated.revoked).toBe(false);
    // Reactivated as an edit of the Indicator does: its decay restarts from its base score, so the decay manager does not
    // revoke it again at its next run.
    expect(reactivated.x_opencti_score).toBe(created.decay_base_score);
    expect(new Date(reactivated.decay_base_score_date).getTime()).toBeGreaterThan(new Date(revoked.decay_base_score_date).getTime());
    expect(new Date(reactivated.valid_until).getTime()).toBeGreaterThan(Date.now());
    // The revert puts the Indicator back as it was, decay state included.
    await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    const restored = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    expect(restored.revoked).toBe(true);
    expect(restored.x_opencti_score).toBe(revokeScore);
    expect(restored.decay_base_score_date).toBe(revoked.decay_base_score_date);
    expect(restored.valid_until).toBe(revoked.valid_until);
  });

  it('should revoke a decayed indicator as an edit of the indicator does, and restore it on revert', async () => {
    const indicator = track(await addIndicator(testContext, ADMIN_USER, {
      name: `${PREFIX} decayed indicator`,
      pattern: "[ipv4-addr:value = '198.51.100.79']",
      pattern_type: 'stix',
      x_opencti_main_observable_type: 'IPv4-Addr',
    } as any), ENTITY_TYPE_INDICATOR) as unknown as BasicStoreEntity;
    const created = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    const revokeScore = created.decay_applied_rule?.decay_revoke_score;
    expect(revokeScore).toBeTypeOf('number');
    // Decayed to its revoke score but not revoked yet.
    await updateAttribute(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR, [{ key: 'x_opencti_score', value: [revokeScore] }]);
    const decayed = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    const id = await createProposal({
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [{ id: indicator.id, entity_type: ENTITY_TYPE_INDICATOR, name: indicator.name }],
      target_id: indicator.id,
      recommended_action: ACTION_REVOKE,
      action_payload: { element_id: indicator.id },
      evidence: evidenceFor('decayed_indicator', 'The decayed score of the indicator fell to its revoke score'),
      confidence: 0.6,
    });
    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id } });
    const revoked = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    expect(revoked.revoked).toBe(true);
    expect(revoked.x_opencti_detection).toBe(false);
    expect(new Date(revoked.valid_until).getTime()).toBeLessThanOrEqual(Date.now());
    expect(revoked.decay_history.length).toBe((decayed.decay_history ?? []).length + 1);
    await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    const restored = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    expect(restored.revoked).toBe(false);
    expect(restored.x_opencti_detection).toBe(decayed.x_opencti_detection);
    expect(restored.valid_until).toBe(decayed.valid_until);
  });

  it('should not reactivate an indicator that is not revoked any more', async () => {
    const indicator = track(await addIndicator(testContext, ADMIN_USER, {
      name: `${PREFIX} reactivated indicator`,
      pattern: "[ipv4-addr:value = '198.51.100.78']",
      pattern_type: 'stix',
      x_opencti_main_observable_type: 'IPv4-Addr',
    } as any), ENTITY_TYPE_INDICATOR) as unknown as BasicStoreEntity;
    await updateAttribute(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR, [{ key: 'revoked', value: [true] }]);
    const id = await createProposal({
      kind: PROPOSAL_KIND_CONTRADICTION,
      detector: DETECTOR_CONTRADICTION,
      subjects: [{ id: indicator.id, entity_type: ENTITY_TYPE_INDICATOR, name: indicator.name }],
      target_id: indicator.id,
      recommended_action: ACTION_UNREVOKE_INDICATOR,
      action_payload: { indicator_id: indicator.id },
      evidence: evidenceFor('revoked_indicator', 'A revoked indicator is still the basis of an active observable'),
      confidence: 0.75,
    });
    // Reactivated by an analyst after the proposal was raised: the contradiction is resolved.
    await updateAttribute(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR, [{ key: 'revoked', value: [false] }]);
    const before = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    const refused = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
    expect(refused.errors?.[0]?.message).toContain('not revoked any more');
    const after = await storeLoadById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR) as unknown as Record<string, any>;
    expect(after.valid_until).toBe(before.valid_until);
    expect((await loadProposal(id)).proposal_status).toBe('open');
  });

  it('should keep both procedures of a relationship whose procedure was overwritten', async () => {
    const actor = await createIntrusionSet(`${PREFIX} Procedure Actor`);
    const malware = track(await addMalware(testContext, ADMIN_USER, { name: `${PREFIX} procedure malware`, is_family: true }), ENTITY_TYPE_MALWARE);
    const relation = await createRelation(testContext, ADMIN_USER, {
      fromId: actor.id,
      toId: malware.id,
      relationship_type: RELATION_USES,
      description: 'Loads the malware through a macro',
    });
    const id = await createProposal({
      kind: PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
      detector: DETECTOR_RELATIONSHIP_CONFLICT,
      subjects: [{ id: relation.id, entity_type: RELATION_USES, name: `${actor.name} uses ${malware.name}` }],
      target_id: relation.id,
      recommended_action: ACTION_PRESERVE_PROCEDURE,
      action_payload: {
        relationship_id: relation.id,
        previous: { text: 'Delivers the malware by spear phishing', source_id: null },
        current: { text: 'Loads the malware through a macro', source_id: null },
      },
      evidence: evidenceFor('procedure_conflict', 'Two sources describe different procedures'),
      confidence: 0.8,
    });
    const accepted = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id } });
    expect(accepted.data?.curationProposalAccept.proposal_status).toBe('accepted');
    expect(accepted.data?.curationProposalAccept.applied_patch).toBeTruthy();
    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    expect(reverted.data?.curationProposalRevert.proposal_status).toBe('reverted');
  });

  it('should reject proposals in bulk and queue a bulk accept', async () => {
    const drafts = await Promise.all([1, 2, 3].map((index) => createIntrusionSet(`${PREFIX} Bulk ${index}`)));
    const ids: string[] = [];
    for (let index = 0; index < drafts.length; index += 1) {
      ids.push(await createProposal({
        kind: PROPOSAL_KIND_STALE,
        detector: DETECTOR_STALENESS,
        subjects: [subjectOf(drafts[index])],
        target_id: drafts[index].id,
        recommended_action: ACTION_ACKNOWLEDGE,
        evidence: evidenceFor('no_recent_activity', 'No update for 24 months'),
        confidence: 0.5,
      }));
    }
    const empty = await queryAsAdmin({ query: BULK_REJECT_MUTATION, variables: { ids: [] } });
    expect(empty.errors?.[0]?.message).toContain('Bulk reject handles between 1 and');
    const rejected = await queryAsAdminWithSuccess({ query: BULK_REJECT_MUTATION, variables: { ids: [ids[0], ids[1], ids[0]], rationale: 'Still relevant' } });
    expect(rejected.data?.curationProposalsBulkReject.sort()).toEqual([ids[0], ids[1]].sort());
    expect((await loadProposal(ids[0])).decision_rationale).toBe('Still relevant');
    // Proposals already decided are left out of a second bulk reject.
    const none = await queryAsAdminWithSuccess({ query: BULK_REJECT_MUTATION, variables: { ids: [ids[0]] } });
    expect(none.data?.curationProposalsBulkReject).toEqual([]);

    const emptyAccept = await queryAsAdmin({ query: BULK_ACCEPT_MUTATION, variables: { ids: [] } });
    expect(emptyAccept.errors?.[0]?.message).toContain('Bulk accept handles between 1 and');
    // An attribution contradiction takes the attribution to keep: it is accepted on its own, never in a bulk accept.
    const choiceId = await createProposal({
      kind: PROPOSAL_KIND_CONTRADICTION,
      detector: DETECTOR_CONTRADICTION,
      subjects: [subjectOf(drafts[2])],
      target_id: drafts[2].id,
      recommended_action: ACTION_RESOLVE_ATTRIBUTION,
      action_payload: { relationships: [] },
      evidence: evidenceFor('attribution_conflict', 'Attributed to two distinct intrusion sets'),
      confidence: 0.9,
    });
    expect((await loadProposal(choiceId)).choice_required).toBe(true);
    expect((await loadProposal(ids[2])).choice_required).toBe(false);
    const withChoice = await queryAsAdmin({ query: BULK_ACCEPT_MUTATION, variables: { ids: [ids[2], choiceId] } });
    expect(withChoice.errors?.[0]?.message).toContain('Some selected proposals need a choice');
    // Every requested proposal must be readable by the initiator: a hidden or unknown one refuses the whole task.
    const hidden = await createIntrusionSet(`${PREFIX} Bulk hidden`, { objectMarking: [MARKING_TLP_RED] });
    const hiddenId = await createProposal({
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [subjectOf(hidden)],
      target_id: hidden.id,
      recommended_action: ACTION_ACKNOWLEDGE,
      evidence: evidenceFor('no_recent_activity', 'No update for 24 months'),
      confidence: 0.5,
    });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: BULK_ACCEPT_MUTATION, variables: { ids: [ids[2], hiddenId] } });
    const unknown = await queryAsAdmin({ query: BULK_ACCEPT_MUTATION, variables: { ids: [ids[2], 'a5c2b8f4-5d0e-4a3b-9a57-0b1d2b0c1f10'] } });
    expect(unknown.errors?.[0]?.message).toContain('do not exist or are not accessible');
    const revisionBeforeQueue = (await storeLoadById(testContext, ADMIN_USER, ids[2], ENTITY_TYPE_CURATION_PROPOSAL) as unknown as { updated_at: string }).updated_at;
    const task = await queryAsAdminWithSuccess({ query: BULK_ACCEPT_MUTATION, variables: { ids: [ids[2]] } });
    expect(task.data?.curationProposalsBulkAccept).toBeTruthy();
    // The task keeps the revision of each proposal it was queued on, which the worker sends back with the apply.
    const queued = await storeLoadById(testContext, ADMIN_USER, task.data?.curationProposalsBulkAccept, ENTITY_TYPE_BACKGROUND_TASK) as unknown as {
      actions: Array<{ context: { revisions: Record<string, string> } }>;
    };
    const queuedRevision = queued.actions[0].context.revisions[ids[2]];
    expect(new Date(queuedRevision).getTime()).toBe(new Date(revisionBeforeQueue).getTime());
    // The background task applies it through the apply mutation, as the worker does (the worker may have done it already).
    const applied = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: ids[2], expectedUpdatedAt: queuedRevision } });
    expect(applied.data?.curationProposalApply.proposal_status).toBe('accepted');
    const replayed = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: ids[2] } });
    expect(replayed.data?.curationProposalApply.proposal_status).toBe('accepted');
  });

  it('should refuse an adjudication while adjudication is disabled', async () => {
    const element = await createIntrusionSet(`${PREFIX} Adjudication`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [subjectOf(element)],
      target_id: element.id,
      recommended_action: ACTION_ACKNOWLEDGE,
      evidence: evidenceFor('no_recent_activity', 'No update for 24 months'),
      confidence: 0.5,
    });
    const available = await queryAsAdminWithSuccess({ query: ADJUDICATION_AVAILABLE_QUERY, variables: {} });
    expect(available.data?.curationAdjudicationAvailable).toBe(false);
    const refused = await queryAsAdmin({ query: ADJUDICATE_MUTATION, variables: { id } });
    expect(refused.errors?.[0]?.message).toContain('Curation adjudication is disabled');
    expect((await loadProposal(id)).adjudicable).toBe(false);
  });

  it('should find the open contradictions of the subjects a policy checks, and only theirs', async () => {
    const contradicted = await createIntrusionSet(`${PREFIX} Contradicted`);
    const clean = await createIntrusionSet(`${PREFIX} Not contradicted`);
    await createProposal({
      kind: PROPOSAL_KIND_CONTRADICTION,
      detector: DETECTOR_CONTRADICTION,
      subjects: [subjectOf(contradicted)],
      target_id: contradicted.id,
      recommended_action: ACTION_ACKNOWLEDGE,
      evidence: evidenceFor('date_inversion', 'first_seen is after last_seen'),
      confidence: 0.95,
    });
    const aliasProposal = async (subject: BasicStoreEntity) => {
      const id = await createProposal({
        kind: PROPOSAL_KIND_ALIAS,
        detector: DETECTOR_NORMALIZATION,
        subjects: [subjectOf(subject)],
        target_id: subject.id,
        recommended_action: ACTION_ADD_ALIASES,
        action_payload: { aliases: [`${subject.name} taxonomy name`] },
        evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
        confidence: 0.95,
      });
      return storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as Promise<BasicStoreEntityCurationProposal>;
    };
    const onContradicted = await aliasProposal(contradicted);
    const onClean = await aliasProposal(clean);
    expect((await loadPolicyFacts(testContext, [onContradicted])).hasOpenContradiction(onContradicted)).toBe(true);
    expect((await loadPolicyFacts(testContext, [onClean])).hasOpenContradiction(onClean)).toBe(false);
  });

  it('should count a stale entity once in the Knowledge Health, whatever the number of its open staleness proposals', async () => {
    const settings = await getCurationSettings(testContext);
    const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    const before = (await computeHealthMetrics(testContext, settings, since)).stale_count;
    const stale = await createIntrusionSet(`${PREFIX} Stale twice`);
    const staleness = (lastActivity: string) => [{
      evidence_type: EVIDENCE_STALENESS,
      score: 1,
      weight: 1,
      description: `No update since ${lastActivity}`,
      details: JSON.stringify({ last_activity: lastActivity, months: 12 }),
    }];
    // Found stale, updated, then found stale again: the first proposal is still open next to the second one.
    for (const lastActivity of ['2023-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z']) {
      await createProposal({
        kind: PROPOSAL_KIND_STALE,
        detector: DETECTOR_STALENESS,
        subjects: [subjectOf(stale)],
        target_id: stale.id,
        recommended_action: ACTION_REVOKE,
        evidence: staleness(lastActivity),
        confidence: 0.7,
      });
    }
    expect((await computeHealthMetrics(testContext, settings, since)).stale_count).toBe(before + 1);

    // Its proposals outlive it: once deleted, the entity no longer counts as stale knowledge.
    await deleteElementById(testContext, ADMIN_USER, stale.id, ENTITY_TYPE_INTRUSION_SET);
    expect((await computeHealthMetrics(testContext, settings, since)).stale_count).toBe(before);
  });

  it('should count a contradiction in the Knowledge Health only while the entity it is about exists', async () => {
    const settings = await getCurationSettings(testContext);
    const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    const before = (await computeHealthMetrics(testContext, settings, since)).contradiction_count;
    const inverted = await createIntrusionSet(`${PREFIX} Inverted dates`);
    await createProposal({
      kind: PROPOSAL_KIND_CONTRADICTION,
      detector: DETECTOR_CONTRADICTION,
      subjects: [subjectOf(inverted)],
      target_id: inverted.id,
      recommended_action: ACTION_FIX_DATES,
      evidence: evidenceFor('date_inversion', 'First seen is after last seen'),
      confidence: 0.95,
    });
    expect((await computeHealthMetrics(testContext, settings, since)).contradiction_count).toBe(before + 1);
    await deleteElementById(testContext, ADMIN_USER, inverted.id, ENTITY_TYPE_INTRUSION_SET);
    expect((await computeHealthMetrics(testContext, settings, since)).contradiction_count).toBe(before);
  });

  it('should remove the open proposals about a deleted entity, and keep the ones about entities that exist', async () => {
    const deleted = await createIntrusionSet(`${PREFIX} Retired Deleted`);
    const kept = await createIntrusionSet(`${PREFIX} Retired Kept`);
    const proposalAbout = (element: BasicStoreEntity) => createProposal({
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [subjectOf(element)],
      target_id: element.id,
      recommended_action: ACTION_ACKNOWLEDGE,
      evidence: evidenceFor('no_recent_activity', 'No update for 24 months'),
      confidence: 0.5,
    });
    const deletedProposalId = await proposalAbout(deleted);
    const keptProposalId = await proposalAbout(kept);
    // Named in a deletion event while it still exists (restored since): nothing is removed.
    expect(await retireProposalsOfDeletedSubjects(testContext, [kept.id])).toBe(0);
    await deleteElementById(testContext, ADMIN_USER, deleted.id, ENTITY_TYPE_INTRUSION_SET);
    expect(await retireProposalsOfDeletedSubjects(testContext, [deleted.id, kept.id])).toBe(1);
    expect(await loadProposal(deletedProposalId)).toBeNull();
    expect((await loadProposal(keptProposalId))?.proposal_status).toBe('open');
  });

  it('should follow the survivor a new detection prefers, and drop the adjudication of the previous recommendation', async () => {
    const first = await createIntrusionSet(`${PREFIX} Survivor First`);
    const second = await createIntrusionSet(`${PREFIX} Survivor Second`);
    const draft: ProposalDraft = {
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(first), subjectOf(second)],
      target_id: first.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    };
    const id = await createProposal(draft);
    const load = async () => storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as Promise<BasicStoreEntityCurationProposal>;
    const stored = await load();
    await elUpdate(testContext, stored._index, stored.internal_id, {
      script: { source: 'ctx._source.curation_adjudication = params.adjudication', lang: 'painless', params: { adjudication: { decision: 'merge', applied: false } } },
    });
    const settings = await getCurationSettings(testContext);
    // The other entity gained the relationships: the duplicate detection now prefers it as the survivor.
    const { proposal, created } = await persistProposalDraft(testContext, settings, { ...draft, target_id: second.id });
    expect(created).toBe(false);
    expect(proposal?.internal_id).toBe(id);
    const refreshed = await load();
    expect(refreshed.target_id).toBe(second.id);
    expect(refreshed.curation_adjudication ?? null).toBeNull();
  });

  it('should request a full scan', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SCAN_REQUEST_MUTATION, variables: {} });
    const requested = await queryAsAdminWithSuccess({ query: SCAN_REQUEST_MUTATION, variables: {} });
    expect(requested.data?.curationScanRequest.force_scan).toBe(true);
  });

  it('should keep the restrictions of an open proposal in line with its subjects, never widening it while one is gone', async () => {
    const kept = await createIntrusionSet(`${PREFIX} Restricted Kept`);
    const removed = await createIntrusionSet(`${PREFIX} Restricted Removed`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(kept), subjectOf(removed)],
      target_id: kept.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    const markingsOf = async () => {
      const stored = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as Record<string, string[]>;
      return stored[RELATION_OBJECT_MARKING] ?? [];
    };
    const reclassify = (subjectId: string, operation: EditOperation) => updateAttribute(testContext, ADMIN_USER, subjectId, ENTITY_TYPE_INTRUSION_SET, [
      { key: INPUT_MARKINGS, value: [MARKING_TLP_RED], operation },
    ]);
    expect(await markingsOf()).toHaveLength(0);

    await reclassify(kept.id, EditOperation.Add);
    expect(await refreshProposalRestrictions(testContext, [kept.id])).toBe(1);
    expect(await markingsOf()).toHaveLength(1);
    const readByParticipant = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: PROPOSAL_QUERY, variables: { id } });
    expect(readByParticipant.data?.curationProposal).toBeNull();

    // The proposal still names the deleted subject: losing the marking of the other one does not widen it.
    await deleteElementById(testContext, ADMIN_USER, removed.id, ENTITY_TYPE_INTRUSION_SET);
    await reclassify(kept.id, EditOperation.Remove);
    expect(await refreshProposalRestrictions(testContext, [kept.id])).toBe(0);
    expect(await markingsOf()).toHaveLength(1);
  });

  it('should refuse a decision taken on a proposal that changed since it was read', async () => {
    const first = await createIntrusionSet(`${PREFIX} Revision First`);
    const second = await createIntrusionSet(`${PREFIX} Revision Second`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(first), subjectOf(second)],
      target_id: first.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    const read = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as { updated_at: string };
    const readAt = new Date(read.updated_at);
    const input = { decision: 'distinct', rationale: 'Different actors', apply: true };
    // Read before a later change: refused under the transition lock, nothing is decided.
    const refused = await queryAsAdmin({
      query: DECIDE_MUTATION,
      variables: { id, input: { ...input, expected_updated_at: new Date(readAt.getTime() - 1000).toISOString() } },
    });
    expect(refused.errors?.[0]?.message).toContain('changed since it was read');
    expect((await loadProposal(id)).proposal_status).toBe('open');
    const decided = await queryAsAdminWithSuccess({ query: DECIDE_MUTATION, variables: { id, input: { ...input, expected_updated_at: readAt.toISOString() } } });
    expect(decided.data?.curationProposalDecide.proposal_status).toBe('rejected');
  });

  it('should refuse an acceptance of a proposal that changed since it was read', async () => {
    const target = await createIntrusionSet(`${PREFIX} Accept Revision`);
    const proposedName = `${PREFIX} Accept Revision Alias`;
    const id = await createProposal({
      kind: PROPOSAL_KIND_ALIAS,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target)],
      target_id: target.id,
      recommended_action: ACTION_ADD_ALIASES,
      action_payload: { aliases: [proposedName] },
      evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
      confidence: 0.7,
    });
    const read = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as { updated_at: string };
    const readAt = new Date(read.updated_at);
    // Read before a later refresh: refused, and the graph is left as it was.
    const refused = await queryAsAdmin({
      query: ACCEPT_MUTATION,
      variables: { id, input: { expected_updated_at: new Date(readAt.getTime() - 1000).toISOString() } },
    });
    expect(refused.errors?.[0]?.message).toContain('changed since it was read');
    expect((await loadProposal(id)).proposal_status).toBe('open');
    expect((await loadIntrusionSet(target.id)).aliases ?? []).toEqual([]);
    const accepted = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { expected_updated_at: readAt.toISOString() } } });
    expect(accepted.data?.curationProposalAccept.proposal_status).toBe('accepted');
    expect((await loadIntrusionSet(target.id)).aliases).toEqual([proposedName]);
  });

  it('should refuse the task apply of a proposal refreshed since the bulk accept was queued', async () => {
    const target = await createIntrusionSet(`${PREFIX} Queued Revision`);
    const proposedName = `${PREFIX} Queued Revision Alias`;
    const id = await createProposal({
      kind: PROPOSAL_KIND_ALIAS,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target)],
      target_id: target.id,
      recommended_action: ACTION_ADD_ALIASES,
      action_payload: { aliases: [proposedName] },
      evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
      confidence: 0.7,
    });
    const queuedAt = new Date((await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as { updated_at: string }).updated_at);
    const stale = await queryAsAdmin({ query: APPLY_MUTATION, variables: { id, expectedUpdatedAt: new Date(queuedAt.getTime() - 1000).toISOString() } });
    expect(stale.errors?.[0]?.message).toContain('changed since it was read');
    expect((await loadProposal(id)).proposal_status).toBe('open');
    expect((await loadIntrusionSet(target.id)).aliases ?? []).toEqual([]);
    const applied = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id, expectedUpdatedAt: queuedAt.toISOString() } });
    expect(applied.data?.curationProposalApply.proposal_status).toBe('accepted');
    expect((await loadIntrusionSet(target.id)).aliases).toEqual([proposedName]);
  });

  it('should keep the content of a proposal whose application started, and not refuse its retry for that start', async () => {
    const target = await createIntrusionSet(`${PREFIX} Started Application`);
    const proposedName = `${PREFIX} Started Application Alias`;
    const draft: ProposalDraft = {
      kind: PROPOSAL_KIND_ALIAS,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target)],
      target_id: target.id,
      recommended_action: ACTION_ADD_ALIASES,
      action_payload: { aliases: [proposedName] },
      evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
      confidence: 0.7,
    };
    const id = await createProposal(draft);
    const read = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as { updated_at: string };
    // An acceptance marked the application as started, then stopped before the change.
    await wait(10);
    await middleware.patchAttribute(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL, { application_started_at: new Date().toISOString() });
    const settings = await getCurationSettings(testContext);
    type StoredProposal = { confidence_score: number; action_payload: unknown };
    const loadStored = async () => storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as Promise<StoredProposal>;
    // The same finding detected again: the proposal being applied is not refreshed.
    const again = await persistProposalDraft(testContext, settings, { ...draft, confidence: 0.9 });
    expect(again.created).toBe(false);
    expect((await loadStored()).confidence_score).toBe(0.7);
    // A detection finds the same entity with one more name: a new proposal, and the one being applied stays as it was.
    const superseding = await persistProposalDraft(testContext, settings, { ...draft, action_payload: { aliases: [proposedName, `${proposedName} Two`] } });
    expect(superseding.created).toBe(true);
    createdProposalIds.push(superseding.proposal?.internal_id as string);
    const { action_payload: payload } = await loadStored();
    expect(typeof payload === 'string' ? JSON.parse(payload) : payload).toEqual({ aliases: [proposedName] });
    // The retry, sent with the revision read before the start, records the application of that content.
    const accepted = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { expected_updated_at: read.updated_at } } });
    expect(accepted.data?.curationProposalAccept.proposal_status).toBe('accepted');
    expect((await loadIntrusionSet(target.id)).aliases).toEqual([proposedName]);
  });

  it('should hide a proposal from a user who lost access to a subject before its restrictions are refreshed', async () => {
    const reclassified = await createIntrusionSet(`${PREFIX} Live Check Reclassified`);
    const other = await createIntrusionSet(`${PREFIX} Live Check Other`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(reclassified), subjectOf(other)],
      target_id: reclassified.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    const FOR_ENTITY_QUERY = gql`
      query CurationActionsProposalsForEntity($id: ID!) {
        curationProposalsForEntity(id: $id) { id }
      }
    `;
    const ofOther = { mode: 'and', filters: [{ key: ['subject_ids'], values: [other.id] }], filterGroups: [] };
    const readByParticipant = async () => {
      const byId = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: PROPOSAL_QUERY, variables: { id } });
      const page = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: PROPOSALS_QUERY, variables: { first: 50, filters: ofOther } });
      const forEntity = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: FOR_ENTITY_QUERY, variables: { id: other.id } });
      return {
        byId: byId.data?.curationProposal?.id ?? null,
        listed: page.data?.curationProposals.edges.map((edge: { node: { id: string } }) => edge.node.id),
        count: page.data?.curationProposals.pageInfo.globalCount,
        forEntity: forEntity.data?.curationProposalsForEntity.map((proposal: { id: string }) => proposal.id),
      };
    };
    expect(await readByParticipant()).toEqual({ byId: id, listed: [id], count: 1, forEntity: [id] });

    // The subject is reclassified and the stored restrictions of the proposal are not refreshed yet.
    await updateAttribute(testContext, ADMIN_USER, reclassified.id, ENTITY_TYPE_INTRUSION_SET, [
      { key: INPUT_MARKINGS, value: [MARKING_TLP_RED], operation: EditOperation.Add },
    ]);
    expect(await readByParticipant()).toEqual({ byId: null, listed: [], count: 0, forEntity: [] });

    await updateAttribute(testContext, ADMIN_USER, reclassified.id, ENTITY_TYPE_INTRUSION_SET, [
      { key: INPUT_MARKINGS, value: [MARKING_TLP_RED], operation: EditOperation.Remove },
    ]);
    // The background refresh may have caught the reclassification: align the stored restrictions before reading.
    await refreshProposalRestrictions(testContext, [reclassified.id]);
    expect(await readByParticipant()).toEqual({ byId: id, listed: [id], count: 1, forEntity: [id] });
  });
  it('should recreate a removed duplicate on a partial unmerge, list the record, then close it', async () => {
    const target = await createIntrusionSet(`${PREFIX} Merge Target`);
    const restoredSource = await createIntrusionSet(`${PREFIX} Merge Restored`);
    const mergedSource = await createIntrusionSet(`${PREFIX} Merge Kept`);
    const malware = track(await addMalware(testContext, ADMIN_USER, { name: `${PREFIX} merge malware`, is_family: true }), ENTITY_TYPE_MALWARE);
    await createRelation(testContext, ADMIN_USER, { fromId: target.id, toId: malware.id, relationship_type: RELATION_USES });
    // Same relationship from a source: the merge removes it as a duplicate, the unmerge recreates it.
    const duplicate = await createRelation(testContext, ADMIN_USER, { fromId: restoredSource.id, toId: malware.id, relationship_type: RELATION_USES });
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target), subjectOf(restoredSource), subjectOf(mergedSource)],
      target_id: target.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    const accepted = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { target_id: target.id } } });
    expect(accepted.data?.curationProposalAccept.proposal_status).toBe('accepted');
    const recordId = (await queryAsAdminWithSuccess({ query: gql`query CurationActionsRecordOf($id: ID!) { curationProposal(id: $id) { merge_record_id } }`, variables: { id } }))
      .data?.curationProposal.merge_record_id as string;
    expect(await storeLoadById(testContext, ADMIN_USER, duplicate.id, RELATION_USES)).toBeUndefined();

    const listed = await queryAsUserWithSuccess(USER_EDITOR, { query: MERGE_RECORDS_QUERY, variables: { search: PREFIX } });
    const listedRecord = listed.data?.mergeRecords.edges.map((edge: { node: Record<string, any> }) => edge.node).find((node: { id: string }) => node.id === recordId);
    expect(listedRecord.merge_status).toBe('active');
    expect(listedRecord.relationships_recreatable_count).toBe(1);

    // A selection naming an entity the merge does not hold is refused as a whole: nothing is restored.
    const stale = await queryAsAdmin({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId, sourceIds: [restoredSource.id, malware.id] } });
    expect(stale.errors?.[0]?.message).toContain('Some selected entities are not waiting to be restored by this merge');
    expect(await loadIntrusionSet(restoredSource.id)).toBeUndefined();

    // The platform refuses to re-create an element during the 5 seconds that follow its deletion.
    await wait(5010);
    const partial = await queryAsAdminWithSuccess({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId, sourceIds: [restoredSource.id] } });
    expect(partial.data?.unmergeEntity.merge_status).toBe('partially_reverted');
    expect(await loadIntrusionSet(restoredSource.id)).toBeDefined();
    expect(await loadIntrusionSet(mergedSource.id)).toBeUndefined();
    expect(await storeLoadById(testContext, ADMIN_USER, duplicate.id, RELATION_USES)).toBeDefined();
    // An already restored entity is not waiting to be restored any more: the other one stays merged.
    const replayed = await queryAsAdmin({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId, sourceIds: [restoredSource.id, mergedSource.id] } });
    expect(replayed.errors?.[0]?.message).toContain('Some selected entities are not waiting to be restored by this merge');
    expect(await loadIntrusionSet(mergedSource.id)).toBeUndefined();

    const stored = await storeLoadById(testContext, ADMIN_USER, recordId, ENTITY_TYPE_MERGE_RECORD) as unknown as BasicStoreEntity;
    const setFields = (fields: Record<string, string>) => elUpdate(testContext, stored._index, stored.internal_id, {
      script: { source: 'for (def entry : params.fields.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }', lang: 'painless', params: { fields } },
    });
    await setFields({ reversible_until: '2020-01-01T00:00:00.000Z' });
    expect(await expireMergeRecords(testContext)).toBeGreaterThanOrEqual(1);
    const expired = await queryAsAdminWithSuccess({ query: MERGE_RECORDS_QUERY, variables: { search: PREFIX } });
    const expiredRecord = expired.data?.mergeRecords.edges.map((edge: { node: Record<string, any> }) => edge.node).find((node: { id: string }) => node.id === recordId);
    expect(expiredRecord.merge_status).toBe('irreversible');
    expect(expiredRecord.irreversible_reason).toBe('retention_over');
    expect(expiredRecord.is_reversible).toBe(false);

    // A record left pending by an interrupted merge, with a source still there, cannot be undone safely.
    await setFields({ merge_status: 'pending', created_at: '2020-01-01T00:00:00.000Z' });
    const completion = await completePendingMergeRecords(testContext);
    expect(completion.irreversible).toBeGreaterThanOrEqual(1);
    const completed = await storeLoadById(testContext, ADMIN_USER, recordId, ENTITY_TYPE_MERGE_RECORD) as unknown as Record<string, string>;
    expect(completed.merge_status).toBe('irreversible');
    expect(completed.irreversible_reason).toBe('merge_interrupted');
  });

  it('should keep a relationship between two merged entities through a partial unmerge, then point it back', async () => {
    const target = await createIntrusionSet(`${PREFIX} Pair Target`);
    const first = await createIntrusionSet(`${PREFIX} Pair First`);
    const second = await createIntrusionSet(`${PREFIX} Pair Second`);
    const targetToSecond = await createRelation(testContext, ADMIN_USER, { fromId: target.id, toId: second.id, relationship_type: RELATION_RELATED_TO });
    // The target already relates to the second entity: the merge moves this relationship on its second side only, so it
    // is deleted with the first entity and listed by both entities as to be recreated.
    const between = await createRelation(testContext, ADMIN_USER, { fromId: first.id, toId: second.id, relationship_type: RELATION_RELATED_TO });
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target), subjectOf(first), subjectOf(second)],
      target_id: target.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { target_id: target.id } } });
    const recordId = (await queryAsAdminWithSuccess({ query: gql`query CurationActionsPairRecordOf($id: ID!) { curationProposal(id: $id) { merge_record_id } }`, variables: { id } }))
      .data?.curationProposal.merge_record_id as string;
    expect(await storeLoadById(testContext, ADMIN_USER, between.id, RELATION_RELATED_TO)).toBeUndefined();
    const listed = await queryAsAdminWithSuccess({ query: MERGE_RECORDS_QUERY, variables: { search: `${PREFIX} Pair` } });
    const listedRecord = listed.data?.mergeRecords.edges.map((edge: { node: Record<string, any> }) => edge.node).find((node: { id: string }) => node.id === recordId);
    expect(listedRecord.relationships_recreatable_count).toBe(1);

    // Restored right after the merge, the first entity relates to the target, which the second one is still part of.
    const partial = await queryAsAdminWithSuccess({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId, sourceIds: [first.id] } });
    expect(partial.data?.unmergeEntity.merge_status).toBe('partially_reverted');
    const joined = await storeLoadById(testContext, ADMIN_USER, between.id, RELATION_RELATED_TO) as unknown as { fromId: string; toId: string };
    expect(joined.fromId).toBe(first.id);
    expect(joined.toId).toBe(target.id);

    // Restoring the second entity points the relationship back to it.
    const full = await queryAsAdminWithSuccess({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId, sourceIds: [second.id] } });
    expect(full.data?.unmergeEntity.merge_status).toBe('reverted');
    const restored = await storeLoadById(testContext, ADMIN_USER, between.id, RELATION_RELATED_TO) as unknown as { fromId: string; toId: string };
    expect(restored.fromId).toBe(first.id);
    expect(restored.toId).toBe(second.id);
    const targetRelation = await storeLoadById(testContext, ADMIN_USER, targetToSecond.id, RELATION_RELATED_TO) as unknown as { fromId: string; toId: string };
    expect(targetRelation.toId).toBe(second.id);
  });

  it('should record on retry the change of an apply whose decision could not be written, without applying it twice', async () => {
    const target = await createIntrusionSet(`${PREFIX} Unrecorded Target`);
    const aliasName = `${PREFIX} Unrecorded Taxonomy Name`;
    const id = await createProposal({
      kind: PROPOSAL_KIND_ALIAS,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target)],
      target_id: target.id,
      recommended_action: ACTION_ADD_ALIASES,
      action_payload: { aliases: [aliasName] },
      evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
      confidence: 0.95,
    });
    // The decision write fails every time: the aliases are added, the proposal stays open and marked as being applied.
    const originalPatch = middleware.patchAttribute;
    const failing = vi.spyOn(middleware, 'patchAttribute').mockImplementation(async (...args: Parameters<typeof originalPatch>) => {
      const [, , elementId, , patch] = args;
      if (elementId === id && (patch as Record<string, unknown>).proposal_status) throw new Error('Decision write failed');
      return originalPatch(...args);
    });
    try {
      const failed = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
      expect(failed.errors?.[0]?.message).toContain('The change was applied but the proposal could not be updated');
    } finally {
      failing.mockRestore();
    }
    expect((await loadIntrusionSet(target.id)).aliases).toEqual([aliasName]);
    const pending = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as BasicStoreEntityCurationProposal;
    expect(pending.proposal_status).toBe('open');
    expect(pending.application_started_at).toBeTruthy();

    // The retry records the change that was made, with its applied patch, so that it can still be reverted.
    const recorded = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id } });
    expect(recorded.data?.curationProposalAccept.proposal_status).toBe('accepted');
    expect(recorded.data?.curationProposalAccept.applied_patch).toContain(aliasName);
    await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    expect((await loadIntrusionSet(target.id)).aliases ?? []).toEqual([]);
  });

  it('should record and revert on retry a change kept before it reached the graph, when the attempt stopped before recording it', async () => {
    const stale = await createIntrusionSet(`${PREFIX} Stopped Revoke`);
    await ageIntrusionSet(stale.id);
    const id = await createProposal({
      kind: PROPOSAL_KIND_STALE,
      detector: DETECTOR_STALENESS,
      subjects: [subjectOf(stale)],
      target_id: stale.id,
      recommended_action: ACTION_REVOKE,
      action_payload: { element_id: stale.id },
      evidence: stalenessEvidence,
      confidence: 0.8,
    });
    // The attempt stops after the graph change: the decision is not written and nothing but the planned change is kept.
    const originalPatch = middleware.patchAttribute;
    const originalKeep = redis.redisCurationSetApplicationResult;
    const failing = vi.spyOn(middleware, 'patchAttribute').mockImplementation(async (...args: Parameters<typeof originalPatch>) => {
      const [, , elementId, , patch] = args;
      if (elementId === id && (patch as Record<string, unknown>).proposal_status) throw new Error('Decision write failed');
      return originalPatch(...args);
    });
    const keeping = vi.spyOn(redis, 'redisCurationSetApplicationResult').mockImplementation(async (proposalId, result) => {
      if ((result as { planned?: boolean }).planned) await originalKeep(proposalId, result);
    });
    try {
      const failed = await queryAsAdmin({ query: ACCEPT_MUTATION, variables: { id } });
      expect(failed.errors?.[0]?.message).toContain('The change was applied but the proposal could not be updated');
    } finally {
      failing.mockRestore();
      keeping.mockRestore();
    }
    expect((await loadIntrusionSet(stale.id)).revoked).toBe(true);
    expect((await loadProposal(id)).proposal_status).toBe('open');

    // The retry reads the change back from the graph: recorded once, with what it replaced, so it can be reverted.
    const recorded = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id } });
    expect(recorded.data?.curationProposalAccept.proposal_status).toBe('accepted');
    const appliedPatch = JSON.parse(recorded.data?.curationProposalAccept.applied_patch);
    expect(appliedPatch.operations).toEqual([expect.objectContaining({ key: 'revoked', previous: false, value: true })]);
    await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id } });
    expect((await loadIntrusionSet(stale.id)).revoked).toBe(false);
  });

  it('should resume from the merge record an unmerge whose proposal could not be closed, and close both', async () => {
    const target = await createIntrusionSet(`${PREFIX} Unclosed Target`);
    const source = await createIntrusionSet(`${PREFIX} Unclosed Source`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target), subjectOf(source)],
      target_id: target.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { target_id: target.id } } });
    const recordId = (await queryAsAdminWithSuccess({ query: gql`query CurationActionsUnclosedRecordOf($id: ID!) { curationProposal(id: $id) { merge_record_id } }`, variables: { id } }))
      .data?.curationProposal.merge_record_id as string;
    // The platform refuses to re-create an element during the 5 seconds that follow its deletion.
    await wait(5010);
    // The proposal cannot be closed: the graph is restored, and the record keeps its recovery marker.
    const originalPatch = middleware.patchAttribute;
    const failing = vi.spyOn(middleware, 'patchAttribute').mockImplementation(async (...args: Parameters<typeof originalPatch>) => {
      const [, , elementId, , patch] = args;
      if (elementId === id && (patch as Record<string, unknown>).proposal_status) throw new Error('Proposal write failed');
      return originalPatch(...args);
    });
    try {
      const failed = await queryAsAdmin({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId } });
      expect(failed.errors?.[0]?.message).toBeDefined();
    } finally {
      failing.mockRestore();
    }
    expect(await loadIntrusionSet(source.id)).toBeDefined();
    const interrupted = await storeLoadById(testContext, ADMIN_USER, recordId, ENTITY_TYPE_MERGE_RECORD) as unknown as Record<string, any>;
    expect(interrupted.merge_status).toBe('active');
    expect(interrupted.unmerge_pending_source_ids).toEqual([source.id]);
    expect((await loadProposal(id)).proposal_status).toBe('accepted');

    // Resumed from the record: nothing is restored twice, the record and the proposal are closed.
    const resumed = await queryAsAdminWithSuccess({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId } });
    expect(resumed.data?.unmergeEntity.merge_status).toBe('reverted');
    expect(await loadIntrusionSet(source.id)).toBeDefined();
    expect((await loadProposal(id)).proposal_status).toBe('reverted');
    const closed = await storeLoadById(testContext, ADMIN_USER, recordId, ENTITY_TYPE_MERGE_RECORD) as unknown as Record<string, any>;
    expect(closed.unmerge_pending_source_ids ?? []).toEqual([]);
  });

  it('should record a merge run again after an interrupted one as not reversible', async () => {
    const target = await createIntrusionSet(`${PREFIX} Rerun Target`);
    const source = await createIntrusionSet(`${PREFIX} Rerun Source`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target), subjectOf(source)],
      target_id: target.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    const first = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { target_id: target.id } } });
    const firstRecordId = first.data?.curationProposalAccept.merge_record_id as string;
    expect(first.data?.curationProposalAccept.can_revert).toBe(true);
    // Undo it so that both entities exist again, then leave things as an attempt interrupted halfway would.
    await wait(5010);
    await queryAsAdminWithSuccess({ query: UNMERGE_MUTATION, variables: { mergeRecordId: firstRecordId } });
    const setFields = async (element: BasicStoreEntity, fields: Record<string, string | null>) => elUpdate(testContext, element._index, element.internal_id, {
      script: { source: 'for (def entry : params.fields.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }', lang: 'painless', params: { fields } },
    });
    const firstRecord = await storeLoadById(testContext, ADMIN_USER, firstRecordId, ENTITY_TYPE_MERGE_RECORD) as unknown as BasicStoreEntity;
    await setFields(firstRecord, { merge_status: 'irreversible', irreversible_reason: 'merge_interrupted' });
    const proposal = await storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as BasicStoreEntity;
    await setFields(proposal, { proposal_status: 'open', application_started_at: new Date().toISOString(), merge_record_id: null, decided_at: null });

    const retried = await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { target_id: target.id } } });
    const retriedRecordId = retried.data?.curationProposalAccept.merge_record_id as string;
    expect(retried.data?.curationProposalAccept.proposal_status).toBe('accepted');
    expect(retriedRecordId).not.toBe(firstRecordId);
    const retriedRecord = await storeLoadById(testContext, ADMIN_USER, retriedRecordId, ENTITY_TYPE_MERGE_RECORD) as unknown as Record<string, string>;
    expect(retriedRecord.merge_status).toBe('irreversible');
    expect(retriedRecord.irreversible_reason).toBe('merge_rerun_after_interruption');
    expect(retried.data?.curationProposalAccept.can_revert).toBe(false);
  });

  it('should only discard a pending merge record whose merge never started writing', async () => {
    const target = await createIntrusionSet(`${PREFIX} Pending Target`);
    const source = await createIntrusionSet(`${PREFIX} Pending Source`);
    const id = await createProposal({
      kind: PROPOSAL_KIND_MERGE,
      detector: DETECTOR_NORMALIZATION,
      subjects: [subjectOf(target), subjectOf(source)],
      target_id: target.id,
      recommended_action: ACTION_MERGE,
      evidence: evidenceFor('canonical_collision', 'Same canonical name'),
      confidence: 0.9,
    });
    await queryAsAdminWithSuccess({ query: ACCEPT_MUTATION, variables: { id, input: { target_id: target.id } } });
    const recordId = (await queryAsAdminWithSuccess({ query: gql`query CurationActionsPendingRecordOf($id: ID!) { curationProposal(id: $id) { merge_record_id } }`, variables: { id } }))
      .data?.curationProposal.merge_record_id as string;
    const merged = await storeLoadById(testContext, ADMIN_USER, recordId, ENTITY_TYPE_MERGE_RECORD) as unknown as BasicStoreEntity & { merge_started_at?: string };
    // The merge marked its record before its first write.
    expect(merged.merge_started_at).toBeTruthy();
    // Undo it, so that both entities exist again, then leave the record pending, as a stopped merge would.
    await wait(5010);
    await queryAsAdminWithSuccess({ query: UNMERGE_MUTATION, variables: { mergeRecordId: recordId } });
    expect(await loadIntrusionSet(source.id)).toBeDefined();
    const setFields = (fields: Record<string, string | null>) => elUpdate(testContext, merged._index, merged.internal_id, {
      script: { source: 'for (def entry : params.fields.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }', lang: 'painless', params: { fields } },
    });

    // Every source is still there, but the merge had started writing: the record is kept, as not reversible.
    await setFields({ merge_status: 'pending', created_at: '2020-01-01T00:00:00.000Z' });
    expect((await completePendingMergeRecords(testContext)).irreversible).toBeGreaterThanOrEqual(1);
    const interrupted = await storeLoadById(testContext, ADMIN_USER, recordId, ENTITY_TYPE_MERGE_RECORD) as unknown as Record<string, string>;
    expect(interrupted.merge_status).toBe('irreversible');
    expect(interrupted.irreversible_reason).toBe('merge_interrupted');

    // A merge stopped before its first write left nothing to undo: its record is discarded.
    await setFields({ merge_status: 'pending', irreversible_reason: null, merge_started_at: null });
    expect((await completePendingMergeRecords(testContext)).discarded).toBeGreaterThanOrEqual(1);
    expect(await storeLoadById(testContext, ADMIN_USER, recordId, ENTITY_TYPE_MERGE_RECORD)).toBeUndefined();
  });

  describe('curation policies (Enterprise Edition)', () => {
    let policyId: string;

    beforeAll(async () => {
      vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
      vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
      const created = await queryAsAdminWithSuccess({
        query: POLICY_ADD_MUTATION,
        variables: {
          input: {
            name: `${PREFIX} alias policy`,
            policy_enabled: true,
            policy_entity_types: [ENTITY_TYPE_INTRUSION_SET],
            policy_kinds: [PROPOSAL_KIND_ALIAS],
            auto_apply_threshold: 0.9,
            max_applies_per_run: 5,
          },
        },
      });
      policyId = created.data?.curationPolicyAdd.id;
    });

    afterAll(async () => {
      const policies = await fullEntitiesList(testContext, ADMIN_USER, [ENTITY_TYPE_CURATION_POLICY]);
      for (let index = 0; index < policies.length; index += 1) {
        if ((policies[index] as unknown as { name: string }).name.startsWith(PREFIX)) {
          await deleteElementById(testContext, ADMIN_USER, policies[index].internal_id, ENTITY_TYPE_CURATION_POLICY);
        }
      }
      vi.restoreAllMocks();
    });

    it('should validate the policy edits', async () => {
      const invalidKey = await queryAsAdmin({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'applied_count', value: ['10'] }] } });
      expect(invalidKey.errors?.[0]?.message).toContain('Invalid or forbidden key');
      const invalidKinds = await queryAsAdmin({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'policy_kinds', value: ['split'] }] } });
      expect(invalidKinds.errors?.[0]?.message).toContain('auto-applicable proposal kind');
      const invalidTypes = await queryAsAdmin({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'policy_entity_types', value: ['Report'] }] } });
      expect(invalidTypes.errors?.[0]?.message).toContain('Policies only apply to knowledge entity types');
      const invalidMax = await queryAsAdmin({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'max_applies_per_run', value: [5000] }] } });
      expect(invalidMax.errors?.[0]?.message).toContain('between 1 and 1000');
      // The policy an edit produces is validated: removing its only kind, or a required value, is refused.
      const noKind = await queryAsAdmin({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'policy_kinds', value: [PROPOSAL_KIND_ALIAS], operation: 'remove' }] } });
      expect(noKind.errors?.[0]?.message).toContain('auto-applicable proposal kind');
      const noThreshold = await queryAsAdmin({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'auto_apply_threshold', value: [], operation: 'remove' }] } });
      expect(noThreshold.errors?.[0]?.message).toContain('cannot be emptied');
      // A renamed policy follows the name rule of a created one.
      const invalidNames = ['   ', 'x'];
      for (let index = 0; index < invalidNames.length; index += 1) {
        const invalidName = await queryAsAdmin({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'name', value: [invalidNames[index]] }] } });
        expect(invalidName.errors?.[0]?.message).toContain('at least 2 characters');
      }
      const edited = await queryAsAdminWithSuccess({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'auto_apply_threshold', value: [0.85] }] } });
      expect(edited.data?.curationPolicyFieldPatch.auto_apply_threshold).toBe(0.85);
      const listed = await queryAsAdminWithSuccess({ query: POLICIES_QUERY, variables: { search: PREFIX } });
      expect(listed.data?.curationPolicies.edges.map((edge: { node: { id: string } }) => edge.node.id)).toContain(policyId);
    });

    it('should count the proposals a dry run excludes for their confidence or their kind', async () => {
      const target = await createIntrusionSet(`${PREFIX} Dry Run Target`);
      await createProposal({
        kind: PROPOSAL_KIND_ALIAS,
        detector: DETECTOR_NORMALIZATION,
        subjects: [subjectOf(target)],
        target_id: target.id,
        recommended_action: ACTION_ADD_ALIASES,
        action_payload: { aliases: [`${PREFIX} Dry Run Name`] },
        evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
        confidence: 0.55,
      });
      await createProposal({
        kind: PROPOSAL_KIND_STALE,
        detector: DETECTOR_STALENESS,
        subjects: [subjectOf(target)],
        target_id: target.id,
        recommended_action: ACTION_REVOKE,
        evidence: evidenceFor('staleness', 'No activity for a year'),
        confidence: 0.7,
      });
      const dryRun = await queryAsAdminWithSuccess({
        query: gql`query CurationActionsPolicyDryRun($id: ID!) { curationPolicyDryRun(id: $id) { excluded_count exclusions { key count } } }`,
        variables: { id: policyId },
      });
      const result = dryRun.data?.curationPolicyDryRun;
      const excluded = Object.fromEntries(result.exclusions.map((entry: { key: string; count: number }) => [entry.key, entry.count]));
      // Below the threshold or of a kind the policy does not cover: both are counted, not left out of the dry run.
      expect(excluded.below_threshold).toBeGreaterThanOrEqual(1);
      expect(excluded.kind_not_covered).toBeGreaterThanOrEqual(1);
      expect(result.excluded_count).toBe(Object.values(excluded).reduce((sum: number, count) => sum + (count as number), 0));
    });

    it('should apply an eligible proposal in the name of the policy, for policy managers only', async () => {
      const target = await createIntrusionSet(`${PREFIX} Policy Target`);
      const aliasName = `${PREFIX} Policy Taxonomy Name`;
      const id = await createProposal({
        kind: PROPOSAL_KIND_ALIAS,
        detector: DETECTOR_NORMALIZATION,
        subjects: [subjectOf(target)],
        target_id: target.id,
        recommended_action: ACTION_ADD_ALIASES,
        action_payload: { aliases: [aliasName] },
        evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
        confidence: 0.95,
      });
      const started = await queryAsAdminWithSuccess({ query: POLICY_APPLY_MUTATION, variables: { id: policyId } });
      expect(started.data?.curationPolicyApply).toBeTruthy();
      // A second run while the first task holds the proposal (or after it applied it) never queues it again.
      const again = await queryAsAdminWithSuccess({ query: POLICY_APPLY_MUTATION, variables: { id: policyId } });
      const againTaskId = again.data?.curationPolicyApply as string | null;
      const queuedAgain = againTaskId
        ? ((await storeLoadById(testContext, ADMIN_USER, againTaskId, ENTITY_TYPE_BACKGROUND_TASK)) as unknown as { task_ids: string[] }).task_ids
        : [];
      expect(queuedAgain).not.toContain(id);
      // The editor may accept proposals, but not apply them in the name of a policy.
      await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: APPLY_MUTATION, variables: { id, policyId } });
      const applied = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id, policyId } });
      expect(applied.data?.curationProposalApply.proposal_status).toBe('auto_applied');
      expect(applied.data?.curationProposalApply.policy_id).toBe(policyId);
      expect((await loadIntrusionSet(target.id)).aliases).toEqual([aliasName]);
      const policy = await queryAsAdminWithSuccess({ query: POLICY_QUERY, variables: { id: policyId } });
      expect(policy.data?.curationPolicy.applied_count).toBe(1);
    });

    it('should skip a proposal that is not eligible anymore, or whose policy is disabled', async () => {
      const target = await createIntrusionSet(`${PREFIX} Skipped Target`);
      const lowId = await createProposal({
        kind: PROPOSAL_KIND_ALIAS,
        detector: DETECTOR_NORMALIZATION,
        subjects: [subjectOf(target)],
        target_id: target.id,
        recommended_action: ACTION_ADD_ALIASES,
        action_payload: { aliases: [`${PREFIX} Skipped Taxonomy Name`] },
        evidence: evidenceFor('taxonomy', 'The vendor taxonomy lists a name the entity does not carry'),
        confidence: 0.6,
      });
      const belowThreshold = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: lowId, policyId } });
      expect(belowThreshold.data?.curationProposalApply.proposal_status).toBe('open');
      await queryAsAdminWithSuccess({ query: POLICY_PATCH_MUTATION, variables: { id: policyId, input: [{ key: 'policy_enabled', value: [false] }] } });
      const policy = await queryAsAdminWithSuccess({ query: POLICY_QUERY, variables: { id: policyId } });
      expect(policy.data?.curationPolicy.policy_enabled).toBe(false);
      const refusedRun = await queryAsAdmin({ query: POLICY_APPLY_MUTATION, variables: { id: policyId } });
      expect(refusedRun.errors?.[0]?.message).toContain('Enable the curation policy to apply it now');
      const disabled = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: lowId, policyId } });
      expect(disabled.data?.curationProposalApply.proposal_status).toBe('open');
      expect((await loadIntrusionSet(target.id)).aliases ?? []).toEqual([]);
    });

    it('should only merge a pair the detectors still find duplicates at the policy threshold', async () => {
      const created = await queryAsAdminWithSuccess({
        query: POLICY_ADD_MUTATION,
        variables: {
          input: {
            name: `${PREFIX} merge policy`,
            policy_enabled: true,
            policy_entity_types: [ENTITY_TYPE_INTRUSION_SET],
            policy_kinds: [PROPOSAL_KIND_MERGE],
            auto_apply_threshold: 0.9,
            max_applies_per_run: 5,
          },
        },
      });
      const mergePolicyId = created.data?.curationPolicyAdd.id;
      const mergeDraft = (left: BasicStoreEntity, right: BasicStoreEntity): ProposalDraft => ({
        kind: PROPOSAL_KIND_MERGE,
        detector: DETECTOR_NORMALIZATION,
        subjects: [subjectOf(left), subjectOf(right)],
        target_id: left.id,
        recommended_action: ACTION_MERGE,
        evidence: evidenceFor('canonical_collision', 'Same name once normalized'),
        confidence: 0.95,
      });
      // Raised on names the entities no longer carry: nothing makes them duplicates now.
      const lone = await createIntrusionSet(`${PREFIX} Lone Wolf`);
      const owl = await createIntrusionSet(`${PREFIX} Night Owl`);
      const outdatedId = await createProposal(mergeDraft(lone, owl));
      const skipped = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: outdatedId, policyId: mergePolicyId } });
      expect(skipped.data?.curationProposalApply.proposal_status).toBe('open');
      expect(await loadIntrusionSet(owl.id)).toBeDefined();

      // Still the same name once normalized: the policy merges them.
      const spider = await createIntrusionSet(`${PREFIX} Twin Spider`);
      const hyphenated = await createIntrusionSet(`${PREFIX} Twin-Spider`);
      const currentId = await createProposal(mergeDraft(spider, hyphenated));
      const applied = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: currentId, policyId: mergePolicyId } });
      expect(applied.data?.curationProposalApply.proposal_status).toBe('auto_applied');
      expect(await loadIntrusionSet(hyphenated.id)).toBeUndefined();
    });
  });
});
