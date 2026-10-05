import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../../utils/testQuery';
import { awaitUntilCondition, queryAsAdmin, queryAsAdminWithSuccess, queryAsUser } from '../../../utils/testQueryHelper';
import { fetchElementChangeFieldHistoryEvents, fetchElementHistoryEvents, fetchRelationshipsHistoryEvents } from '../../../../src/modules/timeMachine/timeMachine-history';
import { extractAttributeValues, rewindAccessReferences } from '../../../../src/modules/timeMachine/timeMachine-replay';
import { buildCompactDocuments, type ChangedElementsCursor, findChangedElementIds } from '../../../../src/manager/snapshotManager';
import { indexSnapshots, findSnapshotAtOrAfter, loadUserVisits } from '../../../../src/modules/timeMachine/timeMachine-store';
import { buildChangeDigestData } from '../../../../src/modules/timeMachine/timeMachine-changeDigest';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { MARKING_TLP_AMBER } from '../../../../src/schema/identifier';
import { STATIC_NOTIFIER_UI } from '../../../../src/modules/notifier/notifier-statics';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { finalizeStaleLandscapeState, findLandscapeDiff, userAccessFingerprint, writeActiveLandscapeState } from '../../../../src/modules/timeMachine/landscapeDiff-domain';
import type { LandscapeDiffState } from '../../../../src/modules/timeMachine/timeMachine-types';

const HISTORY_BUDGET_MS = 60000;

const CREATE_INTRUSION_SET = gql`
  mutation TimeMachineIntrusionSetAdd($input: IntrusionSetAddInput!) {
    intrusionSetAdd(input: $input) { id standard_id name }
  }
`;
const CREATE_MALWARE = gql`
  mutation TimeMachineMalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) { id standard_id name }
  }
`;
const UPDATE_INTRUSION_SET = gql`
  mutation TimeMachineIntrusionSetEdit($id: ID!, $input: [EditInput]!) {
    intrusionSetEdit(id: $id) { fieldPatch(input: $input) { id description confidence } }
  }
`;
const ADD_RELATION = gql`
  mutation TimeMachineRelationAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { id }
  }
`;
const DELETE_RELATION = gql`
  mutation TimeMachineRelationDelete($id: ID!) {
    stixCoreRelationshipEdit(id: $id) { delete }
  }
`;
const ADD_RELATION_REF = gql`
  mutation TimeMachineRelationRefAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
    stixCoreRelationshipEdit(id: $id) { relationAdd(input: $input) { id } }
  }
`;
const ADD_INTRUSION_SET_REF = gql`
  mutation TimeMachineIntrusionSetRefAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
    intrusionSetEdit(id: $id) { relationAdd(input: $input) { id } }
  }
`;
const DELETE_INTRUSION_SET = gql`
  mutation TimeMachineIntrusionSetDelete($id: ID!) {
    intrusionSetEdit(id: $id) { delete }
  }
`;
const DELETE_MALWARE = gql`
  mutation TimeMachineMalwareDelete($id: ID!) {
    malwareEdit(id: $id) { delete }
  }
`;
const AS_OF = gql`
  query TimeMachineAsOf($id: String!, $date: DateTime!) {
    entityAsOf(id: $id, date: $date) {
      entity_id
      exists
      deleted
      restricted
      complete
      anchor
      representative
      replayed_events
      attributes { key label values { raw display restricted deleted } }
      relationships { relationship_type count }
      relationships_total
    }
  }
`;
const DIFF = gql`
  query TimeMachineDiff($id: String!, $from: DateTime!, $to: DateTime!) {
    entityDiff(id: $id, from: $from, to: $to) {
      entity_id
      restricted
      existed_at_from
      exists_at_to
      summary { attributes_changed relationships_added relationships_removed confidence_before confidence_after relationships_added_by_type { relationship_type count } }
      attributes { key before { display } after { display } changed_by changes_count }
      relationships { relationship_type action target_name target_type is_source }
    }
  }
`;
const TIMELINE = gql`
  query TimeMachineTimeline($id: String!) {
    entityTimeMachineTimeline(id: $id) { entity_id created_at history_start events { date event_scope } events_truncated snapshots max_replay_days }
  }
`;
const CREATE_REPORT = gql`
  mutation TimeMachineReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) { id }
  }
`;
const DELETE_REPORT = gql`
  mutation TimeMachineReportDelete($id: ID!) {
    reportEdit(id: $id) { delete }
  }
`;
const AS_OF_CONTAINER = gql`
  query TimeMachineAsOfContainer($id: String!, $date: DateTime!) {
    entityAsOf(id: $id, date: $date) { entity_id exists anchor container_objects_count }
  }
`;
const SAVED_FILTER_ADD = gql`
  mutation TimeMachineSavedFilterAdd($input: SavedFilterAddInput!) {
    savedFilterAdd(input: $input) { id }
  }
`;
const SAVED_FILTER_DELETE = gql`
  mutation TimeMachineSavedFilterDelete($id: ID!) { savedFilterDelete(id: $id) }
`;
const VISIT = gql`
  mutation TimeMachineVisit($id: String!) {
    entityVisitRecord(id: $id) { entity_id first_visit reference_date last_seen_at new_relationships updates }
  }
`;
const SINCE_LAST_VISIT = gql`
  query TimeMachineSinceLastVisit($ids: [String!]!) {
    entitiesSinceLastVisit(ids: $ids) { entity_id first_visit last_seen_at new_relationships updates }
  }
`;
const PURGE_VISITS = gql`
  mutation TimeMachinePurgeVisits { userVisitsPurge }
`;
const LANDSCAPE_SUMMARY = gql`
  query TimeMachineLandscapeSummary($input: LandscapeDiffInput!) {
    landscapeDiffSummary(input: $input) {
      scope_entity_types
      aggregates { entities_in_scope entities_changed new_relationships new_malware { name standard_id x_mitre_id count } new_relationships_by_type { key count } groups { key count } }
      entities { entity_id standard_id name relationships_added attributes_changed change_score }
    }
  }
`;
const LANDSCAPE_RUN = gql`
  mutation TimeMachineLandscapeRun($input: LandscapeDiffInput!) {
    landscapeDiffRun(input: $input) { id status }
  }
`;
const LANDSCAPE_GET = gql`
  query TimeMachineLandscapeGet($id: ID!) {
    landscapeDiff(id: $id) { id status progress total error aggregates { entities_in_scope new_relationships } entities { entity_id } }
  }
`;
const CHANGE_DIGEST_ADD = gql`
  mutation TimeMachineChangeDigestAdd($input: TriggerChangeDigestAddInput!) {
    triggerKnowledgeChangeDigestAdd(input: $input) { id trigger_type period trigger_time filters scope_entity_types }
  }
`;
const TRIGGER_DELETE = gql`
  mutation TimeMachineTriggerDelete($id: ID!) { triggerKnowledgeDelete(id: $id) }
`;

const waitForHistory = async (elementId: string, scope: string, minCount = 1) => {
  await awaitUntilCondition(async () => {
    const events = await fetchElementHistoryEvents(testContext, SYSTEM_USER, elementId, { scopes: [scope], max: 100 });
    return events.length >= minCount;
  }, HISTORY_BUDGET_MS, { message: `history ${scope} event for ${elementId}` });
  const events = await fetchElementHistoryEvents(testContext, SYSTEM_USER, elementId, { scopes: [scope], max: 100 });
  return events.map((event) => event.timestamp).sort();
};

const middle = (a: string, b: string) => new Date((new Date(a).getTime() + new Date(b).getTime()) / 2).toISOString();
const attributeValues = (asOf: any, key: string) => (asOf.attributes.find((a: any) => a.key === key)?.values ?? []).map((v: any) => v.display);

describe('Knowledge time machine', () => {
  const testName = `Time machine intrusion set ${Date.now()}`;
  let intrusionSetId: string;
  let malwareId: string;
  let intrusionSetStandardId: string;
  let malwareStandardId: string;
  let createdAt: string;
  let updatedAt: string;
  let relationAddedAt: string;
  let relationId: string;

  beforeAll(async () => {
    const intrusionSet = await queryAsAdminWithSuccess({
      query: CREATE_INTRUSION_SET,
      variables: { input: { name: testName, description: 'first description', confidence: 50 } },
    });
    intrusionSetId = intrusionSet.data.intrusionSetAdd.id;
    intrusionSetStandardId = intrusionSet.data.intrusionSetAdd.standard_id;
    const malware = await queryAsAdminWithSuccess({
      query: CREATE_MALWARE,
      variables: { input: { name: `${testName} malware`, description: 'malware for the time machine', is_family: true } },
    });
    malwareId = malware.data.malwareAdd.id;
    malwareStandardId = malware.data.malwareAdd.standard_id;
    [createdAt] = await waitForHistory(intrusionSetId, 'create');
    await queryAsAdminWithSuccess({
      query: UPDATE_INTRUSION_SET,
      variables: { id: intrusionSetId, input: [{ key: 'description', value: ['second description'] }, { key: 'confidence', value: ['80'] }] },
    });
    const updates = await waitForHistory(intrusionSetId, 'update');
    updatedAt = updates[updates.length - 1];
    const relation = await queryAsAdminWithSuccess({
      query: ADD_RELATION,
      variables: { input: { fromId: intrusionSetId, toId: malwareId, relationship_type: 'uses' } },
    });
    relationId = relation.data.stixCoreRelationshipAdd.id;
    await awaitUntilCondition(async () => {
      const events = await fetchElementHistoryEvents(testContext, SYSTEM_USER, malwareId, { max: 10 });
      return events.length > 0;
    }, HISTORY_BUDGET_MS);
    relationAddedAt = new Date().toISOString();
  }, 4 * HISTORY_BUDGET_MS);

  afterAll(async () => {
    await queryAsAdminWithSuccess({ query: PURGE_VISITS });
    if (intrusionSetId) await queryAsAdminWithSuccess({ query: DELETE_INTRUSION_SET, variables: { id: intrusionSetId } });
    if (malwareId) await queryAsAdminWithSuccess({ query: DELETE_MALWARE, variables: { id: malwareId } });
  });

  it('should rebuild the entity as it was between its creation and its update', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: AS_OF, variables: { id: intrusionSetId, date: middle(createdAt, updatedAt) } });
    const asOf = data.entityAsOf;
    expect(asOf.exists).toBe(true);
    expect(asOf.restricted).toBe(false);
    expect(asOf.complete).toBe(true);
    expect(asOf.anchor).toEqual('current');
    expect(asOf.representative).toEqual(testName);
    expect(attributeValues(asOf, 'description')).toEqual(['first description']);
    expect(attributeValues(asOf, 'confidence')).toEqual(['50']);
    expect(asOf.replayed_events).toBeGreaterThanOrEqual(1);
  });

  it('should rebuild the current state and report non existence before creation', async () => {
    const now = await queryAsAdminWithSuccess({ query: AS_OF, variables: { id: intrusionSetId, date: new Date().toISOString() } });
    expect(attributeValues(now.data.entityAsOf, 'description')).toEqual(['second description']);
    expect(attributeValues(now.data.entityAsOf, 'confidence')).toEqual(['80']);
    expect(now.data.entityAsOf.relationships.find((r: any) => r.relationship_type === 'uses')?.count).toEqual(1);
    const before = await queryAsAdminWithSuccess({ query: AS_OF, variables: { id: intrusionSetId, date: new Date(new Date(createdAt).getTime() - 60000).toISOString() } });
    expect(before.data.entityAsOf.exists).toBe(false);
    expect(before.data.entityAsOf.attributes).toEqual([]);
  });

  it('should diff the entity attributes and relationships between two dates', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: DIFF, variables: { id: intrusionSetId, from: middle(createdAt, updatedAt), to: new Date().toISOString() } });
    const diff = data.entityDiff;
    expect(diff.restricted).toBe(false);
    expect(diff.existed_at_from).toBe(true);
    expect(diff.exists_at_to).toBe(true);
    const description = diff.attributes.find((a: any) => a.key === 'description');
    expect(description.before.map((v: any) => v.display)).toEqual(['first description']);
    expect(description.after.map((v: any) => v.display)).toEqual(['second description']);
    expect(description.changes_count).toBeGreaterThanOrEqual(1);
    expect(diff.summary.confidence_before).toEqual(50);
    expect(diff.summary.confidence_after).toEqual(80);
    expect(diff.summary.relationships_added).toEqual(1);
    const added = diff.relationships.find((r: any) => r.action === 'added');
    expect(added.relationship_type).toEqual('uses');
    expect(added.target_name).toEqual(`${testName} malware`);
    expect(added.is_source).toBe(true);
  });

  it('should report no change over a period ending before the creation of the entity', async () => {
    const createdTime = new Date(createdAt).getTime();
    const variables = { id: intrusionSetId, from: new Date(createdTime - 120000).toISOString(), to: new Date(createdTime - 60000).toISOString() };
    const { data } = await queryAsAdminWithSuccess({ query: DIFF, variables });
    expect(data.entityDiff.existed_at_from).toEqual(false);
    expect(data.entityDiff.exists_at_to).toEqual(false);
    expect(data.entityDiff.restricted).toEqual(false);
    expect(data.entityDiff.summary.attributes_changed).toEqual(0);
    expect(data.entityDiff.attributes).toEqual([]);
    expect(data.entityDiff.relationships).toEqual([]);
  });

  it('should reject invalid diff periods', async () => {
    const result = await queryAsUser(USER_PARTICIPATE, { query: DIFF, variables: { id: intrusionSetId, from: new Date().toISOString(), to: createdAt } });
    expect(result.errors).toBeDefined();
  });

  it('should expose the timeline of the entity for the time slider', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: TIMELINE, variables: { id: intrusionSetId } });
    const timeline = data.entityTimeMachineTimeline;
    expect(timeline.entity_id).toEqual(intrusionSetId);
    expect(timeline.history_start).toBeDefined();
    expect(timeline.events.length).toBeGreaterThanOrEqual(2);
    expect(timeline.events_truncated).toBe(false);
    expect(timeline.max_replay_days).toBeGreaterThan(0);
  });

  it('should count the objects of a container at a past date with the rights of the user', async () => {
    const restricted = await queryAsAdminWithSuccess({
      query: CREATE_INTRUSION_SET,
      variables: { input: { name: `${testName} contained amber`, objectMarking: [MARKING_TLP_AMBER] } },
    });
    const restrictedId = restricted.data.intrusionSetAdd.id;
    const report = await queryAsAdminWithSuccess({
      query: CREATE_REPORT,
      variables: { input: { name: `${testName} report`, published: new Date().toISOString(), objects: [intrusionSetId, malwareId, restrictedId] } },
    });
    const reportId = report.data.reportAdd.id;
    const [reportCreatedAt] = await waitForHistory(reportId, 'create');
    const entity = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, reportId, { type: 'Report' });
    const snapshotDate = new Date().toISOString();
    const documents = await buildCompactDocuments(testContext, [entity], snapshotDate);
    await indexSnapshots([{ entityId: reportId, entityType: 'Report', snapshotDate, historyCursor: snapshotDate, document: documents.get(reportId)! }]);
    const variables = { id: reportId, date: middle(reportCreatedAt, snapshotDate) };
    // Rebuilt from the snapshot, the as-of view counts the objects of the report from its current objects
    const { data } = await queryAsAdminWithSuccess({ query: AS_OF_CONTAINER, variables });
    expect(data.entityAsOf.exists).toBe(true);
    expect(data.entityAsOf.anchor).toEqual('snapshot');
    expect(data.entityAsOf.container_objects_count).toEqual(3);
    // A contained object the user cannot access is not counted
    const participate = await queryAsUser(USER_PARTICIPATE, { query: AS_OF_CONTAINER, variables });
    expect(participate.errors).toBeUndefined();
    expect(participate.data?.entityAsOf.container_objects_count).toEqual(2);
    await queryAsAdminWithSuccess({ query: DELETE_REPORT, variables: { id: reportId } });
    await queryAsAdminWithSuccess({ query: DELETE_INTRUSION_SET, variables: { id: restrictedId } });
  });

  it('should rebuild from a knowledge snapshot when one is available', async () => {
    const entity = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, intrusionSetId, { type: 'Intrusion-Set' });
    const snapshotDate = new Date().toISOString();
    const documents = await buildCompactDocuments(testContext, [entity], snapshotDate);
    expect(documents.get(intrusionSetId)?.relationships_count.uses).toEqual(1);
    expect(documents.get(intrusionSetId)?.attributes.description).toEqual(['second description']);
    // A snapshot dated before the update is rewound: it never embeds a later value
    const earlierDocuments = await buildCompactDocuments(testContext, [entity], middle(createdAt, updatedAt));
    expect(earlierDocuments.get(intrusionSetId)?.attributes.description).toEqual(['first description']);
    expect(earlierDocuments.get(intrusionSetId)?.attributes.confidence).toEqual(['50']);
    await indexSnapshots([{ entityId: intrusionSetId, entityType: 'Intrusion-Set', snapshotDate, historyCursor: snapshotDate, document: documents.get(intrusionSetId)! }]);
    const snapshot = await findSnapshotAtOrAfter(testContext, intrusionSetId, middle(createdAt, updatedAt));
    expect(snapshot?.entity_id).toEqual(intrusionSetId);
    const { data } = await queryAsAdminWithSuccess({ query: AS_OF, variables: { id: intrusionSetId, date: middle(createdAt, updatedAt) } });
    expect(data.entityAsOf.anchor).toEqual('snapshot');
    expect(attributeValues(data.entityAsOf, 'description')).toEqual(['first description']);
    // Relationships are rebuilt from the relationship set of the snapshot with the events between the two dates only
    expect(data.entityAsOf.relationships).toEqual([]);
    const atRelation = await queryAsAdminWithSuccess({ query: AS_OF, variables: { id: intrusionSetId, date: relationAddedAt } });
    expect(atRelation.data.entityAsOf.anchor).toEqual('snapshot');
    expect(atRelation.data.entityAsOf.relationships).toEqual([{ relationship_type: 'uses', count: 1 }]);
  });

  it('should never return an as-of view of a marking the user cannot access', async () => {
    const markedName = `${testName} amber`;
    const marked = await queryAsAdminWithSuccess({
      query: CREATE_INTRUSION_SET,
      variables: { input: { name: markedName } },
    });
    const markedId = marked.data.intrusionSetAdd.id;
    const [markedCreatedAt] = await waitForHistory(markedId, 'create');
    await queryAsAdminWithSuccess({
      query: ADD_INTRUSION_SET_REF,
      variables: { id: markedId, input: { toId: MARKING_TLP_AMBER, relationship_type: 'object-marking' } },
    });
    await waitForHistory(markedId, 'update');
    const result = await queryAsUser(USER_PARTICIPATE, { query: AS_OF, variables: { id: markedId, date: new Date().toISOString() } });
    expect(result.errors).toBeDefined();
    // The access references are rewound with their own changes only, independently of the attribute replay
    const accessEvents = await fetchElementChangeFieldHistoryEvents(testContext, SYSTEM_USER, markedId, ['Intrusion-Set--objectMarking'], { max: 10 });
    expect(accessEvents.length).toEqual(1);
    const element = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, markedId);
    const current = extractAttributeValues(element as any);
    expect(current.objectMarking?.length).toEqual(1);
    const keys = { marking: 'objectMarking', granted: 'objectOrganization' };
    expect(rewindAccessReferences(current, 'Intrusion-Set', accessEvents, markedCreatedAt, keys).objectMarking).toBeUndefined();
    expect(rewindAccessReferences(current, 'Intrusion-Set', accessEvents, new Date().toISOString(), keys).objectMarking).toEqual(current.objectMarking);
    await queryAsAdminWithSuccess({ query: DELETE_INTRUSION_SET, variables: { id: markedId } });
  }, 2 * HISTORY_BUDGET_MS);

  it('should record visits and count what is new since the last visit', async () => {
    const first = await queryAsAdminWithSuccess({ query: VISIT, variables: { id: intrusionSetId } });
    expect(first.data.entityVisitRecord.entity_id).toEqual(intrusionSetId);
    expect(first.data.entityVisitRecord.first_visit).toBe(true);
    const visits = await loadUserVisits(testContext, ADMIN_USER.id, [intrusionSetId]);
    expect(visits.get(intrusionSetId)?.last_seen_at).toBeDefined();
    const since = await queryAsAdminWithSuccess({ query: SINCE_LAST_VISIT, variables: { ids: [intrusionSetId, malwareId] } });
    const intrusionSetSince = since.data.entitiesSinceLastVisit.find((s: any) => s.entity_id === intrusionSetId);
    expect(intrusionSetSince.first_visit).toBe(false);
    expect(intrusionSetSince.new_relationships).toEqual(0);
    const malwareSince = since.data.entitiesSinceLastVisit.find((s: any) => s.entity_id === malwareId);
    expect(malwareSince.first_visit).toBe(true);
  });

  it('should compute the landscape diff summary of a filter set', async () => {
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: ['name'], values: [testName], operator: 'eq', mode: 'or' }], filterGroups: [] });
    const { data } = await queryAsAdminWithSuccess({
      query: LANDSCAPE_SUMMARY,
      variables: { input: { filters, entity_types: ['Intrusion-Set'], from: new Date(new Date(createdAt).getTime() - 60000).toISOString(), to: relationAddedAt } },
    });
    const summary = data.landscapeDiffSummary;
    expect(summary.scope_entity_types).toEqual(['Intrusion-Set']);
    expect(summary.aggregates.entities_in_scope).toEqual(1);
    expect(summary.aggregates.entities_changed).toEqual(1);
    expect(summary.aggregates.new_relationships).toEqual(1);
    expect(summary.aggregates.new_malware.map((m: any) => m.name)).toEqual([`${testName} malware`]);
    expect(summary.entities[0].entity_id).toEqual(intrusionSetId);
    expect(summary.entities[0].relationships_added).toEqual(1);
    // STIX ids let external consumers link the changes to their own copy of the knowledge
    expect(summary.entities[0].standard_id).toEqual(intrusionSetStandardId);
    expect(summary.aggregates.new_malware[0].standard_id).toEqual(malwareStandardId);
    expect(summary.aggregates.new_malware[0].x_mitre_id).toBeNull();
  });

  it('should run a landscape diff in the background and report its progress', async () => {
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: ['name'], values: [testName], operator: 'eq', mode: 'or' }], filterGroups: [] });
    const input = { filters, entity_types: ['Intrusion-Set'], from: new Date(new Date(createdAt).getTime() - 60000).toISOString(), to: relationAddedAt, group_by: 'relationship_type' };
    const run = await queryAsAdminWithSuccess({ query: LANDSCAPE_RUN, variables: { input } });
    const { id } = run.data.landscapeDiffRun;
    let status = run.data.landscapeDiffRun.status;
    await awaitUntilCondition(async () => {
      const current = await queryAsAdminWithSuccess({ query: LANDSCAPE_GET, variables: { id } });
      status = current.data.landscapeDiff.status;
      return status === 'complete' || status === 'failed';
    }, HISTORY_BUDGET_MS);
    expect(status).toEqual('complete');
    const result = await queryAsAdminWithSuccess({ query: LANDSCAPE_GET, variables: { id } });
    expect(result.data.landscapeDiff.total).toEqual(1);
    expect(result.data.landscapeDiff.aggregates.new_relationships).toEqual(1);
    // A landscape diff is private to its requester
    const other = await queryAsUser(USER_PARTICIPATE, { query: LANDSCAPE_GET, variables: { id } });
    expect(other.data?.landscapeDiff ?? null).toBeNull();
    // The same request returns the cached result
    const cached = await queryAsAdminWithSuccess({ query: LANDSCAPE_RUN, variables: { input } });
    expect(cached.data.landscapeDiffRun.id).toEqual(id);
  }, 2 * HISTORY_BUDGET_MS);

  it('should finalize a stale landscape run once and never let its execution revive it', async () => {
    const staleAt = new Date(Date.now() - 10 * 60000).toISOString();
    const stale: LandscapeDiffState = {
      id: `landscape-stale-${Date.now()}`,
      user_id: SYSTEM_USER.id,
      access_fingerprint: userAccessFingerprint(testContext, SYSTEM_USER),
      status: 'running',
      progress: 1,
      total: 10,
      input: { from: createdAt, to: relationAddedAt, group_by: 'entity_type' },
      scope_entity_types: ['Intrusion-Set'],
      created_at: staleAt,
      updated_at: staleAt,
      expires_at: new Date(Date.now() + 60000).toISOString(),
      error: null,
      truncated: false,
      aggregates: null,
      entities: [],
    };
    expect(await writeActiveLandscapeState(stale)).toBe(true);
    // A run that progressed since it was read is not finalized
    expect(await finalizeStaleLandscapeState({ ...stale, updated_at: new Date(Date.now() - 20 * 60000).toISOString() }, { ...stale, status: 'failed' })).toBe(false);
    // A poll, from any node, finalizes the stale run
    const found = await findLandscapeDiff(testContext, SYSTEM_USER, stale.id);
    expect(found?.status).toEqual('failed');
    // Its execution, wherever it runs, can no longer overwrite the terminal state
    expect(await writeActiveLandscapeState({ ...stale, status: 'complete', updated_at: new Date().toISOString() })).toBe(false);
    expect((await findLandscapeDiff(testContext, SYSTEM_USER, stale.id))?.status).toEqual('failed');
  });

  it('should never serve a cached landscape result after one of its counted relationships is reclassified', async () => {
    const name = `${testName} reclassified`;
    const from = new Date(Date.now() - 60000).toISOString();
    const scoped = await queryAsAdminWithSuccess({ query: CREATE_INTRUSION_SET, variables: { input: { name } } });
    const scopedId = scoped.data.intrusionSetAdd.id;
    const relation = await queryAsAdminWithSuccess({
      query: ADD_RELATION,
      variables: { input: { fromId: scopedId, toId: malwareId, relationship_type: 'uses' } },
    });
    const scopedRelationId = relation.data.stixCoreRelationshipAdd.id;
    // An end date in the past keeps one cache key for every request of the test
    const to = new Date().toISOString();
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: ['name'], values: [name], operator: 'eq', mode: 'or' }], filterGroups: [] });
    const input = { filters, entity_types: ['Intrusion-Set'], from, to };
    const summaryAsUser = async () => {
      const result = await queryAsUser(USER_PARTICIPATE, { query: LANDSCAPE_SUMMARY, variables: { input } });
      expect(result.errors).toBeUndefined();
      return result.data?.landscapeDiffSummary as any;
    };
    const landscapeAsUser = async (id: string) => {
      const result = await queryAsUser(USER_PARTICIPATE, { query: LANDSCAPE_GET, variables: { id } });
      return result.data?.landscapeDiff as any;
    };
    const before = await summaryAsUser();
    expect(before.aggregates.new_relationships).toEqual(1);
    const run = await queryAsUser(USER_PARTICIPATE, { query: LANDSCAPE_RUN, variables: { input } });
    const runId = (run.data?.landscapeDiffRun as any).id;
    await awaitUntilCondition(async () => (await landscapeAsUser(runId))?.status === 'complete', HISTORY_BUDGET_MS);
    expect((await landscapeAsUser(runId)).aggregates.new_relationships).toEqual(1);
    // The relationship is counted by both results but named in neither
    await queryAsAdminWithSuccess({
      query: ADD_RELATION_REF,
      variables: { id: scopedRelationId, input: { toId: MARKING_TLP_AMBER, relationship_type: 'object-marking' } },
    });
    const after = await summaryAsUser();
    expect(after.aggregates.new_relationships).toEqual(0);
    expect(after.aggregates.new_malware).toEqual([]);
    const outdated = await landscapeAsUser(runId);
    expect(outdated.status).toEqual('failed');
    expect(outdated.aggregates).toBeNull();
    await queryAsAdminWithSuccess({ query: DELETE_INTRUSION_SET, variables: { id: scopedId } });
  }, 2 * HISTORY_BUDGET_MS);

  it('should create change digests and build their content', async () => {
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: ['name'], values: [testName], operator: 'eq', mode: 'or' }], filterGroups: [] });
    const { data } = await queryAsAdminWithSuccess({
      query: CHANGE_DIGEST_ADD,
      variables: { input: { name: 'Time machine change digest', filters, scope_entity_types: ['Intrusion-Set'], period: 'week', trigger_time: '1-09:00:00.000Z', notifiers: [STATIC_NOTIFIER_UI] } },
    });
    const trigger = data.triggerKnowledgeChangeDigestAdd;
    expect(trigger.trigger_type).toEqual('change_digest');
    expect(trigger.period).toEqual('week');
    expect(trigger.scope_entity_types).toEqual(['Intrusion-Set']);
    const content = await buildChangeDigestData(testContext, ADMIN_USER, { internal_id: trigger.id, name: 'digest', filters, scope_entity_types: ['Intrusion-Set'] }, new Date(new Date(createdAt).getTime() - 60000).toISOString(), new Date().toISOString());
    expect(content.length).toEqual(1);
    expect(content[0].notification_id).toEqual(trigger.id);
    expect(content[0].message).toContain('new relationship');
    await queryAsAdminWithSuccess({ query: TRIGGER_DELETE, variables: { id: trigger.id } });
  });

  it('should copy the filters and the entity types of a saved filter in a change digest', async () => {
    const savedFilterFilters = { mode: 'and', filters: [{ key: ['name'], values: [`${testName} malware`], operator: 'eq', mode: 'or' }], filterGroups: [] };
    const savedFilter = await queryAsAdminWithSuccess({
      query: SAVED_FILTER_ADD,
      variables: { input: { name: `${testName} saved filter`, filters: JSON.stringify(savedFilterFilters), scope: 'malwares' } },
    });
    const savedFilterId = savedFilter.data.savedFilterAdd.id;
    const { data } = await queryAsAdminWithSuccess({
      query: CHANGE_DIGEST_ADD,
      variables: { input: { name: 'Time machine saved filter digest', saved_filter_id: savedFilterId, period: 'day', trigger_time: '09:00:00.000Z', notifiers: [STATIC_NOTIFIER_UI] } },
    });
    const trigger = data.triggerKnowledgeChangeDigestAdd;
    expect(trigger.scope_entity_types).toEqual(['Malware']);
    expect(JSON.parse(trigger.filters)).toEqual(savedFilterFilters);
    await queryAsAdminWithSuccess({ query: TRIGGER_DELETE, variables: { id: trigger.id } });
    await queryAsAdminWithSuccess({ query: SAVED_FILTER_DELETE, variables: { id: savedFilterId } });
  });

  it('should require explicit entity types for a saved filter of a list without entity type', async () => {
    const savedFilter = await queryAsAdminWithSuccess({
      query: SAVED_FILTER_ADD,
      variables: { input: { name: `${testName} relationships filter`, filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }), scope: 'relationships' } },
    });
    const savedFilterId = savedFilter.data.savedFilterAdd.id;
    const input = { name: 'Time machine unmapped saved filter digest', saved_filter_id: savedFilterId, period: 'day', trigger_time: '09:00:00.000Z', notifiers: [STATIC_NOTIFIER_UI] };
    const rejected = await queryAsAdmin({ query: CHANGE_DIGEST_ADD, variables: { input } });
    expect(rejected.errors?.[0]?.message).toContain('choose the entity types');
    const { data } = await queryAsAdminWithSuccess({ query: CHANGE_DIGEST_ADD, variables: { input: { ...input, scope_entity_types: ['Intrusion-Set'] } } });
    expect(data.triggerKnowledgeChangeDigestAdd.scope_entity_types).toEqual(['Intrusion-Set']);
    await queryAsAdminWithSuccess({ query: TRIGGER_DELETE, variables: { id: data.triggerKnowledgeChangeDigestAdd.id } });
    await queryAsAdminWithSuccess({ query: SAVED_FILTER_DELETE, variables: { id: savedFilterId } });
  });

  it('should reject ambiguous scopes and change digests for several recipients', async () => {
    const now = new Date().toISOString();
    const ambiguous = await queryAsUser(USER_PARTICIPATE, {
      query: LANDSCAPE_SUMMARY,
      variables: { input: { saved_filter_id: 'saved-filter', custom_view_id: 'custom-view', from: createdAt, to: now } },
    });
    expect(ambiguous.errors?.[0]?.message).toContain('either a saved filter or a custom view');
    // The filters of a saved filter or a custom view are read from it, never combined with ad-hoc filters
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: ['name'], values: ['APT-TEST'], operator: 'eq', mode: 'or' }], filterGroups: [] });
    const mixedSavedFilter = await queryAsUser(USER_PARTICIPATE, {
      query: LANDSCAPE_SUMMARY,
      variables: { input: { saved_filter_id: 'saved-filter', filters, from: createdAt, to: now } },
    });
    expect(mixedSavedFilter.errors?.[0]?.message).toContain('either filters, a saved filter or a custom view');
    const mixedCustomView = await queryAsUser(USER_PARTICIPATE, {
      query: LANDSCAPE_RUN,
      variables: { input: { custom_view_id: 'custom-view', filters, from: createdAt, to: now } },
    });
    expect(mixedCustomView.errors?.[0]?.message).toContain('either filters, a saved filter or a custom view');
    const severalRecipients = await queryAsAdmin({
      query: CHANGE_DIGEST_ADD,
      variables: { input: { name: 'Several recipients', period: 'day', trigger_time: '09:00:00.000Z', notifiers: [STATIC_NOTIFIER_UI], recipients: [ADMIN_USER.id, USER_PARTICIPATE.id] } },
    });
    expect(severalRecipients.errors?.[0]?.message).toContain('single recipient');
  });

  it('should select both sides of the relationships changed in a snapshot window', async () => {
    await awaitUntilCondition(async () => {
      const events = await fetchRelationshipsHistoryEvents(testContext, SYSTEM_USER, [intrusionSetId], { scopes: ['create'], max: 10 });
      return events.length > 0;
    }, HISTORY_BUDGET_MS, { message: 'history create event of the relationship' });
    const windowEnd = new Date().toISOString();
    // The relationship created after the last update of the intrusion set selects both of its sides
    const { ids, cursor } = await findChangedElementIds(testContext, updatedAt, windowEnd, null, 10000);
    expect(cursor).toBeNull();
    expect(ids).toEqual(expect.arrayContaining([intrusionSetId, malwareId]));
    // Read the smallest budget at a time (the two sides of one relationship), a run resumes the element events then
    // the relationship events of the window and never returns more ids than its budget
    const paged = new Set<string>();
    let pageCursor: ChangedElementsCursor | null = null;
    let pages = 0;
    do {
      const page = await findChangedElementIds(testContext, updatedAt, windowEnd, pageCursor, 2);
      expect(page.ids.length).toBeLessThanOrEqual(2);
      page.ids.forEach((id) => paged.add(id));
      pageCursor = page.cursor;
      pages += 1;
    } while (pageCursor && pages < 1000);
    expect(pageCursor).toBeNull();
    expect([...paged]).toEqual(expect.arrayContaining([intrusionSetId, malwareId]));
  });

  it('should keep in a snapshot the relationships deleted after its date', async () => {
    const snapshotDate = new Date().toISOString();
    await queryAsAdminWithSuccess({ query: DELETE_RELATION, variables: { id: relationId } });
    await awaitUntilCondition(async () => {
      const events = await fetchRelationshipsHistoryEvents(testContext, SYSTEM_USER, [intrusionSetId], { scopes: ['delete'], max: 10 });
      return events.length > 0;
    }, HISTORY_BUDGET_MS, { message: 'history delete event of the relationship' });
    const entity = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, intrusionSetId, { type: 'Intrusion-Set' });
    const atSnapshotDate = await buildCompactDocuments(testContext, [entity], snapshotDate);
    expect(atSnapshotDate.get(intrusionSetId)?.relationships_count.uses).toEqual(1);
    expect(atSnapshotDate.get(intrusionSetId)?.relationships.uses).toEqual([relationId]);
    const afterDeletion = await buildCompactDocuments(testContext, [entity], new Date().toISOString());
    expect(afterDeletion.get(intrusionSetId)?.relationships_count.uses).toBeUndefined();
  }, 2 * HISTORY_BUDGET_MS);
});
