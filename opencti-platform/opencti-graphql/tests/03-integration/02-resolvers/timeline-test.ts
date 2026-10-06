import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import {
  awaitUntilCondition,
  queryAsAdmin,
  queryAsAdminWithError,
  queryAsAdminWithSuccess,
  queryAsAuthUser,
  queryAsUserIsExpectedForbidden,
  queryAsUserWithSuccess,
} from '../../utils/testQueryHelper';
import { redisGetTelemetry } from '../../../src/database/redis';
import * as redis from '../../../src/database/redis';
import { BUS_TOPICS } from '../../../src/config/conf';
import { TELEMETRY_GAUGE_TIMELINE_MANUAL_EVENT } from '../../../src/manager/telemetryManager';
import * as timelineNotification from '../../../src/modules/timeline/timeline-notification';
import { ENTITY_TYPE_TIMELINE_EVENT, TIMELINE_KINDS } from '../../../src/modules/timeline/timeline-types';
import { RULE_INVESTIGATION_RUN } from '../../../src/modules/timeline/timeline-rules';
import { ADMIN_USER, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext, USER_EDITOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { timelineUpdateForUser } from '../../../src/modules/timeline/timeline-domain';
import { acknowledgeTimelineRegeneration, claimDueTimelineRegenerations, enqueueTimelineRegeneration } from '../../../src/modules/timeline/timeline-queue';
import { resolveUserById } from '../../../src/modules/user/user-domain';
import type { AuthUser } from '../../../src/types/user';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_TIMELINE } from '../../../src/types/stix-2-1-extensions';
import {
  buildTimelineEventDoc,
  computeDerivedEventId,
  deleteContainerTimeline,
  loadStoredTimelineEvents,
  type StoredTimelineEvent,
  timelineEventSignature,
  timelineEventSourceIds,
} from '../../../src/modules/timeline/timeline-engine';
import * as timelineEngine from '../../../src/modules/timeline/timeline-engine';
import { elIndexElements, elUpdate } from '../../../src/database/engine';
import { processDueTimelineRegenerations, timelineStreamEventsHandler } from '../../../src/manager/timelineManager';
import type { DataEvent, SseEvent } from '../../../src/types/event';
import { createEntity, createRelation, deleteElementById } from '../../../src/database/middleware';
import { RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';
import { MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../../../src/utils/access';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';

const KILL_CHAIN_PHASE_ADD = gql`
  mutation TimelineKillChainPhaseAdd($input: KillChainPhaseAddInput!) {
    killChainPhaseAdd(input: $input) { id }
  }
`;
const ATTACK_PATTERN_ADD = gql`
  mutation TimelineAttackPatternAdd($input: AttackPatternAddInput!) {
    attackPatternAdd(input: $input) { id standard_id }
  }
`;
const MALWARE_ADD = gql`
  mutation TimelineMalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) { id standard_id }
  }
`;
const INDICATOR_ADD = gql`
  mutation TimelineIndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) { id standard_id }
  }
`;
const RELATIONSHIP_ADD = gql`
  mutation TimelineRelationshipAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { id standard_id }
  }
`;
const CASE_INCIDENT_ADD = gql`
  mutation TimelineCaseIncidentAdd($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input) { id standard_id }
  }
`;
const SIGHTING_ADD = gql`
  mutation TimelineSightingAdd($input: StixSightingRelationshipAddInput!) {
    stixSightingRelationshipAdd(input: $input) { id standard_id }
  }
`;
const EXTERNAL_REFERENCE_ADD = gql`
  mutation TimelineExternalReferenceAdd($input: ExternalReferenceAddInput!) {
    externalReferenceAdd(input: $input) { id standard_id }
  }
`;
const EXTERNAL_REFERENCE_DELETE = gql`
  mutation TimelineExternalReferenceDelete($id: ID!) {
    externalReferenceEdit(id: $id) { delete }
  }
`;
const LABEL_ADD = gql`
  mutation TimelineLabelAdd($input: LabelAddInput!) {
    labelAdd(input: $input) { id standard_id }
  }
`;
const LABEL_DELETE = gql`
  mutation TimelineLabelDelete($id: ID!) {
    labelEdit(id: $id) { delete }
  }
`;
const TASK_ADD = gql`
  mutation TimelineTaskAdd($input: TaskAddInput!) {
    taskAdd(input: $input) { id standard_id }
  }
`;
const NOTE_ADD = gql`
  mutation TimelineNoteAdd($input: NoteAddInput!) {
    noteAdd(input: $input) { id standard_id }
  }
`;
const STIX_CORE_OBJECT_DELETE = gql`
  mutation TimelineStixCoreObjectDelete($id: ID!) {
    stixCoreObjectEdit(id: $id) { delete }
  }
`;
const STIX_CORE_RELATIONSHIP_DELETE = gql`
  mutation TimelineStixCoreRelationshipDelete($id: ID!) {
    stixCoreRelationshipEdit(id: $id) { delete }
  }
`;
const KILL_CHAIN_PHASE_DELETE = gql`
  mutation TimelineKillChainPhaseDelete($id: ID!) {
    killChainPhaseEdit(id: $id) { delete }
  }
`;
const CASE_INCIDENT_STIX = gql`
  query TimelineCaseIncidentStix($id: String!) {
    caseIncident(id: $id) {
      id
      toStix
      x_opencti_timeline_anchors { first_adversary_activity first_response containment computed_at }
    }
  }
`;

const TIMELINE_EVENT_FIELDS = `
  id
  standard_id
  entity_type
  container_id
  event_time
  event_end_time
  precision
  lane
  kind
  title
  description
  source
  rule_id
  element_id
  element_type
  pinned
  hidden
  annotation
  confidence
  ordering_hint
  external_id
  analyst_fields
  editable
  annotatable
  objectMarking { id standard_id }
  createdBy { id }
`;

const CONTAINER_TIMELINE = gql`
  query ContainerTimeline(
    $id: String!
    $from: DateTime
    $to: DateTime
    $lanes: [TimelineLane!]
    $kinds: [TimelineEventKind!]
    $sources: [TimelineEventSource!]
    $search: String
    $includeHidden: Boolean
    $pinnedOnly: Boolean
    $orderMode: OrderingMode
    $first: Int
  ) {
    containerTimeline(
      id: $id
      from: $from
      to: $to
      lanes: $lanes
      kinds: $kinds
      sources: $sources
      search: $search
      includeHidden: $includeHidden
      pinnedOnly: $pinnedOnly
      orderMode: $orderMode
      first: $first
    ) {
      pageInfo { globalCount }
      edges { node { ${TIMELINE_EVENT_FIELDS} } }
    }
  }
`;
const CONTAINER_TIMELINE_BOUNDS = gql`
  query ContainerTimelineBounds($id: String!, $sources: [TimelineEventSource!]) {
    containerTimelineBounds(id: $id, sources: $sources) {
      first_event_time
      last_event_time
    }
  }
`;
const CONTAINER_TIMELINE_SUMMARY_SCOPED = gql`
  query ContainerTimelineSummaryScoped($id: String!, $lanes: [TimelineLane!], $kinds: [TimelineEventKind!]) {
    containerTimelineSummary(id: $id, lanes: $lanes, kinds: $kinds) {
      total
      first_event_time
      last_event_time
      lanes { lane count }
    }
  }
`;

const CONTAINER_TIMELINE_SUMMARY = gql`
  query ContainerTimelineSummary($id: String!) {
    containerTimelineSummary(id: $id) {
      container_id
      total
      manual_count
      pinned_count
      hidden_count
      first_event_time
      last_event_time
      lanes { lane count }
      kinds { kind count }
      anchors { first_adversary_activity first_detection first_response containment closure computed_at }
      settings { enabled_lanes default_grouping default_zoom_window hidden_kinds }
      can_edit
      truncated
      generated_at
    }
  }
`;
const CONTAINER_TIMELINE_EXPORT = gql`
  query ContainerTimelineExport(
    $id: String!
    $format: TimelineExportFormat!
    $labels: [TimelineExportLabelInput!]
    $search: String
    $sources: [TimelineEventSource!]
    $kinds: [TimelineEventKind!]
    $pinnedOnly: Boolean
    $contentMaxMarkings: [String!]
  ) {
    containerTimelineExport(
      id: $id
      format: $format
      labels: $labels
      search: $search
      sources: $sources
      kinds: $kinds
      pinnedOnly: $pinnedOnly
      contentMaxMarkings: $contentMaxMarkings
    )
  }
`;
const CONTAINER_TIMELINE_EXPORT_FILE = gql`
  query ContainerTimelineExportFile($id: String!, $format: TimelineExportFormat!, $kinds: [TimelineEventKind!], $contentMaxMarkings: [String!], $fileMarkings: [String!]) {
    containerTimelineExportFile(id: $id, format: $format, kinds: $kinds, contentMaxMarkings: $contentMaxMarkings, fileMarkings: $fileMarkings) {
      content
      file_markings { id standard_id }
    }
  }
`;
const TIMELINE_VIEWED = gql`
  mutation TimelineViewed($containerId: ID!) {
    timelineViewed(containerId: $containerId)
  }
`;
const MARKING_DEFINITION = gql`
  query TimelineMarkingDefinition($id: String!) {
    markingDefinition(id: $id) { id }
  }
`;
const TIMELINE_EVENT = gql`
  query TimelineEvent($id: String!) {
    timelineEvent(id: $id) { ${TIMELINE_EVENT_FIELDS} }
  }
`;
const TIMELINE_ANCHORS = gql`
  query TimelineAnchors($containerId: String!) {
    timelineAnchors(containerId: $containerId) { first_adversary_activity first_detection first_response containment closure computed_at changed_at }
  }
`;
const TIMELINE_RULES = gql`
  query TimelineRules {
    timelineRules { id label kinds available }
  }
`;
const TIMELINE_REGENERATE = gql`
  mutation TimelineRegenerate($containerId: ID!) {
    timelineRegenerate(containerId: $containerId) {
      container_id derived_count manual_count created_count updated_count deleted_count truncated duration_ms
      anchors { first_adversary_activity first_response containment }
    }
  }
`;
const TIMELINE_EVENT_ADD = gql`
  mutation TimelineEventAdd($input: TimelineEventAddInput!) {
    timelineEventAdd(input: $input) { ${TIMELINE_EVENT_FIELDS} }
  }
`;
const TIMELINE_EVENT_EDIT = gql`
  mutation TimelineEventEdit($id: ID!, $input: TimelineEventEditInput!) {
    timelineEventEdit(id: $id, input: $input) { ${TIMELINE_EVENT_FIELDS} }
  }
`;
const TIMELINE_EVENT_DELETE = gql`
  mutation TimelineEventDelete($id: ID!) {
    timelineEventDelete(id: $id)
  }
`;
const TIMELINE_EVENT_PIN = gql`
  mutation TimelineEventPin($id: ID!, $pinned: Boolean!) {
    timelineEventPin(id: $id, pinned: $pinned) { id pinned analyst_fields }
  }
`;
const TIMELINE_EVENT_HIDE = gql`
  mutation TimelineEventHide($id: ID!, $hidden: Boolean!) {
    timelineEventHide(id: $id, hidden: $hidden) { id hidden analyst_fields }
  }
`;
const TIMELINE_SETTINGS_UPDATE = gql`
  mutation TimelineSettingsUpdate($containerId: ID!, $input: TimelineSettingsInput!) {
    timelineSettingsUpdate(containerId: $containerId, input: $input) { container_id enabled_lanes default_grouping default_zoom_window hidden_kinds }
  }
`;
const TIMELINE_IMPORT = gql`
  mutation TimelineImport($containerId: ID!, $extension: String!) {
    timelineImport(containerId: $containerId, extension: $extension) { container_id manual_count derived_count }
  }
`;
const CASE_INCIDENTS_BY_ANCHOR = gql`
  query TimelineCaseIncidentsByAnchor($filters: FilterGroup, $orderBy: CaseIncidentsOrdering, $orderMode: OrderingMode) {
    caseIncidents(first: 50, filters: $filters, orderBy: $orderBy, orderMode: $orderMode) {
      edges { node { id x_opencti_timeline_anchors { containment } } }
    }
  }
`;

interface TimelineEventNode {
  id: string;
  standard_id: string;
  kind: string;
  lane: string;
  title: string;
  source: string;
  rule_id: string | null;
  element_id: string | null;
  precision: string;
  pinned: boolean;
  hidden: boolean;
  annotation: string | null;
  event_time: string;
  event_end_time: string | null;
  external_id: string | null;
  analyst_fields: string[];
  editable: boolean;
  annotatable: boolean;
  objectMarking: { id: string; standard_id: string }[];
  createdBy: { id: string } | null;
}

const ADVERSARY_START = '2026-02-01T08:00:00.000Z';
const ADVERSARY_STOP = '2026-02-03T18:00:00.000Z';
const CONTAINMENT_TIME = '2026-02-05T10:30:00.000Z';

// DateTime values are returned as dates by the test client
const iso = (value: string | Date | null | undefined) => (value ? new Date(value).toISOString() : null);

const listTimeline = async (id: string, variables: Record<string, unknown> = {}): Promise<TimelineEventNode[]> => {
  const result = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE, variables: { id, first: 500, ...variables } });
  return result.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => ({
    ...edge.node,
    event_time: iso(edge.node.event_time) as string,
    event_end_time: iso(edge.node.event_end_time),
  }));
};

// The static test admin and the stored user carry no max shareable markings; the complete user, built like a session, has them all
const queryAsPlatformAdminWithSuccess = async (request: { query: unknown; variables: Record<string, unknown> }) => {
  const completeAdmin = await resolveUserById(testContext, ADMIN_USER.id);
  const admin = { ...completeAdmin, origin: { referer: 'test', user_id: completeAdmin?.internal_id } } as AuthUser;
  const result = await queryAsAuthUser(admin, request as Parameters<typeof queryAsAuthUser>[1]);
  expect(result.errors, `This errors should not be there: ${JSON.stringify(result.errors)}`).toBeUndefined();
  return { data: result.data as Record<string, any> };
};

const storedSignatures = async (containerId: string) => {
  const stored = await loadStoredTimelineEvents(testContext, containerId);
  return Object.fromEntries(stored.map((event) => [event.internal_id, JSON.parse(timelineEventSignature(event))]));
};

const streamEvent = (stix: Record<string, unknown>): SseEvent<DataEvent> => ({
  id: `${Date.now()}-0`,
  event: 'update',
  data: { data: stix } as unknown as DataEvent,
});

describe('Incident and case timeline', () => {
  let killChainPhaseId: string;
  let attackPatternId: string;
  let malware: { id: string; standard_id: string };
  let indicatorId: string;
  let usesRelationshipId: string;
  let caseIncident: { id: string; standard_id: string };
  let secondCase: { id: string; standard_id: string };
  let taskId: string;
  let noteId: string;
  let manualEventId: string;
  let derivedMalwareEventId: string;

  beforeAll(async () => {
    const phase = await queryAsAdminWithSuccess({
      query: KILL_CHAIN_PHASE_ADD,
      variables: { input: { kill_chain_name: 'timeline-kill-chain', phase_name: 'timeline-initial-access', x_opencti_order: 3 } },
    });
    killChainPhaseId = phase.data.killChainPhaseAdd.id;
    const attackPattern = await queryAsAdminWithSuccess({
      query: ATTACK_PATTERN_ADD,
      variables: { input: { name: 'Timeline spearphishing', x_mitre_id: 'T9991', killChainPhases: [killChainPhaseId] } },
    });
    attackPatternId = attackPattern.data.attackPatternAdd.id;
    const malwareResult = await queryAsAdminWithSuccess({
      query: MALWARE_ADD,
      variables: { input: { name: 'Timeline malware', first_seen: '2026-02-01T09:00:00.000Z', last_seen: '2026-02-04T09:00:00.000Z' } },
    });
    malware = malwareResult.data.malwareAdd;
    const indicator = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: {
        input: {
          name: 'Timeline amber indicator',
          pattern: '[domain-name:value = \'timeline-amber.example\']',
          pattern_type: 'stix',
          x_opencti_main_observable_type: 'Domain-Name',
          valid_from: '2026-02-02T00:00:00.000Z',
          valid_until: '2026-08-02T00:00:00.000Z',
          objectMarking: [MARKING_TLP_AMBER],
        },
      },
    });
    indicatorId = indicator.data.indicatorAdd.id;
    const uses = await queryAsAdminWithSuccess({
      query: RELATIONSHIP_ADD,
      variables: { input: { fromId: malware.id, toId: attackPatternId, relationship_type: 'uses', start_time: ADVERSARY_START, stop_time: ADVERSARY_STOP } },
    });
    usesRelationshipId = uses.data.stixCoreRelationshipAdd.id;
    const objects = [attackPatternId, malware.id, indicatorId, usesRelationshipId];
    const caseResult = await queryAsAdminWithSuccess({
      query: CASE_INCIDENT_ADD,
      variables: { input: { name: 'Timeline ransomware case', created: '2026-02-04T12:00:00.000Z', objects } },
    });
    caseIncident = caseResult.data.caseIncidentAdd;
    const secondCaseResult = await queryAsAdminWithSuccess({
      query: CASE_INCIDENT_ADD,
      variables: { input: { name: 'Timeline imported case', created: '2026-02-04T12:00:00.000Z', objects } },
    });
    secondCase = secondCaseResult.data.caseIncidentAdd;
    const task = await queryAsAdminWithSuccess({
      query: TASK_ADD,
      variables: { input: { name: 'Isolate the infected hosts', created: '2026-02-04T13:00:00.000Z', due_date: '2026-02-06T13:00:00.000Z', objects: [caseIncident.id] } },
    });
    taskId = task.data.taskAdd.id;
  });

  afterAll(async () => {
    const deletions: Array<[typeof STIX_CORE_OBJECT_DELETE, string | undefined]> = [
      [STIX_CORE_OBJECT_DELETE, noteId],
      [STIX_CORE_OBJECT_DELETE, taskId],
      [STIX_CORE_OBJECT_DELETE, caseIncident?.id],
      [STIX_CORE_OBJECT_DELETE, secondCase?.id],
      [STIX_CORE_RELATIONSHIP_DELETE, usesRelationshipId],
      [STIX_CORE_OBJECT_DELETE, indicatorId],
      [STIX_CORE_OBJECT_DELETE, malware?.id],
      [STIX_CORE_OBJECT_DELETE, attackPatternId],
      [KILL_CHAIN_PHASE_DELETE, killChainPhaseId],
    ];
    for (let index = 0; index < deletions.length; index += 1) {
      const [query, id] = deletions[index];
      if (id) await queryAsAdmin({ query, variables: { id } });
    }
    // The timeline manager is disabled in tests: remove what the deletions would have cleaned
    if (caseIncident) await deleteContainerTimeline(caseIncident.id);
    if (secondCase) await deleteContainerTimeline(secondCase.id);
  });

  describe('derivation', () => {
    it('should derive the case timeline from its knowledge on regeneration', async () => {
      const result = await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      const regeneration = result.data.timelineRegenerate;
      expect(regeneration.container_id).toEqual(caseIncident.id);
      expect(regeneration.derived_count).toBeGreaterThan(0);
      expect(regeneration.created_count).toEqual(regeneration.derived_count);
      expect(regeneration.truncated).toBe(false);
      const events = await listTimeline(caseIncident.id);
      const kinds = events.map((e) => e.kind);
      expect(kinds).toEqual(expect.arrayContaining(['technique_used', 'malware_seen', 'indicator_valid', 'case_opened', 'task_created', 'task_due', 'relation_created']));
      expect(events.every((e) => e.source === 'derived' && e.editable === false)).toBe(true);
      // Ordered by time
      const times = events.map((e) => new Date(e.event_time).getTime());
      expect([...times].sort((a, b) => a - b)).toEqual(times);
    });

    it('should give techniques the exact window of their uses relationships', async () => {
      const events = await listTimeline(caseIncident.id, { kinds: ['technique_used'] });
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({ element_id: attackPatternId, precision: 'exact', event_time: ADVERSARY_START, event_end_time: ADVERSARY_STOP, lane: 'adversary' });
    });

    it('should place a sighting between elements of a case in the adversary lane and leave out their sightings elsewhere', async () => {
      const sightingCase = await queryAsAdminWithSuccess({
        query: CASE_INCIDENT_ADD,
        variables: { input: { name: 'Timeline sighting case', created: '2026-02-04T12:00:00.000Z', objects: [malware.id, TEST_ORGANIZATION.id] } },
      });
      const caseId = sightingCase.data.caseIncidentAdd.id;
      const sighting = (toId: string, firstSeen: string) => queryAsAdminWithSuccess({
        query: SIGHTING_ADD,
        variables: { input: { fromId: malware.id, toId, first_seen: firstSeen, last_seen: '2026-02-03T10:00:00.000Z', attribute_count: 2 } },
      });
      const inScope = (await sighting(TEST_ORGANIZATION.id, '2026-02-03T08:00:00.000Z')).data.stixSightingRelationshipAdd.id;
      const elsewhere = (await sighting(PLATFORM_ORGANIZATION.id, '2026-02-03T09:00:00.000Z')).data.stixSightingRelationshipAdd.id;
      try {
        await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseId } });
        const sightings = await listTimeline(caseId, { kinds: ['sighting'] });
        expect(sightings).toHaveLength(1);
        expect(sightings[0]).toMatchObject({ element_id: inScope, lane: 'adversary', event_time: '2026-02-03T08:00:00.000Z' });
      } finally {
        await deleteElementById(testContext, SYSTEM_USER, inScope, STIX_SIGHTING_RELATIONSHIP);
        await deleteElementById(testContext, SYSTEM_USER, elsewhere, STIX_SIGHTING_RELATIONSHIP);
        await queryAsAdmin({ query: STIX_CORE_OBJECT_DELETE, variables: { id: caseId } });
        await deleteContainerTimeline(caseId);
      }
    });

    it('should be idempotent: a second regeneration rewrites nothing and keeps the ids', async () => {
      const before = await storedSignatures(caseIncident.id);
      const anchorsBefore = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      const result = await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      expect(await storedSignatures(caseIncident.id)).toEqual(before);
      expect(result.data.timelineRegenerate).toMatchObject({ created_count: 0, updated_count: 0, deleted_count: 0 });
      const anchorsAfter = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      expect(anchorsAfter.data.timelineAnchors.changed_at).toBeDefined();
      expect(anchorsAfter.data.timelineAnchors.changed_at).toEqual(anchorsBefore.data.timelineAnchors.changed_at);
    });

    it('should compute the anchors and expose them on the container', async () => {
      const anchors = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      expect(iso(anchors.data.timelineAnchors.first_adversary_activity)).toEqual(ADVERSARY_START);
      expect(iso(anchors.data.timelineAnchors.first_response)).toEqual('2026-02-04T12:00:00.000Z');
      expect(anchors.data.timelineAnchors.containment).toBeNull();
      expect(anchors.data.timelineAnchors.computed_at).toBeDefined();
      const stix = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_STIX, variables: { id: caseIncident.id } });
      expect(iso(stix.data.caseIncident.x_opencti_timeline_anchors.first_adversary_activity)).toEqual(ADVERSARY_START);
    });

    it('should list the derivation rules with their availability', async () => {
      const result = await queryAsAdminWithSuccess({ query: TIMELINE_RULES, variables: {} });
      const rules = result.data.timelineRules as Array<{ id: string; available: boolean; kinds: string[] }>;
      expect(rules.find((r) => r.id === 'technique-kill-chain')).toMatchObject({ available: true, kinds: ['technique_used'] });
      expect(rules.find((r) => r.id === 'security-coverage-result')?.available).toBe(true);
      expect(rules.map((r) => r.id)).toEqual(expect.arrayContaining(['hunt-run', 'indicator-deployment', 'investigation-run']));
    });
  });

  describe('access', () => {
    it('should not return the events of elements the viewer cannot see', async () => {
      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500 } });
      const events = result.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node);
      expect(events.length).toBeGreaterThan(0);
      expect(events.find((e: TimelineEventNode) => e.element_id === indicatorId)).toBeUndefined();
      expect(events.find((e: TimelineEventNode) => e.kind === 'malware_seen')).toBeDefined();
      const editorResult = await queryAsUserWithSuccess(USER_EDITOR, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500 } });
      const editorEvents = editorResult.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node);
      expect(editorEvents.find((e: TimelineEventNode) => e.element_id === indicatorId)).toBeDefined();
    });

    it('should only name in a live update the events the subscriber can read', async () => {
      const participate = await resolveUserById(testContext, USER_PARTICIPATE.id) as AuthUser;
      const editor = await resolveUserById(testContext, USER_EDITOR.id) as AuthUser;
      const stored = await loadStoredTimelineEvents(testContext, caseIncident.id);
      const restrictedId = stored.find((event) => event.element_id === indicatorId)?.internal_id as string;
      const openId = stored.find((event) => event.kind === 'malware_seen')?.internal_id as string;
      expect(restrictedId && openId).toBeTruthy();
      const update = { id: caseIncident.id, container_id: caseIncident.id, update_type: 'derived' as const, changed_event_ids: [openId, restrictedId], updated_at: new Date().toISOString() };
      expect((await timelineUpdateForUser(testContext, participate, update))?.changed_event_ids).toEqual([openId]);
      expect((await timelineUpdateForUser(testContext, editor, update))?.changed_event_ids.sort()).toEqual([openId, restrictedId].sort());
      // An update about restricted events only, changed or removed, never reaches the subscriber
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [restrictedId] })).toBeNull();
      const openAccess = { restricted_members: [], granted: [] };
      const removedAboutIndicator = { id: 'removed-event', element_id: indicatorId, element_type: 'Indicator', marking_ids: [], element_access: openAccess };
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedAboutIndicator] })).toBeNull();
      const amber = await internalLoadById(testContext, SYSTEM_USER, MARKING_TLP_AMBER);
      const removedAmber = { id: 'removed-event', element_id: null, element_type: null, marking_ids: [amber.internal_id], element_access: null };
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedAmber] })).toBeNull();
      const removedOpen = { id: 'removed-event', element_id: null, element_type: null, marking_ids: [], element_access: null };
      const removedUpdate = await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedOpen] });
      expect(removedUpdate?.changed_event_ids).toEqual(['removed-event']);
      expect(removedUpdate).not.toHaveProperty('removed_events');
      // The element of a removed event may be deleted: it is read as it was, from the access recorded on the event
      const deletedElementId = '5a3c1e9e-1f4b-4b0e-8f1a-7d0c2b9e4a61';
      const removedAboutDeleted = { id: 'removed-event', element_id: deletedElementId, element_type: 'Malware', marking_ids: [], element_access: openAccess };
      const deletedUpdate = await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedAboutDeleted] });
      expect(deletedUpdate?.changed_event_ids).toEqual(['removed-event']);
      const removedAmberAboutDeleted = { ...removedAboutDeleted, marking_ids: [amber.internal_id] };
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedAmberAboutDeleted] })).toBeNull();
      const removedAboutRestrictedDeleted = {
        ...removedAboutDeleted,
        element_access: { restricted_members: [{ id: editor.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }], granted: [] },
      };
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedAboutRestrictedDeleted] })).toBeNull();
      expect((await timelineUpdateForUser(testContext, editor, { ...update, changed_event_ids: [], removed_events: [removedAboutRestrictedDeleted] }))?.changed_event_ids)
        .toEqual(['removed-event']);
      // Without a recorded access, nobody reads an event whose element was deleted
      const removedWithoutAccess = { ...removedAboutDeleted, element_access: null };
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedWithoutAccess] })).toBeNull();
      // A source of a removed event may be deleted while its element remains (a deleted uses relationship removes its
      // technique event): the source is read as it was, from the access recorded on the event, the element as it is now
      const openElementId = stored.find((event) => event.kind === 'malware_seen')?.element_id as string;
      const deletedSource = { id: '0c1f2e3d-4b5a-4c6d-8e7f-9a0b1c2d3e4f', entity_type: 'uses', restricted_members: [], granted: [] };
      const removedWithDeletedSource = {
        id: 'removed-event',
        element_id: openElementId,
        element_type: 'Malware',
        marking_ids: [],
        element_access: { ...openAccess, sources: [deletedSource] },
      };
      const sourceUpdate = await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedWithDeletedSource] });
      expect(sourceUpdate?.changed_event_ids).toEqual(['removed-event']);
      const removedWithDeletedRestrictedSource = {
        ...removedWithDeletedSource,
        element_access: { ...openAccess, sources: [{ ...deletedSource, restricted_members: [{ id: editor.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }] }] },
      };
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedWithDeletedRestrictedSource] })).toBeNull();
      expect((await timelineUpdateForUser(testContext, editor, { ...update, changed_event_ids: [], removed_events: [removedWithDeletedRestrictedSource] }))?.changed_event_ids)
        .toEqual(['removed-event']);
      // A deleted source recorded without its type is read by nobody, and a source that still exists is read as it is now
      const untypedSource = { id: deletedSource.id, restricted_members: [], granted: [] };
      const removedWithUntypedSource = { ...removedWithDeletedSource, element_access: { ...openAccess, sources: [untypedSource] } };
      expect(await timelineUpdateForUser(testContext, editor, { ...update, changed_event_ids: [], removed_events: [removedWithUntypedSource] })).toBeNull();
      const removedWithAmberSourceAndDeletedOne = {
        ...removedWithDeletedSource,
        element_access: { ...openAccess, sources: [deletedSource, { id: indicatorId, entity_type: 'Indicator', restricted_members: [], granted: [] }] },
      };
      expect(await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedWithAmberSourceAndDeletedOne] })).toBeNull();
      expect((await timelineUpdateForUser(testContext, editor, { ...update, changed_event_ids: [], removed_events: [removedWithAmberSourceAndDeletedOne] }))?.changed_event_ids)
        .toEqual(['removed-event']);
      // Element and source both deleted: both are read as they were
      const removedWithEverythingDeleted = { ...removedAboutDeleted, element_access: { ...openAccess, sources: [deletedSource] } };
      expect((await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [], removed_events: [removedWithEverythingDeleted] }))?.changed_event_ids)
        .toEqual(['removed-event']);
      // An update naming only part of its events reaches the subscriber, without the events it cannot read
      const truncatedUpdate = await timelineUpdateForUser(testContext, participate, { ...update, changed_event_ids: [restrictedId], truncated: true });
      expect(truncatedUpdate?.changed_event_ids).toEqual([]);
      expect(truncatedUpdate).not.toHaveProperty('truncated');
      // Updates about the container itself name no event and go through to every reader of the container
      expect(await timelineUpdateForUser(testContext, participate, { ...update, update_type: 'settings', changed_event_ids: [] })).toMatchObject({ update_type: 'settings', changed_event_ids: [] });
      // The access to the container is read again for every update: a subscriber who cannot read it any more gets nothing
      const restrictedCase = await createEntity(testContext, SYSTEM_USER, {
        name: 'Timeline subscriber without access',
        authorized_members: [{ id: ADMIN_USER.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }],
      }, ENTITY_TYPE_CONTAINER_CASE_RFI);
      const restrictedUpdate = { ...update, id: restrictedCase.id, container_id: restrictedCase.id, update_type: 'settings' as const, changed_event_ids: [] };
      expect(await timelineUpdateForUser(testContext, participate, restrictedUpdate)).toBeNull();
      expect(await timelineUpdateForUser(testContext, editor, restrictedUpdate)).toBeNull();
      expect(await timelineUpdateForUser(testContext, ADMIN_USER, restrictedUpdate)).toMatchObject({ update_type: 'settings', container_id: restrictedCase.id });
      await deleteElementById(testContext, SYSTEM_USER, restrictedCase.id, ENTITY_TYPE_CONTAINER_CASE_RFI);
    });

    it('should read a derived event like every relationship it is dated by, not only like its technique', async () => {
      const participate = await resolveUserById(testContext, USER_PARTICIPATE.id) as AuthUser;
      const [technique] = (await loadStoredTimelineEvents(testContext, caseIncident.id)).filter((event) => event.kind === 'technique_used');
      // The window of the technique comes from its uses relationship: the regeneration records the relationship as a source
      expect(timelineEventSourceIds(technique)).toEqual([usesRelationshipId]);
      // Pinning and unpinning the event rewrite it: its sources and recorded access stay
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_PIN, variables: { id: technique.internal_id, pinned: true } });
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_PIN, variables: { id: technique.internal_id, pinned: false } });
      const [repinned] = (await loadStoredTimelineEvents(testContext, caseIncident.id)).filter((event) => event.kind === 'technique_used');
      expect(repinned.element_access).toEqual(technique.element_access);
      // The relationship becomes unreadable for the participant (shared with fewer organizations, restricted to some members),
      // the technique and the markings of the event staying readable: the TLP:AMBER indicator stands for it
      await elUpdate(testContext, technique._index, technique.internal_id, {
        doc: { element_access: { ...technique.element_access, sources: [{ id: indicatorId, restricted_members: [], granted: [] }] } },
      });
      try {
        const listedIds = async (user: typeof USER_EDITOR) => {
          const result = await queryAsUserWithSuccess(user, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500, kinds: ['technique_used'] } });
          return { ids: result.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node.id), count: result.data.containerTimeline.pageInfo.globalCount };
        };
        // Left out before the pagination, so that the page and its count agree
        expect(await listedIds(USER_PARTICIPATE)).toEqual({ ids: [], count: 0 });
        expect(await listedIds(USER_EDITOR)).toEqual({ ids: [technique.internal_id], count: 1 });
        const kindCount = async (user: typeof USER_EDITOR) => {
          const result = await queryAsUserWithSuccess(user, { query: CONTAINER_TIMELINE_SUMMARY, variables: { id: caseIncident.id } });
          return result.data.containerTimelineSummary.kinds.find((k: { kind: string; count: number }) => k.kind === 'technique_used')?.count ?? 0;
        };
        expect(await kindCount(USER_PARTICIPATE)).toEqual(0);
        expect(await kindCount(USER_EDITOR)).toEqual(1);
        // Its window no longer opens the span of the timeline for the participant
        const firstEventTime = async (user: typeof USER_EDITOR) => {
          const result = await queryAsUserWithSuccess(user, { query: CONTAINER_TIMELINE_BOUNDS, variables: { id: caseIncident.id } });
          return iso(result.data.containerTimelineBounds.first_event_time);
        };
        expect(await firstEventTime(USER_PARTICIPATE)).not.toEqual(ADVERSARY_START);
        expect(await firstEventTime(USER_EDITOR)).toEqual(ADVERSARY_START);
        // Nor is it read by its id or named in a live update
        const byId = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: TIMELINE_EVENT, variables: { id: technique.internal_id } });
        expect(byId.data.timelineEvent).toBeNull();
        const update = { id: caseIncident.id, container_id: caseIncident.id, update_type: 'derived' as const, changed_event_ids: [technique.internal_id], updated_at: new Date().toISOString() };
        expect(await timelineUpdateForUser(testContext, participate, update)).toBeNull();
      } finally {
        // The regeneration records the access of the actual source again
        await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      }
      const [restored] = (await loadStoredTimelineEvents(testContext, caseIncident.id)).filter((event) => event.kind === 'technique_used');
      expect(timelineEventSourceIds(restored)).toEqual([usesRelationshipId]);
    });

    it('should tell who can contribute to the timeline', async () => {
      const participate = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE_SUMMARY, variables: { id: caseIncident.id } });
      expect(participate.data.containerTimelineSummary.can_edit).toBe(false);
      const editor = await queryAsUserWithSuccess(USER_EDITOR, { query: CONTAINER_TIMELINE_SUMMARY, variables: { id: caseIncident.id } });
      expect(editor.data.containerTimelineSummary.can_edit).toBe(true);
    });

    it('should refuse contributions from users who cannot update the container', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: CONTAINMENT_TIME, title: 'Not allowed' } },
      });
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
    });
  });

  describe('analyst contributions', () => {
    it('should add a containment milestone and move the containment anchor', async () => {
      const result = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: CONTAINMENT_TIME, title: 'Hosts isolated', kind: 'containment', lane: 'response', description: 'EDR isolation of the 4 hosts' } },
      });
      const event = result.data.timelineEventAdd as TimelineEventNode;
      manualEventId = event.id;
      expect(event).toMatchObject({ source: 'manual', kind: 'containment', lane: 'response', title: 'Hosts isolated', editable: true, precision: 'exact' });
      const anchors = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      expect(iso(anchors.data.timelineAnchors.containment)).toEqual(CONTAINMENT_TIME);
    });

    it('should not move the anchors with events marked more strictly than the container', async () => {
      const restricted = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: '2026-02-03T08:00:00.000Z', title: 'Amber containment', kind: 'containment', lane: 'response', objectMarking: [MARKING_TLP_AMBER] } },
      });
      // Every reader of the case gets the same anchors: an earlier containment only TLP:AMBER readers can see is left out
      const anchors = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      expect(iso(anchors.data.timelineAnchors.containment)).toEqual(CONTAINMENT_TIME);
      expect(iso(anchors.data.timelineAnchors.first_response)).toEqual('2026-02-04T12:00:00.000Z');
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: restricted.data.timelineEventAdd.id } });
    });

    it('should be idempotent on the external id of a manual event', async () => {
      const input = { container_id: caseIncident.id, event_time: '2026-02-05T12:00:00.000Z', title: 'Regulator notified', kind: 'notification', external_id: 'splunk-alert-42', createdBy: TEST_ORGANIZATION.id };
      const first = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input } });
      const second = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, title: 'Regulator notified (CNIL)' } } });
      expect(second.data.timelineEventAdd.id).toEqual(first.data.timelineEventAdd.id);
      expect(second.data.timelineEventAdd).toMatchObject({ title: 'Regulator notified (CNIL)', external_id: 'splunk-alert-42' });
      // A retry that names no author keeps the author of the event
      const { createdBy: _, ...withoutAuthor } = input;
      const retry = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...withoutAuthor, title: 'Regulator notified (CNIL)' } } });
      const author = await internalLoadById(testContext, SYSTEM_USER, TEST_ORGANIZATION.id);
      expect(retry.data.timelineEventAdd).toMatchObject({ id: first.data.timelineEventAdd.id, createdBy: { id: author.internal_id } });
      const manual = await listTimeline(caseIncident.id, { sources: ['manual'] });
      expect(manual).toHaveLength(2);
    });

    it('should refuse an empty external id, which would add the event again on every call', async () => {
      const input = { container_id: caseIncident.id, event_time: '2026-02-05T12:30:00.000Z', title: 'Ticket opened' };
      await queryAsAdminWithError({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, external_id: '' } } }, 'The external id of a timeline event cannot be empty');
      await queryAsAdminWithError({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, external_id: '   ' } } }, 'The external id of a timeline event cannot be empty');
      const manual = await listTimeline(caseIncident.id, { sources: ['manual'] });
      expect(manual.map((event) => event.title)).not.toContain('Ticket opened');
    });

    it('should edit a manual event and validate its window', async () => {
      const edited = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: manualEventId, input: { title: 'Hosts isolated by the SOC', annotation: 'Confirmed by the EDR console' } } });
      expect(edited.data.timelineEventEdit).toMatchObject({ title: 'Hosts isolated by the SOC', annotation: 'Confirmed by the EDR console' });
      await queryAsAdminWithError(
        { query: TIMELINE_EVENT_EDIT, variables: { id: manualEventId, input: { event_end_time: '2026-01-01T00:00:00.000Z' } } },
        'The end time of an event must be after its start time',
      );
      // A window ending at its start is no window
      await queryAsAdminWithError(
        { query: TIMELINE_EVENT_EDIT, variables: { id: manualEventId, input: { event_end_time: CONTAINMENT_TIME } } },
        'The end time of an event must be after its start time',
      );
    });

    it('should mark a manual event at least as strictly as the element it points to, and never declassify it on edit', async () => {
      const added = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T11:00:00.000Z', title: 'Amber indicator blocked', element_id: indicatorId } },
      });
      const event = added.data.timelineEventAdd as TimelineEventNode;
      expect(event.objectMarking.map((marking) => marking.standard_id)).toContain(MARKING_TLP_AMBER);
      // Replacing the markings of the event never drops the markings of its element
      const edited = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: event.id, input: { objectMarking: [] } } });
      expect((edited.data.timelineEventEdit as TimelineEventNode).objectMarking.map((marking) => marking.standard_id)).toContain(MARKING_TLP_AMBER);
      const participate = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500, sources: ['manual'] } });
      expect(participate.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node.id)).not.toContain(event.id);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: event.id } });
      // Nor the markings the event already carries: an edit adds markings, it never removes one
      const marked = (await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T11:30:00.000Z', title: 'Amber note', objectMarking: [MARKING_TLP_AMBER] } },
      })).data.timelineEventAdd as TimelineEventNode;
      const cleared = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: marked.id, input: { title: 'Amber note edited', objectMarking: [] } } });
      expect((cleared.data.timelineEventEdit as TimelineEventNode).objectMarking.map((marking) => marking.standard_id)).toContain(MARKING_TLP_AMBER);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: marked.id } });
    });

    it('should pin, hide and annotate a derived event, never change its content', async () => {
      const malwareEvents = await listTimeline(caseIncident.id, { kinds: ['malware_seen'] });
      derivedMalwareEventId = malwareEvents[0].id;
      const pinned = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_PIN, variables: { id: derivedMalwareEventId, pinned: true } });
      expect(pinned.data.timelineEventPin).toMatchObject({ pinned: true, analyst_fields: ['pinned'] });
      const annotated = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: derivedMalwareEventId, input: { annotation: 'Initial dropper' } } });
      expect(annotated.data.timelineEventEdit.annotation).toEqual('Initial dropper');
      await queryAsAdminWithError(
        { query: TIMELINE_EVENT_EDIT, variables: { id: derivedMalwareEventId, input: { title: 'Renamed' } } },
        'A derived event only accepts an annotation and an ordering hint (pin and hide it with timelineEventPin and timelineEventHide)',
      );
      await queryAsAdminWithError({ query: TIMELINE_EVENT_DELETE, variables: { id: derivedMalwareEventId } }, 'A derived event cannot be deleted, hide it instead');
      const pinnedOnly = await listTimeline(caseIncident.id, { pinnedOnly: true });
      expect(pinnedOnly.map((e) => e.id)).toEqual([derivedMalwareEventId]);
    });

    it('should keep the analyst fields of derived events across regenerations', async () => {
      await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      const result = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT, variables: { id: derivedMalwareEventId } });
      expect(result.data.timelineEvent).toMatchObject({ pinned: true, annotation: 'Initial dropper' });
      expect(result.data.timelineEvent.analyst_fields).toEqual(expect.arrayContaining(['pinned', 'annotation']));
      // Manual events keep their author
      const [notification] = await listTimeline(caseIncident.id, { kinds: ['notification'] });
      expect(notification.createdBy?.id).toBeDefined();
    });

    it('should hide events from the default view only', async () => {
      const relationEvents = await listTimeline(caseIncident.id, { kinds: ['relation_created'] });
      const hidden = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_HIDE, variables: { id: relationEvents[0].id, hidden: true } });
      expect(hidden.data.timelineEventHide.hidden).toBe(true);
      expect((await listTimeline(caseIncident.id)).find((e) => e.id === relationEvents[0].id)).toBeUndefined();
      expect((await listTimeline(caseIncident.id, { includeHidden: true })).find((e) => e.id === relationEvents[0].id)).toBeDefined();
      const summary = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_SUMMARY, variables: { id: caseIncident.id } });
      expect(summary.data.containerTimelineSummary).toMatchObject({ hidden_count: 1, pinned_count: 1, manual_count: 2, can_edit: true, truncated: false });
    });

    it('should publish every live update of a change as its author, who does not receive them', async () => {
      const editTopic = BUS_TOPICS[ENTITY_TYPE_TIMELINE_EVENT].EDIT_TOPIC;
      const [technique] = (await loadStoredTimelineEvents(testContext, caseIncident.id)).filter((event) => event.kind === 'technique_used');
      const published = vi.spyOn(redis, 'notify');
      try {
        // A containment milestone earlier than the current one moves the anchors: the anchors update follows the event update
        const added = await queryAsAdminWithSuccess({
          query: TIMELINE_EVENT_ADD,
          variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T09:00:00.000Z', title: 'Earlier containment', kind: 'containment', lane: 'response' } },
        });
        await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: added.data.timelineEventAdd.id } });
        // A regeneration asked by the analyst that rewrites an event
        await elUpdate(testContext, technique._index, technique.internal_id, { doc: { description: 'Outdated description' } });
        await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
        const updates = published.mock.calls.filter(([topic, update]) => topic === editTopic && update.container_id === caseIncident.id);
        expect(updates.map(([, update]) => update.update_type)).toEqual(expect.arrayContaining(['manual', 'anchors', 'derived']));
        // The subscription leaves out the updates published by its own user
        expect(updates.map(([, , author]) => author.id)).toEqual(updates.map(() => ADMIN_USER.id));
      } finally {
        published.mockRestore();
      }
    });
  });

  describe('queries', () => {
    it('should filter by lane, kind, source, search and window', async () => {
      const response = await listTimeline(caseIncident.id, { lanes: ['response'] });
      expect(response.length).toBeGreaterThan(0);
      expect(response.every((e) => e.lane === 'response')).toBe(true);
      const searched = await listTimeline(caseIncident.id, { search: 'Regulator' });
      expect(searched.map((e) => e.external_id)).toEqual(['splunk-alert-42']);
      const windowed = await listTimeline(caseIncident.id, { from: '2026-02-05T00:00:00.000Z', to: '2026-02-05T23:59:59.000Z' });
      expect(windowed.length).toBeGreaterThan(0);
      // Windows still open at the start of the period are included (indicator validity)
      expect(windowed.find((e) => e.kind === 'indicator_valid')).toBeDefined();
      expect(windowed.every((e) => new Date(e.event_time).getTime() <= new Date('2026-02-05T23:59:59.000Z').getTime())).toBe(true);
    });

    it('should summarize the timeline', async () => {
      const result = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_SUMMARY, variables: { id: caseIncident.id } });
      const summary = result.data.containerTimelineSummary;
      expect(summary.total).toBeGreaterThan(5);
      expect(iso(summary.first_event_time)).toEqual(ADVERSARY_START);
      // The only knowledge event (the relationship) is hidden, the notification milestone has no lane
      expect(summary.lanes.map((l: { lane: string }) => l.lane).sort()).toEqual(['adversary', 'custom', 'evidence', 'response']);
      expect(iso(summary.anchors.containment)).toEqual(CONTAINMENT_TIME);
      expect(summary.settings).toMatchObject({ default_grouping: 'day', default_zoom_window: 'fit' });
    });

    it('should restrict the counts and bounds of the summary to some lanes and kinds', async () => {
      const restricted = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_SUMMARY_SCOPED, variables: { id: caseIncident.id, kinds: ['malware_seen'] } });
      const summary = restricted.data.containerTimelineSummary;
      const malwareEvents = await listTimeline(caseIncident.id, { kinds: ['malware_seen'] });
      expect(summary.total).toEqual(malwareEvents.length);
      const times = malwareEvents.flatMap((event) => [event.event_time, event.event_end_time]).filter((time): time is string => !!time).map((time) => Date.parse(time));
      expect(Date.parse(summary.first_event_time)).toEqual(Math.min(...malwareEvents.map((event) => Date.parse(event.event_time))));
      expect(Date.parse(summary.last_event_time)).toEqual(Math.max(...times));
      const responseOnly = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_SUMMARY_SCOPED, variables: { id: caseIncident.id, lanes: ['response'] } });
      expect(responseOnly.data.containerTimelineSummary.lanes.map((l: { lane: string }) => l.lane)).toEqual(['response']);
    });

    it('should export the timeline as CSV, SVG and HTML with translated labels', async () => {
      const csv = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv' } });
      const csvContent: string = csv.data.containerTimelineExport;
      expect(csvContent.split('\r\n')[0]).toEqual('time,end_time,lane,kind,precision,title,element,element_type,source,pinned,hidden,annotation,description');
      expect(csvContent).toContain('Hosts isolated by the SOC');
      const svg = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'svg' } });
      expect(svg.data.containerTimelineExport.startsWith('<svg')).toBe(true);
      const html = await queryAsAdminWithSuccess({
        query: CONTAINER_TIMELINE_EXPORT,
        variables: { id: caseIncident.id, format: 'html', labels: [{ key: 'title', label: 'Chronologie' }, { key: 'lane.response', label: 'Reponse' }] },
      });
      const htmlContent: string = html.data.containerTimelineExport;
      expect(htmlContent).toContain('<svg');
      expect(htmlContent).toContain('Chronologie - Timeline ransomware case');
      expect(htmlContent).toContain('Reponse');
    });

    it('should export with the filters of the current view', async () => {
      const filtered = await queryAsAdminWithSuccess({
        query: CONTAINER_TIMELINE_EXPORT,
        variables: { id: caseIncident.id, format: 'csv', search: 'Regulator', sources: ['manual'] },
      });
      const rows = (filtered.data.containerTimelineExport as string).split('\r\n').filter((row) => row.length > 0);
      expect(rows).toHaveLength(2);
      expect(rows[1]).toContain('Regulator notified (CNIL)');
      const pinned = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv', pinnedOnly: true } });
      expect(pinned.data.containerTimelineExport).not.toContain('Regulator notified (CNIL)');
    });

    it('should list from the latest event in descending order', async () => {
      const descending = await listTimeline(caseIncident.id, { orderMode: 'desc', first: 3 });
      const ascending = await listTimeline(caseIncident.id);
      expect(descending[0].event_time).toEqual(ascending[ascending.length - 1].event_time);
      const times = descending.map((event) => new Date(event.event_time).getTime());
      expect([...times].sort((a, b) => b - a)).toEqual(times);
    });

    it('should bound every matching event the user can list, also a window ending after the latest start', async () => {
      const span = (events: Array<Pick<TimelineEventNode, 'event_time' | 'event_end_time'>>) => {
        const starts = events.map((event) => new Date(event.event_time).getTime());
        const ends = events.filter((event) => !!event.event_end_time).map((event) => new Date(event.event_end_time as string).getTime());
        return { first: Math.min(...starts), last: Math.max(...starts, ...ends) };
      };
      const time = (value: string | Date | null) => (value ? new Date(value).getTime() : null);
      const listed = await listTimeline(caseIncident.id);
      const bounds = (await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_BOUNDS, variables: { id: caseIncident.id } })).data.containerTimelineBounds;
      expect({ first: time(bounds.first_event_time), last: time(bounds.last_event_time) }).toEqual(span(listed));
      // Same filters as the list
      const manual = await listTimeline(caseIncident.id, { sources: ['manual'] });
      const manualBounds = (await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_BOUNDS, variables: { id: caseIncident.id, sources: ['manual'] } })).data.containerTimelineBounds;
      expect({ first: time(manualBounds.first_event_time), last: time(manualBounds.last_event_time) }).toEqual(span(manual));
      // Same visibility as the list
      const userListed = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500 } });
      const userBounds = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE_BOUNDS, variables: { id: caseIncident.id } });
      const userEvents = userListed.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node);
      const { first_event_time: userFirst, last_event_time: userLast } = userBounds.data.containerTimelineBounds;
      expect({ first: time(userFirst), last: time(userLast) }).toEqual(span(userEvents));
    });

    it('should count in the summary exactly the events the user can list', async () => {
      const summary = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE_SUMMARY, variables: { id: caseIncident.id } });
      const listed = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500 } });
      expect(summary.data.containerTimelineSummary.total).toEqual(listed.data.containerTimeline.edges.length);
    });

    it('should only export what the exporting user can see', async () => {
      const csv = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv' } });
      expect(csv.data.containerTimelineExport).not.toContain('Timeline amber indicator');
    });

    it('should apply the content ceiling and the max shareable markings to exports', async () => {
      const green = await queryAsAdminWithSuccess({ query: MARKING_DEFINITION, variables: { id: MARKING_TLP_GREEN } });
      const greenId = green.data.markingDefinition.id;
      const full = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv' } });
      expect(full.data.containerTimelineExport).toContain('Timeline amber indicator');
      const ceiled = await queryAsPlatformAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv', contentMaxMarkings: [greenId] } });
      expect(ceiled.data.containerTimelineExport).not.toContain('Timeline amber indicator');
      expect(ceiled.data.containerTimelineExport).toContain('Hosts isolated by the SOC');
      // The editor sees the amber indicator, but can only share up to TLP:GREEN
      const editorList = await queryAsUserWithSuccess(USER_EDITOR, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500 } });
      expect(editorList.data.containerTimeline.edges.some((edge: { node: TimelineEventNode }) => edge.node.element_id === indicatorId)).toBe(true);
      const editorCsv = await queryAsUserWithSuccess(USER_EDITOR, { query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv' } });
      expect(editorCsv.data.containerTimelineExport).not.toContain('Timeline amber indicator');
      await queryAsAdminWithError(
        { query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv', contentMaxMarkings: ['marking-definition--00000000-0000-4000-8000-000000000000'] } },
        'Marking definition cannot be found',
      );
    });

    it('should mark a stored export at least as strictly as the events it contains', async () => {
      const green = await queryAsAdminWithSuccess({ query: MARKING_DEFINITION, variables: { id: MARKING_TLP_GREEN } });
      const greenId = green.data.markingDefinition.id;
      const markingIdsOf = (file: { file_markings: { standard_id: string }[] }) => file.file_markings.map((marking) => marking.standard_id);
      const raised = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT_FILE, variables: { id: caseIncident.id, format: 'csv', fileMarkings: [greenId] } });
      // The content and its markings come from the same events: the amber indicator is in the file, marked TLP:AMBER
      expect(raised.data.containerTimelineExportFile.content).toContain('Timeline amber indicator');
      // TLP:AMBER (amber indicator events) replaces the weaker TLP:GREEN selected for the file
      expect(markingIdsOf(raised.data.containerTimelineExportFile)).toContain(MARKING_TLP_AMBER);
      expect(markingIdsOf(raised.data.containerTimelineExportFile)).not.toContain(MARKING_TLP_GREEN);
      const ceiled = await queryAsPlatformAdminWithSuccess({
        query: CONTAINER_TIMELINE_EXPORT_FILE,
        variables: { id: caseIncident.id, format: 'csv', contentMaxMarkings: [greenId], fileMarkings: [greenId] },
      });
      expect(ceiled.data.containerTimelineExportFile.content).not.toContain('Timeline amber indicator');
      expect(markingIdsOf(ceiled.data.containerTimelineExportFile)).toEqual([MARKING_TLP_GREEN]);
    });

    it('should apply the content ceiling and the file markings to the sources of an event, not only to its element', async () => {
      const green = await queryAsAdminWithSuccess({ query: MARKING_DEFINITION, variables: { id: MARKING_TLP_GREEN } });
      const greenId = green.data.markingDefinition.id;
      const [technique] = (await loadStoredTimelineEvents(testContext, caseIncident.id)).filter((event) => event.kind === 'technique_used');
      // A source marked TLP:AMBER since the last regeneration: the event and its technique do not carry its markings yet
      await elUpdate(testContext, technique._index, technique.internal_id, {
        doc: { element_access: { ...technique.element_access, sources: [{ id: indicatorId, restricted_members: [], granted: [] }] } },
      });
      try {
        const variables = { id: caseIncident.id, format: 'csv', kinds: ['technique_used'] };
        const full = await queryAsPlatformAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables });
        expect(full.data.containerTimelineExport).toContain('Timeline spearphishing');
        const ceiled = await queryAsPlatformAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { ...variables, contentMaxMarkings: [greenId] } });
        expect(ceiled.data.containerTimelineExport).not.toContain('Timeline spearphishing');
        const file = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT_FILE, variables: { ...variables, fileMarkings: [greenId] } });
        expect(file.data.containerTimelineExportFile.content).toContain('Timeline spearphishing');
        const fileMarkingIds = file.data.containerTimelineExportFile.file_markings.map((marking: { standard_id: string }) => marking.standard_id);
        expect(fileMarkingIds).toContain(MARKING_TLP_AMBER);
        expect(fileMarkingIds).not.toContain(MARKING_TLP_GREEN);
      } finally {
        await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      }
      const [restored] = (await loadStoredTimelineEvents(testContext, caseIncident.id)).filter((event) => event.kind === 'technique_used');
      expect(timelineEventSourceIds(restored)).toEqual([usesRelationshipId]);
    });

    it('should leave out of a stored export the events about elements restricted to some members', async () => {
      // Only its authorized members read this request for information: the exporting admin does, other readers of the case do not
      const restricted = await createEntity(testContext, SYSTEM_USER, {
        name: 'Timeline restricted request',
        authorized_members: [{ id: ADMIN_USER.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }],
      }, ENTITY_TYPE_CONTAINER_CASE_RFI);
      const added = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T09:00:00.000Z', title: 'Regulator questions received', element_id: restricted.id } },
      });
      try {
        // Downloaded, the export only reaches the exporting user: the event is in it
        const downloaded = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv' } });
        expect(downloaded.data.containerTimelineExport).toContain('Regulator questions received');
        // Stored in the case, the file reaches every reader of the case whose markings cover it: the event is left out
        const stored = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT_FILE, variables: { id: caseIncident.id, format: 'csv' } });
        expect(stored.data.containerTimelineExportFile.content).not.toContain('Regulator questions received');
        expect(stored.data.containerTimelineExportFile.content).toContain('Hosts isolated by the SOC');
      } finally {
        await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: added.data.timelineEventAdd.id } });
        await deleteElementById(testContext, SYSTEM_USER, restricted.id, ENTITY_TYPE_CONTAINER_CASE_RFI);
      }
    });

    it('should name the referenced elements in the exports', async () => {
      const csv = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv' } });
      const rows = (csv.data.containerTimelineExport as string).split('\r\n').filter((row) => row.length > 0);
      // The element and element_type columns carry the representative name (MITRE id and name) and the type of the attack pattern, never an internal id
      expect(rows.some((row) => row.includes(',[T9991] Timeline spearphishing,Attack-Pattern,'))).toBe(true);
    });

    it('should only mark as editable the manual events of users who can update the container', async () => {
      const editor = await queryAsUserWithSuccess(USER_EDITOR, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500 } });
      const editorEvents: TimelineEventNode[] = editor.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node);
      const editorManual = editorEvents.filter((event) => event.source === 'manual');
      expect(editorManual.length).toBeGreaterThan(0);
      expect(editorManual.every((event) => event.editable)).toBe(true);
      expect(editorManual.every((event) => event.annotatable)).toBe(true);
      expect(editorEvents.filter((event) => event.source === 'derived').some((event) => event.editable)).toBe(false);
      const participate = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE, variables: { id: caseIncident.id, first: 500, sources: ['manual'] } });
      const participateManual: TimelineEventNode[] = participate.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node);
      expect(participateManual.length).toBeGreaterThan(0);
      expect(participateManual.some((event) => event.editable)).toBe(false);
      expect(participateManual.some((event) => event.annotatable)).toBe(false);
    });

    it('should count the openings of the timeline tab', async () => {
      const viewed = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: TIMELINE_VIEWED, variables: { containerId: caseIncident.id } });
      expect(viewed.data.timelineViewed).toBe(true);
      await queryAsAdminWithError({ query: TIMELINE_VIEWED, variables: { containerId: 'unknown-container' } }, 'Timeline container cannot be found');
    });

    it('should update the settings of the timeline', async () => {
      const result = await queryAsAdminWithSuccess({
        query: TIMELINE_SETTINGS_UPDATE,
        variables: { containerId: caseIncident.id, input: { enabled_lanes: ['adversary', 'response', 'adversary'], default_grouping: 'week', hidden_kinds: ['relation_created'] } },
      });
      expect(result.data.timelineSettingsUpdate).toMatchObject({ enabled_lanes: ['adversary', 'response'], default_grouping: 'week', default_zoom_window: 'fit', hidden_kinds: ['relation_created'] });
      await queryAsAdminWithError({ query: TIMELINE_SETTINGS_UPDATE, variables: { containerId: caseIncident.id, input: { enabled_lanes: [] } } }, 'At least one lane must be enabled');
      await queryAsAdminWithError({ query: TIMELINE_SETTINGS_UPDATE, variables: { containerId: caseIncident.id, input: { hidden_kinds: [...TIMELINE_KINDS] } } }, 'At least one kind must stay visible');
    });

    it('should publish with a settings update the anchors read under the timeline lock', async () => {
      type LoadedCase = { _index: string; x_opencti_timeline_anchors?: Record<string, unknown> | null };
      const loaded = await internalLoadById(testContext, SYSTEM_USER, caseIncident.id) as unknown as LoadedCase;
      const previousAnchors = loaded.x_opencti_timeline_anchors ?? null;
      const closure = '2026-02-09T09:00:00.000Z';
      // A regeneration writes new anchors while the settings update waits for the lock of the timeline
      const withLock = timelineEngine.withTimelineLock;
      const lock = vi.spyOn(timelineEngine, 'withTimelineLock').mockImplementationOnce(async (containerId, write) => {
        await elUpdate(testContext, loaded._index, caseIncident.id, { doc: { x_opencti_timeline_anchors: { ...(previousAnchors ?? {}), closure } } });
        return withLock(containerId, write);
      });
      const published = vi.spyOn(timelineEngine, 'publishTimelineUpdate');
      try {
        await queryAsAdminWithSuccess({ query: TIMELINE_SETTINGS_UPDATE, variables: { containerId: caseIncident.id, input: { default_grouping: 'week' } } });
        const update = published.mock.calls.map(([payload]) => payload).find((payload) => payload.update_type === 'settings' && payload.container_id === caseIncident.id);
        expect(iso(update?.anchors?.closure as string | undefined)).toEqual(closure);
      } finally {
        lock.mockRestore();
        published.mockRestore();
        await elUpdate(testContext, loaded._index, caseIncident.id, { doc: { x_opencti_timeline_anchors: previousAnchors } });
      }
    });

    it('should filter and order the containers on their anchors', async () => {
      const filters = {
        mode: 'and',
        filters: [{ key: ['x_opencti_timeline_anchors.containment'], values: [CONTAINMENT_TIME], operator: 'eq' }],
        filterGroups: [],
      };
      const filtered = await queryAsAdminWithSuccess({ query: CASE_INCIDENTS_BY_ANCHOR, variables: { filters } });
      expect(filtered.data.caseIncidents.edges.map((edge: { node: { id: string } }) => edge.node.id)).toEqual([caseIncident.id]);
      const ordered = await queryAsAdminWithSuccess({ query: CASE_INCIDENTS_BY_ANCHOR, variables: { orderBy: 'timeline_containment', orderMode: 'desc' } });
      expect(ordered.data.caseIncidents.edges[0].node.id).toEqual(caseIncident.id);
    });

    it('should page the containers whose anchors changed since a cursor', async () => {
      const anchors = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      const { changed_at: changedAt, computed_at: computedAt } = anchors.data.timelineAnchors;
      const since = (key: string, operator: string, value: string) => ({
        mode: 'and',
        filters: [{ key: [`x_opencti_timeline_anchors.${key}`], values: [value], operator }],
        filterGroups: [],
      });
      const ids = (result: { data: Record<string, any> }): string[] => result.data.caseIncidents.edges.map((edge: { node: { id: string } }) => edge.node.id);
      const fromCursor = await queryAsAdminWithSuccess({
        query: CASE_INCIDENTS_BY_ANCHOR,
        variables: { filters: since('changed_at', 'gte', changedAt), orderBy: 'timeline_changed_at', orderMode: 'asc' },
      });
      expect(ids(fromCursor)).toContain(caseIncident.id);
      const afterCursor = await queryAsAdminWithSuccess({ query: CASE_INCIDENTS_BY_ANCHOR, variables: { filters: since('changed_at', 'gt', changedAt) } });
      expect(ids(afterCursor)).not.toContain(caseIncident.id);
      const computedSince = await queryAsAdminWithSuccess({
        query: CASE_INCIDENTS_BY_ANCHOR,
        variables: { filters: since('computed_at', 'gte', computedAt), orderBy: 'timeline_computed_at', orderMode: 'desc' },
      });
      expect(ids(computedSince)).toContain(caseIncident.id);
    });
  });

  describe('STIX exchange', () => {
    it('should carry the analyst contributions in the timeline extension of the container', async () => {
      const result = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_STIX, variables: { id: caseIncident.id } });
      const stix = JSON.parse(result.data.caseIncident.toStix);
      const extension = stix.extensions[STIX_EXT_OCTI_TIMELINE];
      expect(extension.extension_type).toEqual('property-extension');
      expect(extension.events.map((e: { title: string }) => e.title).sort()).toEqual(['Hosts isolated by the SOC', 'Regulator notified (CNIL)']);
      expect(extension.annotations).toEqual(expect.arrayContaining([
        expect.objectContaining({ rule_id: 'entity-first-last-seen', kind: 'malware_seen', element_ref: malware.standard_id, pinned: true, annotation: 'Initial dropper' }),
      ]));
    });

    it('should recreate the contributions on another container and stay idempotent', async () => {
      const source = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_STIX, variables: { id: caseIncident.id } });
      const extension = JSON.stringify(JSON.parse(source.data.caseIncident.toStix).extensions[STIX_EXT_OCTI_TIMELINE]);
      const manualEventCount = () => redisGetTelemetry(TELEMETRY_GAUGE_TIMELINE_MANUAL_EVENT);
      const countBefore = await manualEventCount();
      const notified = vi.spyOn(timelineNotification, 'notifyTimelineMilestonesAdded');
      const imported = await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
      expect(imported.data.timelineImport.manual_count).toEqual(2);
      // The milestones created by the import count and notify like the ones added by an analyst (both fire-and-forget),
      // in one pass over the triggers
      await awaitUntilCondition(async () => (await manualEventCount()) === countBefore + 2, 3000, { message: 'Imported milestones were not counted in time' });
      await awaitUntilCondition(async () => notified.mock.calls.length === 1, 3000, { message: 'Imported milestones were not notified in time' });
      const [[, , notifiedContainerId, notifiedMilestones]] = notified.mock.calls;
      expect(notifiedContainerId).toEqual(secondCase.id);
      expect(notifiedMilestones.map((milestone) => milestone.name).sort()).toEqual(['Hosts isolated by the SOC', 'Regulator notified (CNIL)']);
      const again = await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
      expect(again.data.timelineImport.manual_count).toEqual(2);
      const pinnedOnly = await listTimeline(secondCase.id, { pinnedOnly: true });
      expect(pinnedOnly).toHaveLength(1);
      expect(pinnedOnly[0]).toMatchObject({ kind: 'malware_seen', element_id: malware.id, annotation: 'Initial dropper' });
      // Coming back to the platform it was exported from, an event updates itself
      const back = await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: caseIncident.id, extension } });
      expect(back.data.timelineImport.manual_count).toEqual(2);
      // Updates of known events are neither counted nor notified again
      expect(await manualEventCount()).toEqual(countBefore + 2);
      expect(notified).toHaveBeenCalledTimes(1);
      notified.mockRestore();
    });

    it('should clear on the receiving container an annotation cleared before the export', async () => {
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: derivedMalwareEventId, input: { annotation: null } } });
      const source = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_STIX, variables: { id: caseIncident.id } });
      const extension = JSON.parse(source.data.caseIncident.toStix).extensions[STIX_EXT_OCTI_TIMELINE];
      const malwareAnnotation = extension.annotations.find((a: { kind: string; element_ref: string }) => a.kind === 'malware_seen' && a.element_ref === malware.standard_id);
      expect(malwareAnnotation).toMatchObject({ pinned: true, cleared_fields: ['annotation'] });
      expect(malwareAnnotation).not.toHaveProperty('annotation');
      // The container that imported the annotation before it was cleared keeps it until the next import
      expect((await listTimeline(secondCase.id, { pinnedOnly: true }))[0]).toMatchObject({ element_id: malware.id, annotation: 'Initial dropper' });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: JSON.stringify(extension) } });
      const received = await listTimeline(secondCase.id, { pinnedOnly: true });
      expect(received).toHaveLength(1);
      expect(received[0]).toMatchObject({ element_id: malware.id, pinned: true, annotation: null });
      // Set again for the tests that follow
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: derivedMalwareEventId, input: { annotation: 'Initial dropper' } } });
    });

    it('should reject an invalid extension', async () => {
      await queryAsAdminWithError({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: 'not json' } }, 'Invalid timeline extension');
    });

    it('should only carry contributions as visible as the container and never declassify on import', async () => {
      const amber = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T15:00:00.000Z', title: 'Amber only milestone', objectMarking: [MARKING_TLP_AMBER] } },
      });
      const result = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_STIX, variables: { id: caseIncident.id } });
      const extension = JSON.parse(result.data.caseIncident.toStix).extensions[STIX_EXT_OCTI_TIMELINE];
      expect(extension.events.map((e: { title: string }) => e.title)).not.toContain('Amber only milestone');
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: amber.data.timelineEventAdd.id } });
      const unknownMarking = JSON.stringify({
        events: [{
          id: 'timeline-event--6b0cbf59-1fd4-4b5a-9c55-1f2f4f5b8d11',
          title: 'Unknown marking milestone',
          event_time: '2026-02-05T16:00:00.000Z',
          object_marking_refs: ['marking-definition--00000000-0000-4000-8000-000000000001'],
        }],
        annotations: [],
      });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: unknownMarking } });
      const manual = await listTimeline(secondCase.id, { sources: ['manual'] });
      expect(manual.map((event) => event.title)).not.toContain('Unknown marking milestone');
      // A reference resolving to an object that is not a marking definition is no marking, even for a user who bypasses markings
      const objectAsMarking = JSON.stringify({
        events: [{
          id: 'timeline-event--3d7a9c41-8e2b-4f6d-a0c5-9b1e7f2d4c38',
          title: 'Object as marking milestone',
          event_time: '2026-02-05T16:30:00.000Z',
          object_marking_refs: [malware.standard_id],
        }],
        annotations: [],
      });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: objectAsMarking } });
      const afterObjectAsMarking = await listTimeline(secondCase.id, { sources: ['manual'] });
      expect(afterObjectAsMarking.map((event) => event.title)).not.toContain('Object as marking milestone');
    });

    it('should keep the markings of a known milestone when an import updates it', async () => {
      const amber = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: secondCase.id, event_time: '2026-02-05T18:00:00.000Z', title: 'Regulator call', external_id: 'import-keeps-markings', objectMarking: [MARKING_TLP_AMBER] } },
      });
      const unmarkedUpdate = JSON.stringify({
        events: [{
          id: 'timeline-event--0f3d6a2e-7c51-4f0b-9d7e-2b8c4e1a5f60',
          external_id: 'import-keeps-markings',
          title: 'Regulator call answered',
          event_time: '2026-02-05T18:00:00.000Z',
        }],
        annotations: [],
      });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: unmarkedUpdate } });
      const updated = (await listTimeline(secondCase.id, { sources: ['manual'] })).find((event) => event.id === amber.data.timelineEventAdd.id);
      expect(updated?.title).toEqual('Regulator call answered');
      expect(updated?.objectMarking.map((marking) => marking.standard_id)).toContain(MARKING_TLP_AMBER);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: amber.data.timelineEventAdd.id } });
    });

    it('should keep the markings of a milestone added again with the same external id', async () => {
      const input = { container_id: secondCase.id, event_time: '2026-02-05T19:00:00.000Z', title: 'Regulator follow-up', external_id: 'retry-keeps-markings' };
      const amber = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, objectMarking: [MARKING_TLP_AMBER] } } });
      // A retry without the markings updates the milestone, it never declassifies it
      const retried = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, title: 'Regulator follow-up sent' } } });
      expect(retried.data.timelineEventAdd.id).toEqual(amber.data.timelineEventAdd.id);
      expect(retried.data.timelineEventAdd.title).toEqual('Regulator follow-up sent');
      expect(retried.data.timelineEventAdd.objectMarking.map((marking: { standard_id: string }) => marking.standard_id)).toContain(MARKING_TLP_AMBER);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: amber.data.timelineEventAdd.id } });
    });

    it('should keep the element of a milestone added again without one', async () => {
      const input = { container_id: secondCase.id, event_time: '2026-02-05T19:30:00.000Z', title: 'Dropper sample shared', external_id: 'retry-keeps-element' };
      const added = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, element_id: malware.id } } });
      const addedId = added.data.timelineEventAdd.id;
      const recorded = (await loadStoredTimelineEvents(testContext, secondCase.id)).find((event) => event.internal_id === addedId);
      expect(recorded?.element_access).toEqual({ restricted_members: [], granted: [] });
      // A retry naming no element updates the milestone, it keeps the element that decides who reads it
      const retried = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, title: 'Dropper sample shared with the CERT' } } });
      expect(retried.data.timelineEventAdd).toMatchObject({ id: addedId, title: 'Dropper sample shared with the CERT', element_id: malware.id });
      const kept = (await loadStoredTimelineEvents(testContext, secondCase.id)).find((event) => event.internal_id === addedId);
      expect(kept?.element_access).toEqual(recorded?.element_access);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: addedId } });
    });

    it('should match an imported event by its STIX id first, even when its external id changed', async () => {
      const extensionWith = (externalId: string, title: string) => JSON.stringify({
        events: [{ id: 'timeline-event--5c2e8f14-9a3b-4d7e-b1f0-6e4a2c8d9b17', external_id: externalId, title, event_time: '2026-02-05T20:00:00.000Z' }],
        annotations: [],
      });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: extensionWith('origin-alert-1', 'Firewall rule pushed') } });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: extensionWith('origin-alert-2', 'Firewall rule pushed everywhere') } });
      const matching = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((event) => event.title.startsWith('Firewall rule pushed'));
      expect(matching.map((event) => event.title)).toEqual(['Firewall rule pushed everywhere']);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: matching[0].id } });
    });

    it('should update an event imported with an external id when it is added again through the API with it', async () => {
      const extension = JSON.stringify({
        events: [{ id: 'timeline-event--8e1b3d57-2f6c-4a90-9d4e-7b5c1a3f2e68', external_id: 'splunk-alert-imported', title: 'Exfiltration alert', event_time: '2026-02-05T21:00:00.000Z' }],
        annotations: [],
      });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
      const imported = (await listTimeline(secondCase.id, { sources: ['manual'] })).find((event) => event.title === 'Exfiltration alert');
      expect(imported).toBeDefined();
      const added = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: secondCase.id, event_time: '2026-02-05T21:00:00.000Z', title: 'Exfiltration alert closed', external_id: 'splunk-alert-imported' } },
      });
      expect(added.data.timelineEventAdd.id).toEqual(imported?.id);
      const matching = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((event) => event.title.startsWith('Exfiltration alert'));
      expect(matching.map((event) => event.title)).toEqual(['Exfiltration alert closed']);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: added.data.timelineEventAdd.id } });
    });

    it('should keep the element of a known event when an import names none', async () => {
      const withElement = { id: 'timeline-event--7a1c3e5f-2b4d-4f6a-8c9e-0d1f2a3b4c5d', title: 'Dropper isolated', event_time: '2026-02-06T08:00:00.000Z', element_ref: malware.standard_id };
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: JSON.stringify({ events: [withElement], annotations: [] }) } });
      const { element_ref: _, ...withoutElement } = withElement;
      await queryAsAdminWithSuccess({
        query: TIMELINE_IMPORT,
        variables: { containerId: secondCase.id, extension: JSON.stringify({ events: [{ ...withoutElement, title: 'Dropper isolated and removed' }], annotations: [] }) },
      });
      const [updated] = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((e) => e.title.startsWith('Dropper isolated'));
      expect(updated).toMatchObject({ title: 'Dropper isolated and removed', element_id: malware.id });
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: updated.id } });
    });

    it('should never point a known event to an element, or to none, that more users read, even once its element is deleted', async () => {
      // Only their authorized members read these requests for information; every reader of the case reads the malware
      const restrictedOf = (name: string) => createEntity(testContext, SYSTEM_USER, {
        name,
        authorized_members: [{ id: ADMIN_USER.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }],
      }, ENTITY_TYPE_CONTAINER_CASE_RFI);
      const restricted = await restrictedOf('Timeline restricted source');
      const restrictedTwin = await restrictedOf('Timeline restricted source follow-up');
      const input = { container_id: secondCase.id, event_time: '2026-02-06T07:00:00.000Z', title: 'Source interviewed', external_id: 'restricted-element-kept' };
      const added = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, element_id: restricted.id } } });
      const addedId = added.data.timelineEventAdd.id;
      let twinDeleted = false;
      try {
        const refusal = 'This event cannot point to an element, or to none, that users its current element is hidden from can read: add a new event instead';
        await queryAsAdminWithError({ query: TIMELINE_EVENT_EDIT, variables: { id: addedId, input: { element_id: malware.id } } }, refusal);
        await queryAsAdminWithError({ query: TIMELINE_EVENT_EDIT, variables: { id: addedId, input: { element_id: null } } }, refusal);
        await queryAsAdminWithError({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, element_id: malware.id } } }, refusal);
        // Imported with the malware, the known event keeps its element and takes the rest of the import
        const imported = { id: 'timeline-event--3b8d1f6a-4c2e-4a9b-8e7d-5f0c1a2b3d4e', external_id: input.external_id, title: 'Source interviewed again', event_time: input.event_time, element_ref: malware.standard_id };
        await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: JSON.stringify({ events: [imported], annotations: [] }) } });
        const kept = (await listTimeline(secondCase.id, { sources: ['manual'] })).find((event) => event.id === addedId);
        expect(kept).toMatchObject({ title: 'Source interviewed again', element_id: restricted.id });
        // An element read by the same members takes its place
        const moved = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: addedId, input: { element_id: restrictedTwin.id } } });
        expect(moved.data.timelineEventEdit.element_id).toEqual(restrictedTwin.id);
        // Its element deleted, the event keeps the access recorded for it: still read (and removable) by the members of the
        // deleted element, hidden from the other readers of the case, and still never pointed to the malware
        const recorded = (await loadStoredTimelineEvents(testContext, secondCase.id)).find((event) => event.internal_id === addedId)?.element_access;
        await deleteElementById(testContext, SYSTEM_USER, restrictedTwin.id, ENTITY_TYPE_CONTAINER_CASE_RFI);
        twinDeleted = true;
        await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: secondCase.id } });
        const orphan = (await loadStoredTimelineEvents(testContext, secondCase.id)).find((event) => event.internal_id === addedId);
        expect(orphan).toMatchObject({ element_id: restrictedTwin.id, element_access: recorded });
        expect(recorded?.restricted_members.map((member) => member.id)).toContain(ADMIN_USER.id);
        expect((await listTimeline(secondCase.id, { sources: ['manual'] })).map((event) => event.id)).toContain(addedId);
        const editorListed = await queryAsUserWithSuccess(USER_EDITOR, { query: CONTAINER_TIMELINE, variables: { id: secondCase.id, first: 500, sources: ['manual'] } });
        expect(editorListed.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node.id)).not.toContain(addedId);
        await queryAsAdminWithError({ query: TIMELINE_EVENT_EDIT, variables: { id: addedId, input: { element_id: malware.id } } }, refusal);
      } finally {
        await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: addedId } });
        await deleteElementById(testContext, SYSTEM_USER, restricted.id, ENTITY_TYPE_CONTAINER_CASE_RFI);
        if (!twinDeleted) await deleteElementById(testContext, SYSTEM_USER, restrictedTwin.id, ENTITY_TYPE_CONTAINER_CASE_RFI);
      }
    });

    it('should keep the author of a known event when an import names none', async () => {
      const author = await internalLoadById(testContext, SYSTEM_USER, TEST_ORGANIZATION.id);
      const withAuthor = { id: 'timeline-event--5e2a7c9b-3d1f-4b6e-9a8c-1f0e2d3c4b5a', title: 'Regulator acknowledged', event_time: '2026-02-06T09:00:00.000Z', created_by_ref: author.standard_id };
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: JSON.stringify({ events: [withAuthor], annotations: [] }) } });
      // An exchange leaves out an author that is not as visible as its container: importing it back keeps the author
      const { created_by_ref: _, ...withoutAuthor } = withAuthor;
      await queryAsAdminWithSuccess({
        query: TIMELINE_IMPORT,
        variables: { containerId: secondCase.id, extension: JSON.stringify({ events: [{ ...withoutAuthor, title: 'Regulator acknowledged the filing' }], annotations: [] }) },
      });
      const [updated] = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((e) => e.title.startsWith('Regulator acknowledged'));
      expect(updated).toMatchObject({ title: 'Regulator acknowledged the filing', createdBy: { id: author.internal_id } });
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: updated.id } });
    });

    it('should keep the confidence of a milestone added again without one', async () => {
      const input = { container_id: secondCase.id, event_time: '2026-02-06T09:30:00.000Z', title: 'Containment confirmed', external_id: 'retry-keeps-confidence' };
      const added = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, confidence: 80 } } });
      const addedId = added.data.timelineEventAdd.id;
      // A retry naming no confidence updates the milestone, it keeps the confidence that decides who may edit it
      const retried = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, title: 'Containment confirmed by the CERT' } } });
      expect(retried.data.timelineEventAdd).toMatchObject({ id: addedId, title: 'Containment confirmed by the CERT', confidence: 80 });
      // An explicit null removes it
      const cleared = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, confidence: null } } });
      expect(cleared.data.timelineEventAdd).toMatchObject({ id: addedId, confidence: null });
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: addedId } });
    });

    it('should never lower the confidence of a known event on import', async () => {
      const event = { id: 'timeline-event--3b5d7f9a-1c2e-4a6b-8d0f-2e4a6c8e0b1d', title: 'Backups verified', event_time: '2026-02-06T10:00:00.000Z' };
      const importVersion = async (version: Record<string, unknown>) => {
        const extension = JSON.stringify({ events: [{ ...event, ...version }], annotations: [] });
        await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
        const [stored] = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((e) => e.title.startsWith('Backups verified'));
        return stored;
      };
      expect(await importVersion({ confidence: 90 })).toMatchObject({ confidence: 90 });
      // Imported without a confidence, or with a lower one, the event keeps its own
      expect(await importVersion({ title: 'Backups verified offline' })).toMatchObject({ title: 'Backups verified offline', confidence: 90 });
      expect(await importVersion({ confidence: 40 })).toMatchObject({ confidence: 90 });
      // A higher one applies
      const raised = await importVersion({ confidence: 95 });
      expect(raised).toMatchObject({ confidence: 95 });
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: raised.id } });
    });

    it('should import once two new events of one extension sharing an external id', async () => {
      const first = { id: 'timeline-event--6c8e0a2b-4d5f-4b7a-8e9c-3f4a5b6c7d8e', external_id: 'soar-case-77', title: 'Playbook started', event_time: '2026-02-06T11:00:00.000Z' };
      const second = { ...first, id: 'timeline-event--7d9f1b3c-5e6a-4c8b-9fad-4a5b6c7d8e9f', title: 'Playbook started, last version' };
      const extension = JSON.stringify({ events: [first, second], annotations: [] });
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
      const matching = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((e) => e.title.startsWith('Playbook started'));
      // The last occurrence wins, and a later import of either updates the same event
      expect(matching.map((e) => e.title)).toEqual(['Playbook started, last version']);
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: JSON.stringify({ events: [{ ...first, title: 'Playbook started again' }], annotations: [] }) } });
      const again = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((e) => e.title.startsWith('Playbook started'));
      expect(again.map((e) => e.title)).toEqual(['Playbook started again']);
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: again[0].id } });
    });

    it('should import a window ending at its start as a point in time', async () => {
      const event = { id: 'timeline-event--4b6d8f0a-2c3e-4a5b-9c7d-1e2f3a4b5c6d', title: 'Mailbox purged', event_time: '2026-02-06T10:00:00.000Z', event_end_time: '2026-02-06T10:00:00.000Z' };
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: JSON.stringify({ events: [event], annotations: [] }) } });
      const [imported] = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((e) => e.title === 'Mailbox purged');
      expect(imported).toMatchObject({ event_time: '2026-02-06T10:00:00.000Z', event_end_time: null });
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: imported.id } });
    });

    it('should write, count and notify once an event named twice in one extension', async () => {
      const event = { id: 'timeline-event--2d4f6a8c-1b3e-4c5d-8e7f-9a0b1c2d3e4f', title: 'Duplicated milestone', event_time: '2026-02-05T23:00:00.000Z' };
      const extension = JSON.stringify({ events: [event, { ...event, title: 'Duplicated milestone, last version' }], annotations: [] });
      const manualEventCount = () => redisGetTelemetry(TELEMETRY_GAUGE_TIMELINE_MANUAL_EVENT);
      const countBefore = await manualEventCount();
      const notified = vi.spyOn(timelineNotification, 'notifyTimelineMilestonesAdded');
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
      const matching = (await listTimeline(secondCase.id, { sources: ['manual'] })).filter((e) => e.title.startsWith('Duplicated milestone'));
      // The last occurrence wins
      expect(matching.map((e) => e.title)).toEqual(['Duplicated milestone, last version']);
      await awaitUntilCondition(async () => (await manualEventCount()) === countBefore + 1, 3000, { message: 'The imported milestone was not counted in time' });
      await awaitUntilCondition(async () => notified.mock.calls.length === 1, 3000, { message: 'The imported milestone was not notified in time' });
      expect(await manualEventCount()).toEqual(countBefore + 1);
      // The milestones of one import are notified in one pass over the triggers
      expect(notified).toHaveBeenCalledTimes(1);
      expect(notified.mock.calls[0][3].map((milestone) => milestone.name)).toEqual(['Duplicated milestone, last version']);
      notified.mockRestore();
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: matching[0].id } });
    });

    it('should never apply an imported annotation to a derived event above the confidence level of the user', async () => {
      const confidentMalware = await queryAsAdminWithSuccess({
        query: MALWARE_ADD,
        variables: { input: { name: 'Timeline confident malware', confidence: 90, first_seen: '2026-02-01T09:00:00.000Z', last_seen: '2026-02-04T09:00:00.000Z' } },
      });
      const lowConfidenceCase = await queryAsAdminWithSuccess({
        query: CASE_INCIDENT_ADD,
        variables: { input: { name: 'Timeline low confidence case', confidence: 10, created: '2026-02-04T12:00:00.000Z', objects: [confidentMalware.data.malwareAdd.id] } },
      });
      const caseId = lowConfidenceCase.data.caseIncidentAdd.id;
      const extension = JSON.stringify({
        events: [],
        annotations: [{ rule_id: 'entity-first-last-seen', kind: 'malware_seen', element_ref: confidentMalware.data.malwareAdd.standard_id, pinned: true, annotation: 'Seen by the night shift' }],
      });
      // Allowed to edit the case (confidence 10), not the derived event of the malware (confidence 90)
      const completeAdmin = await resolveUserById(testContext, ADMIN_USER.id);
      const lowConfidenceUser = {
        ...completeAdmin,
        origin: { referer: 'test', user_id: completeAdmin?.internal_id },
        effective_confidence_level: { max_confidence: 50, overrides: [] },
      } as AuthUser;
      const importAsLowConfidenceUser = async () => {
        const result = await queryAsAuthUser(lowConfidenceUser, { query: TIMELINE_IMPORT, variables: { containerId: caseId, extension } });
        expect(result.errors, `This errors should not be there: ${JSON.stringify(result.errors)}`).toBeUndefined();
      };
      const malwareSeen = async () => (await listTimeline(caseId, { kinds: ['malware_seen'] }))[0];
      // The derived event does not exist yet: the annotation waits for it, and the regeneration does not apply it
      await importAsLowConfidenceUser();
      expect(await malwareSeen()).toMatchObject({ confidence: 90, pinned: false, annotation: null });
      // Now stored, the derived event is checked on import
      await importAsLowConfidenceUser();
      expect(await malwareSeen()).toMatchObject({ pinned: false, annotation: null });
      // Within the confidence level of the user, the same annotation applies
      await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: caseId, extension } });
      expect(await malwareSeen()).toMatchObject({ pinned: true, annotation: 'Seen by the night shift' });
      await queryAsAdmin({ query: STIX_CORE_OBJECT_DELETE, variables: { id: caseId } });
      await queryAsAdmin({ query: STIX_CORE_OBJECT_DELETE, variables: { id: confidentMalware.data.malwareAdd.id } });
      await deleteContainerTimeline(caseId);
    });

    it('should never apply an imported annotation to a derived event the user cannot read through one of its sources', async () => {
      // The editor updates the case and reads its malware and both techniques, not the TLP:RED relationship dating the first one
      const sourceMalware = await queryAsAdminWithSuccess({ query: MALWARE_ADD, variables: { input: { name: 'Timeline malware of a restricted source' } } });
      const sourceMalwareId = sourceMalware.data.malwareAdd.id;
      const restrictedTechnique = (await queryAsAdminWithSuccess({
        query: ATTACK_PATTERN_ADD,
        variables: { input: { name: 'Timeline technique dated by a restricted source', x_mitre_id: 'T9992' } },
      })).data.attackPatternAdd;
      const openTechnique = (await queryAsAdminWithSuccess({
        query: ATTACK_PATTERN_ADD,
        variables: { input: { name: 'Timeline technique dated by an open source', x_mitre_id: 'T9993' } },
      })).data.attackPatternAdd;
      const usesOf = async (techniqueId: string, objectMarking: string[]) => (await queryAsAdminWithSuccess({
        query: RELATIONSHIP_ADD,
        variables: { input: { fromId: sourceMalwareId, toId: techniqueId, relationship_type: 'uses', start_time: ADVERSARY_START, stop_time: ADVERSARY_STOP, objectMarking } },
      })).data.stixCoreRelationshipAdd.id as string;
      const restrictedUsesId = await usesOf(restrictedTechnique.id, [MARKING_TLP_RED]);
      const openUsesId = await usesOf(openTechnique.id, []);
      const created = await queryAsAdminWithSuccess({
        query: CASE_INCIDENT_ADD,
        variables: {
          input: {
            name: 'Timeline case with a restricted source',
            created: '2026-02-04T12:00:00.000Z',
            objects: [sourceMalwareId, restrictedTechnique.id, openTechnique.id, restrictedUsesId, openUsesId],
          },
        },
      });
      const caseId = created.data.caseIncidentAdd.id;
      const annotationOf = (technique: { standard_id: string }, annotation: string) => JSON.stringify({
        events: [],
        annotations: [{ rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: technique.standard_id, pinned: true, annotation }],
      });
      const importAsEditor = (extension: string) => queryAsUserWithSuccess(USER_EDITOR, { query: TIMELINE_IMPORT, variables: { containerId: caseId, extension } });
      const importAsAdmin = (extension: string) => queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: caseId, extension } });
      const techniqueEvent = async (techniqueId: string) => (await loadStoredTimelineEvents(testContext, caseId))
        .find((event) => event.kind === 'technique_used' && event.element_id === techniqueId);
      try {
        // The derived event does not exist yet: the regeneration producing it reads it as the importer, its relationship included
        expect(await techniqueEvent(restrictedTechnique.id)).toBeUndefined();
        await importAsEditor(annotationOf(restrictedTechnique, 'Confirmed by the editor'));
        expect(await techniqueEvent(restrictedTechnique.id)).toMatchObject({ pinned: false, annotation: null });
        // An importer who reads every source of the event applies the same annotation
        await importAsAdmin(annotationOf(restrictedTechnique, 'Confirmed by the administrator'));
        expect(await techniqueEvent(restrictedTechnique.id)).toMatchObject({ pinned: true, annotation: 'Confirmed by the administrator' });
        // A stored derived event is read as the importer on import, each source it records included: the TLP:RED relationship
        // stands for a source of the open event the editor cannot read
        const openEvent = await techniqueEvent(openTechnique.id) as StoredTimelineEvent;
        expect(timelineEventSourceIds(openEvent)).toEqual([openUsesId]);
        await elUpdate(testContext, openEvent._index, openEvent.internal_id, {
          doc: { element_access: { ...openEvent.element_access, sources: [{ id: restrictedUsesId, restricted_members: [], granted: [] }] } },
        });
        await importAsEditor(annotationOf(openTechnique, 'Confirmed by the editor'));
        expect(await techniqueEvent(openTechnique.id)).toMatchObject({ pinned: false, annotation: null });
        // Recorded with its actual source again by that regeneration, the event is read by the editor and the annotation applies
        await importAsEditor(annotationOf(openTechnique, 'Confirmed by the editor'));
        expect(await techniqueEvent(openTechnique.id)).toMatchObject({ pinned: true, annotation: 'Confirmed by the editor' });
      } finally {
        await queryAsAdmin({ query: STIX_CORE_OBJECT_DELETE, variables: { id: caseId } });
        await queryAsAdmin({ query: STIX_CORE_RELATIONSHIP_DELETE, variables: { id: restrictedUsesId } });
        await queryAsAdmin({ query: STIX_CORE_RELATIONSHIP_DELETE, variables: { id: openUsesId } });
        await queryAsAdmin({ query: STIX_CORE_OBJECT_DELETE, variables: { id: restrictedTechnique.id } });
        await queryAsAdmin({ query: STIX_CORE_OBJECT_DELETE, variables: { id: openTechnique.id } });
        await queryAsAdmin({ query: STIX_CORE_OBJECT_DELETE, variables: { id: sourceMalwareId } });
        await deleteContainerTimeline(caseId);
      }
    });

    it('should not answer from a container deleted while its first timeline was being built', async () => {
      const created = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_ADD, variables: { input: { name: 'Timeline case deleted during its first opening' } } });
      const caseId = created.data.caseIncidentAdd.id;
      type LoadedCase = { _index: string };
      const loaded = await internalLoadById(testContext, SYSTEM_USER, caseId) as unknown as LoadedCase;
      // Never opened: the first read builds its timeline
      await elUpdate(testContext, loaded._index, caseId, { doc: { x_opencti_timeline_anchors: null } });
      const regenerate = timelineEngine.regenerateContainerTimeline;
      const generation = vi.spyOn(timelineEngine, 'regenerateContainerTimeline').mockImplementationOnce(async (...args) => {
        const result = await regenerate(...args);
        // The container goes away while the reader waits for the generation
        await queryAsAdminWithSuccess({ query: STIX_CORE_OBJECT_DELETE, variables: { id: caseId } });
        return result;
      });
      try {
        const result = await queryAsAdmin({ query: CONTAINER_TIMELINE_SUMMARY, variables: { id: caseId } });
        expect(generation).toHaveBeenCalled();
        expect(result.data?.containerTimelineSummary ?? null).toBeNull();
        expect(result.errors?.[0]?.message).toContain('Timeline container cannot be found');
      } finally {
        generation.mockRestore();
      }
    });

    it('should leave out a manual event about an element restricted to fewer members than the container', async () => {
      const restrictedCase = await createEntity(testContext, SYSTEM_USER, {
        name: 'Timeline restricted request',
        authorized_members: [{ id: ADMIN_USER.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }],
      }, ENTITY_TYPE_CONTAINER_CASE_RFI);
      const added = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T17:00:00.000Z', title: 'Restricted request answered', element_id: restrictedCase.id, confidence: 60 } },
      });
      // Within the max confidence of the user, the confidence is kept as given
      expect(added.data.timelineEventAdd.confidence).toEqual(60);
      const result = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_STIX, variables: { id: caseIncident.id } });
      const extension = JSON.parse(result.data.caseIncident.toStix).extensions[STIX_EXT_OCTI_TIMELINE];
      // Its title and description speak about the element: the event stays local, not only its reference
      expect(extension.events.map((e: { title: string }) => e.title)).not.toContain('Restricted request answered');
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: added.data.timelineEventAdd.id } });
      await deleteElementById(testContext, SYSTEM_USER, restrictedCase.id, ENTITY_TYPE_CONTAINER_CASE_RFI);
    });
  });

  describe('timeline manager', () => {
    it('should regenerate the cases referenced by a new note', async () => {
      const note = await queryAsAdminWithSuccess({
        query: NOTE_ADD,
        variables: { input: { attribute_abstract: 'Timeline note', content: 'Lateral movement confirmed', created: '2026-02-05T09:00:00.000Z', objects: [caseIncident.id] } },
      });
      noteId = note.data.noteAdd.id;
      const stixNote = {
        id: note.data.noteAdd.standard_id,
        type: 'note',
        object_refs: [caseIncident.standard_id],
        extensions: { [STIX_EXT_OCTI]: { id: noteId, type: 'Note' } },
      };
      await timelineStreamEventsHandler(testContext, [streamEvent(stixNote)]);
      await processDueTimelineRegenerations(testContext);
      const notes = await listTimeline(caseIncident.id, { kinds: ['note_added'] });
      expect(notes).toHaveLength(1);
      expect(notes[0]).toMatchObject({ element_id: noteId, lane: 'response', event_time: '2026-02-05T09:00:00.000Z' });
    });

    it('should queue the cases containing a technique whose kill chain phase changed', async () => {
      const stixPhase = { id: 'kill-chain-phase--5d5f0a52-30b1-5d2c-9a8e-0f0c1d2e3f40', type: 'kill-chain-phase', extensions: { [STIX_EXT_OCTI]: { id: killChainPhaseId, type: 'Kill-Chain-Phase' } } };
      await timelineStreamEventsHandler(testContext, [streamEvent(stixPhase)]);
      const { containerIds: claimed, lease } = await claimDueTimelineRegenerations(1000);
      expect(claimed).toContain(caseIncident.id);
      // Handed back to the queue for the tests that follow
      await Promise.all(claimed.map((id) => acknowledgeTimelineRegeneration(id, lease)));
      await enqueueTimelineRegeneration(claimed, 0);
    });

    it('should queue the containers citing an external reference that changed', async () => {
      const reference = await queryAsAdminWithSuccess({
        query: EXTERNAL_REFERENCE_ADD,
        variables: { input: { source_name: 'Timeline advisory', url: 'https://timeline.example/advisory', external_id: 'TL-ADV-1' } },
      });
      const referenceId = reference.data.externalReferenceAdd.id;
      const citing = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_ADD, variables: { input: { name: 'Timeline cited case', externalReferences: [referenceId] } } });
      const citingId = citing.data.caseIncidentAdd.id;
      const stixReference = { id: reference.data.externalReferenceAdd.standard_id, type: 'external-reference', extensions: { [STIX_EXT_OCTI]: { id: referenceId, type: 'External-Reference' } } };
      await timelineStreamEventsHandler(testContext, [streamEvent(stixReference)]);
      const { containerIds: claimed, lease } = await claimDueTimelineRegenerations(1000);
      expect(claimed).toContain(citingId);
      // The other containers are handed back to the queue for the tests that follow
      await Promise.all(claimed.map((id) => acknowledgeTimelineRegeneration(id, lease)));
      await enqueueTimelineRegeneration(claimed.filter((id) => id !== citingId), 0);
      await queryAsAdminWithSuccess({ query: STIX_CORE_OBJECT_DELETE, variables: { id: citingId } });
      await queryAsAdminWithSuccess({ query: EXTERNAL_REFERENCE_DELETE, variables: { id: referenceId } });
    });

    it('should queue the case of a manual event about an element the case does not contain', async () => {
      const outside = await queryAsAdminWithSuccess({ query: MALWARE_ADD, variables: { input: { name: 'Timeline malware outside the case' } } });
      const outsideId = outside.data.malwareAdd.id;
      const milestone = await queryAsAdminWithSuccess({
        query: TIMELINE_EVENT_ADD,
        variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T22:00:00.000Z', title: 'Related campaign spotted', element_id: outsideId } },
      });
      // The regenerations scheduled by the addition are handled first: only the change of the element is left to queue the case
      const { containerIds: pending, lease: pendingLease } = await claimDueTimelineRegenerations(1000);
      await Promise.all(pending.map((id) => acknowledgeTimelineRegeneration(id, pendingLease)));
      const others = pending.filter((id) => id !== caseIncident.id);
      const stixMalware = { id: outside.data.malwareAdd.standard_id, type: 'malware', extensions: { [STIX_EXT_OCTI]: { id: outsideId, type: 'Malware' } } };
      await timelineStreamEventsHandler(testContext, [streamEvent(stixMalware)]);
      const { containerIds: claimed, lease } = await claimDueTimelineRegenerations(1000);
      expect(claimed).toContain(caseIncident.id);
      // Every container is handed back to the queue for the tests that follow
      await Promise.all(claimed.map((id) => acknowledgeTimelineRegeneration(id, lease)));
      await enqueueTimelineRegeneration([...others, ...claimed], 0);
      // The regeneration then refreshes the access of the element on the event: its new marking, and its access beyond markings
      const amber = await internalLoadById(testContext, SYSTEM_USER, MARKING_TLP_AMBER);
      await createRelation(testContext, SYSTEM_USER, { fromId: outsideId, toId: amber.internal_id, relationship_type: RELATION_OBJECT_MARKING });
      await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      const refreshed = (await loadStoredTimelineEvents(testContext, caseIncident.id)).find((event) => event.internal_id === milestone.data.timelineEventAdd.id);
      expect(refreshed?.[`rel_${RELATION_OBJECT_MARKING}.internal_id`]).toContain(amber.internal_id);
      expect(refreshed?.element_access).toEqual({ restricted_members: [], granted: [] });
      await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: milestone.data.timelineEventAdd.id } });
      await queryAsAdminWithSuccess({ query: STIX_CORE_OBJECT_DELETE, variables: { id: outsideId } });
    });

    it('should queue the case of an investigation finding about an element the case does not contain', async () => {
      const outside = await queryAsAdminWithSuccess({ query: MALWARE_ADD, variables: { input: { name: 'Timeline malware found by an investigation' } } });
      const outsideId = outside.data.malwareAdd.id;
      // A finding outside the case, stored the way the investigation-run rule derives it
      const discriminator = `investigation-run-finding-${outsideId}-first_seen`;
      await elIndexElements(testContext, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [buildTimelineEventDoc({
        internal_id: computeDerivedEventId(caseIncident.id, RULE_INVESTIGATION_RUN, `${outsideId}|${discriminator}`, 'investigation_step'),
        container_id: caseIncident.id,
        name: 'Timeline malware found by an investigation first seen',
        event_time: '2026-02-05T21:00:00.000Z',
        time_precision: 'approximate',
        lane: 'evidence',
        kind: 'investigation_step',
        event_source: 'derived',
        rule_id: RULE_INVESTIGATION_RUN,
        element_id: outsideId,
        element_type: 'Malware',
        pinned: false,
        hidden: false,
        analyst_fields: [],
        markings: [],
        creator_ids: [],
        restricted_members: [],
      })]);
      const { containerIds: pending, lease: pendingLease } = await claimDueTimelineRegenerations(1000);
      await Promise.all(pending.map((id) => acknowledgeTimelineRegeneration(id, pendingLease)));
      const stixMalware = { id: outside.data.malwareAdd.standard_id, type: 'malware', extensions: { [STIX_EXT_OCTI]: { id: outsideId, type: 'Malware' } } };
      await timelineStreamEventsHandler(testContext, [streamEvent(stixMalware)]);
      const { containerIds: claimed, lease } = await claimDueTimelineRegenerations(1000);
      expect(claimed).toContain(caseIncident.id);
      // Every container is handed back to the queue for the tests that follow
      await Promise.all(claimed.map((id) => acknowledgeTimelineRegeneration(id, lease)));
      await enqueueTimelineRegeneration([...pending, ...claimed], 0);
      // No investigation run of the case derives the finding: the regeneration removes it again
      await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      const remaining = await loadStoredTimelineEvents(testContext, caseIncident.id);
      expect(remaining.some((event) => event.element_id === outsideId)).toBe(false);
      await queryAsAdminWithSuccess({ query: STIX_CORE_OBJECT_DELETE, variables: { id: outsideId } });
    });

    it('should queue the case of a manual event about a label or an external reference the case does not use', async () => {
      const label = await queryAsAdminWithSuccess({ query: LABEL_ADD, variables: { input: { value: 'timeline-regulator-filing', color: '#00bcd4' } } });
      const reference = await queryAsAdminWithSuccess({
        query: EXTERNAL_REFERENCE_ADD,
        variables: { input: { source_name: 'Timeline regulator portal', url: 'https://timeline.example/regulator', external_id: 'TL-REG-1' } },
      });
      const metaElements = [
        { id: label.data.labelAdd.id, stix: { id: label.data.labelAdd.standard_id, type: 'label', extensions: { [STIX_EXT_OCTI]: { id: label.data.labelAdd.id, type: 'Label' } } } },
        {
          id: reference.data.externalReferenceAdd.id,
          stix: { id: reference.data.externalReferenceAdd.standard_id, type: 'external-reference', extensions: { [STIX_EXT_OCTI]: { id: reference.data.externalReferenceAdd.id, type: 'External-Reference' } } },
        },
      ];
      for (let index = 0; index < metaElements.length; index += 1) {
        const { id, stix } = metaElements[index];
        const milestone = await queryAsAdminWithSuccess({
          query: TIMELINE_EVENT_ADD,
          variables: { input: { container_id: caseIncident.id, event_time: '2026-02-05T23:00:00.000Z', title: `Regulator filing ${index}`, element_id: id } },
        });
        // The regenerations scheduled by the addition are handled first: only the change of the element is left to queue the case
        const { containerIds: pending, lease: pendingLease } = await claimDueTimelineRegenerations(1000);
        await Promise.all(pending.map((containerId) => acknowledgeTimelineRegeneration(containerId, pendingLease)));
        await timelineStreamEventsHandler(testContext, [streamEvent(stix)]);
        const { containerIds: claimed, lease } = await claimDueTimelineRegenerations(1000);
        expect(claimed).toContain(caseIncident.id);
        // Every container is handed back to the queue for the tests that follow
        await Promise.all(claimed.map((containerId) => acknowledgeTimelineRegeneration(containerId, lease)));
        await enqueueTimelineRegeneration([...pending, ...claimed], 0);
        await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: milestone.data.timelineEventAdd.id } });
      }
      await queryAsAdminWithSuccess({ query: LABEL_DELETE, variables: { id: label.data.labelAdd.id } });
      await queryAsAdminWithSuccess({ query: EXTERNAL_REFERENCE_DELETE, variables: { id: reference.data.externalReferenceAdd.id } });
    });

    it('should queue the case of a manual event whose author changed', async () => {
      // The milestone "Regulator notified" of the case is authored by this organization, which the case does not contain
      const author = await internalLoadById(testContext, SYSTEM_USER, TEST_ORGANIZATION.id);
      const { containerIds: pending, lease: pendingLease } = await claimDueTimelineRegenerations(1000);
      await Promise.all(pending.map((id) => acknowledgeTimelineRegeneration(id, pendingLease)));
      const stixAuthor = { id: author.standard_id, type: 'identity', extensions: { [STIX_EXT_OCTI]: { id: author.internal_id, type: 'Organization' } } };
      await timelineStreamEventsHandler(testContext, [streamEvent(stixAuthor)]);
      const { containerIds: claimed, lease } = await claimDueTimelineRegenerations(1000);
      expect(claimed).toContain(caseIncident.id);
      // Every container is handed back to the queue for the tests that follow
      await Promise.all(claimed.map((id) => acknowledgeTimelineRegeneration(id, lease)));
      await enqueueTimelineRegeneration([...pending, ...claimed], 0);
    });

    it('should keep a container scheduled again during its regeneration queued until the running claim is acknowledged', async () => {
      const containerId = `timeline-queue-${Date.now()}`;
      // The other due containers are handed back to the queue for the tests that follow
      // Returns the lease of the claim of the container, null when it was not handed out
      const claimOnly = async () => {
        const { containerIds: claimed, lease } = await claimDueTimelineRegenerations(1000);
        const others = claimed.filter((id) => id !== containerId);
        await Promise.all(others.map((id) => acknowledgeTimelineRegeneration(id, lease)));
        await enqueueTimelineRegeneration(others, 0);
        return claimed.includes(containerId) ? lease : null;
      };
      await enqueueTimelineRegeneration([containerId], 0);
      const lease = await claimOnly();
      expect(lease).not.toBeNull();
      await enqueueTimelineRegeneration([containerId], 0);
      expect(await claimOnly()).toBeNull();
      expect(await acknowledgeTimelineRegeneration(containerId, lease as number)).toBe(true);
      const nextLease = await claimOnly();
      expect(nextLease).not.toBeNull();
      expect(await acknowledgeTimelineRegeneration(containerId, nextLease as number)).toBe(true);
    });

    it('should drop the timeline of a deleted container', async () => {
      await queryAsAdminWithSuccess({ query: STIX_CORE_OBJECT_DELETE, variables: { id: secondCase.id } });
      const stixCase = { id: secondCase.standard_id, type: 'case-incident', extensions: { [STIX_EXT_OCTI]: { id: secondCase.id, type: 'Case-Incident' } } };
      await timelineStreamEventsHandler(testContext, [streamEvent(stixCase)]);
      await processDueTimelineRegenerations(testContext);
      expect(await loadStoredTimelineEvents(testContext, secondCase.id)).toHaveLength(0);
    });

    it('should delete a manual event', async () => {
      const deleted = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_DELETE, variables: { id: manualEventId } });
      expect(deleted.data.timelineEventDelete).toEqual(manualEventId);
      const anchors = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      expect(anchors.data.timelineAnchors.containment).toBeNull();
    });
  });
});
