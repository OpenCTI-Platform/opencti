import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { testContext, USER_EDITOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { MARKING_TLP_AMBER } from '../../../src/schema/identifier';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_TIMELINE } from '../../../src/types/stix-2-1-extensions';
import { deleteContainerTimeline, loadStoredTimelineEvents } from '../../../src/modules/timeline/timeline-engine';
import { processDueTimelineRegenerations, timelineStreamEventsHandler } from '../../../src/manager/timelineManager';
import type { DataEvent, SseEvent } from '../../../src/types/event';

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
  ordering_hint
  external_id
  analyst_fields
  editable
  objectMarking { id }
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
      first: $first
    ) {
      pageInfo { globalCount }
      edges { node { ${TIMELINE_EVENT_FIELDS} } }
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
  query ContainerTimelineExport($id: String!, $format: TimelineExportFormat!, $labels: [TimelineExportLabelInput!]) {
    containerTimelineExport(id: $id, format: $format, labels: $labels)
  }
`;
const TIMELINE_EVENT = gql`
  query TimelineEvent($id: String!) {
    timelineEvent(id: $id) { ${TIMELINE_EVENT_FIELDS} }
  }
`;
const TIMELINE_ANCHORS = gql`
  query TimelineAnchors($containerId: String!) {
    timelineAnchors(containerId: $containerId) { first_adversary_activity first_detection first_response containment closure computed_at }
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
}

const ADVERSARY_START = '2026-02-01T08:00:00.000Z';
const ADVERSARY_STOP = '2026-02-03T18:00:00.000Z';
const CONTAINMENT_TIME = '2026-02-05T10:30:00.000Z';

const listTimeline = async (id: string, variables: Record<string, unknown> = {}): Promise<TimelineEventNode[]> => {
  const result = await queryAsAdminWithSuccess({ query: CONTAINER_TIMELINE, variables: { id, first: 500, ...variables } });
  return result.data.containerTimeline.edges.map((edge: { node: TimelineEventNode }) => edge.node);
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

    it('should be idempotent: a second regeneration rewrites nothing and keeps the ids', async () => {
      const before = await listTimeline(caseIncident.id);
      const result = await queryAsAdminWithSuccess({ query: TIMELINE_REGENERATE, variables: { containerId: caseIncident.id } });
      expect(result.data.timelineRegenerate).toMatchObject({ created_count: 0, updated_count: 0, deleted_count: 0 });
      const after = await listTimeline(caseIncident.id);
      expect(after.map((e) => e.id).sort()).toEqual(before.map((e) => e.id).sort());
    });

    it('should compute the anchors and expose them on the container', async () => {
      const anchors = await queryAsAdminWithSuccess({ query: TIMELINE_ANCHORS, variables: { containerId: caseIncident.id } });
      expect(anchors.data.timelineAnchors.first_adversary_activity).toEqual(ADVERSARY_START);
      expect(anchors.data.timelineAnchors.first_response).toEqual('2026-02-04T12:00:00.000Z');
      expect(anchors.data.timelineAnchors.containment).toBeNull();
      expect(anchors.data.timelineAnchors.computed_at).toBeDefined();
      const stix = await queryAsAdminWithSuccess({ query: CASE_INCIDENT_STIX, variables: { id: caseIncident.id } });
      expect(stix.data.caseIncident.x_opencti_timeline_anchors.first_adversary_activity).toEqual(ADVERSARY_START);
    });

    it('should list the derivation rules with their availability', async () => {
      const result = await queryAsAdminWithSuccess({ query: TIMELINE_RULES, variables: {} });
      const rules = result.data.timelineRules as Array<{ id: string; available: boolean; kinds: string[] }>;
      expect(rules.find((r) => r.id === 'technique-kill-chain')).toMatchObject({ available: true, kinds: ['technique_used'] });
      expect(rules.find((r) => r.id === 'security-coverage-result')?.available).toBe(true);
      expect(rules.map((r) => r.id)).toEqual(expect.arrayContaining(['hunt-run', 'indicator-deployment', 'autopilot-run']));
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
      expect(anchors.data.timelineAnchors.containment).toEqual(CONTAINMENT_TIME);
    });

    it('should be idempotent on the external id of a manual event', async () => {
      const input = { container_id: caseIncident.id, event_time: '2026-02-05T12:00:00.000Z', title: 'Regulator notified', kind: 'notification', external_id: 'splunk-alert-42' };
      const first = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input } });
      const second = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_ADD, variables: { input: { ...input, title: 'Regulator notified (CNIL)' } } });
      expect(second.data.timelineEventAdd.id).toEqual(first.data.timelineEventAdd.id);
      expect(second.data.timelineEventAdd).toMatchObject({ title: 'Regulator notified (CNIL)', external_id: 'splunk-alert-42' });
      const manual = await listTimeline(caseIncident.id, { sources: ['manual'] });
      expect(manual).toHaveLength(2);
    });

    it('should edit a manual event and validate its window', async () => {
      const edited = await queryAsAdminWithSuccess({ query: TIMELINE_EVENT_EDIT, variables: { id: manualEventId, input: { title: 'Hosts isolated by the SOC', annotation: 'Confirmed by the EDR console' } } });
      expect(edited.data.timelineEventEdit).toMatchObject({ title: 'Hosts isolated by the SOC', annotation: 'Confirmed by the EDR console' });
      await queryAsAdminWithError(
        { query: TIMELINE_EVENT_EDIT, variables: { id: manualEventId, input: { event_end_time: '2026-01-01T00:00:00.000Z' } } },
        'The end time of an event must be after its start time',
      );
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
        'A derived event can only be annotated, pinned or hidden',
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
      expect(summary.first_event_time).toEqual(ADVERSARY_START);
      // The only knowledge event (the relationship) is hidden
      expect(summary.lanes.map((l: { lane: string }) => l.lane).sort()).toEqual(['adversary', 'evidence', 'response']);
      expect(summary.anchors.containment).toEqual(CONTAINMENT_TIME);
      expect(summary.settings).toMatchObject({ default_grouping: 'day', default_zoom_window: 'fit' });
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

    it('should only export what the exporting user can see', async () => {
      const csv = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: CONTAINER_TIMELINE_EXPORT, variables: { id: caseIncident.id, format: 'csv' } });
      expect(csv.data.containerTimelineExport).not.toContain('Timeline amber indicator');
    });

    it('should update the settings of the timeline', async () => {
      const result = await queryAsAdminWithSuccess({
        query: TIMELINE_SETTINGS_UPDATE,
        variables: { containerId: caseIncident.id, input: { enabled_lanes: ['adversary', 'response', 'adversary'], default_grouping: 'week', hidden_kinds: ['relation_created'] } },
      });
      expect(result.data.timelineSettingsUpdate).toMatchObject({ enabled_lanes: ['adversary', 'response'], default_grouping: 'week', default_zoom_window: 'fit', hidden_kinds: ['relation_created'] });
      await queryAsAdminWithError({ query: TIMELINE_SETTINGS_UPDATE, variables: { containerId: caseIncident.id, input: { enabled_lanes: [] } } }, 'At least one lane must be enabled');
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
      const imported = await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
      expect(imported.data.timelineImport.manual_count).toEqual(2);
      const again = await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension } });
      expect(again.data.timelineImport.manual_count).toEqual(2);
      const pinnedOnly = await listTimeline(secondCase.id, { pinnedOnly: true });
      expect(pinnedOnly).toHaveLength(1);
      expect(pinnedOnly[0]).toMatchObject({ kind: 'malware_seen', element_id: malware.id, annotation: 'Initial dropper' });
      // Coming back to the platform it was exported from, an event updates itself
      const back = await queryAsAdminWithSuccess({ query: TIMELINE_IMPORT, variables: { containerId: caseIncident.id, extension } });
      expect(back.data.timelineImport.manual_count).toEqual(2);
    });

    it('should reject an invalid extension', async () => {
      await queryAsAdminWithError({ query: TIMELINE_IMPORT, variables: { containerId: secondCase.id, extension: 'not json' } }, 'Invalid timeline extension');
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
