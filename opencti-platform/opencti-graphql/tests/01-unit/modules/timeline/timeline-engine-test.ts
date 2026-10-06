import { describe, expect, it } from 'vitest';
import {
  buildContainerMarkingCoverage,
  buildTimelineEventDoc,
  computeDerivedEventId,
  computeManualEventId,
  createConcurrencyLimiter,
  getTimelineRules,
  isPendingAnnotationApplicable,
  isPortableDerivedEvent,
  isTimelineElementChangeWidening,
  isTimelineEventAccessChanged,
  isTimelineRefreshForEveryReader,
  keptAnalystFields,
  markingsOf,
  recordedTimelineReference,
  type StoredTimelineEvent,
  type TimelineReadableEvent,
  timelineCappedAnnotatedEventAsStored,
  timelineCappedAnnotatedEvents,
  timelineEventMarkings,
  timelineEventMaxConfidence,
  timelineEventSignature,
  timelineEventSourceIds,
  timelineEventStandardId,
  timelineExchangeAnnotation,
  timelineRuleFamily,
} from '../../../../src/modules/timeline/timeline-engine';
import type { AuthUser } from '../../../../src/types/user';
import { buildTimelineFilters, collectTimelineExportPages, latestTimelineTime, strongerTimelineConfidence } from '../../../../src/modules/timeline/timeline-domain';
import { buildStixTimelineExtension, sanitizeTimelineExtension } from '../../../../src/modules/timeline/timeline-extension';
import { RULE_TASK_CONTAINMENT, RULE_WORKFLOW_CLOSURE } from '../../../../src/modules/timeline/timeline-rules';
import { ENTITY_TYPE_TIMELINE_EVENT, TIMELINE_KINDS } from '../../../../src/modules/timeline/timeline-types';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_INCIDENT } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { buildRefRelationKey } from '../../../../src/schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { TimelineEventKind } from '../../../../src/generated/graphql';
import { prepareElementForIndexing } from '../../../../src/database/engine';
import '../../../../src/modules/index';

describe('Timeline event identity', () => {
  it('should compute deterministic derived ids so that regeneration is idempotent', () => {
    const first = computeDerivedEventId('case-1', 'technique-kill-chain', 'ap-1', 'technique_used');
    expect(computeDerivedEventId('case-1', 'technique-kill-chain', 'ap-1', 'technique_used')).toEqual(first);
    expect(computeDerivedEventId('case-2', 'technique-kill-chain', 'ap-1', 'technique_used')).not.toEqual(first);
    expect(computeDerivedEventId('case-1', 'technique-kill-chain', 'ap-2', 'technique_used')).not.toEqual(first);
    expect(timelineEventStandardId(first)).toEqual(`timeline-event--${first}`);
  });

  it('should keep the id of an event when its rule is refined (containment task, closure status)', () => {
    expect(timelineRuleFamily(RULE_TASK_CONTAINMENT)).toEqual('task-lifecycle');
    expect(timelineRuleFamily(RULE_WORKFLOW_CLOSURE)).toEqual('workflow-status');
    expect(computeDerivedEventId('case-1', RULE_TASK_CONTAINMENT, 'task-1', 'task_completed'))
      .toEqual(computeDerivedEventId('case-1', 'task-lifecycle', 'task-1', 'task_completed'));
  });

  it('should only exchange the contributions of derived events another platform can recompute', () => {
    const knowledgeEvent = { internal_id: computeDerivedEventId('case-1', 'entity-first-last-seen', 'malware-1', 'malware_seen'), rule_id: 'entity-first-last-seen', element_id: 'malware-1', kind: 'malware_seen' as const };
    expect(isPortableDerivedEvent('case-1', knowledgeEvent)).toBe(true);
    // Identified by a local run or history entry: no receiving platform holds it
    const runEvent = { internal_id: computeDerivedEventId('case-1', 'hunt-runs', 'hunt-1|run-1', 'hunt_run'), rule_id: 'hunt-runs', element_id: 'hunt-1', kind: 'hunt_run' as const };
    expect(isPortableDerivedEvent('case-1', runEvent)).toBe(false);
    expect(isPortableDerivedEvent('case-1', { ...knowledgeEvent, element_id: null })).toBe(false);
  });

  it('should compute idempotent ids for manual events with an external id', () => {
    expect(computeManualEventId('case-1', 'regulator-notified')).toEqual(computeManualEventId('case-1', 'regulator-notified'));
    expect(computeManualEventId('case-1', 'regulator-notified')).not.toEqual(computeManualEventId('case-2', 'regulator-notified'));
  });
});

describe('Timeline event documents', () => {
  const input = {
    internal_id: 'event-1',
    container_id: 'case-1',
    name: 'Technique Phishing',
    event_time: '2026-03-01T00:00:00.000Z',
    time_precision: 'exact',
    lane: 'adversary',
    kind: 'technique_used',
    event_source: 'derived' as const,
    rule_id: 'technique-kill-chain',
    element_id: 'ap-1',
    element_type: 'Attack-Pattern',
    pinned: false,
    hidden: false,
    analyst_fields: [],
    markings: ['m1', 'm2', 'm1'],
    creator_ids: [],
    restricted_members: [],
  };

  it('should build an internal object document with denormalized access fields', () => {
    const doc = buildTimelineEventDoc(input);
    expect(doc.entity_type).toEqual(ENTITY_TYPE_TIMELINE_EVENT);
    expect(doc.standard_id).toEqual('timeline-event--event-1');
    expect(doc.parent_types).toContain('Internal-Object');
    expect(doc['rel_object-marking.internal_id']).toEqual(['m1', 'm2']);
    expect(doc['rel_created-by.internal_id']).toEqual([]);
  });

  it('should only consider content fields in the signature', () => {
    const doc = buildTimelineEventDoc(input);
    const later = { ...buildTimelineEventDoc(input), updated_at: '2030-01-01T00:00:00.000Z', created_at: '2030-01-01T00:00:00.000Z' };
    expect(timelineEventSignature(later)).toEqual(timelineEventSignature(doc));
    const reordered = { ...doc, 'rel_object-marking.internal_id': ['m2', 'm1'], event_time: new Date('2026-03-01T00:00:00.000Z') };
    expect(timelineEventSignature(reordered)).toEqual(timelineEventSignature(doc));
    expect(timelineEventSignature({ ...doc, pinned: true })).not.toEqual(timelineEventSignature(doc));
  });

  it('should sign a closed window like it is indexed and like the events stored before the open end existed', async () => {
    const doc = buildTimelineEventDoc(input);
    expect(doc.open_ended).toBe(false);
    const indexed = await prepareElementForIndexing(doc);
    expect(indexed.open_ended).toBe(false);
    expect(timelineEventSignature(indexed)).toEqual(timelineEventSignature(doc));
    expect(timelineEventSignature(buildTimelineEventDoc({ ...input, open_ended: null }))).toEqual(timelineEventSignature(doc));
    const { open_ended: _, ...storedBefore } = doc;
    expect(timelineEventSignature(storedBefore)).toEqual(timelineEventSignature(doc));
    const open = buildTimelineEventDoc({ ...input, open_ended: true });
    expect(open.open_ended).toBe(true);
    expect((await prepareElementForIndexing(open)).open_ended).toBe(true);
    expect(timelineEventSignature(open)).not.toEqual(timelineEventSignature(doc));
  });
});

describe('Timeline read filters', () => {
  it('should hide hidden events and apply the requested filters', () => {
    const filters = buildTimelineFilters('case-1', { lanes: ['adversary'], kinds: ['sighting'], sources: ['manual'], markings: ['m1'], search: ' phishing ', pinnedOnly: true, from: '2026-03-01T00:00:00.000Z', to: '2026-03-31T00:00:00.000Z' });
    const keys = filters.filters.map((f: any) => f.key.join(','));
    expect(keys).toEqual(['container_id', 'lane', 'kind', 'event_source', 'objectMarking', 'hidden', 'pinned', 'event_time', 'name,description,annotation']);
    expect(filters.filters.find((f: any) => f.key[0] === 'hidden')).toMatchObject({ operator: 'not_eq' });
    expect(filters.filters.find((f: any) => f.key[0] === 'name')).toMatchObject({ values: ['phishing'], operator: 'search' });
    expect(filters.filterGroups).toHaveLength(1);
    // From the start of the window: events starting in it, windows still running at its start, and windows with no known end
    expect(filters.filterGroups[0].filters.map((f: any) => f.key[0])).toEqual(['event_time', 'event_end_time', 'open_ended']);
    expect(filters.filterGroups[0].filters[2]).toMatchObject({ values: ['true'] });
  });

  it('should include hidden events when requested', () => {
    const filters = buildTimelineFilters('case-1', { includeHidden: true });
    expect(filters.filters.map((f: any) => f.key[0])).toEqual(['container_id']);
  });
});

describe('Timeline summary range', () => {
  it('should end the range at the latest start or end time, whichever is later', () => {
    // A window starting earlier but ending after the latest event start extends the range
    expect(latestTimelineTime('2026-03-10T00:00:00.000Z', '2026-03-20T00:00:00.000Z')).toEqual('2026-03-20T00:00:00.000Z');
    expect(latestTimelineTime('2026-03-10T00:00:00.000Z', '2026-03-05T00:00:00.000Z')).toEqual('2026-03-10T00:00:00.000Z');
    expect(latestTimelineTime('2026-03-10T00:00:00.000Z', null)).toEqual('2026-03-10T00:00:00.000Z');
    expect(latestTimelineTime(undefined, '2026-03-20T00:00:00.000Z')).toEqual('2026-03-20T00:00:00.000Z');
    expect(latestTimelineTime(null, undefined)).toBeNull();
  });
});

describe('Timeline schema registration', () => {
  it('should register the timeline types and the anchors on every timeline container', () => {
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_TIMELINE_EVENT, 'event_time')).toBeDefined();
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_TIMELINE_EVENT, 'time_precision')).toBeDefined();
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, 'x_opencti_timeline_anchors')).toBeDefined();
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_INCIDENT, 'x_opencti_timeline')).toBeDefined();
  });

  it('should keep the GraphQL kinds and the model kinds aligned', () => {
    expect([...TIMELINE_KINDS].sort()).toEqual(Object.values(TimelineEventKind).sort());
  });

  it('should declare every rule with its kinds', () => {
    const rules = getTimelineRules();
    expect(new Set(rules.map((r) => r.id)).size).toEqual(rules.length);
    rules.forEach((rule) => expect(rule.kinds.length).toBeGreaterThan(0));
    // soft-check rules expose their availability
    expect(rules.filter((r) => r.isAvailable).map((r) => r.id)).toEqual(['security-coverage-result', 'hunt-run', 'indicator-deployment', 'investigation-run']);
  });
});

describe('Timeline STIX extension', () => {
  const IMPORT_LIMITS = { maxEvents: 100, maxAnnotations: 100 };

  it('should only exist when there are analyst contributions', () => {
    expect(buildStixTimelineExtension(undefined)).toBeUndefined();
    expect(buildStixTimelineExtension({ events: [], annotations: [] })).toBeUndefined();
    const extension = buildStixTimelineExtension({
      events: [{ id: 'timeline-event--1', event_time: '2026-03-05T00:00:00.000Z', precision: 'exact', lane: 'custom', kind: 'containment', title: 'Hosts isolated', description: undefined }],
      annotations: [{ rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: 'attack-pattern--1', pinned: true }],
    });
    expect(extension?.extension_type).toEqual('property-extension');
    expect(extension?.events[0]).not.toHaveProperty('description');
    expect(extension?.annotations[0]).toMatchObject({ pinned: true });
  });

  it('should keep valid imported contributions unchanged', () => {
    const event = {
      id: 'timeline-event--1',
      external_id: 'splunk:1',
      event_time: '2026-03-05T00:00:00.000Z',
      event_end_time: '2026-03-06T00:00:00.000Z',
      precision: 'day',
      lane: 'detection',
      kind: 'containment',
      title: 'Hosts isolated',
      description: 'EDR isolation',
      element_ref: 'indicator--1',
      confidence: 80,
      ordering_hint: 2,
      pinned: true,
      hidden: false,
      annotation: 'Confirmed',
      object_marking_refs: ['marking-definition--1'],
      created_by_ref: 'identity--1',
    };
    const annotation = { rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: 'attack-pattern--1', pinned: true, ordering_hint: 1 };
    const result = sanitizeTimelineExtension({ extension_type: 'property-extension', events: [event], annotations: [annotation] }, IMPORT_LIMITS);
    expect(result).toEqual({ events: [event], annotations: [annotation], dropped: 0, normalized: 0 });
  });

  it('should map unknown enum values to safe defaults and drop malformed values on import', () => {
    const result = sanitizeTimelineExtension({
      events: [
        { id: 'timeline-event--1', event_time: '2026-03-05T00:00:00.000Z', title: 'Defaults' },
        {
          id: 'timeline-event--2',
          event_time: '2026-03-05T00:00:00.000Z',
          event_end_time: '2026-03-01T00:00:00.000Z',
          precision: 'minute',
          lane: 'future-lane',
          kind: 'future_kind',
          title: 'x'.repeat(600),
          confidence: 150,
          ordering_hint: 1.5,
          pinned: 'yes',
          object_marking_refs: ['marking-definition--1', 42],
        },
      ],
      annotations: [],
    }, IMPORT_LIMITS);
    expect(result.dropped).toEqual(0);
    expect(result.events[0]).toMatchObject({ precision: 'exact', lane: 'custom', kind: 'milestone' });
    const normalized = result.events[1];
    expect(normalized).toMatchObject({ precision: 'approximate', lane: 'custom', kind: 'milestone', object_marking_refs: ['marking-definition--1'] });
    expect(normalized.title).toHaveLength(512);
    expect(normalized).not.toHaveProperty('event_end_time');
    expect(normalized).not.toHaveProperty('confidence');
    expect(normalized).not.toHaveProperty('ordering_hint');
    expect(normalized).not.toHaveProperty('pinned');
    // precision, lane, kind, end time, confidence, ordering hint, markings, pinned, title length
    expect(result.normalized).toEqual(9);
  });

  it('should import a window ending at its start as a point in time', () => {
    const result = sanitizeTimelineExtension({
      events: [{ id: 'timeline-event--1', event_time: '2026-03-05T00:00:00.000Z', event_end_time: '2026-03-05T00:00:00.000Z', title: 'Zero-length' }],
      annotations: [],
    }, IMPORT_LIMITS);
    expect(result.events[0]).not.toHaveProperty('event_end_time');
    expect(result.normalized).toEqual(1);
  });

  it('should drop contributions that cannot be identified, placed in time or targeted', () => {
    const result = sanitizeTimelineExtension({
      events: [
        { event_time: '2026-03-05T00:00:00.000Z', title: 'No identifier' },
        { id: 'timeline-event--1', event_time: 'not a date', title: 'Bad time' },
        { id: 'timeline-event--2', event_time: '2026-03-05T00:00:00.000Z', title: '   ' },
        'not an object',
        { external_id: 'splunk:2', event_time: '2026-03-05T00:00:00.000Z', title: 'Identified by its external id' },
      ],
      annotations: [
        { rule_id: 'technique-kill-chain', kind: 'unknown_kind', element_ref: 'attack-pattern--1' },
        { rule_id: 'technique-kill-chain', kind: 'technique_used' },
        null,
      ],
    }, IMPORT_LIMITS);
    expect(result.events.map((e) => e.id)).toEqual(['splunk:2']);
    expect(result.annotations).toEqual([]);
    expect(result.dropped).toEqual(7);
    expect(sanitizeTimelineExtension('garbage', IMPORT_LIMITS)).toEqual({ events: [], annotations: [], dropped: 0, normalized: 0 });
  });

  it('should drop an overlong external id instead of cutting it', () => {
    const sharedPrefix = 'x'.repeat(256);
    const result = sanitizeTimelineExtension({
      events: [
        { id: 'timeline-event--1', external_id: `${sharedPrefix}-a`, event_time: '2026-03-05T00:00:00.000Z', title: 'First' },
        { id: 'timeline-event--2', external_id: `${sharedPrefix}-b`, event_time: '2026-03-05T00:00:00.000Z', title: 'Second' },
        { external_id: `${sharedPrefix}-c`, event_time: '2026-03-05T00:00:00.000Z', title: 'No other identity' },
      ],
      annotations: [],
    }, IMPORT_LIMITS);
    // Each event keeps its own identity: two keys sharing their first 256 characters never collapse into one
    expect(result.events.map((e) => e.id)).toEqual(['timeline-event--1', 'timeline-event--2']);
    expect(result.events.every((e) => e.external_id === undefined)).toBe(true);
    expect(result.dropped).toEqual(1);
    expect(result.normalized).toEqual(2);
  });

  it('should name the cleared analyst fields of a derived event so that the clear travels', () => {
    const cleared = timelineExchangeAnnotation({
      rule_id: RULE_TASK_CONTAINMENT,
      kind: 'containment',
      analyst_fields: ['pinned', 'annotation', 'ordering_hint'],
      pinned: false,
      hidden: true,
      annotation: null,
      ordering_hint: null,
    }, 'x-opencti-task--1');
    // The fields the analyst never touched are left out: the receiving platform keeps its own values for them
    expect(buildStixTimelineExtension({ events: [], annotations: [cleared] })?.annotations).toEqual([{
      rule_id: 'task-lifecycle',
      kind: 'containment',
      element_ref: 'x-opencti-task--1',
      pinned: false,
      cleared_fields: ['annotation', 'ordering_hint'],
    }]);
    const set = timelineExchangeAnnotation({
      rule_id: 'technique-kill-chain',
      kind: 'technique_used',
      analyst_fields: ['annotation', 'ordering_hint'],
      pinned: false,
      hidden: false,
      annotation: 'Initial dropper',
      ordering_hint: 0,
    }, 'attack-pattern--1');
    expect(set).toMatchObject({ annotation: 'Initial dropper', ordering_hint: 0 });
    expect(set.cleared_fields).toBeUndefined();
  });

  it('should keep the cleared fields of an imported annotation, never against a value it carries', () => {
    const result = sanitizeTimelineExtension({
      annotations: [
        { rule_id: 'task-lifecycle', kind: 'containment', element_ref: 'x-opencti-task--1', cleared_fields: ['annotation', 'ordering_hint'] },
        { rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: 'attack-pattern--1', annotation: 'Kept', cleared_fields: ['annotation', 'pinned'] },
        { rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: 'attack-pattern--2', pinned: true, cleared_fields: 'annotation' },
      ],
    }, IMPORT_LIMITS);
    expect(result.annotations).toEqual([
      { rule_id: 'task-lifecycle', kind: 'containment', element_ref: 'x-opencti-task--1', cleared_fields: ['annotation', 'ordering_hint'] },
      { rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: 'attack-pattern--1', annotation: 'Kept' },
      { rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: 'attack-pattern--2', pinned: true },
    ]);
    // A field that cannot be cleared and a malformed list
    expect(result.normalized).toEqual(2);
  });

  it('should only read a bounded number of contributions', () => {
    const events = Array.from({ length: 5 }, (_, index) => ({ id: `timeline-event--${index}`, event_time: '2026-03-05T00:00:00.000Z', title: `Event ${index}` }));
    const annotations = Array.from({ length: 4 }, (_, index) => ({ rule_id: 'technique-kill-chain', kind: 'technique_used', element_ref: `attack-pattern--${index}` }));
    const result = sanitizeTimelineExtension({ events, annotations }, { maxEvents: 3, maxAnnotations: 2 });
    expect(result.events.map((e) => e.id)).toEqual(['timeline-event--0', 'timeline-event--1', 'timeline-event--2']);
    expect(result.annotations.map((a) => a.element_ref)).toEqual(['attack-pattern--0', 'attack-pattern--1']);
    expect(result.dropped).toEqual(4);
  });
});

describe('Timeline container marking coverage', () => {
  const markings = new Map([
    ['tlp-clear', { definition_type: 'TLP', x_opencti_order: 1 }],
    ['tlp-green', { definition_type: 'TLP', x_opencti_order: 2 }],
    ['tlp-amber', { definition_type: 'TLP', x_opencti_order: 3 }],
    ['tlp-red', { definition_type: 'TLP', x_opencti_order: 4 }],
    ['pap-green', { definition_type: 'PAP', x_opencti_order: 2 }],
  ]);

  it('should cover the markings of the container and the lower markings of the same type', () => {
    const covered = buildContainerMarkingCoverage(['tlp-amber'], markings);
    expect(covered('tlp-amber')).toBe(true);
    expect(covered('tlp-green')).toBe(true);
    expect(covered('tlp-clear')).toBe(true);
  });

  it('should not cover a higher marking, another marking type or an unknown marking', () => {
    const covered = buildContainerMarkingCoverage(['tlp-amber'], markings);
    expect(covered('tlp-red')).toBe(false);
    expect(covered('pap-green')).toBe(false);
    expect(covered('unknown')).toBe(false);
  });

  it('should cover nothing beyond itself for a container without markings', () => {
    const covered = buildContainerMarkingCoverage([], markings);
    expect(covered('tlp-clear')).toBe(false);
    expect(covered('tlp-green')).toBe(false);
  });
});

describe('Timeline element change and readers', () => {
  const member = (id: string, groups?: string[]) => ({ id, access_right: 'view', ...(groups ? { groups_restriction_ids: groups } : {}) });
  const element = (id: string, access: { members?: ReturnType<typeof member>[]; granted?: string[]; type?: string } = {}) => ({
    internal_id: id,
    entity_type: access.type ?? ENTITY_TYPE_INCIDENT,
    restricted_members: access.members ?? [],
    granted: access.granted ?? [],
  });
  const container = element('case-1', { type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT });

  it('should never widen an event without element, or one kept on the same element', () => {
    expect(isTimelineElementChangeWidening(container, null, element('b', { granted: ['org-2'] }), true)).toBe(false);
    const restricted = element('a', { members: [member('user-1')] });
    expect(isTimelineElementChangeWidening(container, restricted, restricted, true)).toBe(false);
  });

  it('should keep an event of an element with authorized members to elements with the same members or fewer', () => {
    const previous = element('a', { members: [member('user-1'), member('group-1')] });
    expect(isTimelineElementChangeWidening(container, previous, element('b', { members: [member('group-1')] }), false)).toBe(false);
    // A member restricted to groups reads less than the same member without restriction, never more
    expect(isTimelineElementChangeWidening(container, element('a', { members: [member('user-1', ['g-2', 'g-1'])] }), element('b', { members: [member('user-1', ['g-1', 'g-2'])] }), false)).toBe(false);
    expect(isTimelineElementChangeWidening(container, previous, element('b', { members: [member('user-2')] }), false)).toBe(true);
    expect(isTimelineElementChangeWidening(container, element('a', { members: [member('user-1', ['g-1'])] }), element('b', { members: [member('user-1')] }), false)).toBe(true);
    // An element without members, or no element, is read beyond the members
    expect(isTimelineElementChangeWidening(container, previous, element('b'), false)).toBe(true);
    expect(isTimelineElementChangeWidening(container, previous, null, false)).toBe(true);
  });

  it('should keep an event of an element shared with organizations to elements shared with the same ones or fewer, under a platform organization', () => {
    // A container shared with more organizations than the elements, so that the elements bound the readers of the event
    const shared = element('case-2', { type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT, granted: ['org-1', 'org-2', 'org-3'] });
    const previous = element('a', { granted: ['org-1', 'org-2'] });
    expect(isTimelineElementChangeWidening(shared, previous, element('b', { granted: ['org-2'] }), true)).toBe(false);
    expect(isTimelineElementChangeWidening(shared, previous, element('b', { granted: ['org-2', 'org-3'] }), true)).toBe(true);
    // An unshared element is read inside the platform organization only
    expect(isTimelineElementChangeWidening(shared, element('a'), element('b', { granted: ['org-1'] }), true)).toBe(true);
    // Authorized members bypass organization sharing: they cannot be placed against the organizations
    expect(isTimelineElementChangeWidening(shared, previous, element('b', { members: [member('user-1')] }), true)).toBe(true);
    // An element of a type no organization restricts is read by every user
    expect(isTimelineElementChangeWidening(shared, previous, element('b', { type: ENTITY_TYPE_IDENTITY_ORGANIZATION }), true)).toBe(true);
    expect(isTimelineElementChangeWidening(shared, element('a', { type: ENTITY_TYPE_IDENTITY_ORGANIZATION }), element('b', { granted: ['org-3'] }), true)).toBe(false);
    // An unshared container is read inside the platform organization only: it bounds the readers of its events
    expect(isTimelineElementChangeWidening(container, previous, element('b', { granted: ['org-2', 'org-3'] }), true)).toBe(false);
  });

  it('should ignore organization sharing without a platform organization', () => {
    expect(isTimelineElementChangeWidening(container, element('a'), element('b', { granted: ['org-1'] }), false)).toBe(false);
    expect(isTimelineElementChangeWidening(container, element('a', { granted: ['org-1'] }), null, false)).toBe(false);
    expect(isTimelineElementChangeWidening(container, element('a'), element('b', { members: [member('user-1')] }), false)).toBe(false);
  });

  it('should allow any change when the container has no reader the previous element lacks', () => {
    // The event is read like its container and its element: within the readers of the previous element, any element goes
    const restrictedContainer = element('case-4', { type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT, members: [member('user-1')] });
    const previous = element('a', { members: [member('user-1'), member('user-2')] });
    expect(isTimelineElementChangeWidening(restrictedContainer, previous, null, false)).toBe(false);
    expect(isTimelineElementChangeWidening(restrictedContainer, previous, element('b'), false)).toBe(false);
    const sharedContainer = element('case-3', { type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT, granted: ['org-1'] });
    expect(isTimelineElementChangeWidening(sharedContainer, element('a', { granted: ['org-1', 'org-2'] }), null, true)).toBe(false);
    expect(isTimelineElementChangeWidening(sharedContainer, element('a', { granted: ['org-2'] }), null, true)).toBe(true);
  });
});

describe('Timeline export bound', () => {
  const event = (id: string, text: number) => ({ internal_id: id, name: 'x'.repeat(text), description: null, annotation: null }) as unknown as StoredTimelineEvent;

  it('should keep every page while the text of the events stays within the bound', () => {
    const pages = collectTimelineExportPages(100);
    expect(pages.collect([event('a', 40), event('b', 40)])).toBe(true);
    expect(pages.collect([{ ...event('c', 10), description: 'y'.repeat(5), annotation: 'z'.repeat(5) } as StoredTimelineEvent])).toBe(true);
    expect(pages.exceeded()).toBe(false);
    expect(pages.events.map((e) => e.internal_id)).toEqual(['a', 'b', 'c']);
  });

  it('should stop reading at the page that passes the bound, without keeping it', () => {
    const pages = collectTimelineExportPages(100);
    expect(pages.collect([event('a', 60)])).toBe(true);
    expect(pages.collect([event('b', 30), event('c', 30)])).toBe(false);
    expect(pages.exceeded()).toBe(true);
    expect(pages.events.map((e) => e.internal_id)).toEqual(['a']);
  });
});

describe('Timeline recorded references', () => {
  const members = [{ id: 'user-1', access_right: 'admin' }];
  const event = ({
    internal_id: 'event-1',
    element_id: 'element-1',
    element_type: 'Case-Rfi',
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: ['marking-1'],
    element_access: {
      restricted_members: members,
      granted: ['org-1'],
      sources: [
        { id: 'source-1', entity_type: 'uses', restricted_members: [], granted: ['org-2'] },
        { id: 'source-2', restricted_members: [], granted: [] },
      ],
    },
  }) as unknown as TimelineReadableEvent;

  it('should read a deleted element as recorded, with the markings of the event', () => {
    expect(recordedTimelineReference(event, 'element-1')).toEqual({
      internal_id: 'element-1',
      entity_type: 'Case-Rfi',
      [RELATION_OBJECT_MARKING]: ['marking-1'],
      restricted_members: members,
      [RELATION_GRANTED_TO]: ['org-1'],
    });
  });

  it('should read a deleted source as recorded, and nothing without its type', () => {
    expect(recordedTimelineReference(event, 'source-1')).toMatchObject({ internal_id: 'source-1', entity_type: 'uses', [RELATION_GRANTED_TO]: ['org-2'] });
    expect(recordedTimelineReference(event, 'source-2')).toBeNull();
    expect(recordedTimelineReference(event, 'unknown')).toBeNull();
  });

  it('should read nothing for an element recorded without its type or its access', () => {
    expect(recordedTimelineReference({ ...event, element_type: null }, 'element-1')).toBeNull();
    expect(recordedTimelineReference({ ...event, element_access: null }, 'element-1')).toBeNull();
  });
});

describe('Timeline first-use generation limit', () => {
  it('should run at most the limit at once, let the others wait in order and refuse beyond the waiting line', async () => {
    const run = createConcurrencyLimiter(1, 1);
    const started: string[] = [];
    let finishFirst: () => void = () => {};
    const first = run(() => new Promise<string>((resolve) => {
      started.push('first');
      finishFirst = () => resolve('first');
    }));
    const second = run(async () => {
      started.push('second');
      return 'second';
    });
    expect(await run(async () => 'third')).toEqual({ started: false });
    expect(started).toEqual(['first']);
    finishFirst();
    expect(await first).toEqual({ started: true, value: 'first' });
    expect(await second).toEqual({ started: true, value: 'second' });
    expect(started).toEqual(['first', 'second']);
    // A failed task gives its slot back as well
    await expect(run(async () => {
      throw new Error('failed');
    })).rejects.toThrow('failed');
    expect(await run(async () => 'fourth')).toEqual({ started: true, value: 'fourth' });
  });
});

describe('Timeline derived event markings', () => {
  it('should never mark a derived event less than its element, even when its rule reads no marking', () => {
    // As read without its relations, the element carries its markings as doc values
    expect(timelineEventMarkings([], { 'object-marking': ['tlp-amber'] }, ['tlp-green']).sort()).toEqual(['tlp-amber', 'tlp-green']);
    expect(timelineEventMarkings(['tlp-amber'], { 'rel_object-marking.internal_id': ['tlp-amber', 'pap-red'] }, []).sort()).toEqual(['pap-red', 'tlp-amber']);
    // The container itself (or an element not read) adds nothing beyond the markings of the container
    expect(timelineEventMarkings(['tlp-clear'], undefined, ['tlp-green']).sort()).toEqual(['tlp-clear', 'tlp-green']);
  });

  it('should tell when who may read an event changed between two versions of it', () => {
    const event = { name: 'Related campaign spotted', 'rel_object-marking.internal_id': ['tlp-green'], element_access: { restricted_members: [], granted: [] } };
    expect(isTimelineEventAccessChanged(event, { ...event, name: 'Renamed' })).toBe(false);
    expect(isTimelineEventAccessChanged(event, { ...event, 'rel_object-marking.internal_id': ['tlp-amber', 'tlp-green'] })).toBe(true);
    expect(isTimelineEventAccessChanged(event, { ...event, element_access: { restricted_members: [{ id: 'user', access_right: 'admin' }], granted: [] } })).toBe(true);
    // The element was deleted: its access is no longer recorded
    expect(isTimelineEventAccessChanged(event, { ...event, element_access: null })).toBe(true);
    // A source of the event (a relationship dating a technique) was restricted
    const withSource = { ...event, element_access: { restricted_members: [], granted: [], sources: [{ id: 'rel-1', restricted_members: [], granted: [] }] } };
    expect(isTimelineEventAccessChanged(event, withSource)).toBe(true);
    expect(isTimelineEventAccessChanged(withSource, {
      ...withSource,
      element_access: { ...withSource.element_access, sources: [{ id: 'rel-1', restricted_members: [], granted: ['org-1'] }] },
    })).toBe(true);
  });

  it('should refresh every reader when a changed event cannot be named to all of them', () => {
    const open = { 'rel_object-marking.internal_id': [], element_access: { restricted_members: [], granted: [] } };
    const withSource = { ...open, element_access: { restricted_members: [], granted: [], sources: [{ id: 'run-1', restricted_members: [], granted: [] }] } };
    // Renamed or created events are named to their readers
    expect(isTimelineRefreshForEveryReader([{ previous: open, next: { ...open, name: 'Renamed' } }, { previous: undefined, next: open }], [open])).toBe(false);
    // A restricted element: the readers who lost the event cannot be named
    expect(isTimelineRefreshForEveryReader([{ previous: open, next: { ...open, element_access: null } }], [])).toBe(true);
    // A removed event about other elements (a hunt run event after its run was deleted) is named to nobody
    expect(isTimelineRefreshForEveryReader([], [withSource])).toBe(true);
  });

  it('should read the sources of an event from the access the regeneration recorded', () => {
    expect(timelineEventSourceIds({ element_access: { restricted_members: [], granted: [], sources: [{ id: 'rel-1', restricted_members: [], granted: [] }, { id: 'rel-2', restricted_members: [], granted: [] }] } })).toEqual(['rel-1', 'rel-2']);
    expect(timelineEventSourceIds({ element_access: { restricted_members: [], granted: [] } })).toEqual([]);
    // An event whose element could not be resolved records no access: it is read by nobody, whatever its sources
    expect(timelineEventSourceIds({ element_access: null })).toEqual([]);
  });
});

describe('Timeline imported annotations and confidence', () => {
  const userWith = (effective: AuthUser['effective_confidence_level']) => ({ effective_confidence_level: effective } as unknown as AuthUser);

  it('should read the confidence level of the user for timeline events, its override first', () => {
    expect(timelineEventMaxConfidence(userWith({ max_confidence: 40, overrides: [] }))).toEqual(40);
    expect(timelineEventMaxConfidence(userWith({ max_confidence: 40, overrides: [{ entity_type: ENTITY_TYPE_TIMELINE_EVENT, max_confidence: 70 }] }))).toEqual(70);
    expect(timelineEventMaxConfidence(userWith({ max_confidence: 40, overrides: [{ entity_type: 'Malware', max_confidence: 90 }] }))).toEqual(40);
    expect(timelineEventMaxConfidence(userWith(null as unknown as AuthUser['effective_confidence_level']))).toBeNull();
  });

  it('should keep the higher of the stored and imported confidence of a known event, none counting as no level', () => {
    expect(strongerTimelineConfidence(90, 40)).toEqual(90);
    expect(strongerTimelineConfidence(40, 90)).toEqual(90);
    expect(strongerTimelineConfidence(90, null)).toEqual(90);
    expect(strongerTimelineConfidence(null, 40)).toEqual(40);
    expect(strongerTimelineConfidence(undefined, null)).toBeNull();
    expect(strongerTimelineConfidence(0, null)).toEqual(0);
  });

  it('should keep the analyst fields of a derived event pushed out by the cap, and only those', () => {
    const kept = keptAnalystFields({ internal_id: 'capped', analyst_fields: ['pinned', 'annotation'], pinned: true, hidden: false, annotation: 'Initial dropper', ordering_hint: 3 });
    expect(kept).toEqual({ event_id: 'capped', pinned: true, annotation: 'Initial dropper', max_confidence: 100 });
    // They were set by users the confidence check of the event let through: they come back whatever its confidence
    expect(isPendingAnnotationApplicable(kept, 100)).toBe(true);
  });

  it('should record the annotated derived events left out by the cap, read like stored events by the exchange', () => {
    const derivedDoc = (internalId: string, fields: Partial<Parameters<typeof buildTimelineEventDoc>[0]>) => buildTimelineEventDoc({
      internal_id: internalId,
      container_id: 'case-1',
      name: 'Malware seen',
      event_time: '2026-03-01T00:00:00.000Z',
      time_precision: 'exact',
      lane: 'evidence',
      kind: 'malware_seen',
      event_source: 'derived',
      rule_id: 'entity-first-last-seen',
      element_id: 'malware-1',
      element_type: 'Malware',
      pinned: false,
      hidden: false,
      analyst_fields: [],
      markings: ['tlp-green'],
      creator_ids: [],
      restricted_members: [],
      element_access: { restricted_members: [], granted: [], sources: [{ id: 'run-1', restricted_members: [], granted: [] }] },
      ...fields,
    });
    const stored = derivedDoc('stored', { analyst_fields: ['pinned'], pinned: true });
    const capped = derivedDoc('capped', { analyst_fields: ['pinned', 'annotation'], pinned: true, annotation: 'Initial dropper', ordering_hint: 4 });
    const untouched = derivedDoc('untouched', {});
    const records = timelineCappedAnnotatedEvents([stored, capped, untouched], new Set(['stored']));
    // Only the analyst fields are recorded: the ordering hint of the rule is not a contribution
    expect(records).toEqual([{
      internal_id: 'capped',
      rule_id: 'entity-first-last-seen',
      kind: 'malware_seen',
      element_id: 'malware-1',
      markings: ['tlp-green'],
      element_access: { restricted_members: [], granted: [], sources: [{ id: 'run-1', restricted_members: [], granted: [] }] },
      analyst_fields: ['pinned', 'annotation'],
      pinned: true,
      hidden: false,
      annotation: 'Initial dropper',
      ordering_hint: null,
    }]);
    const asStored = timelineCappedAnnotatedEventAsStored(records[0]);
    expect(asStored.event_source).toEqual('derived');
    expect(markingsOf(asStored)).toEqual(['tlp-green']);
    expect(timelineEventSourceIds(asStored)).toEqual(['run-1']);
    expect(timelineExchangeAnnotation(asStored, 'malware--1')).toEqual({
      rule_id: 'entity-first-last-seen',
      kind: 'malware_seen',
      element_ref: 'malware--1',
      pinned: true,
      hidden: undefined,
      annotation: 'Initial dropper',
      ordering_hint: undefined,
      cleared_fields: undefined,
    });
  });

  it('should apply an imported annotation only to an event within the confidence level of its importer', () => {
    expect(isPendingAnnotationApplicable({ event_id: 'e', pinned: true, max_confidence: 50 }, 50)).toBe(true);
    expect(isPendingAnnotationApplicable({ event_id: 'e', pinned: true, max_confidence: 50 }, null)).toBe(true);
    expect(isPendingAnnotationApplicable({ event_id: 'e', pinned: true, max_confidence: 50 }, 80)).toBe(false);
    // An annotation imported without a confidence level, or by a user without one, never applies
    expect(isPendingAnnotationApplicable({ event_id: 'e', pinned: true }, 0)).toBe(false);
    expect(isPendingAnnotationApplicable({ event_id: 'e', pinned: true, max_confidence: null }, 0)).toBe(false);
  });
});
