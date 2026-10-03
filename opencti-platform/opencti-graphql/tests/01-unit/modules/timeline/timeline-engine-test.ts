import { describe, expect, it } from 'vitest';
import {
  buildTimelineEventDoc,
  computeDerivedEventId,
  computeManualEventId,
  getTimelineRules,
  timelineEventSignature,
  timelineEventStandardId,
  timelineRuleFamily,
} from '../../../../src/modules/timeline/timeline-engine';
import { buildTimelineFilters } from '../../../../src/modules/timeline/timeline-domain';
import { buildStixTimelineExtension } from '../../../../src/modules/timeline/timeline-extension';
import { RULE_TASK_CONTAINMENT, RULE_WORKFLOW_CLOSURE } from '../../../../src/modules/timeline/timeline-rules';
import { ENTITY_TYPE_TIMELINE_EVENT, TIMELINE_KINDS } from '../../../../src/modules/timeline/timeline-types';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_INCIDENT } from '../../../../src/schema/stixDomainObject';
import { TimelineEventKind } from '../../../../src/generated/graphql';
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
});

describe('Timeline read filters', () => {
  it('should hide hidden events and apply the requested filters', () => {
    const filters = buildTimelineFilters('case-1', { lanes: ['adversary'], kinds: ['sighting'], sources: ['manual'], markings: ['m1'], search: ' phishing ', pinnedOnly: true, from: '2026-03-01T00:00:00.000Z', to: '2026-03-31T00:00:00.000Z' });
    const keys = filters.filters.map((f: any) => f.key.join(','));
    expect(keys).toEqual(['container_id', 'lane', 'kind', 'event_source', 'objectMarking', 'hidden', 'pinned', 'event_time', 'name,description,annotation']);
    expect(filters.filters.find((f: any) => f.key[0] === 'hidden')).toMatchObject({ operator: 'not_eq' });
    expect(filters.filters.find((f: any) => f.key[0] === 'name')).toMatchObject({ values: ['phishing'], operator: 'search' });
    expect(filters.filterGroups).toHaveLength(1);
    expect(filters.filterGroups[0].filters.map((f: any) => f.key[0])).toEqual(['event_time', 'event_end_time']);
  });

  it('should include hidden events when requested', () => {
    const filters = buildTimelineFilters('case-1', { includeHidden: true });
    expect(filters.filters.map((f: any) => f.key[0])).toEqual(['container_id']);
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
});
