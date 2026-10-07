import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  changeFieldKey,
  containerObjectIdsAt,
  currentContainerObjectIds,
  diffDocuments,
  extractAttributeValues,
  firstNumber,
  flagReplayBeyondWindow,
  forwardOperationsForChange,
  isMultipleAttribute,
  normalizeDocument,
  rebuildElementAt,
  replayBackward,
  replayForward,
  reverseOperationsForChange,
  rewindAccessReferences,
} from '../../../../src/modules/timeMachine/timeMachine-replay';
import { extractEntityRepresentativeName } from '../../../../src/database/entity-representative';
import type { AttributeValues, TimeMachineHistoryEvent } from '../../../../src/modules/timeMachine/timeMachine-types';

const ENTITY_TYPE = 'Intrusion-Set';
const MARKING_GREEN = '11111111-1111-4111-8111-111111111111';
const MARKING_AMBER = '22222222-2222-4222-8222-222222222222';
const LABEL_A = '33333333-3333-4333-8333-333333333333';
const LABEL_B = '44444444-4444-4444-8444-444444444444';
const ORGANIZATION_A = '55555555-5555-4555-8555-555555555555';

const updateEvent = (timestamp: string, changes: Array<{ key: string; added?: string[]; removed?: string[] }>): TimeMachineHistoryEvent => ({
  id: `event-${timestamp}`,
  timestamp,
  event_scope: 'update',
  context_id: 'entity-id',
  context_entity_type: ENTITY_TYPE,
  context_entity_name: 'APT-TEST',
  changes: changes.map(({ key, added = [], removed = [] }) => ({
    field: `${ENTITY_TYPE}--${key}`,
    changes_added: added.map((raw) => ({ raw })),
    changes_removed: removed.map((raw) => ({ raw })),
  })),
});

const scopedEvent = (timestamp: string, scope: string): TimeMachineHistoryEvent => ({
  id: `event-${scope}-${timestamp}`,
  timestamp,
  event_scope: scope,
  context_id: 'entity-id',
  context_entity_type: ENTITY_TYPE,
  context_entity_name: 'APT-TEST',
  changes: [],
});

// History of the entity (oldest first):
// 2026-01-01 created with description v1, confidence 50, label A, marking green
// 2026-02-01 description v1 -> v2
// 2026-03-01 confidence 50 -> 80, label B added
// 2026-04-01 marking amber added, label A removed
const EVENTS: TimeMachineHistoryEvent[] = [
  scopedEvent('2026-01-01T00:00:00.000Z', 'create'),
  updateEvent('2026-02-01T00:00:00.000Z', [{ key: 'description', added: ['v2'], removed: ['v1'] }]),
  updateEvent('2026-03-01T00:00:00.000Z', [{ key: 'confidence', added: ['80'], removed: ['50'] }, { key: 'objectLabel', added: [LABEL_B] }]),
  updateEvent('2026-04-01T00:00:00.000Z', [{ key: 'objectMarking', added: [MARKING_AMBER] }, { key: 'objectLabel', removed: [LABEL_A] }]),
];

const CURRENT: AttributeValues = {
  name: ['APT-TEST'],
  description: ['v2'],
  confidence: ['80'],
  objectLabel: [LABEL_B],
  objectMarking: [MARKING_GREEN, MARKING_AMBER],
};

describe('Time machine replay', () => {
  it('should extract raw attribute values from a store element', () => {
    const element = {
      entity_type: ENTITY_TYPE,
      internal_id: 'entity-id',
      standard_id: 'intrusion-set--id',
      name: 'APT-TEST',
      description: 'v2',
      aliases: ['alias-1', 'alias-2'],
      confidence: 80,
      revoked: false,
      first_seen: '2025-05-01T00:00:00.000Z',
      updated_at: '2026-04-01T00:00:00.000Z',
      created_at: '2026-01-01T00:00:00.000Z',
      x_opencti_stix_ids: ['intrusion-set--other'],
      creator_id: ['user-id'],
      'object-marking': [MARKING_GREEN, MARKING_AMBER],
      'object-label': [LABEL_B],
      'created-by': 'identity-id',
      i_aliases_ids: ['some-id'],
    };
    const values = extractAttributeValues(element);
    expect(values.name).toEqual(['APT-TEST']);
    expect(values.description).toEqual(['v2']);
    expect(values.aliases).toEqual(['alias-1', 'alias-2']);
    expect(values.confidence).toEqual(['80']);
    expect(values.revoked).toEqual(['false']);
    expect(values.first_seen).toEqual(['2025-05-01T00:00:00.000Z']);
    expect(values.objectMarking).toEqual([MARKING_GREEN, MARKING_AMBER]);
    expect(values.objectLabel).toEqual([LABEL_B]);
    expect(values.createdBy).toEqual(['identity-id']);
    // Technical attributes are never part of the documents
    expect(values.updated_at).toBeUndefined();
    expect(values.created_at).toBeUndefined();
    expect(values.x_opencti_stix_ids).toBeUndefined();
    expect(values.creator_id).toBeUndefined();
    expect(values.i_aliases_ids).toBeUndefined();
  });

  it('should treat the dates that mean not set as absent and never keep the id attribute', () => {
    const element = {
      entity_type: ENTITY_TYPE,
      id: 'entity-id',
      name: 'APT-TEST',
      first_seen: '1970-01-01T00:00:00.000Z',
      last_seen: '5138-11-16T09:46:40.000Z',
    };
    const values = extractAttributeValues(element);
    expect(values.first_seen).toBeUndefined();
    expect(values.last_seen).toBeUndefined();
    expect(values.id).toBeUndefined();
    // A first seen date set during the period is rewound to not set
    const operations = reverseOperationsForChange({ first_seen: ['2026-02-01T00:00:00.000Z'] }, ENTITY_TYPE, {
      field: `${ENTITY_TYPE}--first_seen`,
      changes_added: [{ raw: '2026-02-01T00:00:00.000Z' }],
      changes_removed: [{ raw: '1970-01-01T00:00:00.000Z' }],
    });
    expect(operations).toEqual([{ op: 'remove', path: '/first_seen' }]);
    // Snapshots stored before this rule are read with it
    expect(normalizeDocument(ENTITY_TYPE, { id: ['entity-id'], name: ['APT-TEST'], last_seen: ['5138-11-16T09:46:40.000Z'] })).toEqual({ name: ['APT-TEST'] });
  });

  it('should decode history change fields and attribute multiplicity', () => {
    expect(changeFieldKey('Intrusion-Set--description')).toEqual('description');
    expect(changeFieldKey('Threat-Actor-Group--objectMarking')).toEqual('objectMarking');
    expect(changeFieldKey('name')).toEqual('name');
    expect(isMultipleAttribute(ENTITY_TYPE, 'objectMarking')).toBe(true);
    expect(isMultipleAttribute(ENTITY_TYPE, 'aliases')).toBe(true);
    expect(isMultipleAttribute(ENTITY_TYPE, 'description')).toBe(false);
    expect(isMultipleAttribute(ENTITY_TYPE, 'createdBy')).toBe(false);
  });

  it('should build reverse and forward patches for single and multiple attributes', () => {
    const document: AttributeValues = { description: ['v2'], objectLabel: [LABEL_A, LABEL_B] };
    expect(reverseOperationsForChange(document, ENTITY_TYPE, { field: `${ENTITY_TYPE}--description`, changes_added: [{ raw: 'v2' }], changes_removed: [{ raw: 'v1' }] }))
      .toEqual([{ op: 'add', path: '/description', value: ['v1'] }]);
    expect(reverseOperationsForChange(document, ENTITY_TYPE, { field: `${ENTITY_TYPE}--description`, changes_added: [{ raw: 'v2' }], changes_removed: [] }))
      .toEqual([{ op: 'remove', path: '/description' }]);
    expect(reverseOperationsForChange(document, ENTITY_TYPE, { field: `${ENTITY_TYPE}--objectLabel`, changes_added: [{ raw: LABEL_B }] }))
      .toEqual([{ op: 'add', path: '/objectLabel', value: [LABEL_A] }]);
    expect(forwardOperationsForChange({ objectLabel: [LABEL_A] }, ENTITY_TYPE, { field: `${ENTITY_TYPE}--objectLabel`, changes_added: [{ raw: LABEL_B }] }))
      .toEqual([{ op: 'add', path: '/objectLabel', value: [LABEL_A, LABEL_B] }]);
    // Container objects are never replayed on documents
    expect(reverseOperationsForChange(document, 'Report', { field: 'Report--objects', changes_added: [{ raw: 'x' }] })).toEqual([]);
  });

  it('should rewind a document to any date with the reverse patches of the history', () => {
    const atMarch15 = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-03-15T00:00:00.000Z', 100);
    expect(atMarch15.exists).toBe(true);
    expect(atMarch15.complete).toBe(true);
    expect(atMarch15.replayedEvents).toBe(1);
    expect(atMarch15.document.objectMarking).toEqual([MARKING_GREEN]);
    expect(atMarch15.document.objectLabel?.sort()).toEqual([LABEL_A, LABEL_B].sort());
    expect(atMarch15.document.confidence).toEqual(['80']);

    const atFebruary15 = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-02-15T00:00:00.000Z', 100);
    expect(atFebruary15.document.confidence).toEqual(['50']);
    expect(atFebruary15.document.objectLabel).toEqual([LABEL_A]);
    expect(atFebruary15.document.description).toEqual(['v2']);

    const atJanuary15 = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', 100);
    expect(atJanuary15.exists).toBe(true);
    expect(atJanuary15.document.description).toEqual(['v1']);
    expect(atJanuary15.document.name).toEqual(['APT-TEST']);

    // The anchor document is never mutated
    expect(CURRENT.description).toEqual(['v2']);
  });

  it('should report that the element did not exist before its creation', () => {
    const beforeCreation = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2025-12-01T00:00:00.000Z', 100);
    expect(beforeCreation.exists).toBe(false);
  });

  it('should flag merges and replay windows exceeded as incomplete reconstructions', () => {
    const withMerge = [...EVENTS, scopedEvent('2026-05-01T00:00:00.000Z', 'merge')];
    const merged = replayBackward(CURRENT, ENTITY_TYPE, withMerge, '2026-04-15T00:00:00.000Z', 100);
    expect(merged.complete).toBe(false);
    expect(merged.warnings).toContain('MERGE_NOT_REVERSIBLE');
    const bounded = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', 1);
    expect(bounded.complete).toBe(false);
    expect(bounded.warnings).toContain('REPLAY_WINDOW_EXCEEDED');
  });

  it('should stop a replay at a merge it cannot reverse instead of applying older or later changes across it', () => {
    const withMerge = [...EVENTS, scopedEvent('2026-03-15T00:00:00.000Z', 'merge')];
    // Rewound to February: the change of April is reversed, the merge stops the rewind, the change of March stays
    const rewound = replayBackward(CURRENT, ENTITY_TYPE, withMerge, '2026-02-15T00:00:00.000Z', 100);
    expect(rewound.complete).toBe(false);
    expect(rewound.warnings).toEqual(['MERGE_NOT_REVERSIBLE']);
    expect(rewound.replayedEvents).toBe(2);
    expect(rewound.document.objectMarking).toEqual([MARKING_GREEN]);
    expect(rewound.document.objectLabel?.sort()).toEqual([LABEL_A, LABEL_B].sort());
    expect(rewound.document.confidence).toEqual(['80']);
    // Moved forward from January: the changes of February and March are applied, the merge stops the replay
    const atJanuary15 = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', 100);
    const forward = replayForward(atJanuary15.document, ENTITY_TYPE, withMerge, '2026-01-15T00:00:00.000Z', '2026-06-01T00:00:00.000Z', 100);
    expect(forward.complete).toBe(false);
    expect(forward.warnings).toEqual(['MERGE_NOT_REVERSIBLE']);
    expect(forward.document.description).toEqual(['v2']);
    expect(forward.document.confidence).toEqual(['80']);
    expect(forward.document.objectLabel?.sort()).toEqual([LABEL_A, LABEL_B].sort());
    expect(forward.document.objectMarking).toEqual([MARKING_GREEN]);
  });

  it('should move an older document forward to the current state', () => {
    const atJanuary15 = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', 100);
    const forward = replayForward(atJanuary15.document, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', '2026-06-01T00:00:00.000Z', 100);
    expect(forward.exists).toBe(true);
    expect(diffDocuments(forward.document, CURRENT)).toEqual([]);
    const deleted = replayForward(atJanuary15.document, ENTITY_TYPE, [...EVENTS, scopedEvent('2026-05-01T00:00:00.000Z', 'delete')], '2026-01-15T00:00:00.000Z', '2026-06-01T00:00:00.000Z', 100);
    expect(deleted.exists).toBe(false);
  });

  it('should flag long replays from an anchor after or before the requested date', () => {
    const atJanuary15 = replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', 100);
    // Backward: the anchor (current knowledge) is months after the requested date
    const backward = flagReplayBeyondWindow(replayBackward(CURRENT, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', 100), '2026-06-01T00:00:00.000Z', '2026-01-15T00:00:00.000Z', 90);
    expect(backward.warnings).toEqual(['REPLAY_BEYOND_WINDOW']);
    // Forward: the anchor (an older snapshot) is months before the requested date
    const forward = replayForward(atJanuary15.document, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', '2026-06-01T00:00:00.000Z', 100);
    expect(flagReplayBeyondWindow(forward, '2026-01-15T00:00:00.000Z', '2026-06-01T00:00:00.000Z', 90).warnings).toEqual(['REPLAY_BEYOND_WINDOW']);
    // Flagged once, and not within the window
    expect(flagReplayBeyondWindow(forward, '2026-01-15T00:00:00.000Z', '2026-06-01T00:00:00.000Z', 90).warnings).toEqual(['REPLAY_BEYOND_WINDOW']);
    const short = replayForward(atJanuary15.document, ENTITY_TYPE, EVENTS, '2026-01-15T00:00:00.000Z', '2026-03-01T00:00:00.000Z', 100);
    expect(flagReplayBeyondWindow(short, '2026-01-15T00:00:00.000Z', '2026-03-01T00:00:00.000Z', 90).warnings).toEqual([]);
  });

  it('should diff two documents attribute by attribute', () => {
    const before: AttributeValues = { description: ['v1'], objectLabel: [LABEL_A], confidence: ['50'] };
    const after: AttributeValues = { description: ['v2'], objectLabel: [LABEL_B, LABEL_A], name: ['APT-TEST'], confidence: ['50'] };
    const deltas = diffDocuments(before, after);
    expect(deltas.map((delta) => delta.key)).toEqual(['description', 'name', 'objectLabel']);
    const labels = deltas.find((delta) => delta.key === 'objectLabel');
    expect(labels?.added).toEqual([LABEL_B]);
    expect(labels?.removed).toEqual([]);
    const name = deltas.find((delta) => delta.key === 'name');
    expect(name?.before).toEqual([]);
    expect(name?.after).toEqual(['APT-TEST']);
  });

  it('should parse numeric raw values', () => {
    expect(firstNumber(['75'])).toBe(75);
    expect(firstNumber([])).toBeNull();
    expect(firstNumber(undefined)).toBeNull();
    expect(firstNumber(['not-a-number'])).toBeNull();
  });

  it('should rewind the objects of a container with the objects changes since a date', () => {
    const current = currentContainerObjectIds({ object: ['object-a', 'object-c', 'object-d'] });
    expect(current).toEqual(['object-a', 'object-c', 'object-d']);
    expect(currentContainerObjectIds({})).toEqual([]);
    const events = [
      updateEvent('2026-01-03T00:00:00.000Z', [{ key: 'objects', added: ['object-c'], removed: ['object-b'] }]),
      // Added then removed since the date: it was not part of the container at that date
      updateEvent('2026-01-04T00:00:00.000Z', [{ key: 'objects', added: ['object-e'] }]),
      updateEvent('2026-01-05T00:00:00.000Z', [{ key: 'objects', removed: ['object-e'] }, { key: 'description', added: ['other change'] }]),
      updateEvent('2026-01-06T00:00:00.000Z', [{ key: 'objects', added: ['object-d'] }]),
    ];
    expect(containerObjectIdsAt(current, events).sort()).toEqual(['object-a', 'object-b']);
    expect(containerObjectIdsAt(current, [])).toEqual(current);
  });
});

describe('Element rebuilt at a date', () => {
  it('should represent an observable by its value at that date', () => {
    const observable = { entity_type: 'IPv4-Addr', value: '2.2.2.2', x_opencti_score: 80 };
    const rebuilt = rebuildElementAt(observable, { value: ['1.1.1.1'], x_opencti_score: ['50'] });
    expect(rebuilt.value).toEqual('1.1.1.1');
    expect(rebuilt.x_opencti_score).toEqual(50);
    expect(extractEntityRepresentativeName(rebuilt)).toEqual('1.1.1.1');
    expect(extractEntityRepresentativeName(observable)).toEqual('2.2.2.2');
  });

  it('should decode every attribute type and empty the attributes absent at that date', () => {
    const intrusionSet = { entity_type: ENTITY_TYPE, name: 'APT-NEW', description: 'current', revoked: false, aliases: ['NEW'] };
    const rebuilt = rebuildElementAt(intrusionSet, { name: ['APT-OLD'], revoked: ['true'], aliases: ['OLD-1', 'OLD-2'] });
    expect(rebuilt.name).toEqual('APT-OLD');
    expect(rebuilt.revoked).toBe(true);
    expect(rebuilt.aliases).toEqual(['OLD-1', 'OLD-2']);
    expect(rebuilt.description).toBeUndefined();
    expect(extractEntityRepresentativeName(rebuilt)).toEqual('APT-OLD');
    const currentFile = { entity_type: 'StixFile', hashes: { MD5: 'current' } };
    const file = rebuildElementAt(currentFile, { hashes: [JSON.stringify({ MD5: 'past' })] });
    expect(file.hashes).toEqual({ MD5: 'past' });
  });

  it('should rewind the access references with their own changes only', () => {
    const keys = { marking: 'objectMarking', granted: 'objectOrganization' };
    const current: AttributeValues = { ...CURRENT, objectOrganization: [ORGANIZATION_A] };
    const events = [
      ...EVENTS,
      updateEvent('2026-05-01T00:00:00.000Z', [{ key: 'objectOrganization', added: [ORGANIZATION_A] }, { key: 'description', added: ['v2'], removed: ['v1'] }]),
    ];
    // Before the amber marking and the organization sharing of April and May
    const march = rewindAccessReferences(current, ENTITY_TYPE, events, '2026-03-15T00:00:00.000Z', keys);
    expect(march).toEqual({ objectMarking: [MARKING_GREEN] });
    // Only the access references are rebuilt, whatever the other changes of the events
    const april = rewindAccessReferences(current, ENTITY_TYPE, events, '2026-04-15T00:00:00.000Z', keys);
    expect(april).toEqual({ objectMarking: [MARKING_GREEN, MARKING_AMBER] });
  });

  it('should keep no organization sharing before a merge it cannot reverse', () => {
    const keys = { marking: 'objectMarking', granted: 'objectOrganization' };
    const current: AttributeValues = { objectMarking: [MARKING_GREEN, MARKING_AMBER], objectOrganization: [ORGANIZATION_A] };
    const events = [scopedEvent('2026-06-01T00:00:00.000Z', 'merge')];
    const beforeMerge = rewindAccessReferences(current, ENTITY_TYPE, events, '2026-05-01T00:00:00.000Z', keys);
    // The markings brought by the merge stay (restrictive), the organization sharing is dropped (restrictive)
    expect(beforeMerge).toEqual({ objectMarking: [MARKING_GREEN, MARKING_AMBER] });
    const afterMerge = rewindAccessReferences(current, ENTITY_TYPE, events, '2026-06-15T00:00:00.000Z', keys);
    expect(afterMerge).toEqual(current);
  });
});
