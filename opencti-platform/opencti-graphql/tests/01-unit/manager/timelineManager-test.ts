import { describe, expect, it } from 'vitest';
import {
  buildTimelineConsistencyFilters,
  collectTimelineImpacts,
  computeChangedWorkflowTypes,
  isTimelineConsistencyPassDue,
  newImpactCollector,
} from '../../../src/manager/timelineManager';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import type { DataEvent, SseEvent } from '../../../src/types/event';

const streamEvent = (data: Record<string, any>): SseEvent<DataEvent> => ({
  id: '1-0',
  event: 'update',
  data: { type: 'update', scope: 'external', version: '4', origin: {}, message: '', data } as any,
});

const newCollector = newImpactCollector;

describe('Timeline manager impact collection', () => {
  it('should directly impact a timeline container, and the timelines containing it or related to it', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'incident', extensions: { [STIX_EXT_OCTI]: { id: 'incident-1', type: 'Incident' } } }), collector);
    expect(Array.from(collector.containers)).toEqual(['incident-1']);
    expect(Array.from(collector.contained)).toEqual(['incident-1']);
    expect(Array.from(collector.related)).toEqual(['incident-1']);
    expect(collector.references.size).toEqual(0);
  });

  it('should follow the object refs of tasks, notes, opinions and reports', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'note', object_refs: ['case-incident--1'], extensions: { [STIX_EXT_OCTI]: { id: 'note-1', type: 'Note' } } }), collector);
    expect(Array.from(collector.references)).toEqual(['case-incident--1']);
  });

  it('should reach the cases of a task whose labels changed, published as an update of the task', () => {
    // A label is a ref of the task: adding or removing it is streamed as an update of the task, never as a relationship
    const collector = newCollector();
    const event = streamEvent({ type: 'task', labels: ['containment'], object_refs: ['case-incident--1'], extensions: { [STIX_EXT_OCTI]: { id: 'task-1', type: 'Task' } } });
    (event.data as any).context = {
      patch: [{ op: 'add', path: '/labels', value: ['containment'] }],
      reverse_patch: [{ op: 'remove', path: '/labels' }],
    };
    collectTimelineImpacts(event, collector);
    expect(Array.from(collector.references)).toEqual(['case-incident--1']);
  });

  it('should follow the labels and kill chain phases the derivation reads through tasks and techniques', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'label', extensions: { [STIX_EXT_OCTI]: { id: 'label-1', type: 'Label' } } }), collector);
    collectTimelineImpacts(streamEvent({ type: 'kill-chain-phase', extensions: { [STIX_EXT_OCTI]: { id: 'phase-1', type: 'Kill-Chain-Phase' } } }), collector);
    expect(Array.from(collector.labels)).toEqual(['label-1']);
    expect(Array.from(collector.killChainPhases)).toEqual(['phase-1']);
    expect(collector.contained.size).toEqual(0);
    // A label or a phase just created is used by nothing yet
    const created = newCollector();
    const event = streamEvent({ type: 'label', extensions: { [STIX_EXT_OCTI]: { id: 'label-2', type: 'Label' } } });
    (event.data as any).type = 'create';
    collectTimelineImpacts(event, created);
    expect(created.labels.size).toEqual(0);
  });

  it('should reach the containers citing an updated external reference, never the containment lookup', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'external-reference', extensions: { [STIX_EXT_OCTI]: { id: 'ref-1', type: 'External-Reference' } } }), collector);
    expect(Array.from(collector.externalReferences)).toEqual(['ref-1']);
    expect(collector.contained.size + collector.related.size).toEqual(0);
    // An external reference just created is cited by nothing yet
    const created = newCollector();
    const event = streamEvent({ type: 'external-reference', extensions: { [STIX_EXT_OCTI]: { id: 'ref-2', type: 'External-Reference' } } });
    (event.data as any).type = 'create';
    collectTimelineImpacts(event, created);
    expect(created.externalReferences.size).toEqual(0);
  });

  it('should also impact the cases an update removed from the object refs', () => {
    const collector = newCollector();
    const note = { type: 'note', object_refs: ['case-incident--1'], extensions: { [STIX_EXT_OCTI]: { id: 'note-1', type: 'Note' } } };
    const event = streamEvent(note);
    // The reverse patch rebuilds the note as it was before the update, when it also referenced the second case
    (event.data as any).context = {
      patch: [{ op: 'remove', path: '/object_refs/1' }],
      reverse_patch: [{ op: 'add', path: '/object_refs/1', value: 'case-incident--2' }],
    };
    collectTimelineImpacts(event, collector);
    expect(Array.from(collector.references).sort()).toEqual(['case-incident--1', 'case-incident--2']);
    expect(note.object_refs).toEqual(['case-incident--1']);
  });

  it('should keep the current refs when the reverse patch of an update does not apply', () => {
    const collector = newCollector();
    const event = streamEvent({ type: 'note', object_refs: ['case-incident--1'], extensions: { [STIX_EXT_OCTI]: { id: 'note-1', type: 'Note' } } });
    (event.data as any).context = { patch: [], reverse_patch: [{ op: 'replace', path: '/missing/0', value: 'x' }] };
    collectTimelineImpacts(event, collector);
    expect(Array.from(collector.references)).toEqual(['case-incident--1']);
  });

  it('should impact incidents linked by a relationship and containers of its elements', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({
      type: 'relationship',
      extensions: { [STIX_EXT_OCTI]: { id: 'rel-1', type: 'uses', source_ref: 'incident-1', source_type: 'Incident', target_ref: 'ap-1', target_type: 'Attack-Pattern' } },
    }), collector);
    expect(Array.from(collector.containers)).toEqual(['incident-1']);
    // Cases containing either endpoint (here the targeted attack pattern) are impacted too
    expect(Array.from(collector.contained).sort()).toEqual(['ap-1', 'incident-1', 'rel-1']);
  });

  it('should reach the incidents related to a deployed indicator, which read its deployments', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({
      type: 'relationship',
      extensions: { [STIX_EXT_OCTI]: { id: 'dep-1', type: 'deployed-on', source_ref: 'ind-1', source_type: 'Indicator', target_ref: 'platform-1', target_type: 'SecurityPlatform' } },
    }), collector);
    expect(Array.from(collector.contained).sort()).toEqual(['dep-1', 'ind-1', 'platform-1']);
    expect(Array.from(collector.related)).toEqual(['ind-1']);
    // Any other relationship reaches incidents only as an endpoint or through containment
    const other = newCollector();
    collectTimelineImpacts(streamEvent({
      type: 'relationship',
      extensions: { [STIX_EXT_OCTI]: { id: 'rel-1', type: 'indicates', source_ref: 'ind-1', source_type: 'Indicator', target_ref: 'mal-1', target_type: 'Malware' } },
    }), other);
    expect(other.related.size).toEqual(0);
  });

  it('should follow the sighted element of a sighting', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'sighting', extensions: { [STIX_EXT_OCTI]: { id: 's-1', type: 'stix-sighting-relationship', sighting_of_ref: 'ind-1' } } }), collector);
    expect(Array.from(collector.contained).sort()).toEqual(['ind-1', 's-1']);
    // Incidents load the platform sightings of their related indicators
    expect(Array.from(collector.related)).toEqual(['ind-1']);
  });

  it('should look for the cases and incidents of any other updated entity', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'malware', extensions: { [STIX_EXT_OCTI]: { id: 'mal-1', type: 'Malware' } } }), collector);
    expect(Array.from(collector.contained)).toEqual(['mal-1']);
    expect(Array.from(collector.related)).toEqual(['mal-1']);
  });

  it('should reach the containers of the soft-check sources the way the loader selects them', () => {
    const collector = newCollector();
    // A hunt run of an incident, not an object of it, and of a hunt
    collectTimelineImpacts(streamEvent({ type: 'hunt-run', incident_id: 'incident-1', hunt_id: 'hunt-1', extensions: { [STIX_EXT_OCTI]: { id: 'run-1', type: 'Hunt-Run' } } }), collector);
    // An investigation run about a subject and attached to cases
    collectTimelineImpacts(streamEvent({
      type: 'investigation-run', subject_id: 'case-incident--1', case_ids: ['case-incident--2', 'case-rfi--1'], extensions: { [STIX_EXT_OCTI]: { id: 'inv-1', type: 'InvestigationRun' } },
    }), collector);
    // A security coverage of a case, a result of a coverage and a has-covered relationship of a coverage
    collectTimelineImpacts(streamEvent({ type: 'security-coverage', covered_ref: 'case-incident--3', extensions: { [STIX_EXT_OCTI]: { id: 'cov-1', type: 'Security-Coverage' } } }), collector);
    collectTimelineImpacts(streamEvent({ type: 'security-coverage-result', result_of_ref: 'security-coverage--2', extensions: { [STIX_EXT_OCTI]: { id: 'res-1', type: 'Security-Coverage-Result' } } }), collector);
    collectTimelineImpacts(streamEvent({
      type: 'relationship',
      extensions: { [STIX_EXT_OCTI]: { id: 'rel-1', type: 'has-covered', source_ref: 'cov-3', source_type: 'Security-Coverage', target_ref: 'ap-1', target_type: 'Attack-Pattern' } },
    }), collector);
    expect(Array.from(collector.references).sort()).toEqual(['case-incident--1', 'case-incident--2', 'case-incident--3', 'case-rfi--1', 'incident-1']);
    expect(Array.from(collector.contained)).toEqual(expect.arrayContaining(['hunt-1', 'run-1', 'inv-1']));
    expect(Array.from(collector.coverages).sort()).toEqual(['cov-3', 'security-coverage--2']);
  });

  it('should also reach the containers an update moved a soft-check source away from', () => {
    const collector = newCollector();
    const run = { type: 'investigation-run', subject_id: 'case-incident--1', case_ids: ['case-incident--1'], extensions: { [STIX_EXT_OCTI]: { id: 'inv-1', type: 'InvestigationRun' } } };
    const event = streamEvent(run);
    // Before the update, the run was also attached to a second case
    (event.data as any).context = {
      patch: [{ op: 'remove', path: '/case_ids/1' }],
      reverse_patch: [{ op: 'add', path: '/case_ids/1', value: 'case-incident--2' }],
    };
    collectTimelineImpacts(event, collector);
    expect(Array.from(collector.references).sort()).toEqual(['case-incident--1', 'case-incident--2']);
    expect(run.case_ids).toEqual(['case-incident--1']);
    // A hunt run moved to another incident leaves the previous one
    const moved = newCollector();
    const huntEvent = streamEvent({ type: 'hunt-run', incident_id: 'incident-2', extensions: { [STIX_EXT_OCTI]: { id: 'run-1', type: 'Hunt-Run' } } });
    (huntEvent.data as any).context = { patch: [{ op: 'replace', path: '/incident_id', value: 'incident-2' }], reverse_patch: [{ op: 'replace', path: '/incident_id', value: 'incident-1' }] };
    collectTimelineImpacts(huntEvent, moved);
    expect(Array.from(moved.references).sort()).toEqual(['incident-1', 'incident-2']);
  });

  it('should reach the incidents related to the hunt of a run, before and after the update', () => {
    // Incidents read the runs of the hunts related to them: a run moved to another hunt leaves the incidents of the first
    const collector = newCollector();
    const event = streamEvent({ type: 'hunt-run', hunt_id: 'hunt-2', extensions: { [STIX_EXT_OCTI]: { id: 'run-1', type: 'Hunt-Run' } } });
    (event.data as any).context = { patch: [{ op: 'replace', path: '/hunt_id', value: 'hunt-2' }], reverse_patch: [{ op: 'replace', path: '/hunt_id', value: 'hunt-1' }] };
    collectTimelineImpacts(event, collector);
    expect(Array.from(collector.related).sort()).toEqual(['hunt-1', 'hunt-2', 'run-1']);
    expect(Array.from(collector.contained).sort()).toEqual(['hunt-1', 'hunt-2', 'run-1']);
  });

  it('should ignore inferred data and timeline objects', () => {
    const collector = newCollector();
    collectTimelineImpacts(streamEvent({ type: 'malware', extensions: { [STIX_EXT_OCTI]: { id: 'mal-1', type: 'Malware', is_inferred: true } } }), collector);
    collectTimelineImpacts(streamEvent({ type: 'timeline-event', extensions: { [STIX_EXT_OCTI]: { id: 'te-1', type: 'Timeline-Event' } } }), collector);
    collectTimelineImpacts(streamEvent({}), collector);
    expect(collector.contained.size + collector.related.size + collector.containers.size).toEqual(0);
  });
});

describe('Timeline consistency pass schedule', () => {
  const at = (iso: string) => Date.parse(iso);

  it('should run once a day after the configured hour', () => {
    // The first pass (backfill of an existing platform) never waits for the scheduled hour
    expect(isTimelineConsistencyPassDue(null, at('2026-10-03T01:00:00.000Z'), 2)).toBe(true);
    expect(isTimelineConsistencyPassDue(null, at('2026-10-03T02:00:00.000Z'), 2)).toBe(true);
    expect(isTimelineConsistencyPassDue(at('2026-10-03T00:30:00.000Z'), at('2026-10-03T01:00:00.000Z'), 2)).toBe(false);
    expect(isTimelineConsistencyPassDue(at('2026-10-02T02:00:05.000Z'), at('2026-10-03T03:00:00.000Z'), 2)).toBe(true);
    expect(isTimelineConsistencyPassDue(at('2026-10-03T02:00:05.000Z'), at('2026-10-03T23:00:00.000Z'), 2)).toBe(false);
  });

  it('should only schedule the containers changed since the last pass, never computed or older than the max age', () => {
    const filters = buildTimelineConsistencyFilters(at('2026-10-02T02:00:05.000Z'), at('2026-10-03T02:00:00.000Z'), 30);
    expect(filters.mode).toEqual('or');
    expect(filters.filters).toEqual([
      { key: ['updated_at'], operator: 'gte', values: ['2026-10-02T02:00:05.000Z'] },
      { key: ['x_opencti_timeline_anchors.computed_at'], operator: 'nil', values: [] },
      { key: ['x_opencti_timeline_anchors.computed_at'], operator: 'lt', values: ['2026-09-03T02:00:00.000Z'] },
    ]);
  });

  it('should look back one day on the first pass', () => {
    const filters = buildTimelineConsistencyFilters(null, at('2026-10-03T02:00:00.000Z'), 7);
    expect(filters.filters[0].values).toEqual(['2026-10-02T02:00:00.000Z']);
    expect(filters.filters[2].values).toEqual(['2026-09-26T02:00:00.000Z']);
  });

  it('should schedule every container of a type whose workflow changed, and every container for the task workflow', () => {
    const caseWorkflow = buildTimelineConsistencyFilters(at('2026-10-02T02:00:05.000Z'), at('2026-10-03T02:00:00.000Z'), 30, ['Case-Incident', 'Report']);
    expect(caseWorkflow.filters[3]).toEqual({ key: ['entity_type'], values: ['Case-Incident'] });
    const taskWorkflow = buildTimelineConsistencyFilters(at('2026-10-02T02:00:05.000Z'), at('2026-10-03T02:00:00.000Z'), 30, ['Task']);
    expect(taskWorkflow.filters[3]).toEqual({ key: ['entity_type'], values: ['Incident', 'Case-Incident', 'Case-Rfi', 'Case-Rft'] });
    expect(buildTimelineConsistencyFilters(at('2026-10-02T02:00:05.000Z'), at('2026-10-03T02:00:00.000Z'), 30, ['Report']).filters).toHaveLength(3);
  });

  it('should find the types whose statuses, published workflow definition or workflow setting changed since the last pass', () => {
    const lastRun = at('2026-10-02T02:00:00.000Z');
    const before = '2026-10-01T00:00:00.000Z';
    const after = '2026-10-02T10:00:00.000Z';
    const statuses = [{ type: 'Case-Rfi', updated_at: after }, { type: 'Case-Rft', updated_at: before }];
    const settings = [
      // A change of transitions only: the published definition moved, no status did
      { target_type: 'Case-Incident', workflow_id: 'definition-incident', updated_at: before },
      { target_type: 'Incident', workflow_id: 'definition-unchanged', updated_at: before },
      // The type was linked to another workflow
      { target_type: 'Task', workflow_id: null, updated_at: after },
      { target_type: 'Case-Rft', workflow_id: null, updated_at: before },
    ];
    const definitions = { 'definition-incident': { updated_at: after }, 'definition-unchanged': { updated_at: before } };
    expect(computeChangedWorkflowTypes(lastRun, statuses, settings, definitions).sort()).toEqual(['Case-Incident', 'Case-Rfi', 'Task']);
    expect(computeChangedWorkflowTypes(lastRun, [], [{ target_type: 'Incident', workflow_id: 'missing', updated_at: before }], {})).toEqual([]);
  });
});
