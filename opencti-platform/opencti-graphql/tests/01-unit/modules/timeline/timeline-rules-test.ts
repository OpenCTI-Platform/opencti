import { describe, expect, it } from 'vitest';
import {
  autopilotRule,
  computeAdversaryWindow,
  coverageResultRule,
  deploymentRule,
  deriveTimelineEvents,
  huntRunRule,
  RULE_TASK_CONTAINMENT,
  RULE_WORKFLOW_CLOSURE,
  TIMELINE_CORE_RULES,
  TIMELINE_SOFT_RULES,
  type TimelineDerivationInput,
  type TimelineElementData,
  toTimelineTime,
} from '../../../../src/modules/timeline/timeline-rules';

const element = (data: Partial<TimelineElementData> & { id: string; entity_type: string }): TimelineElementData => ({
  standard_id: `${data.entity_type.toLowerCase()}--${data.id}`,
  name: data.id,
  markings: [],
  ...data,
});

const buildInput = (overrides: Partial<TimelineDerivationInput> = {}): TimelineDerivationInput => ({
  container: {
    ...element({ id: 'case-1', entity_type: 'Case-Incident', name: 'Ransomware case', created: '2026-03-10T08:00:00.000Z' }),
    is_case: true,
    files: [],
  },
  entities: [],
  relationships: [],
  tasks: [],
  notes: [],
  opinions: [],
  reports: [],
  externalReferences: [],
  history: [],
  taskHistory: [],
  killChainPhases: new Map(),
  statuses: new Map(),
  soft: { coverageResults: [], coverageRelationships: [], huntRuns: [], deployments: [], investigationRuns: [] },
  securityPlatformType: 'SecurityPlatform',
  ...overrides,
});

const derive = (input: TimelineDerivationInput) => deriveTimelineEvents(input, [...TIMELINE_CORE_RULES, ...TIMELINE_SOFT_RULES], (ruleId, error) => {
  throw new Error(`Rule ${ruleId} failed: ${error}`);
});

describe('Timeline time parsing', () => {
  it('should ignore empty values and the open interval sentinels', () => {
    expect(toTimelineTime(null)).toBeNull();
    expect(toTimelineTime('')).toBeNull();
    expect(toTimelineTime('not a date')).toBeNull();
    expect(toTimelineTime('1970-01-01T00:00:00.000Z')).toBeNull();
    expect(toTimelineTime('5138-11-16T09:46:40.000Z')).toBeNull();
    expect(toTimelineTime('2026-03-10T08:00:00.000Z')).toEqual(Date.parse('2026-03-10T08:00:00.000Z'));
  });
});

describe('Timeline adversary rules', () => {
  it('should give techniques exact windows from uses relationships', () => {
    const technique = element({ id: 'ap-1', entity_type: 'Attack-Pattern', name: 'Phishing', kill_chain_phase_ids: ['kc-1'] });
    const uses = element({
      id: 'rel-1',
      entity_type: 'uses',
      relationship_type: 'uses',
      from_id: 'is-1',
      to_id: 'ap-1',
      start_time: '2026-03-01T10:00:00.000Z',
      stop_time: '2026-03-02T10:00:00.000Z',
      markings: ['marking-rel'],
    });
    const events = derive(buildInput({
      entities: [technique],
      relationships: [uses],
      killChainPhases: new Map([['kc-1', { id: 'kc-1', phase_name: 'initial-access', kill_chain_name: 'mitre-attack', order: 3 }]]),
    })).filter((e) => e.kind === 'technique_used');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      lane: 'adversary',
      time_precision: 'exact',
      event_time: '2026-03-01T10:00:00.000Z',
      event_end_time: '2026-03-02T10:00:00.000Z',
      element_id: 'ap-1',
      ordering_hint: 3,
    });
    expect(events[0].markings).toContain('marking-rel');
    expect(events[0].description).toContain('initial-access');
  });

  it('should place techniques without times in kill chain order over the adversary window, flagged approximate', () => {
    const phases = new Map([
      ['kc-recon', { id: 'kc-recon', phase_name: 'reconnaissance', kill_chain_name: 'mitre-attack', order: 1 }],
      ['kc-impact', { id: 'kc-impact', phase_name: 'impact', kill_chain_name: 'mitre-attack', order: 14 }],
    ]);
    const impact = element({ id: 'ap-impact', entity_type: 'Attack-Pattern', name: 'Data Encrypted', kill_chain_phase_ids: ['kc-impact'] });
    const recon = element({ id: 'ap-recon', entity_type: 'Attack-Pattern', name: 'Active Scanning', kill_chain_phase_ids: ['kc-recon'] });
    const observed = element({ id: 'od-1', entity_type: 'Observed-Data', first_observed: '2026-03-01T00:00:00.000Z', last_observed: '2026-03-05T00:00:00.000Z' });
    const input = buildInput({ entities: [impact, recon, observed], killChainPhases: phases });
    expect(computeAdversaryWindow(input)).toEqual({ from: Date.parse('2026-03-01T00:00:00.000Z'), to: Date.parse('2026-03-05T00:00:00.000Z') });
    const techniques = derive(input).filter((e) => e.kind === 'technique_used');
    expect(techniques).toHaveLength(2);
    expect(techniques.every((e) => e.time_precision === 'approximate')).toBe(true);
    const reconEvent = techniques.find((e) => e.element_id === 'ap-recon');
    const impactEvent = techniques.find((e) => e.element_id === 'ap-impact');
    expect(Date.parse(reconEvent?.event_time as string)).toBeLessThan(Date.parse(impactEvent?.event_time as string));
    expect(Date.parse(reconEvent?.event_time as string)).toBeGreaterThan(Date.parse('2026-03-01T00:00:00.000Z'));
    expect(Date.parse(impactEvent?.event_time as string)).toBeLessThan(Date.parse('2026-03-05T00:00:00.000Z'));
  });

  it('should derive first and last seen of incidents, infrastructures, malware and threats', () => {
    const input = buildInput({
      entities: [
        element({ id: 'infra-1', entity_type: 'Infrastructure', first_seen: '2026-02-01T00:00:00.000Z', last_seen: '2026-02-10T00:00:00.000Z' }),
        element({ id: 'mal-1', entity_type: 'Malware', first_seen: '2026-02-02T00:00:00.000Z', last_seen: '5138-11-16T09:46:40.000Z' }),
        element({ id: 'is-1', entity_type: 'Intrusion-Set', first_seen: '1970-01-01T00:00:00.000Z', last_seen: '5138-11-16T09:46:40.000Z' }),
        element({ id: 'inc-1', entity_type: 'Incident', first_seen: '2026-02-03T00:00:00.000Z' }),
      ],
    });
    const events = derive(input);
    expect(events.find((e) => e.element_id === 'infra-1')).toMatchObject({ kind: 'infrastructure_seen', event_end_time: '2026-02-10T00:00:00.000Z' });
    expect(events.find((e) => e.element_id === 'mal-1')).toMatchObject({ kind: 'malware_seen', event_end_time: null });
    expect(events.find((e) => e.element_id === 'is-1')).toBeUndefined();
    expect(events.find((e) => e.element_id === 'inc-1')).toMatchObject({ kind: 'incident_seen', lane: 'adversary' });
  });

  it('should start an incident timeline with the incident itself', () => {
    const input = buildInput({
      container: {
        ...element({ id: 'incident-1', entity_type: 'Incident', first_seen: '2026-04-01T00:00:00.000Z', last_seen: '2026-04-03T00:00:00.000Z' }),
        is_case: false,
        files: [],
      },
    });
    const events = derive(input);
    expect(events.find((e) => e.kind === 'incident_seen')).toMatchObject({ element_id: 'incident-1' });
    expect(events.find((e) => e.kind === 'case_opened')).toBeUndefined();
  });

  it('should put platform sightings in the detection lane and other sightings in the adversary lane', () => {
    const input = buildInput({
      relationships: [
        element({ id: 's-platform', entity_type: 'stix-sighting-relationship', from_name: 'evil.com', to_type: 'SecurityPlatform', to_name: 'EDR', first_seen: '2026-03-03T00:00:00.000Z', attribute_count: 4 }),
        element({ id: 's-org', entity_type: 'stix-sighting-relationship', from_name: 'evil.com', to_type: 'Organization', to_name: 'ACME', first_seen: '2026-03-02T00:00:00.000Z' }),
      ],
    });
    const sightings = derive(input).filter((e) => e.kind === 'sighting');
    expect(sightings.find((e) => e.element_id === 's-platform')).toMatchObject({ lane: 'detection', description: '4 sightings' });
    expect(sightings.find((e) => e.element_id === 's-org')).toMatchObject({ lane: 'adversary' });
  });

  it('should derive observation windows of observed data', () => {
    const input = buildInput({
      entities: [element({ id: 'od-1', entity_type: 'Observed-Data', first_observed: '2026-03-01T00:00:00.000Z', last_observed: '2026-03-01T06:00:00.000Z', number_observed: 1 })],
    });
    expect(derive(input).find((e) => e.kind === 'observed_window')).toMatchObject({ description: '1 observation', event_end_time: '2026-03-01T06:00:00.000Z' });
  });
});

describe('Timeline evidence rules', () => {
  it('should derive indicators, reports, external references and files', () => {
    const input = buildInput({
      entities: [element({ id: 'ind-1', entity_type: 'Indicator', valid_from: '2026-03-01T00:00:00.000Z', valid_until: '2026-06-01T00:00:00.000Z' })],
      reports: [element({ id: 'rep-1', entity_type: 'Report', published: '2026-03-04T00:00:00.000Z' })],
      externalReferences: [element({ id: 'ref-1', entity_type: 'External-Reference', source_name: 'CERT', external_id: 'CERT-1', created: '2026-03-05T00:00:00.000Z', url: 'https://cert.example' })],
      container: {
        ...element({ id: 'case-1', entity_type: 'Case-Incident', created: '2026-03-10T08:00:00.000Z' }),
        is_case: true,
        files: [{ id: 'import/Case-Incident/case-1/memo.pdf', name: 'memo.pdf', version: '2026-03-11T00:00:00.000Z', mime_type: 'application/pdf', markings: ['tlp-amber'] }],
      },
    });
    const events = derive(input);
    expect(events.find((e) => e.kind === 'indicator_valid')).toMatchObject({ lane: 'evidence', event_end_time: '2026-06-01T00:00:00.000Z' });
    expect(events.find((e) => e.kind === 'report_published')).toMatchObject({ event_time: '2026-03-04T00:00:00.000Z', time_precision: 'exact' });
    expect(events.find((e) => e.kind === 'reference_published')).toMatchObject({ name: 'Reference CERT (CERT-1)', time_precision: 'day' });
    expect(events.find((e) => e.kind === 'file_uploaded')).toMatchObject({ element_id: 'case-1', markings: ['tlp-amber'], discriminator: 'import/Case-Incident/case-1/memo.pdf' });
  });
});

describe('Timeline response rules', () => {
  const statuses = new Map([
    ['status-new', { id: 'status-new', name: 'NEW', order: 1, type: 'Case-Incident', is_final: false }],
    ['status-closed', { id: 'status-closed', name: 'CLOSED', order: 9, type: 'Case-Incident', is_final: true }],
    ['task-open', { id: 'task-open', name: 'OPEN', order: 1, type: 'Task', is_final: false }],
    ['task-done', { id: 'task-done', name: 'DONE', order: 2, type: 'Task', is_final: true }],
  ]);

  it('should open the case and read workflow transitions and assignments from the history', () => {
    const input = buildInput({
      statuses,
      history: [{
        id: 'h-1',
        timestamp: '2026-03-12T00:00:00.000Z',
        event_scope: 'update',
        entity_id: 'case-1',
        entity_type: 'Case-Incident',
        entity_name: 'Ransomware case',
        message: 'replaces status',
        user_id: 'user-1',
        markings: [],
        changes: [
          { field: 'Case-Incident--x_opencti_workflow_id', added: [{ raw: 'status-closed' }], removed: [{ raw: 'status-new' }] },
          { field: 'Case-Incident--objectAssignee', added: [{ raw: 'user-2', name: 'Jane' }], removed: [] },
        ],
      }],
    });
    const events = derive(input);
    expect(events.find((e) => e.kind === 'case_opened')).toMatchObject({ lane: 'response', event_time: '2026-03-10T08:00:00.000Z' });
    expect(events.find((e) => e.kind === 'status_changed')).toMatchObject({ rule_id: RULE_WORKFLOW_CLOSURE, name: 'Status changed to CLOSED', description: 'From NEW', creator_ids: ['user-1'] });
    expect(events.find((e) => e.kind === 'assigned')).toMatchObject({ name: 'Assignee added: Jane' });
  });

  it('should derive task creation, due date and completion, containment tasks included', () => {
    const input = buildInput({
      statuses,
      tasks: [
        element({ id: 'task-1', entity_type: 'Task', name: 'Isolate hosts', created: '2026-03-10T09:00:00.000Z', due_date: '2026-03-11T09:00:00.000Z', workflow_id: 'task-done', labels: ['Containment'] }),
        element({ id: 'task-2', entity_type: 'Task', name: 'Collect logs', created: '2026-03-10T10:00:00.000Z', workflow_id: 'task-open' }),
      ],
      taskHistory: [{
        id: 'th-1',
        timestamp: '2026-03-10T15:00:00.000Z',
        event_scope: 'update',
        entity_id: 'task-1',
        entity_type: 'Task',
        entity_name: 'Isolate hosts',
        message: 'replaces status',
        markings: [],
        changes: [{ field: 'Task--x_opencti_workflow_id', added: [{ raw: 'task-done' }], removed: [{ raw: 'task-open' }] }],
      }],
    });
    const events = derive(input);
    expect(events.filter((e) => e.kind === 'task_created')).toHaveLength(2);
    expect(events.filter((e) => e.kind === 'task_due')).toHaveLength(1);
    const completions = events.filter((e) => e.kind === 'task_completed');
    expect(completions).toHaveLength(1);
    expect(completions[0]).toMatchObject({ rule_id: RULE_TASK_CONTAINMENT, event_time: '2026-03-10T15:00:00.000Z', time_precision: 'exact' });
  });

  it('should fall back to the task update date when the history has no transition', () => {
    const input = buildInput({
      statuses,
      tasks: [element({ id: 'task-1', entity_type: 'Task', name: 'Patch', created: '2026-03-10T09:00:00.000Z', updated_at: '2026-03-12T09:00:00.000Z', workflow_id: 'task-done' })],
    });
    expect(derive(input).find((e) => e.kind === 'task_completed')).toMatchObject({ rule_id: 'task-lifecycle', time_precision: 'approximate', event_time: '2026-03-12T09:00:00.000Z' });
  });

  it('should derive notes and opinions', () => {
    const input = buildInput({
      notes: [element({ id: 'note-1', entity_type: 'Note', name: 'Initial triage', created: '2026-03-10T11:00:00.000Z' })],
      opinions: [element({ id: 'op-1', entity_type: 'Opinion', name: 'agree', created: '2026-03-10T12:00:00.000Z' })],
    });
    const events = derive(input);
    expect(events.find((e) => e.kind === 'note_added')).toMatchObject({ name: 'Note Initial triage' });
    expect(events.find((e) => e.kind === 'opinion_added')).toMatchObject({ name: 'Opinion agree' });
  });
});

describe('Timeline knowledge rules', () => {
  it('should group objects added by history entry and derive relations and merges', () => {
    const names = Array.from({ length: 12 }, (_, i) => ({ raw: `obj-${i}`, name: `Object ${i}` }));
    const input = buildInput({
      relationships: [element({ id: 'rel-9', entity_type: 'uses', relationship_type: 'uses', from_name: 'APT', to_name: 'Phishing', created_at: '2026-03-10T13:00:00.000Z' })],
      history: [
        { id: 'h-objects', timestamp: '2026-03-10T12:30:00.000Z', event_scope: 'update', entity_id: 'case-1', entity_type: 'Case-Incident', entity_name: 'x', message: 'adds', markings: [], changes: [{ field: 'Case-Incident--objects', added: names, removed: [] }] },
        { id: 'h-merge', timestamp: '2026-03-10T14:00:00.000Z', event_scope: 'merge', entity_id: 'obj-1', entity_type: 'Malware', entity_name: 'Ryuk', message: 'merges Malware `Ryuk 2` in `Ryuk`', markings: [], changes: [] },
      ],
    });
    const events = derive(input);
    const added = events.find((e) => e.kind === 'object_added');
    expect(added).toMatchObject({ name: '12 objects added', element_id: null, discriminator: 'h-objects', lane: 'knowledge' });
    expect(added?.description).toContain('and 2 more');
    expect(events.find((e) => e.kind === 'relation_created')).toMatchObject({ name: 'APT uses Phishing' });
    expect(events.find((e) => e.kind === 'merged')).toMatchObject({ element_id: 'obj-1', name: 'Ryuk merged' });
  });
});

describe('Timeline soft-check rules', () => {
  it('should derive coverage results, hunt runs, deployments and autopilot steps from their sources', () => {
    const input = buildInput({
      entities: [element({ id: 'hunt-1', entity_type: 'Hunt', name: 'Cobalt beacons' }), element({ id: 'malware-1', entity_type: 'Malware', name: 'Cobalt Strike' })],
      soft: {
        coverageResults: [element({ id: 'cov-res-1', entity_type: 'Security-Coverage-Result', name: 'Weekly', extra: { coverage_last_result: '2026-03-15T00:00:00.000Z', coverage_information: [{ coverage_name: 'detection', coverage_score: 80 }] } })],
        coverageRelationships: [element({ id: 'has-cov-1', entity_type: 'has-covered', to_name: 'Phishing', updated_at: '2026-03-15T01:00:00.000Z', extra: { coverage_information: [{ coverage_name: 'prevention', coverage_score: 40 }] } })],
        huntRuns: [
          element({ id: 'run-1', entity_type: 'Hunt-Run', name: 'schedule run (completed)', created_at: '2026-03-14T00:00:00.000Z', extra: { hunt_id: 'hunt-1', hunt_run_status: 'completed', hits_count: 3, verdict: 'true_positive' } }),
          element({ id: 'run-2', entity_type: 'Hunt-Run', name: 'manual run (failed)', extra: { hunt_id: 'hunt-out-of-scope', incident_id: 'case-1', started_at: '2026-03-14T02:00:00.000Z', hunt_run_status: 'failed' } }),
        ],
        deployments: [element({ id: 'dep-1', entity_type: 'deployed-on', from_name: 'evil.com', to_name: 'Sentinel', extra: { deployed_at: '2026-03-13T00:00:00.000Z', deployment_status: 'active', hit_count: 2 } })],
        investigationRuns: [element({
          id: 'inv-1',
          entity_type: 'InvestigationRun',
          name: 'Autopilot',
          extra: {
            started_at: '2026-03-16T00:00:00.000Z',
            completed_at: '2026-03-16T01:00:00.000Z',
            run_status: 'completed',
            steps: [
              { id: 'step-a', tool: 'enrich', description: 'Enrichment wave 1', status: 'succeeded', started_at: '2026-03-16T00:10:00.000Z', duration_ms: 60000 },
              { id: 'step-b', tool: 'search' },
            ],
            timeline: [
              { ts: '2026-03-01T00:00:00.000Z', entity_id: 'malware-1', entity_type: 'Malware', name: 'Cobalt Strike', event: 'first_seen' },
              { ts: '2026-02-20T00:00:00.000Z', entity_id: 'ip-9', entity_type: 'IPv4-Addr', name: '10.0.0.9', event: 'first_seen' },
            ],
          },
        })],
      },
    });
    const events = deriveTimelineEvents(input, [coverageResultRule, huntRunRule, deploymentRule, autopilotRule], () => {});
    expect(events.find((e) => e.element_id === 'cov-res-1')).toMatchObject({ kind: 'coverage_result', lane: 'detection', description: 'detection: 80%' });
    expect(events.find((e) => e.element_id === 'has-cov-1')).toMatchObject({ name: 'Coverage of Phishing', description: 'prevention: 40%' });
    const huntRuns = events.filter((e) => e.kind === 'hunt_run');
    expect(huntRuns[0]).toMatchObject({ element_id: 'hunt-1', element_type: 'Hunt', discriminator: 'run-1', name: 'Hunt run Cobalt beacons', description: 'Status: completed - 3 hits - Verdict: true_positive' });
    // The hunt of the second run is not in scope: the event points to the run itself
    expect(huntRuns[1]).toMatchObject({ element_id: 'run-2', element_type: 'Hunt-Run', name: 'Hunt run manual run (failed)', description: 'Status: failed' });
    expect(events.find((e) => e.kind === 'deployment')).toMatchObject({ name: 'evil.com deployed on Sentinel', lane: 'detection' });
    const autopilot = events.filter((e) => e.kind === 'autopilot_step');
    expect(autopilot).toHaveLength(3);
    expect(autopilot[0]).toMatchObject({ name: 'Case Autopilot run Autopilot', description: 'Status: completed', event_end_time: '2026-03-16T01:00:00.000Z' });
    expect(autopilot[1]).toMatchObject({ name: 'Enrichment wave 1', discriminator: 'inv-1-step-step-a', description: 'Tool: enrich - Status: succeeded', event_end_time: '2026-03-16T00:11:00.000Z' });
    // Findings about elements in scope are already derived by the core rules
    expect(autopilot[2]).toMatchObject({ lane: 'evidence', element_id: 'ip-9', name: '10.0.0.9 first seen', discriminator: 'inv-1-finding-ip-9-first_seen' });
  });

  it('should skip unavailable rules and isolate failing rules', () => {
    const failures: string[] = [];
    const events = deriveTimelineEvents(buildInput(), [
      { id: 'unavailable', label: 'x', kinds: ['hunt_run'], isAvailable: () => false, derive: () => {
        throw new Error('should not run');
      } },
      { id: 'failing', label: 'x', kinds: ['milestone'], derive: () => {
        throw new Error('boom');
      } },
      ...TIMELINE_CORE_RULES,
    ], (ruleId) => failures.push(ruleId));
    expect(failures).toEqual(['failing']);
    expect(events.find((e) => e.kind === 'case_opened')).toBeDefined();
  });
});
