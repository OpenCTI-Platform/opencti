import { Readable } from 'node:stream';
import type { FileHandle } from 'fs/promises';
import { describe, expect, it } from 'vitest';
import { computeHuntPlaybookOutcome, HUNT_PLAYBOOK_MAX_CONTEXT_LENGTH, isHuntRunGroupSettled, isStorableHuntPlaybookContext } from '../../../../src/modules/hunt/hunt-playbook';
import { huntTriageRunPayload, isHuntRunFinalized } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import { isHuntStepNode, matchHuntResultFilter } from '../../../../src/modules/playbook/components/hunt-result-filter-component';
import {
  eventTouchedRefs,
  indexStandingCandidates,
  isStandingHuntTriggered,
  matchStandingEvents,
  type StandingCandidate,
  type StandingMatch,
} from '../../../../src/modules/hunt/hunt-automation';
import { FilterMode } from '../../../../src/generated/graphql';
import { HUNT_PACK_MAX_BYTES, huntExtensionDefinition, parseHuntPack, toPackHunt } from '../../../../src/modules/hunt/hunt-pack';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import type { BasicStoreEntityHunt, StixHunt } from '../../../../src/modules/hunt/hunt-types';
import type { DataEvent } from '../../../../src/types/event';
import { STIX_EXT_OCTI_HUNT } from '../../../../src/types/stix-2-1-extensions';
import { testContext } from '../../../utils/testQuery';

const run = (overrides: Partial<BasicStoreEntityHuntRun>): BasicStoreEntityHuntRun => ({
  internal_id: `run-${Math.random()}`,
  hunt_id: 'hunt-1',
  connector_id: 'connector-1',
  hunt_run_status: 'completed',
  hunt_run_trigger: 'playbook',
  hunt_run_mode: 'execute',
  verdict: 'pending',
  attempt: 1,
  hits_count: 0,
  ...overrides,
} as BasicStoreEntityHuntRun);

const filterConfiguration = { verdicts: ['true_positive', 'pending'], use_triage_proposals: true, min_hits: 1, require_incident: false };

describe('Hunt run finalization', () => {
  it('should finalize again a terminated executed run whose verdict was never recorded', () => {
    expect(isHuntRunFinalized({ hunt_run_mode: 'execute', hunt_run_status: 'completed', verdict_source: undefined })).toBe(false);
    expect(isHuntRunFinalized({ hunt_run_mode: 'execute', hunt_run_status: 'timeout', verdict_source: undefined })).toBe(false);
    expect(isHuntRunFinalized({ hunt_run_mode: 'execute', hunt_run_status: 'completed', verdict_source: 'auto' })).toBe(true);
    expect(isHuntRunFinalized({ hunt_run_mode: 'execute', hunt_run_status: 'failed', verdict_source: 'analyst' })).toBe(true);
    expect(isHuntRunFinalized({ hunt_run_mode: 'execute', hunt_run_status: 'running', verdict_source: undefined })).toBe(true);
    expect(isHuntRunFinalized({ hunt_run_mode: 'preview', hunt_run_status: 'completed', verdict_source: undefined })).toBe(true);
  });
});

describe('Hunt run triage request', () => {
  it('should tell the triage agent when the counts of the run are lower bounds', () => {
    const partial = huntTriageRunPayload(run({ hits_count: 0, results_truncated: true }), 'Splunk prod');
    expect(partial).toMatchObject({ hits_count: 0, results_truncated: true, security_platform: 'Splunk prod' });
    expect(huntTriageRunPayload(run({ hits_count: 0, results_truncated: false }), 'Splunk prod')).toMatchObject({ hits_count: 0, results_truncated: false });
    // A connector that did not state the completeness of its results: unknown, never complete
    expect(huntTriageRunPayload(run({ hits_count: 4 }), undefined)).toMatchObject({ hits_count: 4, results_truncated: null, security_platform: 'internet' });
    // Nor does it count entities it did not report
    expect(huntTriageRunPayload(run({ hits_count: 4 }), undefined).distinct_entities).toBeNull();
    expect(huntTriageRunPayload(run({ hits_count: 4, distinct_entities: 0 }), undefined).distinct_entities).toEqual(0);
  });
});

describe('Hunt playbook outcome', () => {
  it('should only count the last attempt of a retried run', () => {
    const outcome = computeHuntPlaybookOutcome([
      run({ hunt_run_status: 'failed', verdict: 'inconclusive', attempt: 1 }),
      run({ hunt_run_status: 'completed', verdict: 'pending', attempt: 2, hits_count: 7, incident_id: 'incident-1' }),
      run({ connector_id: 'connector-2', verdict: 'benign', hits_count: 0 }),
    ]);
    expect(outcome.runs_count).toBe(2);
    expect(outcome.completed_count).toBe(2);
    expect(outcome.hits_total).toBe(7);
    expect(outcome.verdicts.sort()).toEqual(['benign', 'pending']);
    expect(outcome.incident_ids).toEqual(['incident-1']);
  });

  it('should count the runs of two steps executing the same hunt on the same connector separately', () => {
    const outcome = computeHuntPlaybookOutcome([
      run({ playbook_step_id: 'step-1', hits_count: 4 }),
      run({ playbook_step_id: 'step-2', hits_count: 3 }),
      run({ playbook_step_id: 'step-2', hunt_run_status: 'failed', attempt: 1, time_window_start: '2026-10-01T00:00:00Z' }),
      run({ playbook_step_id: 'step-2', attempt: 2, hits_count: 5, time_window_start: '2026-10-01T00:00:00Z' }),
    ]);
    expect(outcome.runs_count).toBe(3);
    expect(outcome.hits_total).toBe(12);
  });

  it('should use the triage proposals of pending runs', () => {
    const outcome = computeHuntPlaybookOutcome([run({ verdict: 'pending', verdict_proposal: 'benign', hits_count: 3 })]);
    expect(outcome.verdicts).toEqual(['pending']);
    expect(outcome.proposed_verdicts).toEqual(['benign']);
    expect(matchHuntResultFilter(outcome, filterConfiguration)).toBe(false);
    expect(matchHuntResultFilter(outcome, { ...filterConfiguration, use_triage_proposals: false })).toBe(true);
  });

  it('should require every configured condition', () => {
    const outcome = computeHuntPlaybookOutcome([run({ verdict: 'pending', hits_count: 2 })]);
    expect(matchHuntResultFilter(outcome, filterConfiguration)).toBe(true);
    expect(matchHuntResultFilter(outcome, { ...filterConfiguration, min_hits: 3 })).toBe(false);
    expect(matchHuntResultFilter(outcome, { ...filterConfiguration, require_incident: true })).toBe(false);
    expect(matchHuntResultFilter(outcome, { ...filterConfiguration, verdicts: [] })).toBe(true);
    expect(matchHuntResultFilter(outcome, { ...filterConfiguration, verdicts: ['benign'] })).toBe(false);
    expect(matchHuntResultFilter(computeHuntPlaybookOutcome([]), { ...filterConfiguration, verdicts: [], min_hits: 0 })).toBe(false);
  });

  it('should read the runs of the previous step only when it is a hunt step', () => {
    const node = (id: string, component_id: string) => ({ id, name: id, position: { x: 0, y: 0 }, component_id, configuration: '{}' });
    const definition = JSON.stringify({
      nodes: [node('hunt-step', 'PLAYBOOK_HUNT_COMPONENT'), node('enrich-step', 'PLAYBOOK_CONNECTOR_COMPONENT')],
      links: [],
    });
    expect(isHuntStepNode(definition, 'hunt-step')).toBe(true);
    expect(isHuntStepNode(definition, 'enrich-step')).toBe(false);
    expect(isHuntStepNode(definition, 'unknown-step')).toBe(false);
    expect(isHuntStepNode(undefined, 'hunt-step')).toBe(false);
  });

  it('should settle a group once every run is terminated without planned retry', () => {
    expect(isHuntRunGroupSettled([run({ hunt_run_status: 'completed' }), run({ hunt_run_status: 'timeout' })])).toBe(true);
    expect(isHuntRunGroupSettled([run({ hunt_run_status: 'running' })])).toBe(false);
    expect(isHuntRunGroupSettled([run({ hunt_run_status: 'failed', next_retry_at: '2026-10-03T10:00:00.000Z' })])).toBe(false);
  });

  it('should let a step wait on its runs only when its whole context fits on its leader run', () => {
    const bundleOf = (length: number) => JSON.stringify({ id: 'bundle--1', type: 'bundle', objects: [{ id: 'note--1', content: 'x'.repeat(length) }] });
    const playbookContext = (bundle: string, previousBundle: string) => ({
      playbook_id: 'playbook-1',
      step_id: 'step-1',
      previous_step_id: 'step-0',
      execution_id: 'execution-1',
      event_id: 'event-1',
      data_instance_id: 'malware--1',
      execution_start: '2026-10-07T03:00:00.000Z',
      include_results: true,
      bundle,
      previous_bundle: previousBundle,
    });
    const small = bundleOf(1024);
    const half = bundleOf(HUNT_PLAYBOOK_MAX_CONTEXT_LENGTH / 2);
    expect(isStorableHuntPlaybookContext(playbookContext(small, small))).toBe(true);
    // Each bundle alone is under the limit, the stored context is not
    expect(half.length).toBeLessThan(HUNT_PLAYBOOK_MAX_CONTEXT_LENGTH);
    expect(isStorableHuntPlaybookContext(playbookContext(half, half))).toBe(false);
    expect(isStorableHuntPlaybookContext(playbookContext(small, half))).toBe(true);
  });
});

describe('Standing hunt triggers', () => {
  const candidate = (refIds: string[]) => ({ hunt: { internal_id: 'hunt-1' } as BasicStoreEntityHunt, filters: null, refIds: new Set(refIds), rising: false });

  it('should collect the refs of created objects', () => {
    const event = {
      type: 'create',
      data: { id: 'relationship--1', type: 'relationship', source_ref: 'intrusion-set--1', target_ref: 'attack-pattern--1' },
    } as unknown as DataEvent;
    expect(eventTouchedRefs(event)).toEqual(['intrusion-set--1', 'attack-pattern--1']);
  });

  it('should collect the refs added by an update only', () => {
    const event = {
      type: 'update',
      data: { id: 'report--1', type: 'report', object_refs: ['attack-pattern--old', 'attack-pattern--new'] },
      context: {
        patch: [
          { op: 'add', path: '/object_refs/1', value: 'attack-pattern--new' },
          { op: 'replace', path: '/name', value: 'renamed' },
          { op: 'remove', path: '/object_refs/0' },
        ],
        reverse_patch: [],
        changes: [],
      },
    } as unknown as DataEvent;
    expect(eventTouchedRefs(event)).toEqual(['attack-pattern--new']);
  });

  it('should trigger a hunt without filters when the knowledge around it moves', async () => {
    const reportAddsTechnique = {
      type: 'update',
      data: { id: 'report--1', type: 'report' },
      context: { patch: [{ op: 'add', path: '/object_refs/3', value: 'attack-pattern--t1059' }], reverse_patch: [], changes: [] },
    } as unknown as DataEvent;
    expect(await isStandingHuntTriggered(testContext, candidate(['attack-pattern--t1059']), reportAddsTechnique)).toBe(true);
    expect(await isStandingHuntTriggered(testContext, candidate(['attack-pattern--other']), reportAddsTechnique)).toBe(false);
    const sighting = { type: 'create', data: { id: 'sighting--1', type: 'sighting', sighting_of_ref: 'indicator--1', where_sighted_refs: ['identity--1'] } } as unknown as DataEvent;
    expect(await isStandingHuntTriggered(testContext, candidate(['indicator--1']), sighting)).toBe(true);
  });

  const filteredCandidate = (huntId: string): StandingCandidate => ({
    hunt: { internal_id: huntId } as BasicStoreEntityHunt,
    filters: { mode: FilterMode.And, filters: [{ key: ['entity_type'], values: ['Report'] }], filterGroups: [] },
    refIds: new Set(),
    rising: false,
  });
  const streamEvent = (id: string, data: Record<string, unknown>) => ({ id, event: 'create', data: { type: 'create', origin: {}, data } as unknown as DataEvent });

  it('should find the hunts without filters from the refs of an event, without evaluating them', async () => {
    const byRef = { hunt: { internal_id: 'hunt-ref' } as BasicStoreEntityHunt, filters: null, refIds: new Set(['indicator--1']), rising: false };
    const indexed = indexStandingCandidates([byRef, filteredCandidate('hunt-filter')]);
    const match: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    const evaluated: string[] = [];
    await matchStandingEvents(indexed, [streamEvent('1-0', { id: 'sighting--1', type: 'sighting', sighting_of_ref: 'indicator--1' })], match, {
      budget: 10,
      isIgnored: () => false,
      evaluate: async (candidate) => {
        evaluated.push(candidate.hunt.internal_id);
        return false;
      },
    });
    expect(Array.from(match.triggered.keys())).toEqual(['hunt-ref']);
    expect(evaluated).toEqual(['hunt-filter']);
    expect(match).toMatchObject({ evaluations: 1, budgetSpent: false, matchedEventId: '1-0' });
  });

  it('should find a hunt from any ref of a large container, past the first thousands', async () => {
    const objectRefs = Array.from({ length: 2501 }, (_, index) => `indicator--${index}`);
    const byRef = { hunt: { internal_id: 'hunt-last-ref' } as BasicStoreEntityHunt, filters: null, refIds: new Set(['indicator--2500']), rising: false };
    const match: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    await matchStandingEvents(indexStandingCandidates([byRef]), [streamEvent('1-0', { id: 'report--1', type: 'report', object_refs: objectRefs })], match, {
      budget: 10,
      isIgnored: () => false,
      evaluate: async () => false,
    });
    expect(Array.from(match.triggered.keys())).toEqual(['hunt-last-ref']);
    expect(match.matchedEventId).toEqual('1-0');
  });

  it('should stop matching before the event that would exceed the filter budget', async () => {
    const indexed = indexStandingCandidates([filteredCandidate('hunt-a'), filteredCandidate('hunt-b'), filteredCandidate('hunt-c')]);
    const events = ['1-0', '2-0', '3-0'].map((id) => streamEvent(id, { id: `report--${id}`, type: 'report' }));
    const options = { budget: 4, isIgnored: () => false, evaluate: async () => false };
    const first: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    await matchStandingEvents(indexed, events, first, options);
    expect(first).toMatchObject({ evaluations: 3, budgetSpent: true, matchedEventId: '1-0' });
    expect(first.partial).toBeUndefined();
    // The next tick resumes from the event after the last one fully matched
    const next: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    await matchStandingEvents(indexed, events.slice(1), next, { ...options, budget: 6 });
    expect(next).toMatchObject({ evaluations: 6, budgetSpent: false, matchedEventId: '3-0' });
    // A triggered hunt is not evaluated again, and ignored events cost nothing
    const triggered: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    await matchStandingEvents(indexed, events, triggered, { budget: 100, isIgnored: (event) => event.data.id === 'report--2-0', evaluate: async (candidate) => candidate.hunt.internal_id === 'hunt-a' });
    expect(triggered.evaluations).toEqual(5);
    expect(Array.from(triggered.triggered.keys())).toEqual(['hunt-a']);
  });

  it('should match an event needing more evaluations than the budget over several ticks, never exceeding it', async () => {
    const indexed = indexStandingCandidates(['hunt-e', 'hunt-c', 'hunt-a', 'hunt-d', 'hunt-b'].map(filteredCandidate));
    const events = ['1-0', '2-0'].map((id) => streamEvent(id, { id: `report--${id}`, type: 'report' }));
    const evaluated: string[] = [];
    const options = {
      budget: 2,
      isIgnored: () => false,
      evaluate: async (candidate: StandingCandidate, event: DataEvent) => {
        evaluated.push(`${event.data.id}:${candidate.hunt.internal_id}`);
        return candidate.hunt.internal_id === 'hunt-d';
      },
    };
    // The first tick evaluates the first event up to the budget and stays before it
    const first: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    await matchStandingEvents(indexed, events, first, options);
    expect(first).toMatchObject({ evaluations: 2, budgetSpent: true, matchedEventId: null, partial: { eventId: '1-0', afterHuntId: 'hunt-b' } });
    // The next ticks resume the event after the last hunt evaluated, then move on
    const second: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    await matchStandingEvents(indexed, events, second, { ...options, resume: first.partial });
    expect(second).toMatchObject({ evaluations: 2, budgetSpent: true, matchedEventId: null, partial: { eventId: '1-0', afterHuntId: 'hunt-d' } });
    expect(Array.from(second.triggered.keys())).toEqual(['hunt-d']);
    const third: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null };
    await matchStandingEvents(indexed, events, third, { ...options, resume: second.partial });
    expect(third).toMatchObject({ evaluations: 1, budgetSpent: true, matchedEventId: '1-0' });
    expect(third.partial).toBeUndefined();
    expect(evaluated).toEqual(['hunt-a', 'hunt-b', 'hunt-c', 'hunt-d', 'hunt-e'].map((huntId) => `report--1-0:${huntId}`));
  });
});

describe('Hunt packs', () => {
  const upload = (chunks: Iterable<Buffer | string>) => Promise.resolve({ createReadStream: () => Readable.from(chunks) } as unknown as FileHandle);

  it('should read a pack under its byte limit and refuse a larger one while it streams', async () => {
    const pack = { type: 'bundle', objects: [{ id: 'hunt--1', type: 'hunt', name: 'Hunt' }, { id: 'hunt--1', type: 'hunt', name: 'Hunt, last occurrence' }] };
    const parsed = await parseHuntPack(upload([JSON.stringify(pack)]));
    // A hunt listed twice is read once, as its last occurrence
    expect(parsed.hunts.map((hunt) => hunt.name)).toEqual(['Hunt, last occurrence']);
    let produced = 0;
    function* oversized() {
      for (let index = 0; index < 1000; index += 1) {
        produced += 1;
        yield Buffer.alloc(1024 * 1024, ' ');
      }
    }
    await expect(parseHuntPack(upload(oversized()))).rejects.toThrow(`A hunt pack is limited to ${HUNT_PACK_MAX_BYTES / (1024 * 1024)} MB`);
    expect(produced).toBeLessThan(1000);
    await expect(parseHuntPack(upload(['not json']))).rejects.toThrow('A hunt pack must be a STIX 2.1 bundle');
  });

  it('should distribute hunts as hub drafts without local execution settings', () => {
    const stixHunt = {
      id: 'hunt--1',
      type: 'hunt',
      name: 'Hunt',
      hunt_status: 'active',
      hunt_source_kind: 'analyst',
      hunt_scope: '{"mode":"and"}',
      trigger_filters: '{"mode":"and"}',
      hunt_pir_activation: true,
      sigma_rule: 'title: t',
    } as unknown as StixHunt;
    expect(toPackHunt(stixHunt)).toMatchObject({
      id: 'hunt--1',
      hunt_status: 'draft',
      hunt_source_kind: 'hub',
      hunt_scope: '',
      trigger_filters: '',
      hunt_pir_activation: false,
      sigma_rule: 'title: t',
    });
  });

  it('should declare the hunt extension definition', () => {
    const extension = huntExtensionDefinition();
    expect(extension.id).toBe(STIX_EXT_OCTI_HUNT);
    expect(extension.extension_types).toEqual(['new-sdo']);
    expect(extension.created_by_ref.startsWith('identity--')).toBe(true);
  });
});
