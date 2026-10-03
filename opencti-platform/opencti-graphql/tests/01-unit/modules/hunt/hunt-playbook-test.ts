import { describe, expect, it } from 'vitest';
import { computeHuntPlaybookOutcome, isHuntRunGroupSettled } from '../../../../src/modules/hunt/hunt-playbook';
import { matchHuntResultFilter } from '../../../../src/modules/playbook/components/hunt-result-filter-component';
import { eventTouchedRefs, isStandingHuntTriggered } from '../../../../src/modules/hunt/hunt-automation';
import { huntExtensionDefinition, toPackHunt } from '../../../../src/modules/hunt/hunt-pack';
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

  it('should settle a group once every run is terminated without planned retry', () => {
    expect(isHuntRunGroupSettled([run({ hunt_run_status: 'completed' }), run({ hunt_run_status: 'timeout' })])).toBe(true);
    expect(isHuntRunGroupSettled([run({ hunt_run_status: 'running' })])).toBe(false);
    expect(isHuntRunGroupSettled([run({ hunt_run_status: 'failed', next_retry_at: '2026-10-03T10:00:00.000Z' })])).toBe(false);
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
});

describe('Hunt packs', () => {
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
